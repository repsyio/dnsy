//! A scriptable fake upstream DNS server (UDP): per name and type answers, delays, failures and
//! garbage, plus a log of what it was asked.

use dnsy_core::{Clock as _, SystemClock};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnsy_core::{KeyRole, KeyState};
use dnsy_dnssec::{
    ActiveKeys, Algorithm, Denial, DigestType, SignedZone, SigningKey, SigningPolicy, ZoneData,
    ZoneKey, ZoneSigner, ds_for,
};
use dnsy_proto::{Class, Message, Name, RData, Rcode, Record, RecordType, Soa};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// What the upstream does with a matching query.
#[derive(Clone, Debug)]
pub enum Reply {
    /// NOERROR with these answer records.
    Answer(Vec<Record>),
    /// NOERROR, no answers, SOA with this TTL and minimum.
    NoData(u32),
    /// NXDOMAIN with a SOA with this TTL and minimum.
    NxDomain(u32),
    /// An empty response with this rcode (SERVFAIL, REFUSED, ...).
    Rcode(Rcode),
    /// No reply at all.
    Drop,
    /// Reply with a different id (a spoofed or mismatching response).
    WrongId(Box<Reply>),
    /// Reply with these raw bytes.
    Garbage(Vec<u8>),
    /// Wait, then reply with the inner reply.
    Delay(Duration, Box<Reply>),
    /// A full response: this rcode with these answer and authority records (signed fixtures).
    Message {
        rcode: Rcode,
        answers: Vec<Record>,
        authority: Vec<Record>,
    },
}

/// Computes a reply from the question and the query's DO bit; `None` falls through to the
/// default reply.
pub type Responder = Arc<dyn Fn(&Name, RecordType, bool) -> Option<Reply> + Send + Sync>;

#[derive(Default)]
struct State {
    rules: HashMap<(Name, RecordType), Reply>,
    default: Option<Reply>,
    responder: Option<Responder>,
    log: Vec<(Name, RecordType)>,
}

/// Builds an A record.
pub fn a(name: &str, ttl: u32, ip: &str) -> Record {
    rec(name, ttl, RecordType::A, ip)
}

/// Builds a record from presentation-format rdata.
pub fn rec(name: &str, ttl: u32, rtype: RecordType, rdata: &str) -> Record {
    Record {
        name: Name::from_ascii(name).expect("name"),
        rtype,
        class: Class::In,
        ttl,
        data: RData::parse(rtype, rdata).expect("rdata"),
    }
}

fn soa(ttl: u32) -> Record {
    Record {
        name: Name::from_ascii("test.").expect("name"),
        rtype: RecordType::Soa,
        class: Class::In,
        ttl,
        data: RData::Soa(Soa {
            mname: Name::from_ascii("ns.test.").expect("name"),
            rname: Name::from_ascii("hostmaster.test.").expect("name"),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: ttl,
        }),
    }
}

/// A signed root zone served by the fake upstream: the records given by the test plus SOA, NS,
/// DNSKEY, NSEC and the RRSIGs over all of them. The validator trusts it through
/// [`trust_anchor`](Self::trust_anchor) (the only anchors the configuration accepts are root DS
/// records), so fixture names live at the top level (`host.`).
pub struct SignedRoot {
    zone: SignedZone,
    /// The DS of the zone's key as a trust anchor (`keytag algorithm digest-type digest-hex`).
    pub trust_anchor: String,
}

impl SignedRoot {
    /// The records of one `RRset` with their `RRSIG`s, as the upstream sends them.
    pub fn rrset(&self, name: &str, rtype: RecordType) -> Vec<Record> {
        let name = Name::from_ascii(name).expect("name");
        self.zone
            .rrset(&name, rtype)
            .map(|s| s.records.iter().chain(s.rrsigs.iter()).cloned().collect())
            .unwrap_or_default()
    }
}

/// The fake upstream; the task stops when it is dropped.
pub struct FakeUpstream {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl FakeUpstream {
    /// Binds `127.0.0.1:0`; unscripted queries get SERVFAIL until [`set_default`](Self::set_default).
    pub async fn start() -> FakeUpstream {
        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind upstream"),
        );
        let addr = socket.local_addr().expect("addr");
        let state = Arc::new(Mutex::new(State::default()));
        let task = tokio::spawn(serve(socket, Arc::clone(&state)));
        FakeUpstream { addr, state, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Scripts the reply for `name` and `rtype` (replacing an earlier script).
    pub fn on(&self, name: &str, rtype: RecordType, reply: Reply) {
        let name = Name::from_ascii(name).expect("name");
        self.state
            .lock()
            .expect("state")
            .rules
            .insert((name, rtype), reply);
    }

    /// Computes the reply for everything without a script of its own (scripts win).
    pub fn set_responder(&self, responder: Responder) {
        self.state.lock().expect("state").responder = Some(responder);
    }

    /// Reply for everything without a script of its own.
    pub fn set_default(&self, reply: Reply) {
        self.state.lock().expect("state").default = Some(reply);
    }

    /// Signs a root zone holding `records` (with a fresh ECDSA P-256 CSK, NSEC denial), scripts
    /// every `RRset` of it and answers everything else `NXDOMAIN`.
    pub fn serve_signed_root(&self, records: Vec<Record>) -> SignedRoot {
        let key = SigningKey::generate(Algorithm::EcdsaP256Sha256, true).expect("key");
        let dnskey = key.dnskey();
        let ds = ds_for(&Name::root(), &dnskey, DigestType::Sha256).expect("ds");
        let digest = crate::hex(&ds.digest).to_uppercase();
        let trust_anchor = format!(
            "{} {} {} {digest}",
            ds.key_tag, ds.algorithm, ds.digest_type
        );
        let mut all = vec![
            Record {
                name: Name::root(),
                rtype: RecordType::Soa,
                class: Class::In,
                ttl: 3600,
                data: RData::Soa(Soa {
                    mname: Name::from_ascii("a.root.test.").expect("name"),
                    rname: Name::from_ascii("hostmaster.root.test.").expect("name"),
                    serial: 1,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1_209_600,
                    minimum: 300,
                }),
            },
            rec(".", 3600, RecordType::Ns, "a.root.test."),
        ];
        all.extend(records);
        let now = u64::try_from(SystemClock.unix_secs()).expect("unix time fits");
        let signed = ZoneSigner::sign(
            &ZoneData {
                origin: Name::root(),
                records: all,
            },
            &ActiveKeys {
                keys: vec![ZoneKey::new(KeyRole::Csk, KeyState::Active, key)],
            },
            &SigningPolicy {
                denial: Denial::Nsec,
                signature_validity_days: 14,
                refresh_days: 5,
                dnskey_ttl: 3600,
            },
            u32::try_from(now).expect("unix time fits"),
        )
        .expect("sign fixture zone");
        let mut s = self.state.lock().expect("state");
        s.default = Some(Reply::NxDomain(300));
        for ((name, code), set) in &signed.rrsets {
            s.rules.insert(
                (name.clone(), RecordType::from(*code)),
                Reply::Answer(
                    set.records
                        .iter()
                        .chain(set.rrsigs.iter())
                        .cloned()
                        .collect(),
                ),
            );
        }
        SignedRoot {
            zone: signed,
            trust_anchor,
        }
    }

    /// Makes every query (scripted or not) go unanswered, as if the upstream were down.
    pub fn go_dark(&self) {
        let mut s = self.state.lock().expect("state");
        s.rules.clear();
        s.default = Some(Reply::Drop);
    }

    /// How often `name` and `rtype` were asked.
    pub fn count(&self, name: &str, rtype: RecordType) -> usize {
        let name = Name::from_ascii(name).expect("name");
        self.state
            .lock()
            .expect("state")
            .log
            .iter()
            .filter(|(n, t)| *n == name && *t == rtype)
            .count()
    }

    /// Total queries received.
    pub fn total(&self) -> usize {
        self.state.lock().expect("state").log.len()
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(socket: Arc<UdpSocket>, state: Arc<Mutex<State>>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let Ok(query) = Message::decode(&buf[..n]) else {
            continue;
        };
        let Some(q) = query.questions.first() else {
            continue;
        };
        let reply = {
            let mut s = state.lock().expect("state");
            s.log.push((q.name.clone(), q.qtype));
            let do_bit = query.edns.as_ref().is_some_and(|e| e.dnssec_ok);
            s.rules
                .get(&(q.name.clone(), q.qtype))
                .cloned()
                .or_else(|| {
                    s.responder
                        .as_ref()
                        .and_then(|r| r(&q.name, q.qtype, do_bit))
                })
                .or_else(|| s.default.clone())
                .unwrap_or(Reply::Rcode(Rcode::ServFail))
        };
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Some(bytes) = render(&query, reply).await {
                let _ = socket.send_to(&bytes, peer).await;
            }
        });
    }
}

async fn render(query: &Message, reply: Reply) -> Option<Vec<u8>> {
    let mut reply = reply;
    let mut wrong_id = false;
    loop {
        match reply {
            Reply::Delay(d, inner) => {
                tokio::time::sleep(d).await;
                reply = *inner;
            }
            Reply::WrongId(inner) => {
                wrong_id = true;
                reply = *inner;
            }
            other => {
                reply = other;
                break;
            }
        }
    }
    let mut m = Message::response_to(query);
    m.header.ra = true;
    if wrong_id {
        m.header.id = m.header.id.wrapping_add(1);
    }
    match reply {
        Reply::Answer(records) => m.answers = records,
        Reply::NoData(ttl) => m.authority = vec![soa(ttl)],
        Reply::NxDomain(ttl) => {
            m.header.rcode = Rcode::NxDomain;
            m.authority = vec![soa(ttl)];
        }
        Reply::Rcode(rc) => m.header.rcode = rc,
        Reply::Garbage(bytes) => return Some(bytes),
        Reply::Drop => return None,
        Reply::Message {
            rcode,
            answers,
            authority,
        } => {
            m.header.rcode = rcode;
            m.answers = answers;
            m.authority = authority;
        }
        Reply::Delay(..) | Reply::WrongId(_) => unreachable!("unwrapped above"),
    }
    if query.edns.is_some() {
        m.edns = Some(dnsy_proto::Edns::default());
    }
    m.encode(4096).ok()
}
