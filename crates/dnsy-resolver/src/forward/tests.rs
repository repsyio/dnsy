use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnsy_config::{Config, Dnssec};
use dnsy_proto::{Class, RData, Record, RecordType};

use super::*;
use crate::groups::{GroupMember, GroupSpec, Strategy, SystemClock, ThreadRng};
use crate::{Upstream, UpstreamError};

const ROOT_DS: &str = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn q(name: &str, qtype: RecordType) -> Question {
    Question {
        name: n(name),
        qtype,
        qclass: Class::In,
    }
}

/// Answers every query with one A record and remembers the queries it saw.
#[derive(Default)]
struct Fake {
    seen: Mutex<Vec<Message>>,
    calls: AtomicUsize,
    wrong_question: bool,
    fail: bool,
}

impl Exchange for Arc<Fake> {
    async fn exchange(&self, _u: &Upstream, query: &Message) -> Result<Message, UpstreamError> {
        tokio::task::yield_now().await;
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(query.clone());
        if self.fail {
            return Err(UpstreamError::Timeout);
        }
        let mut r = Message::response_to(query);
        r.header.aa = true;
        r.header.ad = true;
        if self.wrong_question {
            r.questions = vec![q("other.example.", RecordType::A)];
        }
        r.answers.push(Record {
            name: query.questions[0].name.clone(),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 300,
            data: RData::A(Ipv4Addr::LOCALHOST),
        });
        r.additional.push(r.answers[0].clone());
        Ok(r)
    }
}

fn groups() -> GroupSet {
    GroupSet::new(
        vec![GroupSpec {
            name: "default".to_owned(),
            strategy: Strategy::Failover,
            default: true,
            domains: vec![],
            members: vec![GroupMember {
                upstream: "udp://192.0.2.1:53".parse().unwrap(),
                weight: 1,
            }],
        }],
        Arc::new(SystemClock::new()),
        Arc::new(ThreadRng),
    )
    .unwrap()
}

struct Rig {
    groups: GroupSet,
    fake: Arc<Fake>,
    cache: Cache,
    permits: Semaphore,
}

impl Rig {
    fn new(fake: Fake) -> Self {
        Self {
            groups: groups(),
            fake: Arc::new(fake),
            cache: Cache::new(&Config::default().cache),
            permits: Semaphore::new(MAX_CONCURRENT_FETCHES),
        }
    }

    fn fetcher(&self, within: Duration) -> UpstreamFetcher<'_, Arc<Fake>> {
        UpstreamFetcher {
            groups: &self.groups,
            exchange: &self.fake,
            cache: &self.cache,
            permits: &self.permits,
            deadline: tokio::time::Instant::now() + within,
        }
    }
}

#[tokio::test]
async fn fetch_sends_do_and_cd_and_memoises_unchecked() {
    let rig = Rig::new(Fake::default());
    let f = rig.fetcher(Duration::from_secs(5));
    let question = q("Example.", RecordType::Dnskey);
    let first = f.fetch(question.clone()).await.unwrap();
    assert!(!first.header.aa && !first.header.ad);
    assert_eq!(first.additional.len(), 0);
    let sent = rig.fake.seen.lock().unwrap()[0].clone();
    assert!(sent.header.cd && sent.header.rd);
    assert!(sent.edns.as_ref().unwrap().dnssec_ok);

    let again = f.fetch(question).await.unwrap();
    assert_eq!(again.answers.len(), 1);
    assert_eq!(rig.fake.calls.load(Ordering::SeqCst), 1);
    let key = CacheKey {
        name: n("example."),
        qtype: RecordType::Dnskey,
        qclass: Class::In,
        do_bit: true,
        cd_bit: true,
    };
    match rig.cache.get(&key, Instant::now()) {
        CacheLookup::Fresh { dnssec, .. } => assert_eq!(dnssec, DnssecStatus::Unchecked),
        other => panic!("fetch result not memoised: {other:?}"),
    }
    let validated = CacheKey {
        cd_bit: false,
        ..key
    };
    assert_eq!(rig.cache.get(&validated, Instant::now()), CacheLookup::Miss);
}

#[tokio::test]
async fn fetch_rejects_mismatched_answers_and_failures() {
    let rig = Rig::new(Fake {
        wrong_question: true,
        ..Fake::default()
    });
    let err = rig
        .fetcher(Duration::from_secs(5))
        .fetch(q("example.", RecordType::Ds))
        .await
        .unwrap_err();
    assert!(err.0.contains("does not match"), "{err}");

    let rig = Rig::new(Fake {
        fail: true,
        ..Fake::default()
    });
    assert!(
        rig.fetcher(Duration::from_secs(5))
            .fetch(q("example.", RecordType::Ds))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fetch_waits_for_a_permit_only_until_the_deadline() {
    let rig = Rig::new(Fake::default());
    let _all = rig
        .permits
        .acquire_many(u32::try_from(MAX_CONCURRENT_FETCHES).unwrap())
        .await
        .unwrap();
    let err = rig
        .fetcher(Duration::from_millis(20))
        .fetch(q("example.", RecordType::Ds))
        .await
        .unwrap_err();
    assert!(err.0.contains("deadline"), "{err}");
    assert_eq!(rig.fake.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn policy_from_config_reads_anchors_file_and_ntas() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("anchors");
    std::fs::write(&file, format!("; comment\n\n# other\n{ROOT_DS}\n")).unwrap();
    let cfg = Dnssec {
        validation: Validation::Permissive,
        trust_anchors: vec![ROOT_DS.to_owned()],
        trust_anchor_file: Some(file.clone()),
        negative_trust_anchors: vec!["Broken.Example".to_owned(), "lab.test.".to_owned()],
        clock_skew_s: 60,
        key_passphrase_file: None,
    };
    let p = DnssecPolicy::from_config(&cfg).unwrap();
    assert_eq!(p.mode, Validation::Permissive);
    assert_eq!(p.validator.limits().clock_skew, 60);
    assert_eq!(
        p.validator.anchors().closest(&n("a.example.")),
        Some(&Name::root())
    );
    assert!(p.validator.anchors().is_negative(&n("www.broken.example.")));
    assert!(p.validator.anchors().is_negative(&n("lab.test.")));
    assert!(!p.validator.anchors().is_negative(&n("example.")));

    let p = p.with_negative_trust_anchors(vec![n("other.test.")]);
    assert!(!p.validator.anchors().is_negative(&n("lab.test.")));
    assert!(p.validator.anchors().is_negative(&n("x.other.test.")));
    assert_eq!(p.validator.limits().clock_skew, 60);

    let bad = |c: Dnssec| DnssecPolicy::from_config(&c).unwrap_err().to_string();
    let base = Dnssec {
        trust_anchor_file: None,
        ..cfg
    };
    assert!(
        bad(Dnssec {
            trust_anchors: vec!["nonsense".to_owned()],
            ..base.clone()
        })
        .contains("trust anchor")
    );
    assert!(
        bad(Dnssec {
            trust_anchor_file: Some(dir.path().join("missing")),
            ..base.clone()
        })
        .contains("trust anchor file")
    );
    assert!(
        bad(Dnssec {
            negative_trust_anchors: vec!["a..b".to_owned()],
            ..base
        })
        .contains("negative trust anchor")
    );
}

#[tokio::test]
async fn untrusted_clock_is_indeterminate_without_fetching() {
    let rig = Rig::new(Fake::default());
    let policy = DnssecPolicy::from_config(&Dnssec::default()).unwrap();
    assert_eq!(policy.mode, Validation::Strict);
    assert!(policy.clock_trusted(RELEASE_FLOOR_UNIX));
    assert!(!policy.clock_trusted(0));
    assert!(policy.clock_trusted(unix_now()));
    let question = q("www.example.", RecordType::A);
    let resp = Message::response_to(&dnssec_query(&question));
    let out = policy
        .validate(
            &rig.fetcher(Duration::from_secs(5)),
            &question,
            &resp,
            86_400,
        )
        .await;
    assert_eq!(out.status, DnssecStatus::Indeterminate);
    assert_eq!(out.ede.unwrap().0, ede::DNSSEC_INDETERMINATE);
    assert_eq!(rig.fake.calls.load(Ordering::SeqCst), 0);

    let off = DnssecPolicy::off();
    assert_eq!(off.mode, Validation::Off);
    assert!(off.validator.anchors().is_empty());
}

#[test]
fn cap_ttls_lowers_every_record() {
    let question = q("www.example.", RecordType::A);
    let mut msg = Message::response_to(&dnssec_query(&question));
    let a = Record {
        name: n("www.example."),
        rtype: RecordType::A,
        class: Class::In,
        ttl: 300,
        data: RData::A(Ipv4Addr::LOCALHOST),
    };
    msg.answers = vec![
        a.clone(),
        Record {
            ttl: 30,
            ..a.clone()
        },
    ];
    msg.authority = vec![a.clone()];
    msg.additional = vec![a];
    cap_ttls(&mut msg, 100);
    let ttls: Vec<u32> = msg
        .answers
        .iter()
        .chain(&msg.authority)
        .chain(&msg.additional)
        .map(|r| r.ttl)
        .collect();
    assert_eq!(ttls, [100, 30, 100, 100]);
}
