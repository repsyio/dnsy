use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use dnsy_proto::{Class, Name, Question, RData, Record, RecordType};

use super::LookupResult;
use crate::model::Zone;
use crate::store::ZoneSet;

const EXAMPLE_COM: &str = r#"{"schema":1,"origin":"example.com.","default_ttl":3600,
  "soa":{"mname":"ns1.example.com.","rname":"h.example.com.","serial":1,"refresh":1,"retry":1,
         "expire":1,"minimum":300},
  "records":[
    {"name":"@","type":"NS","value":"ns1.example.com."},
    {"name":"@","type":"MX","value":"10 mail.example.com."},
    {"name":"ns1","type":"A","value":"192.0.2.53"},
    {"name":"mail","type":"A","value":"192.0.2.25"},
    {"name":"www","type":"A","ttl":300,"value":"192.0.2.1"},
    {"name":"www","type":"A","ttl":300,"value":"192.0.2.2"},
    {"name":"www","type":"A","ttl":300,"value":"192.0.2.3"},
    {"name":"www","type":"AAAA","ttl":300,"value":"2001:db8::1"},
    {"name":"c1","type":"CNAME","value":"c2.example.com."},
    {"name":"c2","type":"CNAME","value":"WWW.example.com."},
    {"name":"dangling","type":"CNAME","value":"nothing.example.com."},
    {"name":"to-nodata","type":"CNAME","value":"mail.example.com."},
    {"name":"out","type":"CNAME","value":"host1.example."},
    {"name":"to-sub","type":"CNAME","value":"x.sub.example.com."},
    {"name":"loop1","type":"CNAME","value":"loop2.example.com."},
    {"name":"loop2","type":"CNAME","value":"loop1.example.com."},
    {"name":"self","type":"CNAME","value":"self.example.com."},
    {"name":"h0","type":"CNAME","value":"h1.example.com."},
    {"name":"h1","type":"CNAME","value":"h2.example.com."},
    {"name":"h2","type":"CNAME","value":"h3.example.com."},
    {"name":"h3","type":"CNAME","value":"h4.example.com."},
    {"name":"h4","type":"CNAME","value":"h5.example.com."},
    {"name":"h5","type":"CNAME","value":"h6.example.com."},
    {"name":"h6","type":"CNAME","value":"h7.example.com."},
    {"name":"h7","type":"CNAME","value":"h8.example.com."},
    {"name":"h8","type":"CNAME","value":"h9.example.com."},
    {"name":"h9","type":"A","value":"192.0.2.9"},
    {"name":"a.b.c.deep","type":"A","value":"192.0.2.77"},
    {"name":"sub","type":"NS","value":"ns.sub.example.com."},
    {"name":"sub","type":"NS","value":"ns1.example.com."},
    {"name":"sub","type":"NS","value":"ns.elsewhere.org."},
    {"name":"ns.sub","type":"A","value":"192.0.2.99"},
    {"name":"ns.sub","type":"AAAA","value":"2001:db8::99"}
  ]}"#;

/// The example zone of RFC 4592 section 2.2.1.
const RFC4592: &str = r#"{"schema":1,"origin":"example.","default_ttl":3600,
  "soa":{"mname":"ns.example.com.","rname":"h.example.com.","serial":1,"refresh":1,"retry":1,
         "expire":1,"minimum":3600,"ttl":60},
  "records":[
    {"name":"@","type":"NS","value":"ns.example.com."},
    {"name":"@","type":"NS","value":"ns.example.net."},
    {"name":"*","type":"TXT","value":"\"this is a wildcard\""},
    {"name":"*","type":"MX","value":"10 host1.example."},
    {"name":"sub.*","type":"TXT","value":"\"this is not a wildcard\""},
    {"name":"host1","type":"A","value":"192.0.2.1"},
    {"name":"_ssh._tcp.host1","type":"SRV","value":"0 0 22 host1.example."},
    {"name":"_ssh._tcp.host2","type":"SRV","value":"0 0 22 host2.example."},
    {"name":"subdel","type":"NS","value":"ns.example.com."},
    {"name":"subdel","type":"NS","value":"ns.example.net."},
    {"name":"*.wc","type":"CNAME","value":"host1.example."}
  ]}"#;

fn set() -> ZoneSet {
    let zones: BTreeMap<Name, Arc<Zone>> = [EXAMPLE_COM, RFC4592]
        .into_iter()
        .map(|json| {
            let (zone, _) = Zone::from_json(json).unwrap();
            (zone.origin.clone(), Arc::new(zone))
        })
        .collect();
    ZoneSet::new(zones)
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn q(s: &str, qtype: RecordType) -> Question {
    Question {
        name: name(s),
        qtype,
        qclass: Class::In,
    }
}

fn lookup(set: &ZoneSet, s: &str, qtype: RecordType) -> LookupResult {
    set.lookup(&q(s, qtype), false)
        .unwrap_or_else(|| panic!("{s} should be authoritative"))
}

fn summary(records: &[Record]) -> Vec<String> {
    records
        .iter()
        .map(|r| format!("{} {} {:?} {}", r.name, r.ttl, r.rtype, r.data))
        .collect()
}

fn answer_lines(result: LookupResult) -> Vec<String> {
    match result {
        LookupResult::Answer { answers, .. } => summary(&answers),
        other => panic!("expected an answer, got {other:?}"),
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn assert_soa(authority: &[Record], origin: &str, ttl: u32) {
    assert_eq!(authority.len(), 1, "{authority:?}");
    assert_eq!(authority[0].name, name(origin));
    assert_eq!(authority[0].rtype, RecordType::Soa);
    assert_eq!(authority[0].class, Class::In);
    assert_eq!(authority[0].ttl, ttl);
    assert!(matches!(authority[0].data, RData::Soa(_)));
}

fn assert_nodata(result: LookupResult, origin: &str) {
    match result {
        // Every caller uses the RFC 4592 zone: SOA TTL 60, minimum 3600.
        LookupResult::NoData { authority } => assert_soa(&authority, origin, 60),
        other => panic!("expected NODATA, got {other:?}"),
    }
}

fn assert_nxdomain(result: LookupResult, origin: &str, ttl: u32) {
    match result {
        LookupResult::NxDomain { authority } => assert_soa(&authority, origin, ttl),
        other => panic!("expected NXDOMAIN, got {other:?}"),
    }
}

#[test]
fn exact_match() {
    let set = set();
    let LookupResult::Answer {
        answers,
        authority,
        additional,
    } = lookup(&set, "WWW.Example.COM.", RecordType::Aaaa)
    else {
        panic!("expected an answer");
    };
    assert_eq!(summary(&answers), ["www.example.com. 300 Aaaa 2001:db8::1"]);
    assert_eq!(answers[0].class, Class::In);
    assert!(authority.is_empty() && additional.is_empty());
    // The apex SOA is answered from the soa block, with its own TTL.
    assert_eq!(
        answer_lines(lookup(&set, "example.com.", RecordType::Soa)),
        ["example.com. 3600 Soa ns1.example.com. h.example.com. 1 1 1 1 300"]
    );
    // A deep name and its empty non-terminal ancestors.
    assert_eq!(
        answer_lines(lookup(&set, "a.b.c.deep.example.com.", RecordType::A)),
        ["a.b.c.deep.example.com. 3600 A 192.0.2.77"]
    );
    // Not authoritative: no enclosing zone, or a class other than IN.
    assert!(
        set.lookup(&q("example.org.", RecordType::A), false)
            .is_none()
    );
    let mut chaos = q("www.example.com.", RecordType::A);
    chaos.qclass = Class::Ch;
    assert!(set.lookup(&chaos, false).is_none());
    chaos.qclass = Class::Any;
    assert!(set.lookup(&chaos, true).is_some());
    assert!(
        ZoneSet::default()
            .lookup(&q("example.com.", RecordType::A), false)
            .is_none()
    );
}

#[test]
fn any_returns_all_rrsets() {
    let set = set();
    let got = sorted(answer_lines(lookup(
        &set,
        "www.example.com.",
        RecordType::Any,
    )));
    assert_eq!(got.len(), 4);
    assert_eq!(got[3], "www.example.com. 300 Aaaa 2001:db8::1");
    let apex = answer_lines(lookup(&set, "example.com.", RecordType::Any));
    assert_eq!(apex.len(), 3, "{apex:?}");
    assert!(apex.iter().any(|r| r.contains(" Soa ")));
    // ANY at a CNAME returns the CNAME without following it.
    assert_eq!(
        answer_lines(lookup(&set, "c1.example.com.", RecordType::Any)),
        ["c1.example.com. 3600 Cname c2.example.com."]
    );
    // ANY at an empty non-terminal is NODATA.
    assert!(matches!(
        lookup(&set, "deep.example.com.", RecordType::Any),
        LookupResult::NoData { .. }
    ));
}

#[test]
fn additional_section_processing() {
    let set = set();
    let LookupResult::Answer { additional, .. } = lookup(&set, "example.com.", RecordType::Mx)
    else {
        panic!("expected an answer");
    };
    assert_eq!(
        summary(&additional),
        ["mail.example.com. 3600 A 192.0.2.25"]
    );
    let LookupResult::Answer { additional, .. } = lookup(&set, "example.com.", RecordType::Ns)
    else {
        panic!("expected an answer");
    };
    assert_eq!(summary(&additional), ["ns1.example.com. 3600 A 192.0.2.53"]);
    let LookupResult::Answer { additional, .. } =
        lookup(&set, "_ssh._tcp.host1.example.", RecordType::Srv)
    else {
        panic!("expected an answer");
    };
    assert_eq!(summary(&additional), ["host1.example. 3600 A 192.0.2.1"]);
}

#[test]
fn cname_chain_in_zone() {
    let set = set();
    let LookupResult::Answer {
        answers, authority, ..
    } = lookup(&set, "c1.example.com.", RecordType::A)
    else {
        panic!("expected an answer");
    };
    let got = summary(&answers);
    assert_eq!(got.len(), 5, "{got:?}");
    assert_eq!(got[0], "c1.example.com. 3600 Cname c2.example.com.");
    assert_eq!(got[1], "c2.example.com. 3600 Cname WWW.example.com.");
    assert!(
        got[2..]
            .iter()
            .all(|r| r.starts_with("www.example.com. 300 A "))
    );
    assert_eq!(authority.len(), 0);
    // Asking for the CNAME itself does not follow it.
    assert_eq!(
        answer_lines(lookup(&set, "c1.example.com.", RecordType::Cname)),
        ["c1.example.com. 3600 Cname c2.example.com."]
    );
    // A target outside the zone (even one we serve in another zone) ends the chain.
    assert_eq!(
        answer_lines(lookup(&set, "out.example.com.", RecordType::A)),
        ["out.example.com. 3600 Cname host1.example."]
    );
    // A dangling target or a type the target lacks: CNAME plus the negative SOA.
    for (owner, target) in [("dangling", "nothing"), ("to-nodata", "mail")] {
        let LookupResult::Answer {
            answers, authority, ..
        } = lookup(&set, &format!("{owner}.example.com."), RecordType::Txt)
        else {
            panic!("expected an answer");
        };
        assert_eq!(
            summary(&answers),
            [format!(
                "{owner}.example.com. 3600 Cname {target}.example.com."
            )]
        );
        assert_soa(&authority, "example.com.", 300);
    }
    // A target below a zone cut: CNAME plus the referral.
    let LookupResult::Answer {
        answers,
        authority,
        additional,
    } = lookup(&set, "to-sub.example.com.", RecordType::A)
    else {
        panic!("expected an answer");
    };
    assert_eq!(answers.len(), 1);
    assert_eq!(authority.len(), 3);
    assert!(authority.iter().all(|r| r.rtype == RecordType::Ns));
    assert_eq!(additional.len(), 3);
}

#[test]
fn cname_loop_terminates() {
    let set = set();
    let got = answer_lines(lookup(&set, "loop1.example.com.", RecordType::A));
    assert_eq!(
        got,
        [
            "loop1.example.com. 3600 Cname loop2.example.com.",
            "loop2.example.com. 3600 Cname loop1.example.com."
        ]
    );
    assert_eq!(
        answer_lines(lookup(&set, "self.example.com.", RecordType::A)),
        ["self.example.com. 3600 Cname self.example.com."]
    );
    // A chain longer than the limit stops after 8 CNAMEs, without the final address.
    let got = answer_lines(lookup(&set, "h0.example.com.", RecordType::A));
    assert_eq!(got.len(), 8, "{got:?}");
    assert!(got.iter().all(|r| r.contains(" Cname ")));
    let got = answer_lines(lookup(&set, "h1.example.com.", RecordType::A));
    assert_eq!(got.len(), 9, "{got:?}");
    assert_eq!(got[8], "h9.example.com. 3600 A 192.0.2.9");
}

#[test]
fn wildcard_rules_rfc4592() {
    // RFC 4592 section 2.2.1, the example answers.
    let set = set();
    assert_eq!(
        answer_lines(lookup(&set, "host3.example.", RecordType::Mx)),
        ["host3.example. 3600 Mx 10 host1.example."]
    );
    let LookupResult::Answer { additional, .. } = lookup(&set, "host3.example.", RecordType::Mx)
    else {
        panic!("expected an answer");
    };
    assert_eq!(summary(&additional), ["host1.example. 3600 A 192.0.2.1"]);
    assert_nodata(lookup(&set, "host3.example.", RecordType::A), "example.");
    assert_eq!(
        answer_lines(lookup(&set, "foo.bar.example.", RecordType::Txt)),
        ["foo.bar.example. 3600 Txt \"this is a wildcard\""]
    );
    // The name exists, so the wildcard does not apply.
    assert_nodata(lookup(&set, "host1.example.", RecordType::Mx), "example.");
    assert_nodata(lookup(&set, "sub.*.example.", RecordType::Mx), "example.");
    // The closest encloser host1.example has no wildcard child.
    assert_nxdomain(
        lookup(&set, "_telnet._tcp.host1.example.", RecordType::Srv),
        "example.",
        60,
    );
    // Delegations stop wildcard matching.
    assert!(matches!(
        lookup(&set, "host.subdel.example.", RecordType::A),
        LookupResult::Referral { .. }
    ));
    // The closest encloser is *.example, and *.*.example does not exist.
    assert_nxdomain(
        lookup(&set, "ghost.*.example.", RecordType::Mx),
        "example.",
        60,
    );
    // A `*` label asked for directly is matched literally.
    assert_eq!(
        answer_lines(lookup(&set, "*.example.", RecordType::Txt)),
        ["*.example. 3600 Txt \"this is a wildcard\""]
    );
    // ANY collects every wildcard RRset under the query name.
    let got = sorted(answer_lines(lookup(&set, "any.example.", RecordType::Any)));
    assert_eq!(got.len(), 2);
    assert!(got.iter().all(|r| r.starts_with("any.example. 3600 ")));
    // A wildcard CNAME is synthesised and then followed.
    assert_eq!(
        answer_lines(lookup(&set, "x.y.wc.example.", RecordType::A)),
        [
            "x.y.wc.example. 3600 Cname host1.example.",
            "host1.example. 3600 A 192.0.2.1"
        ]
    );
}

#[test]
fn empty_non_terminal_is_nodata() {
    let set = set();
    // host2.example and _tcp.host2.example exist only as ancestors of _ssh._tcp.host2.example:
    // NODATA, never the *.example wildcard.
    assert_nodata(lookup(&set, "host2.example.", RecordType::Mx), "example.");
    assert_nodata(
        lookup(&set, "_tcp.host2.example.", RecordType::Txt),
        "example.",
    );
    assert_nodata(
        lookup(&set, "_tcp.host1.example.", RecordType::A),
        "example.",
    );
    match lookup(&set, "b.c.deep.example.com.", RecordType::A) {
        LookupResult::NoData { authority } => assert_soa(&authority, "example.com.", 300),
        other => panic!("expected NODATA, got {other:?}"),
    }
    // A name below an empty non-terminal that does not exist is NXDOMAIN.
    assert_nxdomain(
        lookup(&set, "x.host2.example.", RecordType::A),
        "example.",
        60,
    );
}

#[test]
fn delegation_referral_with_glue() {
    let set = set();
    for qname in [
        "sub.example.com.",
        "x.sub.example.com.",
        "a.b.sub.example.com.",
        // Data below the cut is occluded: only served as glue.
        "ns.sub.example.com.",
    ] {
        let LookupResult::Referral {
            ns,
            ds_or_proof,
            glue,
        } = lookup(&set, qname, RecordType::A)
        else {
            panic!("expected a referral for {qname}");
        };
        // NS rotates like any RRset.
        assert_eq!(
            sorted(summary(&ns)),
            [
                "sub.example.com. 3600 Ns ns.elsewhere.org.",
                "sub.example.com. 3600 Ns ns.sub.example.com.",
                "sub.example.com. 3600 Ns ns1.example.com."
            ]
        );
        assert_eq!(ds_or_proof.len(), 0);
        assert_eq!(
            sorted(summary(&glue)),
            [
                "ns.sub.example.com. 3600 A 192.0.2.99",
                "ns.sub.example.com. 3600 Aaaa 2001:db8::99",
                "ns1.example.com. 3600 A 192.0.2.53"
            ]
        );
    }
    // DS belongs to the parent side of the cut: answered here, unsigned so NODATA.
    match lookup(&set, "sub.example.com.", RecordType::Ds) {
        LookupResult::NoData { authority } => assert_soa(&authority, "example.com.", 300),
        other => panic!("expected NODATA, got {other:?}"),
    }
    // Below the cut, DS is referred like any other type.
    assert!(matches!(
        lookup(&set, "x.sub.example.com.", RecordType::Ds),
        LookupResult::Referral { .. }
    ));
    // Apex NS is an answer, not a referral.
    assert!(matches!(
        lookup(&set, "example.com.", RecordType::Ns),
        LookupResult::Answer { .. }
    ));
}

#[test]
fn nxdomain_has_soa() {
    let set = set();
    // SOA TTL 3600, minimum 300.
    assert_nxdomain(
        lookup(&set, "nope.example.com.", RecordType::A),
        "example.com.",
        300,
    );
    assert_nxdomain(
        lookup(&set, "x.y.www.example.com.", RecordType::A),
        "example.com.",
        300,
    );
    // SOA TTL 60, minimum 3600.
    assert_nodata(lookup(&set, "example.", RecordType::A), "example.");
    match lookup(&set, "nope.example.com.", RecordType::A) {
        LookupResult::NxDomain { authority } => {
            let RData::Soa(soa) = &authority[0].data else {
                panic!("not a SOA");
            };
            assert_eq!(soa.minimum, 300);
        }
        other => panic!("expected NXDOMAIN, got {other:?}"),
    }
}

#[test]
fn rrset_rotation() {
    let set = set();
    let first = |r: LookupResult| match r {
        LookupResult::Answer { answers, .. } => {
            assert_eq!(answers.len(), 3);
            match answers[0].data {
                RData::A(ip) => ip,
                ref other => panic!("not an A record: {other:?}"),
            }
        }
        other => panic!("expected an answer, got {other:?}"),
    };
    let mut seen: Vec<Ipv4Addr> = (0..3)
        .map(|_| first(lookup(&set, "www.example.com.", RecordType::A)))
        .collect();
    let fourth = first(lookup(&set, "www.example.com.", RecordType::A));
    assert_eq!(fourth, seen[0], "rotation cycles through the RRset");
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "every record leads once per cycle");
    // Rotation keeps the cyclic order of the RRset.
    let LookupResult::Answer { answers, .. } = lookup(&set, "www.example.com.", RecordType::A)
    else {
        panic!("expected an answer");
    };
    let order: Vec<u8> = answers
        .iter()
        .map(|r| match r.data {
            RData::A(ip) => ip.octets()[3],
            _ => 0,
        })
        .collect();
    assert!(
        [[1, 2, 3], [2, 3, 1], [3, 1, 2]].contains(&[order[0], order[1], order[2]]),
        "{order:?}"
    );
}
