use std::io::Cursor;

use dnsy_proto::{
    Class, Edns, EdnsOption, Header, Message, Name, Opcode, Question, RData, Rcode, RecordType, ede,
};
use proptest::prelude::*;

use crate::{
    BlockMode, BlocklistError, CUSTOM_LIST, FilterLimits, FilterSet, FilterSetBuilder, ListFormat,
    MAX_LINE_LEN, Verdict, block_response,
};

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn build(format: ListFormat, text: &str) -> (FilterSet, crate::ParseStats) {
    let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    let stats = b
        .add_list("test", format, Cursor::new(text.as_bytes()))
        .unwrap();
    (b.build(), stats)
}

fn blocked(set: &FilterSet, n: &str) -> bool {
    matches!(set.check(&name(n)), Verdict::Block { .. })
}

#[test]
fn parse_hosts_format() {
    let text = "\u{feff}# comment\r\n127.0.0.1 localhost\r\n0.0.0.0 ads.example.com\r\n\
                :: tracker.example.net other.example.org # trailing\r\n0.0.0.0 XN--80ak6aa92e.com\r\n";
    let (set, stats) = build(ListFormat::Hosts, text);
    assert_eq!((stats.blocks, stats.invalid), (4, 0));
    assert!(blocked(&set, "ads.example.com"));
    assert!(blocked(&set, "other.example.org"));
    assert!(blocked(&set, "xn--80ak6aa92e.com"));
    assert!(!blocked(&set, "localhost"));
    assert!(!blocked(&set, "example.com"));
}

#[test]
fn parse_domain_list() {
    let (set, stats) = build(
        ListFormat::Domains,
        "a.example\n*.wild.example\n\nb.example # note\n",
    );
    assert_eq!((stats.blocks, stats.invalid, stats.skipped), (3, 0, 1));
    assert!(blocked(&set, "x.wild.example"));
    assert!(blocked(&set, "wild.example"));
}

#[test]
fn parse_adblock_subset() {
    let text =
        "[Adblock Plus 2.0]\n! comment\n# other\n||ads.example.com^\n@@||good.ads.example.com^\n";
    let (set, stats) = build(ListFormat::Adblock, text);
    assert_eq!((stats.blocks, stats.allows, stats.invalid), (1, 1, 0));
    assert!(blocked(&set, "ads.example.com"));
    assert!(!blocked(&set, "good.ads.example.com"));
    assert!(!blocked(&set, "deeper.good.ads.example.com"));
}

#[test]
fn auto_detects_per_line() {
    let (set, stats) = build(
        ListFormat::Auto,
        "0.0.0.0 h.example\np.example\n||a.example^\n@@||ok.a.example^\n",
    );
    assert_eq!((stats.blocks, stats.allows, stats.invalid), (3, 1, 0));
    assert!(blocked(&set, "h.example") && blocked(&set, "p.example") && blocked(&set, "a.example"));
    assert!(!blocked(&set, "ok.a.example"));
}

#[test]
fn allowlist_overrides_block() {
    let mut b = FilterSetBuilder::new(BlockMode::NxDomain, FilterLimits::default());
    b.add_list("l", ListFormat::Domains, Cursor::new(b"example.com\n"))
        .unwrap();
    b.add_allow_rule("Safe.Example.com").unwrap();
    let set = b.build();
    assert!(blocked(&set, "example.com"));
    assert_eq!(set.check(&name("safe.example.com")), Verdict::Allow);
    assert_eq!(set.check(&name("deep.SAFE.example.com")), Verdict::Allow);
    assert!(blocked(&set, "other.example.com"));
}

#[test]
fn subdomain_blocked_by_parent() {
    let (set, _) = build(ListFormat::Domains, "example.com\n");
    assert!(blocked(&set, "a.b.c.EXAMPLE.com"));
    assert!(!blocked(&set, "notexample.com"));
    assert!(!blocked(&set, "com"));
    assert!(!blocked(&set, "."));
}

#[test]
fn invalid_lines_counted() {
    let mut text = Vec::new();
    text.extend_from_slice(
        b"ok.example\nbad domain here\n1.2.3.4\nb\xffd.example\n-.\n\xc3\xa9.example\n",
    );
    text.extend(std::iter::repeat_n(b'a', MAX_LINE_LEN + 50));
    text.extend_from_slice(b"\nlast.example");
    let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    let stats = b
        .add_list("t", ListFormat::Auto, Cursor::new(text))
        .unwrap();
    assert_eq!(stats.blocks, 2);
    assert_eq!(stats.invalid, 6);
    let set = b.build();
    assert!(blocked(&set, "last.example") && blocked(&set, "ok.example"));
}

#[test]
fn custom_rule_reports_custom_list() {
    let mut b = FilterSetBuilder::new(BlockMode::Refused, FilterLimits::default());
    b.add_block_rule("evil.test").unwrap();
    assert!(matches!(
        b.add_block_rule("bad domain"),
        Err(BlocklistError::InvalidDomain(_))
    ));
    let set = b.build();
    assert_eq!(
        set.check(&name("www.evil.test")),
        Verdict::Block {
            list: CUSTOM_LIST.into(),
            mode: BlockMode::Refused
        }
    );
}

#[test]
fn limits_enforced() {
    let mut b = FilterSetBuilder::new(
        BlockMode::NullIp,
        FilterLimits {
            max_entries: 2,
            max_input_bytes: 1 << 20,
        },
    );
    let err = b
        .add_list("t", ListFormat::Domains, Cursor::new(b"a.x\nb.x\nc.x\n"))
        .unwrap_err();
    assert!(matches!(err, BlocklistError::TooManyEntries(2)));
    let mut b = FilterSetBuilder::new(
        BlockMode::NullIp,
        FilterLimits {
            max_entries: 10,
            max_input_bytes: 8,
        },
    );
    let err = b
        .add_list(
            "t",
            ListFormat::Domains,
            Cursor::new(b"a.example\nb.example\n"),
        )
        .unwrap_err();
    assert!(matches!(err, BlocklistError::InputTooLarge));
    let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    let long = vec![b'a'; 1 << 20];
    let stats = b
        .add_list("t", ListFormat::Domains, Cursor::new(long))
        .unwrap();
    assert_eq!(stats.invalid, 1);
}

#[test]
fn duplicate_entries_not_double_counted_in_memory() {
    let mut b = FilterSetBuilder::new(
        BlockMode::NullIp,
        FilterLimits {
            max_entries: 1,
            max_input_bytes: 1 << 20,
        },
    );
    b.add_list("t", ListFormat::Domains, Cursor::new(b"a.x\na.x\nA.X\n"))
        .unwrap();
    assert_eq!(b.build().len(), 1);
}

fn query(qtype: RecordType, edns: bool) -> Message {
    Message {
        header: Header {
            id: 7,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: name("ads.example"),
            qtype,
            qclass: Class::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
        edns: edns.then(Edns::default),
    }
}

fn ede_code(m: &Message) -> Option<u16> {
    m.edns.as_ref()?.options.iter().find_map(|o| match o {
        EdnsOption::ExtendedError { code, .. } => Some(*code),
        _ => None,
    })
}

#[test]
fn block_response_modes() {
    let r = block_response(&query(RecordType::A, true), BlockMode::NxDomain, "l").unwrap();
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert!(r.answers.is_empty());
    assert_eq!(ede_code(&r), Some(ede::BLOCKED));
    assert_eq!(r.header.id, 7);

    let r = block_response(&query(RecordType::A, true), BlockMode::Refused, "l").unwrap();
    assert_eq!(r.header.rcode, Rcode::Refused);

    let r = block_response(&query(RecordType::A, true), BlockMode::NullIp, "l").unwrap();
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(r.answers[0].data, RData::A([0, 0, 0, 0].into()));
    let r = block_response(&query(RecordType::Aaaa, true), BlockMode::NullIp, "l").unwrap();
    assert_eq!(r.answers[0].data, RData::Aaaa([0; 16].into()));
    let r = block_response(&query(RecordType::Txt, true), BlockMode::NullIp, "l").unwrap();
    assert!(r.answers.is_empty());
    assert_eq!(r.header.rcode, Rcode::NoError);

    let mode = BlockMode::CustomIp {
        v4: Some([10, 0, 0, 1].into()),
        v6: None,
    };
    let r = block_response(&query(RecordType::A, true), mode, "l").unwrap();
    assert_eq!(r.answers[0].data, RData::A([10, 0, 0, 1].into()));
    assert!(
        block_response(&query(RecordType::Aaaa, true), mode, "l")
            .unwrap()
            .answers
            .is_empty()
    );

    let r = block_response(
        &query(RecordType::A, true),
        BlockMode::NxDomain,
        CUSTOM_LIST,
    )
    .unwrap();
    assert_eq!(ede_code(&r), Some(ede::FILTERED));
    let r = block_response(&query(RecordType::A, false), BlockMode::NxDomain, "l").unwrap();
    assert!(r.edns.is_none());

    let mut empty = query(RecordType::A, true);
    empty.questions.clear();
    assert!(block_response(&empty, BlockMode::NxDomain, "l").is_none());
    // The response survives a wire round trip.
    let wire = block_response(&query(RecordType::A, true), BlockMode::NullIp, "l")
        .unwrap()
        .encode(512)
        .unwrap();
    assert_eq!(Message::decode(&wire).unwrap().answers.len(), 1);
}

#[test]
#[ignore = "perf pass: builds a million-entry set"]
fn million_entries_memory_bound() {
    fn rss_kib() -> u64 {
        let s = std::fs::read_to_string("/proc/self/statm").unwrap();
        s.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() * 4
    }
    let mut text = String::with_capacity(32 << 20);
    for i in 0..1_000_000u32 {
        text.push_str(&format!("host{i}.tracker{}.example\n", i % 1000));
    }
    let before = rss_kib();
    let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    b.add_list("big", ListFormat::Domains, Cursor::new(text.as_bytes()))
        .unwrap();
    let set = b.build();
    let grown_mib = rss_kib().saturating_sub(before) / 1024;
    assert_eq!(set.len(), 1_000_000);
    assert!(blocked(&set, "x.host999999.tracker999.example"));
    assert!(!blocked(&set, "host1000000.tracker0.example"));
    assert!(grown_mib < 200, "1M entries used {grown_mib} MiB");
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096), fmt in 0..4usize) {
        let format = [ListFormat::Hosts, ListFormat::Domains, ListFormat::Adblock, ListFormat::Auto][fmt];
        let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
        let lines = data.iter().filter(|&&c| c == b'\n').count() + 1;
        let stats = b.add_list("p", format, Cursor::new(data)).unwrap();
        prop_assert!(stats.invalid + stats.skipped <= lines);
        let set = b.build();
        let _ = set.check(&name("example.com"));
    }

    #[test]
    fn arbitrary_text_lines_never_panic(lines in proptest::collection::vec("\\PC{0,80}", 0..50)) {
        let text = lines.join("\n");
        let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
        b.add_list("p", ListFormat::Auto, Cursor::new(text)).unwrap();
        let set = b.build();
        for l in &lines {
            if let Ok(n) = Name::from_ascii(l) { let _ = set.check(&n); }
        }
    }

    #[test]
    fn listed_domain_and_children_blocked(labels in proptest::collection::vec("[a-z][a-z0-9-]{0,9}[a-z0-9]", 1..5), child in "[a-z]{1,8}") {
        let domain = format!("{}.zz", labels.join("."));
        let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
        b.add_list("p", ListFormat::Domains, Cursor::new(format!("{domain}\n"))).unwrap();
        let set = b.build();
        prop_assert!(blocked(&set, &domain));
        let child_name = format!("{child}.{domain}");
        prop_assert!(blocked(&set, &child_name));
    }
}
