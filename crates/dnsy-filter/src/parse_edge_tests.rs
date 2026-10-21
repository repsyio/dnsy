//! Malformed-input behaviour of the list parser and the custom-rule entry points: a bad line must
//! never add an entry, and limits must hold for allow rules too.

use std::io::Cursor;

use dnsy_proto::Name;

use crate::{
    BlockMode, BlocklistError, FilterLimits, FilterSet, FilterSetBuilder, ListFormat, Verdict,
};

fn build(format: ListFormat, text: &str) -> (FilterSet, crate::ParseStats) {
    let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    let stats = b
        .add_list("t", format, Cursor::new(text.as_bytes()))
        .unwrap();
    (b.build(), stats)
}

fn blocked(set: &FilterSet, n: &str) -> bool {
    matches!(
        set.check(&Name::from_ascii(n).unwrap()),
        Verdict::Block { .. }
    )
}

#[test]
fn hosts_line_with_a_bad_name_adds_nothing() {
    let (set, stats) = build(
        ListFormat::Hosts,
        "0.0.0.0 good.example bad_$name.example\n0.0.0.0 ok.example\n",
    );
    assert_eq!(stats.invalid, 1);
    assert_eq!(stats.blocks, 1);
    assert!(
        !blocked(&set, "good.example"),
        "half-valid line must add nothing"
    );
    assert!(blocked(&set, "ok.example"));
}

#[test]
fn hosts_line_without_names_or_with_bad_ip_is_invalid() {
    let (_, stats) = build(ListFormat::Hosts, "0.0.0.0\nnot-an-ip evil.example\n");
    assert_eq!(stats.invalid, 2);
    assert_eq!(stats.blocks, 0);
}

#[test]
fn hosts_only_loopback_names_is_skipped() {
    let (_, stats) = build(
        ListFormat::Hosts,
        "127.0.0.1 localhost localhost.localdomain\n",
    );
    assert_eq!(stats.skipped, 1);
    assert_eq!(stats.invalid, 0);
    assert_eq!(stats.blocks, 0);
}

#[test]
fn adblock_requires_both_anchors() {
    let (set, stats) = build(
        ListFormat::Adblock,
        "||nocaret.example\nplain.example^\n||bad_$.example^\n||ok.example^\n@@||allowed.example^\n",
    );
    assert_eq!(stats.invalid, 3);
    assert_eq!(stats.blocks, 1);
    assert_eq!(stats.allows, 1);
    assert!(blocked(&set, "ok.example"));
    assert!(!blocked(&set, "nocaret.example"));
}

#[test]
fn domains_format_rejects_numeric_tld_and_bad_labels() {
    let (set, stats) = build(
        ListFormat::Domains,
        "1.2.3.4\n-lead.example\ntrail-.example\nempty..label\ngood.example # note\n",
    );
    assert_eq!(stats.invalid, 4);
    assert_eq!(stats.blocks, 1);
    assert!(blocked(&set, "good.example"));
}

#[test]
fn auto_detects_each_syntax_per_line() {
    let (set, stats) = build(
        ListFormat::Auto,
        "||ad.example^\n0.0.0.0 hosts.example\nplain.example\n",
    );
    assert_eq!(stats.blocks, 3);
    assert!(
        blocked(&set, "ad.example")
            && blocked(&set, "hosts.example")
            && blocked(&set, "plain.example")
    );
}

#[test]
fn custom_rules_reject_invalid_domains() {
    let mut b = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    assert!(matches!(
        b.add_block_rule("not a domain"),
        Err(BlocklistError::InvalidDomain(d)) if d == "not a domain"
    ));
    assert!(matches!(
        b.add_allow_rule("1.2.3.4"),
        Err(BlocklistError::InvalidDomain(_))
    ));
}

#[test]
fn entry_limit_applies_to_allow_rules_but_not_to_existing_keys() {
    let limits = FilterLimits {
        max_entries: 2,
        ..FilterLimits::default()
    };
    let mut b = FilterSetBuilder::new(BlockMode::NullIp, limits);
    b.add_allow_rule("a.example").unwrap();
    b.add_block_rule("b.example").unwrap();
    // Re-adding an existing entry is not growth.
    b.add_allow_rule("a.example").unwrap();
    assert!(matches!(
        b.add_allow_rule("c.example"),
        Err(BlocklistError::TooManyEntries(2))
    ));
    assert!(matches!(
        b.add_block_rule("d.example"),
        Err(BlocklistError::TooManyEntries(2))
    ));
}
