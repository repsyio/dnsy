//! Chain-of-trust validator tests against in-memory zones signed with `SigningKey`.

mod fixture;

use dnsy_core::DnssecStatus;
use dnsy_dnssec::{
    Algorithm, DigestType, SigningKey, TrustAnchors, ValidationLimits, Validator, ds_for,
};
use dnsy_proto::{Ds, Message, RData, Rcode, Record, RecordType, ede};
use fixture::{
    INCEPTION, NOW, Net, Zone, a, anchors, block_on, corrupt, msg, n, rec, run, unsigned_soa,
};

use RecordType::{A, Aaaa, Cname, Dnskey, Ds as DsType, Ns, Nsec, Nsec3param, Rrsig, Soa};

/// The root zone and a signed `example.` TLD below it.
struct World {
    root: Zone,
    example: Zone,
    net: Net,
}

fn world() -> World {
    let root = Zone::new(".");
    let example = Zone::new("example.");
    let mut net = Net::default();
    net.zone(&root);
    net.delegate(&root, &example);
    World { root, example, net }
}

impl World {
    fn validator(&self) -> Validator {
        Validator::new(anchors(&self.root))
    }

    fn check(&self, resp: &Message) -> (DnssecStatus, Option<u16>) {
        self.check_with(&self.validator(), resp)
    }

    fn check_with(&self, v: &Validator, resp: &Message) -> (DnssecStatus, Option<u16>) {
        let out = run(v, &self.net, resp);
        (out.status, out.ede.map(|e| e.0))
    }

    /// An unsigned delegation `insecure.example.` proven by an NSEC at the parent.
    fn insecure_child(&mut self) {
        let mut auth = self
            .example
            .nsec("insecure.example.", "www.example.", &[Ns, Rrsig, Nsec]);
        auth.extend(self.example.soa());
        self.net.serve(msg(
            "insecure.example.",
            DsType,
            Rcode::NoError,
            vec![],
            auth,
        ));
        for name in ["www.insecure.example.", "nope.insecure.example."] {
            self.net.serve(msg(
                name,
                DsType,
                Rcode::NoError,
                vec![],
                vec![unsigned_soa("insecure.example.")],
            ));
        }
    }

    fn signed_a(&self, owner: &str) -> Vec<Record> {
        self.example.sign(vec![a(owner)])
    }
}

fn positive(owner: &str, answers: Vec<Record>) -> Message {
    msg(owner, A, Rcode::NoError, answers, vec![])
}

fn concat(parts: Vec<Vec<Record>>) -> Vec<Record> {
    parts.into_iter().flatten().collect()
}

fn apex_types() -> &'static [RecordType] {
    &[Soa, Ns, Dnskey, Nsec3param, Rrsig]
}

#[test]
fn secure_chain_from_root_anchor() {
    let w = world();
    let out = run(
        &w.validator(),
        &w.net,
        &positive("www.example.", w.signed_a("www.example.")),
    );
    assert_eq!(out.status, DnssecStatus::Secure);
    assert_eq!(out.ede, None);
    assert_eq!(out.min_ttl, Some(300));
    assert_eq!(w.net.fetches(), 3, "DS example, DNSKEY ., DNSKEY example");
}

#[test]
fn secure_chain_three_levels_and_dnskey_anchor() {
    let mut w = world();
    let sub = Zone::new("sub.example.");
    w.net.delegate(&w.example, &sub);
    let resp = positive("www.sub.example.", sub.sign(vec![a("www.sub.example.")]));
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));

    let mut ta = TrustAnchors::new();
    ta.add_dnskey(n("."), w.root.ksk.dnskey());
    assert_eq!(
        w.check_with(&Validator::new(ta), &resp),
        (DnssecStatus::Secure, None)
    );
}

#[test]
fn validate_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let w = world();
    let v = w.validator();
    let resp = positive("www.example.", vec![]);
    let fut = v.validate(&w.net, &resp.questions[0], &resp, NOW);
    assert_send(&fut);
    drop(block_on(fut));
}

#[test]
fn insecure_delegation_via_nsec() {
    let mut w = world();
    w.insecure_child();
    let resp = positive("www.insecure.example.", vec![a("www.insecure.example.")]);
    assert_eq!(w.check(&resp), (DnssecStatus::Insecure, None));

    let nx = msg(
        "nope.insecure.example.",
        A,
        Rcode::NxDomain,
        vec![],
        vec![unsigned_soa("insecure.example.")],
    );
    assert_eq!(w.check(&nx), (DnssecStatus::Insecure, None));
}

fn opt_out_world(opt_out: bool) -> World {
    let mut w = world();
    let chain = w.example.nsec3_chain(
        &[("example.", apex_types()), ("www.example.", &[A, Rrsig])],
        opt_out,
        0,
    );
    let mut auth = chain.proof(&w.example, &["example.", "optout.example."]);
    auth.extend(w.example.soa());
    w.net
        .serve(msg("optout.example.", DsType, Rcode::NoError, vec![], auth));
    w.net.serve(msg(
        "www.optout.example.",
        DsType,
        Rcode::NoError,
        vec![],
        vec![unsigned_soa("optout.example.")],
    ));
    w
}

#[test]
fn insecure_delegation_via_nsec3_opt_out() {
    let w = opt_out_world(true);
    let resp = positive("www.optout.example.", vec![a("www.optout.example.")]);
    assert_eq!(w.check(&resp), (DnssecStatus::Insecure, None));
}

#[test]
fn nsec3_without_opt_out_does_not_prove_insecurity() {
    let w = opt_out_world(false);
    let resp = positive("www.optout.example.", vec![a("www.optout.example.")]);
    assert_eq!(
        w.check(&resp),
        (DnssecStatus::Bogus, Some(ede::RRSIGS_MISSING))
    );
}

#[test]
fn nsec3_ds_nodata_in_opt_out_span_is_insecure() {
    let w = world();
    let chain = w
        .example
        .nsec3_chain(&[("example.", apex_types())], true, 0);
    let mut auth = chain.proof(&w.example, &["example.", "optout.example."]);
    auth.extend(w.example.soa());
    let resp = msg("optout.example.", DsType, Rcode::NoError, vec![], auth);
    assert_eq!(w.check(&resp), (DnssecStatus::Insecure, None));
}

#[test]
fn bogus_bad_signature() {
    let w = world();
    let mut answers = w.signed_a("www.example.");
    corrupt(&mut answers);
    assert_eq!(
        w.check(&positive("www.example.", answers)),
        (DnssecStatus::Bogus, Some(ede::DNSSEC_BOGUS))
    );
}

#[test]
fn bogus_expired_rrsig_ede7() {
    let w = world();
    let z = &w.example;
    let expired = z.sign_window(
        vec![a("www.example.")],
        &z.zsk,
        NOW - 10 * 86_400,
        NOW - 86_400,
    );
    assert_eq!(
        w.check(&positive("www.example.", expired)),
        (DnssecStatus::Bogus, Some(ede::SIGNATURE_EXPIRED))
    );
    let future = z.sign_window(
        vec![a("www.example.")],
        &z.zsk,
        NOW + 86_400,
        NOW + 2 * 86_400,
    );
    assert_eq!(
        w.check(&positive("www.example.", future)),
        (DnssecStatus::Bogus, Some(ede::SIGNATURE_NOT_YET_VALID))
    );
}

#[test]
fn clock_skew_is_configurable() {
    let w = world();
    let z = &w.example;
    let just_expired = z.sign_window(vec![a("www.example.")], &z.zsk, INCEPTION, NOW - 100);
    let resp = positive("www.example.", just_expired);
    assert_eq!(w.check(&resp).0, DnssecStatus::Secure, "default skew 300 s");
    let strict = Validator::with_limits(
        anchors(&w.root),
        ValidationLimits {
            clock_skew: 0,
            ..ValidationLimits::default()
        },
    );
    assert_eq!(
        w.check_with(&strict, &resp),
        (DnssecStatus::Bogus, Some(ede::SIGNATURE_EXPIRED))
    );
}

#[test]
fn bogus_missing_ds_dnskey_mismatch() {
    let root = Zone::new(".");
    let example = Zone::new("example.");
    let impostor = Zone::new("example.");
    let mut net = Net::default();
    net.zone(&root);
    net.serve(msg(
        "example.",
        DsType,
        Rcode::NoError,
        root.sign(impostor.ds_rrset()),
        vec![],
    ));
    net.zone(&example);
    let out = run(
        &Validator::new(anchors(&root)),
        &net,
        &positive("www.example.", example.sign(vec![a("www.example.")])),
    );
    assert_eq!(out.status, DnssecStatus::Bogus);
    assert_eq!(out.ede.unwrap().0, ede::DNSKEY_MISSING);
}

#[test]
fn fetch_error_is_indeterminate_not_bogus() {
    let root = Zone::new(".");
    let example = Zone::new("example.");
    let mut net = Net::default();
    net.zone(&root);
    net.serve(msg(
        "example.",
        DsType,
        Rcode::NoError,
        root.sign(example.ds_rrset()),
        vec![],
    ));
    let out = run(
        &Validator::new(anchors(&root)),
        &net,
        &positive("www.example.", example.sign(vec![a("www.example.")])),
    );
    // The DNSKEY fetch failed: a transport problem, not an attack. EDE 5, and the answer is
    // cached only for `indeterminate_ttl`.
    assert_eq!(out.status, DnssecStatus::Indeterminate);
    assert_eq!(out.ede.unwrap().0, ede::DNSSEC_INDETERMINATE);
    assert_eq!(
        out.min_ttl,
        Some(ValidationLimits::default().indeterminate_ttl)
    );

    // The same for a failed DS fetch.
    let w = world();
    let resp = positive("www.example.", w.signed_a("www.example."));
    let mut net = Net::default();
    net.zone(&w.root);
    let out = run(&w.validator(), &net, &resp);
    assert_eq!(out.status, DnssecStatus::Indeterminate);
    assert_eq!(out.ede.unwrap().0, ede::DNSSEC_INDETERMINATE);
    assert!(out.min_ttl.is_some());
}

#[test]
fn bogus_rrsigs_stripped_ede10() {
    let mut w = world();
    let mut auth = w
        .example
        .nsec("www.example.", "zzz.example.", &[A, Rrsig, Nsec]);
    auth.extend(w.example.soa());
    w.net
        .serve(msg("www.example.", DsType, Rcode::NoError, vec![], auth));
    assert_eq!(
        w.check(&positive("www.example.", vec![a("www.example.")])),
        (DnssecStatus::Bogus, Some(ede::RRSIGS_MISSING))
    );
}

#[test]
fn stripped_ds_proof_is_bogus() {
    let mut w = world();
    // The DS answer for www.example. lost its signatures too: no insecurity is proven.
    w.net.serve(msg(
        "www.example.",
        DsType,
        Rcode::NoError,
        vec![],
        vec![unsigned_soa("example.")],
    ));
    assert_eq!(
        w.check(&positive("www.example.", vec![a("www.example.")])),
        (DnssecStatus::Bogus, Some(ede::RRSIGS_MISSING))
    );
}

fn nx(w: &World, qname: &str, auth: Vec<Vec<Record>>) -> Message {
    let mut auth = concat(auth);
    auth.extend(w.example.soa());
    msg(qname, A, Rcode::NxDomain, vec![], auth)
}

#[test]
fn nxdomain_nsec_proof_valid() {
    let w = world();
    let z = &w.example;
    let apex = z.nsec("example.", "mail.example.", &[Soa, Ns, Dnskey, Rrsig, Nsec]);
    let cover = z.nsec("mail.example.", "www.example.", &[A, Rrsig, Nsec]);
    let resp = nx(&w, "nope.example.", vec![cover.clone(), apex]);
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));

    let no_wildcard = nx(&w, "nope.example.", vec![cover.clone()]);
    assert_eq!(
        w.check(&no_wildcard),
        (DnssecStatus::Bogus, Some(ede::NSEC_MISSING))
    );

    let wildcard_exists = nx(
        &w,
        "nope.example.",
        vec![
            cover,
            z.nsec("*.example.", "mail.example.", &[A, Rrsig, Nsec]),
        ],
    );
    assert_eq!(w.check(&wildcard_exists).0, DnssecStatus::Bogus);

    let name_exists = nx(
        &w,
        "mail.example.",
        vec![z.nsec("mail.example.", "www.example.", &[A, Rrsig, Nsec])],
    );
    assert_eq!(w.check(&name_exists).0, DnssecStatus::Bogus);
}

#[test]
fn negative_answer_without_denial() {
    let mut w = world();
    let mut auth = w
        .example
        .nsec("mail.example.", "www.example.", &[A, Rrsig, Nsec]);
    auth.extend(w.example.soa());
    w.net
        .serve(msg("nope.example.", DsType, Rcode::NxDomain, vec![], auth));
    let resp = nx(&w, "nope.example.", vec![]);
    assert_eq!(
        w.check(&resp),
        (DnssecStatus::Bogus, Some(ede::NSEC_MISSING))
    );
}

#[test]
fn nxdomain_nsec3_closest_encloser() {
    let w = world();
    let chain = w.example.nsec3_chain(
        &[("example.", apex_types()), ("www.example.", &[A, Rrsig])],
        false,
        0,
    );
    let proof = chain.proof(&w.example, &["example.", "nope.example.", "*.example."]);
    let resp = nx(&w, "nope.example.", vec![proof]);
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));

    let exists = nx(
        &w,
        "www.example.",
        vec![chain.proof(&w.example, &["www.example."])],
    );
    assert_eq!(w.check(&exists).0, DnssecStatus::Bogus);

    let budget = Validator::with_limits(
        anchors(&w.root),
        ValidationLimits {
            max_nsec3_hashes: 1,
            ..ValidationLimits::default()
        },
    );
    assert_eq!(w.check_with(&budget, &resp).0, DnssecStatus::Bogus);
}

#[test]
fn nxdomain_nsec3_opt_out_is_insecure() {
    let w = world();
    let chain = w.example.nsec3_chain(
        &[("example.", apex_types()), ("www.example.", &[A, Rrsig])],
        true,
        0,
    );
    let proof = chain.proof(&w.example, &["example.", "nope.example.", "*.example."]);
    assert_eq!(
        w.check(&nx(&w, "nope.example.", vec![proof])),
        (DnssecStatus::Insecure, None)
    );
}

#[test]
fn nsec3_high_iterations_insecure() {
    let w = world();
    let chain = w.example.nsec3_chain(
        &[("example.", apex_types()), ("www.example.", &[A, Rrsig])],
        false,
        150,
    );
    let proof = chain.proof(&w.example, &["example.", "nope.example.", "*.example."]);
    assert_eq!(
        w.check(&nx(&w, "nope.example.", vec![proof.clone()])),
        (DnssecStatus::Insecure, None)
    );
    let nodata = msg("www.example.", Aaaa, Rcode::NoError, vec![], proof);
    assert_eq!(w.check(&nodata), (DnssecStatus::Insecure, None));
}

fn nodata(w: &World, qname: &str, qtype: RecordType, auth: Vec<Vec<Record>>) -> Message {
    let mut auth = concat(auth);
    auth.extend(w.example.soa());
    msg(qname, qtype, Rcode::NoError, vec![], auth)
}

#[test]
fn nodata_nsec_bitmap() {
    let w = world();
    let z = &w.example;
    let ok = nodata(
        &w,
        "www.example.",
        Aaaa,
        vec![z.nsec("www.example.", "zzz.example.", &[A, Rrsig, Nsec])],
    );
    assert_eq!(w.check(&ok), (DnssecStatus::Secure, None));

    let lists_type = nodata(
        &w,
        "www.example.",
        Aaaa,
        vec![z.nsec("www.example.", "zzz.example.", &[A, Aaaa, Rrsig, Nsec])],
    );
    assert_eq!(
        w.check(&lists_type),
        (DnssecStatus::Bogus, Some(ede::DNSSEC_BOGUS))
    );

    let cname = nodata(
        &w,
        "www.example.",
        Aaaa,
        vec![z.nsec("www.example.", "zzz.example.", &[Cname, Rrsig, Nsec])],
    );
    assert_eq!(w.check(&cname).0, DnssecStatus::Bogus);

    // A parent-side delegation NSEC cannot prove NODATA for types other than DS.
    let delegation = nodata(
        &w,
        "sub.example.",
        A,
        vec![z.nsec("sub.example.", "zzz.example.", &[Ns, Rrsig, Nsec])],
    );
    assert_eq!(w.check(&delegation).0, DnssecStatus::Bogus);
    let ds = nodata(
        &w,
        "sub.example.",
        DsType,
        vec![z.nsec("sub.example.", "zzz.example.", &[Ns, Rrsig, Nsec])],
    );
    assert_eq!(w.check(&ds), (DnssecStatus::Secure, None));
}

#[test]
fn nodata_empty_non_terminal_and_wildcard_nsec() {
    let w = world();
    let z = &w.example;
    let ent = nodata(
        &w,
        "ent.example.",
        A,
        vec![z.nsec("dog.example.", "a.ent.example.", &[A, Rrsig, Nsec])],
    );
    assert_eq!(w.check(&ent), (DnssecStatus::Secure, None));

    let wild = nodata(
        &w,
        "foo.example.",
        Aaaa,
        vec![z.nsec("*.example.", "www.example.", &[A, Rrsig, Nsec])],
    );
    assert_eq!(w.check(&wild), (DnssecStatus::Secure, None));

    let none = nodata(
        &w,
        "foo.example.",
        Aaaa,
        vec![z.nsec("bar.example.", "www.example.", &[A, Rrsig, Nsec])],
    );
    assert_eq!(
        w.check(&none),
        (DnssecStatus::Bogus, Some(ede::NSEC_MISSING))
    );
}

#[test]
fn nodata_nsec3() {
    let w = world();
    let chain = w.example.nsec3_chain(
        &[
            ("example.", apex_types()),
            ("*.example.", &[A, Rrsig]),
            ("www.example.", &[A, Rrsig]),
        ],
        false,
        0,
    );
    let exact = nodata(
        &w,
        "www.example.",
        Aaaa,
        vec![chain.proof(&w.example, &["www.example."])],
    );
    assert_eq!(w.check(&exact), (DnssecStatus::Secure, None));

    let wild = nodata(
        &w,
        "foo.example.",
        Aaaa,
        vec![chain.proof(&w.example, &["example.", "foo.example.", "*.example."])],
    );
    assert_eq!(w.check(&wild), (DnssecStatus::Secure, None));

    let lists = nodata(
        &w,
        "www.example.",
        A,
        vec![chain.proof(&w.example, &["www.example."])],
    );
    assert_eq!(w.check(&lists).0, DnssecStatus::Bogus);

    let missing = nodata(&w, "foo.example.", Aaaa, vec![]);
    let mut w2 = w;
    let mut auth = w2
        .example
        .nsec("foo.example.", "zzz.example.", &[A, Rrsig, Nsec]);
    auth.extend(w2.example.soa());
    w2.net
        .serve(msg("foo.example.", DsType, Rcode::NoError, vec![], auth));
    assert_eq!(
        w2.check(&missing),
        (DnssecStatus::Bogus, Some(ede::NSEC_MISSING))
    );
}

fn wildcard_answer(w: &World) -> Vec<Record> {
    let mut answers = w.signed_a("*.example.");
    for r in &mut answers {
        r.name = n("foo.example.");
    }
    answers
}

#[test]
fn wildcard_expansion_proof() {
    let w = world();
    let z = &w.example;
    let proof = z.nsec("*.example.", "www.example.", &[A, Rrsig, Nsec]);
    let resp = msg(
        "foo.example.",
        A,
        Rcode::NoError,
        wildcard_answer(&w),
        proof,
    );
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));

    let unproven = positive("foo.example.", wildcard_answer(&w));
    assert_eq!(
        w.check(&unproven),
        (DnssecStatus::Bogus, Some(ede::NSEC_MISSING))
    );

    let wrong = z.nsec("www.example.", "zzz.example.", &[A, Rrsig, Nsec]);
    let resp = msg(
        "foo.example.",
        A,
        Rcode::NoError,
        wildcard_answer(&w),
        wrong,
    );
    assert_eq!(w.check(&resp).0, DnssecStatus::Bogus);
}

#[test]
fn literal_wildcard_owner_needs_no_proof() {
    let w = world();
    let resp = positive("*.example.", w.signed_a("*.example."));
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));
}

#[test]
fn wildcard_expansion_from_too_distant_encloser_is_bogus() {
    // a.b.example. answered from *.example. although b.example. exists.
    let w = world();
    let mut answers = w.signed_a("*.example.");
    for r in &mut answers {
        r.name = n("a.b.example.");
    }
    let proof = w
        .example
        .nsec("b.example.", "c.example.", &[A, Rrsig, Nsec]);
    let resp = msg("a.b.example.", A, Rcode::NoError, answers, proof);
    assert_eq!(
        w.check(&resp),
        (DnssecStatus::Bogus, Some(ede::DNSSEC_BOGUS))
    );
}

#[test]
fn wildcard_expansion_proof_nsec3() {
    let w = world();
    let chain = w.example.nsec3_chain(
        &[
            ("example.", apex_types()),
            ("*.example.", &[A, Rrsig]),
            ("www.example.", &[A, Rrsig]),
        ],
        false,
        0,
    );
    let proof = chain.proof(&w.example, &["foo.example."]);
    let resp = msg(
        "foo.example.",
        A,
        Rcode::NoError,
        wildcard_answer(&w),
        proof,
    );
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));

    let matching = chain.proof(&w.example, &["www.example."]);
    let resp = msg(
        "foo.example.",
        A,
        Rcode::NoError,
        wildcard_answer(&w),
        matching,
    );
    let both_covered = w.check(&resp);
    // www's record may also cover foo's hash; either way the answer is never Insecure.
    assert_ne!(both_covered.0, DnssecStatus::Insecure);

    let high = w.example.nsec3_chain(
        &[("example.", apex_types()), ("*.example.", &[A])],
        false,
        101,
    );
    let resp = msg(
        "foo.example.",
        A,
        Rcode::NoError,
        wildcard_answer(&w),
        high.proof(&w.example, &["foo.example."]),
    );
    assert_eq!(w.check(&resp), (DnssecStatus::Insecure, None));
}

#[test]
fn wildcard_expansion_proof_nsec3_opt_out_is_insecure() {
    let w = world();
    let resp_with = |opt_out: bool| {
        let chain = w.example.nsec3_chain(
            &[
                ("example.", apex_types()),
                ("*.example.", &[A, Rrsig]),
                ("www.example.", &[A, Rrsig]),
            ],
            opt_out,
            0,
        );
        msg(
            "foo.example.",
            A,
            Rcode::NoError,
            wildcard_answer(&w),
            chain.proof(&w.example, &["foo.example."]),
        )
    };
    // The covering NSEC3 may span an unsigned delegation, so the next closer name is not
    // proven absent (RFC 5155 8.8).
    assert_eq!(w.check(&resp_with(true)), (DnssecStatus::Insecure, None));
    assert_eq!(w.check(&resp_with(false)), (DnssecStatus::Secure, None));
}

/// A DNSKEY `RRset` for `zone` with a revoked ZSK, and `www.example.` signed by that ZSK with a
/// key tag matching the revoked key, so only the REVOKE check can reject it.
fn revoked_zsk_world(revoke: bool) -> (World, Message) {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let mut w = world();
    let mut zsk = w.example.zsk.dnskey();
    if revoke {
        zsk.flags |= 0x0080;
    }
    let dnskeys: Vec<Record> = [w.example.ksk.dnskey(), zsk.clone()]
        .into_iter()
        .map(|k| rec("example.", RData::Dnskey(k)))
        .collect();
    let signed_keys = w.example.sign(dnskeys);
    w.net
        .serve(msg("example.", Dnskey, Rcode::NoError, signed_keys, vec![]));

    let rrset = vec![a("www.example.")];
    let mut sig = match w
        .example
        .zsk
        .sign_rrset(
            &rrset,
            &n("example."),
            fixture::INCEPTION,
            fixture::EXPIRATION,
        )
        .unwrap()
        .data
    {
        RData::Rrsig(s) => s,
        _ => unreachable!(),
    };
    sig.key_tag = zsk.key_tag();
    let input = dnsy_proto::canonical::rrset_signing_input(&sig, &rrset);
    let rng = ring::rand::SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &w.example.zsk.to_pkcs8(),
        &rng,
    )
    .unwrap();
    assert_eq!(pair.public_key().as_ref().len(), 65);
    sig.signature = pair.sign(&rng, &input).unwrap().as_ref().to_vec();
    let mut answers = rrset;
    answers.push(rec("www.example.", RData::Rrsig(sig)));
    let resp = positive("www.example.", answers);
    (w, resp)
}

#[test]
fn revoked_zsk_signature_is_bogus() {
    // Control: the same signature under a non-revoked key validates.
    let (w, resp) = revoked_zsk_world(false);
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));
    let (w, resp) = revoked_zsk_world(true);
    assert_eq!(w.check(&resp).0, DnssecStatus::Bogus);
}

/// `example.` after the DS handover: the DNSKEY `RRset` holds the old and the new KSK, signed
/// by the old one when `old_signs` and by the new one when `new_signs`; the parent's DS names
/// the old key when `ds_old`, else the new one.
fn rollover_world(old_signs: bool, new_signs: bool, ds_old: bool) -> World {
    let root = Zone::new(".");
    let example = Zone::new("example.");
    let new_ksk = SigningKey::generate(Algorithm::EcdsaP256Sha256, true).unwrap();
    let mut net = Net::default();
    net.zone(&root);
    let keys: Vec<Record> = [example.ksk.dnskey(), new_ksk.dnskey(), example.zsk.dnskey()]
        .into_iter()
        .map(|k| rec("example.", RData::Dnskey(k)))
        .collect();
    let mut served = keys.clone();
    for key in [(old_signs, &example.ksk), (new_signs, &new_ksk)]
        .into_iter()
        .filter_map(|(on, k)| on.then_some(k))
    {
        served.push(
            key.sign_rrset(
                &keys,
                &n("example."),
                fixture::INCEPTION,
                fixture::EXPIRATION,
            )
            .unwrap(),
        );
    }
    net.serve(msg("example.", Dnskey, Rcode::NoError, served, vec![]));
    let ds_key = if ds_old { &example.ksk } else { &new_ksk };
    let ds = ds_for(&n("example."), &ds_key.dnskey(), DigestType::Sha256).unwrap();
    net.serve(msg(
        "example.",
        DsType,
        Rcode::NoError,
        root.sign(vec![rec("example.", RData::Ds(ds))]),
        vec![],
    ));
    World { root, example, net }
}

#[test]
fn retired_ksk_still_signs_dnskey_rrset() {
    // A validator holding only the old DS (cached at the parent for up to a DS TTL) and one
    // holding only the new DS must both find a valid DNSKEY signature after the handover.
    let probe = |w: &World| {
        w.check(&positive(
            "www.example.",
            w.example.sign(vec![a("www.example.")]),
        ))
    };
    for ds_old in [true, false] {
        assert_eq!(
            probe(&rollover_world(true, true, ds_old)),
            (DnssecStatus::Secure, None),
            "double-signed, DS names the {} key",
            if ds_old { "old" } else { "new" }
        );
    }
    // Signed by the new key alone (what the signer did before): the old DS no longer chains.
    assert_eq!(
        probe(&rollover_world(false, true, false)).0,
        DnssecStatus::Secure
    );
    assert_eq!(
        probe(&rollover_world(false, true, true)).0,
        DnssecStatus::Bogus
    );
}

fn ds_rrset(owner: &str, ds: Ds) -> Vec<Record> {
    vec![rec(owner, RData::Ds(ds))]
}

#[test]
fn unsupported_algorithm_is_insecure() {
    let root = Zone::new(".");
    let example = Zone::new("example.");
    let mut net = Net::default();
    net.zone(&root);
    let ds = Ds {
        key_tag: 1,
        algorithm: 253,
        digest_type: 2,
        digest: vec![0; 32],
    };
    net.serve(msg(
        "example.",
        DsType,
        Rcode::NoError,
        root.sign(ds_rrset("example.", ds)),
        vec![],
    ));
    let out = run(
        &Validator::new(anchors(&root)),
        &net,
        &positive("www.example.", example.sign(vec![a("www.example.")])),
    );
    assert_eq!(out.status, DnssecStatus::Insecure);
    assert_eq!(out.ede.unwrap().0, ede::UNSUPPORTED_DNSKEY_ALG);
}

#[test]
fn unsupported_digest_is_insecure() {
    let root = Zone::new(".");
    let example = Zone::new("example.");
    let mut net = Net::default();
    net.zone(&root);
    let mut ds = ds_for(&example.apex, &example.ksk.dnskey(), DigestType::Sha256).unwrap();
    ds.digest_type = 99;
    net.serve(msg(
        "example.",
        DsType,
        Rcode::NoError,
        root.sign(ds_rrset("example.", ds)),
        vec![],
    ));
    let out = run(
        &Validator::new(anchors(&root)),
        &net,
        &positive("www.example.", example.sign(vec![a("www.example.")])),
    );
    assert_eq!(out.status, DnssecStatus::Insecure);
    assert_eq!(out.ede.unwrap().0, ede::UNSUPPORTED_DS_DIGEST);

    let mut ta = TrustAnchors::new();
    let mut k = root.ksk.dnskey();
    k.algorithm = 200;
    ta.add_dnskey(n("."), k);
    let out = run(&Validator::new(ta), &net, &positive(".", vec![]));
    assert_eq!(out.status, DnssecStatus::Insecure);
    assert_eq!(out.ede.unwrap().0, ede::UNSUPPORTED_DNSKEY_ALG);
}

#[test]
fn sha1_ds_ignored_when_sha256_present() {
    let root = Zone::new(".");
    let example = Zone::new("example.");
    let other = Zone::new("example.");
    let mut net = Net::default();
    net.zone(&root);
    net.zone(&example);
    let good_sha1 = ds_for(&example.apex, &example.ksk.dnskey(), DigestType::Sha1).unwrap();
    let wrong_sha256 = ds_for(&example.apex, &other.ksk.dnskey(), DigestType::Sha256).unwrap();
    let mut set = ds_rrset("example.", good_sha1.clone());
    set.extend(ds_rrset("example.", wrong_sha256));
    net.serve(msg(
        "example.",
        DsType,
        Rcode::NoError,
        root.sign(set),
        vec![],
    ));
    let resp = positive("www.example.", example.sign(vec![a("www.example.")]));
    let out = run(&Validator::new(anchors(&root)), &net, &resp);
    assert_eq!(out.status, DnssecStatus::Bogus);

    let mut net = Net::default();
    net.zone(&root);
    net.zone(&example);
    net.serve(msg(
        "example.",
        DsType,
        Rcode::NoError,
        root.sign(ds_rrset("example.", good_sha1)),
        vec![],
    ));
    let out = run(&Validator::new(anchors(&root)), &net, &resp);
    assert_eq!(out.status, DnssecStatus::Secure);
}

#[test]
fn expired_nta_no_longer_short_circuits() {
    let w = world();
    let mut answers = w.signed_a("www.example.");
    corrupt(&mut answers);
    let resp = positive("www.example.", answers);
    let check = |expires: u32| {
        let mut ta = anchors(&w.root);
        ta.add_negative_until(n("example."), expires);
        block_on(Validator::new(ta).validate(&w.net, &resp.questions[0], &resp, NOW)).status
    };
    assert_eq!(check(NOW + 1), DnssecStatus::Insecure, "still in force");
    assert_eq!(check(NOW), DnssecStatus::Bogus, "expired: validated again");
    assert_eq!(check(NOW - 1000), DnssecStatus::Bogus);
}

#[test]
fn answers_accepted_under_an_expiring_nta_are_capped_at_its_expiry() {
    let w = world();
    let mut answers = w.signed_a("www.example.");
    corrupt(&mut answers);
    let resp = positive("www.example.", answers);
    let run_at = |expires: Option<u32>| {
        let mut ta = anchors(&w.root);
        match expires {
            Some(e) => ta.add_negative_until(n("example."), e),
            None => ta.add_negative(n("example.")),
        }
        block_on(Validator::new(ta).validate(&w.net, &resp.questions[0], &resp, NOW))
    };
    let out = run_at(Some(NOW + 90));
    assert_eq!(out.status, DnssecStatus::Insecure);
    assert_eq!(
        out.min_ttl,
        Some(90),
        "cache for no longer than the NTA lasts"
    );
    assert_eq!(run_at(None).min_ttl, None, "no expiry, no cap");
}

#[test]
fn nta_short_circuits() {
    let w = world();
    let mut ta = anchors(&w.root);
    ta.add_negative(n("example."));
    let v = Validator::new(ta);
    let mut answers = w.signed_a("www.example.");
    corrupt(&mut answers);
    let out = run(&v, &w.net, &positive("www.example.", answers));
    assert_eq!(out.status, DnssecStatus::Insecure);
    assert_eq!(w.net.fetches(), 0);

    // A CNAME from a secure zone into the NTA: that link is insecure.
    let mut w2 = world();
    let other = Zone::new("other.");
    w2.net.delegate(&w2.root, &other);
    let mut ta = anchors(&w2.root);
    ta.add_negative(n("broken.example."));
    let answers = concat(vec![
        other.sign(vec![rec(
            "www.other.",
            RData::Cname(n("x.broken.example.")),
        )]),
        vec![a("x.broken.example.")],
    ]);
    let resp = positive("www.other.", answers);
    assert_eq!(
        w2.check_with(&Validator::new(ta.clone()), &resp),
        (DnssecStatus::Insecure, None)
    );
    let neg = msg(
        "www.other.",
        A,
        Rcode::NxDomain,
        other.sign(vec![rec(
            "www.other.",
            RData::Cname(n("x.broken.example.")),
        )]),
        vec![],
    );
    w2.net = {
        let mut net = Net::default();
        net.zone(&w2.root);
        net.delegate(&w2.root, &other);
        net
    };
    assert_eq!(
        w2.check_with(&Validator::new(ta), &neg),
        (DnssecStatus::Insecure, None)
    );
}

#[test]
fn keytrap_many_keys_bounded() {
    let w = world();
    let mut answers = w.signed_a("www.example.");
    let good = answers.pop().unwrap();
    for i in 0..40u8 {
        let mut bad = good.clone();
        if let RData::Rrsig(s) = &mut bad.data {
            s.signature[0] ^= i.wrapping_add(1);
        }
        answers.push(bad);
    }
    answers.push(good);
    let out = run(&w.validator(), &w.net, &positive("www.example.", answers));
    assert_eq!(out.status, DnssecStatus::Bogus);
    assert!(out.ede.unwrap().1.contains("work limit"));
}

#[test]
fn work_limits_bound_fetches_cuts_and_verifications() {
    let w = world();
    let resp = positive("www.example.", w.signed_a("www.example."));
    let limited = |l: ValidationLimits| Validator::with_limits(anchors(&w.root), l);
    for limits in [
        ValidationLimits {
            max_fetches: 2,
            ..ValidationLimits::default()
        },
        ValidationLimits {
            max_zone_cuts: 0,
            ..ValidationLimits::default()
        },
        ValidationLimits {
            max_verifications: 2,
            ..ValidationLimits::default()
        },
    ] {
        let out = run(&limited(limits), &w.net, &resp);
        assert_eq!(out.status, DnssecStatus::Bogus, "{limits:?}");
        assert!(out.ede.unwrap().1.contains("work limit"), "{limits:?}");
    }
}

#[test]
fn cname_chain_validated_per_link() {
    let mut w = world();
    let other = Zone::new("other.");
    w.net.delegate(&w.root, &other);
    let link = w
        .example
        .sign(vec![rec("www.example.", RData::Cname(n("target.other.")))]);
    let target = other.sign(vec![a("target.other.")]);
    let resp = positive("www.example.", concat(vec![link.clone(), target.clone()]));
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));

    let mut bad_target = target;
    corrupt(&mut bad_target);
    let resp = positive("www.example.", concat(vec![link, bad_target]));
    assert_eq!(w.check(&resp).0, DnssecStatus::Bogus);

    w.insecure_child();
    let to_insecure = w.example.sign(vec![rec(
        "alias.example.",
        RData::Cname(n("www.insecure.example.")),
    )]);
    let resp = positive(
        "alias.example.",
        concat(vec![to_insecure, vec![a("www.insecure.example.")]]),
    );
    assert_eq!(w.check(&resp), (DnssecStatus::Insecure, None));
}

#[test]
fn unrelated_answer_rrsets_are_validated() {
    let mut w = world();
    let mut auth = w
        .example
        .nsec("evil.example.", "zzz.example.", &[A, Rrsig, Nsec]);
    auth.extend(w.example.soa());
    w.net
        .serve(msg("evil.example.", DsType, Rcode::NoError, vec![], auth));
    let answers = concat(vec![w.signed_a("www.example."), vec![a("evil.example.")]]);
    let out = run(&w.validator(), &w.net, &positive("www.example.", answers));
    assert_eq!(out.status, DnssecStatus::Bogus);
}

fn dname(owner: &str, target: &str) -> Record {
    rec(
        owner,
        RData::Opaque {
            rtype: 39,
            data: n(target).as_wire().to_vec(),
        },
    )
}

#[test]
fn dname_chain_validated() {
    let w = world();
    let z = &w.example;
    let link = z.sign(vec![dname("old.example.", "new.example.")]);
    let synth = rec("www.old.example.", RData::Cname(n("www.new.example.")));
    let answers = concat(vec![
        link.clone(),
        vec![synth],
        w.signed_a("www.new.example."),
    ]);
    assert_eq!(
        w.check(&positive("www.old.example.", answers)),
        (DnssecStatus::Secure, None)
    );

    let forged = rec("www.old.example.", RData::Cname(n("www.evil.example.")));
    let answers = concat(vec![
        link.clone(),
        vec![forged],
        w.signed_a("www.evil.example."),
    ]);
    assert_eq!(
        w.check(&positive("www.old.example.", answers)).0,
        DnssecStatus::Bogus
    );

    let answers = concat(vec![link, w.signed_a("www.new.example.")]);
    assert_eq!(
        w.check(&positive("www.old.example.", answers)),
        (DnssecStatus::Secure, None)
    );
}

#[test]
fn signer_must_be_a_zone_apex() {
    let mut w = world();
    let fake = Zone::new("www.example.");
    let mut auth = w
        .example
        .nsec("www.example.", "zzz.example.", &[A, Rrsig, Nsec]);
    auth.extend(w.example.soa());
    w.net
        .serve(msg("www.example.", DsType, Rcode::NoError, vec![], auth));
    let resp = positive("a.www.example.", fake.sign(vec![a("a.www.example.")]));
    assert_eq!(
        w.check(&resp),
        (DnssecStatus::Bogus, Some(ede::DNSSEC_BOGUS))
    );
}

#[test]
fn no_anchor_and_error_rcodes_are_indeterminate() {
    let w = world();
    let resp = positive("www.example.", w.signed_a("www.example."));
    let out = run(&Validator::new(TrustAnchors::new()), &w.net, &resp);
    assert_eq!(out.status, DnssecStatus::Indeterminate);
    assert_eq!(out.ede.unwrap().0, ede::DNSSEC_INDETERMINATE);

    let servfail = msg("www.example.", A, Rcode::ServFail, vec![], vec![]);
    assert_eq!(
        w.check(&servfail),
        (DnssecStatus::Indeterminate, Some(ede::DNSSEC_INDETERMINATE))
    );
}

#[test]
fn ds_query_answered_from_parent() {
    let w = world();
    let resp = msg(
        "example.",
        DsType,
        Rcode::NoError,
        w.root.sign(w.example.ds_rrset()),
        vec![],
    );
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));
    let resp = msg(
        "example.",
        Dnskey,
        Rcode::NoError,
        w.example.sign(w.example.dnskey_rrset()),
        vec![],
    );
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));
    let resp = msg(
        "example.",
        RecordType::Any,
        Rcode::NoError,
        concat(vec![w.example.soa(), w.signed_a("example.")]),
        vec![],
    );
    assert_eq!(w.check(&resp), (DnssecStatus::Secure, None));
}

#[test]
fn ds_walk_rejects_bad_denials() {
    // DS denial claiming a DS exists, unsigned denial, and a missing DS response.
    let mut w = world();
    let mut auth = w.example.nsec(
        "insecure.example.",
        "www.example.",
        &[Ns, DsType, Rrsig, Nsec],
    );
    auth.extend(w.example.soa());
    w.net.serve(msg(
        "insecure.example.",
        DsType,
        Rcode::NoError,
        vec![],
        auth,
    ));
    let resp = positive("insecure.example.", vec![a("insecure.example.")]);
    assert_eq!(w.check(&resp).0, DnssecStatus::Bogus);

    let mut w = world();
    w.net.serve(msg(
        "insecure.example.",
        DsType,
        Rcode::NoError,
        vec![],
        concat(vec![w.example.soa()]),
    ));
    assert_eq!(
        w.check(&resp),
        (DnssecStatus::Bogus, Some(ede::NSEC_MISSING))
    );

    let w = world();
    let out = run(&w.validator(), &w.net, &resp);
    assert_eq!(out.status, DnssecStatus::Indeterminate);
    assert!(out.ede.unwrap().1.contains("fetch failed"));
}

#[test]
fn ds_walk_with_nsec3_and_covering_nsec() {
    // NSEC3 matching a delegation without DS proves insecurity; an NSEC covering the
    // name proves it is not a zone cut.
    let mut w = world();
    let chain = w.example.nsec3_chain(
        &[("example.", apex_types()), ("insecure.example.", &[Ns])],
        false,
        0,
    );
    let mut auth = chain.proof(&w.example, &["insecure.example."]);
    auth.extend(w.example.soa());
    w.net.serve(msg(
        "insecure.example.",
        DsType,
        Rcode::NoError,
        vec![],
        auth,
    ));
    let resp = positive("insecure.example.", vec![a("insecure.example.")]);
    assert_eq!(w.check(&resp), (DnssecStatus::Insecure, None));

    let mut w = world();
    let mut auth = w
        .example
        .nsec("a.example.", "zzz.example.", &[A, Rrsig, Nsec]);
    auth.extend(w.example.soa());
    w.net
        .serve(msg("ghost.example.", DsType, Rcode::NxDomain, vec![], auth));
    let resp = positive("ghost.example.", vec![a("ghost.example.")]);
    assert_eq!(
        w.check(&resp),
        (DnssecStatus::Bogus, Some(ede::RRSIGS_MISSING))
    );

    let mut w = world();
    let chain = w
        .example
        .nsec3_chain(&[("example.", apex_types())], false, 200);
    let mut auth = chain.proof(&w.example, &["example.", "insecure.example."]);
    auth.extend(w.example.soa());
    w.net.serve(msg(
        "insecure.example.",
        DsType,
        Rcode::NoError,
        vec![],
        auth,
    ));
    assert_eq!(
        w.check(&resp_for("insecure.example.")),
        (DnssecStatus::Insecure, None)
    );
}

fn resp_for(owner: &str) -> Message {
    positive(owner, vec![a(owner)])
}

#[test]
fn rrsig_expiry_caps_min_ttl() {
    let w = world();
    let z = &w.example;
    let soon = z.sign_window(vec![a("www.example.")], &z.zsk, INCEPTION, NOW + 60);
    let out = run(&w.validator(), &w.net, &positive("www.example.", soon));
    assert_eq!(out.status, DnssecStatus::Secure);
    assert_eq!(out.min_ttl, Some(60));
}

/// `example.` and its secure child `sub.example.`, both signed with NSEC3.
fn nsec3_parent_and_child() -> (World, Zone, fixture::Nsec3Chain, fixture::Nsec3Chain) {
    let mut w = world();
    let sub = Zone::new("sub.example.");
    w.net.delegate(&w.example, &sub);
    let parent = w.example.nsec3_chain(
        &[
            ("example.", apex_types()),
            ("sub.example.", &[Ns, DsType, Rrsig]),
        ],
        false,
        0,
    );
    let child = sub.nsec3_chain(
        &[
            ("sub.example.", apex_types()),
            ("*.sub.example.", &[A, Rrsig]),
            ("www.sub.example.", &[A, Rrsig]),
        ],
        false,
        0,
    );
    (w, sub, parent, child)
}

#[test]
fn nsec3_proof_cannot_mix_zones() {
    // Forged NXDOMAIN for an existing name: the child's apex NSEC3 plus parent records
    // covering the name and the wildcard.
    let (w, sub, parent, child) = nsec3_parent_and_child();
    let mut auth = child.proof(&sub, &["sub.example."]);
    auth.extend(parent.proof(&w.example, &["www.sub.example.", "*.sub.example."]));
    auth.extend(sub.soa());
    let resp = msg("www.sub.example.", A, Rcode::NxDomain, vec![], auth);
    assert_eq!(w.check(&resp).0, DnssecStatus::Bogus);
}

#[test]
fn wildcard_proof_must_come_from_the_signer_zone() {
    // *.sub.example. replayed as www.sub.example. with a parent NSEC3 covering the name.
    let (w, sub, parent, _) = nsec3_parent_and_child();
    let mut answers = sub.sign(vec![a("*.sub.example.")]);
    for r in &mut answers {
        r.name = n("www.sub.example.");
    }
    let proof = parent.proof(&w.example, &["www.sub.example."]);
    let resp = msg("www.sub.example.", A, Rcode::NoError, answers, proof);
    assert_eq!(
        w.check(&resp),
        (DnssecStatus::Bogus, Some(ede::NSEC_MISSING))
    );
}

#[test]
fn nodata_after_wildcard_cname_into_insecure_zone() {
    let mut w = world();
    w.insecure_child();
    let mut answers = w.example.sign(vec![rec(
        "*.example.",
        RData::Cname(n("www.insecure.example.")),
    )]);
    for r in &mut answers {
        r.name = n("foo.example.");
    }
    let mut auth = w
        .example
        .nsec("*.example.", "www.example.", &[Cname, Rrsig, Nsec]);
    auth.push(unsigned_soa("insecure.example."));
    let resp = msg("foo.example.", Aaaa, Rcode::NoError, answers, auth);
    assert_eq!(w.check(&resp), (DnssecStatus::Insecure, None));
}

#[test]
fn unsigned_extra_record_cannot_downgrade_secure_answer() {
    let mut w = world();
    w.insecure_child();
    let answers = concat(vec![
        w.signed_a("www.example."),
        vec![a("www.insecure.example.")],
    ]);
    assert_eq!(
        w.check(&positive("www.example.", answers)),
        (DnssecStatus::Bogus, Some(ede::DNSSEC_BOGUS))
    );
}
