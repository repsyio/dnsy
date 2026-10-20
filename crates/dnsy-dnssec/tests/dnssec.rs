//! DNSSEC crypto tests: RFC 4034/5155/5702/6605/8080 vectors plus behaviour and limits.

mod common;

use common::{Example, examples, lines, n, record};
use dnsy_dnssec::{
    Algorithm, DigestType, DnssecError, MAX_CLOCK_SKEW, MAX_NSEC3_ITERATIONS, SigningKey,
    VerifyError, checked_nsec3_hash, ds_for, nsec3_hash, verify_rrsig, verify_rrsig_with_skew,
};
use dnsy_proto::{
    Class, Dnskey, Name, RData, Record, RecordType, Rrsig, base32hex_encode, canonical,
    parse_timestamp,
};
use ring::signature::{ED25519, UnparsedPublicKey};
use std::net::Ipv4Addr;

fn ts(s: &str) -> u32 {
    parse_timestamp(s).unwrap()
}

fn verify(e: &Example, now: u32) -> Result<(), VerifyError> {
    verify_rrsig(&e.rrset, &e.rrsig, &e.key(), now)
}

fn a_record(owner: &str, ip: [u8; 4]) -> Record {
    Record {
        name: n(owner),
        rtype: RecordType::A,
        class: Class::In,
        ttl: 300,
        data: RData::A(Ipv4Addr::from(ip)),
    }
}

// ---- RFC vectors -------------------------------------------------------------------

#[test]
fn rfc5702_rsasha256_example_verifies() {
    // The RFC's own key is 512 bits, below the 1024-bit floor of ring (see the next test),
    // so algorithm 8 is verified with a 2048-bit key signed by openssl over the same RRset.
    let e = &examples("rsa2048_sha256.txt")[0];
    assert_eq!(e.rrsig.algorithm, 8);
    assert_eq!(e.key().key_tag(), e.rrsig.key_tag);
    assert_eq!(verify(e, ts("20240101000000")), Ok(()));
}

#[test]
fn rfc5702_512_bit_key_is_refused() {
    let e = &examples("rfc5702.txt")[0];
    assert_eq!(e.key().key_tag(), 9033);
    assert_eq!(
        verify(e, ts("20240101000000")),
        Err(VerifyError::UnsupportedKeySize)
    );
}

#[test]
fn rfc5702_rsasha512_example_verifies() {
    let e = &examples("rfc5702.txt")[1];
    assert_eq!(e.key().key_tag(), 3740);
    assert_eq!(e.rrsig.algorithm, 10);
    assert_eq!(verify(e, ts("20240101000000")), Ok(()));
}

#[test]
fn rfc6605_ecdsap256_example_verifies() {
    let e = &examples("rfc6605.txt")[0];
    assert_eq!(e.key().key_tag(), 55648);
    assert_eq!(verify(e, ts("20100901000000")), Ok(()));
}

#[test]
fn rfc6605_ecdsap384_example_verifies() {
    let e = &examples("rfc6605.txt")[1];
    assert_eq!(e.key().key_tag(), 10771);
    assert_eq!(verify(e, ts("20100901000000")), Ok(()));
}

#[test]
fn rfc8080_ed25519_examples_verify() {
    // The RFC prints RRSIG labels as 3 for `example.com.` (two labels); the signatures were
    // made over that value. verify_rrsig rightly refuses it (RFC 4035 5.3.1), so check the
    // RFC signature over the signing input directly with ring.
    let all = examples("rfc8080.txt");
    assert_eq!(all.len(), 2);
    for (e, tag) in all.iter().zip([3613, 35217]) {
        assert_eq!(e.key().key_tag(), tag);
        assert_eq!(e.rrsig.labels, 3);
        assert_eq!(verify(e, 1_439_000_000), Err(VerifyError::InvalidLabels));
        let input = canonical::rrset_signing_input(&e.rrsig, &e.rrset);
        UnparsedPublicKey::new(&ED25519, e.key().public_key)
            .verify(&input, &e.rrsig.signature)
            .expect("RFC 8080 signature verifies over our signing input");
        // The same RRset with the correct labels value, signed by the RFC key, verifies.
        let mut fixed = e.rrsig.clone();
        fixed.labels = 2;
        assert_eq!(
            verify_rrsig(&e.rrset, &fixed, &e.key(), 1_439_000_000),
            Err(VerifyError::BadSignature),
            "labels are part of the signed data"
        );
    }
}

/// PKCS#8 v2 wrapper for a raw Ed25519 seed and public key.
fn ed25519_pkcs8(seed: &[u8], public: &[u8]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
    der.extend_from_slice(public);
    der
}

/// Decodes a base64 string through the DNSKEY presentation parser.
fn base64(text: &str) -> Vec<u8> {
    match RData::parse(RecordType::Dnskey, &format!("257 3 15 {text}")).unwrap() {
        RData::Dnskey(k) => k.public_key,
        _ => unreachable!(),
    }
}

#[test]
fn rfc8080_seeds_give_the_rfc_public_keys_and_sign() {
    // Ed25519 is deterministic: the RFC seeds must reproduce the RFC DNSKEYs, and a
    // signature made with them (with the correct labels) verifies under the RFC key.
    let seeds = common::seeds("rfc8080.txt");
    assert_eq!(seeds.len(), 2);
    for (e, seed) in examples("rfc8080.txt").iter().zip(&seeds) {
        let der = ed25519_pkcs8(&base64(seed), &e.key().public_key);
        let key = SigningKey::from_pkcs8(Algorithm::Ed25519, true, &der).unwrap();
        assert_eq!(key.dnskey(), e.key());
        let record = key
            .sign_rrset(
                &e.rrset,
                &n("example.com."),
                e.rrsig.inception,
                e.rrsig.expiration,
            )
            .unwrap();
        let RData::Rrsig(sig) = &record.data else {
            panic!("not an RRSIG")
        };
        assert_eq!(sig.labels, 2);
        assert_eq!(verify_rrsig(&e.rrset, sig, &e.key(), 1_439_000_000), Ok(()));
    }
}

#[test]
fn rfc4034_ds_example_matches() {
    let ls = lines("rfc4034.txt");
    let key_record = record(&ls[0]);
    let want = common::ds(&record(&ls[1]));
    let key = common::dnskey(&key_record);
    assert_eq!(key.key_tag(), 60485);
    let ds = ds_for(&key_record.name, &key, DigestType::Sha1).unwrap();
    assert_eq!(ds, want);
}

#[test]
fn rfc6605_and_rfc8080_ds_digests_match() {
    for (file, types) in [
        ("rfc6605.txt", vec![DigestType::Sha256, DigestType::Sha384]),
        ("rfc8080.txt", vec![DigestType::Sha256, DigestType::Sha256]),
    ] {
        for (e, dt) in examples(file).iter().zip(types) {
            let want = e.ds.clone().unwrap();
            assert_eq!(ds_for(&e.dnskey_record.name, &e.key(), dt).unwrap(), want);
        }
    }
}

#[test]
fn ds_owner_is_case_folded_and_unknown_digest_rejected() {
    let e = &examples("rfc6605.txt")[0];
    let upper = n("EXAMPLE.NET.");
    assert_eq!(
        ds_for(&upper, &e.key(), DigestType::Sha256).unwrap(),
        e.ds.clone().unwrap()
    );
    assert_eq!(
        ds_for(&upper, &e.key(), DigestType::from(3)),
        Err(DnssecError::UnsupportedDigest(3))
    );
}

#[test]
fn rfc5155_appendix_a_hashes() {
    let vectors = lines("rfc5155_appendix_a.txt");
    assert_eq!(vectors.len(), 12);
    let salt = [0xaa, 0xbb, 0xcc, 0xdd];
    for line in vectors {
        let (name, want) = line.split_once(' ').unwrap();
        let got = nsec3_hash(&n(name), &salt, 12);
        assert_eq!(base32hex_encode(&got).to_lowercase(), want, "{name}");
        // Owner case does not matter.
        let upper = nsec3_hash(&n(&name.to_uppercase()), &salt, 12);
        assert_eq!(got, upper);
    }
}

// ---- verification failures ---------------------------------------------------------

fn ecdsa_example() -> Example {
    examples("rfc6605.txt").remove(0)
}

const NOW: &str = "20100901000000";

#[test]
fn expired_rrsig_rejected() {
    let e = ecdsa_example();
    assert_eq!(verify(&e, ts("20100910000000")), Err(VerifyError::Expired));
}

#[test]
fn not_yet_valid_rrsig_rejected() {
    let e = ecdsa_example();
    assert_eq!(
        verify(&e, ts("20100811000000")),
        Err(VerifyError::NotYetValid)
    );
}

#[test]
fn validity_edges_inclusive_and_skew_widens() {
    let e = ecdsa_example();
    assert_eq!(verify(&e, e.rrsig.inception), Ok(()));
    assert_eq!(verify(&e, e.rrsig.expiration), Ok(()));
    assert_eq!(
        verify(&e, e.rrsig.expiration + 1),
        Err(VerifyError::Expired)
    );
    let key = e.key();
    let late = e.rrsig.expiration + 600;
    assert_eq!(
        verify_rrsig_with_skew(&e.rrset, &e.rrsig, &key, late, 600),
        Ok(())
    );
    assert_eq!(
        verify_rrsig_with_skew(&e.rrset, &e.rrsig, &key, late, 599),
        Err(VerifyError::Expired)
    );
    let early = e.rrsig.inception - 600;
    assert_eq!(
        verify_rrsig_with_skew(&e.rrset, &e.rrsig, &key, early, 600),
        Ok(())
    );
    assert_eq!(
        verify_rrsig_with_skew(&e.rrset, &e.rrsig, &key, early, 599),
        Err(VerifyError::NotYetValid)
    );
    // Skew is capped.
    let way_late = e.rrsig.expiration + MAX_CLOCK_SKEW + 1;
    assert_eq!(
        verify_rrsig_with_skew(&e.rrset, &e.rrsig, &key, way_late, u32::MAX),
        Err(VerifyError::Expired)
    );
}

#[test]
fn tampered_rdata_fails() {
    let mut e = ecdsa_example();
    e.rrset[0].data = RData::A(Ipv4Addr::new(192, 0, 2, 2));
    assert_eq!(verify(&e, ts(NOW)), Err(VerifyError::BadSignature));
}

#[test]
fn tampered_signature_and_ttl_fail() {
    let mut e = ecdsa_example();
    e.rrsig.signature[0] ^= 1;
    assert_eq!(verify(&e, ts(NOW)), Err(VerifyError::BadSignature));
    let mut e = ecdsa_example();
    e.rrsig.original_ttl += 1;
    assert_eq!(verify(&e, ts(NOW)), Err(VerifyError::BadSignature));
    let mut e = ecdsa_example();
    e.rrsig.signature.pop();
    assert_eq!(verify(&e, ts(NOW)), Err(VerifyError::BadSignature));
}

#[test]
fn wrong_key_tag_fails() {
    let mut e = ecdsa_example();
    e.rrsig.key_tag ^= 1;
    assert_eq!(verify(&e, ts(NOW)), Err(VerifyError::KeyTagMismatch));
}

#[test]
fn key_checks() {
    let e = ecdsa_example();
    let now = ts(NOW);
    let check = |edit: &dyn Fn(&mut Dnskey)| {
        let mut k = e.key();
        edit(&mut k);
        verify_rrsig(&e.rrset, &e.rrsig, &k, now)
    };
    assert_eq!(check(&|k| k.flags = 0), Err(VerifyError::NotZoneKey));
    assert_eq!(check(&|k| k.protocol = 2), Err(VerifyError::NotZoneKey));
    assert_eq!(
        check(&|k| k.algorithm = 14),
        Err(VerifyError::AlgorithmMismatch)
    );
    // Wrong public key bytes with a matching tag is impossible to craft cheaply; a different
    // key of the right shape simply fails the signature (and its tag differs).
    assert_eq!(
        check(&|k| k.public_key[10] ^= 1),
        Err(VerifyError::KeyTagMismatch)
    );
}

#[test]
fn malformed_and_unsupported_keys_rejected() {
    let now = ts(NOW);
    let e = ecdsa_example();
    // Re-sign nothing: build RRSIGs whose tag matches the crafted key so key parsing is reached.
    let probe = |alg: u8, public_key: Vec<u8>| {
        let key = Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: alg,
            public_key,
        };
        let mut sig = e.rrsig.clone();
        sig.algorithm = alg;
        sig.key_tag = key.key_tag();
        verify_rrsig(&e.rrset, &sig, &key, now)
    };
    assert_eq!(probe(13, vec![1; 63]), Err(VerifyError::MalformedKey));
    assert_eq!(probe(14, vec![1; 64]), Err(VerifyError::MalformedKey));
    assert_eq!(probe(15, vec![1; 31]), Err(VerifyError::MalformedKey));
    assert_eq!(probe(13, vec![1; 64]), Err(VerifyError::BadSignature));
    assert_eq!(
        probe(5, vec![1; 64]),
        Err(VerifyError::UnsupportedAlgorithm(5))
    );
    for alg in [1, 3, 6, 7, 12, 16] {
        assert_eq!(
            probe(alg, vec![1; 64]),
            Err(VerifyError::UnsupportedAlgorithm(alg))
        );
    }
    // RSA structure: empty, zero exponent length, exponent swallowing the modulus,
    // leading zeros, too small, too large.
    let rsa = |public_key: Vec<u8>| probe(8, public_key);
    assert_eq!(rsa(vec![]), Err(VerifyError::MalformedKey));
    assert_eq!(rsa(vec![0]), Err(VerifyError::MalformedKey));
    assert_eq!(rsa(vec![0, 0]), Err(VerifyError::MalformedKey));
    assert_eq!(rsa(vec![0, 0, 0, 1, 2]), Err(VerifyError::MalformedKey));
    assert_eq!(rsa(vec![3, 1, 0, 1]), Err(VerifyError::MalformedKey));
    assert_eq!(rsa(vec![9, 1, 0, 1]), Err(VerifyError::MalformedKey));
    let mut leading_zero_exp = vec![3, 0, 1, 1];
    leading_zero_exp.extend_from_slice(&[0x80; 128]);
    assert_eq!(rsa(leading_zero_exp), Err(VerifyError::MalformedKey));
    let mut leading_zero_mod = vec![3, 1, 0, 1, 0];
    leading_zero_mod.extend_from_slice(&[0x80; 128]);
    assert_eq!(rsa(leading_zero_mod), Err(VerifyError::MalformedKey));
    let sized = |bytes: usize, first: u8| {
        let mut k = vec![3, 1, 0, 1, first];
        k.extend(std::iter::repeat_n(0x55, bytes - 1));
        k
    };
    assert_eq!(rsa(sized(127, 0xff)), Err(VerifyError::UnsupportedKeySize));
    assert_eq!(rsa(sized(1025, 0xff)), Err(VerifyError::UnsupportedKeySize));
    // 16-bit exponent length form, and a well-formed but meaningless key: plain bad signature.
    let mut long_form = vec![0, 0, 3, 1, 0, 1, 0xff];
    long_form.extend(std::iter::repeat_n(0x55, 127));
    assert_eq!(rsa(long_form), Err(VerifyError::BadSignature));
    for alg in [8, 10] {
        for bytes in [128, 256] {
            assert_eq!(
                probe(alg, sized(bytes, 0xff)),
                Err(VerifyError::BadSignature),
                "{alg}/{bytes}"
            );
        }
    }
}

#[test]
fn rrset_shape_checks() {
    let e = ecdsa_example();
    let key = e.key();
    let now = ts(NOW);
    let go = |rrset: &[Record], sig: &Rrsig| verify_rrsig(rrset, sig, &key, now);
    assert_eq!(go(&[], &e.rrsig), Err(VerifyError::EmptyRrset));

    let mut other_owner = e.rrset.clone();
    other_owner.push(a_record("ftp.example.net.", [192, 0, 2, 9]));
    assert_eq!(go(&other_owner, &e.rrsig), Err(VerifyError::RrsetMismatch));

    let mut other_class = e.rrset.clone();
    other_class.push(Record {
        class: Class::Ch,
        ..a_record("www.example.net.", [1, 1, 1, 1])
    });
    assert_eq!(go(&other_class, &e.rrsig), Err(VerifyError::RrsetMismatch));

    let mut wrong_type = e.rrsig.clone();
    wrong_type.type_covered = RecordType::Aaaa;
    assert_eq!(go(&e.rrset, &wrong_type), Err(VerifyError::RrsetMismatch));
    wrong_type.type_covered = RecordType::Rrsig;
    assert_eq!(go(&e.rrset, &wrong_type), Err(VerifyError::RrsetMismatch));

    let mut lying = e.rrset.clone();
    lying[0].rtype = RecordType::Aaaa;
    assert_eq!(go(&lying, &e.rrsig), Err(VerifyError::RrsetMismatch));

    let mut labels = e.rrsig.clone();
    labels.labels = 4;
    assert_eq!(go(&e.rrset, &labels), Err(VerifyError::InvalidLabels));

    let mut signer = e.rrsig.clone();
    signer.signer = n("example.org.");
    assert_eq!(go(&e.rrset, &signer), Err(VerifyError::SignerNotAncestor));
    signer.signer = n("sub.www.example.net.");
    assert_eq!(go(&e.rrset, &signer), Err(VerifyError::SignerNotAncestor));
}

#[test]
fn owner_case_does_not_affect_verification() {
    let mut e = ecdsa_example();
    e.rrset[0].name = n("WWW.Example.NET.");
    assert_eq!(verify(&e, ts(NOW)), Ok(()));
}

#[test]
fn rrset_order_and_duplicates_do_not_matter() {
    let key = SigningKey::generate(Algorithm::Ed25519, false).unwrap();
    let rrset = vec![
        a_record("www.example.org.", [10, 0, 0, 2]),
        a_record("www.example.org.", [10, 0, 0, 1]),
    ];
    let sig = key
        .sign_rrset(&rrset, &n("example.org."), 1000, 2000)
        .unwrap();
    let RData::Rrsig(sig) = sig.data else {
        panic!()
    };
    let mut reordered = rrset.clone();
    reordered.reverse();
    reordered.push(reordered[0].clone());
    assert_eq!(verify_rrsig(&reordered, &sig, &key.dnskey(), 1500), Ok(()));
}

// ---- signing -----------------------------------------------------------------------

#[test]
fn sign_then_verify_ecdsa_and_ed25519() {
    for (alg, ksk) in [
        (Algorithm::EcdsaP256Sha256, false),
        (Algorithm::Ed25519, true),
    ] {
        let key = SigningKey::generate(alg, ksk).unwrap();
        assert_eq!(key.algorithm(), alg);
        let dnskey = key.dnskey();
        assert_eq!(dnskey.flags, if ksk { 257 } else { 256 });
        assert_eq!(dnskey.protocol, 3);
        assert_eq!(dnskey.algorithm, alg.number());
        assert!(dnskey.is_zone_key());
        assert_eq!(dnskey.is_sep(), ksk);

        let rrset = vec![a_record("www.example.org.", [192, 0, 2, 1])];
        let record = key
            .sign_rrset(&rrset, &n("example.org."), 1000, 5000)
            .unwrap();
        assert_eq!(record.name, rrset[0].name);
        assert_eq!(record.rtype, RecordType::Rrsig);
        assert_eq!(record.ttl, 300);
        let RData::Rrsig(sig) = &record.data else {
            panic!("not an RRSIG")
        };
        assert_eq!(sig.labels, 3);
        assert_eq!(sig.key_tag, dnskey.key_tag());
        assert_eq!(verify_rrsig(&rrset, sig, &dnskey, 2000), Ok(()));
        assert_eq!(
            verify_rrsig(&rrset, sig, &dnskey, 6000),
            Err(VerifyError::Expired)
        );

        // A different key does not verify.
        let other = SigningKey::generate(alg, ksk).unwrap().dnskey();
        let mut forged = sig.clone();
        forged.key_tag = other.key_tag();
        assert!(verify_rrsig(&rrset, &forged, &other, 2000).is_err());
    }
}

#[test]
fn wildcard_owner_signs_and_verifies_when_expanded() {
    let key = SigningKey::generate(Algorithm::EcdsaP256Sha256, false).unwrap();
    let wild = vec![a_record("*.example.org.", [192, 0, 2, 7])];
    let RData::Rrsig(sig) = key
        .sign_rrset(&wild, &n("example.org."), 10, 20)
        .unwrap()
        .data
    else {
        panic!()
    };
    assert_eq!(sig.labels, 2, "the wildcard label is not counted");
    assert_eq!(verify_rrsig(&wild, &sig, &key.dnskey(), 15), Ok(()));
    let expanded = vec![a_record("a.b.example.org.", [192, 0, 2, 7])];
    // `a.b` has two labels below the zone, but the RRSIG covers `*.example.org`.
    assert_eq!(
        verify_rrsig(&expanded, &sig, &key.dnskey(), 15),
        Ok(()),
        "owner is rewritten to the wildcard"
    );
}

#[test]
fn signing_rsa_unsupported_error() {
    for alg in [Algorithm::RsaSha256, Algorithm::RsaSha512] {
        assert_eq!(
            SigningKey::generate(alg, false).unwrap_err(),
            DnssecError::UnsupportedAlgorithm(alg.number())
        );
        assert_eq!(
            SigningKey::from_pkcs8(alg, false, &[0x30, 0x00]).unwrap_err(),
            DnssecError::UnsupportedAlgorithm(alg.number())
        );
    }
    assert_eq!(
        SigningKey::generate(Algorithm::EcdsaP384Sha384, false).unwrap_err(),
        DnssecError::UnsupportedAlgorithm(14)
    );
}

#[test]
fn pkcs8_round_trip_and_garbage_rejected() {
    for alg in [Algorithm::EcdsaP256Sha256, Algorithm::Ed25519] {
        let key = SigningKey::generate(alg, true).unwrap();
        let der = key.to_pkcs8();
        let again = SigningKey::from_pkcs8(alg, true, &der).unwrap();
        assert_eq!(again.dnskey(), key.dnskey());
        assert_eq!(
            SigningKey::from_pkcs8(alg, true, &[]).unwrap_err(),
            DnssecError::InvalidKey
        );
        assert_eq!(
            SigningKey::from_pkcs8(alg, true, &der[..der.len() - 1]).unwrap_err(),
            DnssecError::InvalidKey
        );
        // An Ed25519 document is not an ECDSA one and vice versa.
        let other = if alg == Algorithm::Ed25519 {
            Algorithm::EcdsaP256Sha256
        } else {
            Algorithm::Ed25519
        };
        assert!(SigningKey::from_pkcs8(other, true, &der).is_err());
    }
}

#[test]
fn ed25519_pkcs8_with_mismatched_public_key_rejected() {
    let key = SigningKey::generate(Algorithm::Ed25519, false).unwrap();
    let mut der = key.to_pkcs8().to_vec();
    let last = der.len() - 1;
    der[last] ^= 1;
    assert_eq!(
        SigningKey::from_pkcs8(Algorithm::Ed25519, false, &der).unwrap_err(),
        DnssecError::InvalidKey
    );
}

#[test]
fn debug_never_prints_key_material() {
    let key = SigningKey::generate(Algorithm::Ed25519, true).unwrap();
    let text = format!("{key:?}");
    assert!(text.contains("Ed25519") && text.contains("ksk"));
    let der = key.to_pkcs8();
    let hex = der
        .iter()
        .fold(String::new(), |acc, b| acc + &format!("{b:02x}"));
    assert!(!text.contains(&hex[hex.len() - 16..]));
    assert!(!text.contains("pkcs8") && !text.contains("pair"));
}

#[test]
fn sign_rrset_rejects_bad_input() {
    let key = SigningKey::generate(Algorithm::Ed25519, false).unwrap();
    let zone = n("example.org.");
    let a = a_record("www.example.org.", [1, 2, 3, 4]);
    let sign = |rrset: &[Record], signer: &Name, i, e| key.sign_rrset(rrset, signer, i, e);
    let invalid = |r: Result<Record, DnssecError>| {
        assert!(matches!(r, Err(DnssecError::InvalidRrset(_))), "{r:?}");
    };
    invalid(sign(&[], &zone, 1, 2));
    invalid(sign(
        &[a.clone(), a_record("ftp.example.org.", [1, 2, 3, 4])],
        &zone,
        1,
        2,
    ));
    invalid(sign(
        &[
            a.clone(),
            Record {
                class: Class::Ch,
                ..a.clone()
            },
        ],
        &zone,
        1,
        2,
    ));
    invalid(sign(std::slice::from_ref(&a), &n("example.net."), 1, 2));
    invalid(sign(
        std::slice::from_ref(&a),
        &n("a.www.example.org."),
        1,
        2,
    ));
    let mut wrong = a.clone();
    wrong.rtype = RecordType::Aaaa;
    invalid(sign(&[wrong], &zone, 1, 2));
    let rrsig_record = key
        .sign_rrset(std::slice::from_ref(&a), &zone, 1, 2)
        .unwrap();
    invalid(sign(&[rrsig_record], &zone, 1, 2));
    assert_eq!(
        sign(std::slice::from_ref(&a), &zone, 5, 5),
        Err(DnssecError::InvalidValidity)
    );
    assert_eq!(
        sign(std::slice::from_ref(&a), &zone, 6, 5),
        Err(DnssecError::InvalidValidity)
    );
    // Serial arithmetic: expiration may wrap past u32::MAX.
    assert!(sign(&[a], &zone, u32::MAX - 5, 5).is_ok());
}

// ---- NSEC3 limits and error text ---------------------------------------------------

#[test]
fn nsec3_iteration_and_salt_limits() {
    let name = n("example.");
    let ok = checked_nsec3_hash(&name, &[1, 2], 12, MAX_NSEC3_ITERATIONS).unwrap();
    assert_eq!(ok, nsec3_hash(&name, &[1, 2], 12));
    assert_eq!(
        checked_nsec3_hash(&name, &[], MAX_NSEC3_ITERATIONS + 1, MAX_NSEC3_ITERATIONS),
        Err(DnssecError::Nsec3IterationsTooHigh {
            iterations: MAX_NSEC3_ITERATIONS + 1,
            max: MAX_NSEC3_ITERATIONS
        })
    );
    assert!(checked_nsec3_hash(&name, &[], MAX_NSEC3_ITERATIONS, MAX_NSEC3_ITERATIONS).is_ok());
    assert_eq!(
        checked_nsec3_hash(&name, &[0; 256], 0, MAX_NSEC3_ITERATIONS),
        Err(DnssecError::Nsec3SaltTooLong)
    );
    assert!(checked_nsec3_hash(&name, &[0; 255], 0, MAX_NSEC3_ITERATIONS).is_ok());
    // Iterations and salt both change the hash.
    assert_ne!(nsec3_hash(&name, &[], 0), nsec3_hash(&name, &[], 1));
    assert_ne!(nsec3_hash(&name, &[], 0), nsec3_hash(&name, &[1], 0));
    // The root name hashes too.
    let _ = nsec3_hash(&Name::root(), &[], u16::MAX);
}

#[test]
fn error_messages_are_descriptive() {
    let verify_errors = [
        VerifyError::EmptyRrset,
        VerifyError::RrsetMismatch,
        VerifyError::InvalidLabels,
        VerifyError::SignerNotAncestor,
        VerifyError::NotZoneKey,
        VerifyError::AlgorithmMismatch,
        VerifyError::KeyTagMismatch,
        VerifyError::NotYetValid,
        VerifyError::Expired,
        VerifyError::UnsupportedAlgorithm(5),
        VerifyError::MalformedKey,
        VerifyError::UnsupportedKeySize,
        VerifyError::BadSignature,
    ];
    for e in verify_errors {
        assert_ne!(e.to_string(), "");
        let _: &dyn std::error::Error = &e;
    }
    let dnssec_errors = [
        DnssecError::UnsupportedAlgorithm(8),
        DnssecError::UnsupportedDigest(3),
        DnssecError::InvalidKey,
        DnssecError::KeyGeneration,
        DnssecError::InvalidRrset("why"),
        DnssecError::InvalidValidity,
        DnssecError::SigningFailed,
        DnssecError::Nsec3IterationsTooHigh {
            iterations: 9,
            max: 1,
        },
        DnssecError::Nsec3SaltTooLong,
    ];
    for e in dnssec_errors {
        assert_ne!(e.to_string(), "");
        let _: &dyn std::error::Error = &e;
    }
    assert!(DnssecError::InvalidRrset("why").to_string().contains("why"));
}
