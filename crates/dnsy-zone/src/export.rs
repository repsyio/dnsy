//! BIND master-file export.
//!
//! Every name and character-string written here is escaped for master-file syntax, so no zone
//! content (a label with `;`, a newline or `$` in a TXT string, ...) can end a line, open a
//! comment or inject a directive.

use std::cmp::Ordering;
use std::fmt::Write as _;

use dnsy_proto::{Name, RData, RecordType, WireWriter};

use crate::model::{Record, Zone};

/// DNSSEC records produced by signing a zone (DNSKEY, RRSIG, NSEC/NSEC3, NSEC3PARAM), appended
/// to the export in canonical order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedZone {
    pub records: Vec<Record>,
}

const MAX_CHAR_STRING: usize = 255;

/// Writes a name as master-file text: absolute, with every byte that is special in a master
/// file (`. \ ; ( ) " $ @`) backslash-escaped and non-printable bytes as `\DDD`.
fn write_labels<'a>(out: &mut String, labels: impl Iterator<Item = &'a [u8]>, trailing_dot: bool) {
    let mut first = true;
    for label in labels {
        if !first {
            out.push('.');
        }
        first = false;
        for &b in label {
            match b {
                b'.' | b'\\' | b';' | b'(' | b')' | b'"' | b'$' | b'@' => {
                    out.push('\\');
                    out.push(char::from(b));
                }
                0x21..=0x7e => out.push(char::from(b)),
                _ => {
                    let _ = write!(out, "\\{b:03}");
                }
            }
        }
    }
    if trailing_dot {
        out.push('.');
    }
}

fn absolute(out: &mut String, name: &Name) {
    if name.is_root() {
        out.push('.');
    } else {
        write_labels(out, name.labels(), true);
    }
}

fn owner(out: &mut String, name: &Name, origin: &Name) {
    if name == origin {
        out.push('@');
        return;
    }
    let keep = usize::from(name.label_count()) - usize::from(origin.label_count());
    write_labels(out, name.labels().take(keep), false);
}

fn quoted(out: &mut String, data: &[u8]) {
    out.push('"');
    for &b in data {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
    out.push('"');
}

fn generic(out: &mut String, data: &[u8]) {
    let _ = write!(out, "\\# {}", data.len());
    if !data.is_empty() {
        out.push(' ');
        for b in data {
            let _ = write!(out, "{b:02X}");
        }
    }
}

fn type_name(t: RecordType) -> String {
    match t {
        RecordType::A => "A".into(),
        RecordType::Ns => "NS".into(),
        RecordType::Cname => "CNAME".into(),
        RecordType::Soa => "SOA".into(),
        RecordType::Ptr => "PTR".into(),
        RecordType::Mx => "MX".into(),
        RecordType::Txt => "TXT".into(),
        RecordType::Aaaa => "AAAA".into(),
        RecordType::Srv => "SRV".into(),
        RecordType::Ds => "DS".into(),
        RecordType::Rrsig => "RRSIG".into(),
        RecordType::Nsec => "NSEC".into(),
        RecordType::Dnskey => "DNSKEY".into(),
        RecordType::Nsec3 => "NSEC3".into(),
        RecordType::Nsec3param => "NSEC3PARAM".into(),
        RecordType::Cds => "CDS".into(),
        RecordType::Cdnskey => "CDNSKEY".into(),
        RecordType::Caa => "CAA".into(),
        other => format!("TYPE{}", u16::from(other)),
    }
}

fn rdata(out: &mut String, data: &RData) {
    match data {
        RData::A(ip) => {
            let _ = write!(out, "{ip}");
        }
        RData::Aaaa(ip) => {
            let _ = write!(out, "{ip}");
        }
        RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => absolute(out, n),
        RData::Mx {
            preference,
            exchange,
        } => {
            let _ = write!(out, "{preference} ");
            absolute(out, exchange);
        }
        RData::Txt(strings) => {
            let mut first = true;
            for s in strings {
                // A single character-string is at most 255 octets in a master file.
                let mut chunks: Vec<&[u8]> = s.chunks(MAX_CHAR_STRING).collect();
                if chunks.is_empty() {
                    chunks.push(&[]);
                }
                for chunk in chunks {
                    if !first {
                        out.push(' ');
                    }
                    first = false;
                    quoted(out, chunk);
                }
            }
            if first {
                out.push_str("\"\"");
            }
        }
        RData::Soa(s) => {
            absolute(out, &s.mname);
            out.push(' ');
            absolute(out, &s.rname);
            let _ = write!(
                out,
                " {} {} {} {} {}",
                s.serial, s.refresh, s.retry, s.expire, s.minimum
            );
        }
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            let _ = write!(out, "{priority} {weight} {port} ");
            absolute(out, target);
        }
        RData::Caa { flags, tag, value } => {
            let plain_tag = !tag.is_empty()
                && tag.len() <= MAX_CHAR_STRING
                && tag.bytes().all(|b| b.is_ascii_alphanumeric())
                && value.len() <= MAX_CHAR_STRING;
            if plain_tag {
                let _ = write!(out, "{flags} {tag} ");
                quoted(out, value);
            } else {
                let mut raw = vec![*flags];
                raw.push(u8::try_from(tag.len()).unwrap_or(u8::MAX));
                raw.extend_from_slice(tag.as_bytes());
                raw.extend_from_slice(value);
                generic(out, &raw);
            }
        }
        RData::Opaque { data, .. } => generic(out, data),
        // DNSSEC types: the proto presentation text is used when it holds nothing that is
        // special in a master file (a signer or next name with `;`, `(`, `"`, ...);
        // otherwise the RFC 3597 generic form is written, which is always safe.
        other => {
            let text = other.to_string();
            let plain = text
                .bytes()
                .all(|b| (0x20..0x7f).contains(&b) && !b";()\"$@\\".contains(&b));
            let mut w = WireWriter::new();
            if plain {
                out.push_str(&text);
            } else if other.encode(&mut w).is_ok() {
                generic(out, &w.finish());
            } else {
                out.push_str("\\# 0");
            }
        }
    }
}

fn line(out: &mut String, name: &Name, ttl: Option<u32>, data: &RData, origin: &Name) {
    owner(out, name, origin);
    out.push('\t');
    if let Some(ttl) = ttl {
        let _ = write!(out, "{ttl}");
    }
    out.push_str("\tIN\t");
    out.push_str(&type_name(data.rtype()));
    out.push('\t');
    rdata(out, data);
    out.push('\n');
}

/// Canonical name order (RFC 4034 6.1): compare labels from the right, case-insensitively.
fn canonical_cmp(a: &Name, b: &Name) -> Ordering {
    let key = |n: &Name| -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = n.labels().map(<[u8]>::to_ascii_lowercase).collect();
        v.reverse();
        v
    };
    key(a).cmp(&key(b))
}

/// Exports a zone as a BIND master file. Records are grouped by owner (in order of first
/// appearance); the SOA comes first. With `signed`, the DNSSEC records follow in canonical
/// order (owner, then type).
#[must_use]
pub fn export_bind(zone: &Zone, signed: Option<&SignedZone>) -> String {
    let mut out = String::new();
    out.push_str("$ORIGIN ");
    absolute(&mut out, &zone.origin);
    let _ = write!(out, "\n$TTL {}\n", zone.default_ttl);

    // SOA, multi-line.
    let soa = &zone.soa;
    out.push_str("@\t");
    if zone.soa_ttl != zone.default_ttl {
        let _ = write!(out, "{}", zone.soa_ttl);
    }
    out.push_str("\tIN\tSOA\t");
    absolute(&mut out, &soa.mname);
    out.push(' ');
    absolute(&mut out, &soa.rname);
    let _ = write!(
        out,
        " (\n\t\t\t{} ; serial\n\t\t\t{} ; refresh\n\t\t\t{} ; retry\n\t\t\t{} ; expire\n\t\t\t{} ; minimum\n\t\t\t)\n",
        soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
    );

    let mut owners: Vec<&Name> = Vec::new();
    for r in &zone.records {
        if !owners.contains(&&r.name) {
            owners.push(&r.name);
        }
    }
    for name in owners {
        for r in zone.records.iter().filter(|r| &r.name == name) {
            let ttl = (r.ttl != zone.default_ttl).then_some(r.ttl);
            line(&mut out, &r.name, ttl, &r.rdata, &zone.origin);
        }
    }

    if let Some(signed) = signed {
        let mut extra: Vec<&Record> = signed
            .records
            .iter()
            .filter(|r| r.name.is_subdomain_of(&zone.origin))
            .collect();
        extra.sort_by(|a, b| {
            canonical_cmp(&a.name, &b.name)
                .then_with(|| u16::from(a.rdata.rtype()).cmp(&u16::from(b.rdata.rtype())))
        });
        for r in extra {
            line(&mut out, &r.name, Some(r.ttl), &r.rdata, &zone.origin);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../tests/fixtures/example.com.json");

    fn zone(json: &str) -> Zone {
        Zone::from_json(json).unwrap().0
    }

    #[test]
    fn export_snapshot_example_zone() {
        insta::assert_snapshot!(export_bind(&zone(EXAMPLE), None));
    }

    fn hostile_zone() -> Zone {
        let mut z = zone(EXAMPLE);
        let origin = z.origin.clone();
        let evil = Name::from_labels([
            b"a;b".to_vec(),
            b"x y\nz".to_vec(),
            b"$ORIGIN".to_vec(),
            b"(@)".to_vec(),
        ])
        .unwrap();
        let name = Name::from_labels(
            evil.labels()
                .chain(origin.labels())
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        z.records.push(Record {
            name: name.clone(),
            ttl: 60,
            rdata: RData::Txt(vec![
                b"line1\nexample.org. 60 IN A 6.6.6.6\n$INCLUDE /etc/passwd".to_vec(),
                b"q\"uote\\ ; (paren)".to_vec(),
                vec![b'x'; 600],
            ]),
        });
        z.records.push(Record {
            name: Name::from_ascii("alias.example.com.").unwrap(),
            ttl: 60,
            rdata: RData::Cname(name),
        });
        z.records.push(Record {
            name: Name::from_labels(
                [b"$INCLUDE".to_vec()]
                    .into_iter()
                    .chain(origin.labels().map(<[u8]>::to_vec)),
            )
            .unwrap(),
            ttl: 60,
            rdata: RData::Caa {
                flags: 0,
                tag: "bad tag\n$ORIGIN x.".into(),
                value: b"v\nw".to_vec(),
            },
        });
        z
    }

    #[test]
    fn export_escapes_txt() {
        let text = export_bind(&hostile_zone(), None);
        for line in text.lines() {
            // No injected directive or extra record: every line is known-good structure.
            let ok = line.starts_with("$ORIGIN example.com.")
                || line.starts_with("$TTL ")
                || line.starts_with('\t')
                || line.contains("\tIN\t");
            assert!(ok, "unexpected line {line:?}");
            assert!(!line.starts_with("$INCLUDE") && line != "$ORIGIN x.");
            assert!(!line.starts_with("example.org."));
        }
        assert_eq!(
            text.matches("$ORIGIN").count(),
            1 + text.matches("\\$ORIGIN").count()
        );
        assert!(text.contains("\\010"), "newline escaped as decimal");
        assert!(text.contains(r#"q\"uote\\ ; (paren)"#));
        // 600 x bytes split into 255 + 255 + 90.
        assert!(text.contains(&format!(
            "\"{}\" \"{}\" \"{}\"",
            "x".repeat(255),
            "x".repeat(255),
            "x".repeat(90)
        )));
        assert!(
            text.contains("\\# "),
            "bad CAA tag falls back to generic form"
        );
        assert!(text.contains("\\$INCLUDE"));
    }

    #[test]
    fn owner_names_are_relative_and_origin_is_at() {
        let text = export_bind(&zone(EXAMPLE), None);
        assert!(text.contains("\nwww\t300\tIN\tA\t192.0.2.1\n"));
        assert!(text.contains("\n@\t\tIN\tNS\tns1.example.com.\n"));
        assert!(text.starts_with("$ORIGIN example.com.\n$TTL 3600\n@\t\tIN\tSOA"));
    }

    #[test]
    fn signed_records_appended_in_canonical_order() {
        let z = zone(EXAMPLE);
        let mk = |n: &str, t: u16| Record {
            name: Name::from_ascii(n).unwrap(),
            ttl: 3600,
            rdata: RData::Opaque {
                rtype: t,
                data: vec![1, 2],
            },
        };
        let signed = SignedZone {
            records: vec![
                mk("www.example.com.", 46),
                mk("example.com.", 48),
                mk("example.com.", 47),
                mk("evil.org.", 48),
            ],
        };
        let text = export_bind(&z, Some(&signed));
        let tail: Vec<&str> = text.lines().rev().take(3).collect();
        assert!(tail[0].starts_with("www\t3600\tIN\tRRSIG"));
        assert!(tail[1].starts_with("@\t3600\tIN\tDNSKEY"));
        assert!(tail[2].starts_with("@\t3600\tIN\tNSEC"));
        assert!(!text.contains("evil"));
    }

    #[test]
    fn signed_rdata_with_special_names_uses_generic_form() {
        let z = zone(EXAMPLE);
        let nsec = |next: Name| Record {
            name: Name::from_ascii("example.com.").unwrap(),
            ttl: 300,
            rdata: RData::Nsec {
                next,
                types: dnsy_proto::TypeBitmap::from_types(&[RecordType::A]),
            },
        };
        let plain = Name::from_ascii("www.example.com.").unwrap();
        let evil = Name::from_labels([b"a;\n$INCLUDE".to_vec(), b"com".to_vec()]).unwrap();
        let signed = SignedZone {
            records: vec![nsec(plain), nsec(evil)],
        };
        let text = export_bind(&z, Some(&signed));
        let lines: Vec<&str> = text.lines().filter(|l| l.contains("NSEC")).collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().any(|l| l.contains("www.example.com. A")));
        assert!(lines.iter().any(|l| l.contains("\\# ")));
        assert!(!text.contains("$INCLUDE"));
    }

    #[test]
    fn named_checkzone_accepts_export() {
        let have = std::process::Command::new("named-checkzone")
            .arg("-v")
            .output()
            .is_ok();
        if !have {
            eprintln!("named-checkzone not installed, skipping");
            return;
        }
        for z in [zone(EXAMPLE), hostile_zone()] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("zone.db");
            std::fs::write(&path, export_bind(&z, None)).unwrap();
            let out = std::process::Command::new("named-checkzone")
                .arg("example.com")
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
    }
}
