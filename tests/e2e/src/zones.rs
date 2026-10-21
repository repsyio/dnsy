//! Zone JSON fixtures.

/// A small signed or unsigned zone `origin` (with trailing dot) with the records given as
/// `(name, type, value)`; the SOA minimum is 300 and the default TTL 300.
pub fn zone_json(origin: &str, records: &[(&str, &str, &str)], signed: bool) -> String {
    let rows: Vec<String> = records
        .iter()
        .map(|(n, t, v)| serde_json::json!({"name": n, "type": t, "value": v}).to_string())
        .collect();
    format!(
        r#"{{"schema": 1, "origin": "{origin}", "default_ttl": 300,
  "soa": {{"mname": "ns1.{origin}", "rname": "hostmaster.{origin}", "serial": 1,
          "refresh": 7200, "retry": 3600, "expire": 1209600, "minimum": 300}},
  "records": [{}],
  "dnssec": {{"enabled": {signed}}}}}"#,
        rows.join(",")
    )
}

/// The file stem the server expects for `origin` (`example.test.` becomes `example.test`).
pub fn file_stem(origin: &str) -> String {
    if origin == "." {
        return "_root".to_owned();
    }
    origin.trim_end_matches('.').to_ascii_lowercase()
}

/// The zone most suites use: `example.test.` with a plain host, aliases, a wildcard, a delegation-free
/// tree and a name with enough records to overflow 512 octets.
pub fn example_zone() -> String {
    let many: Vec<(String, &str, String)> = (1..=40)
        .map(|i| ("many".to_owned(), "A", format!("198.51.100.{i}")))
        .collect();
    let mut records: Vec<(&str, &str, &str)> = vec![
        ("www", "A", "192.0.2.7"),
        ("www", "AAAA", "2001:db8::7"),
        ("alias", "CNAME", "www.example.test."),
        ("hop1", "CNAME", "hop2.example.test."),
        ("hop2", "CNAME", "hop3.example.test."),
        ("hop3", "CNAME", "www.example.test."),
        ("out", "CNAME", "elsewhere.invalid."),
        ("*.wild", "A", "192.0.2.99"),
        ("mail", "MX", "10 www.example.test."),
        ("txt", "TXT", "hello world"),
        ("_tcp.srv", "TXT", "only a child, so srv and _tcp exist"),
    ];
    let some: Vec<(String, &str, String)> = (1..=10)
        .map(|i| ("some".to_owned(), "A", format!("198.51.100.{i}")))
        .collect();
    for (n, t, v) in many.iter().chain(&some) {
        records.push((n, t, v));
    }
    zone_json("example.test.", &records, false)
}
