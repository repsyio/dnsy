# Glossary

| Term | Meaning |
| --- | --- |
| ACL | access control list: rules deciding per client address or mTLS certificate whether a query is allowed, refused or dropped |
| AD | "authenticated data" header flag, set on answers DNSY validated as secure |
| Authoritative | an answer from a zone DNSY serves itself (AA flag), as opposed to forwarded |
| Bogus | a DNSSEC validation failure: signatures that do not verify, expired signatures, missing proofs |
| CD | "checking disabled" header flag: the client asks for data without validation |
| CSK | combined signing key: one key used as both KSK and ZSK |
| DO | the EDNS "DNSSEC OK" bit: the client wants DNSSEC records |
| DoH | DNS over HTTPS (RFC 8484) |
| DoT | DNS over TLS (RFC 7858) |
| DS | delegation signer record held by the parent zone; links the parent to the child's KSK |
| EDE | Extended DNS Error (RFC 8914): a reason code attached to an answer, e.g. 6 DNSSEC bogus, 15 blocked |
| EDNS | extension mechanism for DNS (RFC 6891): larger UDP payloads, flags and options |
| KSK / ZSK | key signing key (signs the DNSKEY set, its DS is at the parent) / zone signing key (signs the records) |
| mTLS | mutual TLS: the client also presents a certificate, here for DoT |
| Negative cache | cached NXDOMAIN or NODATA answers (RFC 2308) |
| NSEC / NSEC3 | DNSSEC records proving a name or type does not exist; NSEC3 hashes the names |
| NTA | negative trust anchor (RFC 7646): a name under which validation is switched off temporarily |
| Nox | the DNSY owl mascot, see [Branding and the mascot](branding.md) |
| Prefetch | refreshing a popular cache entry shortly before it expires |
| RRSIG | the signature over a record set |
| Serve-stale | answering from an expired cache entry when upstreams fail (RFC 8767) |
| Trust anchor | the starting point of validation, here the root zone's DS records |
| Upstream group | a set of upstream resolvers with a load-balancing policy and routing |
| Zone | a DNS subtree DNSY is authoritative for, stored as one JSON file |
