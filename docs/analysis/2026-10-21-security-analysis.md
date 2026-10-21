# Security analysis (DNSY-61)

- **Date:** 2026-10-21
- **Scope:** `main` at `237751b` (DNSY-1..58, 69, 70 merged; feature complete, pre-release)
- **Method:** STRIDE threat model over the trust boundaries, manual review of every
  security-critical crate, a 150 s fuzz-style run against `dnsy-proto`, `cargo audit`,
  `cargo deny`, `pnpm audit`, and black-box probes against a locally built binary
  (UDP/TCP/DoT/DoH listeners and the REST API with a temp config).
- **Status of this document:** report only. No product code was changed. Follow-up stories
  are proposed in section 7; DNSY-68 already tracks a set of earlier findings and their
  status on `main` is recorded in section 5.

## 1. Summary

| Severity | Count | Headline |
| --- | --- | --- |
| Critical | 0 | |
| High | 1 | SEC-01: login throttle is keyed on `0.0.0.0` for every client, so anyone who can reach the API port locks any account out |
| Medium | 5 | SEC-02 UDP in-flight slots exhaustible by slow-upstream names; SEC-03 unbounded concurrent argon2 on login; SEC-04 TCP/DoT connection cap is per listener and never per client; SEC-05 default config is an open, unlimited forwarder on all interfaces; SEC-06 retired KSK stops signing the DNSKEY RRset at DS confirmation |
| Low | 19 | SEC-07 .. SEC-25 |
| Info | 17 | SEC-26 .. SEC-42 |

Overall the codebase is in good shape for a pre-release audit: the wire parser survived
23.6 million adversarial inputs without a panic, the cache-poisoning defences (per-query random
port and ID, bailiwick scrubbing, DO/CD/state-isolated cache keys), the KeyTrap work budgets,
the token/session cryptography, SSRF protection, SQL parameterisation and the UI's CSP are all
implemented correctly (section 8). The high and medium findings are concentrated in
availability (resource caps that are missing or keyed wrongly) and in one wiring omission that
disables the IP dimension of the login throttle.

Tooling results: `cargo audit` 0 advisories (308 crates), `cargo deny check` passes
(advisories, bans, licenses, sources ok; 16 duplicate-version warnings), `pnpm audit` reports 3
advisories (1 high, 2 moderate) all in `vite` via `@angular/build` (`launch-editor`,
Windows-only, dev server only, not in the shipped bundle). `cargo-geiger` and `cargo-fuzz` could
not be installed on the pinned stable toolchain and were skipped; a scratch fuzz harness was
used instead (section 4.1).

## 2. Threat model

### 2.1 Trust boundaries and actors

| # | Boundary | Untrusted side | What crosses it | Main controls |
| --- | --- | --- | --- | --- |
| B1 | Internet DNS clients (UDP/TCP :53) | anyone, spoofable source | raw DNS messages | parser, FORMERR/NOTIMP, ACL, per-client rate limit, EDNS size cap 1232, TC, `max_tcp_conns`, `tcp_idle_ms` |
| B2 | DoT clients (:853, optional mTLS) | anyone with TCP reach; authenticated principal when mTLS | TLS + DNS | rustls 1.2/1.3, client CA + fingerprint allowlist, resumption disabled under mTLS, same DNS pipeline |
| B3 | DoH clients (:443) | anyone; token-authenticated by default | HTTP/2 or HTTP/1.1 + DNS | bearer or path token, failure throttle, 64 KiB body/`dns=` limits, header read timeout, h2 stream cap |
| B4 | Upstream resolvers | configured by operator, but answers may be forged or hostile | DNS answers over UDP/TCP/DoT | random port + ID, question match, bailiwick scrub, DNSSEC validation, TTL clamps, Bogus isolation |
| B5 | Blocklist URL fetch | arbitrary HTTP(S) servers chosen by an operator | HTTP bodies | scheme allowlist, private-address refusal with DNS pinning, redirect re-validation, 50 MiB cap, 30 s deadline, admin re-auth for private targets |
| B6 | Admin API / UI users (:5380) | authenticated with roles `admin`/`operator`/`viewer`; login endpoint is anonymous | JSON over HTTP(S) | argon2id, sessions, tokens with scopes, CSRF double submit, security headers, body limits |
| B7 | Filesystem: zone JSON, key passphrase file, TLS keys, SQLite | local users on the host | files | zone-name whitelist for file names, atomic writes, passphrase-file mode check, encrypted keys |
| B8 | SQLite database | same host; backups | password/token/session hashes, encrypted keys, query log | parameterised SQL, migration checksums, WAL |
| B9 | Operator CLI | trusted operator; argv and env visible to local users | passwords, passphrases | password via stdin/env only, passphrase via env/file only, bundle files 0600 |

### 2.2 STRIDE per boundary (condensed)

- **Spoofing.** B1/B4: forged upstream answers (cache poisoning) are defended by a fresh
  `bind(:0)` socket per attempt, a CSPRNG transaction ID and a full question match
  (`crates/dnsy-resolver/src/upstream/mod.rs:257-300`); no 0x20 or DNS cookies (SEC-31). B6:
  session fixation is prevented by rotating the id at login; bootstrap code is one-time and
  128-bit. B2: mTLS identity is bound to the connection; expiry re-check gap is tracked in
  DNSY-68.
- **Tampering.** B4: `scrub` keeps only in-bailiwick, in-chain records; validated data caps TTLs
  by RRSIG expiry; Bogus never overwrites Secure. B7: zone file names are whitelisted; writes are
  temp-file + rename. B8: migrations are checksummed and refuse edits.
- **Repudiation.** Query log stores `token:<id>` principals, not secrets; API access log has
  method/path/status. Client-cert ids are reused after deletion (DNSY-68).
- **Information disclosure.** Secrets never reach logs or API bodies (verified by grep and by
  probe: 0 token strings in the server log after 600 requests). `dnsy.db` is created with umask
  permissions (SEC-13); `GET /api/v1/version` and `/api/openapi.json` are anonymous (SEC-36).
- **Denial of service.** This is where the findings cluster: SEC-01..SEC-05, SEC-09, SEC-10,
  SEC-11, SEC-19.
- **Elevation of privilege.** Route x role matrix has no gaps (section 6); the bearer-token
  role re-check noted in DNSY-68 is fixed on `main`. Scopes are flat, not hierarchical (SEC-40).

## 3. Findings

Severity follows CVSS-style reasoning: attacker position (unauthenticated remote > authenticated
> local), impact on confidentiality/integrity/availability, and default-config reachability.
Each finding lists the location, scenario, proof where one was collected, a fix and a
regression test. "DNSY-68" marks items already tracked there.

### High

#### SEC-01 Login throttle is keyed on `0.0.0.0` for every client (account lock-out by anyone)

- **Location:** `crates/dnsy/src/http.rs:76-82` (the router is served with
  `app.clone().oneshot(req)`; `ConnectInfo` is never inserted although `peer` is in scope at
  `:53`); `crates/dnsy-api/src/routes/auth.rs:69-74` (`client_ip` falls back to
  `Ipv4Addr::UNSPECIFIED` when the extension is missing);
  `crates/dnsy-auth/src/sessions.rs:17-18,90-110` (5 failures per `(username, ip)` in 15 min).
- **Scenario:** anyone who can reach the API port sends five wrong passwords for `admin`
  every 15 minutes. The real administrator gets 429 from any address, including with the right
  password. Behind a reverse proxy this is also the shape of every deployment with a public UI.
  Not a bypass of the throttle, but it converts the throttle into an unauthenticated
  denial-of-service against any account.
- **Proof (probe):** five `POST /api/v1/auth/login` with a wrong password from `127.0.0.1`,
  then the correct password from `127.0.0.2` returned
  `429 Too Many Requests`, `retry-after: 899`. `login_attempts` rows:
  `('admin', '0.0.0.0', ...)` for every attempt.
- **Fix:** insert `ConnectInfo(peer)` as a request extension in `http.rs` before `oneshot`
  (or use `into_make_service_with_connect_info::<SocketAddr>()`); make `client_ip` fail closed
  (error or `warn!`) when the extension is absent; group IPv6 by /64 (DNSY-68 item); add a
  per-username backoff that does not fully lock the account (for example exponential delay with
  a cap) so a remote attacker cannot deny the legitimate user.
- **Regression test:** integration test through `http::serve` on a real `TcpListener`: five bad
  logins from `127.0.0.1`, a good login from `127.0.0.2` succeeds, and `login_attempts.ip`
  is never `0.0.0.0`.

### Medium

#### SEC-02 UDP in-flight slots exhaustible by names that resolve slowly

- **Location:** `crates/dnsy-server/src/udp.rs:17,41` (`MAX_IN_FLIGHT = 1024`, excess datagrams
  silently dropped); `crates/dnsy-engine/src/builder.rs:206` (deadline =
  `timeout_ms * attempts` = 4 s by default); `crates/dnsy-engine/src/engine.rs:497-503` (cache
  misses call `resolve` directly; the `Refreshes` single-flight is used only for stale/prefetch).
- **Scenario:** about 256 queries per second for unique names in a zone whose upstream does not
  answer keep all 1024 slots busy for 4 s each; every other datagram, including queries for local
  authoritative zones, is dropped. Sources can be spoofed, and identical misses are not coalesced
  so the same storm is forwarded upstream N times.
- **Proof:** static (lines above). Not exercised dynamically.
- **Fix:** raise the per-socket cap substantially (the in-flight future is small; the real
  bound is upstream concurrency), add a per-`client_key` in-flight cap, reuse `Refreshes::begin`
  for cache misses so concurrent identical misses share one upstream exchange, and prefer
  answering local zones before admission control (the pipeline already orders zones before
  cache, so a cheap pre-check is possible).
- **Regression test:** handler that sleeps 4 s; send 1024 datagrams from one source, then one
  authoritative query from another and assert it is answered; assert N concurrent identical
  misses produce one `Exchange` call.

#### SEC-03 Unbounded concurrent argon2 on the anonymous login path

- **Location:** `crates/dnsy-auth/src/password.rs:30-36` (`spawn_blocking` with no limit);
  `crates/dnsy-auth/src/users.rs:308-316` (unknown users are hashed too, correctly, for
  enumeration resistance); the throttle in `sessions.rs:72` is per username so random usernames
  bypass it; argon2id m=19 MiB.
- **Scenario:** flood `POST /api/v1/auth/login` with random usernames. tokio's blocking pool
  allows 512 threads, each holding 19 MiB and a core for tens of milliseconds; the DNS service in
  the same process degrades. Reachable only where the API is exposed (default bind is loopback),
  hence medium.
- **Fix:** a global `tokio::sync::Semaphore` around `blocking()` sized to the CPU count with
  fail-fast 503/429 when exhausted; a global per-IP login rate limit once SEC-01 is fixed; cap
  password length (1 KiB) before hashing.
- **Regression test:** 200 concurrent logins with distinct usernames; a counter in a test hook
  asserts the number of simultaneously running hashes never exceeds the cap.

#### SEC-04 TCP/DoT connection cap is per listener and never per client

- **Location:** `crates/dnsy-server/src/tcp.rs:73` (a fresh `Semaphore` per `serve_with`),
  `crates/dnsy-server/src/doh/mod.rs:174` (another one); `tcp.rs:144-149` bounds only one frame
  by `tcp_idle_ms`; no per-client accounting.
- **Scenario:** one client opens `max_tcp_conns` connections and sends one byte every few
  seconds (or one query per 9 s); every further connection is reset. Because UDP truncation
  (TC) is the designed fallback for large answers, blocking TCP also breaks DNSSEC-sized answers.
- **Proof (probe, `max_tcp_conns = 64`):** 200 idle connections from one client; the server
  kept 64 and reset the rest; a fresh query connection got `ECONNRESET`. Trickling one byte per
  5 s kept a connection alive for 20 s then it was closed (the idle timer covers partial frames,
  which is correct), but 64 trickling clients are enough to hold the listener.
- **Fix:** one shared `Arc<Semaphore>` per transport created in `Server::start`; a per-client
  cap (for example 16 per /32 or /64); when saturated, close the oldest idle connection rather
  than refusing new ones (the BIND `tcp-clients` recycling model).
- **Regression test:** two TCP listen addresses with cap 1 share the cap; the 17th connection
  from one IP is closed while a different IP still connects.

#### SEC-05 Default configuration is an open, unlimited forwarder on all interfaces

- **Location:** `crates/dnsy-config/src/model.rs:75-80` (`dns.udp/tcp = 0.0.0.0:53`),
  `:384` (`per_client_qps: 0`), `crates/dnsy-engine/src/builder.rs:192`
  (`Acl::new(AclAction::Allow, [])`).
- **Scenario:** the first thing an operator does is add an upstream group through the API; the
  host then answers recursive queries for the whole internet with no rate limit. Amplification
  is bounded to 1232 B per ~40 B query (about 30x) and ANY is answered in full (SEC-14).
  `docs/book/src/security.md` does warn, but defaults are what ships.
- **Fix:** default ACL allowing loopback, RFC 1918, ULA and link-local only (explicit
  `open_resolver = true` to widen), a non-zero default `per_client_qps` (for example 50), and a
  startup `warn!` when a non-loopback listener coincides with an allow-all ACL and qps 0.
- **Regression test:** `Config::default()` -> `Acl::check(203.0.113.5)` is `Refuse`; config
  load with `0.0.0.0:53` and no ACL emits the warning.

#### SEC-06 Retired KSK/CSK stops signing the DNSKEY RRset the moment the DS is confirmed

- **Location:** `crates/dnsy-dnssec/src/sign/mod.rs:105-107` (`signs_dnskeys` requires
  `Published | Active`); `crates/dnsy-dnssec/src/keys.rs:213-218,231-240` (old SEP key is
  Retired `publish_wait` = 2 h after `ds_confirmed_at`); `crates/dnsy-zone/src/keystore.rs:714-742`
  (DS confirmation accepted at any time).
- **Scenario:** an operator confirms the DS as soon as it is visible at the parent. Resolvers
  that still cache the old DS (TLD DS TTLs are 24-48 h) fetch a DNSKEY RRset signed only by the
  new KSK and return SERVFAIL for the zone until their DS cache expires. The operator guide says
  to wait the DS TTL, but nothing enforces it. Availability of the operator's own signed zones.
- **Fix:** let Retired SEP keys keep signing the DNSKEY RRset until Removed (`retire_wait`
  already spans the needed time), or add a `ds_ttl` policy field and gate the transition on
  `ds_confirmed_at + ds_ttl + propagation`.
- **Regression test:** sign with `{Ksk Retired, Ksk Active}` and assert two RRSIGs over
  DNSKEY; validator test with only the old DS as anchor still validates after the transition.

### Low

#### SEC-07 Validator DS/DNSKEY fetches are cached unscrubbed under a client-visible key

- **Location:** `crates/dnsy-resolver/src/forward.rs:283-295` (only `aa/ad/additional/edns`
  cleared, stored under `(name, DS|DNSKEY, IN, DO=1, CD=1)`); `crates/dnsy-engine/src/engine.rs:431-437,481-485`
  (a client query with DO=1 CD=1 uses the same key and is served the entry).
- **Scenario:** a misbehaving configured upstream adds out-of-bailiwick records to the answer or
  authority section of a DNSKEY response; a CD=1 client receives them without passing `scrub`.
  Trust boundary is "configured upstream", hence low. Found independently by two reviewers.
- **Fix:** run `scrub(&q, resp, true)` before `cache.insert`, or key validator fetches with a
  reserved flag so they never satisfy client lookups.
- **Regression test:** fake upstream DNSKEY answer with an extra `bank.example A` in the answer
  section; a CD=1 client query must not see it.

#### SEC-08 Transient DS/DNSKEY fetch failures are classified Bogus and cached for 60 s

- **Location:** `crates/dnsy-dnssec/src/validate/chain.rs:93-100` (any `FetchError`, including
  the 64-permit semaphore deadline in `forward.rs:271-282`, maps to `Failure::bogus`);
  `crates/dnsy-config/src/model.rs:236` (`bogus_ttl` 60 s vs `servfail_ttl` 5 s).
- **Scenario:** one upstream hiccup during a DS fetch blacks out a subtree for a minute in
  strict mode; a burst that saturates the fetch semaphore does the same for many names.
- **Fix:** map fetch errors to `Indeterminate` (EDE 5) cached with `servfail_ttl`.
- **Regression test:** fetcher returning `Err` -> `status == Indeterminate`, not cached as Bogus.

#### SEC-09 Error replies bypass ACL `drop` and the rate limiter

- **Location:** `crates/dnsy-engine/src/engine.rs:367-385` (FORMERR, NOTIMP and BADVERS are
  answered before the ACL check at `:399` and the rate check at `:404`);
  `crates/dnsy-server/src/query.rs:22-31` (listener-level FORMERR for malformed, zero- or
  multi-question packets without consulting the handler).
- **Scenario:** a client the operator set to `drop` still gets replies (presence disclosure,
  1:1 reflection); the rate limiter is not consumed by these packets.
- **Proof (probe):** `qd=0`, `qd=2`, opcode UPDATE/NOTIFY and EDNS v1 all received replies of
  12-45 bytes (never larger than the request, so no amplification).
- **Fix:** evaluate `acl.check(ip, principal)` and the rate limit first (they need only
  ip/transport); for listener-level FORMERR route through a cheap `handler.allowed(ip)` hook.
- **Regression test:** ACL drop + NOTIFY opcode / EDNS v1 / zero-question packet -> no datagram.

#### SEC-10 Rate limiter: spoofed-source starvation and O(n) eviction under the shard lock

- **Location:** `crates/dnsy-filter/src/ratelimit.rs:88-89` (over-limit UDP silently dropped),
  `:97-105` (`make_room` does a full `retain` plus `min_by_key` scan of a 6250-entry shard for
  every new key once full).
- **Scenario:** spoofing a victim's address (or any address in its /64) exhausts the victim's
  bucket (classic RRL problem, mitigated elsewhere with "slip"); a spoofed-IP flood turns each
  new key into a 6k-entry scan while holding the shard mutex.
- **Fix:** send a minimal TC=1 reply for 1-in-N over-limit UDP queries so real clients fall
  back to TCP; make eviction amortised (random sample, like the cache's `EVICTION_SAMPLE`).
- **Regression test:** fill a shard and time 10k inserts; over-limit UDP gets a TC reply every
  Nth query.

#### SEC-11 API HTTP listener has no header-read timeout, idle timeout or connection cap

- **Location:** `crates/dnsy/src/http.rs:81-82` (`Builder::new(TokioExecutor::new())` with no
  timer, so hyper's 30 s header timeout is disabled); no semaphore, no `TimeoutLayer`.
- **Proof (probe):** a connection that sent half a request line stayed open for 40 s.
- **Scenario:** slowloris against the admin port. Default bind is loopback, so low.
- **Fix:** mirror `doh/mod.rs:220-230` (timer, `header_read_timeout`, h2 limits) and reuse a
  connection semaphore; add a `TimeoutLayer` excluding `/querylog/stream`.
- **Regression test:** open a socket, send half a request line, assert close within the
  timeout; 2k idle connections still allow `/healthz` within 1 s.

#### SEC-12 `Secure` cookie flag and HSTS depend only on DNSY's own TLS (no reverse-proxy override)

- **Location:** `crates/dnsy-api/src/lib.rs:84` (`cookie_secure = config.tls`),
  `crates/dnsy/src/serve.rs:94`, `crates/dnsy-api/src/security.rs:38-43` (HSTS on the same flag);
  `public_url` (`crates/dnsy-config/src/model.rs:151`) is used only by `cacheflush.rs:52`.
- **Scenario:** TLS terminated by nginx/Caddy with `[api] listen` on plain HTTP: `dnsy_session`
  is set without `Secure` and no HSTS is sent; an `http://` request to the same host carries the
  cookie in clear. `SameSite=Strict` does not help because it is same-site.
- **Fix:** `[api] secure_cookies = "auto" | true | false` (or derive from `public_url` starting
  with `https://`) feeding both the cookie and HSTS; document the proxy case. Behind a proxy
  SEC-01 also means every client shares one IP; an optional trusted-proxy `X-Forwarded-For`
  setting belongs in the same story.
- **Regression test:** router built with `tls: false, secure_cookies: true` ->
  both `Set-Cookie` headers contain `; Secure` and the response has `Strict-Transport-Security`.

#### SEC-13 `dnsy.db` (and WAL/SHM) created with umask permissions; TLS key files not mode-checked

- **Location:** `crates/dnsy/src/lib.rs:107-110` (`create_dir_all` + `Store::open`),
  `crates/dnsy-store/src/store.rs:68` (`Connection::open` with no mode); contrast
  `crates/dnsy-zone/src/keystore.rs:1067` (bundle 0600) and `:113-120` (passphrase-file mode check).
- **Proof (probe):** fresh `data_dir`: `dnsy.db`, `dnsy.db-wal`, `dnsy.db-shm` all `0644`.
  The database holds password hashes, token and session hashes and the DNSSEC private keys
  (plaintext when no passphrase is configured).
- **Fix:** create `data_dir` 0700 and pre-create the db file with `OpenOptions::mode(0o600)`;
  warn when `api.tls_key`, `dot.key`, `doh.key` are group/world readable.
- **Regression test:** open a fresh store in a tempdir, assert `mode & 0o077 == 0`.

#### SEC-14 ANY answered in full; AXFR/IXFR forwarded or answered instead of refused

- **Location:** `crates/dnsy-engine/src/engine.rs:373-378` (only non-Query opcodes rejected);
  `crates/dnsy-zone/src/lookup.rs:204-209` (ANY in full); qtype 251/252 reach upstream as
  `Unknown`.
- **Proof (probe):** ANY on a 14-record name over UDP returned TC=1 (34 B, 1:1), full 3082 B
  over TCP; ANY at the apex 122 B for a 41 B query (3x); AXFR/IXFR over UDP and TCP answered
  NOERROR/NODATA with the SOA in authority.
- **Fix:** RFC 8482 minimal ANY (HINFO) or REFUSED over UDP; NOTIMP/REFUSED for 251/252 without
  an upstream round trip.
- **Regression test:** qtype ANY over UDP yields <= ~100 B; AXFR gets REFUSED and no upstream call.

#### SEC-15 Wildcard expansion proof accepts an opt-out NSEC3 as Secure

- **Location:** `crates/dnsy-dnssec/src/validate/denial.rs:349-354` (no `opt_out()` check,
  unlike `nxdomain` at `:253-255` and `ds_absence` at `:318-322`). RFC 5155 9.2; Unbound and
  BIND return Insecure here. Moderate confidence on the spec reading.
- **Scenario:** opt-out parent with `*.example A` and an insecure delegation `child.example`;
  replaying `www.child.example A` with the wildcard RRSIG and the opt-out NSEC3 covering the
  next closer name gets AD although the next closer name may exist as an unsigned delegation.
- **Fix:** return `Verdict::Insecure(None)` when the covering NSEC3 has opt-out.
- **Regression test:** `wildcard_expansion_proof_nsec3` variant with `opt_out = true` -> Insecure.

#### SEC-16 DNSKEY REVOKE bit ignored

- **Location:** `crates/dnsy-dnssec/src/verify.rs:34`, `crates/dnsy-dnssec/src/validate/chain.rs:298`
  (only ZONE flag and protocol 3 checked).
- **Scenario:** a key with 0x0080 set still validates data (RFC 5011 2.1 forbids it). Needs the
  zone's own cooperation; low.
- **Fix:** drop keys with `flags & 0x0080 != 0` from the trusted set in `child_trust`.
- **Regression test:** revoked ZSK signing an RRset -> Bogus.

#### SEC-17 Key backup bundle: 8-character passphrase minimum at the OWASP-minimum KDF cost; export allowed on plaintext API listeners

- **Location:** `crates/dnsy-zone/src/keystore.rs:142-150` (19 MiB, t=2, p=1),
  `crates/dnsy-api/src/routes/dnssec.rs:813`, `crates/dnsy/src/admin.rs:31` (`MIN_PASSPHRASE_LEN = 8`);
  `POST /dnssec/keys/export` returns every zone's private keys in one bundle and the bundle
  passphrase travels in the request body; the API may run without TLS (`serve.rs:90-93`).
- **Fix:** 12+ characters, a higher cost for bundles (64 MiB, t=3), refuse the export route on
  a plaintext listener unless `secure_cookies`/TLS (SEC-12) says the hop is protected.
- **Regression test:** 8-character passphrase -> 422; export over plain HTTP -> 403 with a
  clear problem detail.

#### SEC-18 `POST /zones/{name}/dnssec/keys` silently starts a rollover

- **Location:** `crates/dnsy-dnssec/src/keys.rs:212,231-240` (Generated -> Published on the
  next tick, then Active, retiring the current key); `crates/dnsy-api/src/routes/dnssec.rs:687-707`
  has no in-progress guard, unlike `keystore.rs:686-691`.
- **Scenario:** several generated ZSKs go active together; the docs describe the state as
  "not yet published". Operational integrity.
- **Fix:** keep Generated inert until an explicit publish, or apply the `RolloverInProgress`
  guard in `generate_key`.
- **Regression test:** two `POST .../keys` in a row -> second returns 409.

#### SEC-19 Passphrase change is not persisted; after a restart a signed zone is served unsigned

- **Location:** `crates/dnsy-zone/src/keystore.rs:989-1049` (live switch only);
  `crates/dnsy-zone/src/signed.rs:412-414` and `store.rs:208-211` (open failure logs and serves
  unsigned while the DS stays at the parent, so validators SERVFAIL; readiness stays green).
- **Fix:** fail startup (or mark the zone unavailable and flip `/readyz`) when
  `dnssec.enabled` and the zone's keys cannot be opened.
- **Regression test:** rotate the passphrase, restart without updating the env/file, assert
  `/readyz` is not ready and the zone is not served unsigned.

#### SEC-20 No input length limits on token names/usernames/passwords; live-tail cap is global

- **Location:** `crates/dnsy-api/src/routes/tokens.rs:114-123` (only "not empty"),
  `crates/dnsy-api/src/routes/users.rs:20-27` (minimum length only), `crates/dnsy-api/src/state.rs:76`
  (`MAX_LIVE_TAILS = 16` shared by all principals; verified by probe: the 41st stream got 429
  while 40 were held, normal requests kept working).
- **Fix:** cap names at 128, usernames at 64, passwords at 1 KiB, tokens per user at 100; make
  the SSE cap per principal with an admin reservation.
- **Regression test:** `POST /tokens` with a 1 MiB name -> 422.

#### SEC-21 Canonical form does not lowercase RDATA names of RFC 4034 6.2 types modelled as Opaque

- **Location:** `crates/dnsy-proto/src/canonical.rs:37-41` (fallback `other.encode`),
  `crates/dnsy-proto/src/rdata/mod.rs:212-215` (DNAME, NAPTR, RP, AFSDB, RT, KX, PX, MINFO,
  MB/MG/MR, A6 kept raw).
- **Impact:** validation failure (SERVFAIL), never a bypass: lowercasing only merges case
  variants that are already compared case-insensitively. DNAME in a signed zone with upper-case
  RDATA is the realistic case.
- **Fix:** add DNAME (and NAPTR) variants routed through `name()` in `rdata_wire`.
- **Regression test:** `rdata_wire` of a DNAME `Example.COM.` yields lowercase wire.

#### SEC-22 Name compression is case-insensitive, rewriting RDATA case to the first occurrence

- **Location:** `crates/dnsy-proto/src/writer.rs:58-61` (`to_ascii_lowercase` lookup key).
- **Proof (fuzz harness):** `MX 10 Mail.Example.com.` after question `www.example.com.`
  decodes as `Mail.example.com.`. RFC 1035 4.1.4 / RFC 4343 4.1 ask for case preservation. The
  question name (first occurrence) keeps its case, so a client's 0x20 echo is unaffected; DNSSEC
  canonicalisation lowercases these names anyway.
- **Fix:** key the compression map on exact suffix bytes, or document the choice.

#### SEC-23 rcode > 15 silently truncated when no OPT is present (DNSY-68)

- **Location:** `crates/dnsy-proto/src/message.rs:235` (`Rcode::from(rcode & 0xF)`); the
  12-bit path at `:189` runs only inside `if let Some(edns)`. Still present. Not reachable from
  the engine's own BADVERS path (`badvers_for` attaches an OPT; probe confirmed extended rcode
  `0x01` in the OPT of the BADVERS reply), so a latent fail-open for future callers.
- **Fix/test:** as in DNSY-68 (return `EncodeError::BadRcode`).

#### SEC-24 No `[profile.release]` hardening

- **Location:** root `Cargo.toml` (no profile section, no `.cargo/config.toml`).
- **Impact:** integer overflow wraps silently in release in a parser-heavy codebase. The fuzz
  run was compiled with `overflow-checks = true` and found none, and all untrusted length
  arithmetic is checked, so this is defence in depth.
- **Fix:** `[profile.release] overflow-checks = true, lto = "thin", codegen-units = 1,
  strip = "symbols"`; consider `panic = "abort"` after reviewing task supervision.

#### SEC-25 `scripts/check-svg.sh` misses event-handler attributes and SMIL `href` animation (DNSY-68)

- **Location:** `scripts/check-svg.sh:17` (regex has no `on[a-z]+=`, `attributeName="href"`,
  `<style>`). Still grep-based. Low: SVGs are loaded via `<img>`/TextureLoader and CSP blocks
  script when opened top-level.

### Info

- **SEC-26 Validator fetch path and CD=1 served from the same key** is covered by SEC-07; noted
  here because the cache key design is otherwise sound.
- **SEC-27 OPT accepted in answer/authority sections** and re-emitted as an Opaque type-41
  record (`crates/dnsy-proto/src/message.rs:343-345,367`). RFC 6891 6.1.1. Fix: `BadOpt` on decode.
- **SEC-28 Type-bitmap decode allocation**: 8.7 KB of wire expands to 128 KB per NSEC/NSEC3
  (`crates/dnsy-proto/src/bitmap.rs:78-85`); bounded to roughly 1 MB per 64 KB message.
- **SEC-29 Padding can evict answers** when the unpadded message is within 4..471 bytes of a
  65 535 limit (`crates/dnsy-server/src/query.rs:58-78`, `message.rs:293-312`). RFC 8467 says pad
  only as much as fits.
- **SEC-30 Strict NSEC bitmap acceptance** (`bitmap.rs:68-77`) rejects trailing-zero octets and
  out-of-order windows; RFC-correct but stricter than BIND/Unbound (interoperability only).
- **SEC-31 No DNS cookies (RFC 7873) and no 0x20.** Baseline (random port + ID per query) is
  sound; 0x20 is cheap extra entropy since `matches()` already compares questions.
- **SEC-32 CRL plumbing exists but is unused**: `crates/dnsy-server/src/dot/mtls.rs:208-217`
  accepts a CRL, `serve.rs:229` passes `None`, `[dot]` has no `client_crl`; revocation is
  allowlist-only.
- **SEC-33 DoH `Cache-Control: max-age=<ttl>`** without `private`/`Vary: Authorization`
  (`doh/mod.rs:335-339`); a shared cache may store `/dns-query/{token}?dns=` responses (public
  data, no secret).
- **SEC-34 Blocklist matches qname only**, not CNAME targets (`engine.rs:410`); IDN entries must
  be punycode (unicode lines silently dropped, `crates/dnsy-filter/src/parse.rs:251-277`).
- **SEC-35 Upstream hostnames resolved with `tokio::net::lookup_host` per attempt**
  (`crates/dnsy-resolver/src/upstream/mod.rs:263-268`); a system resolver pointing at DNSY loops.
  No SPKI pinning for `tls://` upstreams (hostname verification is correct).
- **SEC-36 Anonymous `GET /api/v1/version` and `/api/openapi.json`** (`routes/meta.rs:84-90`,
  `lib.rs:87-93`). Acceptable for an open-source product; document or gate behind `api:read`.
- **SEC-37 Password change bypasses the login throttle** (`routes/auth.rs:256-259` calls
  `verify_password` directly). Needs a valid session already.
- **SEC-38 CSRF token not bound to the session; no `__Host-` prefix** (`auth.rs:160-168`,
  `routes/auth.rs:83`). Defence is provided by `SameSite=Strict`, the custom header and the
  absence of CORS; hardening: `__Host-` names when secure, HMAC(session id) as the CSRF value.
- **SEC-39 Algorithm rollover is not double-signed** (`sign/mod.rs:294-301`); RFC 6840 5.11
  obliges validators to accept it, RFC 6781 4.1.4 recommends double-signing.
- **SEC-40 Scopes are flat**: a token with only `admin` scope gets 403 on `GET /zones`
  (needs `api:read`) while `GET /settings` works. Least privilege is preserved; the UI and docs
  should make it clear that `admin` is not a superset.
- **SEC-41 Zeroisation gaps**: `ExportKeysInput.passphrase` and `ChangePassphraseInput` are
  plain `String`s (`routes/dnssec.rs:235,261`); the stdin buffer in `admin.rs:296-298` is not
  wiped; unencrypted `NewKey.private_key` is a plain `Vec` (`keystore.rs:454`);
  `private_key = x''` does not reach SQLite freelist/WAL pages.
- **SEC-42 DNSSEC spec nits**: unknown NSEC3 flag bits not ignored (`denial.rs:146`, RFC 5155
  8.2); three NSEC3 iteration constants (`nsec3.rs:10` = 150 unused, `validate/mod.rs:68` = 100,
  `policy.rs:12` = 500); RSA modulus leading-zero strictness (`pubkey.rs:91`); RFC 1982 exact
  2^31 distance accepted for both bounds; CDS-delete (RFC 8078) not implemented; passphrase-file
  permission check is warn-only (`keystore.rs:111-121`); `pnpm audit` vite advisories (dev only).

## 4. Tooling and probe record

### 4.1 Static tooling

| Tool | Result |
| --- | --- |
| `cargo audit` 0.22.2 | 308 crates, 0 advisories |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok; 16 `duplicate` warnings (`getrandom`, `hashbrown`, `syn`, `synstructure`, `bit-vec`, `windows-*`) |
| `pnpm audit` (web/) | 3 advisories, all `vite` 8.3.0-8.3.2 via `@angular/build` (GHSA-587h-7wmj-h5pm high, GHSA-698v-4r3x-3vcv, GHSA-r825-w8mm-5pxw moderate): `launch-editor`, Windows-only, dev server only |
| `cargo clippy` pedantic `-D warnings` | part of `just check`, clean on `main` |
| `cargo geiger` | does not compile on the pinned toolchain; skipped. Unsafe-bearing dependencies in the binary graph: `ring`, `libsqlite3-sys` (bundled C), `rusqlite`, `tokio`, `mio`, `bytes`, `memchr`, `parking_lot`, `getrandom`; the workspace itself is `unsafe_code = "forbid"` |
| `cargo fuzz` | needs nightly; `crates/dnsy-proto/fuzz/fuzz_targets/fuzz_decode.rs` exists but is not wired into any recipe. The one-hour `fuzz_decode`/`fuzz_validate` runs the story asked for were replaced by the scratch harness below (150 s, 23.6 M inputs) and should be done properly in a follow-up (story F7) |

Scratch fuzz harness (release, `overflow-checks = true`, 150 s, 23 660 042 iterations: 11.83 M
random buffers 0..600 B, 11.83 M stacked mutations of three encoder-built messages covering
A/AAAA/MX/TXT/CNAME/SRV/CAA/RRSIG/SOA/NS/NSEC/NSEC3/NSEC3PARAM/DNSKEY/DS/Opaque/OPT with EDE,
ECS, unknown option and padding, plus 42 hand-crafted cases: pointer self/forward/loop/ping-pong,
200- and 300-deep chains, `0xC0` as last byte, label 64, names 255/257/320, `qdcount = 65535` on
12 bytes and with 3000 pointer questions, all counts 65535, RDLENGTH > remaining, OPT option
length overflow, EDE short/bad UTF-8, duplicate/non-root OPT, version 1 with extended rcode,
NSEC windows 0/33/full, NSEC3 salt/hash overflow and empty hash, TXT/CAA overflow, CNAME pointer
to header and to its own RDATA, SOA short, A length 3/5, trailing byte). Each input ran
`formerr_for`, `decode`, `encode` at 12/100/512/1232/65535, `encode_padded`, `set_ede`,
re-decode, `decode(encode(decode(x))) == decode(x)`, presentation `Display`/parse and
`canonical::rdata_wire` under `catch_unwind`. Result: 1 338 682 decoded Ok, 22 321 360 `Err`,
**0 panics**, 0 round-trip mismatches, 0 encodes above `max_len`.

### 4.2 Black-box probes (debug binary, temp config, loopback, upstream unreachable)

| Probe | Observation | Verdict |
| --- | --- | --- |
| UDP: empty, 11 B, 4 KiB garbage, QR=1 | no reply | sound |
| UDP: `qdcount=65535`, counts 65535, pointer self/loop/forward, label 64, name 300, `0xC0` last, label type 0x80, two OPT, OPT RDLENGTH overflow, control chars in qname, `qd=0/2` | FORMERR 12-45 B, never larger than the request | sound (SEC-09 for ACL `drop`) |
| UDP: 8876 mutated queries | server alive, answers correct afterwards | sound |
| Opcode UPDATE/NOTIFY | NOTIMP | sound |
| EDNS version 1 | BADVERS with OPT extended rcode | sound |
| Unknown EDNS option, NSID, cookie | not echoed, no NSID, no cookie | sound / SEC-31 |
| AD=1 CD=1 DO on an unsigned local zone | AD clear, CD echoed | sound |
| ANY/TXT on a 14-record name, bufsize 100/1232/65535 | TC=1, 45 B; 3082 B over TCP | sound cap, SEC-14 |
| AXFR/IXFR UDP and TCP | NOERROR/NODATA with SOA | SEC-14 |
| TCP: 50 pipelined queries | 50 answers | sound |
| TCP: partial length prefix, 65535 length with no body, zero-length frame, post-answer idle | closed at 10 s / 10 s / immediately / 10 s | sound |
| TCP: 200 idle connections, cap 64, then a fresh query | fresh connection reset | SEC-04 |
| DoH: no/bad token, bad base64, 70 KB `dns=`, POST wrong content type, 70 KB body, 64 KB header, TLS 1.1, HTTP/2 | 401, 401, 400, connection closed, 415, 400, 431, refused, 200 over h2 | sound |
| API: every protected route anonymous | 401 with `WWW-Authenticate: Bearer`; `/version`, `/healthz`, `/readyz`, `/api/openapi.json` 200 | sound / SEC-36 |
| API: security headers | CSP `default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`, nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP, Permissions-Policy, `Cache-Control: no-store` on `/api/` | sound |
| API: CORS preflight, cross-origin GET | no `Access-Control-*` headers (405 / plain 200) | sound (no CORS) |
| API: cookies | `dnsy_session` HttpOnly SameSite=Strict Path=/ Max-Age=43200; `dnsy_csrf` readable (double submit) | sound; SEC-12 for `Secure` |
| API: DELETE with session but no/wrong CSRF header | 403 | sound |
| API: login wrong password vs unknown user | identical 401 body; 0.22 s both (dummy hash) | sound |
| API: 5 failures from 127.0.0.1 then correct password from 127.0.0.2 | 429, `login_attempts.ip = 0.0.0.0` | **SEC-01** |
| API: half-sent request held 40 s | still open | SEC-11 |
| API: zone name traversal (`..%2F`, `%2e%2e`, `_root`, CRLF) | 400 | sound |
| API: bad JSON, 3 MB body, 100k-deep JSON | 400 (serde detail, no paths), 413, 400 in 7 ms | sound |
| API: `limit=1000000`, `limit=-1`, LIKE metacharacters, `client='` | 400 with bounds message | sound |
| API: 41 concurrent SSE tails | 41st 429, other requests unaffected | SEC-20 |
| API: blocklist `location` to loopback/link-local/mapped-IPv6/`file://`/`ftp://` | request-shape 422 in this probe (field is `location`, not `url`); code path verified statically in section 8 | sound |
| API: `POST /zones` with unknown top-level field | accepted shape (flatten) | DNSY-68 |
| Logs after ~600 requests | 0 token strings, no `Authorization`, DoH URI never logged | sound |
| Fresh `data_dir` | `dnsy.db*` mode 0644 | SEC-13 |

## 5. Status of the DNSY-68 items on `main`

| DNSY-68 item | Status | Evidence |
| --- | --- | --- |
| `check_throttle`/`record_failure` race | present | `crates/dnsy-auth/src/sessions.rs:72,83` (separate read and write transactions). Superseded in impact by SEC-01 |
| Throttle key `(username, ip)` without /64 | present | `sessions.rs:91,97-98`; the ip is always `0.0.0.0` today (SEC-01) |
| Sessions not invalidated on credential change | **fixed** | `crates/dnsy-auth/src/users.rs:200-202,221,254-256`; tests `tests_auth.rs:510,606` |
| `check-svg.sh` grep-based | present | `scripts/check-svg.sh:17` (SEC-25) |
| rcode > 15 truncated without OPT | present | `crates/dnsy-proto/src/message.rs:235` (SEC-23) |
| Bearer path not re-checking owner role | **fixed** | `crates/dnsy-api/src/auth.rs:117-125`, `tokens.rs:308`; tests `tests_auth.rs:477`, e2e `rest_auth.rs:631` |
| DoH throttle table `clear()` and no /64 | present | `crates/dnsy-server/src/doh/throttle.rs:42-47` (line 45 `table.clear()`), key is full `IpAddr` (`:18,33,48`) |
| mTLS expiry not re-checked on open connections | present, narrower | `crates/dnsy-server/src/dot/mtls.rs:364-376`; in the shipped wiring `Allowlist::spawn_refresh` (`serve.rs:226-228`) bumps the generation every 30 s so the gap is at most ~30 s, but embedders without an allowlist have no re-check |
| Client-cert ids reused after deletion | present | `AUTOINCREMENT` not used in `migrations/0008_client_certs.sql` |
| `POST /zones` ignores unknown fields | present | `crates/dnsy-api/src/routes/zones.rs:122-128` (`#[serde(flatten)]` precludes `deny_unknown_fields`) |
| First cache-miss answer not TTL-clamped | present | `crates/dnsy-engine/src/engine.rs:497-503` vs `cache/mod.rs:355-359` |
| New blocklists empty until first refresh | not re-verified here | |
| UI items (blocklist `allow_private`, wrong-password wording, client-side password length, browser matrix) | not re-verified here | |

## 6. Route x role matrix

Derived from `openapi/dnsy.json` (75 operations) and the extractors in
`crates/dnsy-api/src/routes/*.rs`. OAS = `security` declared in the spec (scheme only; scopes are
not expressible). Tested = role/auth assertion in `crates/dnsy-api/src/tests_auth.rs` (U) or
`tests/e2e/tests/rest_auth.rs` (E). Role model: Admin -> all scopes; Operator -> `api:read`,
`api:write`, `dns:query`; Viewer -> `api:read` (`crates/dnsy-core/src/lib.rs:57-63`).

| Method path | Guard in code | OAS | Tested |
| --- | --- | --- | --- |
| GET /healthz, /readyz, /api/v1/version | none (public) | none | tests.rs:229 |
| POST /auth/bootstrap, /auth/login | none (public) | none | U, E |
| POST /auth/logout | Read + session + CSRF | session | U, E |
| GET /auth/me | Read | bearer/session | U, E |
| PUT /auth/me/password | Read, session-only in handler (`auth.rs:249`) | session | U, E |
| GET/POST /users, GET/PATCH/DELETE /users/{id} | Admin | ok | U, E (GET /users/{id}: U) |
| GET /tokens | Read (admin all, others own) | ok | U, E |
| POST /tokens | Read + session-only (`tokens.rs:109`) | session | U, E |
| DELETE /tokens/{id} | Read + ownership (`tokens.rs:150-163`) | ok | U, E |
| GET /zones, /zones/{name}, /records, /export | Read | ok | E (list), zones.rs tests |
| POST /zones, PUT/DELETE /zones/{name}, POST /records | Write | ok | E |
| PUT/DELETE /zones/{name}/records/{id} | Write | ok | zones.rs tests |
| GET /zones/{name}/dnssec, /dnssec/ds, /dnssec/keys; GET /dnssec/status | Read | ok | no role test |
| PUT /zones/{name}/dnssec, POST .../keys, .../ds-confirmed, .../rollover, .../rollover/abort | Admin | ok | dnssec_tests.rs (2 viewer checks) |
| POST /dnssec/keys/export, POST /dnssec/passphrase | Admin + bundle passphrase | ok | no role test |
| GET /acl, /rules, /blocklists, /cache, /querylog, /stats/* | Read | ok | E (stats summary only) |
| POST /acl, DELETE /acl/{id}, PUT /acl/rate-limit, POST/DELETE /rules, POST/PATCH/DELETE /blocklists, POST /blocklists/{id}/refresh, DELETE /cache, DELETE /cache/entries | Write | ok | E |
| POST /blocklists with file path / private target | Write + Admin re-auth (`blocklists.rs:227-243`) | ok | no role test |
| GET /querylog/stream | Write (deliberate, documented) | ok | E, tests_obs.rs:257 |
| GET /upstream-groups, /{name}, /{name}/health | Read | ok | no role test |
| POST /upstream-groups, PUT/DELETE /{name}, POST/DELETE .../upstreams[/index] | Admin | ok | E (groups), none (upstreams) |
| GET/POST /client-certs, PATCH/DELETE /{id} | Admin | ok | E (PATCH untested) |
| GET/PATCH /settings, PATCH /settings/dnssec | Admin | ok | E (settings) |
| GET /settings/dnssec | Read | ok | no role test |

Result: no unguarded route; no route where a viewer can write or an operator reaches user
management, other users' tokens, settings, client certificates or DNSSEC key management. Gaps
are in test coverage only (story F8 adds a generated matrix test).

## 7. Proposed follow-up stories

Ordered by impact over effort. Estimates are story points (1 = half a day).

| # | Title | Acceptance criteria | Est. |
| --- | --- | --- | --- |
| F1 | Wire `ConnectInfo` into the API server and harden login throttling (SEC-01, SEC-03, DNSY-68 items 1-2) | `login_attempts.ip` records the peer address (test through a real listener); throttle reserves the attempt atomically; IPv6 keyed by /64; per-username backoff that cannot lock the legitimate user out from another address; argon2 concurrency bounded by a semaphore with 503 on exhaustion; password length capped. | 3 |
| F2 | Admission control for UDP and TCP/DoT (SEC-02, SEC-04, SEC-09) | Per-client in-flight and connection caps keyed by /32 and /64; UDP cache misses coalesced through `Refreshes`; one shared connection semaphore per transport with oldest-idle eviction; ACL and rate limit evaluated before FORMERR/NOTIMP/BADVERS replies; tests for saturation from one source while another is served. | 5 |
| F3 | Safe resolver defaults and startup warnings (SEC-05, SEC-14) | Default ACL allows loopback, RFC 1918, ULA and link-local only, with an explicit `open_resolver` opt-in; default `per_client_qps` non-zero; warning when a non-loopback listener has an allow-all ACL; ANY answered minimally (RFC 8482) and AXFR/IXFR refused without an upstream round trip; docs and `examples/dnsy.toml` updated. | 3 |
| F4 | KSK rollover keeps the retired SEP key signing DNSKEY (SEC-06, SEC-18, SEC-19) | Retired SEP keys sign the DNSKEY RRset until Removed, or `ds_ttl` gates activation; `POST .../keys` cannot start an implicit rollover; a zone whose keys cannot be opened fails readiness instead of serving unsigned; validator test with old-DS anchors right after the transition. | 3 |
| F5 | Validator hardening: scrub fetches, Indeterminate on fetch errors, opt-out wildcard, REVOKE (SEC-07, SEC-08, SEC-15, SEC-16) | Validator DS/DNSKEY fetches are scrubbed before caching or keyed internally; fetch errors yield Indeterminate cached with `servfail_ttl`; opt-out NSEC3 in a wildcard proof yields Insecure; revoked DNSKEYs are not trusted; unit tests for each. | 3 |
| F6 | Reverse-proxy and file-permission hardening (SEC-11, SEC-12, SEC-13, SEC-17) | `api.secure_cookies` (auto/true/false) drives `Secure` and HSTS; API listener has header-read and idle timeouts and a connection cap; `dnsy.db*` created 0600 in a 0700 `data_dir`; warning for group/world-readable TLS keys; key export refused on plaintext listeners; bundle passphrase minimum 12 with a higher KDF cost. | 3 |
| F7 | Fuzzing in the toolchain (section 4.1, SEC-24) | `fuzz_decode` and a new `fuzz_validate` target run for one hour each on nightly with the corpus committed; a `just fuzz` recipe; `[profile.release]` with `overflow-checks = true`, thin LTO and symbol stripping; the hand-crafted cases from this audit added to `message_tests.rs`. | 3 |
| F8 | Generated route x role matrix test and input limits (section 6, SEC-20, SEC-40) | A test iterates every OpenAPI operation with each role and asserts the expected 2xx/403; token name, username and password length caps; live-tail cap per principal; docs state that scopes are not hierarchical. | 2 |
| F9 | Protocol polish: DNAME canonical form, case-preserving compression, OPT placement, padding (SEC-21, SEC-22, SEC-27, SEC-29) | DNAME/NAPTR RDATA lowercased in canonical form; compression keyed on exact bytes; OPT outside additional is a decode error; padding never evicts RRsets; snapshot tests updated. | 2 |
| F10 | Remaining DNSY-68 items not covered above (DoH throttle table, mTLS expiry re-check, client-cert ids, `deny_unknown_fields` on zones, first-answer TTL clamp, blocklist initial fetch, `check-svg` parser) | Each item has a flip-and-fail test as described in DNSY-68. | 3 |
| F11 | Rate limiter slip and amortised eviction (SEC-10) | 1-in-N over-limit UDP queries get a minimal TC=1 reply; eviction samples instead of scanning the shard; benchmark shows bounded insert cost at saturation. | 2 |
| F12 | Optional anti-spoofing extras (SEC-31, SEC-32, SEC-35) | 0x20 case randomisation towards upstreams with fallback; `dot.client_crl` config wired to the existing CRL verifier; SPKI pin option for `tls://` upstreams; loop guard when the system resolver points at DNSY. | 3 |

## 8. Verified secure

Checked and found sound (file:line on `main`).

**Wire format (`dnsy-proto`).** Every read uses `slice::get`/`read_bytes` with `checked_add`
(`reader.rs:24-29,54,62,71`); no `as` casts on untrusted lengths; no `unwrap`/`expect` reachable
from wire data. Compression pointers must satisfy `target < cursor` and `hops <= 128`
(`reader.rs:70-79`); label types 0x40/0x80 rejected; total name length enforced incrementally
before allocation (`reader.rs:63-66`). Allocation follows parsed data, not counts
(`message.rs:114-130`). RDLENGTH checked against `remaining()` before use (`rdata/mod.rs:137-140`)
and every sub-decoder is closed by the `position == end` check (`:217-221`). Encoder pointers are
strictly backward and below 0x4000 (`writer.rs:63-66`); RRset-atomic truncation with TC
(`message.rs:196-236`). Presentation parsing: `\DDD` three digits, <= 255, non-ASCII rejected
(`name.rs:99-109`, `rdata/text.rs:51-60`). Canonical RR ordering and the RFC 6840 5.1 decision
on which RDATA names to lowercase (`canonical.rs:52-80`, `canonical/tests.rs:134-178`);
`Name::cmp` is RFC 4034 6.1 (`name.rs:205-219`).

**Listeners.** UDP >= 4096 B dropped (`udp.rs:15,41`); EDNS bufsize clamped 512..1232
(`query.rs:37-41`); client EDNS options neither forwarded nor echoed (`engine.rs:724-727`,
`response.rs:91-104`); FORMERR never answers a response packet (`message.rs:319-321`). TCP: whole
frame under `tcp_idle_ms` (`tcp.rs:144-149`), write timeout (`:130`), 32 in-flight per connection
with back-pressure (`:140-142`), garbage closes the stream (`:152`). DoT: TLS 1.2/1.3 only
(`dot/mod.rs:88-90`), ALPN `dot`, session resumption and tickets disabled whenever a client
verifier is set (`:98-103`), handshake under the idle timeout (`:121`), leaf fingerprint checked
after chain validation (`mtls.rs:239-258`), cert reload keeps the previous pair on failure and
checks key/cert match (`dot/certs.rs:43-51,78`), subject text sanitised and bounded
(`mtls.rs:320-326`). DoH: base64url no-pad with both lengths checked (`doh/wire.rs:45-54`),
content type enforced, `Content-Length` pre-check plus `Limited` body of 65 535 and a body timeout
(`doh/mod.rs:393-412`), throttle consulted before any token lookup (`:351-357`), token compare in
constant time (`dnsy-auth/src/tokens.rs:301`), hyper 1.12.0 / h2 0.4.20 (rapid-reset and
CONTINUATION-flood fixes), `max_concurrent_streams(100)`, header read timeout with timer
(`doh/mod.rs:220-230`), URI and `Authorization` never logged (`:279`).

**Engine and cache.** Pipeline order ACL -> rate -> blocklist -> zones -> RD -> cache ->
upstream -> response-IP -> AD shaping (`engine.rs:399-467`); RD=0 -> REFUSED (`:427-429`);
dynamic update/notify -> NOTIMP (`:373-378`); BADVERS (`:379-385`). AD only for Secure, CD=0 and
DO/AD asked (RFC 6840 5.7, `engine.rs:461-462`); CD=1 skips validation and uses its own key
(`:479`); `response_to` clears AD (`message.rs:246-267`). ACL canonicalises IPv4-mapped
(`acl.rs:107`), longest prefix then stricter action (`:87-92,108-111`). Rate limit keys IPv6 by
/64 and mapped v4 as v4 (`ratelimit.rs:25-30`); 100 000 keys max (`engine.rs:51`). Bailiwick
scrub keeps only CNAME-chain owners with the asked type/class, drops additional, keeps SOA only
if it encloses the final name, clears AA/AD, rejects a question mismatch, chain bounded to 16 and
loop-safe (`response.rs:76-78,109-126,201-243`). Negative caching requires SOA and uses
min(SOA TTL, minimum, `negative_max_ttl`) (`cache/mod.rs:348-353`); TC/AA/TTL-0/other-rcode never
cached (`:287-294,361`); SERVFAIL 5 s, Bogus <= 60 s (`:363-367`); Bogus never overwrites a live
Secure entry (`:321-328`); cache key includes DO and CD (`engine.rs:431-437`); mode or anchor
change flushes (`:292-342`). Serve-stale only after failed/slow/SERVFAIL refresh, never Bogus or
SERVFAIL, Secure degraded to Indeterminate without AD, bounded by `max_stale`, refresh coalesced
per key (`engine.rs:486-496`, `cache/stale.rs:29-45,81-87`, `cache/mod.rs:305-309`). Prefetch once
per entry, never Bogus, queue 64, 4 workers (`cache/prefetch.rs:34-40`). Cache globally bounded
with sampled LRU (`cache/mod.rs:334-338,373-398`). Block responses: NullIp TTL 60, NXDOMAIN or
REFUSED, EDE 15/17 only with client EDNS (`dnsy-filter/src/response.rs:8,16-52`); suffix
matching case-insensitive on wire form with allow precedence (`matcher.rs:227-249`).

**Upstream anti-spoofing.** Random ID from `rand::fill` (rand 0.10 CSPRNG)
(`upstream/mod.rs:257-261`); fresh `bind(:0)` + `connect` UDP socket per attempt (`:283-291`);
response must match QR, ID, opcode and the full question (`:271-276`); mismatches ignored until
the timeout (`:293-300`); TC -> TCP retry (`:145-147`); TCP/DoT mismatch is an error
(`:322-326`); DoT upstream verifies the hostname via `ServerName` against webpki or custom roots
with safe protocol versions and no insecure switch (`:107-116,206-214`); only transport errors
affect health (`groups/mod.rs:362-371`).

**DNSSEC validator.** KeyTrap limits enforced before work and exhaustion -> Bogus EDE 6
(`validate/mod.rs:61-73,188-193`): 8 verifications per RRset and 64 per validation checked
before each verify (`rrset.rs:79-86`); only matching tag and algorithm tried (`:74-78`);
unsupported algorithms cost nothing (`:70-73`); DS digests charged to the same budget
(`chain.rs:321-324`); 32 fetches (`:84-87`), 16 zone cuts (`:182-184`); NSEC3 iterations > 100 ->
Insecure before any hash (`denial.rs:206-221`); 64 distinct NSEC3 hashes with the memo checked
first (`:29-40`); shared semaphore of 64 fetches with a deadline (`forward.rs:29,272-282`).
Validity window with RFC 1982 serial arithmetic and skew 300 s capped at 86 400 (`verify.rs:8,43-49`).
ZONE flag and protocol 3 (`verify.rs:34`, `chain.rs:298`); key tag per RFC 4034 App. B
(`proto/rdata/dnssec/mod.rs:59-77`); algorithms 8/10/13/14/15 (`algorithm.rs:48-58`); RFC 6840
5.2/5.11 downgrade handling (`chain.rs:257-292`); RFC 4509 SHA-1 pruning (`:265-271`); RSA per
RFC 3110 1024-8192 bits (`pubkey.rs:9-11,77-106`); ECDSA fixed 64/96 (`:61-73`); Ed25519 32
(`:35-41`). Signer must be an apex under the anchor and the owner under the signer
(`verify.rs:73`, `chain.rs:119,141-146`); type covered != RRSIG; labels <= owner labels
(`verify.rs:57,70`). Wildcard proofs demanded from the signing zone (`response.rs:34-44`,
`denial.rs:337-347`); denial proofs: canonical order, wrap-around and own-owner edges, ancestor
delegation/DNAME NSEC never covers below itself, bitmap and side-of-cut rules, NSEC3 owner must be
a 20-byte hash directly under the signer with algorithm 1, per-record salt/iterations, no
cross-zone mixing, opt-out -> Insecure for NXDOMAIN and DS, ENT NODATA
(`denial.rs:54-69,146-199,253-273,290-292,318-322,424-454`). CNAME/DNAME chains validated per
link (`response.rs:81-156`). TTL cap = min(TTL, original TTL, time to expiry) (`rrset.rs:111-119`,
`engine.rs:649-651`). Trust anchors: root KSK-2017 and KSK-2024 by default
(`dnsy-config/src/model.rs:8-13`); NTAs subtree-scoped with expiry, root NTA refused, admin-only
(`anchors.rs:86-101`, `routes/dnssec.rs:1020-1025`); clock floor from build time ->
Indeterminate with a flush on recovery (`forward.rs:142-170`, `engine.rs:695-703`).

**Signer and key storage.** AES-256-GCM with a 16-byte random salt and 12-byte random nonce per
seal from `SystemRandom` (fresh KEK per seal), header as AAD (`keystore.rs:180-236`); argon2id
v0x13 m=19456 KiB t=2 p=1 (`:142-164`), blob-supplied cost bounded (`:36-37,213-215`), run off
the async threads (`:441-449`); key generation via ring `SystemRandom` (`signing.rs:31-42`);
PKCS#8 in `Zeroizing` with redacted `Debug` (`:24,62,72,158-165`); no API type carries a private
key (`routes/dnssec.rs:119-136`); export only as an encrypted bundle, admin scope, logged
(`:834-854`); import CLI-only; bundle file `create_new` + 0600 (`keystore.rs:1062-1068`);
unencrypted mode warns at startup (observed) and is surfaced as `keys_encrypted`; passphrases
from stdin, env or file, never argv (`cli.rs`, `admin.rs:290-308`). RRSIG inception now-1 h,
validity 14 d minus deterministic jitter, refresh 5 d (`sign/mod.rs:22-26,211-254`); NSEC3
defaults 0 iterations, empty salt, opt-out off, override capped at 500 (`policy.rs:12,73-93`);
DS export SHA-256/384 only; `start_rollover` needs an Active key and refuses a second rollover
(`keystore.rs:686-697`).

**Auth and API.** argon2id m=19456 KiB t=2 p=1 (`password.rs:8-9`); CSPRNG for bootstrap code
128 bit, session id 256 bit, token id 53 bit + secret 256 bit, CSRF 256 bit (`bootstrap.rs:32-33`,
`sessions.rs:144-146`, `tokens.rs:160-167`, `routes/auth.rs:98-100`). Tokens looked up by random
id and compared as SHA-256 with `ct_eq` (`tokens.rs:271-303`); sessions stored hashed
(`sessions.rs:28-30,151`); expiry, revocation and owner-disabled checked on every verify
(`tokens.rs:304`, `sessions.rs:175-177`); idle 30 min / absolute 12 h; login rotates the session
id (`sessions.rs:76-79`); logout deletes server-side (`routes/auth.rs:180-183`); `ON DELETE CASCADE`
with `foreign_keys=ON` (`store.rs:48`). Last-admin protection on delete/demote/disable counts only
active admins (`users.rs:72-80,189-195,246,276-281`). Dummy hash for unknown users and a single
error text (`users.rs:308-321`, probe: 0.22 s either way). Bootstrap one-time, 1 h, printed once
to stderr, race-safe inside the write transaction (`users.rs:346,374-381`). CSRF required for
every non-GET/HEAD/OPTIONS method with no exempt paths (`auth.rs:145-158`); a malformed
`Authorization` never falls back to the cookie (`:102-114`). Security headers as probed
(`security.rs:12-47`); HSTS 2 y with `includeSubDomains` when TLS. Problem+json never carries
internal detail (`error.rs:96-99`). Body limits 1 MiB on zone routes and 2 MiB elsewhere;
serde_json recursion limit holds (100k-deep JSON rejected in 7 ms). All SQL values bound; the only
interpolation is constant column lists and static clause joins (`users.rs:65,101`,
`client_certs.rs:36`, `sources.rs:202`, `dnsy-observe/src/query.rs:80-125`); `LIKE` input escaped
with `ESCAPE '\'` (`query.rs:64-73,94-95`); page sizes capped (querylog 500, records 1000, stats
100). Migrations SHA-256 checksummed, unknown migrations refuse start (`migrate.rs:107-126`).
Zone file names whitelisted `[a-z0-9.-]` with no leading `.`/`..` (`dnsy-zone/src/model.rs:133-146`);
BIND export escapes names and TXT (`name.rs:222-238`, `export.rs:63-76`). SSRF: scheme allowlist
http/https, no userinfo (`fetch.rs:67-82`), every hop resolved and checked against a thorough
non-public list incl. IPv4-mapped/NAT64/6to4/CGNAT and pinned with `resolve_to_addrs`
(`:203-211,299-352`), redirects re-validated per hop with https -> http refused and max 5
(`:206,225-238`), 50 MiB cap on the decompressed stream and a 30 s deadline (`:17-20,162-167,246-259`),
file paths and private targets need admin plus `allow_private` persisted and honoured by the
scheduler (`blocklists.rs:173-243`, `manager.rs:336`). Query log stores `token:<id>`
(`engine.rs:210-214`) and scrubs token-shaped runs (`querylog.rs:326-346`); qnames rendered through
the escaping `Name` display.

**Web UI and supply chain.** No `innerHTML`, `bypassSecurityTrust*`, `DomSanitizer`, `eval`,
`document.write`, `window.open`, `postMessage`, `[href]`/`[src]`/`[style]` bindings anywhere in
`web/src`; attacker-controlled DNS data goes through interpolation or benign attributes; API paths
use `encodeURIComponent`; SSE query via `URLSearchParams`. No `localStorage`/`sessionStorage`/
IndexedDB; the token secret is shown once and dropped on close; password fields use the right
`autocomplete` values. Redirect validation accepts only `redirect` starting with `/` and not `//`
and uses `navigateByUrl` (`login.page.ts:207-210`). CSRF header attached by the interceptor to
every non-safe `/api/` request (`api.interceptor.ts:27-31`). Mascot SVG is a static template;
three.js scene lazy and same-origin; no external fonts/CDN; no service worker. UI serving rejects
`..`, serves only known extensions with an explicit MIME table, and `index.html` is `no-cache`
(`ui.rs:81-114`). CSP works because no component declares `styles`, `inlineCritical` and font
inlining are off, and `security.spec.ts` plus the Playwright `cspGuard` fixture assert it.
Build: `outputHashing: all`, no production sourcemaps, full `strict` TypeScript, pinned
`packageManager`, lockfile v9 with no overrides or `postinstall`, `--frozen-lockfile` everywhere.
Cargo: `unsafe_code = "forbid"` workspace-wide, `deny.toml` denies wildcards, yanked crates,
unknown registries/git and the banned DNS/OpenSSL crates, only crates.io sources in `Cargo.lock`,
the single `build.rs` stamps the build time honouring `SOURCE_DATE_EPOCH`, toolchain pinned to
1.99.1, no `curl | sh` in scripts or recipes.
