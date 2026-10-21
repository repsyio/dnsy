-- Compact query-log rows (DNSY-95): integer codes for transport, source and dnssec and a 4 or 16
-- byte binary client instead of text. The codes are fixed by dnsy-observe (event.rs):
--   transport: udp 0, tcp 1, dot 2, doh 3
--   source:    authoritative 0, cache 1, cache_stale 2, upstream 3, blocked 4, refused 5, error 6
--   dnssec:    unchecked 0, secure 1, insecure 2, bogus 3, indeterminate 4
-- dnsy_ip_blob is registered by the migration runner. A value the mapping does not know becomes
-- NULL and fails the NOT NULL constraint, which rolls the whole migration back.
CREATE TABLE query_log_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms         INTEGER NOT NULL,
    client        BLOB    NOT NULL CHECK (length(client) IN (4, 16)),
    transport     INTEGER NOT NULL CHECK (transport BETWEEN 0 AND 3),
    principal     TEXT,
    qname         TEXT    NOT NULL,
    qtype         INTEGER NOT NULL,
    rcode         INTEGER NOT NULL,
    source        INTEGER NOT NULL CHECK (source BETWEEN 0 AND 6),
    source_detail TEXT,
    dnssec        INTEGER NOT NULL CHECK (dnssec BETWEEN 0 AND 4),
    latency_us    INTEGER NOT NULL
);
INSERT INTO query_log_new (id, ts_ms, client, transport, principal, qname, qtype, rcode, source,
                           source_detail, dnssec, latency_us)
    SELECT id, ts_ms, dnsy_ip_blob(client),
           CASE transport WHEN 'udp' THEN 0 WHEN 'tcp' THEN 1 WHEN 'dot' THEN 2 WHEN 'doh' THEN 3 END,
           principal, qname, qtype, rcode,
           CASE source WHEN 'authoritative' THEN 0 WHEN 'cache' THEN 1 WHEN 'cache_stale' THEN 2
                       WHEN 'upstream' THEN 3 WHEN 'blocked' THEN 4 WHEN 'refused' THEN 5
                       WHEN 'error' THEN 6 END,
           source_detail,
           CASE dnssec WHEN 'unchecked' THEN 0 WHEN 'secure' THEN 1 WHEN 'insecure' THEN 2
                       WHEN 'bogus' THEN 3 WHEN 'indeterminate' THEN 4 END,
           latency_us
    FROM query_log ORDER BY id;
-- Ids stay unique forever: carry the AUTOINCREMENT high-water mark over, even past deleted rows.
DELETE FROM sqlite_sequence WHERE name = 'query_log_new';
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'query_log_new', seq FROM sqlite_sequence WHERE name = 'query_log';
DROP TABLE query_log;
ALTER TABLE query_log_new RENAME TO query_log;
CREATE INDEX query_log_ts ON query_log (ts_ms, id);
CREATE INDEX query_log_client ON query_log (client, ts_ms, id);
-- Same partial index as 0011, over the codes: blocked, refused, error.
CREATE INDEX query_log_rare ON query_log (ts_ms, id)
    WHERE source IN (4, 5, 6) OR rcode NOT IN (0, 3);
