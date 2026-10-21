-- Query-log lookups by client (DNSY-76). The order (client, ts_ms, id) serves the equality and
-- the newest-first ORDER BY without a sort. Builds in about 0.7 s per million rows.
CREATE INDEX query_log_client ON query_log (client, ts_ms, id);
