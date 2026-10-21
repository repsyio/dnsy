-- Query-log lookups by outcome operators search for (DNSY-76). Partial: only blocked, refused
-- and error answers and non-NOERROR/NXDOMAIN response codes; search emits this predicate
-- verbatim so the planner can use the index.
CREATE INDEX query_log_rare ON query_log (ts_ms, id)
    WHERE source IN ('blocked', 'refused', 'error') OR rcode NOT IN (0, 3);
