-- Daily counter rollup (DNSY-87), folded from stats_minute with the same dimensions. day is the
-- unix-second start of a UTC day.
CREATE TABLE stats_day (
    day            INTEGER NOT NULL,
    dimension      TEXT    NOT NULL,
    key            TEXT    NOT NULL,
    count          INTEGER NOT NULL,
    latency_sum_us INTEGER NOT NULL,
    latency_max_us INTEGER NOT NULL,
    PRIMARY KEY (day, dimension, key)
) WITHOUT ROWID;
