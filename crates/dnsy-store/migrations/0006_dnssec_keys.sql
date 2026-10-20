-- Per-zone DNSSEC keys. The private key is PKCS#8, AES-256-GCM encrypted when
-- `encrypted` is 1. A removed key keeps its row but its private key is wiped.
CREATE TABLE dnssec_keys (
    id              INTEGER PRIMARY KEY,
    zone            TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('csk', 'ksk', 'zsk')),
    algorithm       INTEGER NOT NULL CHECK (algorithm IN (13, 15)),
    key_tag         INTEGER NOT NULL CHECK (key_tag BETWEEN 0 AND 65535),
    state           TEXT    NOT NULL CHECK (state IN ('generated', 'published', 'active', 'retired', 'removed')),
    created_at      INTEGER NOT NULL,
    published_at    INTEGER,
    active_at       INTEGER,
    retired_at      INTEGER,
    removed_at      INTEGER,
    ds_confirmed_at INTEGER,
    encrypted       INTEGER NOT NULL CHECK (encrypted IN (0, 1)),
    public_key      BLOB    NOT NULL,
    private_key     BLOB    NOT NULL
);
CREATE INDEX dnssec_keys_zone ON dnssec_keys(zone, role, state);
