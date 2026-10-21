-- A disabled user cannot log in; their sessions are removed and their tokens stop working.
ALTER TABLE users ADD COLUMN disabled_at INTEGER;
