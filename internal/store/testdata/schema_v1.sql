CREATE TABLE IF NOT EXISTS users (
 login TEXT PRIMARY KEY, password_hash BYTEA NOT NULL,
 salt BYTEA NOT NULL CHECK(octet_length(salt)=16), key_check BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, login TEXT NOT NULL REFERENCES users(login), expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS records (
 login TEXT NOT NULL REFERENCES users(login), id TEXT NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0), deleted BOOLEAN NOT NULL, data BYTEA,
 PRIMARY KEY(login,id)
);
CREATE TABLE IF NOT EXISTS operations (
 login TEXT NOT NULL REFERENCES users(login), id TEXT NOT NULL,
 request_hash BYTEA NOT NULL, result JSONB NOT NULL,
 PRIMARY KEY(login,id)
);
