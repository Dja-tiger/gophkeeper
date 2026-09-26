CREATE TABLE IF NOT EXISTS users (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 login VARCHAR(64) NOT NULL UNIQUE, password_hash BYTEA NOT NULL,
 salt BYTEA NOT NULL CHECK(octet_length(salt)=16), key_check BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash VARCHAR(64) PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id), expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS records (
 user_id BIGINT NOT NULL REFERENCES users(id), id VARCHAR(32) NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0), deleted BOOLEAN NOT NULL, data BYTEA,
 labels VARCHAR(64)[] NOT NULL DEFAULT '{}' CHECK(cardinality(labels)<=16),
 PRIMARY KEY(user_id,id)
);
CREATE TABLE IF NOT EXISTS operations (
 user_id BIGINT NOT NULL REFERENCES users(id), id VARCHAR(32) NOT NULL,
 request_hash BYTEA NOT NULL, result JSONB NOT NULL,
 PRIMARY KEY(user_id,id)
);
CREATE INDEX IF NOT EXISTS records_labels ON records USING GIN(labels);
