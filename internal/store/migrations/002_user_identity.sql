ALTER TABLE users ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY;
ALTER TABLE users ADD CONSTRAINT users_login_key UNIQUE(login);

ALTER TABLE sessions ADD COLUMN user_id BIGINT;
UPDATE sessions SET user_id=users.id FROM users WHERE sessions.login=users.login;
ALTER TABLE sessions ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE sessions DROP COLUMN login;
ALTER TABLE sessions ALTER COLUMN token_hash TYPE VARCHAR(64);

ALTER TABLE records ADD COLUMN user_id BIGINT;
UPDATE records SET user_id=users.id FROM users WHERE records.login=users.login;
ALTER TABLE records ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE records DROP COLUMN login;
ALTER TABLE records ALTER COLUMN id TYPE VARCHAR(32);
ALTER TABLE records ADD PRIMARY KEY(user_id,id);

ALTER TABLE operations ADD COLUMN user_id BIGINT;
UPDATE operations SET user_id=users.id FROM users WHERE operations.login=users.login;
ALTER TABLE operations ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE operations DROP COLUMN login;
ALTER TABLE operations ALTER COLUMN id TYPE VARCHAR(32);
ALTER TABLE operations ADD PRIMARY KEY(user_id,id);

ALTER TABLE users DROP CONSTRAINT users_pkey;
ALTER TABLE users ADD PRIMARY KEY(id);
ALTER TABLE users ALTER COLUMN login TYPE VARCHAR(64);
ALTER TABLE sessions ADD FOREIGN KEY(user_id) REFERENCES users(id);
ALTER TABLE records ADD FOREIGN KEY(user_id) REFERENCES users(id);
ALTER TABLE operations ADD FOREIGN KEY(user_id) REFERENCES users(id);

ALTER TABLE records ADD COLUMN labels VARCHAR(64)[] NOT NULL DEFAULT '{}' CHECK(cardinality(labels)<=16);
CREATE INDEX records_labels ON records USING GIN(labels);
