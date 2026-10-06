CREATE TABLE IF NOT EXISTS users (
	id                  TEXT PRIMARY KEY,
	email               TEXT NOT NULL UNIQUE,
	password_hash       TEXT NOT NULL DEFAULT '',
	failed_logins       INTEGER NOT NULL DEFAULT 0,
	locked_until        INTEGER NOT NULL DEFAULT 0,
	session_generation  INTEGER NOT NULL DEFAULT 0,
	created_at          INTEGER NOT NULL,
	updated_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_tokens (
	hash       TEXT PRIMARY KEY,
	email      TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	id          TEXT PRIMARY KEY,
	user_id     TEXT NOT NULL,
	auth_time   INTEGER NOT NULL,
	auth_method TEXT NOT NULL,
	generation  INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL,
	revoked_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	hash       TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	user_id    TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	used_at    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS login_tokens_expires_at ON login_tokens (expires_at);
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at ON refresh_tokens (expires_at);
