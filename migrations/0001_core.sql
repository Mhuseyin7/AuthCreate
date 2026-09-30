-- Reference schema for a durable SQLite/PostgreSQL adapter.
CREATE TABLE users (subject TEXT PRIMARY KEY, email TEXT, email_verified BOOLEAN NOT NULL, name TEXT, username TEXT, roles_json TEXT NOT NULL, groups_json TEXT NOT NULL, custom_claims_json TEXT NOT NULL, enabled BOOLEAN NOT NULL);
CREATE TABLE clients (client_id TEXT PRIMARY KEY, secret_hash TEXT, name TEXT NOT NULL, grant_types_json TEXT NOT NULL, scopes_json TEXT NOT NULL, token_ttl_seconds INTEGER NOT NULL, refresh_ttl_seconds INTEGER NOT NULL);
CREATE TABLE client_redirect_uris (client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, PRIMARY KEY(client_id, redirect_uri));
CREATE TABLE authorization_codes (code_fingerprint TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, subject TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, consumed_at TIMESTAMP);
CREATE TABLE refresh_tokens (token_fingerprint TEXT PRIMARY KEY, client_id TEXT NOT NULL, subject TEXT NOT NULL, expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP, replaced_at TIMESTAMP);
CREATE TABLE sessions (id TEXT PRIMARY KEY, subject TEXT NOT NULL, expires_at TIMESTAMP NOT NULL);
CREATE TABLE signing_keys (kid TEXT PRIMARY KEY, public_jwk_json TEXT NOT NULL, encrypted_private_key BLOB NOT NULL, active BOOLEAN NOT NULL);
CREATE TABLE scenarios (name TEXT PRIMARY KEY, configuration_json TEXT NOT NULL);
CREATE TABLE events (id INTEGER PRIMARY KEY, created_at TIMESTAMP NOT NULL, type TEXT NOT NULL, metadata_json TEXT NOT NULL);
CREATE TABLE admin_users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
