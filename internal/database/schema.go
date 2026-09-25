package database

// SchemaSQL contains table definitions and indices for SQLite.
const SchemaSQL = `
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    is_active INTEGER NOT NULL DEFAULT 1,
    allow_extend INTEGER NOT NULL DEFAULT 1,
    max_extensions INTEGER NULL,
    valid_from TEXT NULL,
    valid_until TEXT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    session_token_hash TEXT UNIQUE NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    client_ip TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(session_token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

CREATE TABLE IF NOT EXISTS port_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    custom_text TEXT NOT NULL DEFAULT '',
    availability_mode TEXT NOT NULL DEFAULT 'key_only',
    allow_extend INTEGER NOT NULL DEFAULT 1,
    max_extensions INTEGER NULL,
    grant_duration_seconds INTEGER NOT NULL DEFAULT 3600,
    max_duration_seconds INTEGER NOT NULL DEFAULT 28800,
    valid_from TEXT NULL,
    valid_until TEXT NULL,
    network_match_mode TEXT NOT NULL DEFAULT 'any',
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS port_group_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_group_id INTEGER NOT NULL REFERENCES port_groups(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    port INTEGER NOT NULL,
    UNIQUE(port_group_id, protocol, port)
);
CREATE INDEX IF NOT EXISTS idx_port_group_ports_group ON port_group_ports(port_group_id);

CREATE TABLE IF NOT EXISTS access_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    allow_extend INTEGER NOT NULL DEFAULT 1,
    max_extensions INTEGER NULL,
    max_concurrent_ips INTEGER NULL,
    max_total_uses INTEGER NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    max_duration_seconds INTEGER NULL,
    valid_from TEXT NULL,
    valid_until TEXT NULL,
    last_used_at TEXT NULL,
    created_by_admin_id INTEGER REFERENCES admin_users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_access_keys_hash ON access_keys(password_hash);

CREATE TABLE IF NOT EXISTS access_key_port_groups (
    access_key_id INTEGER NOT NULL REFERENCES access_keys(id) ON DELETE CASCADE,
    port_group_id INTEGER NOT NULL REFERENCES port_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (access_key_id, port_group_id)
);

CREATE TABLE IF NOT EXISTS allowed_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    network_cidr TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'always_allowed',
    scope TEXT NOT NULL DEFAULT 'global',
    allow_extend INTEGER NOT NULL DEFAULT 1,
    max_extensions INTEGER NULL,
    valid_from TEXT NULL,
    valid_until TEXT NULL,
    access_key_id INTEGER NULL REFERENCES access_keys(id) ON DELETE SET NULL,
    grant_duration_seconds INTEGER NOT NULL DEFAULT 3600,
    is_active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_allowed_networks_mode ON allowed_networks(mode, is_active);

CREATE TABLE IF NOT EXISTS allowed_network_port_groups (
    allowed_network_id INTEGER NOT NULL REFERENCES allowed_networks(id) ON DELETE CASCADE,
    port_group_id INTEGER NOT NULL REFERENCES port_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (allowed_network_id, port_group_id)
);

CREATE TABLE IF NOT EXISTS access_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_key_id INTEGER NULL REFERENCES access_keys(id) ON DELETE SET NULL,
    allowed_network_id INTEGER NULL REFERENCES allowed_networks(id) ON DELETE SET NULL,
    grant_source TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    ipv6_prefix_length INTEGER NULL,
    extension_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    visitor_token_hash TEXT UNIQUE NOT NULL,
    granted_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_grants_ip_status ON access_grants(source_ip, status);
CREATE INDEX IF NOT EXISTS idx_access_grants_token ON access_grants(visitor_token_hash);
CREATE INDEX IF NOT EXISTS idx_access_grants_expires ON access_grants(status, expires_at);

CREATE TABLE IF NOT EXISTS access_grant_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_grant_id INTEGER NOT NULL REFERENCES access_grants(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    UNIQUE(access_grant_id, protocol, port)
);
CREATE INDEX IF NOT EXISTS idx_access_grant_ports_grant ON access_grant_ports(access_grant_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_identifier TEXT NOT NULL,
    target_ip TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type);

CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`
