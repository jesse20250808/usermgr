-- ============================================================
-- User Management Schema
-- ============================================================

-- Users
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(64)  NOT NULL UNIQUE,
    email       VARCHAR(255) NOT NULL UNIQUE,
    password    TEXT         NOT NULL,           -- bcrypt hash
    display_name VARCHAR(128),
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Roles
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(64)  NOT NULL UNIQUE,    -- e.g. "admin", "editor", "viewer"
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Permissions
CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    VARCHAR(64)  NOT NULL,           -- e.g. "users", "reports"
    action      VARCHAR(32)  NOT NULL,           -- e.g. "read", "write", "delete"
    UNIQUE (resource, action)
);

-- Role <-> Permission (M:N)
CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- User <-> Role (M:N)
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Opaque Tokens
CREATE TABLE tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,     -- SHA-256 of the raw token
    name        VARCHAR(128),                    -- e.g. "web session", "api key"
    expires_at  TIMESTAMPTZ,                     -- NULL = non-expiring
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tokens_token_hash ON tokens(token_hash);
CREATE INDEX idx_tokens_user_id    ON tokens(user_id);

-- Audit Log
CREATE TABLE audit_logs (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(128) NOT NULL,           -- e.g. "user.create", "user.delete"
    resource    VARCHAR(64),
    resource_id TEXT,
    ip_address  INET,
    user_agent  TEXT,
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id    ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Seed: default roles
INSERT INTO roles (name, description) VALUES
    ('admin',  'Full access'),
    ('editor', 'Read and write'),
    ('viewer', 'Read only');

-- Seed: default permissions
INSERT INTO permissions (resource, action) VALUES
    ('users',   'read'),
    ('users',   'write'),
    ('users',   'delete'),
    ('roles',   'read'),
    ('roles',   'write'),
    ('audit',   'read');

-- Assign all permissions to admin
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'admin';

-- editor: read/write users
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r
JOIN permissions p ON (p.resource = 'users' AND p.action IN ('read','write'))
WHERE r.name = 'editor';

-- viewer: read users
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r
JOIN permissions p ON (p.resource = 'users' AND p.action = 'read')
WHERE r.name = 'viewer';
