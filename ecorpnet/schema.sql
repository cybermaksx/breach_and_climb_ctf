DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS announcements;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS ticket_comments;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS payroll_runs;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS login_attempts;

CREATE TABLE login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_login_attempts ON login_attempts (ip, username, created_at);

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    role          TEXT NOT NULL DEFAULT 'contractor'
                  CHECK (role IN ('contractor', 'employee', 'it', 'manager', 'admin')),
    department    TEXT NOT NULL DEFAULT 'Contractors',
    title         TEXT NOT NULL DEFAULT 'External Contractor',
    phone         TEXT NOT NULL DEFAULT '',
    office        TEXT NOT NULL DEFAULT '',
    bio           TEXT NOT NULL DEFAULT '',
    manager_id    INTEGER REFERENCES users (id),
    salary        INTEGER NOT NULL DEFAULT 0,      -- annual, whole E Coin
    balance       INTEGER NOT NULL DEFAULT 0,      -- E Coin cents
    is_active     INTEGER NOT NULL DEFAULT 1,
    session_epoch INTEGER NOT NULL DEFAULT 0,      -- bump to revoke all session cookies
    hired_at      TEXT NOT NULL DEFAULT (date('now')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
);

CREATE TABLE transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER REFERENCES users (id),   -- NULL = E Corp treasury
    recipient_id INTEGER NOT NULL REFERENCES users (id),
    amount       INTEGER NOT NULL CHECK (amount > 0),
    kind         TEXT NOT NULL CHECK (kind IN ('transfer', 'payroll', 'bonus')),
    memo         TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE payroll_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    period     TEXT UNIQUE NOT NULL,              -- YYYY-MM
    run_by     INTEGER NOT NULL REFERENCES users (id),
    employees  INTEGER NOT NULL,
    total      INTEGER NOT NULL,                  -- cents
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id   INTEGER NOT NULL REFERENCES users (id),
    assignee_id INTEGER REFERENCES users (id),
    subject     TEXT NOT NULL,
    category    TEXT NOT NULL,
    priority    TEXT NOT NULL DEFAULT 'normal',
    status      TEXT NOT NULL DEFAULT 'open',
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE ticket_comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id  INTEGER NOT NULL REFERENCES tickets (id) ON DELETE CASCADE,
    author_id  INTEGER NOT NULL REFERENCES users (id),
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE documents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    category      TEXT NOT NULL,
    clearance     TEXT NOT NULL DEFAULT 'all'
                  CHECK (clearance IN ('all', 'employee', 'manager', 'admin')),
    stored_name   TEXT UNIQUE NOT NULL,
    original_name TEXT NOT NULL,
    size          INTEGER NOT NULL,
    uploaded_by   INTEGER NOT NULL REFERENCES users (id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE announcements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users (id),
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    pinned     INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id   INTEGER NOT NULL REFERENCES users (id),
    title       TEXT NOT NULL,
    report_type TEXT NOT NULL,
    department  TEXT NOT NULL DEFAULT '',
    date_from   TEXT NOT NULL,
    date_to     TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
