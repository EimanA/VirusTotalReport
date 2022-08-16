-- PRAGMA foreign_keys = ON;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS hashes;
DROP TABLE IF EXISTS hash_report_bridge;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    title TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_value TEXT NOT NULL,
    fortinet_result TEXT,
    positives INTEGER,
    scan_date TEXT
);

CREATE TABLE hash_report_bridge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_id INTEGER NOT NULL,
    report_id INTEGER NOT NULL,
    FOREIGN KEY(hash_id) REFERENCES hashes(id),
    FOREIGN KEY(report_id) REFERENCES reports(id)
);