"""SQLite-backed durable store.

The database file *is* the checkpoint: every state transition runs inside a
``BEGIN IMMEDIATE`` transaction, so a crash mid-ingest either commits fully or
rolls back, and a restarted process resumes exactly where the log stands.
WAL mode plus a busy timeout lets several worker processes/threads share one
store file and converge on identical state.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source             TEXT PRIMARY KEY,
    quarantined        INTEGER NOT NULL DEFAULT 0,
    quarantine_reason  TEXT,
    last_confirmed_seq INTEGER NOT NULL DEFAULT 0,
    head_digest        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidates (
    source         TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    prev_digest    TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    digest         TEXT NOT NULL,
    signature      TEXT NOT NULL,
    received_at    TEXT NOT NULL,
    PRIMARY KEY (source, seq, digest)
);
CREATE TABLE IF NOT EXISTS confirmed (
    source         TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    prev_digest    TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    digest         TEXT NOT NULL,
    signature      TEXT NOT NULL,
    confirmed_at   TEXT NOT NULL,
    PRIMARY KEY (source, seq)
);
CREATE TABLE IF NOT EXISTS conflicts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    digests     TEXT NOT NULL,           -- JSON array of competing digests
    status      TEXT NOT NULL DEFAULT 'pending',
    detected_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    digest       TEXT NOT NULL,
    segment_json TEXT NOT NULL,
    reason       TEXT NOT NULL,
    conflict_id  INTEGER,
    recorded_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resolutions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    conflict_id     INTEGER NOT NULL,
    source          TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    accepted_digest TEXT NOT NULL,
    rejected_digests TEXT NOT NULL,      -- JSON array
    reason          TEXT NOT NULL,
    decided_by      TEXT NOT NULL,
    decided_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS publications (
    round        INTEGER PRIMARY KEY,
    root         TEXT NOT NULL,
    manifest     TEXT NOT NULL,          -- JSON: source -> {last_seq, head}
    source_count INTEGER NOT NULL,
    publisher    TEXT,
    published_at TEXT NOT NULL
);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Thread-local connections over a shared SQLite file (WAL)."""

    def __init__(self, path: str):
        if path == ":memory:":
            raise ValueError("in-memory databases are not supported; use a file path")
        self.path = path
        self._local = threading.local()
        self._conn().executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    @contextmanager
    def tx(self):
        """Exclusive write transaction; retries while another worker holds the lock."""
        conn = self._conn()
        delay = 0.005
        for _ in range(400):
            try:
                conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                if "locked" in str(exc).lower():
                    time.sleep(delay)
                    delay = min(delay * 1.5, 0.5)
                    continue
                raise
        else:  # pragma: no cover - defensive
            raise sqlite3.OperationalError("could not acquire database write lock")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
