"""SQLite persistence for LinShield.

A single database file holds scan history, individual detections, quarantine
records, the file-integrity baseline and a generic event log. The connection
is created per-process and guarded so the GUI (threaded) and CLI behave.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .models import Detection, Finding, QuarantineEntry, ScanSummary

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type   TEXT NOT NULL,
    started     REAL NOT NULL,
    ended       REAL NOT NULL,
    files       INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    errors      INTEGER NOT NULL,
    infected    INTEGER NOT NULL,
    suspicious  INTEGER NOT NULL,
    quarantined INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS detections (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER,
    path      TEXT NOT NULL,
    verdict   TEXT NOT NULL,
    method    TEXT NOT NULL,
    signature TEXT NOT NULL,
    severity  TEXT NOT NULL,
    details   TEXT,
    sha256    TEXT,
    size      INTEGER,
    ts        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    stored_name   TEXT NOT NULL,
    sha256        TEXT,
    size          INTEGER,
    signature     TEXT,
    severity      TEXT,
    original_mode INTEGER,
    ts            REAL NOT NULL,
    restored      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fim_baseline (
    path   TEXT PRIMARY KEY,
    sha256 TEXT,
    size   INTEGER,
    mode   INTEGER,
    mtime  REAL,
    uid    INTEGER DEFAULT -1,
    gid    INTEGER DEFAULT -1,
    ts     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    title    TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail   TEXT,
    ts       REAL NOT NULL
);
"""


class Database:
    """Thin typed wrapper around the SQLite store."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, timeout=30.0
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- scans -------------------------------------------------------------
    def record_scan(self, summary: ScanSummary) -> int:
        cur = self._conn.execute(
            """INSERT INTO scans
               (scan_type, started, ended, files, bytes, errors,
                infected, suspicious, quarantined)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                summary.scan_type,
                summary.started,
                summary.ended or time.time(),
                summary.files_scanned,
                summary.bytes_scanned,
                summary.errors,
                summary.infected,
                summary.suspicious,
                summary.auto_quarantined,
            ),
        )
        scan_id = int(cur.lastrowid or 0)
        for det in summary.detections:
            self._conn.execute(
                """INSERT INTO detections
                   (scan_id, path, verdict, method, signature, severity,
                    details, sha256, size, ts)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    det.path,
                    det.verdict.value,
                    det.method.value,
                    det.signature,
                    det.severity.value,
                    det.details,
                    det.sha256,
                    det.size,
                    det.timestamp,
                ),
            )
        self._conn.commit()
        return scan_id

    def recent_scans(self, limit: int = 25) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def last_scan(self) -> dict[str, object] | None:
        row = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def recent_detections(self, limit: int = 100) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM detections ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # -- quarantine --------------------------------------------------------
    def add_quarantine(self, entry: QuarantineEntry) -> int:
        cur = self._conn.execute(
            """INSERT INTO quarantine
               (original_path, stored_name, sha256, size, signature,
                severity, original_mode, ts)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                entry.original_path,
                entry.stored_name,
                entry.sha256,
                entry.size,
                entry.signature,
                entry.severity,
                entry.original_mode,
                entry.quarantined_at,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def list_quarantine(self, include_restored: bool = False) -> list[QuarantineEntry]:
        sql = "SELECT * FROM quarantine"
        if not include_restored:
            sql += " WHERE restored = 0"
        sql += " ORDER BY id DESC"
        rows = self._conn.execute(sql).fetchall()
        return [
            QuarantineEntry(
                qid=int(r["id"]),
                original_path=r["original_path"],
                stored_name=r["stored_name"],
                sha256=r["sha256"] or "",
                size=int(r["size"] or 0),
                signature=r["signature"] or "",
                severity=r["severity"] or "medium",
                quarantined_at=float(r["ts"]),
                original_mode=int(r["original_mode"] or 0o600),
            )
            for r in rows
        ]

    def get_quarantine(self, qid: int) -> QuarantineEntry | None:
        for entry in self.list_quarantine(include_restored=True):
            if entry.qid == qid:
                return entry
        return None

    def mark_restored(self, qid: int) -> None:
        self._conn.execute(
            "UPDATE quarantine SET restored = 1 WHERE id = ?", (qid,)
        )
        self._conn.commit()

    def delete_quarantine(self, qid: int) -> None:
        self._conn.execute("DELETE FROM quarantine WHERE id = ?", (qid,))
        self._conn.commit()

    # -- FIM baseline ------------------------------------------------------
    def set_baseline(self, records: list[tuple[str, str, int, int, float, int, int]]) -> None:
        now = time.time()
        self._conn.execute("DELETE FROM fim_baseline")
        self._conn.executemany(
            """INSERT INTO fim_baseline (path, sha256, size, mode, mtime, uid, gid, ts)
               VALUES (?,?,?,?,?,?,?,?)""",
            [(p, h, s, m, mt, u, g, now) for (p, h, s, m, mt, u, g) in records],
        )
        self._conn.commit()

    def get_baseline(self) -> dict[str, dict[str, object]]:
        rows = self._conn.execute("SELECT * FROM fim_baseline").fetchall()
        return {r["path"]: dict(r) for r in rows}

    def baseline_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM fim_baseline").fetchone()
        return int(row["c"]) if row else 0

    # -- events ------------------------------------------------------------
    def add_event(self, finding: Finding) -> None:
        self._conn.execute(
            "INSERT INTO events (category, title, severity, detail, ts) VALUES (?,?,?,?,?)",
            (
                finding.category,
                finding.title,
                finding.severity.value,
                finding.detail,
                finding.timestamp,
            ),
        )
        self._conn.commit()

    def recent_events(self, limit: int = 100) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def counts(self) -> dict[str, int]:
        def one(sql: str) -> int:
            row = self._conn.execute(sql).fetchone()
            return int(tuple(row)[0]) if row else 0

        return {
            "scans": one("SELECT COUNT(*) FROM scans"),
            "detections": one("SELECT COUNT(*) FROM detections"),
            "quarantine": one("SELECT COUNT(*) FROM quarantine WHERE restored = 0"),
            "events": one("SELECT COUNT(*) FROM events"),
            "baseline": one("SELECT COUNT(*) FROM fim_baseline"),
        }
