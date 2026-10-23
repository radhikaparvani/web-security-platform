
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_platform.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_db():
    with get_connection() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                http_status INTEGER,
                findings_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                category TEXT,
                severity TEXT,
                evidence TEXT,
                recommendation TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            );
        """)


def save_scan(target, result):
    findings = result.get("findings", [])

    with get_connection() as connection:
        cursor = connection.execute(
            """INSERT INTO scans (
                target, status, http_status,
                findings_count, created_at
            ) VALUES (?, ?, ?, ?, ?)""",
            (
                target,
                result.get("status", "completed"),
                result.get("http_status"),
                len(findings),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        scan_id = cursor.lastrowid

        for finding in findings:
            connection.execute(
                """INSERT INTO findings (
                    scan_id, title, category, severity,
                    evidence, recommendation
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    str(finding.get("title", "Unknown finding")),
                    finding.get("category", ""),
                    finding.get("severity", ""),
                    finding.get("evidence", ""),
                    finding.get("recommendation", ""),
                ),
            )

    return scan_id


def get_scan_history():
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, target, status, http_status,
                      findings_count, created_at
               FROM scans
               ORDER BY id DESC"""
        ).fetchall()

    return [dict(row) for row in rows]


def get_scan_details(scan_id):
    with get_connection() as connection:
        scan = connection.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if scan is None:
            return None

        findings = connection.execute(
            """SELECT id, title, category, severity,
                      evidence, recommendation
               FROM findings
               WHERE scan_id = ?
               ORDER BY id""",
            (scan_id,),
        ).fetchall()

    result = dict(scan)
    result["findings"] = [dict(row) for row in findings]
    return result
