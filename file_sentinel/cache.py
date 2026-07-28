import sqlite3
import time
from pathlib import Path
from typing import Optional


class ScanCache:
    """Keeps a local record of previously scanned hashes so the same file
    isn't re-submitted to VirusTotal every time it reappears (e.g. re-downloads,
    browser retries, or files copied between folders)."""

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                sha256 TEXT PRIMARY KEY,
                malicious_count INTEGER NOT NULL,
                scanned_at REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, sha256: str) -> Optional[int]:
        row = self._conn.execute(
            "SELECT malicious_count FROM scans WHERE sha256 = ?", (sha256,)
        ).fetchone()
        return row[0] if row else None

    def put(self, sha256: str, malicious_count: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans (sha256, malicious_count, scanned_at) VALUES (?, ?, ?)",
            (sha256, malicious_count, time.time()),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
