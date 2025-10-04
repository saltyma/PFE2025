# verif_app/ver_db_helper.py
"""
Verifier App - Database Helper
--------------------------------
- Works with the SQLite DB created by create_db.py
- Safe to import anywhere in the verifier app
- Provides: init, insert verification, list & fetch, trust-store snapshot, settings, and local logs.

Tables expected (see create_db.py):
  verifications(id, file_name, file_sha256, signer_email, signer_cn, cert_serial,
                ca_cn, result, reason, verified_at_utc, crl_version, crl_issued_at_utc, app_version)
  trust_store(id, ca_root_pem, crl_pem, crl_version, crl_issued_at_utc, last_sync_utc)
  settings(key PRIMARY KEY, value)
  local_logs(id, action, timestamp, details)
"""

from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional, Iterable, Tuple
from contextlib import contextmanager

DB_PATH = Path(__file__).resolve().parent / "verifier_app.sqlite"

# ---------- Low-level utilities ----------

@contextmanager
def _connect(db_path: Path = DB_PATH):
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    finally:
        conn.close()

def _exec(conn: sqlite3.Connection, sql: str, params: Iterable = ()):
    cur = conn.execute(sql, params)
    return cur

def _fetchall_dicts(cur: sqlite3.Cursor) -> List[Dict[str, Any]]:
    rows = cur.fetchall()
    return [dict(r) for r in rows]

def _fetchone_dict(cur: sqlite3.Cursor) -> Optional[Dict[str, Any]]:
    row = cur.fetchone()
    return dict(row) if row else None

# ---------- Schema init / sanity ----------

def init_db():
    with _connect() as conn:
        # --- THE FIX: Added 'pdf_sig_timestamp_utc' column ---
        _exec(conn, """
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            file_sha256 TEXT NOT NULL,
            signer_email TEXT NOT NULL,
            signer_cn TEXT,
            cert_serial TEXT,
            ca_cn TEXT,
            result TEXT NOT NULL,
            reason TEXT,
            verified_at_utc TEXT NOT NULL,
            pdf_sig_timestamp_utc TEXT, -- Added this column
            crl_version TEXT,
            crl_issued_at_utc TEXT,
            app_version TEXT
        )""")
        _exec(conn, """
        CREATE TABLE IF NOT EXISTS trust_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ca_root_pem TEXT, crl_pem TEXT, crl_version TEXT,
            crl_issued_at_utc TEXT, last_sync_utc TEXT
        )""")
        _exec(conn, "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        _exec(conn, """
        CREATE TABLE IF NOT EXISTS local_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL, timestamp TEXT NOT NULL, details TEXT
        )""")

# ---------- Verifications ----------

def add_verification(
    *,
    file_name: str, file_sha256: str, signer_email: str, result: str,
    verified_at_utc: str, reason: Optional[str] = None,
    signer_cn: Optional[str] = None, cert_serial: Optional[str] = None,
    ca_cn: Optional[str] = None, crl_version: Optional[str] = None,
    crl_issued_at_utc: Optional[str] = None, app_version: Optional[str] = None,
    pdf_sig_timestamp_utc: Optional[str] = None # Added this parameter
) -> int:
    init_db()
    with _connect() as conn:
        cur = _exec(conn, """
            INSERT INTO verifications
            (file_name, file_sha256, signer_email, signer_cn, cert_serial, ca_cn,
             result, reason, verified_at_utc, crl_version, crl_issued_at_utc,
             app_version, pdf_sig_timestamp_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            file_name, file_sha256, signer_email, signer_cn, cert_serial, ca_cn,
            result, reason, verified_at_utc, crl_version, crl_issued_at_utc,
            app_version, pdf_sig_timestamp_utc
        ))
        return cur.lastrowid

def list_verifications(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Return most recent verifications (paged).
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, """
            SELECT * FROM verifications
            ORDER BY datetime(verified_at_utc) DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return _fetchall_dicts(cur)

def get_verification(verification_id: int) -> Optional[Dict[str, Any]]:
    """
    Return a single verification row by id.
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, "SELECT * FROM verifications WHERE id = ?", (verification_id,))
        return _fetchone_dict(cur)

def find_verification_by_hash(file_sha256: str, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Lookup verifications by exact SHA-256.
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, """
            SELECT * FROM verifications
            WHERE file_sha256 = ?
            ORDER BY datetime(verified_at_utc) DESC
            LIMIT ?
        """, (file_sha256, limit))
        return _fetchall_dicts(cur)

# ---------- Trust store snapshots ----------

def save_trust_snapshot(
    *,
    ca_root_pem: Optional[str],
    crl_pem: Optional[str],
    crl_version: Optional[str],
    crl_issued_at_utc: Optional[str],
    last_sync_utc: str
) -> int:
    """
    Store the latest trust set (CA root + CRL) used for verification/audit.
    Returns inserted row id.
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, """
            INSERT INTO trust_store
            (ca_root_pem, crl_pem, crl_version, crl_issued_at_utc, last_sync_utc)
            VALUES (?, ?, ?, ?, ?)
        """, (ca_root_pem, crl_pem, crl_version, crl_issued_at_utc, last_sync_utc))
        return cur.lastrowid

def get_latest_trust_snapshot() -> Optional[Dict[str, Any]]:
    """
    Get most recent trust snapshot.
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, """
            SELECT * FROM trust_store
            ORDER BY datetime(last_sync_utc) DESC, id DESC
            LIMIT 1
        """)
        return _fetchone_dict(cur)

# ---------- Settings (simple KV) ----------

def set_setting(key: str, value: str) -> None:
    """
    Upsert a setting key/value.
    """
    init_db()
    with _connect() as conn:
        _exec(conn, """
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """, (key, value))

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Fetch a setting value or default.
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, "SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else default

# ---------- Local logs ----------

def log_action(action: str, timestamp_utc: str, details_json: Optional[str] = None) -> int:
    """
    Append a local log entry (JSON string allowed in details).
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, """
            INSERT INTO local_logs (action, timestamp, details)
            VALUES (?, ?, ?)
        """, (action, timestamp_utc, details_json))
        return cur.lastrowid

def list_logs(limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Return recent local logs (paged).
    """
    init_db()
    with _connect() as conn:
        cur = _exec(conn, """
            SELECT * FROM local_logs
            ORDER BY datetime(timestamp) DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return _fetchall_dicts(cur)


def delete_logs_by_ids(log_ids: Iterable[int]) -> None:
    ids = [int(i) for i in log_ids if isinstance(i, (int, float, str)) and str(i).strip()]
    if not ids:
        return

    placeholders = ",".join(["?"] * len(ids))
    init_db()
    with _connect() as conn:
        _exec(conn, f"DELETE FROM local_logs WHERE id IN ({placeholders})", tuple(ids))
