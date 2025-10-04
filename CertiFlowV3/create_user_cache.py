import sqlite3
from datetime import datetime
import os
from typing import Set

# Folder to store the User cache database
DB_FOLDER = "user_app"
os.makedirs(DB_FOLDER, exist_ok=True)
DB_PATH = os.path.join(DB_FOLDER, "user_cache.sqlite")

SCHEMA_VERSION = 3  # bump if we add new tables/columns in the future


def get_existing_columns(cur: sqlite3.Cursor, table: str) -> Set[str]:
    cur.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def add_column_if_missing(cur: sqlite3.Cursor, table: str, col_def: str, col_name: str):
    cols = get_existing_columns(cur, table)
    if col_name not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")


def main():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Track schema version
    c.execute("PRAGMA user_version")
    current_ver = c.fetchone()[0]

    # ------------------------------
    # Core tables (create if missing)
    # ------------------------------

    # Minimal user info + V3 flags and cert metadata
    c.execute("""
    CREATE TABLE IF NOT EXISTS user_info (
        email TEXT,
        hsm_id TEXT,
        cert_pem TEXT,
        last_sync DATETIME
    )
    """)

    # Pending signatures (unchanged)
    c.execute("""
    CREATE TABLE IF NOT EXISTS pending_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        request_time DATETIME NOT NULL,
        status TEXT NOT NULL
    )
    """)

    # Local logs (unchanged)
    c.execute("""
    CREATE TABLE IF NOT EXISTS local_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        details TEXT
    )
    """)

    # Signed documents history (keep existing design and user_email link)
    c.execute("""
    CREATE TABLE IF NOT EXISTS signed_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_filename TEXT NOT NULL,
        signed_filepath TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        signature_type TEXT NOT NULL
    )
    """)
    # Ensure user_email column exists
    try:
        add_column_if_missing(c, "signed_documents", "user_email TEXT NOT NULL DEFAULT ''", "user_email")
    except sqlite3.OperationalError:
        # In rare race cases, ignore
        pass

    # ------------------------------
    # V3: Additional supporting tables
    # ------------------------------

    # Trust cache for root/CRL material synced from CA
    c.execute("""
    CREATE TABLE IF NOT EXISTS trust_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ca_root_pem TEXT,
        crl_pem TEXT,
        crl_version INTEGER,
        crl_issued_at_utc TEXT,
        last_sync_utc TEXT
    )
    """)

    # Owned certs (history / renewals)
    c.execute("""
    CREATE TABLE IF NOT EXISTS owned_certs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_serial TEXT UNIQUE,
        cert_pem TEXT,
        not_before TEXT,
        not_after TEXT,
        status TEXT
    )
    """)

    # Simple settings key/value
    c.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    # ------------------------------
    # V3: user_info migrations
    # ------------------------------
    # Add flags required by the CA’s three gates + cert metadata
    try:
        add_column_if_missing(c, "user_info", "cert_serial TEXT", "cert_serial")
        add_column_if_missing(c, "user_info", "valid_from TEXT", "valid_from")
        add_column_if_missing(c, "user_info", "valid_to TEXT", "valid_to")
        add_column_if_missing(c, "user_info", "policy_version TEXT DEFAULT 'v3'", "policy_version")
        add_column_if_missing(c, "user_info", "email_verified INTEGER DEFAULT 0", "email_verified")
        add_column_if_missing(c, "user_info", "device_bound INTEGER DEFAULT 0", "device_bound")
        add_column_if_missing(c, "user_info", "activation_consumed INTEGER DEFAULT 0", "activation_consumed")
    except sqlite3.OperationalError:
        # Ignore concurrent ALTER conflicts
        pass

    # Helpful index on email
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_info_email ON user_info(email)")

    # ------------------------------
    # Finalize schema version
    # ------------------------------
    if current_ver < SCHEMA_VERSION:
        c.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    conn.commit()
    conn.close()
    print(f"[OK] User cache database created/updated at {DB_PATH} (schema v{SCHEMA_VERSION})")


if __name__ == "__main__":
    main()
