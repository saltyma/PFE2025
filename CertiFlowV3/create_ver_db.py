import sqlite3
from datetime import datetime
import os

# --- Verifier App database schema creator ---
# Safe to run multiple times. It creates the DB if missing and adds new columns if needed.

db_folder = "verif_app"
os.makedirs(db_folder, exist_ok=True)
db_path = os.path.join(db_folder, "verifier_app.sqlite")

conn = sqlite3.connect(db_path)
c = conn.cursor()

# 1) Core table: verification history
#    Stores each verification attempt with enough evidence for audit & export.
c.execute("""
CREATE TABLE IF NOT EXISTS verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    signer_email TEXT NOT NULL,
    signer_cn TEXT,              -- Common Name parsed from certificate (optional)
    cert_serial TEXT,            -- Serial of the signer certificate (optional)
    ca_cn TEXT,                  -- CA common name used for chain validation
    result TEXT NOT NULL,        -- 'valid' | 'invalid'
    reason TEXT,                 -- failure reason or 'OK'
    verified_at_utc TEXT NOT NULL,   -- ISO8601
    crl_version TEXT,            -- optional CRL version string
    crl_issued_at_utc TEXT,      -- CRL this verification used
    app_version TEXT             -- optional app version string
)
""")

# 2) Trust material snapshot
#    Keep one or more rows; latest is active. Useful for offline verify & audit.
c.execute("""
CREATE TABLE IF NOT EXISTS trust_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_root_pem TEXT,            -- PEM of trusted CA root
    crl_pem TEXT,                -- PEM of CRL used for verification
    crl_version TEXT,
    crl_issued_at_utc TEXT,
    last_sync_utc TEXT           -- when we last refreshed this trust set
)
""")

# 3) App settings as simple key/value pairs (for future toggles).
c.execute("""
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
)
""")

# 4) Local logs (mirrors the idea of user/local logs; JSON 'details' allowed)
c.execute("""
CREATE TABLE IF NOT EXISTS local_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details TEXT
)
""")

# ---- Example of safe schema evolution (idempotent ALTERs) ----
def safe_add_column(table: str, col_def: str):
    try:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        print(f"[OK] Added column to {table}: {col_def}")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print(f"[INFO] Column already exists on {table}: {col_def.split()[0]}")
        else:
            raise e

# In case you decide later to add fields:
safe_add_column("verifications", "pdf_sig_timestamp_utc TEXT")

conn.commit()
conn.close()

print(f"[SUCCESS] Verifier database schema is up to date at {db_path}")
