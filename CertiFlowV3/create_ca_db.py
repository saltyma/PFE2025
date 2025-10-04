# ca_app/create_ca_db.py
import sqlite3
from datetime import datetime
import os
from contextlib import closing

# Single source of truth for the CA database schema (V3).
# Safe to run multiple times. Performs additive migrations and a one-time
# users-table reshape if an old NOT NULL hsm_id column is detected.

DB_FOLDER = "ca_app"
os.makedirs(DB_FOLDER, exist_ok=True)
DB_PATH = os.path.join(DB_FOLDER, "ca_database.sqlite")


def column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


def get_column_meta(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    for row in cur.fetchall():
        # row: (cid, name, type, notnull, dflt_value, pk)
        if row[1] == column:
            return {
                "name": row[1],
                "type": row[2],
                "notnull": bool(row[3]),
                "default": row[4],
                "pk": bool(row[5]),
            }
    return None


def table_exists(cur, table):
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    )
    return cur.fetchone() is not None


def create_or_migrate_users(cur):
    # Desired V3 schema:
    # users(id PK, email UNIQUE NOT NULL, status TEXT DEFAULT 'active',
    #       created_at, updated_at, email_verified INTEGER DEFAULT 0)
    if not table_exists(cur, "users"):
        cur.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        print("[OK] Created users table (V3).")
        return

    # If table exists, check for legacy NOT NULL hsm_id and migrate if necessary.
    legacy = get_column_meta(cur, "users", "hsm_id")
    if legacy and legacy["notnull"]:
        # Migrate to V3: create new table, copy across compatible columns.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users_v3 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        # Ensure columns exist in old table
        cols = []
        for name in ["id", "email", "status", "created_at", "updated_at", "email_verified"]:
            cols.append(name if column_exists(cur, "users", name) else None)
        # Compose copy statement
        select_expr = ", ".join(
            [
                "id",
                "email",
                # Defaults for possibly missing columns
                "COALESCE(status, 'active')",
                "COALESCE(created_at, DATETIME('now'))",
                "COALESCE(updated_at, DATETIME('now'))",
                "COALESCE(email_verified, 0)",
            ]
        )
        cur.execute(f"INSERT OR IGNORE INTO users_v3(id,email,status,created_at,updated_at,email_verified) SELECT {select_expr} FROM users")
        cur.execute("DROP TABLE users")
        cur.execute("ALTER TABLE users_v3 RENAME TO users")
        print("[OK] Migrated legacy users table to V3 (removed NOT NULL hsm_id).")

    # Ensure email_verified exists
    if not column_exists(cur, "users", "email_verified"):
        cur.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
        print("[OK] Added users.email_verified column.")

    # Ensure status exists (default active)
    if not column_exists(cur, "users", "status"):
        cur.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        print("[OK] Added users.status column.")


def create_or_alter_hsm_devices(cur):
    # V3 schema: store HSM ID as hash for lookups + encrypted blob for confidentiality
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS hsm_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hsm_id_hash TEXT UNIQUE,
            hsm_id_enc BLOB,
            status TEXT NOT NULL DEFAULT 'unassigned', -- unassigned|assigned|activated|revoked
            bound_email TEXT,
            activation_code_hash TEXT,
            activation_consumed INTEGER NOT NULL DEFAULT 0,
            detected_at DATETIME NOT NULL,
            bound_at DATETIME,
            activated_at DATETIME,
            last_seen DATETIME,
            notes TEXT
        )
        """
    )
    # Add missing columns if the table pre-existed with legacy schema
    wanted_cols = [
        ("hsm_id_hash", "TEXT"),
        ("hsm_id_enc", "BLOB"),
        ("activation_code_hash", "TEXT"),
        ("activation_consumed", "INTEGER NOT NULL DEFAULT 0"),
        ("last_seen", "DATETIME"),
        ("notes", "TEXT"),
    ]
    for col, typ in wanted_cols:
        if not column_exists(cur, "hsm_devices", col):
            cur.execute(f"ALTER TABLE hsm_devices ADD COLUMN {col} {typ}")
            print(f"[OK] Added hsm_devices.{col} column.")

    # Legacy plaintext columns may exist; we do not drop them here to keep migration safe.
    # Handlers should stop using plaintext columns (`hsm_id`, `activation_code`) after migration.

    # Indexes
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_hsm_devices_hsm_id_hash ON hsm_devices(hsm_id_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hsm_devices_email ON hsm_devices(bound_email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hsm_devices_status ON hsm_devices(status)")


def create_or_alter_certificates(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            cert_serial TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            hsm_id_hash TEXT,
            cert_pem TEXT NOT NULL,
            valid_from DATETIME NOT NULL,
            valid_to DATETIME NOT NULL,
            status TEXT NOT NULL DEFAULT 'valid', -- valid|revoked|expired
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    # Add missing columns for V3
    for col, typ in [
        ("email", "TEXT"),
        ("hsm_id_hash", "TEXT"),
        ("status", "TEXT NOT NULL DEFAULT 'valid'"),
    ]:
        if not column_exists(cur, "certificates", col):
            cur.execute(f"ALTER TABLE certificates ADD COLUMN {col} {typ}")
            print(f"[OK] Added certificates.{col} column.")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_certs_email ON certificates(email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_certs_hsm_hash ON certificates(hsm_id_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status)")


def create_or_alter_admins(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            hsm_id TEXT UNIQUE,
            is_root INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL
        )
        """
    )
    # We keep admins.hsm_id as-is for now because admin HSMs are managed separately.
    # If needed later, we can add admins.hsm_id_hash the same way.


def create_or_alter_pending_requests(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            email TEXT NOT NULL,
            hsm_id_hash TEXT,
            csr_pem TEXT NOT NULL,
            is_renewal INTEGER NOT NULL DEFAULT 0,
            request_date DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    for col, typ in [
        ("email", "TEXT NOT NULL"),
        ("hsm_id_hash", "TEXT"),
        ("is_renewal", "INTEGER NOT NULL DEFAULT 0"),
    ]:
        if not column_exists(cur, "pending_requests", col):
            cur.execute(f"ALTER TABLE pending_requests ADD COLUMN {col} {typ}")
            print(f"[OK] Added pending_requests.{col} column.")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_user ON pending_requests(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pending_email ON pending_requests(email)")


def create_or_alter_crl(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS crl (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_serial TEXT UNIQUE NOT NULL,
            revocation_date DATETIME NOT NULL,
            reason TEXT
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_serial ON crl(cert_serial)")


def create_or_alter_logs(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            admin_id INTEGER,
            action TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            details TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(admin_id) REFERENCES admins(id)
        )
        """
    )
    # Ensure admin_id exists
    if not column_exists(cur, "logs", "admin_id"):
        cur.execute("ALTER TABLE logs ADD COLUMN admin_id INTEGER REFERENCES admins(id)")
        print("[OK] Added logs.admin_id column.")
    # Helpful indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_action ON logs(action)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(timestamp)")


def create_or_alter_email_verifications(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verifications (
            token_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            issued_at DATETIME NOT NULL,
            used_at DATETIME,
            expires_at DATETIME NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_email ON email_verifications(email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ev_expires ON email_verifications(expires_at)")


def main():
    with closing(sqlite3.connect(DB_PATH)) as conn, closing(conn.cursor()) as cur:
        # Foreign keys optional; keep off to avoid migration pain across copies/drops
        cur.execute("PRAGMA foreign_keys = OFF")

        # Users (may perform one-time migration)
        create_or_migrate_users(cur)

        # HSM devices with hashed/encrypted identifiers and hashed activation codes
        create_or_alter_hsm_devices(cur)

        # Core tables
        create_or_alter_certificates(cur)
        create_or_alter_admins(cur)
        create_or_alter_pending_requests(cur)
        create_or_alter_crl(cur)
        create_or_alter_logs(cur)

        # Tokenized email verification flow
        create_or_alter_email_verifications(cur)

        conn.commit()

    print(f"[SUCCESS] CA/Admin database schema is up to date at {DB_PATH}")


if __name__ == "__main__":
    main()
