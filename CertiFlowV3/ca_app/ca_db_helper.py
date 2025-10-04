import sqlite3
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "ca_database.sqlite")

logger = logging.getLogger(__name__)

# ---------------- KMS-lite helpers (simple, explicit) ----------------
_KMS_KEY_B64 = os.environ.get("CERTIFLOW_HSM_KMS_KEY", "").encode()

try:
    from cryptography.fernet import Fernet  # optional
except Exception:  # cryptography might not be available
    Fernet = None  # type: ignore[assignment]

def _get_cipher():
    if not _KMS_KEY_B64 or Fernet is None:
        return None
    try:
        return Fernet(_KMS_KEY_B64)
    except Exception:
        return None

_CIPHER = _get_cipher()

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _encrypt_str(plain: str) -> Optional[bytes]:
    if _CIPHER is None:
        return None
    try:
        return _CIPHER.encrypt(plain.encode("utf-8"))
    except Exception:
        return None

def _decrypt_str(blob: Optional[bytes]) -> Optional[str]:
    if _CIPHER is None or not blob:
        return None
    try:
        return _CIPHER.decrypt(blob).decode("utf-8")
    except Exception:
        return None

def _mask_hsmid(hsmid: Optional[str]) -> str:
    if not hsmid:
        return ""
    s = str(hsmid)
    return s if len(s) <= 8 else f"{s[:4]}…{s[-4:]}"


# ---------------- Core DB connection & bootstrap ----------------

def connect_db():
    return sqlite3.connect(DB_PATH)

def ensure_schema():
    """
    Create missing tables and indexes so a fresh DB works from Setup.
    Safe to call repeatedly.
    """
    conn = connect_db()
    c = conn.cursor()

    # users
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            email_verified INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

    # admins
    c.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            hsm_id TEXT NOT NULL,
            is_root INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email)")

    # hsm_devices
    c.execute("""
        CREATE TABLE IF NOT EXISTS hsm_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hsm_id_hash TEXT UNIQUE NOT NULL,
            hsm_id_enc BLOB,
            status TEXT NOT NULL DEFAULT 'detected',  -- detected|bound|activated|revoked
            detected_at TIMESTAMP,
            last_seen TIMESTAMP,
            bound_email TEXT,
            activation_code_hash TEXT,
            activation_code_enc BLOB,
            activation_consumed INTEGER NOT NULL DEFAULT 0,
            bound_at TIMESTAMP,
            activated_at TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_hsm_hash ON hsm_devices(hsm_id_hash)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_hsm_bound_email ON hsm_devices(bound_email)")
    try:
        c.execute("ALTER TABLE hsm_devices ADD COLUMN activation_code_enc BLOB")
    except Exception:
        pass

    # pending_requests
    c.execute("""
        CREATE TABLE IF NOT EXISTS pending_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            csr_pem TEXT NOT NULL,
            request_date TIMESTAMP NOT NULL,
            hsm_id_hash TEXT,         -- bind CSR to a specific HSM (stable, non-PII)
            hsm_id_enc  BLOB,         -- optional plaintext (when KMS key is set)
            is_renewal INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    # Backward-compat: add columns if the table already existed
    for column, ddl in (
        ("email", "TEXT"),
        ("hsm_id_hash", "TEXT"),
        ("hsm_id_enc", "BLOB"),
        ("is_renewal", "INTEGER NOT NULL DEFAULT 0"),
    ):
        try:
            c.execute(f"ALTER TABLE pending_requests ADD COLUMN {column} {ddl}")
        except Exception:
            pass
    c.execute("CREATE INDEX IF NOT EXISTS idx_pending_hsm_hash ON pending_requests(hsm_id_hash)")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_user ON pending_requests(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_pending_email ON pending_requests(email)")

    # certificates
    c.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cert_serial TEXT UNIQUE NOT NULL,
            cert_pem TEXT NOT NULL,
            valid_from TIMESTAMP NOT NULL,
            valid_to TIMESTAMP NOT NULL,
            email TEXT,
            hsm_id_hash TEXT,
            status TEXT NOT NULL DEFAULT 'valid', -- valid|revoked|expired
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_cert_user ON certificates(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(cert_serial)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cert_hsmhash ON certificates(hsm_id_hash)")

    # crl
    c.execute("""
        CREATE TABLE IF NOT EXISTS crl (
            cert_serial TEXT PRIMARY KEY,
            revocation_date TIMESTAMP NOT NULL,
            reason TEXT
        )
    """)

    # logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            admin_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            details TEXT
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(timestamp)")

    # email_verifications
    c.execute("""
        CREATE TABLE IF NOT EXISTS email_verifications (
            token_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            issued_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_ev_email ON email_verifications(email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ev_expires ON email_verifications(expires_at)")
    
    conn.commit()
    conn.close()

# Ensure schema exists as soon as the module is imported
ensure_schema()


# ---------------- Users ----------------

def add_user(email: str, status: str = "pending"):
    now = datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO users (email, status, created_at, updated_at, email_verified)
            VALUES (?, ?, ?, ?, 0)
        """, (email, status, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

def get_user(email: str):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT id, email, status, email_verified FROM users WHERE email=?", (email,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "email": row[1], "status": row[2], "email_verified": bool(row[3])}
    return None

def get_user_by_id(user_id: int):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT id, email, status, email_verified FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "email": row[1], "status": row[2], "email_verified": bool(row[3])}
    return None

def get_user_by_hsm_id(hsm_id: str):
    h = _sha256_hex(hsm_id)
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT u.id, u.email, u.status, u.email_verified
        FROM hsm_devices d
        JOIN users u ON u.email = d.bound_email
        WHERE d.hsm_id_hash = ?
    """, (h,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "email": row[1], "status": row[2], "email_verified": bool(row[3])}
    return None

def update_user_status(user_id: int, status: str):
    now = datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    c.execute("UPDATE users SET status=?, updated_at=? WHERE id=?", (status, now, user_id))
    conn.commit()
    conn.close()

def mark_email_as_verified(email: str):
    now = datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    c.execute("UPDATE users SET email_verified=1, updated_at=? WHERE email=?", (now, email))
    conn.commit()
    conn.close()


# ---------------- Certificates ----------------

def add_certificate(user_id: int, cert_serial: str, cert_pem: str, valid_from, valid_to, email: Optional[str] = None, hsm_id: Optional[str] = None):
    h_hash = _sha256_hex(hsm_id) if hsm_id else None
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO certificates (user_id, cert_serial, cert_pem, valid_from, valid_to, email, hsm_id_hash, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'valid')
    """, (user_id, cert_serial, cert_pem, valid_from, valid_to, email, h_hash))
    conn.commit()
    conn.close()

def get_latest_certificate_for_user(user_id: int) -> Optional[str]:
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT cert_pem FROM certificates
        WHERE user_id = ?
        ORDER BY valid_from DESC
        LIMIT 1
    """, (user_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


def get_certificate_by_email(email: str) -> Optional[Dict[str, str]]:
    """Return the latest certificate for an email, including serial/validity."""
    if not email:
        return None

    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT cert_serial, cert_pem, valid_from, valid_to
        FROM certificates
        WHERE email = ? AND status = 'valid'
        ORDER BY datetime(valid_from) DESC
        LIMIT 1
        """,
        (email,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None

    cert_serial, cert_pem, valid_from, valid_to = row
    return {
        "cert_serial": cert_serial,
        "cert_pem": cert_pem,
        "valid_from": str(valid_from) if valid_from else None,
        "valid_to": str(valid_to) if valid_to else None,
    }


def get_user_status_snapshot(email: str) -> Optional[Dict[str, Any]]:
    """Return a consolidated view of the user's status for API consumers."""
    if not email:
        return None

    user = get_user(email)
    if not user:
        return None

    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT status, bound_email, activation_consumed, activated_at, hsm_id_enc
        FROM hsm_devices
        WHERE bound_email = ?
        ORDER BY COALESCE(activated_at, bound_at, detected_at) DESC
        LIMIT 1
        """,
        (email,),
    )
    hsm_row = c.fetchone()
    conn.close()

    hsm_info: Dict[str, Any]
    if hsm_row:
        status, bound_email, consumed, activated_at, hsm_enc = hsm_row
        hsm_info = {
            "status": status or "unknown",
            "bound_email": bound_email,
            "activation_consumed": bool(consumed),
            "activated_at": str(activated_at) if activated_at else None,
            "hsm_id": _decrypt_str(hsm_enc),
        }
    else:
        hsm_info = {
            "status": "not_found",
            "bound_email": None,
            "activation_consumed": False,
            "activated_at": None,
            "hsm_id": None,
        }

    cert_info = get_certificate_by_email(email)

    return {
        "email": email,
        "user_status": user.get("status"),
        "email_verified": bool(user.get("email_verified")),
        "hsm": hsm_info,
        "certificate": cert_info,
    }


# ---------------- HSM Management ----------------

def add_detected_hsm(hsm_id: str):
    now = datetime.now(timezone.utc)
    h = _sha256_hex(hsm_id)
    enc = _encrypt_str(hsm_id)

    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO hsm_devices (hsm_id_hash, hsm_id_enc, status, detected_at, last_seen)
            VALUES (?, ?, 'detected', ?, ?)
        """, (h, enc, now, now))
    except sqlite3.IntegrityError:
        c.execute("UPDATE hsm_devices SET last_seen=? WHERE hsm_id_hash=?", (now, h))
    conn.commit()
    conn.close()
    log_admin_action(None, "HSM_DETECTED", json.dumps({"hsm_id_masked": _mask_hsmid(hsm_id)}))

def get_detected_hsms():
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT hsm_id_enc, detected_at, last_seen
        FROM hsm_devices WHERE status='detected'
        ORDER BY detected_at DESC
    """)
    rows = c.fetchall()
    conn.close()

    out = []
    for enc, det, last_seen in rows:
        plain = _decrypt_str(enc) or ""
        out.append({
            "hsm_id": plain,
            "hsm_id_masked": _mask_hsmid(plain),
            "detected_at": str(det),
            "last_seen": str(last_seen) if last_seen else None
        })
    return out

def get_bound_hsms():
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT hsm_id_enc, bound_email, status, bound_at, activated_at, last_seen, activation_code_enc
        FROM hsm_devices WHERE status IN ('bound','activated')
        ORDER BY COALESCE(bound_at, detected_at) DESC
    """)
    rows = c.fetchall()
    conn.close()

    out = []
    for enc, email, status, bound_at, activated_at, last_seen, code_enc in rows:
        plain = _decrypt_str(enc) or ""
        activation_code = _decrypt_str(code_enc) if code_enc else None
        out.append({
            "hsm_id": plain,
            "hsm_id_masked": _mask_hsmid(plain),
            "bound_email": email,
            "status": status,
            "activation_code": activation_code,
            "bound_at": str(bound_at) if bound_at else None,
            "activated_at": str(activated_at) if activated_at else None,
            "last_seen": str(last_seen) if last_seen else None
        })
    return out


def get_hsm_status(hsm_id: str) -> Dict[str, Optional[str]]:
    """Return the current status details for a specific HSM ID."""
    if not hsm_id:
        return {
            "status": "unknown",
            "bound_email": None,
            "activation_consumed": False,
            "activated_at": None,
            "hsm_id": None,
        }

    h = _sha256_hex(hsm_id)
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT status, bound_email, activation_consumed, activated_at, hsm_id_enc
        FROM hsm_devices
        WHERE hsm_id_hash=?
        LIMIT 1
        """,
        (h,),
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return {
            "status": "not_found",
            "bound_email": None,
            "activation_consumed": False,
            "activated_at": None,
            "hsm_id": None,
        }

    status, email, consumed, activated_at, enc = row
    return {
        "status": status or "unknown",
        "bound_email": email,
        "activation_consumed": bool(consumed),
        "activated_at": str(activated_at) if activated_at else None,
        "hsm_id": _decrypt_str(enc),
    }


def bind_hsm(admin_id: int, hsm_id: str, email: str, activation_code: str):
    now = datetime.now(timezone.utc)
    h = _sha256_hex(hsm_id)
    code_hash = _sha256_hex(activation_code)
    code_enc = _encrypt_str(activation_code)

    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        UPDATE hsm_devices
        SET status='bound', bound_email=?, activation_code_hash=?, activation_code_enc=?, bound_at=?
        WHERE hsm_id_hash=? AND status='detected'
    """, (email, code_hash, code_enc, now, h))
    conn.commit()
    conn.close()
    log_admin_action(admin_id, "HSM_BOUND", json.dumps({"hsm_id_masked": _mask_hsmid(hsm_id), "email": email}))

def check_activation_code(hsm_id: str, code: str) -> bool:
    h = _sha256_hex(hsm_id)
    code_hash = _sha256_hex(code)
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT 1 FROM hsm_devices
        WHERE hsm_id_hash = ? AND activation_code_hash = ? AND status='bound'
    """, (h, code_hash))
    ok = c.fetchone() is not None
    conn.close()
    return ok

def activate_hsm(hsm_id: str):
    now = datetime.now(timezone.utc)
    h = _sha256_hex(hsm_id)
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        UPDATE hsm_devices
        SET status='activated', activation_consumed=1, activated_at=?
        WHERE hsm_id_hash=?
    """, (now, h))
    conn.commit()

    c.execute("SELECT bound_email FROM hsm_devices WHERE hsm_id_hash=?", (h,))
    row = c.fetchone()
    user_id = None
    if row and row[0]:
        u = get_user(row[0])
        user_id = u["id"] if u else None
    conn.close()

    log_user_action(user_id, "HSM_ACTIVATED", json.dumps({"hsm_id_masked": _mask_hsmid(hsm_id)}))

def regenerate_activation_code(admin_id: int, hsm_id: str, new_code: str):
    h = _sha256_hex(hsm_id)
    code_hash = _sha256_hex(new_code)
    code_enc = _encrypt_str(new_code)
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        UPDATE hsm_devices
        SET activation_code_hash=?, activation_code_enc=?
        WHERE hsm_id_hash=? AND status IN ('bound','activated')
    """, (code_hash, code_enc, h))
    conn.commit()
    conn.close()
    log_admin_action(admin_id, "HSM_CODE_REGENERATED", json.dumps({"hsm_id_masked": _mask_hsmid(hsm_id)}))

def revoke_hsm(admin_id: int, hsm_id: str, reason: str = "Unspecified"):
    h = _sha256_hex(hsm_id)
    conn = connect_db()
    c = conn.cursor()
    c.execute("UPDATE hsm_devices SET status='revoked' WHERE hsm_id_hash=?", (h,))
    conn.commit()
    conn.close()
    log_admin_action(admin_id, "HSM_REVOKED", json.dumps({"hsm_id_masked": _mask_hsmid(hsm_id), "reason": reason}))


# ---------------- Email Verification helpers ----------------
# These are lightweight wrappers around the email_verifications table
# so other modules can use them without inlining SQL.

def email_verif_recent_unused_exists(email: str, cooldown_seconds: int) -> bool:
    """
    True if there's an unused token for this email issued within cooldown_seconds.
    """
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT issued_at FROM email_verifications
            WHERE email = ? AND used_at IS NULL
            ORDER BY issued_at DESC LIMIT 1
        """, (email,))
        row = c.fetchone()
        if not row:
            return False
        # str(row[0]) is usually 'YYYY-MM-DD HH:MM:SS[.ffffff]'
        ts_str = str(row[0]).split('.')[0]
        try:
            import time as _t
            issued = int(_t.mktime(_t.strptime(ts_str, "%Y-%m-%d %H:%M:%S")))
            return (int(_t.time()) - issued) < cooldown_seconds
        except Exception:
            return False
    finally:
        conn.close()

def email_verif_insert_token(email: str, token: str, expires_at_unix: int) -> None:
    """
    Record a freshly generated token (by its hash) for this email.
    """
    token_hash = _sha256_hex(token)
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR REPLACE INTO email_verifications
            (token_hash, email, issued_at, expires_at, used_at)
            VALUES (?, ?, DATETIME('now'), DATETIME(?, 'unixepoch'), NULL)
        """, (token_hash, email, expires_at_unix))
        conn.commit()
    finally:
        conn.close()

def email_verif_mark_used(token: str) -> None:
    """
    Mark a token as used (by its hash).
    """
    token_hash = _sha256_hex(token)
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("""
            UPDATE email_verifications
            SET used_at = DATETIME('now')
            WHERE token_hash = ?
        """, (token_hash,))
        conn.commit()
    finally:
        conn.close()

def email_verif_get_state(token: str):
    """
    Return (issued_at_iso, expires_at_iso, used_at_iso_or_none) for a token hash,
    or (None, None, None) if the token is unknown.
    """
    token_hash = _sha256_hex(token)
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT issued_at, expires_at, used_at
            FROM email_verifications
            WHERE token_hash = ?
        """, (token_hash,))
        row = c.fetchone()
        if not row:
            return None, None, None
        return str(row[0]), str(row[1]), (str(row[2]) if row[2] else None)
    finally:
        conn.close()

def email_verif_purge_expired() -> int:
    """
    Delete expired and already-used tokens to keep the table small.
    Returns number of rows deleted.
    """
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("""
            DELETE FROM email_verifications
            WHERE expires_at < DATETIME('now') AND used_at IS NOT NULL
        """)
        n = c.rowcount
        conn.commit()
        return n if n is not None else 0
    finally:
        conn.close()


# ---------------- Pending Requests ----------------

def add_pending_request(
    user_id: int,
    email: str,
    csr_pem: str,
    hsm_id: str = "",
    *,
    is_renewal: bool = False,
) -> bool:

    now = datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    try:
        h_hash = _sha256_hex(hsm_id) if hsm_id else None
        h_enc  = _encrypt_str(hsm_id) if hsm_id else None
        c.execute("""
            INSERT INTO pending_requests (
                user_id, email, csr_pem, request_date, hsm_id_hash, hsm_id_enc, is_renewal
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, email, csr_pem, now, h_hash, h_enc, 1 if is_renewal else 0))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        conn.rollback()
        logger.warning(
            "Failed to insert pending CSR request for user_id=%s (possible duplicate or FK violation)",
            user_id,
        )
        return False
      
    finally:
        conn.close()


def get_pending_requests():
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT
            pr.id, pr.user_id, pr.csr_pem, pr.request_date,
            u.email, u.email_verified, u.status,
            pr.is_renewal,
            d.status         AS hsm_status,
            d.bound_email    AS hsm_bound_email,
            pr.hsm_id_enc
        FROM pending_requests pr
        JOIN users u ON u.id = pr.user_id
        LEFT JOIN hsm_devices d ON d.hsm_id_hash = pr.hsm_id_hash
    """)
    rows = c.fetchall()
    conn.close()

    out = []
    for rid, uid, csr, rdate, email, email_verified, user_status, is_renewal, hsm_status, bound_email, enc in rows:
        hsm_plain = _decrypt_str(enc) or None
        # Bound means: this specific device is assigned to THIS email
        is_bound     = bool(bound_email and bound_email == email and hsm_status in ("bound", "activated"))
        is_activated = bool(hsm_status == "activated")
        out.append({
            "id": rid,
            "user_id": uid,
            "email": email,
            "csr_pem": csr,
            "request_date": str(rdate),
            "hsm_id": hsm_plain,
            "user_status": user_status,
            "is_renewal": bool(is_renewal),
            "verification_status": {
                "hsm_bound": is_bound,
                "hsm_activated": is_activated,
                "email_verified": bool(email_verified),
            }
        })
    return out

def get_pending_request_by_id(request_id: int):
    """
    Return a single pending request with the same HSM context fields used in the list view,
    so approvers see the correct 'three checks' for the exact device.
    """
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT
            pr.id, pr.user_id, pr.csr_pem, pr.request_date,
            u.email, u.email_verified, u.status,
            pr.is_renewal,
            d.status         AS hsm_status,
            d.bound_email    AS hsm_bound_email,
            pr.hsm_id_enc
        FROM pending_requests pr
        JOIN users u ON u.id = pr.user_id
        LEFT JOIN hsm_devices d ON d.hsm_id_hash = pr.hsm_id_hash
        WHERE pr.id = ?
    """, (request_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None

    rid, uid, csr, rdate, email, email_verified, user_status, is_renewal, hsm_status, bound_email, enc = row
    hsm_plain = _decrypt_str(enc) or None
    is_bound     = bool(bound_email and bound_email == email and hsm_status in ("bound", "activated"))
    is_activated = bool(hsm_status == "activated")

    return {
        "id": rid,
        "user_id": uid,
        "email": email,
        "csr_pem": csr,
        "request_date": str(rdate),
        "hsm_id": hsm_plain,
        "user_status": user_status,
        "is_renewal": bool(is_renewal),
        "verification_status": {
            "hsm_bound": is_bound,
            "hsm_activated": is_activated,
            "email_verified": bool(email_verified),
        }
    }

def delete_pending_request(request_id: int):
    conn = connect_db()
    c = conn.cursor()
    c.execute("DELETE FROM pending_requests WHERE id=?", (request_id,))
    conn.commit()
    conn.close()


# ---------------- Revocation (CRL) ----------------

def revoke_certificate(cert_serial: str, reason: str = "Unspecified"):
    now = datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO crl (cert_serial, revocation_date, reason) VALUES (?, ?, ?)", (cert_serial, now, reason))
    c.execute("""
        UPDATE users SET status='revoked', updated_at=?
        WHERE id = (SELECT user_id FROM certificates WHERE cert_serial = ?)
    """, (now, cert_serial))
    c.execute("UPDATE certificates SET status='revoked' WHERE cert_serial=?", (cert_serial,))
    conn.commit()
    conn.close()

def is_certificate_revoked(cert_serial: str) -> bool:
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT 1 FROM crl WHERE cert_serial = ?", (cert_serial,))
    ok = c.fetchone() is not None
    conn.close()
    return ok

def get_revoked_certificates() -> List[str]:
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT cert_serial FROM crl")
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]


# ---------------- Admins ----------------

def add_admin(email: str, hsm_id: str, is_root: bool = False):
    now = datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO admins (email, hsm_id, is_root, created_at)
        VALUES (?, ?, ?, ?)
    """, (email, hsm_id, 1 if is_root else 0, now))
    conn.commit()
    conn.close()

def get_admin(email: str):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT id, email, hsm_id, is_root FROM admins WHERE email=?", (email,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "email": row[1], "hsm_id": row[2], "is_root": bool(row[3])}
    return None

def get_admin_by_id(admin_id: int):
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT id, email, hsm_id, is_root FROM admins WHERE id=?", (admin_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "email": row[1], "hsm_id": row[2], "is_root": bool(row[3])}
    return None

def get_all_admins():
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT id, email, hsm_id, is_root FROM admins ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "email": r[1], "hsm_id": r[2], "is_root": bool(r[3])} for r in rows]

def delete_admin(admin_id: int):
    conn = connect_db()
    c = conn.cursor()
    c.execute("DELETE FROM admins WHERE id=?", (admin_id,))
    conn.commit()
    conn.close()


# ---------------- Logging ----------------

def log_user_action(
    user_id: Optional[int],
    action: str,
    details: Any = "",
    timestamp: Optional[datetime] = None,
):
    if isinstance(details, (dict, list)):
        try:
            details = json.dumps(details)
        except Exception:
            details = json.dumps({"detail": str(details)})
    elif details is None:
        details = ""

    now = timestamp or datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO logs (user_id, action, timestamp, details)
        VALUES (?, ?, ?, ?)
    """, (user_id, action, now, details))
    conn.commit()
    conn.close()

def log_admin_action(admin_id: Optional[int], action: str, details: str = ""):
    now = datetime.now(timezone.utc)
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO logs (admin_id, action, timestamp, details)
        VALUES (?, ?, ?, ?)
    """, (admin_id, action, now, details))
    conn.commit()
    conn.close()

def get_logs():
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT l.id, u.email as user_email, a.email as admin_email, l.action, l.timestamp, l.details
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        LEFT JOIN admins a ON l.admin_id = a.id
        ORDER BY l.timestamp DESC
    """)
    rows = c.fetchall()
    conn.close()

    logs = []
    for r in rows:
        details_dict = {}
        try:
            if r[5]:
                details_dict = json.loads(r[5])
        except Exception:
            details_dict = {"raw": r[5]}
        logs.append({
            "id": r[0],
            "user_email": r[1],
            "admin_email": r[2],
            "action": r[3],
            "timestamp": str(r[4]),
            "details": details_dict
        })
    return logs


# ---------------- Aggregates for UI ----------------

def get_all_users_with_certificate_info() -> List[dict]:
    """
    Returns one row per user with certificate and HSM summary fields the UI expects.
    """
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        SELECT
            u.id, u.email, u.status, u.email_verified,
            -- Latest certificate by valid_from
            (SELECT cert_serial FROM certificates c2 WHERE c2.user_id = u.id ORDER BY c2.valid_from DESC LIMIT 1) AS cert_serial,
            (SELECT valid_to   FROM certificates c3 WHERE c3.user_id = u.id ORDER BY c3.valid_from DESC LIMIT 1) AS valid_to,
            (SELECT status     FROM certificates c4 WHERE c4.user_id = u.id ORDER BY c4.valid_from DESC LIMIT 1) AS cert_status,
            -- HSM device bound to this email, if any
            (SELECT hsm_id_enc FROM hsm_devices d WHERE d.bound_email = u.email LIMIT 1) AS hsm_id_enc,
            (SELECT status FROM hsm_devices d2 WHERE d2.bound_email = u.email LIMIT 1) AS hsm_status
        FROM users u
        ORDER BY u.created_at DESC
    """)
    rows = c.fetchall()
    conn.close()

    out = []
    for r in rows:
        user_id, email, status, email_verified, cert_serial, valid_to, cert_status, hsm_enc, hsm_status = r
        hsm_plain = _decrypt_str(hsm_enc) if hsm_enc else None
        out.append({
            "id": user_id,
            "email": email,
            "status": status,
            "email_verified": bool(email_verified),
            "cert_serial": cert_serial,
            "valid_to": str(valid_to) if valid_to else None,
            "cert_status": cert_status,
            "is_revoked": bool(status == "revoked" or (cert_status == "revoked")),
            "hsm_id": hsm_plain,
            "hsm_status": hsm_status
        })
    return out

# Back-compat alias for older callers
def get_all_users_with_certs() -> List[dict]:
    return get_all_users_with_certificate_info()
