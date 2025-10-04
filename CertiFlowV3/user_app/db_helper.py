# user_app/db_helper.py

import sqlite3
from datetime import datetime
import os
import base64
import hashlib
from typing import Optional, Dict, Any, List, Iterable

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes  # noqa: F401  (kept for future use)

DB_PATH = os.path.join(os.path.dirname(__file__), "user_cache.sqlite")

# ---------- Encryption Utilities ----------
# AES-256 EAX for encrypting HSM IDs in the cache.
# NOTE: Replace MASTER_KEY with a secure derivation in production.
MASTER_KEY = hashlib.sha256(b"your-super-secret-key").digest()

def _iso_utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")

def encrypt(data: Optional[str]) -> Optional[str]:
    if data is None:
        return None
    data_bytes = data.encode("utf-8")
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode("utf-8")

def decrypt(enc_data: Optional[str]) -> Optional[str]:
    if not enc_data:
        return None
    raw = base64.b64decode(enc_data)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode("utf-8")

# ---------- Database Utilities ----------
def connect_db():
    # row_factory returns dict-like rows for convenience in some getters
    conn = sqlite3.connect(DB_PATH)
    return conn

# =========================
# User Info (core V3 model)
# =========================
def add_or_update_user(email: str, hsm_id: Optional[str], cert_pem: Optional[str] = None):
    """Insert or update a user with optional HSM and cert. Does not set flags."""
    enc_hsm = encrypt(hsm_id) if hsm_id else None
    now = _iso_utc_now()
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT 1 FROM user_info WHERE email=?", (email,))
    if c.fetchone():
        c.execute(
            """
            UPDATE user_info
               SET hsm_id = COALESCE(?, hsm_id),
                   cert_pem = COALESCE(?, cert_pem),
                   last_sync = ?
             WHERE email = ?
            """,
            (enc_hsm, cert_pem, now, email),
        )
    else:
        c.execute(
            """
            INSERT INTO user_info (email, hsm_id, cert_pem, last_sync)
            VALUES (?, ?, ?, ?)
            """,
            (email, enc_hsm, cert_pem, now),
        )
    conn.commit()
    conn.close()

def set_verification_flags(
    email: str,
    email_verified: Optional[int] = None,
    device_bound: Optional[int] = None,
    activation_consumed: Optional[int] = None,
):
    """Mirror CA-side truth for the three gates."""
    sets = []
    vals = []
    if email_verified is not None:
        sets.append("email_verified=?")
        vals.append(int(bool(email_verified)))
    if device_bound is not None:
        sets.append("device_bound=?")
        vals.append(int(bool(device_bound)))
    if activation_consumed is not None:
        sets.append("activation_consumed=?")
        vals.append(int(bool(activation_consumed)))
    if not sets:
        return
    sets.append("last_sync=?")
    vals.append(_iso_utc_now())
    vals.append(email)
    conn = connect_db()
    c = conn.cursor()
    c.execute(f"UPDATE user_info SET {', '.join(sets)} WHERE email=?", vals)
    conn.commit()
    conn.close()

def update_cert_metadata(
    email: str,
    cert_serial: Optional[str] = None,
    valid_from: Optional[str] = None,
    valid_to: Optional[str] = None,
    cert_pem: Optional[str] = None,
    policy_version: Optional[str] = "v3",
):
    """Update issued certificate metadata after CA approval."""
    sets = []
    vals = []
    if cert_serial is not None:
        sets.append("cert_serial=?")
        vals.append(cert_serial)
    if valid_from is not None:
        sets.append("valid_from=?")
        vals.append(valid_from)
    if valid_to is not None:
        sets.append("valid_to=?")
        vals.append(valid_to)
    if cert_pem is not None:
        sets.append("cert_pem=?")
        vals.append(cert_pem)
    if policy_version is not None:
        sets.append("policy_version=?")
        vals.append(policy_version)
    sets.append("last_sync=?")
    vals.append(_iso_utc_now())
    vals.append(email)
    conn = connect_db()
    c = conn.cursor()
    c.execute(f"UPDATE user_info SET {', '.join(sets)} WHERE email=?", vals)
    conn.commit()
    conn.close()

def get_user(email: str) -> Optional[Dict[str, Any]]:
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT email, hsm_id, cert_pem, last_sync,
               cert_serial, valid_from, valid_to, policy_version,
               COALESCE(email_verified,0), COALESCE(device_bound,0), COALESCE(activation_consumed,0)
          FROM user_info
         WHERE email=?
        """,
        (email,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "email": row[0],
        "hsm_id": decrypt(row[1]),
        "cert_pem": row[2],
        "last_sync": row[3],
        "cert_serial": row[4],
        "valid_from": row[5],
        "valid_to": row[6],
        "policy_version": row[7],
        "email_verified": int(row[8]),
        "device_bound": int(row[9]),
        "activation_consumed": int(row[10]),
    }

def get_all_users() -> List[Dict[str, Any]]:
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT email, hsm_id, cert_pem, last_sync,
               cert_serial, valid_from, valid_to, policy_version,
               COALESCE(email_verified,0), COALESCE(device_bound,0), COALESCE(activation_consumed,0)
          FROM user_info
        """
    )
    rows = c.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append(
            {
                "email": r[0],
                "hsm_id": decrypt(r[1]),
                "cert_pem": r[2],
                "last_sync": r[3],
                "cert_serial": r[4],
                "valid_from": r[5],
                "valid_to": r[6],
                "policy_version": r[7],
                "email_verified": int(r[8]),
                "device_bound": int(r[9]),
                "activation_consumed": int(r[10]),
            }
        )
    return out

def get_decrypted_hsm_id(email: str) -> Optional[str]:
    """Convenience accessor for handlers that only need the HSMID."""
    u = get_user(email)
    return u.get("hsm_id") if u else None

# =========================
# Pending Signatures
# =========================
def add_pending_signature(file_path: str):
    now = _iso_utc_now()
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO pending_signatures (file_path, request_time, status)
        VALUES (?, ?, ?)
        """,
        (file_path, now, "pending"),
    )
    conn.commit()
    conn.close()

def update_signature_status(signature_id: int, status: str):
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        UPDATE pending_signatures
           SET status=?
         WHERE id=?
        """,
        (status, signature_id),
    )
    conn.commit()
    conn.close()

def get_pending_signatures() -> List[Dict[str, Any]]:
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT id, file_path, request_time, status FROM pending_signatures WHERE status='pending'")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "file_path": r[1], "request_time": r[2], "status": r[3]} for r in rows]

# =========================
# Signed Documents History
# =========================
def add_signed_document(original_filename: str, signed_filepath: str, signature_type: str, user_email: str):
    now = _iso_utc_now()
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO signed_documents (original_filename, signed_filepath, timestamp, signature_type, user_email)
        VALUES (?, ?, ?, ?, ?)
        """,
        (original_filename, signed_filepath, now, signature_type, user_email),
    )
    conn.commit()
    conn.close()

def get_signed_documents_for_user(user_email: str) -> List[Dict[str, Any]]:
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        SELECT id, original_filename, signed_filepath, timestamp, signature_type, user_email
          FROM signed_documents
         WHERE user_email = ?
         ORDER BY timestamp DESC
        """,
        (user_email,),
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "original_filename": r[1],
            "signed_filepath": r[2],
            "timestamp": r[3],
            "signature_type": r[4],
            "user_email": r[5],
        }
        for r in rows
    ]

def delete_signed_document(doc_id: int):
    conn = connect_db()
    c = conn.cursor()
    c.execute("DELETE FROM signed_documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()

def update_document_path(doc_id: int, new_filepath: str):
    conn = connect_db()
    c = conn.cursor()
    c.execute("UPDATE signed_documents SET signed_filepath = ? WHERE id = ?", (new_filepath, doc_id))
    conn.commit()
    conn.close()

# =========================
# Trust Cache (root/CRL)
# =========================
def upsert_trust_cache(
    ca_root_pem: Optional[str] = None,
    crl_pem: Optional[str] = None,
    crl_version: Optional[int] = None,
    crl_issued_at_utc: Optional[str] = None,
):
    """Replace trust cache with the latest material pulled from CA."""
    conn = connect_db()
    c = conn.cursor()
    c.execute("DELETE FROM trust_cache")  # single row policy
    c.execute(
        """
        INSERT INTO trust_cache (ca_root_pem, crl_pem, crl_version, crl_issued_at_utc, last_sync_utc)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ca_root_pem, crl_pem, crl_version, crl_issued_at_utc, _iso_utc_now()),
    )
    conn.commit()
    conn.close()

def get_trust_cache() -> Optional[Dict[str, Any]]:
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        "SELECT id, ca_root_pem, crl_pem, crl_version, crl_issued_at_utc, last_sync_utc FROM trust_cache ORDER BY id DESC LIMIT 1"
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "ca_root_pem": row[1],
        "crl_pem": row[2],
        "crl_version": row[3],
        "crl_issued_at_utc": row[4],
        "last_sync_utc": row[5],
    }

# =========================
# Owned Certificates (history/renewals)
# =========================
def add_owned_cert(cert_serial: str, cert_pem: str, not_before: str, not_after: str, status: str = "valid"):
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT OR REPLACE INTO owned_certs (id, cert_serial, cert_pem, not_before, not_after, status)
        VALUES (
            COALESCE((SELECT id FROM owned_certs WHERE cert_serial=?), NULL),
            ?, ?, ?, ?, ?
        )
        """,
        (cert_serial, cert_serial, cert_pem, not_before, not_after, status),
    )
    conn.commit()
    conn.close()

def get_owned_certs() -> List[Dict[str, Any]]:
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT cert_serial, cert_pem, not_before, not_after, status FROM owned_certs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"cert_serial": r[0], "cert_pem": r[1], "not_before": r[2], "not_after": r[3], "status": r[4]} for r in rows]

def set_owned_cert_status(cert_serial: str, status: str):
    conn = connect_db()
    c = conn.cursor()
    c.execute("UPDATE owned_certs SET status=? WHERE cert_serial=?", (status, cert_serial))
    conn.commit()
    conn.close()

# =========================
# Local Logging
# =========================
def log_action(action: str, details: str = ""):
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO local_logs (action, timestamp, details)
        VALUES (?, ?, ?)
        """,
        (action, _iso_utc_now(), details),
    )
    conn.commit()
    conn.close()

def get_logs() -> List[Dict[str, Any]]:
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT id, action, timestamp, details FROM local_logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "action": r[1], "timestamp": r[2], "details": r[3]} for r in rows]


def delete_logs_by_ids(log_ids: Iterable[int]) -> None:
    """Remove the specified log entries from the local cache."""

    ids = [int(i) for i in log_ids if isinstance(i, (int, float, str)) and str(i).strip()]
    if not ids:
        return

    placeholders = ",".join(["?"] * len(ids))
    conn = connect_db()
    try:
        c = conn.cursor()
        c.execute(f"DELETE FROM local_logs WHERE id IN ({placeholders})", tuple(ids))
        conn.commit()
    finally:
        conn.close()

def clear_local_logs():
    """Deletes all records from the local_logs table."""
    conn = connect_db()
    c = conn.cursor()
    c.execute("DELETE FROM local_logs")
    conn.commit()
    conn.close()

# =========================
# Settings (simple K/V)
# =========================
def set_setting(key: str, value: str):
    conn = connect_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """,
        (key, value),
    )
    conn.commit()
    conn.close()

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    conn = connect_db()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else default

# =========================
# Utility
# =========================
def delete_user(email: str):
    conn = connect_db()
    c = conn.cursor()
    c.execute("DELETE FROM user_info WHERE email=?", (email,))
    conn.commit()
    conn.close()
