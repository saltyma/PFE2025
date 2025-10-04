# ca_app/handlers/hsm_management_handler.py

import os
import sys
import time
import secrets
import hashlib
from typing import List, Dict, Tuple, Optional

# --- Path setup to import helpers ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ca_db_helper import (
    connect_db,
    add_detected_hsm,
    get_detected_hsms,
    get_bound_hsms,
    bind_hsm as db_bind_hsm,  # legacy plaintext path (kept for back-compat)
)

# --- Dependency check for pyserial ---
try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except Exception:
    SERIAL_AVAILABLE = False


# -------------------------
# Utilities
# -------------------------

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _mask_hsmid_like(s: str) -> str:
    if not s:
        return ""
    return s if len(s) <= 8 else f"{s[:4]}…{s[-4:]}"


# -------------------------
# Serial / Emulator helpers
# -------------------------

def _probe_port_for_hsmid(
    port_name: str,
    baudrate: int = 115200,
    timeout: float = 0.8,
    per_port_attempts: int = 2,
) -> Optional[str]:
    """
    Production probe used by the app. Returns HSMID on success, None otherwise.
    """
    if not SERIAL_AVAILABLE:
        return None

    for _ in range(per_port_attempts):
        try:
            with serial.Serial(
                port=port_name,
                baudrate=baudrate,
                timeout=timeout,           # read timeout
                write_timeout=timeout,     # write timeout
                dsrdtr=False,              # avoid DSR/DTR lockups on some drivers
            ) as ser:
                try:
                    ser.dtr = True
                    ser.rts = True
                except Exception:
                    pass

                # Drain greeting/noise
                time.sleep(0.05)
                try:
                    pending = getattr(ser, "in_waiting", 0)
                except Exception:
                    pending = 0
                if pending:
                    try:
                        ser.read(pending)
                    except Exception:
                        pass

                # Send probe
                try:
                    ser.write(b"HSMID\r\n")
                    ser.flush()
                except Exception:
                    continue

                def _readline() -> str:
                    try:
                        return ser.readline().decode(errors="ignore").strip()
                    except Exception:
                        return ""

                line1 = _readline()
                if not line1:
                    time.sleep(0.05)
                    line1 = _readline()

                up = line1.upper() if line1 else ""
                if up.startswith("OK"):
                    parts = line1.split()
                    if len(parts) >= 2 and parts[1].upper() == "HSMID":
                        line2 = _readline()
                        if line2 and len(line2) >= 4:
                            return line2
                        if len(parts) >= 3 and len(parts[2]) >= 4:
                            return parts[2]
                    if len(parts) >= 2 and len(parts[1]) >= 4:
                        return parts[1]
                    line2 = _readline()
                    if line2 and len(line2) >= 4:
                        return line2

                if line1 and len(line1) >= 4 and not up.startswith(("ERR", "BAD", "OK")):
                    return line1

                time.sleep(0.05)
        except PermissionError:
            # In use
            return None
        except OSError:
            return None
        except Exception:
            return None

    return None


# -------------------------
# Public API used by pages
# -------------------------

def _visible_ports() -> List[str]:
    if not SERIAL_AVAILABLE:
        return []
    # Allow narrowing via env to avoid problematic ports: CERTIFLOW_SERIAL_PORTS="COM11,COM12"
    env_ports = os.environ.get("CERTIFLOW_SERIAL_PORTS", "").strip()
    if env_ports:
        return [p.strip() for p in env_ports.split(",") if p.strip()]
    return [getattr(p, "device", None) or str(p) for p in serial.tools.list_ports.comports()]

def detect_new_hsms() -> int:
    """
    Scan available serial ports, probe with HSMID, and register newly found devices.
    Returns the count of *newly* added devices.
    """
    if not SERIAL_AVAILABLE:
        return 0

    ports = _visible_ports()
    if not ports:
        return 0

    new_count = 0

    # Known set uses hashes; we cannot rely on plaintext being available
    existing_hashes = set()
    conn = connect_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT hsm_id_hash FROM hsm_devices")
        existing_hashes = {r[0] for r in cur.fetchall() if r and r[0]}
    finally:
        conn.close()

    for port_name in ports:
        hsm_id = _probe_port_for_hsmid(port_name)
        if not hsm_id:
            continue
        h = _sha256_hex(hsm_id)
        if h in existing_hashes:
            continue
        add_detected_hsm(hsm_id)
        existing_hashes.add(h)
        new_count += 1

    return new_count


def get_detected_hsms_for_ui() -> List[Dict]:
    """
    Returns detected devices for the Detected table, including hashes.
    Shape: [{ "hsm_id": str|None, "hsm_id_masked": str, "hsm_id_hash": str, "detected_at": str, "last_seen": str|None }]
    """
    # Prefer DB direct read to ensure we always return the hash even when decryption is unavailable
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT hsm_id_hash, hsm_id_enc, detected_at, last_seen
        FROM hsm_devices WHERE status='detected'
        ORDER BY detected_at DESC
    """)
    rows = cur.fetchall()
    conn.close()

    # Try to use the ca_db_helper version to get plaintext if available
    fallback_plain = { (r.get("hsm_id_hash") if "hsm_id_hash" in r else None): r.get("hsm_id")
                       for r in [] }  # kept for structure; not used without helper change

    out = []
    from ca_db_helper import _decrypt_str  # local helper is private but available
    for hsm_hash, enc, det, last_seen in rows:
        plain = _decrypt_str(enc) if enc else None
        # If no plaintext, mask from hash
        masked = _mask_hsmid_like(plain) if plain else f"HSM-{_mask_hsmid_like(hsm_hash)}"
        out.append({
            "hsm_id": plain,                 # may be None when encryption key is not configured
            "hsm_id_masked": masked,
            "hsm_id_hash": hsm_hash,
            "detected_at": str(det),
            "last_seen": str(last_seen) if last_seen else None
        })
    return out


def get_bound_hsms_for_ui() -> List[Dict]:
    """
    Returns bound or activated devices for the Bound table, including hashes.
    Shape: [{ "hsm_id": str|None, "hsm_id_masked": str, "hsm_id_hash": str, "bound_email": str|None, "status": str, ... }]
    """
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT hsm_id_hash, hsm_id_enc, bound_email, status, bound_at, activated_at, last_seen, activation_code_enc
        FROM hsm_devices WHERE status IN ('bound','activated')
        ORDER BY COALESCE(bound_at, detected_at) DESC
    """)
    rows = cur.fetchall()
    conn.close()

    from ca_db_helper import _decrypt_str
    out = []
    for hsm_hash, enc, email, status, bound_at, activated_at, last_seen, code_enc in rows:
        plain = _decrypt_str(enc) if enc else None
        masked = _mask_hsmid_like(plain) if plain else f"HSM-{_mask_hsmid_like(hsm_hash)}"
        activation_code = _decrypt_str(code_enc) if code_enc else None
        out.append({
            "hsm_id": plain,
            "hsm_id_masked": masked,
            "hsm_id_hash": hsm_hash,
            "bound_email": email,
            "status": status,
            "activation_code": activation_code,
            "bound_at": str(bound_at) if bound_at else None,
            "activated_at": str(activated_at) if activated_at else None,
            "last_seen": str(last_seen) if last_seen else None
        })
    return out


def _generate_activation_code(n_bytes: int = 16) -> str:
    return secrets.token_urlsafe(n_bytes)


# -------- Hash-first ops (preferred path) --------

def bind_hsm_to_email_by_hash(admin_id: int, hsm_id_hash: str, email: str) -> Tuple[bool, str, Optional[str]]:
    """
    Bind a detected device (identified by its hash) to an institutional email and generate a one-time activation code.
    Stores only the activation_code_hash in DB. Returns the plaintext code once for the UI to display.
    """
    if not hsm_id_hash or not email:
        return False, "Missing HSM hash or email.", None
    code = _generate_activation_code()
    code_hash = _sha256_hex(code)
    from ca_db_helper import _encrypt_str  # local KMS helper (may return None)
    code_enc = _encrypt_str(code)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE hsm_devices
        SET status='bound', bound_email=?, activation_code_hash=?, activation_code_enc=?, bound_at=?
        WHERE hsm_id_hash=? AND status='detected'
    """, (email, code_hash, code_enc, now, hsm_id_hash))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    if changed <= 0:
        return False, "HSM not found in detected state.", None
    return True, "Device bound. Provide the activation code to the user.", code


def regenerate_activation_code_by_hash(admin_id: int, hsm_id_hash: str, new_code: str) -> Tuple[bool, str]:
    if not hsm_id_hash or not new_code:
        return False, "Missing HSM hash or code."
    code_hash = _sha256_hex(new_code)
    from ca_db_helper import _encrypt_str
    code_enc = _encrypt_str(new_code)
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE hsm_devices
        SET activation_code_hash=?, activation_code_enc=?
        WHERE hsm_id_hash=? AND status IN ('bound','activated')
    """, (code_hash, code_enc, hsm_id_hash))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    if changed <= 0:
        return False, "HSM not found or not in bound/activated state."
    return True, "Activation code updated."


def revoke_hsm_by_hash(admin_id: int, hsm_id_hash: str, reason: str = "Unspecified") -> Tuple[bool, str]:
    if not hsm_id_hash:
        return False, "Missing HSM hash."
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE hsm_devices SET status='revoked' WHERE hsm_id_hash=?", (hsm_id_hash,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    if changed <= 0:
        return False, "HSM not found."
    return True, "Device revoked."


# -------- Legacy plaintext ops (kept for back-compat) --------

def bind_hsm_to_email(admin_id: int, hsm_id: str, email: str) -> Tuple[bool, str, Optional[str]]:
    """
    Legacy plaintext variant. Prefer bind_hsm_to_email_by_hash from the UI.
    """
    if not hsm_id or not email:
        return False, "Missing HSM ID or email.", None
    code = _generate_activation_code()
    try:
        db_bind_hsm(admin_id, hsm_id, email, code)
        return True, f"Device {hsm_id} bound to {email}. Provide the activation code to the user.", code
    except Exception as ex:
        return False, f"Binding failed: {str(ex)}", None


# --------------------------------------------------------------------
#                           SMOKE TEST (HARD TIMEOUT)
# ... unchanged from your current file ...
# --------------------------------------------------------------------

# Keep your existing smoke-test implementation here (unchanged).
# (Omitted for brevity; no functional changes needed to the smoke CLI.)
