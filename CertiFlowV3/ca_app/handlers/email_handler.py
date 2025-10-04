import os
import sys
import json
import smtplib
import ssl
import argparse
import base64
import time
import hmac
import hashlib
from email.message import EmailMessage
from typing import Optional

# Resolve project root for helper import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ca_db_helper import connect_db, mark_email_as_verified, get_user, log_user_action

# ------------------------------------------------------------------------------
# Config (config.json is the source of truth)
# ------------------------------------------------------------------------------
def _load_config():
    cfg_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    cfg_path = os.path.abspath(cfg_path)
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

CFG = _load_config()
SMTP_USER = (CFG.get("sender_email") or "").strip()
SMTP_PASS = (CFG.get("app_password") or "").strip()
TOKEN_SECRET = (CFG.get("token_secret") or "").strip()
API_BASE = (CFG.get("api_base_url") or "http://127.0.0.1:7001").rstrip("/")

TOKEN_TTL = int(CFG.get("token_ttl_seconds") or 24 * 3600)
RESEND_COOLDOWN = int(CFG.get("email_cooldown_seconds") or 120)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT_SSL = 465

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def _now() -> int:
    return int(time.time())

def _require_email_cfg() -> Optional[str]:
    if not SMTP_USER or not SMTP_PASS or not TOKEN_SECRET:
        return ("Email verification not configured. "
                "Set sender_email, app_password and token_secret in config.json.")
    return None

# ------------------------------------------------------------------------------
# Token generation / verification (HMAC + exp)
# ------------------------------------------------------------------------------
def _generate_token(email: str) -> str:
    payload = {"email": email, "exp": _now() + TOKEN_TTL}
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = _hmac_sha256(TOKEN_SECRET.encode(), payload_json)
    return f"{_b64u(payload_json)}.{_b64u(sig)}"

def _verify_token(token: str) -> tuple[bool, Optional[str], Optional[str]]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return False, None, "Malformed token."
        payload_b64, sig_b64 = parts
        payload_json = _b64u_dec(payload_b64)
        sig = _b64u_dec(sig_b64)
        expected = _hmac_sha256(TOKEN_SECRET.encode(), payload_json)
        if not hmac.compare_digest(sig, expected):
            return False, None, "Invalid signature."
        payload = json.loads(payload_json.decode())
        email = payload.get("email")
        exp = int(payload.get("exp", 0))
        if not email or _now() > exp:
            return False, None, "Token expired."
        return True, email, None
    except Exception:
        return False, None, "Invalid token."

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

# ------------------------------------------------------------------------------
# DB helpers (throttle + persist tokens)
# ------------------------------------------------------------------------------
def _recent_unused_token_exists(email: str) -> bool:
    conn = connect_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT issued_at FROM email_verifications
            WHERE email = ? AND used_at IS NULL
            ORDER BY issued_at DESC LIMIT 1
        """, (email,))
        row = cur.fetchone()
        if not row:
            return False
        ts_str = str(row[0]).split('.')[0]
        try:
            issued_tuple = time.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            issued = int(time.mktime(issued_tuple))
        except Exception:
            return False
        return _now() - issued < RESEND_COOLDOWN
    finally:
        conn.close()

def _insert_token(email: str, token: str, exp_ts: int):
    conn = connect_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT OR REPLACE INTO email_verifications (token_hash, email, issued_at, expires_at, used_at)
            VALUES (?, ?, DATETIME('now'), DATETIME(?, 'unixepoch'), NULL)
        """, (_token_hash(token), email, exp_ts))
        conn.commit()
    finally:
        conn.close()

def _mark_token_used(token: str):
    conn = connect_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE email_verifications SET used_at = DATETIME('now')
            WHERE token_hash = ?
        """, (_token_hash(token),))
        conn.commit()
    finally:
        conn.close()

# ------------------------------------------------------------------------------
# Return type compatible with both tuple-unpack and boolean checks
# ------------------------------------------------------------------------------
class SendResult:
    def __init__(self, ok: bool, message: str = ""):
        self.ok = ok
        self.message = message
    def __bool__(self): return self.ok
    def __iter__(self):
        yield self.ok
        yield self.message
    def __repr__(self):
        return f"SendResult(ok={self.ok!r}, message={self.message!r})"

# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------
def send_verification_email(recipient_email: str) -> SendResult:
    miscfg = _require_email_cfg()
    if miscfg:
        return SendResult(False, miscfg)

    if _recent_unused_token_exists(recipient_email):
        return SendResult(False, f"Please wait {RESEND_COOLDOWN}s before requesting another email.")

    token = _generate_token(recipient_email)
    verification_link = f"{API_BASE}/api/verify_email?token={token}"

    ok, email, reason = _verify_token(token)
    if not ok or not email:
        return SendResult(False, reason or "Could not generate token.")
    exp = _now() + TOKEN_TTL
    _insert_token(recipient_email, token, exp)

    # ------------------------------------------------------------------
    # EMAIL HTML: light page bg, centered dark card, centered brand/logo
    # ------------------------------------------------------------------
    html_body = f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:24px 12px;background:#F4F6FA;
               font:15px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,'Helvetica Neue',Arial,sans-serif;color:#1C2430;">
    <div style="max-width:640px;margin:0 auto;">
      <div style="background:#1E1E1E;border:1px solid rgba(0,0,0,.15);border-radius:14px;
                  padding:26px 22px;box-shadow:0 10px 30px rgba(0,0,0,.15); text-align:center;">
        <div style="font-weight:800; font-size:39px; letter-spacing:.3px; margin-bottom:8px; color:#E6EEF8;">
          Certi<span style="color:#9B2335;">Flow.</span>
        </div>
        <h1 style="margin:0 0 8px;font-size:20px;line-height:1.35;color:#E6EEF8;">Verify your email</h1>
        <div style="margin:0 auto 18px; max-width:520px; color:#8FA0B3;">
          Click the button to confirm your address and continue in CertiFlow.
        </div>
        <p style="margin:0 0 16px;">
          <a href="{verification_link}" 
             style="display:inline-block;padding:10px 16px;border-radius:10px;text-decoration:none;
                    background:#9B2335;color:#fff;font-weight:700;box-shadow:0 6px 18px rgba(0,0,0,.25);">
            Verify my email
          </a>
        </p>
        <div style="color:#8FA0B3;font-size:13px;margin-top:12px;">If the button doesn’t work, copy this link:</div>
        <div style="margin-top:8px;padding:10px 12px;border-radius:8px;background:#141414;
                    border:1px solid rgba(255,255,255,.06);word-break:break-all;">
          <a href="{verification_link}" style="color:#D6EAFB;text-decoration:none">{verification_link}</a>
        </div>
      </div>
    </div>
  </body>
</html>
    """

    msg = EmailMessage()
    msg["Subject"] = "Verify your CertiFlow email"
    msg["From"] = SMTP_USER
    msg["To"] = recipient_email
    msg.set_content(f"Verify your email: {verification_link}")
    msg.add_alternative(html_body, subtype="html")

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT_SSL, context=context) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        try:
            u = get_user(recipient_email)
            log_user_action(u["id"] if u else None, "EMAIL_VERIFICATION_SENT",
                            json.dumps({"cooldown": RESEND_COOLDOWN}))
        except Exception:
            pass

        return SendResult(True, "Verification email sent.")
    except Exception as ex:
        return SendResult(False, f"SMTP error: {ex}")

def verify_token_and_mark(token: str) -> dict:
    miscfg = _require_email_cfg()
    if miscfg:
        return {"ok": False, "email": None, "reason": miscfg}

    ok, email, reason = _verify_token(token)
    if not ok or not email:
        return {"ok": False, "email": None, "reason": reason or "Invalid token."}

    conn = connect_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT issued_at, expires_at, used_at FROM email_verifications
            WHERE token_hash = ?
        """, (_token_hash(token),))
        row = cur.fetchone()
        if not row:
            return {"ok": False, "email": None, "reason": "Unknown token."}

        cur.execute(
            "SELECT strftime('%s', ?), strftime('%s', ?), used_at IS NOT NULL FROM email_verifications WHERE token_hash = ?",
            (row[0], row[1], _token_hash(token)),
        )
        ts = cur.fetchone()
        if not ts:
            return {"ok": False, "email": None, "reason": "Token state not found."}
        issued_s, expires_s, used_flag = int(ts[0]), int(ts[1]), bool(ts[2])
        if used_flag:
            return {"ok": False, "email": None, "reason": "Token already used."}
        if _now() > expires_s:
            return {"ok": False, "email": None, "reason": "Token expired."}

        mark_email_as_verified(email)
        _mark_token_used(token)

        try:
            u = get_user(email)
            log_user_action(u["id"] if u else None, "EMAIL_VERIFIED", json.dumps({"method": "token"}))
        except Exception:
            pass

        return {"ok": True, "email": email, "reason": None}
    finally:
        conn.close()

# ------------------------------------------------------------------------------
# CLI smoke test
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email Handler Smoke Test (config.json driven)")
    parser.add_argument("recipient_email", type=str, help="Recipient email.")
    args = parser.parse_args()

    print("--- Email Handler Smoke Test ---")
    res = send_verification_email(args.recipient_email)
    print(res)
