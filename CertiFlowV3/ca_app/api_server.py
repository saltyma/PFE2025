from flask import Flask, jsonify, request, make_response
from datetime import datetime, timezone
import os
import json
import traceback

# Handlers / helpers
from handlers.request_handler import approve_request, create_renewal_request
from handlers.hsm_management_handler import detect_new_hsms
from handlers import log_handler
from handlers.log_handler import LogAction
from ca_db_helper import (
    add_user,
    get_user,
    get_user_by_hsm_id,
    add_pending_request,
    get_pending_requests,
    get_pending_request_by_id,
    delete_pending_request,
    check_activation_code,
    activate_hsm,
    get_hsm_status,
    get_user_status_snapshot,
    get_certificate_by_email,
    get_revoked_certificates,
    log_user_action as db_log_user_action,
)
from handlers import email_handler  # signed tokens + DB-backed verification

# --------------------------------------------------------------------------
# Config loader (config.json is the single source of truth)
# --------------------------------------------------------------------------
def _load_config():
    cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

CFG = _load_config()
SMTP_USER = (CFG.get("sender_email") or "").strip()
SMTP_PASS = (CFG.get("app_password") or "").strip()
API_BASE = (CFG.get("api_base_url") or "http://127.0.0.1:7001").rstrip("/")

# --------------------------------------------------------------------------
# App boot
# --------------------------------------------------------------------------
app = Flask(__name__)

# --------------------------------------------------------------------------
# Minimal HTML renderer for pretty pages
# --------------------------------------------------------------------------
def _page(title: str, subtitle: str = "", body_html: str = "", kind: str = "info", back_url: str = None, code: int = 200):
    """
    kind: "success" | "error" | "info"
    """
    back_url = (back_url or API_BASE)

    # Tag colors (subtle), button uses brand red
    tag_bg = {
        "success": "#0F2216",
        "error":   "#2A1414",
        "info":    "#14181F",
    }.get(kind, "#14181F")
    tag_fg = {
        "success": "#B9F6CA",
        "error":   "#FFCDD2",
        "info":    "#C5D7FF",
    }.get(kind, "#C5D7FF")

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CertiFlow • {title}</title>
<style>
  :root {{
    --page-bg: #F4F6FA;
    --card-bg: #1E1E1E;
    --muted: #8FA0B3;
    --text: #E6EEF8;
    --brand-red: #9B2335;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 40px 16px;
    background: var(--page-bg);
    color: var(--text);
    font: 15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,"Helvetica Neue",Arial,sans-serif;
  }}
  .wrap {{ max-width: 720px; margin: 0 auto; }}
  .card {{
    background: var(--card-bg);
    border: 1px solid rgba(0,0,0,.15);
    border-radius: 14px;
    padding: 26px 22px;
    box-shadow: 0 10px 30px rgba(0,0,0,.15);
    text-align: center;
  }}
  .logo {{
    font-weight: 800; font-size: 39px; letter-spacing: .3px;
    color: var(--text); margin-bottom: 8px;
  }}
  h1 {{ margin: 0 0 8px; font-size: 20px; line-height: 1.35; color: var(--text); }}
  .sub {{ color: var(--muted); margin: 0 0 18px; }}
  .tag {{
    display: inline-block; border-radius: 10px; padding: 8px 10px; margin: 6px 0 18px;
    background: {tag_bg}; color: {tag_fg}; font-weight: 600; font-size: 12px; letter-spacing: .3px;
  }}
  .body p {{ margin: 0 0 12px; color: var(--muted); }}
  .btns {{ margin-top: 20px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }}
  .btn {{
    display: inline-block; padding: 10px 16px; border-radius: 10px; text-decoration: none;
    background: var(--brand-red); color: #fff; font-weight: 700; box-shadow: 0 6px 18px rgba(0,0,0,.25);
  }}
  code, pre {{
    background: #141414; border: 1px solid rgba(255,255,255,.06); border-radius: 8px; padding: 2px 6px;
    color: #D6EAFB; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="logo">Certi<span style="color:#9B2335;">Flow.</span></div>
      <div class="tag">{kind.upper()}</div>
      <h1>{title}</h1>
      <div class="sub">{subtitle}</div>
      <div class="body">{body_html}</div>
    </div>
  </div>
</body>
</html>"""
    return make_response(html, code)


# --------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------
def j_ok(**extra):
    payload = {"ok": True}
    payload.update(extra)
    return jsonify(payload)

def j_err(status: int, code: str, msg: str, **extra):
    payload = {"ok": False, "error": {"code": code, "message": msg}}
    if extra:
        payload["error"].update(extra)
    return jsonify(payload), status


def _parse_iso_timestamp(raw_value):
    if raw_value is None:
        return None
    try:
        if isinstance(raw_value, (int, float)):
            return datetime.fromtimestamp(raw_value, tz=timezone.utc)
        if isinstance(raw_value, str):
            value = raw_value.strip()
            if not value:
                return None
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
    except Exception:
        return None
    return None

# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return j_ok(service="CertiFlow CA API", time=datetime.now(timezone.utc).isoformat())

# --------------------------------------------------------------------------
# HSM activation
# --------------------------------------------------------------------------
@app.post("/api/activate_hsm")
def api_activate_hsm():
    try:
        body = request.get_json(force=True, silent=True) or {}
        hsm_id = (body.get("hsm_id") or "").strip()
        code   = (body.get("activation_code") or "").strip()
        if not hsm_id or not code:
            return j_err(400, "BAD_REQUEST", "hsm_id and activation_code are required.")

        # If code check fails, allow idempotent success when device is already activated.
        if not check_activation_code(hsm_id, code):
            status_info = get_hsm_status(hsm_id)
            if status_info.get("status") == "activated":
                return j_ok(message="HSM already activated.")
            return j_err(403, "INVALID_CODE", "Activation code is invalid or device not in bound state.")

        activate_hsm(hsm_id)
        return j_ok(message="HSM activated.")
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to activate HSM.", detail=str(ex))


# --------------------------------------------------------------------------
# Email verification (tokenized) — pretty page flow via email_handler
# --------------------------------------------------------------------------
@app.get("/api/verify_email")
def api_verify_email():
    token = request.args.get("token", "").strip()
    if not token:
        return _page(
            "Invalid request",
            "The verification link is missing its token.",
            "<p>Please request a new verification email from the app.</p>",
            kind="error",
            code=400,
        )
    try:
        ok, msg, email = email_handler.verify_token_and_mark(token)
        if not ok:
            return _page("Verification failed", "", f"<p>{msg or 'Invalid or expired token.'}</p>", kind="error", code=400)
        # Handler already updated DB + logs
        return _page("Email verified", email or "", "<p>You can return to the app and continue.</p>", kind="success", code=200)
    except Exception as ex:
        return _page("Server error", "", f"<pre>{str(ex)}</pre>", kind="error", code=500)

# --------------------------------------------------------------------------
# Email send endpoint
# --------------------------------------------------------------------------
@app.post("/api/email/send_verification")
def api_send_verification():
    try:
        body  = request.get_json(force=True, silent=True) or {}
        email = (body.get("email") or "").strip()
        if not email:
            return j_err(400, "BAD_REQUEST", "email is required.")

        add_user(email=email, status="pending")
        user = get_user(email)
        if not user:
            return j_err(500, "USER_CREATE_FAILED", "Could not create or load user.")

        ok, msg = email_handler.send_verification_email(email)
        if not ok:
            return j_err(500, "EMAIL_SEND_FAILED", msg or "Unable to send verification email.")

        return j_ok(message="Verification email sent.")
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to send verification email.", detail=str(ex))

# --------------------------------------------------------------------------
# CSR intake
# --------------------------------------------------------------------------
@app.post("/api/cert/csr")
def api_submit_csr():
    try:
        body    = request.get_json(force=True, silent=True) or {}
        email   = (body.get("email")   or "").strip()
        hsm_id  = (body.get("hsm_id")  or "").strip()
        csr_pem = (body.get("csr_pem") or "").strip()

        if not email or not csr_pem:
            return j_err(400, "BAD_REQUEST", "email and csr_pem are required.")

        add_user(email=email, status="pending")
        user = get_user(email)
        if not user:
            return j_err(500, "USER_CREATE_FAILED", "Could not create or load user.")

        # Pin CSR to the exact device (DB helper hashes/encrypts as needed)
        inserted = add_pending_request(user_id=user["id"], email=email, csr_pem=csr_pem, hsm_id=hsm_id)
        if not inserted:
            log_handler.log_admin_action(
                admin_id=None,
                action=LogAction.APPLICATION_ERROR,
                details={
                    "context": "csr_queue",
                    "email": email,
                    "message": "Failed to queue CSR (likely duplicate or invalid request).",
                },
            )
            return j_err(400, "CSR_NOT_ACCEPTED", "CSR could not be queued. Please check if a request already exists.")


        email_sent = False
        email_msg = ""
        try:
            email_sent, email_msg = email_handler.send_verification_email(email)
        except Exception as mail_ex:
            email_msg = str(mail_ex) or "Unknown email error"

        if not email_sent:
            log_handler.log_admin_action(
                admin_id=None,
                action=LogAction.APPLICATION_ERROR,
                details={
                    "context": "csr_email_dispatch",
                    "email": email,
                    "message": email_msg,
                },
            )
            return j_ok(
                message="CSR accepted, but verification email could not be sent.",
                user_id=user["id"],
                email_sent=False,
                email_error=email_msg,
            )

        log_handler.log_admin_action(
            admin_id=None,
            action=LogAction.EMAIL_VERIFICATION_SENT,
            details={"email": email},
        )
        return j_ok(message="CSR submitted.", user_id=user["id"], email_sent=True)
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to accept CSR.", detail=str(ex))


@app.post("/api/cert/renew")
def api_submit_renewal():
    try:
        body    = request.get_json(force=True, silent=True) or {}
        email   = (body.get("email")   or "").strip()
        hsm_id  = (body.get("hsm_id")  or "").strip()
        csr_pem = (body.get("csr_pem") or "").strip()

        if not email or not csr_pem:
            return j_err(400, "BAD_REQUEST", "email and csr_pem are required.")

        ok, msg = create_renewal_request(email=email, csr_pem=csr_pem, hsm_id=hsm_id)
        if not ok:
            return j_err(400, "CSR_NOT_ACCEPTED", msg)

        return j_ok(message=msg or "Renewal request submitted.")
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to accept renewal CSR.", detail=str(ex))


@app.post("/api/logs/sync")
def api_sync_logs():
    try:
        body  = request.get_json(force=True, silent=True) or {}
        email = (body.get("email") or "").strip()
        logs  = body.get("logs")

        if not email:
            return j_err(400, "BAD_REQUEST", "email is required.")
        if logs is None:
            logs = []
        if not isinstance(logs, list):
            return j_err(400, "BAD_REQUEST", "logs must be a list of entries.")

        user = get_user(email)
        user_id = user["id"] if user else None
        stored = 0
        skipped = 0

        for entry in logs:
            if not isinstance(entry, dict):
                skipped += 1
                continue
            action = entry.get("action")
            if not action:
                skipped += 1
                continue

            details = entry.get("details")
            if user_id is None:
                if isinstance(details, dict):
                    details.setdefault("email", email)
                elif details in (None, ""):
                    details = {"email": email}
                else:
                    details = {"message": str(details), "email": email}

            timestamp = _parse_iso_timestamp(entry.get("timestamp"))
            try:
                db_log_user_action(user_id, action, details, timestamp=timestamp)
                stored += 1
            except Exception as log_ex:
                skipped += 1
                log_handler.log_admin_action(
                    admin_id=None,
                    action=LogAction.APPLICATION_ERROR,
                    details={
                        "context": "log_sync",
                        "email": email,
                        "action": action,
                        "error": str(log_ex),
                    },
                )

        return j_ok(message="Logs synchronized.", stored=stored, skipped=skipped)
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to sync logs.", detail=str(ex))

# --------------------------------------------------------------------------
# Admin: list/approve requests
# --------------------------------------------------------------------------
@app.get("/api/requests")
def api_list_requests():
    try:
        data = get_pending_requests()
        return j_ok(requests=data)
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to list requests.", detail=str(ex))

@app.post("/api/requests/<int:req_id>/approve")
def api_approve_request(req_id: int):
    try:
        req = get_pending_request_by_id(req_id)
        if not req:
            return j_err(404, "NOT_FOUND", "Pending request not found.")
        body = request.get_json(force=True, silent=True) or {}
        admin_id = body.get("admin_id")
        hsm_path = (body.get("admin_hsm_path") or "").strip()
        hsm_password = body.get("admin_hsm_password")

        if admin_id is None or not hsm_path or not hsm_password:
            return j_err(400, "BAD_REQUEST", "admin_id, admin_hsm_path, and admin_hsm_password are required.")

        try:
            admin_id_int = int(admin_id)
        except (TypeError, ValueError):
            return j_err(400, "BAD_REQUEST", "admin_id must be an integer.")

        ok, result = approve_request(req_id, admin_id_int, hsm_path, hsm_password)
        if not ok:
            if isinstance(result, dict):
                reason = result.get("reason") or "Approval failed."
                code = result.get("code") or "APPROVAL_FAILED"
                return j_err(400, code, reason)
            return j_err(400, "APPROVAL_FAILED", str(result))

        delete_pending_request(req_id)

        snapshot = get_user_status_snapshot(req.get("email", "")) or {}
        cert_info = get_certificate_by_email(req.get("email", ""))
        user_payload = {
            "id": req.get("user_id"),
            "email": req.get("email"),
            "status": snapshot.get("user_status"),
            "email_verified": bool(snapshot.get("email_verified", False)),
        }
        if snapshot.get("hsm") is not None:
            user_payload["hsm"] = snapshot.get("hsm")

        response_payload = {
            "message": str(result) if result else "Request approved and certificate issued.",
            "data": {
                "user": user_payload,
                "certificate": cert_info,
            },
        }

        return j_ok(**response_payload)
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to approve request.", detail=str(ex))

# --------------------------------------------------------------------------
# User + device status for client apps
# --------------------------------------------------------------------------
@app.get("/api/user/status")
def api_user_status():
    email = (request.args.get("email") or "").strip()
    if not email:
        return j_err(400, "BAD_REQUEST", "email query parameter is required.")

    snapshot = get_user_status_snapshot(email)
    if not snapshot:
        return j_err(404, "NOT_FOUND", "User not found.")

    return j_ok(
        email=email,
        status=snapshot.get("user_status"),
        email_verified=bool(snapshot.get("email_verified")),
        hsm=snapshot.get("hsm"),
        certificate=snapshot.get("certificate"),
    )


@app.get("/api/certificates/<path:email>")
def api_get_certificate(email: str):
    email = (email or "").strip()
    if not email:
        return j_err(400, "BAD_REQUEST", "Email is required.")

    cert_info = get_certificate_by_email(email)
    if not cert_info:
        return j_err(404, "NOT_FOUND", "No certificate issued for this email.")

    payload = {
        "certificate_pem": cert_info.get("cert_pem"),
        "cert_serial": cert_info.get("cert_serial"),
        "valid_from": cert_info.get("valid_from"),
        "valid_to": cert_info.get("valid_to"),
    }
    return j_ok(**payload)


@app.get("/api/hsm/<path:hsm_id>/status")
def api_hsm_status(hsm_id: str):
    hsm_id = (hsm_id or "").strip()
    if not hsm_id:
        return j_err(400, "BAD_REQUEST", "hsm_id is required.")

    info = get_hsm_status(hsm_id)
    return j_ok(**info)


# --------------------------------------------------------------------------
# Trust material (root + CRL snapshot)
# --------------------------------------------------------------------------
@app.get("/api/trust/root")
def api_trust_root():
    cert_path = os.path.join(os.path.dirname(__file__), "ca.cert.pem")
    if not os.path.exists(cert_path):
        return j_err(500, "MISSING_ROOT", "Root certificate not found on server.")
    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            pem = f.read()
        return j_ok(certificate_pem=pem)
    except Exception as ex:
        return j_err(500, "READ_FAILED", "Unable to read root certificate.", detail=str(ex))


@app.get("/api/trust/crl")
def api_trust_crl():
    revoked = get_revoked_certificates()
    return j_ok(
        revoked_serials=revoked,
        version=str(len(revoked)),
        issued_at_utc=datetime.now(timezone.utc).isoformat(),
    )

# --------------------------------------------------------------------------
# Admin: HSM detect
# --------------------------------------------------------------------------
@app.post("/api/hsm/detect")
def api_hsm_detect():
    try:
        found = detect_new_hsms()
        return j_ok(found=found)
    except Exception as ex:
        return j_err(500, "SERVER_ERROR", "Failed to scan HSMs.", detail=str(ex))

# --------------------------------------------------------------------------
# Root index (pretty)
# --------------------------------------------------------------------------
@app.get("/")
def index():
    body = """
      <p>This is the Certificate Authority service for CertiFlow.</p>
      <p>Health: <code>/api/health</code></p>
      <p>Email verification: <code>/api/verify_email?token=&lt;opaque&gt;</code></p>
    """
    return _page("CertiFlow CA API", "Operational", body, kind="info", code=200)

# --------------------------------------------------------------------------
# Global error handler
# --------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_any_error(err):
    try:
        return j_err(500, "UNCAUGHT", "Unhandled server error.", detail=str(err), trace=traceback.format_exc())
    except Exception:
        return jsonify({"ok": False, "error": {"code": "UNCAUGHT", "message": "Unhandled server error."}}), 500

# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "7001"))
    print("CertiFlow CA API starting...")
    print("Health:", "GET /api/health")
    print("Verify email (tokenized):", "GET /api/verify_email?token=<opaque>")
    print("Submit CSR:", "POST /api/cert/csr {email, hsm_id, csr_pem}")
    print("Activate HSM:", "POST /api/activate_hsm {hsm_id, activation_code}")
    app.run(host="0.0.0.0", port=port, debug=False)
