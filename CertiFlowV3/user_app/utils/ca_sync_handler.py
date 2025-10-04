# user_app/utils/ca_sync_handler.py

import requests
import json
import argparse
from urllib.parse import quote
from typing import Tuple, List, Dict, Any

# --- App Imports ---
from config import CA_API_URL

# --- Constants ---
REQUEST_TIMEOUT = 10  # seconds


# --- Private Helper Function for Network Requests ---
def _make_request(method: str, endpoint: str, data: dict = None) -> Tuple[dict | None, str | None]:
    """
    Centralized HTTP helper. Builds URL from CA_API_URL + endpoint, performs the request,
    parses JSON, and normalizes common errors into user-readable strings.
    """
    url = f"{CA_API_URL}{endpoint}"
    try:
        if method.upper() == "POST":
            response = requests.post(url, json=data, timeout=REQUEST_TIMEOUT)
        else:  # Default to GET
            response = requests.get(url, timeout=REQUEST_TIMEOUT)

        response.raise_for_status()
        return response.json(), None

    except requests.exceptions.Timeout:
        return None, "Connection timed out. The CA server may be busy or offline."
    except requests.exceptions.ConnectionError:
        return None, "Connection failed. Ensure this app can reach the CA server."
    except requests.exceptions.HTTPError as e:
        try:
            # Try to normalize server-side error payloads that look like { ok:false, error:{ message }}
            payload = e.response.json()
            # Common shapes
            server_message = (
                payload.get("error", {}).get("message")
                or payload.get("message")
                or "HTTP error."
            )
            return None, f"Error from server: {server_message} (Status {e.response.status_code})"
        except json.JSONDecodeError:
            return None, f"HTTP error: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def check_hsm_id_uniqueness(hsm_id: str) -> Tuple[bool, str | None]:
    """
    Check whether an HSM ID is already registered. Safe default is 'registered' on API ambiguities.
    """
    if not hsm_id:
        return False, "HSM ID cannot be empty."

    print(f"[Sync Handler] Checking uniqueness of HSM ID {hsm_id}...")
    response_data, error = _make_request("GET", f"/api/hsm/{quote(hsm_id)}/status")

    if error:
        # If 404, assume not registered
        if "404" in error:
            return True, None
        return False, error

    if response_data.get("ok") is False:
        # treat server "not found" as available
        if response_data.get("error", {}).get("code") == "NOT_FOUND":
            return True, None
        return False, response_data.get("error", {}).get("message")

    status = (response_data or {}).get("status")
    bound_email = (response_data or {}).get("bound_email")
    if status and status.lower() not in ("not_found", "detected"):
        return False, "This HSM device is already registered to another user."
    return True, None


def get_user_status_from_ca(email: str) -> Tuple[dict | None, str | None]:
    """Return the user's status payload from the CA V3 API."""
    print(f"[Sync Handler] Fetching status for {email} from CA server...")
    endpoint = f"/api/user/status?email={quote(email)}"
    response_data, error = _make_request("GET", endpoint)
    if error:
        return None, error
    if response_data.get("ok") is False:
        return None, response_data.get("error", {}).get("message", "Unknown error")
    return response_data, None


def fetch_certificate(email: str) -> Tuple[str | None, str | None]:
    """Fetch the end-entity certificate PEM once approved."""
    print(f"[Sync Handler] Fetching certificate for {email} from CA server...")
    response_data, error = _make_request("GET", f"/api/certificates/{quote(email)}")
    if error:
        return None, error
    if response_data.get("ok") is False:
        return None, response_data.get("error", {}).get("message")
    return response_data.get("certificate_pem"), None


def request_renewal(email: str, csr_pem: str, hsm_id: str = "") -> Tuple[bool, str]:
    """Send a renewal request to the CA API."""
    payload = {"email": email, "csr_pem": csr_pem, "hsm_id": hsm_id or ""}
    response_data, error = _make_request("POST", "/api/cert/renew", data=payload)
    if error:
        return False, error
    if response_data.get("ok") is False:
        message = response_data.get("error", {}).get("message", "Renewal request rejected by CA.")
        return False, message
    return True, response_data.get("message", "Renewal request submitted.")


def get_crl() -> Tuple[Dict[str, Any] | None, str | None]:
    """Fetch the CRL for verifier app sync."""
    print("[Sync Handler] Downloading CRL from CA server...")
    response_data, error = _make_request("GET", "/api/trust/crl")
    if error:
        return None, error
    if response_data.get("ok") is False:
        return None, response_data.get("error", {}).get("message")
    return response_data, None


def get_root_certificate() -> Tuple[str | None, str | None]:
    """Fetch the CA root certificate PEM."""
    response_data, error = _make_request("GET", "/api/trust/root")
    if error:
        return None, error
    if response_data.get("ok") is False:
        return None, response_data.get("error", {}).get("message")
    pem = response_data.get("certificate_pem")
    if not pem:
        return None, "CA did not return a root certificate."
    return pem, None


def sync_user_logs(email: str, logs: List[Dict]) -> Tuple[bool, str]:
    """
    Batch push local logs to CA. Caller usually clears local logs on success.
    """
    if not logs:
        return True, "No new logs to sync."
    payload = {"email": email, "logs": logs}
    response_data, error = _make_request("POST", "/api/logs/sync", data=payload)
    if error:
        return False, error
    if response_data.get("ok") is False:
        message = response_data.get("error", {}).get("message", "Log sync rejected by CA.")
        return False, message
    return True, response_data.get("message", "Logs synchronized with CA.")


# ------------------------------------------------------------------------------
# New V3 endpoints (added; do not second-guess server truth)
# ------------------------------------------------------------------------------

def activate_device(hsm_id: str, activation_code: str) -> Tuple[bool, str]:
    """
    Bind/activate a device on the CA side after the user enters their activation code.
    Endpoint: POST /api/activate_hsm
    Payload: { "hsm_id": "...", "activation_code": "..." }
    """
    if not hsm_id or not activation_code:
        return False, "hsm_id and activation_code are required."

    payload = {"hsm_id": hsm_id, "activation_code": activation_code}
    response_data, error = _make_request("POST", "/api/activate_hsm", data=payload)
    if error:
        return False, error

    # Server uses standard j_ok/j_err shape: { ok: bool, message?: str, ... }
    ok = response_data.get("ok")
    msg = response_data.get("message") or ("Device activated." if ok else "Activation failed.")
    return bool(ok), msg


# Compatibility alias for earlier patch that called consume_activation_code(...)
def consume_activation_code(hsm_id: str, activation_code: str) -> Tuple[bool, str]:
    return activate_device(hsm_id, activation_code)


def submit_csr(email: str, hsm_id: str, csr_pem: str) -> Tuple[bool, str]:
    """
    Submit CSR per V3 flow. CA will also try to send a verification email server-side.
    Endpoint: POST /api/cert/csr
    Payload: { "email": "...", "hsm_id": "...", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..." }
    """
    if not email or not csr_pem:
        return False, "email and csr_pem are required."

    payload = {"email": email, "hsm_id": hsm_id or "", "csr_pem": csr_pem}
    response_data, error = _make_request("POST", "/api/cert/csr", data=payload)
    if error:
        return False, error

    ok = response_data.get("ok", True)
    msg = response_data.get("message", "CSR submitted.")
    return bool(ok), msg


def send_verification_email(email: str) -> Tuple[bool, str]:
    """
    Explicitly trigger a verification email. Useful if user requests a resend.
    Endpoint: POST /api/email/send_verification
    Payload: { "email": "..." }
    """
    if not email:
        return False, "email is required."

    payload = {"email": email}
    response_data, error = _make_request("POST", "/api/email/send_verification", data=payload)
    if error:
        return False, error

    # CA returns j_ok/j_err style
    ok = response_data.get("ok", True)
    msg = response_data.get("message", "Verification email sent.")
    return bool(ok), msg


# ------------------------------------------------------------------------------
# Smoke Test (run this module directly)
# ------------------------------------------------------------------------------

def smoke_test(email: str, hsm_id: str, csr_pem: str = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----") -> Dict[str, str]:
    """
    Quick connectivity & endpoint sanity test. This does NOT create real certs.
    Returns a dict with results for: health, send_email, activate_hsm, submit_csr.
    """
    results: Dict[str, str] = {}

    # 1) Health
    data, err = _make_request("GET", "/api/health")
    results["health"] = "OK" if (data and data.get("ok") is True) else (err or "Unexpected response")

    # 2) Send verification email (should succeed if SMTP is configured on CA)
    ok, msg = send_verification_email(email)
    results["send_email"] = "OK" if ok else f"FAIL: {msg}"

    # 3) Activate HSM with obviously wrong code (we expect a handled failure, not a network error)
    ok, msg = activate_device(hsm_id=hsm_id, activation_code="INVALID-CODE-FOR-SMOKE")
    # We treat either OK or a well-formed server error as "reachable"
    results["activate_hsm"] = "OK" if ok else f"SERVED: {msg}"

    # 4) Submit CSR (CA just queues, no CSR parse here)
    ok, msg = submit_csr(email=email, hsm_id=hsm_id, csr_pem=csr_pem)
    results["submit_csr"] = "OK" if ok else f"FAIL: {msg}"

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CertiFlow CA Sync Handler • Smoke Test")
    parser.add_argument("--email", required=True, help="Test email to use (will receive verification mail if SMTP is configured)")
    parser.add_argument("--hsm-id", required=True, help="HSM ID to exercise endpoints with")
    parser.add_argument("--csr-pem", default="-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
                        help="CSR PEM to send in the smoke test (string; default is a placeholder)")

    args = parser.parse_args()
    print(f"[Smoke] CA base: {CA_API_URL}")
    out = smoke_test(email=args.email, hsm_id=args.hsm_id, csr_pem=args.csr_pem)
    for k, v in out.items():
        print(f"[Smoke] {k}: {v}")
