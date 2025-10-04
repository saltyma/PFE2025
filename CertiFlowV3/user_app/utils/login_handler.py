# user_app/utils/login_handler.py
# CertiFlow V3 — HSM-gated login:
#   1) Look up expected HSMID from local cache
#   2) Detect & connect to that HSM on COM
#   3) UNLOCK <pin> to establish a session
#   4) Query CA for status, fetch certificate if verified
#   5) Update local cache with cert metadata

from typing import Tuple, Dict, Any, Optional

# --- App Imports ---
import db_helper
from utils import hsm_handler, ca_sync_handler, certificate, logging_handler
from utils.logging_handler import LogAction


def _connect_and_unlock(expected_hsm_id: str, pin: str) -> Tuple[Optional[hsm_handler.HSMClient], Optional[str]]:
    """
    Detect the expected HSM on COM ports, connect, and unlock the session with the provided PIN.
    Returns (client, error). Caller must close the client.
    """
    if not pin:
        return None, "HSM PIN is required."

    client = hsm_handler.HSMClient()
    hsm_id, err = client.detect_and_connect(expected_hsm_id=expected_hsm_id)
    if err or not hsm_id:
        client.close()
        return None, "The required HSM device is not connected."

    mode, err = client.unlock(pin)
    if err:
        client.close()
        return None, f"HSM unlock failed: {err}"

    # mode is 'NEWPIN' on first use, or 'UNLOCKED' otherwise. Both are fine here.
    logging_handler.log(LogAction.HSM_UNLOCKED, {"mode": mode, "hsm_id": hsm_id})
    return client, None


def authenticate_user_with_pin(email: str, pin: str) -> Tuple[str, str, Dict[str, Any] | None]:
    """
    Primary V3 login entrypoint. Requires HSM PIN.
    Returns: (status, message, user_data|None)
      status in {'success','pending','rejected','failure'}
    """
    log_details = {"email": email}
    logging_handler.log(LogAction.LOGIN_STARTED, log_details)

    # 1) Local cache: get expected HSMID
    user_cache = db_helper.get_user(email)
    if not user_cache:
        return 'failure', "User not found in local cache. Please register first.", None

    expected_hsm_id = user_cache.get("hsm_id")
    if not expected_hsm_id:
        return 'failure', "Local user record is corrupt (missing HSM ID). Please register again.", None

    # 2) Detect, connect, and UNLOCK with PIN
    client, err = _connect_and_unlock(expected_hsm_id, pin)
    if err:
        logging_handler.log(LogAction.HSM_REMOVED, {"reason": err})
        return 'failure', err, None

    try:
        # 3) CA status check
        status_payload, error = ca_sync_handler.get_user_status_from_ca(email)
        if error:
            logging_handler.log(LogAction.LOGIN_FAILURE, {"reason": f"CA Sync Error: {error}"})
            return 'failure', error, None

        status_from_ca = (status_payload or {}).get('status')

        if status_payload:
            hsm_info = status_payload.get('hsm') or {}
            db_helper.set_verification_flags(
                email,
                email_verified=status_payload.get('email_verified'),
                device_bound=1 if (hsm_info.get('status') in ('bound', 'activated') and (hsm_info.get('bound_email') or '').lower() == email.lower()) else 0,
                activation_consumed=1 if (hsm_info.get('status') == 'activated' or hsm_info.get('activation_consumed')) else 0,
            )

        if status_from_ca == 'pending':
            logging_handler.log(LogAction.LOGIN_PENDING, log_details)
            return 'pending', "Your registration is still pending approval from the CA.", None

        if status_from_ca == 'rejected':
            logging_handler.log(LogAction.LOGIN_REJECTED, log_details)
            return 'rejected', "Your registration request was rejected by the CA.", None

        if status_from_ca == 'revoked':
            logging_handler.log(LogAction.LOGIN_FAILURE, {"reason": "Account revoked by CA."})
            return 'failure', "Your certificate has been revoked by the CA. Please contact the administrator.", None

        if status_from_ca != 'verified':
            msg = f"Your account has an unusual status: '{status_from_ca}'. Please contact support."
            logging_handler.log(LogAction.LOGIN_FAILURE, {"reason": msg})
            return 'failure', msg, None

        # 4) Fetch issued certificate from CA
        cert_pem, cert_error = ca_sync_handler.fetch_certificate(email)
        if cert_error:
            logging_handler.log(LogAction.LOGIN_FAILURE, {"reason": f"Cert fetch error: {cert_error}"})
            return 'failure', f"Failed to fetch your certificate: {cert_error}", None

        if not cert_pem:
            return 'failure', "Your account is verified, but no certificate was found. Please contact support.", None

        # 5) Parse and persist certificate metadata
        cert_details, parse_error = certificate.parse_certificate_pem(cert_pem)
        if parse_error:
            msg = f"Failed to parse your certificate: {parse_error}"
            logging_handler.log(LogAction.LOGIN_FAILURE, {"reason": msg})
            return 'failure', msg, None

        # Update local cache with cert + metadata
        db_helper.add_or_update_user(email, expected_hsm_id, cert_pem)
        db_helper.update_cert_metadata(
            email=email,
            cert_serial=str(cert_details.get("serial_number")),
            valid_from=cert_details.get("valid_from"),
            valid_to=cert_details.get("valid_to"),
            cert_pem=cert_pem,
            policy_version="v3",
        )
        # Keep a copy in owned certs history for renewals/history
        db_helper.add_owned_cert(
            cert_serial=str(cert_details.get("serial_number")),
            cert_pem=cert_pem,
            not_before=cert_details.get("valid_from"),
            not_after=cert_details.get("valid_to"),
            status="valid",
        )

        user_data = {
            "email": email,
            "hsm_id": expected_hsm_id,
            "certificate_pem": cert_pem,
            "certificate_details": cert_details
        }

        logging_handler.log(LogAction.LOGIN_SUCCESS, log_details)
        return 'success', "Login successful.", user_data

    finally:
        # 6) Close the HSM session cleanly
        try:
            client.logout()
        except Exception:
            pass
        client.close()


# --- Backward-compat wrapper (older pages called authenticate_user without PIN) ---
def authenticate_user(email: str) -> Tuple[str, str, Dict[str, Any] | None]:
    """
    Legacy wrapper kept for compatibility with older UI code. In V3, login requires an HSM PIN.
    This function returns a clear message instructing the UI to use the PIN-based flow.
    """
    return 'failure', "This version requires HSM PIN. Please use authenticate_user_with_pin(email, pin).", None
