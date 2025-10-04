# verif_app/utils/verification.py

"""
The single, consolidated handler for all verification logic.
- This file orchestrates the entire verification flow.
- It now correctly verifies the signature against the hash of the EXTRACTED TEXT,
  matching the logic of the user_app's signing process.
- It also saves every result to the local database.
"""

from __future__ import annotations
import os
import base64
import json
from typing import Dict, Any, Optional
from datetime import datetime, timezone

# --- Core Python & Library Imports ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

# --- Local Application Imports ---
from ver_db_helper import add_verification
from utils import ca_sync, trust_manager
from utils.hashing import hash_pdf_normalized_text, sha256_file_hex
from utils.logging import log, LogAction
from config import APP_VERSION

def verify_and_log_signature(
    signed_pdf_path: str,
    signer_email: str
) -> Dict[str, Any]:
    """
    Main function to verify a PDF, check for revocation, and log the result to the database.
    This now follows the user_app's logic of verifying against the text hash.
    """
    # 1. Ensure the trust store is ready.
    trust_ready, msg = trust_manager.ensure_trust_ready(auto_refresh=True)
    if not trust_ready:
        reason = f"Verification failed: {msg} Please go to Settings and click 'Refresh Trust'."
        result = {"result": "invalid", "reason": reason, "file_name": os.path.basename(signed_pdf_path), "signer_email": signer_email}
        log(LogAction.VERIFICATION_FAILURE, result)
        return result

    trust_snapshot = trust_manager.get_current_trust()

    # 2. Perform the actual verification.
    result_dict = _perform_verification(signed_pdf_path, signer_email, trust_snapshot)

    # 3. Save the result to the database.
    try:
        add_verification(**result_dict)
    except Exception as e:
        print(f"CRITICAL: Failed to save verification record to database: {e}")
        log(LogAction.ERROR, {"details": "Failed to write verification to DB", "error": str(e)})

    # 4. Create a general log entry.
    log_action = LogAction.VERIFICATION_SUCCESS if result_dict.get("result") == "valid" else LogAction.VERIFICATION_FAILURE
    log(log_action, details=result_dict)

    return result_dict


def _perform_verification(
    signed_pdf_path: str,
    signer_email: str,
    trust_snapshot: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Private function with the core verification logic, now corrected.
    """
    result = {
        "file_name": os.path.basename(signed_pdf_path),
        "file_sha256": None, # Hash of the full file for identification
        "signer_email": signer_email,
        "signer_cn": None,
        "cert_serial": None,
        "ca_cn": None,
        "result": "invalid",
        "reason": "An unknown error occurred.",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "pdf_sig_timestamp_utc": None,
        "crl_version": trust_snapshot.get('crl_version') if trust_snapshot else None,
        "crl_issued_at_utc": trust_snapshot.get('crl_issued_at_utc') if trust_snapshot else None,
        "app_version": APP_VERSION,
    }

    revoked_serials = _parse_revoked_serials(trust_snapshot)

    if not os.path.exists(signed_pdf_path):
        result["file_sha256"] = "N/A"
        result["reason"] = "File not found at the specified path."
        return result

    # --- Step A: Get hashes ---
    # 1. Full file hash for identification/auditing.
    file_hash_hex, file_hash_err = sha256_file_hex(signed_pdf_path)
    if file_hash_err:
        result["file_sha256"] = "N/A"
        result["reason"] = f"Could not hash file bytes: {file_hash_err}"
        return result
    result["file_sha256"] = file_hash_hex

    # 2. Normalized text hash for signature verification (THE CRITICAL FIX).
    recalculated_text_hash, hash_err = hash_pdf_normalized_text(signed_pdf_path)
    if hash_err:
        result["reason"] = f"Could not read or hash PDF content: {hash_err}"
        return result

    # --- Step B: Read the signature and STORED text hash from PDF metadata ---
    try:
        from pypdf import PdfReader
        reader = PdfReader(signed_pdf_path)
        metadata = reader.metadata or {}
        if not all(k in metadata for k in ["/CertiFlowSignature", "/CertiFlowContentHash"]):
            result["reason"] = "Verification failed: PDF does not contain a CertiFlow signature."
            return result

        signature = base64.b64decode(metadata["/CertiFlowSignature"])
        stored_text_hash = base64.b64decode(metadata["/CertiFlowContentHash"]) # This is the hash of the text
        result["pdf_sig_timestamp_utc"] = metadata.get("/CertiFlowTimestampUTC")
    except Exception as e:
        result["reason"] = f"Could not read signature from PDF metadata. Error: {e}"
        return result

    # --- Step C: Compare text hashes. If they don't match, content has been altered. ---
    if recalculated_text_hash != stored_text_hash:
        result["reason"] = "SIGNATURE INVALID: The text content of this document has been altered since it was signed."
        return result

    # --- Step D: Fetch the signer's certificate ---
    signer_cert, issuer_cert, cert_err = _load_signer_certificate(signer_email, trust_snapshot)
    if signer_cert is None:
        result["reason"] = cert_err or f"Could not retrieve certificate for '{signer_email}'."
        return result

    # --- Step E: Perform cryptographic checks ---

    try:
        public_key = signer_cert.public_key()

        # Check CRL for revocation
        if revoked_serials and signer_cert.serial_number in revoked_serials:
            result["reason"] = "SIGNATURE INVALID: The signer's certificate has been REVOKED."
            return result

        # Verify the signature against the STORED text hash (Prehashed SHA-256)
        public_key.verify(
            signature,
            stored_text_hash,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )

        signer_cn = _safe_get_cn(signer_cert.subject)
        issuer_cn = _safe_get_cn(signer_cert.issuer)
        if issuer_cert is not None:
            issuer_cn = _safe_get_cn(issuer_cert.subject) or issuer_cn

        result["result"] = "valid"
        result["signer_cn"] = signer_cn
        result["ca_cn"] = issuer_cn
        result["cert_serial"] = str(signer_cert.serial_number)
        result["reason"] = (
            "Valid signature.\n"
            f"Signed by: {signer_cn or 'Unknown'} ({signer_email})\n"
            f"Timestamp (UTC): {result.get('pdf_sig_timestamp_utc') or 'Unknown'}"
        )

    except InvalidSignature:
        result["reason"] = "SIGNATURE INVALID: The signature is cryptographically invalid. The document may be forged."
    except Exception as e:
        result["reason"] = f"An unexpected error occurred during cryptographic verification: {e}"

    return result


def _parse_revoked_serials(trust_snapshot: Optional[Dict[str, Any]]) -> set[int]:
    if not trust_snapshot:
        return set()
    raw = trust_snapshot.get('crl_pem')
    if not raw:
        return set()
    try:
        serials = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return set()
    parsed: set[int] = set()
    if isinstance(serials, list):
        for entry in serials:
            if entry is None:
                continue
            try:
                parsed.add(int(str(entry), 0))
            except (TypeError, ValueError):
                continue
    return parsed


def _load_signer_certificate(
    signer_email: str,
    trust_snapshot: Optional[Dict[str, Any]],
) -> tuple[Optional[x509.Certificate], Optional[x509.Certificate], Optional[str]]:
    cert_pem, fetch_err = ca_sync.fetch_certificate(signer_email)
    if fetch_err or not cert_pem:
        return None, None, fetch_err or f"No certificate found for '{signer_email}'."

    try:
        signer_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:
        return None, None, f"Failed to parse signer certificate: {exc}"

    root_cert: Optional[x509.Certificate] = None
    if trust_snapshot and trust_snapshot.get('ca_root_pem'):
        try:
            root_cert = x509.load_pem_x509_certificate(trust_snapshot['ca_root_pem'].encode('utf-8'))
            issuer_public_key = root_cert.public_key()
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    signer_cert.signature,
                    signer_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    signer_cert.signature_hash_algorithm,
                )
            else:
                issuer_public_key.verify(
                    signer_cert.signature,
                    signer_cert.tbs_certificate_bytes,
                    ec.ECDSA(signer_cert.signature_hash_algorithm),
                )
            if signer_cert.issuer != root_cert.subject:
                return None, None, "Signer certificate issuer does not match trusted CA root."
        except InvalidSignature:
            return None, None, "Signer certificate is not signed by the trusted CA root."
        except Exception as exc:
            return None, None, f"Failed to validate signer certificate against CA root: {exc}"

    return signer_cert, root_cert, None


def _safe_get_cn(name: x509.Name) -> Optional[str]:
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return None

