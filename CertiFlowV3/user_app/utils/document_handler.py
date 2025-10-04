# user_app/utils/document_handler.py
# CertiFlow V3 — Device signing pipeline (COM HSM + PIN)
#
# Hash (SHA-256) -> SIGN on HSM -> store base64 DER ECDSA signature.
# PDF: embed metadata + keep your existing UX.
# Non-PDF: write a .sig JSON sidecar next to the file.
#
# NOTE: We keep the old function signature for compatibility:
#   sign_document(file_path, hsm_mount_point, hsm_password, user_email)
#   - hsm_mount_point is ignored in V3
#   - hsm_password is treated as the HSM PIN

import os
import io
import json
import base64
import binascii
import hashlib
from datetime import datetime
from typing import Tuple

import pypdf

# HSM + DB (keep imports minimal and stable)
from utils import hsm_handler
import db_helper


# ---------------- Helpers ----------------

def _extract_text_for_hashing(file_path_or_buffer) -> Tuple[str | None, str | None]:
    """
    Extracts all text from a PDF (from a file path or an in-memory buffer)
    and normalizes it for consistent hashing.
    """
    try:
        reader = pypdf.PdfReader(file_path_or_buffer)
        text_content = ""
        for page in reader.pages:
            extracted = page.extract_text()
            if extracted:
                text_content += extracted
        # normalize whitespace
        return " ".join(text_content.split()), None
    except Exception as e:
        return None, f"Failed to read PDF content: {e}"


def _hash_file_bytes(file_path: str) -> Tuple[bytes | None, str | None]:
    """Reads a non-PDF file in chunks and returns its SHA-256 hash."""
    if not os.path.exists(file_path):
        return None, "File not found."
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.digest(), None
    except Exception as e:
        return None, f"Could not read or hash the file: {e}"


def _connect_and_unlock(email: str, pin: str) -> Tuple[hsm_handler.HSMClient | None, str | None, str | None]:
    """
    Find the expected HSM from local cache for this email, connect to it, and unlock with PIN.
    Returns (client, hsm_id, error)
    """
    if not pin:
        return None, None, "HSM PIN is required."

    user = db_helper.get_user(email)
    if not user or not user.get("hsm_id"):
        return None, None, "No local HSM record for this user. Please register first."

    expected_hsm_id = user["hsm_id"]
    client = hsm_handler.HSMClient()
    hsm_id, err = client.detect_and_connect(expected_hsm_id=expected_hsm_id)
    if err or not hsm_id:
        client.close()
        return None, None, "The required HSM device is not connected."

    mode, unlock_err = client.unlock(pin)
    if unlock_err:
        client.close()
        return None, None, f"HSM unlock failed: {unlock_err}"

    # NEWPIN or UNLOCKED are both acceptable
    return client, hsm_id, None


# ---------------- Core API ----------------

def sign_document(
    file_path: str,
    hsm_mount_point: str,   # ignored in V3
    hsm_password: str,      # treated as HSM PIN
    user_email: str
) -> Tuple[bool, str]:
    """
    CertiFlow V3 signing:
      - PDF: extract text, hash, sign via HSM, embed signature + cert in PDF metadata
      - Non-PDF: hash bytes, sign via HSM, write JSON .sig sidecar
      Returns (ok, message)
    """
    pin = hsm_password  # keep parameter name for compatibility

    # Connect and UNLOCK device
    client, hsm_id, err = _connect_and_unlock(user_email, pin)
    if err:
        return False, err

    # Fetch the user's issued certificate (optional but desired for embedding)
    cert_pem = None
    try:
        u = db_helper.get_user(user_email)
        cert_pem = u.get("cert_pem") if u else None
    except Exception:
        cert_pem = None

    try:
        # PDF path
        if file_path.lower().endswith(".pdf"):
            try:
                reader = pypdf.PdfReader(file_path)
                writer = pypdf.PdfWriter()
                writer.clone_document_from_reader(reader)

                # re-serialize for deterministic hashing of extracted text
                buffer = io.BytesIO()
                writer.write(buffer)
                buffer.seek(0)

                content_to_hash, error = _extract_text_for_hashing(buffer)
                if error:
                    return False, f"Hashing failed: {error}"
                digest = hashlib.sha256(content_to_hash.encode("utf-8")).digest()

            except Exception as e:
                return False, f"Failed to prepare PDF for signing: {e}"

            # Sign via HSM
            try:
                hex_digest = binascii.hexlify(digest).decode("ascii")
                sig_b64, sign_err = client.sign_sha256_hex(hex_digest)
                if sign_err or not sig_b64:
                    return False, f"Signing failed: {sign_err or 'no signature returned'}"
            except Exception as e:
                return False, f"Signing error: {e}"

            # Embed metadata
            try:
                doc_hash_b64 = base64.b64encode(digest).decode("utf-8")
                meta = {
                    "/CertiFlowSignature": sig_b64,
                    "/CertiFlowContentHash": doc_hash_b64,
                    "/CertiFlowAlgorithm": "ECDSA_P256_SHA256",
                    "/CertiFlowHSMID": hsm_id or "",
                    "/CertiFlowTimestampUTC": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                }
                if cert_pem:
                    # Store PEM as base64 to be metadata-safe
                    meta["/CertiFlowCertificateB64"] = base64.b64encode(cert_pem.encode("utf-8")).decode("utf-8")

                writer.add_metadata(meta)
                output_path = file_path[:-4] + "-signed.pdf"
                with open(output_path, "wb") as f_out:
                    writer.write(f_out)

                db_helper.add_signed_document(
                    original_filename=os.path.basename(file_path),
                    signed_filepath=output_path,
                    signature_type="PDF_EMBEDDED",
                    user_email=user_email
                )
                return True, f"Document successfully signed.\nSaved as: {os.path.basename(output_path)}"

            except Exception as e:
                return False, f"Failed to embed signature metadata: {e}"

        # Non-PDF path
        else:
            digest, error = _hash_file_bytes(file_path)
            if error:
                return False, f"Hashing failed: {error}"

            try:
                hex_digest = binascii.hexlify(digest).decode("ascii")
                sig_b64, sign_err = client.sign_sha256_hex(hex_digest)
                if sign_err or not sig_b64:
                    return False, f"Signing failed: {sign_err or 'no signature returned'}"
            except Exception as e:
                return False, f"Signing error: {e}"

            # Write a JSON sidecar with signature and certificate
            sidecar_path = file_path + ".sig"
            sidecar = {
                "file": os.path.basename(file_path),
                "algorithm": "ECDSA_P256_SHA256",
                "digest_b64": base64.b64encode(digest).decode("utf-8"),
                "digest_hex": binascii.hexlify(digest).decode("ascii"),
                "signature_b64": sig_b64,
                "hsm_id": hsm_id,
                "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            }
            if cert_pem:
                sidecar["certificate_pem"] = cert_pem

            try:
                with open(sidecar_path, "w", encoding="utf-8") as f:
                    json.dump(sidecar, f, indent=2)
                db_helper.add_signed_document(
                    original_filename=os.path.basename(file_path),
                    signed_filepath=sidecar_path,
                    signature_type="DETACHED_SIG",
                    user_email=user_email
                )
                return True, f"Signature created for non-PDF file.\nSaved to: {os.path.basename(sidecar_path)}"
            except Exception as e:
                return False, f"Failed to save signature file: {e}"

    finally:
        try:
            client.logout()
        except Exception:
            pass
        client.close()
