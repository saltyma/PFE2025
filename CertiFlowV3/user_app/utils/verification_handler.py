# user_app/utils/verification_handler.py
# CertiFlow V3 — Signature verification (no HSM interaction)
#
# - PDF path: reads embedded metadata set by document_handler (signature_b64, content_hash_b64)
# - Detached path: reads JSON sidecar written by document_handler (.sig)
# - ECDSA P-256 with SHA-256 (Prehashed) verification
# - Cert source: local DB first, else CA fetch
# - Optional CRL check

from __future__ import annotations

import os
import json
import base64
import hashlib
from typing import Tuple, Optional
from datetime import datetime

import pypdf

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

import db_helper
from utils import ca_sync_handler


# ------------- Helpers (content hashing) -------------

def _extract_text_for_hashing(file_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Extracts and normalizes text from a PDF for consistent hashing."""
    if not file_path.lower().endswith('.pdf'):
        return None, "Cannot extract text from non-PDF files."
    try:
        reader = pypdf.PdfReader(file_path)
        text_content = ""
        for page in reader.pages:
            extracted = page.extract_text()
            if extracted:
                text_content += extracted
        # normalize whitespace
        return " ".join(text_content.split()), None
    except Exception as e:
        return None, f"Failed to read PDF content: {e}"


def _hash_file_bytes(file_path: str) -> Tuple[Optional[bytes], Optional[str]]:
    """Reads a file in chunks and returns its SHA-256 hash."""
    if not os.path.exists(file_path):
        return None, "File not found."
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.digest(), None
    except Exception as e:
        return None, f"Could not read or hash the file: {e}"


# ------------- Helpers (cert & CRL) -------------

def _get_signer_cert_pem(signer_email: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Prefer local cache; if missing, fetch from CA.
    """
    try:
        row = db_helper.get_user(signer_email)
        pem = row.get("cert_pem") if row else None
        if pem:
            return pem, None
    except Exception:
        pass

    pem, err = ca_sync_handler.fetch_certificate(signer_email)
    if err or not pem:
        return None, err or "No certificate found for signer."
    return pem, None


def _check_crl_revocation(cert: x509.Certificate) -> Optional[str]:
    """
    Optional CRL check — CA may return a serial list.
    Returns an error string if revoked; otherwise None.
    """
    try:
        crl_bundle, _err = ca_sync_handler.get_crl()
        if not crl_bundle:
            return None
        revoked_serials = crl_bundle.get("revoked_serials") if isinstance(crl_bundle, dict) else None
        if not revoked_serials:
            return None
        serial_str = str(cert.serial_number)
        if any(str(s) == serial_str for s in revoked_serials):
            return "The certificate used for signing has been revoked."
        return None
    except Exception:
        # Soft-fail: if CRL fetch fails, continue without blocking verification.
        return None


# ------------- Core API -------------

def verify_pdf_signature(signed_pdf_path: str, signer_email: str) -> Tuple[bool, str]:
    """
    Verifies a PDF with an embedded CertiFlow V3 signature.
      - Reads /CertiFlowSignature (base64 DER ECDSA) and /CertiFlowContentHash (base64 SHA-256) from metadata
      - Recomputes the hash from extracted text
      - Verifies ECDSA signature with the signer's cert public key (Prehashed SHA-256)
    """
    if not os.path.exists(signed_pdf_path):
        return False, "Verification failed: the signed PDF file does not exist."

    # Extract signature + hash from metadata
    try:
        reader = pypdf.PdfReader(signed_pdf_path)
        meta = reader.metadata or {}
        for key in ("/CertiFlowSignature", "/CertiFlowContentHash"):
            if key not in meta:
                return False, "Verification failed: PDF does not contain a CertiFlow signature."
        sig_b64 = meta["/CertiFlowSignature"]
        doc_hash_b64 = meta["/CertiFlowContentHash"]
        timestamp_str = meta.get("/CertiFlowTimestampUTC", "Unknown")
        signature = base64.b64decode(sig_b64)
        stored_hash = base64.b64decode(doc_hash_b64)
    except Exception as e:
        return False, f"Verification failed: could not read signature from PDF. Error: {e}"

    # Recompute content hash
    content_text, err = _extract_text_for_hashing(signed_pdf_path)
    if err:
        return False, f"Verification failed: {err}"
    recalculated_hash = hashlib.sha256(content_text.encode("utf-8")).digest()

    if recalculated_hash != stored_hash:
        return False, "Invalid signature: the document's text content changed after signing."

    # Load signer cert
    cert_pem, err = _get_signer_cert_pem(signer_email)
    if err or not cert_pem:
        return False, f"Verification failed: could not retrieve a valid certificate for '{signer_email}'. {err or ''}"

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        public_key = cert.public_key()

        # Optional CRL check
        revoked_msg = _check_crl_revocation(cert)
        if revoked_msg:
            return False, f"Invalid signature: {revoked_msg}"

        # ECDSA over the prehashed SHA-256 value
        public_key.verify(signature, stored_hash, ec.ECDSA(Prehashed(hashes.SHA256())))

        cn = None
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = "Unknown"

        return True, f"Valid signature.\nSigned by: {cn} ({signer_email})\nTimestamp (UTC): {timestamp_str}"
    except InvalidSignature:
        return False, "Invalid signature: cryptographic verification failed."
    except Exception as e:
        return False, f"Verification error: {e}"


def verify_detached_signature(document_path: str, signature_path: str, signer_email: str) -> Tuple[bool, str]:
    """
    Verifies a non-PDF file using a JSON sidecar (.sig) produced by document_handler:
      {
        "file": "<basename>",
        "algorithm": "ECDSA_P256_SHA256",
        "digest_b64": "...",
        "digest_hex": "...",
        "signature_b64": "...",
        "hsm_id": "...",
        "timestamp_utc": "...",
        "certificate_pem": "...",     # optional
      }
    Steps:
      - Recompute SHA-256 of the document; compare to stored digest
      - Verify ECDSA signature (DER) over the digest with Prehashed(SHA256)
      - Use certificate bundled in sidecar if present, else fall back to local/CA
    """
    if not os.path.exists(document_path):
        return False, "Verification failed: the document file does not exist."
    if not os.path.exists(signature_path):
        return False, "Verification failed: the signature file does not exist."

    # Load sidecar JSON
    try:
        with open(signature_path, "r", encoding="utf-8") as f:
            sidecar = json.load(f)
        sig_b64 = sidecar.get("signature_b64")
        digest_b64 = sidecar.get("digest_b64")
        timestamp_str = sidecar.get("timestamp_utc", "Unknown")
        cert_pem_sidecar = sidecar.get("certificate_pem")
        if not sig_b64 or not digest_b64:
            return False, "Verification failed: signature file is missing required fields."
        signature = base64.b64decode(sig_b64)
        stored_hash = base64.b64decode(digest_b64)
    except Exception as e:
        return False, f"Verification failed: could not parse signature file. Error: {e}"

    # Recompute hash
    doc_hash, err = _hash_file_bytes(document_path)
    if err:
        return False, f"Verification failed: {err}"
    if doc_hash != stored_hash:
        return False, "Invalid signature: the document content changed after signing."

    # Acquire certificate
    if cert_pem_sidecar:
        cert_pem = cert_pem_sidecar
        cert_err = None
    else:
        cert_pem, cert_err = _get_signer_cert_pem(signer_email)
    if cert_err or not cert_pem:
        return False, f"Verification failed: could not retrieve a valid certificate for '{signer_email}'. {cert_err or ''}"

    # Verify signature
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        public_key = cert.public_key()

        revoked_msg = _check_crl_revocation(cert)
        if revoked_msg:
            return False, f"Invalid signature: {revoked_msg}"

        public_key.verify(signature, stored_hash, ec.ECDSA(Prehashed(hashes.SHA256())))

        cn = None
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = "Unknown"

        return True, f"Valid signature.\nSigned by: {cn} ({signer_email})\nTimestamp (UTC): {timestamp_str}"
    except InvalidSignature:
        return False, "Invalid signature: cryptographic verification failed."
    except Exception as e:
        return False, f"Verification error: {e}"
