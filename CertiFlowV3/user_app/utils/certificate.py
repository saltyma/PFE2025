# user_app/utils/certificate.py
# CertiFlow V3: ECC P-256 CSR builder with SAN=email and custom HSMID OID.

from __future__ import annotations

from typing import Callable, Tuple, Optional, Dict, Any, List
import base64
import binascii
import hashlib
from datetime import datetime, timezone

from asn1crypto import csr as asn1_csr
from asn1crypto import x509 as asn1_x509
from asn1crypto import keys as asn1_keys
from asn1crypto import core as asn1_core
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def build_csr_pem_with_hsm_sign(
    email: str,
    common_name: str,
    hsm_id: str,
    spki_b64: str,
    sign_digest_cb: Callable[[bytes], bytes],
) -> Tuple[Optional[str], Optional[str]]:
    """
    Build a PKCS#10 CSR for EC P-256 using an external signer (HSM).

    - email appears in SAN as rfc822Name
    - hsm_id appears in non-critical custom OID 1.3.6.1.4.1.55555.1.1
    - spki_b64 is base64 DER SubjectPublicKeyInfo for the EC P-256 key
    - sign_digest_cb is called with SHA-256 digest of the CertificationRequestInfo DER
      and must return a DER-encoded ECDSA signature (SEQUENCE of r, s)

    Returns (csr_pem, error). On success, error is None.
    """
    try:
        _validate_email(email)
        _validate_hsm_id(hsm_id)
    except ValueError as e:
        return None, f"Invalid email/HSM ID: {e}"

    # Decode and validate SPKI
    try:
        spki_der = base64.b64decode(spki_b64, validate=True)
    except binascii.Error as e:
        return None, f"Invalid SPKI (base64): {e}"
    try:
        spki = asn1_keys.PublicKeyInfo.load(spki_der)
    except Exception as e:
        return None, f"Invalid SPKI (DER): {e}"
    try:
        _validate_p256_spki(spki)
    except ValueError as e:
        return None, str(e)

    # Subject (minimal)
    subject = asn1_x509.Name.build({'common_name': common_name})

    # Extensions: SAN + custom HSMID
    try:
        extensions = _build_extensions(email=email, hsm_id=hsm_id)
    except Exception as e:
        return None, f"CSR extensions build error: {e}"

    # CSR attributes: extension_request
    attributes = asn1_csr.CRIAttributes()
    attributes.append(asn1_csr.CRIAttribute({
        'type': 'extension_request',
        'values': [extensions],
    }))

    cri = asn1_csr.CertificationRequestInfo({
        'version': 0,
        'subject': subject,
        'subject_pk_info': spki,
        'attributes': attributes,
    })

    tbs_der = cri.dump()
    digest = hashlib.sha256(tbs_der).digest()

    # Obtain DER-encoded ECDSA signature from the HSM
    try:
        sig_der = sign_digest_cb(digest)
        if not isinstance(sig_der, (bytes, bytearray)):
            return None, "HSM/sign callback did not return bytes"
        sig_der = bytes(sig_der)
        if not sig_der or sig_der[0] != 0x30:
            return None, "Signature is not DER-encoded ECDSA (expected SEQUENCE)"
    except Exception as e:
        return None, f"Signing error: {e}"

    # Signature algorithm: ecdsa-with-SHA256
    sig_alg = asn1_x509.SignedDigestAlgorithm({'algorithm': 'sha256_ecdsa'})

    try:
        cert_req = asn1_csr.CertificationRequest({
            'certification_request_info': cri,
            'signature_algorithm': sig_alg,
            'signature': asn1_core.OctetBitString(sig_der),
        })
    except Exception as e:
        return None, f"CSR build error: {e}"

    der = cert_req.dump()
    pem = _der_to_pem(der, b"CERTIFICATE REQUEST")
    return pem, None


# ---------------------------------------------------------------------------

def parse_certificate_pem(pem: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse an issued certificate PEM into a dictionary for UI/DB use."""
    if not pem:
        return None, "Certificate PEM is empty"

    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - want full error propagation for UI
        return None, f"Invalid certificate PEM: {exc}"

    subject = _name_to_dict(cert.subject)
    issuer = _name_to_dict(cert.issuer)

    not_before_utc = _get_cert_datetime(cert, "not_valid_before_utc", "not_valid_before")
    not_after_utc = _get_cert_datetime(cert, "not_valid_after_utc", "not_valid_after")
    now_utc = datetime.now(timezone.utc)
    expires_in_days = (not_after_utc - now_utc).days

    san_emails: List[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_emails = san.value.get_values_for_type(x509.RFC822Name)
    except x509.ExtensionNotFound:
        pass

    hsm_id = None
    try:
        hsm_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.1"))
        raw = hsm_ext.value.value if isinstance(hsm_ext.value, x509.UnrecognizedExtension) else hsm_ext.value
        try:
            hsm_id = asn1_core.UTF8String.load(raw).native
        except Exception:
            try:
                hsm_id = raw.decode("utf-8")
            except Exception:
                hsm_id = None
    except x509.ExtensionNotFound:
        pass

    details: Dict[str, Any] = {
        "serial_number": cert.serial_number,
        "subject": subject,
        "issuer": issuer,
        "valid_from": not_before_utc.isoformat(),
        "valid_to": not_after_utc.isoformat(),
        "expires_in_days": expires_in_days,
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
        "san_emails": san_emails,
    }

    if hsm_id:
        details["hsm_id"] = hsm_id

    details["fingerprints"] = {
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "sha1": cert.fingerprint(hashes.SHA1()).hex(),
    }

    return details, None


def _build_extensions(*, email: str, hsm_id: str) -> asn1_x509.Extensions:
    # SAN with rfc822Name=email
    gen_names = asn1_x509.GeneralNames([
        asn1_x509.GeneralName({'rfc822_name': email})
    ])
    san_ext = asn1_x509.Extension({
        'extn_id': 'subject_alt_name',
        'critical': False,
        # extn_value is an OCTET STRING containing DER of GeneralNames
        'extn_value': asn1_core.ParsableOctetString(gen_names.dump()),
    })

    # Custom HSMID OID; value is DER UTF8String(hsm_id) inside extn_value
    hsm_der = asn1_core.UTF8String(hsm_id).dump()
    hsm_ext = asn1_x509.Extension({
        'extn_id': asn1_x509.ExtensionId('1.3.6.1.4.1.55555.1.1'),
        'critical': False,
        'extn_value': asn1_core.ParsableOctetString(hsm_der),
    })

    exts = asn1_x509.Extensions()
    exts.append(san_ext)
    exts.append(hsm_ext)
    return exts


def _validate_email(email: str) -> None:
    if not email or '@' not in email:
        raise ValueError("Email must contain '@'")
    local, domain = email.split('@', 1)
    if not local or not domain:
        raise ValueError("Email local-part and domain must be non-empty")
    try:
        email.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError("Email must be ASCII")


def _validate_hsm_id(hsm_id: str) -> None:
    if not hsm_id:
        raise ValueError("HSM ID is empty")
    try:
        hsm_id.encode('ascii')
    except UnicodeEncodeError:
        raise ValueError("HSM ID must be ASCII")


def _validate_p256_spki(spki: asn1_keys.PublicKeyInfo) -> None:
    # Algorithm must be EC; curve must be P-256
    alg = spki['algorithm']
    if alg['algorithm'].native != 'ec':
        raise ValueError("SPKI algorithm is not EC")
    params = alg['parameters']
    native = params.native
    # Accept common aliases for P-256
    if native not in ('prime256v1', 'secp256r1'):
        try:
            chosen = params.chosen.native
        except Exception:
            chosen = None
        if chosen not in ('prime256v1', 'secp256r1'):
            raise ValueError("SPKI curve is not P-256 (prime256v1/secp256r1)")
    # Public key should be uncompressed (65 bytes, first byte 0x04)
    pub_bytes = spki['public_key'].native
    if not isinstance(pub_bytes, (bytes, bytearray)):
        raise ValueError("SPKI public key is not bytes")
    if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
        raise ValueError("SPKI public key is not uncompressed P-256 (65 bytes)")


def _der_to_pem(der: bytes, label: bytes) -> str:
    b64 = base64.encodebytes(der).replace(b'\n', b'')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return (
        b"-----BEGIN " + label + b"-----\n" +
        b"\n".join(lines) + b"\n" +
        b"-----END " + label + b"-----\n"
    ).decode('ascii')


def _name_to_dict(name: x509.Name) -> Dict[str, str]:
    mapping = {
        NameOID.COMMON_NAME: "commonName",
        NameOID.EMAIL_ADDRESS: "emailAddress",
        NameOID.COUNTRY_NAME: "countryName",
        NameOID.ORGANIZATION_NAME: "organizationName",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
        NameOID.LOCALITY_NAME: "localityName",
        NameOID.SERIAL_NUMBER: "serialNumber",
    }
    out: Dict[str, str] = {}
    for attr in name:
        label = mapping.get(attr.oid, attr.oid.dotted_string)
        out[label] = attr.value
    return out


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_cert_datetime(cert: x509.Certificate, utc_attr: str, naive_attr: str) -> datetime:
    """Return a timezone-aware datetime without triggering deprecation warnings."""
    dt_utc = getattr(cert, utc_attr, None)
    if dt_utc is not None:
        return dt_utc
    return _as_utc(getattr(cert, naive_attr))

