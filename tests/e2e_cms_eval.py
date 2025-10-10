#!/usr/bin/env python3
"""End-to-end CMS signing and offline verification workflow."""
from __future__ import annotations

import argparse
import base64
import csv
import json
import sys
import time
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))
    from hsm_board_tester import HSMFatalError, SerialHSMClient, execute_happy_path, _percentile, _sha256_digest  # type: ignore
else:
    from .hsm_board_tester import HSMFatalError, SerialHSMClient, execute_happy_path, _percentile, _sha256_digest

DEFAULT_TRUST = Path("./trust")
DEFAULT_PDF = Path("./fixtures/sample.pdf")
DEFAULT_CERT = Path("./artifacts/issued_cert.pem")
DEFAULT_CRL = Path("./artifacts/latest_after_revoke.crl")


@dataclass
class StageTiming:
    run: int
    stage: str
    duration_ms: float
    status: str


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _load_trust_store(path: Path) -> List[x509.Certificate]:
    certs: List[x509.Certificate] = []
    for file in path.glob("**/*"):
        if not file.is_file():
            continue
        data = file.read_bytes()
        try:
            certs.append(x509.load_pem_x509_certificate(data))
        except ValueError:
            try:
                certs.append(x509.load_der_x509_certificate(data))
            except ValueError:
                continue
    if not certs:
        raise RuntimeError(f"No trust anchors found in {path}")
    return certs


def _load_crls(paths: Sequence[Path]) -> List[x509.CertificateRevocationList]:
    crls: List[x509.CertificateRevocationList] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"CRL not found: {path}")
        data = path.read_bytes()
        try:
            crls.append(x509.load_der_x509_crl(data))
        except ValueError:
            crls.append(x509.load_pem_x509_crl(data))
    return crls


def _build_cms(signature: bytes, cert: x509.Certificate, digest: bytes) -> bytes:
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": cms.Name.build(cert.issuer),
                            "serial_number": cert.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": {"algorithm": "sha256"},
            "signature_algorithm": {"algorithm": "ecdsa_with_sha256"},
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [cms.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": cms.EncapsulatedContentInfo(
                {"content_type": "data", "content": digest}
            ),
            "certificates": [cms.Certificate.load(cert.public_bytes(Encoding.DER))],
            "signer_infos": [signer_info],
        }
    )
    content_info = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return content_info.dump()


def _verify_chain(cert: x509.Certificate, trust: Sequence[x509.Certificate], crls: Sequence[x509.CertificateRevocationList]) -> None:
    # Time validity
    now = time.time()
    if cert.not_valid_before.timestamp() > now or cert.not_valid_after.timestamp() < now:
        raise RuntimeError("Signer certificate is not currently valid")

    issuer = None
    for ca in trust:
        if cert.issuer == ca.subject:
            issuer = ca
            break
    if issuer is None:
        raise RuntimeError("Issuer not found in trust store")

    issuer.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),
    )

    for crl in crls:
        if crl.issuer == issuer.subject:
            issuer.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ec.ECDSA(crl.signature_hash_algorithm),
            )
            for revoked in crl:
                if revoked.serial_number == cert.serial_number:
                    raise RuntimeError("Signer certificate is revoked")


def _verify_cms(cms_blob: bytes, digest: bytes, trust: Sequence[x509.Certificate], crls: Sequence[x509.CertificateRevocationList]) -> None:
    content_info = cms.ContentInfo.load(cms_blob)
    if content_info["content_type"].native != "signed_data":
        raise RuntimeError("Unsupported CMS content type")
    signed_data = content_info["content"]
    encap = signed_data["encap_content_info"]
    cms_digest = encap["content"].native
    if cms_digest != digest:
        raise RuntimeError("CMS digest mismatch")
    certs = [x509.load_der_x509_certificate(bytes(cert)) for cert in signed_data["certificates"]]
    if not certs:
        raise RuntimeError("CMS missing certificates")
    cert = certs[0]
    signer_info = signed_data["signer_infos"][0]
    signature = signer_info["signature"].native
    cert.public_key().verify(signature, cms_digest, ec.ECDSA(hashes.SHA256()))
    _verify_chain(cert, trust, crls)


def _tamper(blob: bytes) -> bytes:
    arr = bytearray(blob)
    arr[-1] ^= 0x01
    return bytes(arr)


def _summary_stats(values: Iterable[float]) -> Dict[str, float]:
    data = list(values)
    if not data:
        return {"median": float("nan"), "p95": float("nan")}
    return {"median": float(statistics.median(data)), "p95": _percentile(data, 95)}


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="End-to-end CMS evaluation")
    parser.add_argument("--port", required=True, help="USB CDC-ACM port for the HSM")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--pin", required=True, help="PIN for unlocking the HSM")
    parser.add_argument("--timeout", type=float, default=2.4)
    parser.add_argument("--trust", type=Path, default=DEFAULT_TRUST)
    parser.add_argument("--pdf", type=Path, default=DEFAULT_PDF)
    parser.add_argument("--cert", type=Path, default=DEFAULT_CERT)
    parser.add_argument("--crl", type=Path, action="append", default=[DEFAULT_CRL])
    parser.add_argument("--out", type=Path, default=Path("./artifacts"))
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--csv", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if not args.pdf.exists():
        raise FileNotFoundError(f"PDF not found: {args.pdf}")
    if not args.cert.exists():
        raise FileNotFoundError(f"Signer certificate not found: {args.cert}")

    _ensure_dir(args.out)

    trust_store = _load_trust_store(args.trust)
    crls = _load_crls([Path(p) for p in args.crl])
    signer_cert = x509.load_pem_x509_certificate(args.cert.read_bytes())

    metrics: Dict[str, List[float]] = defaultdict(list)
    stage_rows: List[StageTiming] = []
    cms_artifacts: List[bytes] = []

    client = SerialHSMClient(args.port, args.baud, args.timeout)
    try:
        with client:
            for run in range(1, args.runs + 1):
                t0 = time.perf_counter()
                digest = _sha256_digest(args.pdf)
                digest_duration = (time.perf_counter() - t0) * 1000.0
                metrics["digest"].append(digest_duration)
                stage_rows.append(StageTiming(run, "digest", digest_duration, "OK"))

                digest_b64 = base64.b64encode(digest).decode("ascii")
                try:
                    result = execute_happy_path(client, args.pin, digest_b64, defaultdict(list))
                except HSMFatalError as err:
                    print(f"Run {run} HSM failure: {err}", file=sys.stderr)
                    return 1

                sign_metric = next((m for m in result.command_metrics if m.command == "SIGN"), None)
                if sign_metric is None:
                    print("Missing SIGN metric", file=sys.stderr)
                    return 1
                metrics["hsm_sign"].append(sign_metric.duration)
                stage_rows.append(StageTiming(run, "hsm_sign", sign_metric.duration, sign_metric.status))

                signature = base64.b64decode(result.signature_der_b64)
                cms_start = time.perf_counter()
                cms_blob = _build_cms(signature, signer_cert, digest)
                cms_duration = (time.perf_counter() - cms_start) * 1000.0
                metrics["cms_packaging"].append(cms_duration)
                stage_rows.append(StageTiming(run, "cms_packaging", cms_duration, "OK"))

                verify_start = time.perf_counter()
                try:
                    _verify_cms(cms_blob, digest, trust_store, crls)
                except Exception as err:
                    print(f"Offline verification failed: {err}", file=sys.stderr)
                    return 1
                verify_duration = (time.perf_counter() - verify_start) * 1000.0
                metrics["offline_verify"].append(verify_duration)
                stage_rows.append(StageTiming(run, "offline_verify", verify_duration, "OK"))

                cms_artifacts.append(cms_blob)
    finally:
        client.close()

    if not cms_artifacts:
        print("No CMS artifacts produced", file=sys.stderr)
        return 1

    cms_path = args.out / "cms_signature.p7s"
    cms_path.write_bytes(cms_artifacts[-1])

    negative_results: Dict[str, str] = {}
    final_digest = _sha256_digest(args.pdf)

    try:
        _verify_cms(cms_artifacts[-1], final_digest, [], crls)
        raise RuntimeError("mismatched trust store succeeded")
    except Exception as err:
        negative_results["mismatched_trust"] = str(err)
        if "succeeded" in str(err):
            print("Negative test (mismatched trust) did not fail as expected", file=sys.stderr)
            return 1

    try:
        _verify_cms(_tamper(cms_artifacts[-1]), final_digest, trust_store, crls)
        raise RuntimeError("tampered CMS succeeded")
    except Exception as err:
        negative_results["tampered"] = str(err)
        if "succeeded" in str(err):
            print("Negative test (tampered CMS) did not fail as expected", file=sys.stderr)
            return 1

    try:
        revoked_crl = _load_crls(list(args.crl))
        _verify_cms(cms_artifacts[-1], final_digest, trust_store, revoked_crl)
        raise RuntimeError("revoked signer succeeded")
    except Exception as err:
        negative_results["revoked"] = str(err)
        if "succeeded" in str(err):
            print("Negative test (revoked signer) did not fail as expected", file=sys.stderr)
            return 1

    metric_summary = {stage: _summary_stats(values) for stage, values in metrics.items()}

    if args.csv:
        csv_path = args.out / "e2e_metrics.csv"
        with csv_path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["run", "stage", "duration_ms", "status"])
            for row in stage_rows:
                writer.writerow([row.run, row.stage, f"{row.duration_ms:.3f}", row.status])

    if args.json:
        summary_path = args.out / "e2e_summary.json"
        summary = {
            "runs": len(metrics.get("digest", [])),
            "metrics": metric_summary,
            "cms_artifact": str(cms_path),
            "negative_tests": negative_results,
        }
        with summary_path.open("w") as handle:
            json.dump(summary, handle, indent=2)

    print("E2E CMS evaluation complete")
    for stage, stats in metric_summary.items():
        print(f"{stage}: median={stats['median']:.2f} ms p95={stats['p95']:.2f} ms")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
