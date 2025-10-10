#!/usr/bin/env python3
"""Regression harness for the local CA Owner API.

The script intentionally mirrors the HSM test harness in terms of artifact
creation, CSV/JSON outputs and resilience.  Each API call is measured and the
responses are validated using the ``cryptography`` package when dealing with
X.509 structures.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes


@dataclass
class ApiMetric:
    name: str
    method: str
    url: str
    status_code: int
    duration_ms: float
    ok: bool
    notes: str = ""


@dataclass
class RegressionContext:
    base_url: str
    session: requests.Session
    metrics: List[ApiMetric] = field(default_factory=list)
    artifacts: Dict[str, Path] = field(default_factory=dict)
    failures: List[str] = field(default_factory=list)

    def record(self, name: str, method: str, url: str, response: requests.Response, start: float, ok: bool, notes: str = "") -> None:
        duration_ms = (time.perf_counter() - start) * 1000.0
        self.metrics.append(ApiMetric(name, method, url, response.status_code, duration_ms, ok, notes))
        if not ok:
            self.failures.append(f"{name} failed: HTTP {response.status_code} {notes}")
def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _request(ctx: RegressionContext, name: str, method: str, path: str, **kwargs) -> requests.Response:
    url = ctx.base_url.rstrip("/") + path
    start = time.perf_counter()
    response = ctx.session.request(method, url, timeout=5, **kwargs)
    ok = response.ok
    ctx.record(name, method, url, response, start, ok)
    return response


def _expect_status(response: requests.Response, expected: int) -> None:
    if response.status_code != expected:
        raise RuntimeError(f"Expected HTTP {expected}, got {response.status_code}: {response.text}")


def _load_cert_with_meta(pem_data: str) -> tuple[x509.Certificate, Dict[str, object]]:
    cert = x509.load_pem_x509_certificate(pem_data.encode("ascii"))
    metadata: Dict[str, object] = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "fingerprints": {
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "sha1": cert.fingerprint(hashes.SHA1()).hex(),
        },
        "serial_number": format(cert.serial_number, "x"),
        "extensions": [ext.oid.dotted_string for ext in cert.extensions],
    }
    return cert, metadata


def _save_artifact(path: Path, content: bytes) -> None:
    path.write_bytes(content)


def run_regression(
    base_url: str,
    artifact_dir: Path,
    spki_b64: str,
    csv_enabled: bool,
    json_enabled: bool,
) -> int:
    _ensure_dir(artifact_dir)
    session = requests.Session()
    ctx = RegressionContext(base_url=base_url, session=session)

    user_id = "test-user"
    csr_payload = {"user": user_id, "spki": spki_b64}

    # Submit CSR (happy path)
    response = _request(ctx, "submit_csr", "POST", "/api/cert/csr", json=csr_payload)
    _expect_status(response, 201)
    request_id = response.json().get("id")
    if not request_id:
        raise RuntimeError("CSR submission missing request id")

    # Duplicate CSR should be gracefully handled
    dup_response = _request(ctx, "duplicate_csr", "POST", "/api/cert/csr", json=csr_payload)
    if dup_response.status_code not in {200, 409}:
        raise RuntimeError("Duplicate CSR did not return 200/409")

    # Invalid CSR format
    bad_response = _request(ctx, "invalid_csr", "POST", "/api/cert/csr", json={"user": "bad", "spki": "not-base64"})
    if bad_response.status_code not in {400, 422}:
        raise RuntimeError("Invalid CSR did not return client error")

    # Pending list should include the first request
    pending = _request(ctx, "pending_list", "GET", "/api/requests/pending")
    _expect_status(pending, 200)
    pending_ids = {item.get("id") for item in pending.json()}
    if request_id not in pending_ids:
        raise RuntimeError("Submitted CSR missing from pending list")

    # Approve flow
    approve_resp = _request(ctx, "approve", "POST", f"/api/requests/{request_id}/approve")
    _expect_status(approve_resp, 200)

    cert_resp = _request(ctx, "fetch_cert", "GET", f"/api/cert/{user_id}")
    _expect_status(cert_resp, 200)
    cert_pem = cert_resp.text
    cert, cert_meta = _load_cert_with_meta(cert_pem)
    cert_path = artifact_dir / "issued_cert.pem"
    _save_artifact(cert_path, cert_pem.encode("ascii"))
    ctx.artifacts["issued_cert"] = cert_path

    # CRL fetch
    crl_resp = _request(ctx, "fetch_crl", "GET", "/api/crl")
    _expect_status(crl_resp, 200)
    crl_path = artifact_dir / "latest.crl"
    _save_artifact(crl_path, crl_resp.content)
    ctx.artifacts["crl_initial"] = crl_path
    initial_crl = x509.load_der_x509_crl(crl_resp.content)
    if cert.serial_number in [rev.serial_number for rev in initial_crl]:
        raise RuntimeError("Certificate appears revoked before synthetic revocation")

    # Logs fetch
    logs_resp = _request(ctx, "fetch_logs", "GET", "/api/logs")
    _expect_status(logs_resp, 200)
    logs_path = artifact_dir / "logs.json"
    _save_artifact(logs_path, logs_resp.content)
    ctx.artifacts["logs"] = logs_path

    # Reject flow using a fresh CSR
    reject_payload = {"user": "reject-user", "spki": spki_b64}
    reject_submit = _request(ctx, "reject_submit", "POST", "/api/cert/csr", json=reject_payload)
    _expect_status(reject_submit, 201)
    reject_id = reject_submit.json().get("id")
    if not reject_id:
        raise RuntimeError("Reject flow missing id")
    reject_resp = _request(ctx, "reject", "POST", f"/api/requests/{reject_id}/reject")
    _expect_status(reject_resp, 200)

    # Synthetic revocation: assume API accepts POST /api/cert/{user_id}/revoke
    revoke_resp = _request(ctx, "revoke", "POST", f"/api/cert/{user_id}/revoke", json={"reason": "keyCompromise"})
    if revoke_resp.status_code not in {200, 202, 204}:
        raise RuntimeError("Revocation endpoint returned unexpected status")

    refreshed_crl = _request(ctx, "refresh_crl", "GET", "/api/crl")
    _expect_status(refreshed_crl, 200)
    crl2_path = artifact_dir / "latest_after_revoke.crl"
    _save_artifact(crl2_path, refreshed_crl.content)
    ctx.artifacts["crl_after_revoke"] = crl2_path
    refreshed_crl_obj = x509.load_der_x509_crl(refreshed_crl.content)

    if cert.serial_number not in [rev.serial_number for rev in refreshed_crl_obj]:
        raise RuntimeError("Revoked certificate serial missing from refreshed CRL")

    # Metrics output
    if csv_enabled:
        csv_path = artifact_dir / "ca_api_results.csv"
        with csv_path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["name", "method", "url", "status", "duration_ms", "ok", "notes"])
            for metric in ctx.metrics:
                writer.writerow([
                    metric.name,
                    metric.method,
                    metric.url,
                    metric.status_code,
                    f"{metric.duration_ms:.3f}",
                    int(metric.ok),
                    metric.notes,
                ])

    if json_enabled:
        summary_path = artifact_dir / "ca_api_summary.json"
        summary = {
            "counts": {
                "total": len(ctx.metrics),
                "failures": len(ctx.failures),
            },
            "certificate": cert_meta,
            "http_status": {metric.name: metric.status_code for metric in ctx.metrics},
            "artifacts": {key: str(path) for key, path in ctx.artifacts.items()},
            "crl": {
                "initial_entries": len(initial_crl),
                "post_revoke_entries": len(refreshed_crl_obj),
            },
        }
        with summary_path.open("w") as handle:
            json.dump(summary, handle, indent=2)

    if ctx.failures:
        for failure in ctx.failures:
            print(failure, file=sys.stderr)
        return 1

    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CA Owner API regression harness")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000", help="Base URL for the API")
    parser.add_argument("--out", type=Path, default=Path("./artifacts"), help="Artifact output directory")
    parser.add_argument("--csv", action="store_true", help="Emit CSV metrics")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary")
    parser.add_argument("--spki", type=Path, help="Path to file containing base64 DER SPKI")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    _ensure_dir(args.out)

    if args.spki:
        spki_b64 = args.spki.read_text().strip()
    else:
        raise RuntimeError("SPKI source must be provided via --spki")

    return run_regression(args.base_url, args.out, spki_b64, args.csv, args.json)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover - top-level guard for CLI usage
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
