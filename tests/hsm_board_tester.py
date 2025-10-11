#!/usr/bin/env python3
"""High level functional and latency test harness for the STM32U5 HSM board.

This script opens the board over USB CDC-ACM and exercises its ASCII line
protocol while recording detailed latency metrics.  The implementation is
structured so that it can also be imported by other test tooling (for example
`e2e_cms_eval.py`) without invoking the CLI entry point.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import statistics
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import serial  # type: ignore
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key


DEFAULT_SAMPLE_PATH = Path("./fixtures/sample.pdf")
CRLF = "\r\n"


class HSMProtocolError(RuntimeError):
    """Raised when the device returns an unexpected response."""


class HSMFatalError(RuntimeError):
    """Raised when the device cannot be recovered with retries."""


@dataclass
class CommandMetric:
    """Captures timing and status for a single command invocation."""

    command: str
    duration: float
    status: str


@dataclass
class HSMResponse:
    """Container for a parsed response from the HSM."""

    status: str
    head: str
    body: Optional[str] = None


@dataclass
class RunResult:
    """Stores the data observed in a single successful happy-path run."""

    banner: str
    device_id: str
    public_key_der_b64: str
    signature_der_b64: str
    digest_hex: str
    unlock_state: str
    unlock_detail: str
    keygen_state: str
    keygen_detail: str
    command_metrics: List[CommandMetric] = field(default_factory=list)


@dataclass
class UnlockStatus:
    """Classification of the unlock step."""

    success: bool
    state: str
    detail: str


@dataclass
class KeygenStatus:
    """Classification of the key generation step."""

    success: bool
    state: str
    detail: str


class SerialHSMClient:
    """Thin wrapper around pyserial implementing the ASCII protocol."""

    _PAYLOAD_HEADS = {"HSMID", "PUBKEY", "SIG"}

    def __init__(
        self,
        port: str,
        baudrate: int,
        timeout: float,
    ) -> None:
        self._port = port
        self._baudrate = baudrate
        self._timeout = timeout
        self._serial: Optional[serial.Serial] = None

    def open(self) -> None:
        self.close()
        write_timeout = None if self._timeout <= 0 else max(self._timeout, 5.0)
        self._serial = serial.Serial(
            self._port,
            self._baudrate,
            timeout=self._timeout,
            write_timeout=write_timeout,
        )
        time.sleep(0.2)
        try:
            self._serial.reset_input_buffer()
            self._serial.reset_output_buffer()
        except serial.SerialException:
            pass

    def close(self) -> None:
        if self._serial and self._serial.is_open:
            try:
                self._serial.flush()
            finally:
                self._serial.close()
        self._serial = None

    def __enter__(self) -> "SerialHSMClient":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        self.close()

    @property
    def timeout(self) -> float:
        return self._timeout

    def _readline(self, required: bool, timeout: Optional[float] = None) -> str:
        assert self._serial is not None
        original_timeout = self._serial.timeout
        try:
            if timeout is not None:
                self._serial.timeout = timeout
            elif not required:
                self._serial.timeout = min(0.25, original_timeout or 0.25)
            line = self._serial.readline()
        finally:
            self._serial.timeout = original_timeout
        if not line:
            if required:
                raise HSMProtocolError("Timeout waiting for response line")
            return ""
        return line.decode("utf-8", "ignore").strip()

    def transact(
        self,
        command: str,
        *,
        retries: int = 2,
        expect_payload: bool = False,
        allow_additional: bool = True,
        response_timeout: Optional[float] = None,
        pre_delay: float = 0.0,
        max_payload_lines: int = 4,
    ) -> HSMResponse:
        """Send *command* and return a parsed :class:`HSMResponse`."""

        last_error: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                if not self._serial or not self._serial.is_open:
                    self.open()
                assert self._serial is not None
                line = (command + CRLF).encode("ascii")
                if pre_delay:
                    time.sleep(pre_delay)
                self._serial.write(line)
                self._serial.flush()
                status_timeout = response_timeout or self._timeout
                status_line = self._readline(required=True, timeout=status_timeout)
                if not status_line:
                    raise HSMProtocolError("Empty response")
                parts = status_line.split(" ", 1)
                status = parts[0].upper()
                head = parts[1] if len(parts) > 1 else ""
                body: Optional[str] = None
                head_upper = head.upper()
                read_required = expect_payload or (status == "OK" and head_upper in self._PAYLOAD_HEADS)
                payload_lines: List[str] = []
                if read_required:
                    payload_timeout = response_timeout or max(self._timeout, 1.0)
                    payload_line = self._readline(required=True, timeout=payload_timeout)
                    if not payload_line:
                        raise HSMProtocolError("Missing payload for multi-line response")
                    payload_lines.append(payload_line)
                if allow_additional and max_payload_lines > len(payload_lines):
                    optional_timeout = min(0.35, (response_timeout or self._timeout) or 0.35)
                    for _ in range(max_payload_lines - len(payload_lines)):
                        extra = self._readline(required=False, timeout=optional_timeout)
                        if not extra:
                            break
                        payload_lines.append(extra)
                if payload_lines:
                    body = "\n".join(payload_lines)
                return HSMResponse(status=status, head=head, body=body)
            except (serial.SerialException, serial.SerialTimeoutException, HSMProtocolError) as err:  # type: ignore[attr-defined]
                last_error = err
                self.close()
                time.sleep(0.15 * (attempt + 1))
        raise HSMFatalError(f"Failed to send '{command}': {last_error}")


def _ensure_artifact_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _sha256_digest(path: Path) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.finalize()


def _record_metric(metrics: Dict[str, List[float]], command: str, duration: float) -> None:
    metrics.setdefault(command, []).append(duration)


def _percentile(values: Iterable[float], percentile: float) -> float:
    data = list(sorted(values))
    if not data:
        return float("nan")
    index = max(0, min(len(data) - 1, int(round((percentile / 100.0) * (len(data) - 1)))))
    return data[index]


def _verify_signature(spki_der: bytes, digest: bytes, signature_der: bytes) -> bool:
    public_key = load_der_public_key(spki_der)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise HSMProtocolError("Unsupported public key type")
    try:
        public_key.verify(signature_der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except crypto_exceptions.InvalidSignature:
        return False


def _response_text(response: HSMResponse) -> str:
    parts = [response.status]
    if response.head:
        parts.append(response.head)
    if response.body:
        parts.append(response.body)
    return " ".join(part for part in parts if part).strip()


def _response_tokens(response: HSMResponse) -> set[str]:
    tokens = set()
    text = _response_text(response)
    if not text:
        return tokens
    for piece in re.split(r"[^A-Za-z0-9]+", text):
        if piece:
            tokens.add(piece.upper())
    return tokens


def interpret_unlock_response(response: HSMResponse) -> UnlockStatus:
    tokens = _response_tokens(response)
    detail = _response_text(response)
    if response.status == "OK":
        if {"ALREADY", "UNLOCKED"} & tokens:
            return UnlockStatus(True, "already_unlocked", detail)
        if {"NOPIN", "NO", "PINLESS", "PINFREE"} & tokens:
            return UnlockStatus(True, "no_pin", detail)
        return UnlockStatus(True, "unlocked", detail)
    if response.status == "ERR":
        if {"ALREADY", "UNLOCKED"} & tokens:
            return UnlockStatus(True, "already_unlocked", detail)
        if {"NOPIN", "NO", "PINLESS", "PINFREE"} & tokens:
            return UnlockStatus(True, "no_pin", detail)
    return UnlockStatus(False, "locked", detail)


def interpret_keygen_response(response: HSMResponse) -> KeygenStatus:
    tokens = _response_tokens(response)
    detail = _response_text(response)
    if response.status == "OK":
        if {"EXIST", "KEYEXISTS", "PRESENT", "SKIP"} & tokens:
            return KeygenStatus(True, "existing", detail)
        return KeygenStatus(True, "generated", detail)
    if response.status == "ERR" and {"EXIST", "KEYEXISTS", "PRESENT", "ALREADY"} & tokens:
        return KeygenStatus(True, "existing", detail)
    return KeygenStatus(False, "error", detail)


def _negative_tests(client: SerialHSMClient) -> Dict[str, Dict[str, object]]:
    """Exercise basic negative behaviors and capture their outcomes."""

    results: Dict[str, Dict[str, object]] = {}
    scenarios = {
        "wrong_pin": "UNLOCK 0000",
        "malformed": "INFO???",
        "truncated": "SIGN SHA256 00",
    }
    for name, command in scenarios.items():
        response = client.transact(command, allow_additional=True, max_payload_lines=6)
        passed = response.status == "ERR"
        if name == "wrong_pin":
            unlock_status = interpret_unlock_response(response)
            passed = passed or unlock_status.state in {"already_unlocked", "no_pin"}
        results[name] = {
            "status": response.status,
            "head": response.head,
            "body": response.body,
            "expected": "ERR",
            "passed": bool(passed),
        }

    rate_hits = 0
    hex_digest = "00" * 32
    rate_responses: List[Dict[str, object]] = []
    for _ in range(5):
        response = client.transact(
            f"SIGN SHA256 {hex_digest}",
            allow_additional=True,
            response_timeout=max(client.timeout * 1.5, 5.0),
            max_payload_lines=6,
        )
        rate_responses.append(
            {
                "status": response.status,
                "head": response.head,
                "body": response.body,
            }
        )
        if response.status == "ERR" and "RATE" in _response_text(response).upper():
            rate_hits += 1
        time.sleep(0.05)
    results["rate_limit"] = {
        "status": "ERR" if rate_hits else "UNKNOWN",
        "head": f"hits={rate_hits}",
        "body": rate_responses,
        "expected": "ERR",
        "passed": rate_hits > 0,
    }
    return results


def execute_happy_path(
    client: SerialHSMClient,
    pin: str,
    digest: bytes,
    metrics: Dict[str, List[float]],
) -> RunResult:
    command_log: List[CommandMetric] = []
    start = time.perf_counter()
    digest_hex = digest.hex()

    # INFO
    t0 = time.perf_counter()
    info_resp = client.transact("INFO", allow_additional=True, max_payload_lines=6)
    duration = (time.perf_counter() - t0) * 1000.0
    _record_metric(metrics, "INFO", duration)
    command_log.append(CommandMetric("INFO", duration, info_resp.status))
    if info_resp.status != "OK":
        raise HSMFatalError(f"INFO failed: {info_resp.status} {info_resp.head}")
    banner = info_resp.body or info_resp.head or ""

    # HSMID
    t0 = time.perf_counter()
    hsmid_resp = client.transact("HSMID", expect_payload=True, max_payload_lines=6)
    duration = (time.perf_counter() - t0) * 1000.0
    _record_metric(metrics, "HSMID", duration)
    command_log.append(CommandMetric("HSMID", duration, hsmid_resp.status))
    if hsmid_resp.status != "OK" or not hsmid_resp.body:
        raise HSMFatalError(f"HSMID failed: {hsmid_resp.status} {hsmid_resp.head}")
    device_id = hsmid_resp.body

    # UNLOCK
    t0 = time.perf_counter()
    unlock_timeout = max(client.timeout * 2, 6.0)
    unlock_resp = client.transact(
        f"UNLOCK {pin}",
        allow_additional=True,
        response_timeout=unlock_timeout,
        pre_delay=0.05,
        max_payload_lines=6,
    )
    duration = (time.perf_counter() - t0) * 1000.0
    _record_metric(metrics, "UNLOCK", duration)
    command_log.append(CommandMetric("UNLOCK", duration, unlock_resp.status))
    unlock_status = interpret_unlock_response(unlock_resp)
    if not unlock_status.success:
        raise HSMFatalError(f"UNLOCK failed: {unlock_status.detail}")

    # KEYGEN
    t0 = time.perf_counter()
    keygen_timeout = max(client.timeout * 3, 10.0)
    keygen_resp = client.transact(
        "KEYGEN EC P256",
        allow_additional=True,
        response_timeout=keygen_timeout,
        pre_delay=0.05,
        max_payload_lines=6,
    )
    duration = (time.perf_counter() - t0) * 1000.0
    _record_metric(metrics, "KEYGEN", duration)
    command_log.append(CommandMetric("KEYGEN", duration, keygen_resp.status))
    keygen_status = interpret_keygen_response(keygen_resp)
    if not keygen_status.success:
        raise HSMFatalError(f"KEYGEN unexpected: {keygen_status.detail}")

    # PUBKEY
    t0 = time.perf_counter()
    pubkey_resp = client.transact(
        "PUBKEY",
        expect_payload=True,
        response_timeout=max(client.timeout * 1.5, 5.0),
        max_payload_lines=8,
    )
    duration = (time.perf_counter() - t0) * 1000.0
    _record_metric(metrics, "PUBKEY", duration)
    command_log.append(CommandMetric("PUBKEY", duration, pubkey_resp.status))
    if pubkey_resp.status != "OK" or not pubkey_resp.body:
        raise HSMFatalError(f"PUBKEY failed: {pubkey_resp.status} {pubkey_resp.head}")
    pubkey_b64 = "".join(pubkey_resp.body.split())
    pubkey_der = base64.b64decode(pubkey_b64)

    # SIGN
    t0 = time.perf_counter()
    sign_resp = client.transact(
        f"SIGN SHA256 {digest_hex}",
        expect_payload=True,
        response_timeout=max(client.timeout * 1.5, 5.0),
        max_payload_lines=6,
    )
    duration = (time.perf_counter() - t0) * 1000.0
    _record_metric(metrics, "SIGN", duration)
    command_log.append(CommandMetric("SIGN", duration, sign_resp.status))
    if sign_resp.status != "OK" or not sign_resp.body:
        raise HSMFatalError(f"SIGN failed: {sign_resp.status} {sign_resp.head}")
    if sign_resp.head.upper() not in {"SIG"}:
        raise HSMFatalError(f"Unexpected SIGN response: {sign_resp.head}")

    signature_b64 = "".join(sign_resp.body.split())
    signature_der = base64.b64decode(signature_b64)

    if not _verify_signature(pubkey_der, digest, signature_der):
        raise HSMFatalError("Host verification of signature failed")

    total_duration = (time.perf_counter() - start) * 1000.0
    command_log.append(CommandMetric("TOTAL", total_duration, "OK"))
    _record_metric(metrics, "TOTAL", total_duration)

    return RunResult(
        banner=banner,
        device_id=device_id,
        public_key_der_b64=pubkey_b64,
        signature_der_b64=signature_b64,
        digest_hex=digest_hex,
        unlock_state=unlock_status.state,
        unlock_detail=unlock_status.detail,
        keygen_state=keygen_status.state,
        keygen_detail=keygen_status.detail,
        command_metrics=command_log,
    )


def write_csv(path: Path, rows: List[Tuple[int, CommandMetric]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["run", "cmd", "rtt_ms", "status"])
        for run_idx, metric in rows:
            writer.writerow([run_idx, metric.command, f"{metric.duration:.3f}", metric.status])


def write_summary(
    path: Path,
    metrics: Dict[str, List[float]],
    runs: List[RunResult],
    negatives: Dict[str, Dict[str, object]],
    extra: Optional[Dict[str, object]] = None,
) -> None:
    summary: Dict[str, object] = {
        "medians": {cmd: statistics.median(values) for cmd, values in metrics.items() if values},
        "p95": {cmd: _percentile(values, 95) for cmd, values in metrics.items() if values},
        "runs": len(runs),
        "pass_counts": {cmd: sum(1 for r in runs for m in r.command_metrics if m.command == cmd and m.status == "OK")},
        "device_info": runs[0].device_id if runs else "",
        "firmware_banner": runs[0].banner if runs else "",
        "negative_tests": negatives,
        "unlock_state": runs[-1].unlock_state if runs else "",
        "unlock_detail": runs[-1].unlock_detail if runs else "",
        "keygen_state": runs[-1].keygen_state if runs else "",
        "keygen_detail": runs[-1].keygen_detail if runs else "",
    }
    if extra:
        summary.update(extra)
    with path.open("w") as handle:
        json.dump(summary, handle, indent=2)


def print_human_summary(metrics: Dict[str, List[float]]) -> None:
    for cmd in ("INFO", "HSMID", "PUBKEY", "SIGN"):
        values = metrics.get(cmd, [])
        if not values:
            continue
        median = statistics.median(values)
        p95 = _percentile(values, 95)
        print(f"{cmd:>6}: median={median:7.2f} ms  p95={p95:7.2f} ms")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="STM32U5 HSM board functional tester")
    parser.add_argument("--port", default="COM10", help="Serial port (default: COM10)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--runs", type=int, default=50, help="Number of successful runs to execute")
    parser.add_argument("--pin", default="1234", help="User PIN for UNLOCK (default: 1234)")
    parser.add_argument("--timeout", type=float, default=2.4, help="Serial timeout in seconds")
    parser.add_argument("--out", type=Path, default=Path("./artifacts"), help="Artifact output directory")
    parser.add_argument("--csv", action="store_true", help="Emit CSV metrics file")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary file")
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE_PATH, help="Path to sample PDF")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.sample.exists():
        parser.error(f"Sample payload not found: {args.sample}")

    _ensure_artifact_dir(args.out)

    metrics: Dict[str, List[float]] = defaultdict(list)
    runs: List[RunResult] = []
    csv_rows: List[Tuple[int, CommandMetric]] = []
    negatives: Dict[str, Dict[str, object]] = {}
    digest = _sha256_digest(args.sample)

    client = SerialHSMClient(args.port, args.baud, args.timeout)
    exit_code = 0
    try:
        with client:
            for run in range(1, args.runs + 1):
                try:
                    result = execute_happy_path(client, args.pin, digest, metrics)
                except HSMFatalError as err:
                    print(f"Run {run} failed: {err}", file=sys.stderr)
                    exit_code = 1
                    break
                runs.append(result)
                for metric in result.command_metrics:
                    csv_rows.append((run, metric))
        if runs:
            negatives = _negative_tests(client)
    except HSMFatalError as err:
        print(f"Fatal error: {err}", file=sys.stderr)
        return 1
    finally:
        client.close()

    if not runs:
        print("No successful runs recorded", file=sys.stderr)
        return 1

    if args.csv:
        write_csv(args.out / "hsm_board_metrics.csv", csv_rows)

    latest_run = runs[-1]
    spki_path = args.out / "hsm_pubkey.b64"
    spki_path.write_text(latest_run.public_key_der_b64 + "\n")

    if args.json:
        write_summary(
            args.out / "hsm_board_summary.json",
            metrics,
            runs,
            negatives,
            extra={
                "spki_b64_path": str(spki_path),
                "digest_hex": latest_run.digest_hex,
                "signature_b64": latest_run.signature_der_b64,
            },
        )

    print_human_summary(metrics)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
