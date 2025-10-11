"""Comprehensive firmware benchmark harness for the STM32U5 HSM board.

This script speaks the ASCII CDC-ACM protocol implemented in
`STM32U5_USBX_crypto/Core/Src/hsm_proto.c` and is designed to be run from the
`tests/` directory of the CertiFlow workspace.  It automatically adapts to a
freshly factory-reset board, a provisioned board with an existing PIN/key, or an
already unlocked device.  The harness emulates a Putty-style terminal session
with structured benchmarking, persistence of key artefacts, and rich reporting.

Example invocation (from `tests/`):

    python hsm_firmware_benchmark.py --out ./artifacts

Reports (CSV/JSON/text) are produced automatically; pass `--no-csv`,
`--no-json`, or `--no-text` to disable any of them.

Requirements:
  * pyserial (`pip install pyserial`)
  * cryptography (`pip install cryptography`) – for SPKI parsing & signature verification
  * psutil (optional, `pip install psutil`) – for detailed resource tracking

The script is intentionally verbose and defensive because it is expected to run
against physical hardware that might respond slowly or with transient errors.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import dataclasses
import datetime as dt
import json
import logging
import math
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import serial
from serial import SerialException, SerialTimeoutException

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    psutil = None

try:
    from cryptography import exceptions as crypto_exceptions
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError as exc:  # pragma: no cover - handled at runtime
    crypto_exceptions = None  # type: ignore
    serialization = None  # type: ignore
    hashes = None  # type: ignore
    ec = None  # type: ignore
    _CRYPTO_IMPORT_ERROR = exc
else:
    _CRYPTO_IMPORT_ERROR = None

_DEFAULT_PORT = "COM10"
_DEFAULT_BAUD = 115200
_DEFAULT_PIN = "1234"
_DEFAULT_OUT = Path("./artifacts")
_DEFAULT_MESSAGE = Path("./fixtures/sample.pdf")

_STATUS_PAYLOAD_LINES = {
    "HSMID": 1,
    "PUBKEY": 1,
    "SIG": 1,
}

@dataclasses.dataclass
class CommandRecord:
    run: int
    command: str
    issued_at: dt.datetime
    duration_s: float
    status: str
    code: str
    payload: List[str]
    cpu_time_s: Optional[float]
    cpu_user_s: Optional[float]
    cpu_system_s: Optional[float]
    rss_bytes: Optional[int]
    notes: List[str]

    def as_csv_row(self) -> List[str]:
        payload_str = " | ".join(self.payload)
        notes_str = " | ".join(self.notes)
        return [
            str(self.run),
            self.command,
            self.issued_at.isoformat(timespec="milliseconds"),
            f"{self.duration_s*1000:.3f}",
            self.status,
            self.code,
            payload_str,
            f"{(self.cpu_time_s or 0.0)*1000:.3f}" if self.cpu_time_s is not None else "",
            f"{(self.cpu_user_s or 0.0)*1000:.3f}" if self.cpu_user_s is not None else "",
            f"{(self.cpu_system_s or 0.0)*1000:.3f}" if self.cpu_system_s is not None else "",
            str(self.rss_bytes) if self.rss_bytes is not None else "",
            notes_str,
        ]


class ResourceProbe:
    """Captures lightweight host resource usage around each command."""

    def __init__(self) -> None:
        self._process = psutil.Process(os.getpid()) if psutil else None

    def snapshot(self) -> Dict[str, Optional[float]]:
        data: Dict[str, Optional[float]] = {
            "cpu_time": time.process_time(),
            "cpu_user": None,
            "cpu_system": None,
            "rss": None,
        }
        if self._process is not None:
            try:
                cpu_times = self._process.cpu_times()
                data["cpu_user"] = cpu_times.user
                data["cpu_system"] = getattr(cpu_times, "system", None)
                data["rss"] = float(self._process.memory_info().rss)
            except (psutil.Error, OSError):  # pragma: no cover - defensive
                pass
        return data

    @staticmethod
    def delta(before: Dict[str, Optional[float]], after: Dict[str, Optional[float]]) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[int]]:
        cpu_time = None
        if before["cpu_time"] is not None and after["cpu_time"] is not None:
            cpu_time = float(after["cpu_time"] - before["cpu_time"])
        cpu_user = None
        cpu_system = None
        rss = None
        if before["cpu_user"] is not None and after["cpu_user"] is not None:
            cpu_user = float(after["cpu_user"] - before["cpu_user"])
        if before["cpu_system"] is not None and after["cpu_system"] is not None:
            cpu_system = float(after["cpu_system"] - before["cpu_system"])
        if after["rss"] is not None:
            rss = int(after["rss"])
        return cpu_time, cpu_user, cpu_system, rss


@dataclasses.dataclass
class SerialResponse:
    status: str
    code: str
    payload: List[str]
    raw_lines: List[str]
    duration_s: float


class SerialTranscript:
    def __init__(self) -> None:
        self.entries: List[Dict[str, object]] = []

    def record(self, direction: str, content: str) -> None:
        self.entries.append(
            {
                "timestamp": dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="milliseconds"),
                "direction": direction,
                "content": content,
            }
        )

    def dump(self, path: Path) -> None:
        with path.open("w", encoding="utf-8") as handle:
            for entry in self.entries:
                handle.write(f"[{entry['timestamp']}] {entry['direction']}: {entry['content']}\n")


class HSMClient:
    def __init__(
        self,
        port: str,
        baud: int,
        command_timeout: float,
        long_timeout: float,
        handshake_timeout: float,
        transcript: SerialTranscript,
        read_timeout: float = 0.5,
    ) -> None:
        self._port = port
        self._baud = baud
        self._command_timeout = command_timeout
        self._long_timeout = long_timeout
        self._handshake_timeout = handshake_timeout
        self._read_timeout = read_timeout
        self._serial: Optional[serial.Serial] = None
        self._transcript = transcript
        self._events: List[SerialResponse] = []

    def __enter__(self) -> "HSMClient":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def is_open(self) -> bool:
        return self._serial is not None and self._serial.is_open

    def open(self) -> None:
        if self.is_open:
            return
        try:
            self._serial = serial.Serial(
                port=self._port,
                baudrate=self._baud,
                timeout=self._read_timeout,
                write_timeout=self._long_timeout,
            )
        except SerialException as exc:
            raise RuntimeError(f"Unable to open serial port {self._port}: {exc}") from exc
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()
        self._drain_handshake()

    def close(self) -> None:
        if self._serial is not None:
            try:
                self._serial.close()
            finally:
                self._serial = None

    def _drain_handshake(self) -> None:
        if not self.is_open:
            return
        deadline = time.monotonic() + self._handshake_timeout
        while time.monotonic() < deadline:
            line = self._read_line(timeout=0.5)
            if line is None:
                break
            self._transcript.record("RX", line)
            parsed = self._parse_status_line(line)
            if parsed is not None:
                self._events.append(
                    SerialResponse(parsed[0], parsed[1], [], [line], duration_s=0.0)
                )

    def _read_line(self, timeout: float) -> Optional[str]:
        if not self.is_open:
            return None
        assert self._serial is not None
        deadline = time.monotonic() + timeout
        buffer = bytearray()
        while time.monotonic() < deadline:
            try:
                chunk = self._serial.readline()
            except SerialException as exc:
                raise RuntimeError(f"Serial read error: {exc}") from exc
            if chunk:
                buffer.extend(chunk)
                if buffer.endswith(b"\n"):
                    break
            else:
                # readline timed out, loop until deadline
                continue
        if not buffer:
            return None
        try:
            text = buffer.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            text = buffer.decode("ascii", errors="replace")
        return text.strip("\r\n")

    @staticmethod
    def _parse_status_line(line: str) -> Optional[Tuple[str, str]]:
        if line.startswith("OK "):
            return "OK", line[3:].strip()
        if line == "OK":
            return "OK", ""
        if line.startswith("ERR "):
            return "ERR", line[4:].strip()
        if line == "ERR":
            return "ERR", ""
        return None

    def send_command(
        self,
        command: str,
        *,
        expect_payload: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> SerialResponse:
        if not self.is_open:
            raise RuntimeError("Serial port is not open")
        assert self._serial is not None

        payload_lines = expect_payload
        encoded = (command + "\r\n").encode("utf-8")
        self._transcript.record("TX", command)
        try:
            self._serial.write(encoded)
            self._serial.flush()
        except SerialTimeoutException as exc:
            raise RuntimeError(f"Write timeout while sending '{command}': {exc}") from exc
        except SerialException as exc:
            raise RuntimeError(f"Serial write error for '{command}': {exc}") from exc

        start = time.perf_counter()
        deadline = start + (timeout if timeout is not None else self._command_timeout)
        raw_lines: List[str] = []
        status_line: Optional[str] = None
        status = ""
        code = ""

        while time.perf_counter() < deadline:
            line = self._read_line(timeout=min(self._read_timeout, max(deadline - time.perf_counter(), 0.05)))
            if line is None:
                continue
            self._transcript.record("RX", line)
            raw_lines.append(line)
            parsed = self._parse_status_line(line)
            if parsed is None:
                continue
            status, code = parsed
            status_line = line
            if status == "OK" and code.upper() == "READY":
                # asynchronous ready notification – keep waiting for the actual response
                self._events.append(
                    SerialResponse(status, code, [], [line], duration_s=0.0)
                )
                status_line = None
                status = ""
                code = ""
                continue
            break

        if status_line is None:
            raise TimeoutError(f"Timeout waiting for response to '{command}'")

        if payload_lines is None:
            payload_lines = _STATUS_PAYLOAD_LINES.get(code.upper(), 0)

        payload: List[str] = []
        while payload_lines > 0:
            remaining = max(deadline - time.perf_counter(), 0.05)
            line = self._read_line(timeout=remaining)
            if line is None:
                raise TimeoutError(f"Expected payload for '{command}' but timed out")
            self._transcript.record("RX", line)
            raw_lines.append(line)
            payload.append(line)
            payload_lines -= 1

        duration = time.perf_counter() - start
        response = SerialResponse(status=status, code=code, payload=payload, raw_lines=raw_lines, duration_s=duration)
        return response

    @property
    def events(self) -> List[SerialResponse]:
        return list(self._events)


def percentile(values: Iterable[float], pct: float) -> Optional[float]:
    data = sorted(values)
    if not data:
        return None
    if len(data) == 1:
        return data[0]
    k = (len(data) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return data[int(k)]
    return data[f] + (data[c] - data[f]) * (k - f)


def compute_sha256_hex(path: Path) -> Tuple[str, bytes]:
    import hashlib

    if path.exists() and path.is_file():
        data = path.read_bytes()
    else:
        data = b"CertiFlow benchmark message"
    digest = hashlib.sha256(data).hexdigest().upper()
    return digest, data


def verify_signature(pubkey_b64: str, signature_b64: str, message_bytes: bytes) -> Tuple[Optional[bool], Optional[str]]:
    if serialization is None or ec is None or hashes is None or crypto_exceptions is None:
        return None, f"cryptography not available: {_CRYPTO_IMPORT_ERROR}"
    try:
        spki = base64.b64decode(pubkey_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        return False, f"Failed to decode base64 artefacts: {exc}"
    try:
        public_key = serialization.load_der_public_key(spki)
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Failed to parse SPKI: {exc}"
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return False, "SPKI is not an EC public key"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message_bytes)
    digest_bytes = digest.finalize()
    try:
        public_key.verify(signature, digest_bytes, ec.ECDSA(hashes.SHA256()))
    except crypto_exceptions.InvalidSignature:
        return False, "Invalid signature"
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Verification error: {exc}"
    return True, None


def build_report(
    records: List[CommandRecord],
    summary_path: Optional[Path],
    csv_path: Optional[Path],
    text_path: Optional[Path],
    metadata: Dict[str, object],
) -> None:
    if csv_path is not None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "run",
                    "command",
                    "issued_at",
                    "duration_ms",
                    "status",
                    "code",
                    "payload",
                    "cpu_time_ms",
                    "cpu_user_ms",
                    "cpu_system_ms",
                    "rss_bytes",
                    "notes",
                ]
            )
            for record in records:
                writer.writerow(record.as_csv_row())
        logging.info("Wrote CSV metrics to %s", csv_path)

    summary: Dict[str, object] = {
        "metadata": metadata,
        "generated_at": dt.datetime.now(tz=dt.timezone.utc).isoformat(timespec="seconds"),
        "totals": {
            "commands": len(records),
            "ok": sum(1 for r in records if r.status == "OK"),
            "err": sum(1 for r in records if r.status == "ERR"),
        },
        "per_command": {},
    }

    by_command: Dict[str, List[CommandRecord]] = defaultdict(list)
    for record in records:
        by_command[record.command].append(record)

    for command, rows in by_command.items():
        durations = [row.duration_s for row in rows]
        cpu_times = [row.cpu_time_s for row in rows if row.cpu_time_s is not None]
        rss_values = [row.rss_bytes for row in rows if row.rss_bytes is not None]
        status_counts = Counter(row.status for row in rows)
        summary["per_command"][command] = {
            "runs": len(rows),
            "status": dict(status_counts),
            "duration": {
                "min_ms": min(durations) * 1000.0,
                "max_ms": max(durations) * 1000.0,
                "median_ms": percentile(durations, 50) * 1000.0 if durations else None,
                "p95_ms": percentile(durations, 95) * 1000.0 if durations else None,
            },
            "cpu_time_ms": {
                "median": percentile(cpu_times, 50) * 1000.0 if cpu_times else None,
                "p95": percentile(cpu_times, 95) * 1000.0 if cpu_times else None,
            },
            "rss_bytes": {
                "median": percentile(rss_values, 50) if rss_values else None,
                "p95": percentile(rss_values, 95) if rss_values else None,
            },
        }

    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2)
        logging.info("Wrote JSON summary to %s", summary_path)

    if text_path is not None:
        text_path.parent.mkdir(parents=True, exist_ok=True)
        lines: List[str] = []
        lines.append("HSM Firmware Benchmark Report")
        lines.append("=" * 32)
        lines.append(f"Generated: {summary['generated_at']}")
        lines.append("")
        lines.append("Environment")
        lines.append("-----------")
        for key, value in metadata.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        lines.append("Totals")
        lines.append("------")
        totals = summary["totals"]
        lines.append(f"Commands executed: {totals['commands']}")
        lines.append(f"Successful (OK): {totals['ok']}")
        lines.append(f"Errors (ERR): {totals['err']}")
        lines.append("")
        lines.append("Per-command breakdown")
        lines.append("---------------------")

        def fmt(value: Optional[float], digits: int = 2) -> str:
            return f"{value:.{digits}f}" if value is not None else "n/a"

        for command, details in summary["per_command"].items():
            lines.append(f"* {command}")
            lines.append(f"  - runs: {details['runs']}")
            status_repr = ", ".join(f"{k}={v}" for k, v in details["status"].items())
            lines.append(f"  - status counts: {status_repr}")
            durations = details["duration"]
            lines.append(
                "  - duration (ms): "
                f"min={fmt(durations['min_ms'])}, "
                f"median={fmt(durations['median_ms'])}, "
                f"p95={fmt(durations['p95_ms'])}, "
                f"max={fmt(durations['max_ms'])}"
            )
            cpu = details["cpu_time_ms"]
            lines.append(
                "  - CPU time (ms): "
                f"median={fmt(cpu['median'], digits=4)}, "
                f"p95={fmt(cpu['p95'], digits=4)}"
            )
            rss = details["rss_bytes"]
            lines.append(
                f"  - RSS (bytes): median={rss['median'] if rss['median'] is not None else 'n/a'}, "
                f"p95={rss['p95'] if rss['p95'] is not None else 'n/a'}"
            )
            lines.append("")
        with text_path.open("w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
        logging.info("Wrote text report to %s", text_path)


def run_sequence(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    digest_hex, message_bytes = compute_sha256_hex(Path(args.message))
    digest_path = out_dir / "benchmark_digest_sha256.txt"
    digest_path.write_text(digest_hex + "\n", encoding="utf-8")

    transcript = SerialTranscript()
    resource_probe = ResourceProbe()
    records: List[CommandRecord] = []

    metadata: Dict[str, object] = {
        "port": args.port,
        "baud": args.baud,
        "pin_length": len(args.pin) if args.pin else 0,
        "runs": args.runs,
        "message_path": str(args.message),
        "digest_hex": digest_hex,
        "psutil_available": psutil is not None,
        "cryptography_available": _CRYPTO_IMPORT_ERROR is None,
    }
    metadata["unlock_attempts"] = args.unlock_attempts
    metadata["lockout_wait_s"] = args.lockout_wait
    metadata["locked_retries"] = args.locked_retries

    banner: Optional[str] = None
    hsm_id: Optional[str] = None
    pubkey_b64: Optional[str] = None
    signature_b64: Optional[str] = None

    with HSMClient(
        port=args.port,
        baud=args.baud,
        command_timeout=args.command_timeout,
        long_timeout=args.long_timeout,
        handshake_timeout=args.handshake_timeout,
        transcript=transcript,
        read_timeout=args.serial_read_timeout,
    ) as client:
        metadata["handshake_events"] = [
            {
                "status": event.status,
                "code": event.code,
                "lines": event.raw_lines,
            }
            for event in client.events
        ]
        for run_index in range(1, args.runs + 1):
            logging.info("Starting run %d/%d", run_index, args.runs)

            def send_with_record(
                cmd: str,
                *,
                expect_payload: Optional[int] = None,
                timeout: Optional[float] = None,
                notes: Optional[List[str]] = None,
            ) -> SerialResponse:
                before = resource_probe.snapshot()
                issued_at = dt.datetime.now(tz=dt.timezone.utc)
                response = client.send_command(
                    cmd,
                    expect_payload=expect_payload,
                    timeout=timeout,
                )
                after = resource_probe.snapshot()
                cpu_time, cpu_user, cpu_system, rss = ResourceProbe.delta(before, after)
                note_list = list(notes or [])
                record = CommandRecord(
                    run=run_index,
                    command=cmd,
                    issued_at=issued_at,
                    duration_s=response.duration_s,
                    status=response.status,
                    code=response.code,
                    payload=response.payload,
                    cpu_time_s=cpu_time,
                    cpu_user_s=cpu_user,
                    cpu_system_s=cpu_system,
                    rss_bytes=rss,
                    notes=note_list,
                )
                records.append(record)
                return response

            def ensure_unlocked(context: str) -> None:
                for attempt in range(1, args.unlock_attempts + 1):
                    logging.info(
                        "Ensuring device is unlocked (%s) attempt %d/%d",
                        context,
                        attempt,
                        args.unlock_attempts,
                    )
                    try:
                        resp = send_with_record(
                            f"UNLOCK {args.pin}",
                            timeout=args.long_timeout,
                            notes=[f"context={context}", f"unlock_attempt={attempt}"],
                        )
                    except TimeoutError as exc:
                        logging.warning(
                            "Unlock attempt %d timed out (context=%s): %s",
                            attempt,
                            context,
                            exc,
                        )
                        time.sleep(args.lockout_wait)
                        continue
                    except RuntimeError as exc:
                        raise RuntimeError(f"Serial error while unlocking: {exc}") from exc

                    status = resp.status.upper()
                    code = resp.code.upper()
                    if status == "OK" and code in {"UNLOCKED", "NEWPIN"}:
                        logging.info("Device unlocked via %s (context=%s)", code, context)
                        return
                    if status == "ERR" and code == "LOCKED":
                        logging.warning(
                            "Device reports LOCKED during unlock (context=%s); waiting %.1fs",
                            context,
                            args.lockout_wait,
                        )
                        time.sleep(args.lockout_wait)
                        continue
                    if status == "ERR" and code == "BADPIN":
                        raise RuntimeError("Device rejected supplied PIN (BADPIN)")
                    raise RuntimeError(f"Unexpected unlock response: {resp.status} {resp.code}")

                raise RuntimeError(
                    f"Failed to unlock device after {args.unlock_attempts} attempts (context={context})"
                )

            def execute(
                cmd: str,
                *,
                payload_override: Optional[int] = None,
                timeout: Optional[float] = None,
                notes: Optional[List[str]] = None,
                auto_unlock: bool = True,
            ) -> SerialResponse:
                locked_retries_remaining = max(args.locked_retries, 0)
                attempt = 1
                while True:
                    attempt_notes = list(notes or [])
                    attempt_notes.append(f"attempt={attempt}")
                    response = send_with_record(
                        cmd,
                        expect_payload=payload_override,
                        timeout=timeout,
                        notes=attempt_notes,
                    )
                    status = response.status.upper()
                    code = response.code.upper()
                    if (
                        auto_unlock
                        and status == "ERR"
                        and code == "LOCKED"
                        and locked_retries_remaining > 0
                    ):
                        retry_index = args.locked_retries - locked_retries_remaining + 1
                        locked_retries_remaining -= 1
                        logging.info(
                            "%s reported LOCKED; auto-unlocking for retry %d (remaining retries: %d)",
                            cmd,
                            retry_index,
                            locked_retries_remaining,
                        )
                        ensure_unlocked(f"{cmd} retry {retry_index}")
                        attempt += 1
                        continue
                    return response

            if run_index == 1 or args.repeat_info:
                try:
                    resp = execute("INFO", auto_unlock=False)
                    if resp.status == "OK":
                        banner = resp.code
                except Exception as exc:
                    logging.exception("INFO command failed: %s", exc)
                    return finalize(
                        records,
                        metadata,
                        transcript,
                        out_dir,
                        banner,
                        hsm_id,
                        pubkey_b64,
                        signature_b64,
                        digest_hex,
                        args,
                        fatal_error=str(exc),
                    )

            try:
                ensure_unlocked(f"run{run_index}-preflight")
            except Exception as exc:
                logging.exception("Unable to unlock device: %s", exc)
                return finalize(
                    records,
                    metadata,
                    transcript,
                    out_dir,
                    banner,
                    hsm_id,
                    pubkey_b64,
                    signature_b64,
                    digest_hex,
                    args,
                    fatal_error=str(exc),
                )

            try:
                ping_resp = execute("PING", auto_unlock=False, notes=["post_unlock_probe"])
                if ping_resp.status != "OK":
                    raise RuntimeError(f"PING returned {ping_resp.status} {ping_resp.code}")
            except Exception as exc:
                logging.exception("PING command failed: %s", exc)
                return finalize(
                    records,
                    metadata,
                    transcript,
                    out_dir,
                    banner,
                    hsm_id,
                    pubkey_b64,
                    signature_b64,
                    digest_hex,
                    args,
                    fatal_error=str(exc),
                )

            try:
                resp = execute("HSMID")
                if resp.status == "OK" and resp.payload:
                    hsm_id = resp.payload[0]
                    (out_dir / "hsm_hsmid.txt").write_text(hsm_id + "\n", encoding="utf-8")
            except Exception as exc:
                logging.exception("HSMID command failed: %s", exc)
                return finalize(
                    records,
                    metadata,
                    transcript,
                    out_dir,
                    banner,
                    hsm_id,
                    pubkey_b64,
                    signature_b64,
                    digest_hex,
                    args,
                    fatal_error=str(exc),
                )

            try:
                resp = execute("KEYGEN EC P256", timeout=args.long_timeout)
                if resp.status != "OK":
                    raise RuntimeError(f"KEYGEN returned {resp.status} {resp.code}")
                code_upper = resp.code.upper()
                if code_upper == "KEYEXISTS":
                    logging.info("Device reports existing key material; continuing with benchmark")
                elif code_upper != "KEYGEN":
                    logging.info("KEYGEN reported %s", resp.code)
            except Exception as exc:
                logging.exception("KEYGEN failed: %s", exc)
                return finalize(
                    records,
                    metadata,
                    transcript,
                    out_dir,
                    banner,
                    hsm_id,
                    pubkey_b64,
                    signature_b64,
                    digest_hex,
                    args,
                    fatal_error=str(exc),
                )

            try:
                resp = execute("PUBKEY")
                if resp.status != "OK" or not resp.payload:
                    raise RuntimeError(f"PUBKEY returned {resp.status} {resp.code}")
                pubkey_b64 = resp.payload[0]
                (out_dir / "hsm_pubkey.b64").write_text(pubkey_b64 + "\n", encoding="utf-8")
            except Exception as exc:
                logging.exception("PUBKEY failed: %s", exc)
                return finalize(
                    records,
                    metadata,
                    transcript,
                    out_dir,
                    banner,
                    hsm_id,
                    pubkey_b64,
                    signature_b64,
                    digest_hex,
                    args,
                    fatal_error=str(exc),
                )

            sign_cmd = f"SIGN SHA256 {digest_hex}"
            try:
                resp = execute(sign_cmd, timeout=args.long_timeout)
                if resp.status != "OK" or not resp.payload:
                    raise RuntimeError(f"SIGN returned {resp.status} {resp.code}")
                signature_b64 = resp.payload[0]
                (out_dir / "hsm_signature.b64").write_text(signature_b64 + "\n", encoding="utf-8")
            except Exception as exc:
                logging.exception("SIGN failed: %s", exc)
                return finalize(
                    records,
                    metadata,
                    transcript,
                    out_dir,
                    banner,
                    hsm_id,
                    pubkey_b64,
                    signature_b64,
                    digest_hex,
                    args,
                    fatal_error=str(exc),
                )

            if args.logout_between_runs:
                try:
                    execute("LOGOUT", auto_unlock=False)
                except Exception as exc:
                    logging.warning("LOGOUT failed: %s", exc)

    verify_result: Optional[bool] = None
    verify_note: Optional[str] = None
    if pubkey_b64 and signature_b64:
        verify_result, verify_note = verify_signature(pubkey_b64, signature_b64, message_bytes)
        if verify_result is not None:
            metadata["signature_verified"] = verify_result
        if verify_note:
            metadata["signature_verify_note"] = verify_note

    return finalize(
        records,
        metadata,
        transcript,
        out_dir,
        banner,
        hsm_id,
        pubkey_b64,
        signature_b64,
        digest_hex,
        args,
    )


def finalize(
    records: List[CommandRecord],
    metadata: Dict[str, object],
    transcript: SerialTranscript,
    out_dir: Path,
    banner: Optional[str],
    hsm_id: Optional[str],
    pubkey_b64: Optional[str],
    signature_b64: Optional[str],
    digest_hex: str,
    args: argparse.Namespace,
    *,
    fatal_error: Optional[str] = None,
) -> int:
    metadata = dict(metadata)
    metadata["banner"] = banner
    metadata["hsm_id"] = hsm_id
    metadata["pubkey_available"] = pubkey_b64 is not None
    metadata["signature_available"] = signature_b64 is not None
    metadata["digest_hex"] = digest_hex
    if fatal_error:
        metadata["fatal_error"] = fatal_error

    csv_path = Path(args.csv_path) if args.csv else None
    summary_path = Path(args.json_path) if args.json else None
    text_path = Path(args.text_path) if args.text else None

    build_report(records, summary_path, csv_path, text_path, metadata)
    transcript_path = out_dir / "serial_transcript.log"
    transcript.dump(transcript_path)

    if fatal_error:
        logging.error("Benchmark terminated due to: %s", fatal_error)
        return 1
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark the STM32U5 HSM firmware over USB CDC-ACM")
    parser.add_argument("--port", default=_DEFAULT_PORT, help="Serial port (default: %(default)s)")
    parser.add_argument("--baud", type=int, default=_DEFAULT_BAUD, help="Baud rate (default: %(default)s)")
    parser.add_argument("--pin", default=_DEFAULT_PIN, help="Unlock PIN (default: %(default)s)")
    parser.add_argument("--runs", type=int, default=1, help="Number of benchmark iterations (default: %(default)s)")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT, help="Output directory for artefacts")
    parser.add_argument("--message", type=Path, default=_DEFAULT_MESSAGE, help="File used to derive the SHA-256 digest (default: %(default)s)")
    parser.add_argument("--command-timeout", type=float, default=5.0, help="Timeout in seconds for standard commands")
    parser.add_argument("--long-timeout", type=float, default=30.0, help="Timeout in seconds for long operations (unlock/keygen/sign)")
    parser.add_argument("--lockout-wait", type=float, default=35.0, help="Seconds to wait after LOCKED responses before retrying unlock")
    parser.add_argument("--unlock-attempts", type=int, default=5, help="Maximum unlock attempts before aborting")
    parser.add_argument("--locked-retries", type=int, default=2, help="Automatic retries for a command after re-unlocking when LOCKED is returned (default: %(default)s)")
    parser.add_argument("--handshake-timeout", type=float, default=6.0, help="Seconds to harvest READY banners after opening the port")
    parser.add_argument("--serial-read-timeout", type=float, default=0.5, help="Readline timeout when waiting for data")
    parser.add_argument("--logout-between-runs", action="store_true", help="Issue LOGOUT between runs to measure cold unlock performance")
    parser.add_argument("--repeat-info", action="store_true", help="Request INFO on every run instead of just the first")
    parser.add_argument(
        "--csv",
        dest="csv",
        action="store_true",
        default=True,
        help="Write per-command metrics CSV (default: enabled)",
    )
    parser.add_argument(
        "--no-csv",
        dest="csv",
        action="store_false",
        help="Disable CSV output",
    )
    parser.add_argument(
        "--json",
        dest="json",
        action="store_true",
        default=True,
        help="Write JSON summary report (default: enabled)",
    )
    parser.add_argument(
        "--no-json",
        dest="json",
        action="store_false",
        help="Disable JSON summary output",
    )
    parser.add_argument(
        "--text",
        dest="text",
        action="store_true",
        default=True,
        help="Write human-readable text report (default: enabled)",
    )
    parser.add_argument(
        "--no-text",
        dest="text",
        action="store_false",
        help="Disable text report output",
    )
    parser.add_argument("--csv-path", type=Path, default=_DEFAULT_OUT / "benchmark_metrics.csv", help="Path to the CSV output file")
    parser.add_argument("--json-path", type=Path, default=_DEFAULT_OUT / "benchmark_summary.json", help="Path to the JSON summary file")
    parser.add_argument("--text-path", type=Path, default=_DEFAULT_OUT / "benchmark_report.txt", help="Path to the human-readable report")
    parser.add_argument("--log-level", default="INFO", help="Python logging level (default: %(default)s)")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        return run_sequence(args)
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        return 1


if __name__ == "__main__":
    sys.exit(main())
