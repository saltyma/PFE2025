#!/usr/bin/env python3
"""Stability and light fault-injection soak test for the STM32U5 HSM."""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent))
    from hsm_board_tester import (  # type: ignore
        SerialHSMClient,
        _sha256_digest,
        interpret_keygen_response,
        interpret_unlock_response,
    )
else:
    from .hsm_board_tester import (
        SerialHSMClient,
        _sha256_digest,
        interpret_keygen_response,
        interpret_unlock_response,
    )

DEFAULT_DURATION = 2 * 60 * 60  # 2 hours
DEFAULT_SAMPLE = Path("./fixtures/sample.pdf")


@dataclass
class SoakRecord:
    timestamp: float
    command: str
    duration_ms: float
    status: str
    payload: str


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HSM soak and stability sequence")
    parser.add_argument("--port", default="COM10", help="Serial port for the HSM (default: COM10)")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--pin", default="1234")
    parser.add_argument("--timeout", type=float, default=2.4)
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Duration in seconds")
    parser.add_argument("--out", type=Path, default=Path("./artifacts"))
    parser.add_argument("--csv", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    return parser.parse_args(argv)


def weighted_choice(choices: List[Tuple[str, float]]) -> str:
    total = sum(weight for _, weight in choices)
    r = random.uniform(0, total)
    upto = 0.0
    for name, weight in choices:
        if upto + weight >= r:
            return name
        upto += weight
    return choices[-1][0]


def run_soak(
    args: argparse.Namespace,
) -> Tuple[List[SoakRecord], Dict[str, List[float]], Dict[str, int], Dict[str, str]]:
    artifact_dir = args.out
    artifact_dir.mkdir(parents=True, exist_ok=True)

    digest_hex = _sha256_digest(args.sample).hex()

    operations = [
        ("INFO", 0.10),
        ("HSMID", 0.10),
        ("PUBKEY", 0.10),
        ("SIGN", 0.60),
        ("IDLE", 0.10),
    ]

    records: List[SoakRecord] = []
    rtts: Dict[str, List[float]] = defaultdict(list)
    counters = {"ok": 0, "err": 0, "timeouts": 0}
    frames: Deque[str] = deque(maxlen=50)

    client = SerialHSMClient(args.port, args.baud, args.timeout)
    handshake = {"initial_unlock": "", "initial_keygen": "", "last_unlock": "", "last_keygen": ""}
    start_time = time.perf_counter()
    next_report = start_time + 300.0
    next_reopen = start_time + 900.0
    random.seed(time.time())

    try:
        client.open()
        unlock_timeout = max(client.timeout * 2, 6.0)
        keygen_timeout = max(client.timeout * 3, 10.0)
        sign_timeout = max(client.timeout * 1.5, 5.0)

        unlock_resp = client.transact(
            f"UNLOCK {args.pin}",
            allow_additional=True,
            response_timeout=unlock_timeout,
            pre_delay=0.05,
            max_payload_lines=6,
        )
        unlock_status = interpret_unlock_response(unlock_resp)
        if not unlock_status.success:
            raise RuntimeError(f"Initial unlock failed: {unlock_status.detail}")
        keygen_resp = client.transact(
            "KEYGEN EC P256",
            allow_additional=True,
            response_timeout=keygen_timeout,
            pre_delay=0.05,
            max_payload_lines=6,
        )
        keygen_status = interpret_keygen_response(keygen_resp)
        if not keygen_status.success:
            raise RuntimeError(f"Initial key provisioning failed: {keygen_status.detail}")
        handshake["initial_unlock"] = unlock_status.detail
        handshake["initial_keygen"] = keygen_status.detail
        handshake["last_unlock"] = unlock_status.detail
        handshake["last_keygen"] = keygen_status.detail

        while time.perf_counter() - start_time < args.duration:
            now = time.perf_counter()
            if now >= next_reopen:
                client.close()
                time.sleep(0.5)
                client.open()
                reopen_unlock = client.transact(
                    f"UNLOCK {args.pin}",
                    allow_additional=True,
                    response_timeout=unlock_timeout,
                    pre_delay=0.05,
                    max_payload_lines=6,
                )
                reopen_status = interpret_unlock_response(reopen_unlock)
                if not reopen_status.success:
                    raise RuntimeError(f"Re-open unlock failed: {reopen_status.detail}")
                reopen_keygen = client.transact(
                    "KEYGEN EC P256",
                    allow_additional=True,
                    response_timeout=keygen_timeout,
                    pre_delay=0.05,
                    max_payload_lines=6,
                )
                reopen_key_status = interpret_keygen_response(reopen_keygen)
                if not reopen_key_status.success:
                    raise RuntimeError(f"Re-open key provisioning failed: {reopen_key_status.detail}")
                handshake["last_unlock"] = reopen_status.detail
                handshake["last_keygen"] = reopen_key_status.detail
                next_reopen = now + 900.0

            op = weighted_choice(operations)
            delay = random.uniform(0.05, 0.5)
            if op == "IDLE":
                time.sleep(delay)
                records.append(SoakRecord(time.time(), op, delay * 1000.0, "OK", ""))
                continue

            cmd = op if op != "SIGN" else f"SIGN SHA256 {digest_hex}"
            t0 = time.perf_counter()
            try:
                if op == "SIGN":
                    response = client.transact(
                        cmd,
                        expect_payload=True,
                        response_timeout=sign_timeout,
                        max_payload_lines=6,
                    )
                elif op in {"HSMID", "PUBKEY"}:
                    response = client.transact(
                        cmd,
                        expect_payload=True,
                        response_timeout=sign_timeout,
                        max_payload_lines=6,
                    )
                else:
                    response = client.transact(
                        cmd,
                        allow_additional=True,
                        response_timeout=sign_timeout,
                        max_payload_lines=6,
                    )
                duration_ms = (time.perf_counter() - t0) * 1000.0
            except Exception as err:  # serial timeout or fatal
                counters["timeouts"] += 1
                frames.append(f"{time.time():.0f} CMD {cmd} -> EXC {err}")
                records.append(SoakRecord(time.time(), op, (time.perf_counter() - t0) * 1000.0, "EXC", str(err)))
                if counters["timeouts"] >= 3:
                    raise
                continue

            payload_text = response.body if response.body is not None else response.head
            if op == "SIGN" and payload_text:
                payload_text = "".join(payload_text.split())
            frame_msg = f"{time.time():.0f} CMD {cmd} -> {response.status} {response.head}"
            if response.body:
                frame_msg += f" {response.body}"
            frames.append(frame_msg)
            records.append(SoakRecord(time.time(), op, duration_ms, response.status, payload_text))
            if response.status == "OK":
                counters["ok"] += 1
                rtts[op].append(duration_ms)
                if op == "SIGN" and payload_text:
                    # basic sanity: ensure payload resembles base64
                    if len(payload_text.strip()) < 10:
                        counters["err"] += 1
                time.sleep(delay)
            else:
                counters["err"] += 1
                if counters["err"] >= 5:
                    raise RuntimeError(f"Persistent ERR responses: last={payload_text}")

            if time.perf_counter() >= next_report:
                avg = {k: (sum(v) / len(v) if v else 0.0) for k, v in rtts.items()}
                print(
                    f"[SOAK] t={int(time.perf_counter() - start_time)}s ok={counters['ok']} err={counters['err']} timeouts={counters['timeouts']} avg_rtt_ms={avg}",
                    file=sys.stderr,
                )
                next_report += 300.0
    except Exception as exc:
        dump_path = artifact_dir / "soak_last_frames.log"
        with dump_path.open("w") as handle:
            for frame in frames:
                handle.write(frame + "\n")
        raise RuntimeError(f"Soak sequence aborted: {exc}. Frames saved to {dump_path}")
    finally:
        client.close()

    return records, rtts, counters, handshake


def write_outputs(
    args: argparse.Namespace,
    records: List[SoakRecord],
    rtts: Dict[str, List[float]],
    counters: Dict[str, int],
    handshake: Dict[str, str],
) -> None:
    if args.csv:
        csv_path = args.out / "hsm_soak.csv"
        with csv_path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["timestamp", "command", "duration_ms", "status", "payload"])
            for record in records:
                writer.writerow([record.timestamp, record.command, f"{record.duration_ms:.3f}", record.status, record.payload])

    if args.json:
        summary_path = args.out / "hsm_soak_summary.json"
        drift = {}
        for cmd, values in rtts.items():
            if not values:
                continue
            drift[cmd] = {
                "median": sorted(values)[len(values) // 2],
                "p95": sorted(values)[min(len(values) - 1, int(0.95 * len(values)))],
            }
        summary = {
            "total_records": len(records),
            "counters": counters,
            "latency_stats": drift,
            "notes": "No persistent failures" if counters["err"] == 0 else "Errors observed",
            "handshake": handshake,
        }
        with summary_path.open("w") as handle:
            json.dump(summary, handle, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if not args.sample.exists():
        raise FileNotFoundError(f"Sample payload missing: {args.sample}")

    try:
        records, rtts, counters, handshake = run_soak(args)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    write_outputs(args, records, rtts, counters, handshake)
    print(
        f"Soak complete: {len(records)} events, ok={counters['ok']} err={counters['err']} timeouts={counters['timeouts']}",
        file=sys.stderr,
    )
    return 0 if counters["err"] == 0 and counters["timeouts"] < 3 else 1


if __name__ == "__main__":
    sys.exit(main())
