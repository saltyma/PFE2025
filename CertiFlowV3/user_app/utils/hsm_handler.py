# user_app/utils/hsm_handler.py
# CertiFlow V3 — COM-based HSM client (aligned with CA-side probe)
#
# Detection now mirrors ca_app.handlers.hsm_management_handler._probe_port_for_hsmid:
#   - Drain input
#   - Send HSMID
#   - Parse "OK HSMID" with payload or plain payload fallback
#   - DTR/RTS toggled; short read/write timeouts
#
# Extras:
#   --scan lists all detected HSMs (port + id)
#   --debug prints raw lines seen during probe for each port
#   --port / --id test like before
#
from __future__ import annotations
import argparse
import base64
import binascii
import logging
import os
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple, Any, Callable

try:
    import serial  # pyserial
    from serial.tools import list_ports
except Exception:  # pragma: no cover
    serial = None  # type: ignore
    list_ports = None  # type: ignore

BAUDRATE = 115200
READ_TIMEOUT = 0.80          # general command tolerance
# Hardware boards run PBKDF2 over tens of thousands of iterations and may then
# persist refreshed keystore data. Give them a very generous budget so the UI
# does not spuriously fail while flash is being erased/written.
UNLOCK_READ_TIMEOUT = 8.00
WRITE_TIMEOUT = 0.80
# Probing should be snappy so UI cancellations return quickly
PROBE_READ_TIMEOUT = 0.35
PROBE_WRITE_TIMEOUT = 0.35
EOL = b"\r\n"

@dataclass
class HSMReply:
    ok: bool
    head: str
    payload: Optional[str] = None
    raw: Optional[str] = None

def _candidate_ports() -> List[str]:
    env = os.environ.get("CERTIFLOW_SERIAL_PORTS")
    if env:
        return [p.strip() for p in env.replace(",", ";").split(";") if p.strip()]
    if list_ports is None:
        return []
    # Include every visible device; we filter by protocol
    return [getattr(p, "device", None) or str(p) for p in list_ports.comports()]

logger = logging.getLogger(__name__)


class HSMClient:
    def __init__(self, *, debug: bool = False):
        self.ser: Optional[Any] = None
        self.port: Optional[str] = None
        self._last_unlock_ts: float = 0.0
        self._pin_cached: Optional[str] = None
        self.debug = debug

    @staticmethod
    def list_ports() -> List[str]:
        return _candidate_ports()

    # ------------------ CA-like probe ------------------

    def _probe_port_hsmid(
        self,
        port: str,
        *,
        stop_flag: Optional[Callable[[], bool]] = None,
        per_port_timeout: Optional[float] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Probe like CA app: HSMID-first, tolerate noise, parse payload forgivingly.

        stop_flag allows callers (scan workers) to cooperatively abort while the
        serial port is being probed. Each blocking operation checks the flag so
        UI threads can request cancellation and the worker will exit quickly.
        """

        def _should_stop() -> bool:
            return bool(stop_flag and stop_flag())

        if _should_stop():
            return None, None
        if serial is None:
            return None, "pyserial not installed."
        try:
            timeout = max(0.1, per_port_timeout or PROBE_READ_TIMEOUT)
            with serial.Serial(
                port=port,
                baudrate=BAUDRATE,
                timeout=timeout,
                write_timeout=max(0.1, per_port_timeout or PROBE_WRITE_TIMEOUT),
                dsrdtr=False,
            ) as ser:
                # Similar toggles as CA
                try:
                    ser.dtr = True
                    ser.rts = True
                except Exception:
                    pass

                # Drain any greeting/noise
                time.sleep(0.05)
                if _should_stop():
                    return None, None
                try:
                    pending = getattr(ser, "in_waiting", 0)
                except Exception:
                    pending = 0
                if pending:
                    try:
                        junk = ser.read(pending)
                        if self.debug and junk:
                            print(f"[{port}] drained {len(junk)} byte(s)")
                    except Exception:
                        pass

                # Send HSMID
                if _should_stop():
                    return None, None
                try:
                    ser.write(b"HSMID\r\n")
                    ser.flush()
                except Exception as e:
                    return None, f"write failed: {e}"

                def _readline() -> str:
                    if _should_stop():
                        return ""
                    try:
                        line = ser.readline().decode(errors="ignore").strip()
                        if self.debug:
                            if line:
                                print(f"[{port}] << {line!r}")
                        return line
                    except Exception:
                        return ""

                # Try several lines; CA code tolerates extra noise
                line1 = _readline()
                if not line1:
                    time.sleep(0.05)
                    if _should_stop():
                        return None, None
                    line1 = _readline()

                up = line1.upper() if line1 else ""

                # Fast path: OK HSMID on head, payload next
                if up.startswith("OK"):
                    parts = line1.split()
                    if len(parts) >= 2 and parts[1].upper() == "HSMID":
                        line2 = _readline()
                        if line2 and len(line2) >= 4:
                            return line2, None
                        # Some implementations may stuff it into the header
                        if len(parts) >= 3 and len(parts[2]) >= 4:
                            return parts[2], None
                    # OK <something> + separate payload
                    if len(parts) >= 2 and len(parts[1]) >= 4:
                        return parts[1], None
                    line2 = _readline()
                    if line2 and len(line2) >= 4:
                        return line2, None

                # Fallback: non-ERR line with plausible ID
                if line1 and len(line1) >= 4 and not up.startswith(("ERR", "BAD")):
                    return line1, None

                return None, "no HSMID parsed"
        except PermissionError:
            # Other process has the port; not necessarily fatal for overall scan
            return None, "in use"
        except OSError:
            return None, "open failed"
        except Exception as e:
            return None, f"probe error: {e}"

    def scan_and_detect(
        self, *, stop_flag: Optional[Callable[[], bool]] = None
    ) -> List[Tuple[str, str]]:
        found: List[Tuple[str, str]] = []
        for p in self.list_ports():
            if stop_flag and stop_flag():
                break
            hid, err = self._probe_port_hsmid(p, stop_flag=stop_flag)
            if self.debug and err:
                print(f"[{p}] probe: {err}")
            if hid and not err:
                found.append((p, hid))
        return found

    def connect_first(
        self,
        expected_hsm_id: Optional[str] = None,
        *,
        stop_flag: Optional[Callable[[], bool]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        matches = self.scan_and_detect(stop_flag=stop_flag)
        if expected_hsm_id:
            matches = [(p, hid) for (p, hid) in matches if hid == expected_hsm_id]
        if not matches:
            return None, "No matching HSM found on available COM ports."
        port, hid = matches[0]
        try:
            self.ser = serial.Serial(port, BAUDRATE, timeout=READ_TIMEOUT, write_timeout=WRITE_TIMEOUT)  # type: ignore[union-attr]
            try:
                self.ser.dtr = True
                self.ser.rts = True
            except Exception:
                pass
            # Drain any stale greeting so first command reads its own reply.
            try:
                self._drain_pending(self.ser)
            except Exception:
                pass
            self.port = port
            return hid, None
        except Exception as e:
            self.ser = None
            self.port = None
            return None, f"Failed to open {port}: {e}"

    def connect_to_port(self, port: str) -> Tuple[Optional[str], Optional[str]]:
        """Explicitly open a specific port and verify by asking HSMID once connected."""
        if serial is None:
            return None, "pyserial not installed."
        try:
            s = serial.Serial(port, BAUDRATE, timeout=READ_TIMEOUT, write_timeout=WRITE_TIMEOUT)  # type: ignore[union-attr]
            try:
                s.dtr = True
                s.rts = True
            except Exception:
                pass
        except Exception as e:
            return None, f"Failed to open {port}: {e}"
        try:
            # Drain any line left in buffer
            time.sleep(0.05)
            try:
                pending = getattr(s, "in_waiting", 0)
                if pending:
                    s.read(pending)
            except Exception:
                pass

            s.write(b"HSMID\r\n")
            s.flush()

            head = s.readline().decode(errors="ignore").strip()
            # If head is OK HSMID then read payload, else accept plausible non-ERR head
            hid = None
            if head.upper().startswith("OK HSMID"):
                payload = s.readline().decode(errors="ignore").strip()
                hid = payload if payload else None
            elif head and not head.upper().startswith(("ERR", "BAD")) and len(head) >= 4:
                hid = head

            if not hid:
                s.close()
                return None, "No HSMID reply."

            self.ser = s
            self.port = port
            return hid, None
        except Exception as e:
            try:
                s.close()
            except Exception:
                pass
            return None, str(e)

    # ---------------- Basic I/O helpers ----------------

    def _ensure_open(self) -> None:
        if self.ser is None or not self.ser.is_open:
            raise RuntimeError("HSM not connected.")

    @staticmethod
    def _writeline(s: Any, line: str) -> None:
        s.write(line.encode("utf-8") + EOL)
        s.flush()

    @staticmethod
    def _drain_pending(s: Any) -> None:
        time.sleep(0.05)
        pending = 0
        try:
            pending = getattr(s, "in_waiting", 0)
        except Exception:
            pending = 0
        if pending:
            try:
                s.read(pending)
            except Exception:
                pass

    def _readline(self, s: Any, timeout: float = READ_TIMEOUT) -> Optional[str]:
        end = time.time() + timeout
        buf = bytearray()
        while time.time() < end:
            chunk = s.read(1)
            if not chunk:
                continue
            buf += chunk
            if buf.endswith(b"\r\n") or buf.endswith(b"\n") or buf.endswith(b"\r"):
                return buf.rstrip(b"\r\n").decode("utf-8", errors="ignore")
        return None

    def _read_reply(self, *, timeout: float = READ_TIMEOUT) -> HSMReply:
        if self.ser is None:
            return HSMReply(False, "NO_CONN", None, None)
        while True:
            head = self._readline(self.ser, timeout=timeout)
            if head is None:
                return HSMReply(False, "TIMEOUT", None, None)
            clean_head = head.strip()
            if not clean_head:
                continue
            upper_head = clean_head.upper()
            # Some firmware send a one-time "OK READY" banner after connect; skip it.
            if upper_head == "OK READY":
                continue
            break

        payload = None
        if upper_head.startswith("OK PUBKEY") or upper_head.startswith("OK SIG") or upper_head.startswith("OK HSMID"):
            # Some firmware stream the payload on the very next line but emit blank
            # keep-alives (or split the UART chunk) before the actual data arrives.
            # Tolerate up to a handful of empty reads so we do not bail out with a
            # "PUBKEY failed" error even though the command succeeded.
            for _ in range(4):
                next_line = self._readline(self.ser, timeout=timeout)
                if next_line is None:
                    break
                stripped = next_line.strip()
                if not stripped:
                    # Skip whitespace-only keep-alives.
                    continue
                payload = stripped
                break
        ok = upper_head == "OK" or upper_head.startswith("OK ")
        return HSMReply(ok=ok, head=head, payload=payload, raw=head + ("\n" + payload if payload else ""))

    # ---------------- Public API ----------------

    def close(self) -> None:
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None
        self.port = None

    def info(self) -> Tuple[Optional[str], Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, "INFO")  # type: ignore[arg-type]
            r = self._read_reply()
            return (r.head if r.ok else None, None if r.ok else f"INFO failed: {r.head}")
        except Exception as e:
            return None, str(e)

    def hsmid(self) -> Tuple[Optional[str], Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, "HSMID")  # type: ignore[arg-type]
            r = self._read_reply()
            if r.ok and r.payload:
                return r.payload.strip(), None
            if r.ok and r.head.upper().startswith("OK HSMID"):
                # sometimes emulator inlines the id
                parts = r.head.split()
                if len(parts) >= 3:
                    return parts[2], None
            return None, f"HSMID failed: {r.head}"
        except Exception as e:
            return None, str(e)

    def ping(self) -> Tuple[bool, Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, "PING")  # type: ignore[arg-type]
            r = self._read_reply()
            return (r.ok and r.head.startswith("OK PONG"), None if r.ok else f"PING failed: {r.head}")
        except Exception as e:
            return False, str(e)

    def unlock(self, pin: str) -> Tuple[str, Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, f"UNLOCK {pin}")  # type: ignore[arg-type]
            r = self._read_reply(timeout=UNLOCK_READ_TIMEOUT)
            if r.ok and ("NEWPIN" in r.head or "UNLOCKED" in r.head):
                self._pin_cached = pin
                self._last_unlock_ts = time.time()
                return ("NEWPIN" if "NEWPIN" in r.head else "UNLOCKED"), None
            if not r.ok and "LOCKED" in r.head:
                return "", "Device is locked due to bad PIN attempts. Please wait and try again."
            if not r.ok and "BADPIN" in r.head:
                return "", "Incorrect PIN."
            if not r.ok and "ARG" in r.head:
                return "", "PIN format invalid."
            return "", f"UNLOCK failed: {r.head}"
        except Exception as e:
            return "", str(e)

    def logout(self) -> Tuple[bool, Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, "LOGOUT")  # type: ignore[arg-type]
            r = self._read_reply()
            if r.ok:
                self._last_unlock_ts = 0.0
                return True, None
            return False, f"LOGOUT failed: {r.head}"
        except Exception as e:
            return False, str(e)

    def reset(self) -> Tuple[bool, Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, "RESET")  # type: ignore[arg-type]
            r = self._read_reply()
            if r.ok:
                self._last_unlock_ts = 0.0
                return True, None
            return False, f"RESET failed: {r.head}"
        except Exception as e:
            return False, str(e)

    def keygen_ec_p256(self) -> Tuple[str, Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, "KEYGEN EC P256")  # type: ignore[arg-type]
            r = self._read_reply()
            head = (r.head or "")
            head_upper = head.upper()
            if r.ok:
                if "KEYEXISTS" in head_upper:
                    return "KEYEXISTS", None
                if "KEYGEN" in head_upper:
                    return "KEYGEN", None
                # Some firmware revisions reply with a bare "OK". Treat it as idempotent success.
                return "KEYGEN", None
            if not r.ok and "LOCKED" in head_upper:
                # Attempt to re-unlock automatically if we know the PIN, then retry once.
                if self._pin_cached:
                    _, unlock_err = self.unlock(self._pin_cached)
                    if not unlock_err:
                        self._writeline(self.ser, "KEYGEN EC P256")  # type: ignore[arg-type]
                        r = self._read_reply()
                        head = (r.head or "")
                        head_upper = head.upper()
                        if r.ok:
                            if "KEYEXISTS" in head_upper:
                                return "KEYEXISTS", None
                            if "KEYGEN" in head_upper or not head_upper:
                                return "KEYGEN", None
                            return "KEYGEN", None
                return "", "Device is locked; unlock required or lockout active."
            if not r.ok and "ARG" in r.head:
                return "", "Bad KEYGEN arguments."
            return "", f"KEYGEN failed: {head}"
        except Exception as e:
            return "", str(e)

    def pubkey_spki_b64(self) -> Tuple[Optional[str], Optional[str]]:
        try:
            self._ensure_open()
            self._writeline(self.ser, "PUBKEY")  # type: ignore[arg-type]
            r = self._read_reply()
            if r.ok and r.payload:
                return r.payload.strip(), None
            if not r.ok and "LOCKED" in r.head:
                return None, "Device locked or session expired."
            if not r.ok and "NO_KEY" in r.head:
                return None, "No key present; run KEYGEN first."
            return None, f"PUBKEY failed: {r.head}"
        except Exception as e:
            return None, str(e)

    def sign_sha256_hex(self, hex_digest: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            self._ensure_open()
            logger.info(
                "HSM SIGN on %s: SIGN SHA256 %s",
                self.port or "<disconnected>",
                hex_digest,
            )
            self._writeline(self.ser, f"SIGN SHA256 {hex_digest}")  # type: ignore[arg-type]
            r = self._read_reply()
            if r.ok and r.payload:
                return r.payload.strip(), None
            if not r.ok and "LOCKED" in r.head:
                return None, "Device locked or session expired."
            if not r.ok and "NO_KEY" in r.head:
                return None, "No key present; run KEYGEN first."
            if not r.ok and "ARG" in r.head:
                return None, "Invalid digest argument (need 64 hex chars)."
            return None, f"SIGN failed: {r.head}"
        except Exception as e:
            return None, str(e)

    def sign_sha256_bytes(self, digest: bytes) -> bytes:
        """
        Helper wrapper that returns raw DER ECDSA bytes for a SHA-256 digest.
        Preserves the existing tuple API on sign_sha256_hex for legacy callers.
        """

        if not digest or len(digest) != 32:
            raise ValueError("Invalid digest length for SHA-256.")

        hex_digest = digest.hex()
        sig_b64, err = self.sign_sha256_hex(hex_digest)
        if err:
            raise ValueError(err)
        if not sig_b64:
            raise ValueError("Empty signature payload from HSM.")

        cleaned = "".join(sig_b64.split())
        try:
            sig_bytes = base64.b64decode(cleaned, validate=True)
        except binascii.Error as e:
            raise ValueError(f"Invalid base64 signature from HSM: {e}") from e

        if not sig_bytes:
            raise ValueError("Decoded signature from HSM is empty.")

        return sig_bytes

    def detect_and_connect(
        self,
        expected_hsm_id: Optional[str] = None,
        *,
        stop_flag: Optional[Callable[[], bool]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        if self.ser and self.ser.is_open:
            hid, err = self.hsmid()
            return hid, err
        return self.connect_first(expected_hsm_id, stop_flag=stop_flag)

    def __enter__(self) -> "HSMClient":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

# --------------- Helpers / CLI ---------------

def scan_ports(
    debug: bool = False,
    *,
    stop_flag: Optional[Callable[[], bool]] = None,
) -> List[Tuple[str, Optional[str]]]:
    out: List[Tuple[str, Optional[str]]] = []
    c = HSMClient(debug=debug)
    for p in c.list_ports():
        if stop_flag and stop_flag():
            break
        hid, err = c._probe_port_hsmid(p, stop_flag=stop_flag)
        out.append((p, hid if not err else None))
    return out

def smoke_test(expected_hsm_id: Optional[str] = None, pin: str = "1234",
               port: Optional[str] = None, debug: bool = False) -> Tuple[bool, str]:
    rep: List[str] = []
    try:
        with HSMClient(debug=debug) as c:
            if port:
                hid, err = c.connect_to_port(port)
            else:
                hid, err = c.detect_and_connect(expected_hsm_id=expected_hsm_id)
            if err or not hid:
                return False, f"Detect/connect failed: {err or 'no HSM'}"
            rep.append(f"HSMID: {hid} @ {c.port}")

            info, err = c.info()
            rep.append(f"INFO: {info or err}")
            pong, err = c.ping()
            rep.append(f"PING: {'OK' if pong else 'FAIL'}{(' (' + err + ')') if err else ''}")

            mode, err = c.unlock(pin)
            if err:
                return False, f"UNLOCK failed: {err}"
            rep.append(f"UNLOCK: {mode}")

            mode, err = c.keygen_ec_p256()
            if err:
                return False, f"KEYGEN failed: {err}"
            rep.append(f"KEYGEN: {mode}")

            spki_b64, err = c.pubkey_spki_b64()
            if err or not spki_b64:
                return False, f"PUBKEY failed: {err or 'no key'}"
            rep.append(f"PUBKEY: {len(spki_b64)} base64 chars")

            # sha256("hello")
            hello_hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            sig_b64, err = c.sign_sha256_hex(hello_hex)
            if err or not sig_b64:
                return False, f"SIGN failed: {err or 'no signature'}"
            rep.append(f"SIGN: {len(sig_b64)} base64 chars")

            ok, err = c.logout()
            rep.append(f"LOGOUT: {'OK' if ok else 'FAIL'}{(' (' + err + ')') if err else ''}")

        return True, "\n".join(rep)
    except Exception as e:
        return False, f"Smoke test error: {e}"

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HSM client smoke test")
    ap.add_argument("--scan", action="store_true", help="List detected devices (port + HSMID)")
    ap.add_argument("--id", dest="hsm_id", help="Expected HSMID to match", default=None)
    ap.add_argument("--port", dest="port", help="Explicit port to open", default=None)
    ap.add_argument("--pin", dest="pin", help="PIN to use/provision", default="1234")
    ap.add_argument("--debug", action="store_true", help="Print raw probe lines per port")
    args = ap.parse_args()

    if args.scan:
        lst = scan_ports(debug=args.debug)
        print("Detected ports:")
        for p, hid in lst:
            print(f"  {p}: {'HSMID=' + hid if hid else 'not HSM'}")
        raise SystemExit(0)

    ok, report = smoke_test(expected_hsm_id=args.hsm_id, pin=args.pin, port=args.port, debug=args.debug)
    print(report)
    raise SystemExit(0 if ok else 2)
