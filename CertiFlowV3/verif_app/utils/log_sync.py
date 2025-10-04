"""Utilities for synchronizing verifier logs with the CA owner database."""

from __future__ import annotations

import json
from typing import List, Tuple

import requests

from config import CA_API_URL, LOG_SYNC_EMAIL
from ver_db_helper import list_logs, delete_logs_by_ids

REQUEST_TIMEOUT = 10  # seconds


def _parse_details(raw):
    if raw in (None, ""):
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return {"message": raw}
    return {"message": str(raw)}


def _collect_logs(source: str = "verifier_app") -> Tuple[List[dict], List[int]]:
    rows = list_logs(limit=500)
    if not rows:
        return [], []

    entries: List[dict] = []
    ids: List[int] = []

    for row in reversed(rows):
        log_id = row.get("id")
        action = row.get("action")
        timestamp = row.get("timestamp")
        if not action or not timestamp:
            continue

        details = _parse_details(row.get("details"))
        if not isinstance(details, dict):
            details = {"message": str(details)}

        details = {
            **details,
            "source": details.get("source") or source,
            "local_log_id": log_id,
        }

        entries.append({
            "action": action,
            "timestamp": timestamp,
            "details": details,
        })

        if isinstance(log_id, int):
            ids.append(log_id)

    return entries, ids


def sync_with_ca(email: str | None = None, *, source: str = "verifier_app") -> Tuple[bool, str]:
    target_email = (email or LOG_SYNC_EMAIL or "").strip()
    if not target_email:
        return False, "Log sync email is not configured."

    payload, ids = _collect_logs(source=source)
    if not payload:
        return True, "No pending logs to sync."

    url = f"{CA_API_URL}/logs/sync"
    try:
        response = requests.post(url, json={"email": target_email, "logs": payload}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        return False, "Connection timed out while syncing logs."
    except requests.exceptions.ConnectionError:
        return False, "Unable to reach the CA server for log synchronization."
    except requests.exceptions.HTTPError as exc:
        try:
            data = exc.response.json()
            message = data.get("error", {}).get("message") or data.get("message") or str(exc)
        except Exception:
            message = str(exc)
        return False, f"Log sync rejected by CA: {message}"
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Unexpected log sync error: {exc}"

    if data.get("ok") is not False:
        delete_logs_by_ids(ids)
        return True, data.get("message", "Logs synchronized with CA.")

    error = data.get("error", {})
    message = error.get("message") or "Log sync rejected by CA."
    return False, message
