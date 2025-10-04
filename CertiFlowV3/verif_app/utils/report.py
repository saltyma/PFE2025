# Handles exporting verification results as JSON (and optional PDF).
# verif_app/utils/report.py

"""
Report export helpers (Verifier)
--------------------------------
- Exports a JSON report for a verification result
- Optional plain-text summary writer (handy for email/paste)
- File naming defaults to <original>.verify.json next to the PDF

Usage:
    from utils import report
    path = report.export_json(result_dict, trust_snapshot=trust, out_path=None)
"""

from __future__ import annotations
from typing import Dict, Any, Optional
from pathlib import Path
import json
from datetime import datetime

def _default_json_path(pdf_path: str) -> Path:
    p = Path(pdf_path)
    return p.with_suffix(p.suffix + ".verify.json")  # e.g., file.pdf.verify.json

def _default_txt_path(pdf_path: str) -> Path:
    p = Path(pdf_path)
    return p.with_suffix(p.suffix + ".verify.txt")

def _safe_copy(d: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return dict(d) if isinstance(d, dict) else {}

def _prune_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}

def export_json(
    result: Dict[str, Any],
    *,
    trust_snapshot: Optional[Dict[str, Any]] = None,
    out_path: Optional[str | Path] = None,
    pretty: bool = True
) -> str:
    """
    Save a verification report as JSON.
    - result: dict returned by utils.verification.verify_pdf_signature()
    - trust_snapshot: latest snapshot from trust_manager.get_current_trust()
    - out_path: optional, file path to write (defaults to <pdf>.verify.json)
    - pretty: pretty-print the JSON

    Returns: written path as string
    """
    if not isinstance(result, dict):
        raise ValueError("result must be a dict")

    # Base envelope
    report_obj = {
        "report_type": "certiflow_verification_report",
        "schema_version": "1.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "result": _prune_none(_safe_copy(result)),
        "trust": _prune_none(_safe_copy(trust_snapshot)),
    }

    # Default path derives from original file path in result
    if out_path is None:
        pdf_path = result.get("file") or "document.pdf"
        out_path = _default_json_path(pdf_path)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(report_obj, f, indent=2, ensure_ascii=False)
        else:
            json.dump(report_obj, f, separators=(",", ":"), ensure_ascii=False)

    return str(out_path)

def export_text_summary(
    result: Dict[str, Any],
    *,
    trust_snapshot: Optional[Dict[str, Any]] = None,
    out_path: Optional[str | Path] = None
) -> str:
    """
    Save a short human-readable summary (plain text).
    Returns: written path as string
    """
    if out_path is None:
        pdf_path = result.get("file") or "document.pdf"
        out_path = _default_txt_path(pdf_path)

    r = _safe_copy(result)
    t = _safe_copy(trust_snapshot)

    lines = [
        "=== CertiFlow Verification Summary ===",
        f"File:            {r.get('file','')}",
        f"File SHA-256:    {r.get('file_sha256','')}",
        f"Signer Email:    {r.get('signer_email','')}",
        f"Signer CN:       {r.get('signer_cn','')}",
        f"Cert Serial:     {r.get('cert_serial','')}",
        f"CA CN:           {r.get('ca_cn','')}",
        f"Result:          {r.get('result','')}",
        f"Reason:          {r.get('reason','')}",
        f"PDF Sig Time:    {r.get('pdf_sig_timestamp_utc','')}",
        f"Verified At UTC: {r.get('verified_at_utc','')}",
        "",
        "--- Trust Snapshot ---",
        f"CRL Version:     {t.get('crl_version','')}",
        f"CRL Issued UTC:  {t.get('crl_issued_at_utc','')}",
        f"Snapshot Time:   {t.get('last_sync_utc','')}",
    ]
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return str(out_path)
