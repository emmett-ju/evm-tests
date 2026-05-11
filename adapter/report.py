from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from adapter.models import Report
from adapter.signer import keccak256

LARGE_RECEIPT_LOG_INLINE_BYTES = 256
DURABLE_EVIDENCE_MANIFESTS = frozenset(
    {
        "upstream-block-context-mapped",
        "upstream-log-mapped",
        "upstream-system-mapped",
    }
)


def _sanitize_path_component(value: str, *, field_name: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError(f"{field_name} must be a non-empty path component")
    sanitized = candidate.replace("\\", "/")
    parts = [part for part in sanitized.split("/") if part and part not in {".", ".."}]
    if not parts:
        raise ValueError(f"{field_name} must not contain path traversal segments")
    return "-".join(parts)


def write_report(report: Report, path: str | Path) -> list[Path]:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _compact_large_receipt_log_payloads(asdict(report))
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    written_paths = [report_path]
    durable_path = durable_report_path(report, report_path)
    if durable_path is not None:
        durable_path.parent.mkdir(parents=True, exist_ok=True)
        durable_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        written_paths.append(durable_path)
    return written_paths


def durable_report_path(report: Report, report_path: str | Path) -> Path | None:
    if report.manifest not in DURABLE_EVIDENCE_MANIFESTS:
        return None
    source_path = Path(report_path)
    stem = source_path.stem or "report"
    chain_profile = _sanitize_path_component(report.chain_profile, field_name="chain_profile")
    manifest = _sanitize_path_component(report.manifest, field_name="manifest")
    return source_path.parent / "evidence" / chain_profile / manifest / f"{stem}.json"


def _compact_large_receipt_log_payloads(node: Any) -> Any:
    if isinstance(node, list):
        return [_compact_large_receipt_log_payloads(item) for item in node]
    if not isinstance(node, dict):
        return node
    compacted = {key: _compact_large_receipt_log_payloads(value) for key, value in node.items()}
    receipt_logs = compacted.get("receipt_logs")
    if isinstance(receipt_logs, list):
        compacted["receipt_logs"] = [_compact_receipt_log_entry(entry) for entry in receipt_logs]
    return compacted


def _compact_receipt_log_entry(entry: Any) -> Any:
    if not isinstance(entry, dict):
        return entry
    compacted = dict(entry)
    data = compacted.get("data")
    if not isinstance(data, str) or not data.startswith("0x"):
        return compacted
    normalized = data[2:]
    if len(normalized) % 2 != 0:
        return compacted
    data_length_bytes = len(normalized) // 2
    if data_length_bytes <= LARGE_RECEIPT_LOG_INLINE_BYTES:
        return compacted
    compacted.pop("data", None)
    compacted["data_length_bytes"] = data_length_bytes
    compacted["data_digest"] = "0x" + keccak256(bytes.fromhex(normalized)).hex()
    compacted["data_elided"] = True
    return compacted

