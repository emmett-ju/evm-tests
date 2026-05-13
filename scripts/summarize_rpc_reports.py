#!/usr/bin/env python3
"""Summarize one or more evm-rpc-tests JSON reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from adapter.inventory import summarize_inventory_dir


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize evm-rpc-tests report JSON files.")
    parser.add_argument("--report-dir", help="Directory containing per-family JSON reports.")
    parser.add_argument(
        "--report",
        action="append",
        default=[],
        help="Specific report file to include. May be passed more than once.",
    )
    parser.add_argument("--inventory-dir", default="suites/templates", help="Inventory directory for coverage reference.")
    parser.add_argument("--output", required=True, help="Summary JSON output path.")
    args = parser.parse_args(argv)

    report_paths = discover_report_paths(report_dir=args.report_dir, reports=args.report)
    families = [summarize_report(path) for path in report_paths]
    totals = {
        "families": len(families),
        "selected": sum(item["selected"] for item in families),
        "passed": sum(item["passed"] for item in families),
        "failed": sum(item["failed"] for item in families),
    }
    inventory_summary = summarize_inventory_dir(args.inventory_dir)
    payload = {
        "report_dir": None if args.report_dir is None else str(Path(args.report_dir)),
        "reports": [str(path) for path in report_paths],
        "families": families,
        "totals": totals,
        "coverage_reference": inventory_summary["totals"],
        "coverage_alignment": {
            "selected_equals_admitted": totals["selected"] == inventory_summary["totals"]["admitted"],
            "failed_zero": totals["failed"] == 0,
        },
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if totals["failed"] == 0 else 1


def discover_report_paths(*, report_dir: str | None, reports: Iterable[str]) -> list[Path]:
    paths = [Path(report) for report in reports]
    if report_dir is not None:
        root = Path(report_dir)
        paths.extend(
            path
            for path in sorted(root.glob("*.json"))
            if path.name != "summary.json"
        )
    unique: dict[Path, None] = {}
    for path in paths:
        resolved = path.resolve()
        if not resolved.exists():
            raise SystemExit(f"report not found: {path}")
        unique[resolved] = None
    if not unique:
        raise SystemExit("no report files supplied")
    return list(unique)


def summarize_report(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    results = payload.get("results")
    if not isinstance(results, list):
        raise SystemExit(f"report {path} missing list field 'results'")
    failed_cases = [case_id for case_id, success in result_statuses(results) if not success]
    passed = len(results) - len(failed_cases)
    return {
        "manifest": _string_field(payload, "manifest", default=path.stem),
        "chain_profile": _string_field(payload, "chain_profile", default="<unknown>"),
        "report": str(path),
        "selected": len(results),
        "passed": passed,
        "failed": len(failed_cases),
        "failed_cases": failed_cases,
    }


def result_statuses(results: Iterable[Any]) -> list[tuple[str, bool]]:
    statuses: list[tuple[str, bool]] = []
    for index, result in enumerate(results):
        if not isinstance(result, Mapping):
            statuses.append((f"<malformed-result-{index}>", False))
            continue
        case_id = result.get("case_id")
        statuses.append((str(case_id) if isinstance(case_id, str) and case_id else f"<unknown-{index}>", result.get("success") is True))
    return statuses


def _string_field(payload: Mapping[str, Any], field: str, *, default: str) -> str:
    value = payload.get(field)
    return value if isinstance(value, str) and value else default


if __name__ == "__main__":
    raise SystemExit(main())
