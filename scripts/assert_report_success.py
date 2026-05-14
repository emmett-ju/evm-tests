#!/usr/bin/env python3
"""Exit non-zero when an evm-rpc-tests report contains failed cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assert that every result in an evm-rpc-tests report succeeded.")
    parser.add_argument("report", help="Path to the JSON report written by adapter.cli run.")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    payload = json.loads(report_path.read_text())

    # If it's a summary file, check all reports within it
    if "reports" in payload and isinstance(payload["reports"], list):
        all_passed = True
        for sub_report_path_str in payload["reports"]:
            sub_report_path = Path(sub_report_path_str)
            if not sub_report_path.exists():
                print(f"warning: report {sub_report_path} listed in summary does not exist")
                all_passed = False
                continue
            
            sub_payload = json.loads(sub_report_path.read_text())
            results = sub_payload.get("results")
            if not isinstance(results, list):
                print(f"report {sub_report_path} missing list field 'results'")
                all_passed = False
                continue

            failed = [result for result in results if not _is_success(result)]
            if failed:
                print(f"report failed: {sub_report_path} ({len(failed)} failed / {len(results)} total)")
                all_passed = False
            else:
                print(f"report ok: {sub_report_path} ({len(results)} passed)")

        return 0 if all_passed else 1

    results = payload.get("results")
    if not isinstance(results, list):
        raise SystemExit(f"report {report_path} missing list field 'results'")

    failed = [result for result in results if not _is_success(result)]
    if not failed:
        print(f"report ok: {report_path} ({len(results)} passed)")
        return 0

    failed_ids = [str(result.get("case_id", "<unknown>")) for result in failed if isinstance(result, dict)]
    print(f"report failed: {report_path} ({len(failed)} failed / {len(results)} total)")
    for case_id in failed_ids[:20]:
        print(f"- {case_id}")
    if len(failed_ids) > 20:
        print(f"- ... {len(failed_ids) - 20} more")
    return 1


def _is_success(result: Any) -> bool:
    return isinstance(result, dict) and result.get("success") is True


if __name__ == "__main__":
    raise SystemExit(main())
