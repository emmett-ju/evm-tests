from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from adapter.models import Report


def write_report(report: Report, path: str | Path) -> None:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(asdict(report), indent=2, sort_keys=True))

