from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


JsonDict = dict[str, Any]


def write_json(path: str | Path, payload: Mapping[str, Any]) -> JsonDict:
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    data = dict(payload)
    output.write_text(json.dumps(data, indent=2) + "\n")
    return data


def build_inventory_payload(
    *,
    family: str,
    name: str,
    source: str,
    entries: Iterable[object],
    version: str = "1",
) -> JsonDict:
    return {
        "name": name,
        "version": version,
        "family": family,
        "source": source,
        "entries": [_serialize_entry(entry) for entry in entries],
    }


def write_inventory_payload(
    path: str | Path,
    *,
    family: str,
    name: str,
    source: str,
    entries: Iterable[object],
    version: str = "1",
) -> JsonDict:
    payload = build_inventory_payload(
        family=family,
        name=name,
        source=source,
        entries=entries,
        version=version,
    )
    return write_json(path, payload)


def summarize_inventory_dir(inventory_dir: str | Path) -> JsonDict:
    root = Path(inventory_dir).resolve()
    families: list[JsonDict] = []
    for inventory_file in sorted(root.glob("*_inventory.json")):
        payload = json.loads(inventory_file.read_text())
        entries = payload.get("entries", [])
        blocked_reasons: Counter[str] = Counter()
        admitted = 0
        blocked = 0
        for entry in entries:
            if entry.get("admitted"):
                admitted += 1
                continue
            blocked += 1
            for reason in entry.get("reasons", []):
                blocked_reasons[str(reason)] += 1
        families.append(
            {
                "family": _inventory_family(payload, inventory_file),
                "inventory": inventory_file.name,
                "total": len(entries),
                "admitted": admitted,
                "blocked": blocked,
                "blocked_reasons": dict(sorted(blocked_reasons.items())),
            }
        )

    totals = {
        "families": len(families),
        "cases": sum(item["total"] for item in families),
        "admitted": sum(item["admitted"] for item in families),
        "blocked": sum(item["blocked"] for item in families),
    }

    return {
        "inventory_dir": str(root),
        "families": families,
        "totals": totals,
    }


def _serialize_entry(entry: object) -> JsonDict:
    if is_dataclass(entry):
        return asdict(entry)
    if isinstance(entry, Mapping):
        return dict(entry)
    raise TypeError(f"unsupported inventory entry type: {type(entry).__name__}")


def _inventory_family(payload: Mapping[str, Any], inventory_file: Path) -> str:
    family = payload.get("family")
    if isinstance(family, str) and family:
        return family

    for candidate in (payload.get("name"), inventory_file.stem):
        if not isinstance(candidate, str):
            continue
        match = re.match(r"upstream[-_](.+?)(?:[-_]auto)?[-_]inventory$", candidate)
        if match:
            return match.group(1).replace("_", "-")

    return inventory_file.stem.replace("_", "-")
