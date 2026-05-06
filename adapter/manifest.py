from __future__ import annotations

import json
from pathlib import Path
import subprocess

from adapter.models import FilterRule, Manifest, TestCase


def resolve_execution_specs_ref(
    manifest_path: str | Path,
    declared_ref: str | None,
) -> str:
    if declared_ref and declared_ref != "submodule-pending":
        return declared_ref
    manifest_file = Path(manifest_path).resolve()
    submodule_path = None
    for parent in [manifest_file, *manifest_file.parents]:
        candidate = parent / "third_party" / "execution-specs"
        if candidate.exists():
            submodule_path = candidate
            break
    if submodule_path is None:
        return declared_ref or "submodule-missing"
    try:
        return (
            subprocess.run(
                ["git", "-C", str(submodule_path), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            )
            .stdout.strip()
        )
    except (OSError, subprocess.CalledProcessError):
        return declared_ref or "submodule-unresolved"


def load_manifest(path: str | Path) -> Manifest:
    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text())
    cases = [
        TestCase(
            kind=entry["kind"],
            case_id=entry["case_id"],
            family=entry["family"],
            description=entry["description"],
            filters=FilterRule(**entry.get("filters", {})),
            namespace_seed=entry["namespace_seed"],
            steps=list(entry.get("steps", [])),
            expected=dict(entry.get("expected", {})),
            observe=dict(entry.get("observe", {})),
            upstream_ref=entry.get("upstream_ref"),
            notes=list(entry.get("notes", [])),
        )
        for entry in data["cases"]
    ]
    return Manifest(
        name=data["name"],
        version=data["version"],
        execution_specs_ref=resolve_execution_specs_ref(
            manifest_path,
            data.get("execution_specs_ref"),
        ),
        suite_version=data["suite_version"],
        chain_profile_version=data["chain_profile_version"],
        cases=cases,
        path=manifest_path,
    )
