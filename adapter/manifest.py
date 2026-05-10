from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any

from adapter.models import FilterRule, Manifest, TestCase


class ManifestValidationError(ValueError):
    pass


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


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestValidationError(f"{context} must be an object")
    return value


def _require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ManifestValidationError(f"{context} must be a list")
    return value


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestValidationError(f"{context} is required and must be a non-empty string")
    return value


def _coerce_filter_rule(value: Any, case_label: str) -> FilterRule:
    if value is None:
        return FilterRule()
    if not isinstance(value, dict):
        raise ManifestValidationError(f"{case_label}: filters must be an object")
    return FilterRule(**value)


def _coerce_case(entry: Any, case_index: int) -> TestCase:
    case_label = f"manifest case {case_index + 1}"
    case_data = _require_object(entry, case_label)
    case_id = _require_string(case_data.get("case_id"), f"{case_label}.case_id")
    try:
        case = TestCase(
            kind=_require_string(case_data.get("kind"), f"{case_label}.kind"),
            case_id=case_id,
            family=_require_string(case_data.get("family"), f"{case_label}.family"),
            description=_require_string(case_data.get("description"), f"{case_label}.description"),
            filters=_coerce_filter_rule(case_data.get("filters", {}), f"case {case_id}"),
            namespace_seed=_require_string(
                case_data.get("namespace_seed"),
                f"{case_label}.namespace_seed",
            ),
            steps=_require_list(case_data.get("steps", []), f"case {case_id}: steps"),
            expected=_require_object(case_data.get("expected", {}), f"case {case_id}: expected"),
            observe=_require_object(case_data.get("observe", {}), f"case {case_id}: observe"),
            upstream_ref=case_data.get("upstream_ref"),
            notes=_require_list(case_data.get("notes", []), f"case {case_id}: notes"),
        )
    except TypeError as exc:
        raise ManifestValidationError(f"case {case_id}: invalid filter declaration: {exc}") from exc
    case.validate()
    return case


def load_manifest(path: str | Path) -> Manifest:
    manifest_path = Path(path)
    data = _require_object(json.loads(manifest_path.read_text()), "manifest")
    try:
        cases = [_coerce_case(entry, index) for index, entry in enumerate(_require_list(data.get("cases"), "manifest.cases"))]
        manifest = Manifest(
            name=_require_string(data.get("name"), "manifest.name"),
            version=_require_string(data.get("version"), "manifest.version"),
            execution_specs_ref=resolve_execution_specs_ref(
                manifest_path,
                data.get("execution_specs_ref"),
            ),
            suite_version=_require_string(data.get("suite_version"), "manifest.suite_version"),
            chain_profile_version=_require_string(
                data.get("chain_profile_version"),
                "manifest.chain_profile_version",
            ),
            cases=cases,
            path=manifest_path,
        )
    except KeyError as exc:
        raise ManifestValidationError(f"manifest is missing required field: {exc.args[0]}") from exc
    manifest.validate()
    return manifest
