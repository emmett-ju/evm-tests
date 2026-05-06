from __future__ import annotations

from typing import Any


class ResultOracle:
    def compare(self, expected: dict[str, Any], observed: dict[str, Any]) -> list[str]:
        diffs: list[str] = []
        self._compare_node("", expected, observed, diffs)
        return diffs

    def _compare_node(
        self,
        path: str,
        expected: Any,
        observed: Any,
        diffs: list[str],
    ) -> None:
        if isinstance(expected, dict):
            if not isinstance(observed, dict):
                diffs.append(f"{path or '<root>'}: expected object, got {type(observed).__name__}")
                return
            for key, value in expected.items():
                next_path = f"{path}.{key}" if path else str(key)
                if key not in observed:
                    diffs.append(f"{next_path}: missing observed value")
                    continue
                self._compare_node(next_path, value, observed[key], diffs)
            return
        if expected == "nonempty":
            if observed in (None, "", "0x"):
                diffs.append(f"{path}: expected nonempty value, got {observed!r}")
            return
        if expected != observed:
            diffs.append(f"{path}: expected {expected!r}, got {observed!r}")
