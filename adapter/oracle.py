from __future__ import annotations

from typing import Any


class ResultOracle:
    def compare(
        self,
        expected: dict[str, Any],
        observed: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> list[str]:
        diffs: list[str] = []
        resolved_expected = self._resolve_placeholders(expected, context or {})
        self._compare_node("", resolved_expected, observed, diffs)
        return diffs

    def _resolve_placeholders(self, node: Any, context: dict[str, Any]) -> Any:
        if isinstance(node, dict):
            return {key: self._resolve_placeholders(value, context) for key, value in node.items()}
        if isinstance(node, list):
            return [self._resolve_placeholders(value, context) for value in node]
        if not isinstance(node, str) or not node.startswith("$"):
            return node
        if node.endswith("_word"):
            base_key = node.removesuffix("_word")
            value = self._resolve_placeholder_value(base_key, context)
            return self._hex_to_word(value)
        return self._resolve_placeholder_value(node, context)

    def _resolve_placeholder_value(self, placeholder: str, context: dict[str, Any]) -> Any:
        if placeholder not in context:
            raise ValueError(f"unknown expected placeholder: {placeholder}")
        return context[placeholder]

    def _hex_to_word(self, value: Any) -> str:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError(f"cannot convert placeholder value to 32-byte word: {value!r}")
        normalized = value[2:].lower()
        if len(normalized) > 64:
            raise ValueError(f"expected value that fits in 32 bytes for word conversion, got: {value}")
        return "0x" + normalized.rjust(64, "0")

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
