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
        resolved_expected = self.resolve_expected(expected, context)
        self._compare_node("", resolved_expected, observed, diffs)
        return diffs

    def resolve_expected(
        self,
        expected: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        resolved = self._resolve_placeholders(expected, context or {})
        if not isinstance(resolved, dict):
            raise ValueError("resolved expected payload must be an object")
        return self._canonicalize_expected(resolved)

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

    def _canonicalize_expected(self, expected: dict[str, Any]) -> dict[str, Any]:
        canonical = dict(expected)
        receipt_logs = canonical.get("receipt_logs")
        if receipt_logs is not None:
            if not isinstance(receipt_logs, list):
                raise ValueError("expected receipt_logs payload must be a list")
            canonical["receipt_logs"] = [self._canonicalize_receipt_log(entry, index) for index, entry in enumerate(receipt_logs)]
        return canonical

    def _canonicalize_receipt_log(self, entry: Any, index: int) -> dict[str, Any]:
        if not isinstance(entry, dict):
            raise ValueError(f"expected receipt log {index} must be an object")
        topics = entry.get("topics")
        data = entry.get("data")
        if not isinstance(topics, list):
            raise ValueError(f"expected receipt log {index}.topics must be a list")
        if not isinstance(data, str):
            raise ValueError(f"expected receipt log {index}.data must be a hex string")
        normalized_topics = [self._normalize_hex(topic, field=f"expected receipt log {index}.topics[{topic_index}]") for topic_index, topic in enumerate(topics)]
        normalized_data = self._normalize_hex(data, field=f"expected receipt log {index}.data")
        return {
            "topics": normalized_topics,
            "topic_count": len(normalized_topics),
            "data": normalized_data,
            "data_length_bytes": self._hex_data_length_bytes(normalized_data, field=f"expected receipt log {index}.data"),
        }

    def _normalize_hex(self, value: Any, *, field: str) -> str:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError(f"{field} must be a hex string, got: {value!r}")
        normalized = value[2:]
        if len(normalized) % 2 != 0:
            raise ValueError(f"{field} must contain whole bytes, got: {value!r}")
        return "0x" + normalized.lower()

    def _hex_data_length_bytes(self, value: str, *, field: str) -> int:
        normalized = self._normalize_hex(value, field=field)
        return (len(normalized) - 2) // 2

    def _compare_node(
        self,
        path: str,
        expected: Any,
        observed: Any,
        diffs: list[str],
    ) -> None:
        if self._compare_digest_backed_receipt_log(path, expected, observed, diffs):
            return
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
        if isinstance(expected, list):
            if not isinstance(observed, list):
                diffs.append(f"{path or '<root>'}: expected list, got {type(observed).__name__}")
                return
            if len(expected) != len(observed):
                diffs.append(f"{path}: expected {len(expected)} entries, got {len(observed)}")
                return
            for index, value in enumerate(expected):
                next_path = f"{path}[{index}]"
                self._compare_node(next_path, value, observed[index], diffs)
            return
        if expected == "nonempty":
            if observed in (None, "", "0x"):
                diffs.append(f"{path}: expected nonempty value, got {observed!r}")
            return
        if expected != observed:
            diffs.append(f"{path}: expected {expected!r}, got {observed!r}")
     observed: Any,
        diffs: list[str],
    ) -> bool:
        if not path.startswith("receipt_logs["):
            return False
        if not isinstance(expected, dict) or "data_digest" not in expected:
            return False
        if not isinstance(observed, dict):
            diffs.append(f"{path or '<root>'}: expected object, got {type(observed).__name__}")
            return True
        for key in ("topics", "topic_count", "data_length_bytes"):
            next_path = f"{path}.{key}" if path else str(key)
            if key not in observed:
                diffs.append(f"{next_path}: missing observed value")
                continue
            self._compare_node(next_path, expected[key], observed[key], diffs)
        observed_data = observed.get("data")
        if not isinstance(observed_data, str):
            diffs.append(f"{path}.data: missing observed value")
            return True
        normalized_data = self._normalize_hex(observed_data, field=f"{path}.data")
        observed_digest = "0x" + keccak256(bytes.fromhex(normalized_data[2:])).hex()
        if observed_digest != expected["data_digest"]:
            diffs.append(f"{path}.data_digest: expected {expected['data_digest']!r}, got {observed_digest!r}")
        return True
