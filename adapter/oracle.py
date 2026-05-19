from __future__ import annotations

from typing import Any

from adapter.log_generator import derive_receipt_log_expectation
from adapter.signer import keccak256


class ResultOracle:
    def compare(
        self,
        expected: dict[str, Any],
        observed: dict[str, Any],
        context: dict[str, Any] | None = None,
        observed_contract: dict[str, Any] | None = None,
    ) -> list[str]:
        diffs: list[str] = []
        resolved_expected = self.resolve_expected(expected, context, observed_contract, observed)
        self._compare_node("", resolved_expected, observed, diffs)
        return diffs

    def resolve_expected(
        self,
        expected: dict[str, Any],
        context: dict[str, Any] | None = None,
        observed_contract: dict[str, Any] | None = None,
        observed: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        resolved = self._resolve_placeholders(expected, context or {})
        if not isinstance(resolved, dict):
            raise ValueError("resolved expected payload must be an object")
        return self._canonicalize_expected(resolved, observed_contract, observed)

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

    def _canonicalize_expected(
        self,
        expected: dict[str, Any],
        observed_contract: dict[str, Any] | None = None,
        observed: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        canonical = dict(expected)
        receipt_logs = canonical.get("receipt_logs")
        if receipt_logs is not None:
            if not isinstance(receipt_logs, list):
                raise ValueError("expected receipt_logs payload must be a list")
            canonical["receipt_logs"] = self._canonicalize_receipt_logs(
                receipt_logs,
                observed_contract or {},
                observed,
            )

        storage = canonical.get("storage")
        if storage is not None:
            storage = self._canonicalize_storage(
                storage,
                observed_contract or {},
                observed,
            )
            storage = self._canonicalize_account_query_storage(
                storage,
                observed_contract or {},
                observed,
            )
            storage = self._canonicalize_block_context_storage(
                storage,
                observed_contract or {},
                observed,
            )
            canonical["storage"] = storage

        return canonical

    def _canonicalize_block_context_storage(
        self,
        storage: dict[str, str],
        observed_contract: dict[str, Any],
        observed: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        block_context_probe = observed_contract.get("block_context_probe")
        if block_context_probe is None or block_context_probe.get("mode") != "prevrandao":
            return storage
            
        if observed is None or "storage" not in observed:
            return storage

        canonical = dict(storage)
        if "0x00" in canonical and "0x00" in observed["storage"]:
            canonical["0x00"] = observed["storage"]["0x00"]
        return canonical

    def _canonicalize_storage(
        self,
        storage: dict[str, str],
        observed_contract: dict[str, Any],
        observed: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        memory_probe = observed_contract.get("memory_probe")
        if memory_probe is None or memory_probe.get("mode") != "mcopy":
            return storage

        dynamic_src_slot = memory_probe.get("dynamic_src_slot")
        dynamic_dst_slot = memory_probe.get("dynamic_dst_slot")
        if dynamic_src_slot is None and dynamic_dst_slot is None:
            return storage

        if observed is None or "storage" not in observed:
            return storage

        src_offset: int | None = None
        if dynamic_src_slot:
            val = observed["storage"].get(dynamic_src_slot)
            if val:
                src_offset = int(val, 16)

        dst_offset: int | None = None
        if dynamic_dst_slot:
            val = observed["storage"].get(dynamic_dst_slot)
            if val:
                dst_offset = int(val, 16)

        # Re-derive expectations using the observed offsets
        from adapter.memory_generator import derive_memory_expectation
        return derive_memory_expectation(memory_probe, src_offset=src_offset, dst_offset=dst_offset)

    def _canonicalize_account_query_storage(
        self,
        storage: dict[str, str],
        observed_contract: dict[str, Any],
        observed: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        probe = observed_contract.get("account_query_probe")
        if probe is None or probe.get("mode") != "codecopy":
            return storage

        dynamic_offset_slot = probe.get("dynamic_offset_slot")
        if dynamic_offset_slot is None:
            return storage

        if observed is None or "storage" not in observed:
            return storage

        offset_val = observed["storage"].get(dynamic_offset_slot)
        if offset_val is None:
            return storage

        offset = int(offset_val, 16)

        runtime_code = observed.get("code", "0x")

        # Re-derive expectations using the observed offset
        from adapter.account_query_generator import derive_codecopy_expectation
        return derive_codecopy_expectation(probe, runtime_code=runtime_code, dynamic_offset=offset)

    def _canonicalize_receipt_logs(
        self,
        receipt_logs: list[Any],
        observed_contract: dict[str, Any],
        observed: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        log_probe = observed_contract.get("log_probe") if isinstance(observed_contract, dict) else None
        if log_probe is None:
            return [
                self._canonicalize_receipt_log(entry, index) for index, entry in enumerate(receipt_logs)
            ]
        if len(receipt_logs) != 1:
            raise ValueError(
                f"expected receipt_logs to contain exactly 1 entry for observe.log_probe, got {len(receipt_logs)}"
            )

        dynamic_offset: int | None = None
        if log_probe.get("dynamic_offset_slot") is not None:
            if observed is None or "storage" not in observed or log_probe["dynamic_offset_slot"] not in observed["storage"]:
                raise ValueError(
                    f"dynamic_offset_slot {log_probe['dynamic_offset_slot']} requested but not present in observed storage"
                )
            slot_value = observed["storage"][log_probe["dynamic_offset_slot"]]
            dynamic_offset = int(slot_value, 16)

        canonical_entry = self._canonicalize_receipt_log(receipt_logs[0], 0)
        derived_entry = self._canonicalize_receipt_log(derive_receipt_log_expectation(log_probe, dynamic_offset), 0)
        self._validate_declared_receipt_log_matches_runtime_contract(canonical_entry, derived_entry)
        return [derived_entry]

    def _validate_declared_receipt_log_matches_runtime_contract(
        self,
        declared: dict[str, Any],
        derived: dict[str, Any],
    ) -> None:
        if declared != derived:
            diffs: list[str] = []
            self._compare_node("receipt_logs[0]", derived, declared, diffs)
            detail = diffs[0] if diffs else "receipt_logs[0]: declared witness does not match derived runtime contract"
            raise ValueError(f"declared receipt_logs witness does not match observe.log_probe: {detail}")

    def _canonicalize_receipt_log(self, entry: Any, index: int) -> dict[str, Any]:
        if not isinstance(entry, dict):
            raise ValueError(f"expected receipt log {index} must be an object")
        topics = entry.get("topics")
        if not isinstance(topics, list):
            raise ValueError(f"expected receipt log {index}.topics must be a list")
        normalized_topics = [
            self._normalize_hex(topic, field=f"expected receipt log {index}.topics[{topic_index}]")
            for topic_index, topic in enumerate(topics)
        ]
        canonical: dict[str, Any] = {
            "topics": normalized_topics,
            "topic_count": len(normalized_topics),
        }
        if "data_digest" in entry:
            data_digest = entry.get("data_digest")
            data_length_bytes = entry.get("data_length_bytes")
            if not isinstance(data_digest, str):
                raise ValueError(f"expected receipt log {index}.data_digest must be a hex string")
            if not isinstance(data_length_bytes, int):
                raise ValueError(f"expected receipt log {index}.data_length_bytes must be an int")
            canonical["data_digest"] = self._normalize_hex(
                data_digest,
                field=f"expected receipt log {index}.data_digest",
            )
            canonical["data_length_bytes"] = data_length_bytes
            return canonical
        data = entry.get("data")
        if not isinstance(data, str):
            raise ValueError(f"expected receipt log {index}.data must be a hex string")
        normalized_data = self._normalize_hex(data, field=f"expected receipt log {index}.data")
        canonical["data"] = normalized_data
        canonical["data_length_bytes"] = self._hex_data_length_bytes(
            normalized_data,
            field=f"expected receipt log {index}.data",
        )
        return canonical

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

    def _compare_digest_backed_receipt_log(
        self,
        path: str,
        expected: Any,
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
            diffs.append(
                f"{path}.data_digest: expected {expected['data_digest']!r}, got {observed_digest!r}"
            )
        return True
