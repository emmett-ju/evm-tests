from __future__ import annotations

import re
from typing import Any

SUPPORTED_LOG_OPCODES = frozenset({"LOG0", "LOG1", "LOG2", "LOG3", "LOG4"})
LOG_PROBE_REQUIRED_FIELDS = (
    "opcode",
    "topic_count",
    "log_size",
    "memory_seed_kind",
    "memory_seed_size",
    "witness_mode",
)
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")


def opcode_topic_count(opcode: str) -> int:
    if opcode not in SUPPORTED_LOG_OPCODES:
        raise ValueError(f"unsupported log opcode: {opcode}")
    return int(opcode.removeprefix("LOG"))


def validate_log_probe_declaration(log_probe: Any) -> dict[str, Any]:
    if not isinstance(log_probe, dict):
        raise ValueError("observe.log_probe must be an object")

    missing_fields = [field for field in LOG_PROBE_REQUIRED_FIELDS if field not in log_probe]
    if missing_fields:
        raise ValueError(
            "observe.log_probe is missing required fields: " + ", ".join(missing_fields)
        )

    opcode = log_probe["opcode"]
    if not isinstance(opcode, str) or not opcode:
        raise ValueError("observe.log_probe.opcode must be a non-empty string")

    topic_count = log_probe["topic_count"]
    if not isinstance(topic_count, int) or isinstance(topic_count, bool):
        raise ValueError("observe.log_probe.topic_count must be an integer")
    if topic_count < 0:
        raise ValueError("observe.log_probe.topic_count must be non-negative")

    opcode_count = opcode_topic_count(opcode)
    if opcode_count != topic_count:
        raise ValueError(
            f"observe.log_probe.topic_count does not match opcode {opcode}: expected {opcode_count}, got {topic_count}"
        )

    log_size = log_probe["log_size"]
    if not isinstance(log_size, int) or isinstance(log_size, bool):
        raise ValueError("observe.log_probe.log_size must be an integer")
    if log_size < 0:
        raise ValueError("observe.log_probe.log_size must be non-negative")

    memory_seed_size = log_probe["memory_seed_size"]
    if not isinstance(memory_seed_size, int) or isinstance(memory_seed_size, bool):
        raise ValueError("observe.log_probe.memory_seed_size must be an integer")
    if memory_seed_size < 0:
        raise ValueError("observe.log_probe.memory_seed_size must be non-negative")

    memory_seed_kind = log_probe["memory_seed_kind"]
    if not isinstance(memory_seed_kind, str) or not memory_seed_kind:
        raise ValueError("observe.log_probe.memory_seed_kind must be a non-empty string")
    if memory_seed_kind not in ("zero", "ff"):
        raise ValueError(f"unsupported observe.log_probe.memory_seed_kind: {memory_seed_kind}")

    witness_mode = log_probe["witness_mode"]
    if not isinstance(witness_mode, str) or not witness_mode:
        raise ValueError("observe.log_probe.witness_mode must be a non-empty string")
    if witness_mode not in ("exact", "digest"):
        raise ValueError(f"unsupported observe.log_probe.witness_mode: {witness_mode}")

    topic_word = log_probe.get("topic_word")
    if topic_count == 0:
        topic_word = None
    else:
        if not isinstance(topic_word, str) or not _HEX_RE.match(topic_word):
            raise ValueError(
                "observe.log_probe.topic_word must be a hex string when topic_count is greater than zero"
            )

    return {
        "opcode": opcode,
        "topic_count": topic_count,
        "topic_word": topic_word,
        "log_size": log_size,
        "memory_seed_kind": memory_seed_kind,
        "memory_seed_size": memory_seed_size,
        "witness_mode": witness_mode,
    }
