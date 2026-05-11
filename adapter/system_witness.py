from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

from adapter.assembler import _word_hex

SYSTEM_WITNESS_VERSION = 1
RETURN_REVERT_SELF_CALL_SHAPE = "return_revert_self_call"
SystemWitnessShape = Literal["return_revert_self_call"]


@dataclass(frozen=True, slots=True)
class SystemWitnessBundle:
    observe: dict[str, Any]
    expected: dict[str, Any]
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReturnRevertSystemWitness:
    success: bool
    returndata_size: int
    returndata_digest: str


def build_return_revert_system_witness(
    *,
    opcode: str,
    returndata_size: int,
    returndata_payload: bytes,
    subject: str = "$last_contract",
) -> SystemWitnessBundle:
    """Build the semantic witness declaration for admitted RETURN/REVERT self-call system cases."""
    success = _return_revert_success(opcode)
    digest = "0x" + _keccak256(returndata_payload).hex()
    return SystemWitnessBundle(
        observe={
            "system_witness": {
                "version": SYSTEM_WITNESS_VERSION,
                "shape": RETURN_REVERT_SELF_CALL_SHAPE,
                "subject": subject,
            }
        },
        expected={
            "system_witness": {
                "shape": RETURN_REVERT_SELF_CALL_SHAPE,
                "success": success,
                "returndata_size": returndata_size,
                "returndata_digest": digest,
            }
        },
    )


def validate_system_witness_declaration(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("observe.system_witness must be an object")
    version = value.get("version")
    if version != SYSTEM_WITNESS_VERSION:
        raise ValueError("observe.system_witness.version must be 1")
    shape = value.get("shape")
    if shape != RETURN_REVERT_SELF_CALL_SHAPE:
        raise ValueError(
            "observe.system_witness.shape must be 'return_revert_self_call'; "
            f"unsupported system witness shape: {shape!r}"
        )
    subject = value.get("subject")
    if not isinstance(subject, str) or not subject:
        raise ValueError("observe.system_witness.subject is required and must be a non-empty string")


def collect_return_revert_system_witness_from_storage(
    *,
    witness_config: Mapping[str, Any],
    storage: Mapping[str, str],
) -> dict[str, Any]:
    validate_system_witness_declaration(witness_config)
    return {
        "shape": RETURN_REVERT_SELF_CALL_SHAPE,
        "success": _word_to_bool(storage.get("0x00")),
        "returndata_size": _word_to_int(storage.get("0x01")),
        "returndata_digest": _require_hex_string(storage.get("0x02"), "system witness returndata digest"),
    }


def return_revert_storage_transport_expected(*, opcode: str, returndata_size: int, returndata_payload: bytes) -> dict[str, str]:
    """Return the private storage transport layout used by current self-call witnesses."""
    return {
        "0x00": _word_hex(1 if _return_revert_success(opcode) else 0),
        "0x01": _word_hex(returndata_size),
        "0x02": "0x" + _keccak256(returndata_payload).hex(),
    }


def system_witness_storage_slots(witness_config: Mapping[str, Any]) -> tuple[str, ...]:
    validate_system_witness_declaration(witness_config)
    return ("0x00", "0x01", "0x02")


def _keccak256(data: bytes) -> bytes:
    from adapter.signer import keccak256

    return keccak256(data)


def _return_revert_success(opcode: str) -> bool:
    if opcode == "RETURN":
        return True
    if opcode == "REVERT":
        return False
    raise ValueError(f"unsupported return/revert system witness opcode: {opcode!r}")


def _word_to_int(value: str | None) -> int:
    word = _require_hex_string(value, "system witness storage word")
    if len(word) != 66:
        raise ValueError(f"system witness storage word must be 32 bytes: {word!r}")
    return int(word, 16)


def _word_to_bool(value: str | None) -> bool:
    number = _word_to_int(value)
    if number == 0:
        return False
    if number == 1:
        return True
    raise ValueError(f"system witness success word must be 0 or 1, got {number}")


def _require_hex_string(value: str | None, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{label} must be a hex string")
    return value.lower()
