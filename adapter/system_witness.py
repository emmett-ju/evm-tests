from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

from adapter.assembler import _push_int, _word_hex

SYSTEM_WITNESS_VERSION = 1
RETURN_REVERT_SELF_CALL_SHAPE = "return_revert_self_call"
CREATE_EMPTY_CHILD_SHAPE = "create_empty_child"
CREATE_CHILD_CODE_SHAPE = "create_child_code"
SUPPORTED_SYSTEM_WITNESS_SHAPES = (CREATE_CHILD_CODE_SHAPE, CREATE_EMPTY_CHILD_SHAPE, RETURN_REVERT_SELF_CALL_SHAPE)
SystemWitnessShape = Literal["return_revert_self_call", "create_empty_child", "create_child_code"]


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


@dataclass(frozen=True, slots=True)
class CreateEmptyChildSystemWitness:
    success: bool
    created_address_nonzero: bool
    created_code_size: int
    created_address: str
    created_balance: int | None = None


@dataclass(frozen=True, slots=True)
class CreateChildCodeSystemWitness:
    success: bool
    created_address_nonzero: bool
    created_code_size: int
    created_code_hash: str
    created_address: str


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


def build_create_empty_child_system_witness(
    *,
    opcode: str,
    subject: str = "$last_contract",
    value: int = 0,
    initcode_size: int = 0,
    salt: int | None = None,
) -> SystemWitnessBundle:
    if opcode == "CREATE2" and salt is None:
        salt = 42
    observe_witness: dict[str, Any] = {
        "version": SYSTEM_WITNESS_VERSION,
        "shape": CREATE_EMPTY_CHILD_SHAPE,
        "subject": subject,
        "opcode": opcode,
        "value": value,
        "initcode_size": initcode_size,
    }
    if salt is not None:
        observe_witness["salt"] = salt
    validate_system_witness_declaration(observe_witness)
    expected_witness: dict[str, Any] = {
        "shape": CREATE_EMPTY_CHILD_SHAPE,
        "success": True,
        "created_address_nonzero": True,
        "created_code_size": 0,
    }
    if value > 0:
        expected_witness["created_balance"] = value
    return SystemWitnessBundle(
        observe={"system_witness": observe_witness},
        expected={"system_witness": expected_witness},
    )


def build_create_child_code_system_witness(
    *,
    opcode: str,
    subject: str = "$last_contract",
    value: int = 0,
    initcode_size: int,
    data_kind: str = "zero",
    salt: int | None = None,
) -> SystemWitnessBundle:
    if opcode == "CREATE2" and salt is None:
        salt = 42
    observe_witness: dict[str, Any] = {
        "version": SYSTEM_WITNESS_VERSION,
        "shape": CREATE_CHILD_CODE_SHAPE,
        "subject": subject,
        "opcode": opcode,
        "value": value,
        "initcode_size": initcode_size,
        "data_kind": data_kind,
    }
    if salt is not None:
        observe_witness["salt"] = salt
    validate_system_witness_declaration(observe_witness)
    code_payload = _create_child_code_payload(initcode_size=initcode_size, data_kind=data_kind)
    return SystemWitnessBundle(
        observe={"system_witness": observe_witness},
        expected={
            "system_witness": {
                "shape": CREATE_CHILD_CODE_SHAPE,
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": initcode_size,
                "created_code_hash": "0x" + _keccak256(code_payload).hex(),
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
    if shape not in SUPPORTED_SYSTEM_WITNESS_SHAPES:
        supported = ", ".join(repr(item) for item in SUPPORTED_SYSTEM_WITNESS_SHAPES)
        raise ValueError(
            f"observe.system_witness.shape must be one of [{supported}]; "
            f"unsupported system witness shape: {shape!r}"
        )
    subject = value.get("subject")
    if not isinstance(subject, str) or not subject:
        raise ValueError("observe.system_witness.subject is required and must be a non-empty string")
    if shape == CREATE_EMPTY_CHILD_SHAPE:
        _validate_create_empty_child_declaration(value)
    if shape == CREATE_CHILD_CODE_SHAPE:
        _validate_create_child_code_declaration(value)


def collect_system_witness_from_storage(
    *,
    witness_config: Mapping[str, Any],
    storage: Mapping[str, str],
) -> dict[str, Any]:
    validate_system_witness_declaration(witness_config)
    shape = witness_config["shape"]
    if shape == RETURN_REVERT_SELF_CALL_SHAPE:
        return collect_return_revert_system_witness_from_storage(
            witness_config=witness_config,
            storage=storage,
        )
    if shape == CREATE_EMPTY_CHILD_SHAPE:
        return _collect_create_empty_child_system_witness_from_storage(
            witness_config=witness_config,
            storage=storage,
        )
    if shape == CREATE_CHILD_CODE_SHAPE:
        return _collect_create_child_code_system_witness_from_storage(
            witness_config=witness_config,
            storage=storage,
        )
    raise ValueError(f"unsupported system witness shape: {shape!r}")


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
    if witness_config["shape"] == CREATE_EMPTY_CHILD_SHAPE and int(witness_config.get("value", 0)) > 0:
        return ("0x00", "0x01", "0x02", "0x03")
    if witness_config["shape"] == CREATE_CHILD_CODE_SHAPE:
        return ("0x00", "0x01", "0x02", "0x03")
    return ("0x00", "0x01", "0x02")


def _validate_create_empty_child_declaration(value: Mapping[str, Any]) -> None:
    opcode = value.get("opcode")
    if opcode not in {"CREATE", "CREATE2"}:
        raise ValueError("observe.system_witness.opcode must be 'CREATE' or 'CREATE2' for create_empty_child")
    witness_value = value.get("value")
    if witness_value not in {0, 1}:
        raise ValueError("observe.system_witness.value must be 0 or 1 for create_empty_child")
    if value.get("initcode_size") != 0:
        raise ValueError("observe.system_witness.initcode_size must be 0 for create_empty_child")
    salt = value.get("salt")
    if opcode == "CREATE" and salt is not None:
        raise ValueError("observe.system_witness.salt must be omitted for CREATE create_empty_child")
    if opcode == "CREATE2" and salt != 42:
        raise ValueError("observe.system_witness.salt must be 42 for CREATE2 create_empty_child")


def _validate_create_child_code_declaration(value: Mapping[str, Any]) -> None:
    opcode = value.get("opcode")
    if opcode not in {"CREATE", "CREATE2"}:
        raise ValueError("observe.system_witness.opcode must be 'CREATE' or 'CREATE2' for create_child_code")
    if value.get("value") != 0:
        raise ValueError("observe.system_witness.value must be 0 for create_child_code")
    initcode_size = value.get("initcode_size")
    if not isinstance(initcode_size, int) or initcode_size <= 0:
        raise ValueError("observe.system_witness.initcode_size must be a positive integer for create_child_code")
    data_kind = value.get("data_kind")
    if data_kind not in {"zero", "non_zero"}:
        raise ValueError("observe.system_witness.data_kind must be 'zero' or 'non_zero' for create_child_code")
    salt = value.get("salt")
    if opcode == "CREATE" and salt is not None:
        raise ValueError("observe.system_witness.salt must be omitted for CREATE create_child_code")
    if opcode == "CREATE2" and salt != 42:
        raise ValueError("observe.system_witness.salt must be 42 for CREATE2 create_child_code")


def _collect_create_empty_child_system_witness_from_storage(
    *,
    witness_config: Mapping[str, Any],
    storage: Mapping[str, str],
) -> dict[str, Any]:
    success = _word_to_bool(storage.get("0x00"))
    created_address_word = _require_word(storage.get("0x01"), "system witness created address word")
    created_address = "0x" + created_address_word[26:]
    created_code_size = _word_to_int(storage.get("0x02"))
    collected: dict[str, Any] = {
        "shape": CREATE_EMPTY_CHILD_SHAPE,
        "success": success,
        "created_address_nonzero": int(created_address_word, 16) != 0,
        "created_code_size": created_code_size,
        "created_address": created_address,
    }
    if int(witness_config.get("value", 0)) > 0:
        collected["created_balance"] = _word_to_int(storage.get("0x03"))
    return collected


def _collect_create_child_code_system_witness_from_storage(
    *,
    witness_config: Mapping[str, Any],
    storage: Mapping[str, str],
) -> dict[str, Any]:
    success = _word_to_bool(storage.get("0x00"))
    created_address_word = _require_word(storage.get("0x01"), "system witness created address word")
    created_address = "0x" + created_address_word[26:]
    return {
        "shape": CREATE_CHILD_CODE_SHAPE,
        "success": success,
        "created_address_nonzero": int(created_address_word, 16) != 0,
        "created_code_size": _word_to_int(storage.get("0x02")),
        "created_code_hash": _require_word(storage.get("0x03"), "system witness created code hash"),
        "created_address": created_address,
    }


def _create_child_code_payload(*, initcode_size: int, data_kind: str) -> bytes:
    if data_kind == "zero":
        return b"\x00" * initcode_size
    if data_kind == "non_zero":
        initcode_prefix = _create_child_non_zero_initcode_prefix(initcode_size)
        return initcode_prefix + bytes(index % 256 for index in range(initcode_size - len(initcode_prefix)))
    raise ValueError(f"unsupported create_child_code data kind: {data_kind!r}")


def _create_child_non_zero_initcode_prefix(initcode_size: int) -> bytes:
    if initcode_size <= 0:
        raise ValueError("create_child_code initcode_size must be positive")
    prefix = _push_int(initcode_size) + bytes([0x80, 0x5F, 0x5F, 0x39, 0x5F, 0xF3])
    if len(prefix) > initcode_size:
        raise ValueError(
            f"create_child_code non_zero initcode_size {initcode_size} is smaller than initcode prefix {len(prefix)}"
        )
    return prefix


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
    return int(_require_word(value, "system witness storage word"), 16)


def _word_to_bool(value: str | None) -> bool:
    number = _word_to_int(value)
    if number == 0:
        return False
    if number == 1:
        return True
    raise ValueError(f"system witness success word must be 0 or 1, got {number}")


def _require_word(value: str | None, label: str) -> str:
    word = _require_hex_string(value, label)
    if len(word) != 66:
        raise ValueError(f"{label} must be 32 bytes: {word!r}")
    return word


def _require_hex_string(value: str | None, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{label} must be a hex string")
    return value.lower()
