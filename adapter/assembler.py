from __future__ import annotations

def _build_init_code(runtime_code: str) -> str:
    runtime_hex = runtime_code.removeprefix("0x")
    runtime_bytes = bytes.fromhex(runtime_hex)
    length = len(runtime_bytes)
    if length == 0:
        raise ValueError("runtime_code must not be empty")
    length_push = _push_int(length)
    offset = len(length_push) + 5 + len(length_push) + 3
    if offset > 0xFF:
        raise ValueError(f"runtime_code init helper offset too large: {offset}")
    init_code = length_push + bytes([0x60, offset, 0x60, 0x00, 0x39]) + length_push + bytes([0x60, 0x00, 0xF3]) + runtime_bytes
    return "0x" + init_code.hex()

def _push_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("push literal must be non-negative")
    if value == 0:
        return bytes([0x5F])
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(raw) > 32:
        raise ValueError(f"push literal too large: {value}")
    return bytes([0x5F + len(raw)]) + raw

def _word_hex(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()
