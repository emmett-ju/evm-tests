from __future__ import annotations

def _build_init_code(runtime_code: str) -> str:
    runtime_hex = runtime_code.removeprefix("0x")
    runtime_bytes = bytes.fromhex(runtime_hex)
    length = len(runtime_bytes)
    if length == 0:
        raise ValueError("runtime_code must not be empty")
    if length > 0xFF:
        raise ValueError("runtime_code too long for PUSH1 init helper")
    return f"0x60{length:02x}600c60003960{length:02x}6000f3{runtime_hex}"

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
