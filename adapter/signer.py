from __future__ import annotations

import os
import secrets
import subprocess
from pathlib import Path
from typing import Any

from adapter.models import ChainProfile


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
SECP256K1_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
SECP256K1_G = (SECP256K1_GX, SECP256K1_GY)


def load_private_key(profile: ChainProfile) -> int:
    source = profile.admin_key_source
    if not source:
        raise ValueError("admin_key_source is required for local signing")
    if source.startswith("env:"):
        env_name = source.split(":", 1)[1]
        value = os.environ.get(env_name, "")
        if not value.strip():
            raise ValueError(
                f"missing private key in environment variable {env_name}; "
                "set it in .env or the shell before running"
            )
        return _parse_private_key_hex(value)
    if source.startswith("file:"):
        file_path = Path(source.split(":", 1)[1])
        if not file_path.exists():
            raise ValueError(f"private key file not found: {file_path}")
        value = file_path.read_text().strip()
        return _parse_private_key_hex(value)
    raise ValueError(f"unsupported admin_key_source for local signing: {source}")


def private_key_to_address(private_key: int) -> str:
    public_key = _public_key_bytes(private_key)
    digest = keccak256(public_key[1:])
    return "0x" + digest[-20:].hex()


def sign_type_2_transaction(profile: ChainProfile, private_key: int, transaction: dict[str, str]) -> str:
    payload = [
        _int_to_bytes(int(profile.chain_id)),
        _int_to_bytes(_hex_to_int(transaction["nonce"])),
        _int_to_bytes(_hex_to_int(transaction["maxPriorityFeePerGas"])),
        _int_to_bytes(_hex_to_int(transaction["maxFeePerGas"])),
        _int_to_bytes(_hex_to_int(transaction["gas"])),
        _hex_to_bytes(transaction.get("to", "0x")),
        _int_to_bytes(_hex_to_int(transaction.get("value", "0x0"))),
        _hex_to_bytes(transaction.get("data", "0x")),
        [],
    ]
    signing_hash = keccak256(b"\x02" + _rlp_encode(payload))
    y_parity, r, s = _sign_digest(private_key, signing_hash)
    signed = payload + [
        _int_to_bytes(y_parity),
        _int_to_bytes(r),
        _int_to_bytes(s),
    ]
    return "0x" + (b"\x02" + _rlp_encode(signed)).hex()


def sign_authorization(private_key: int, chain_id: int, address: str, nonce: int) -> list[bytes]:
    payload = [
        _int_to_bytes(chain_id),
        _hex_to_bytes(address),
        _int_to_bytes(nonce),
    ]
    signing_hash = keccak256(b"\x05" + _rlp_encode(payload))
    y_parity, r, s = _sign_digest(private_key, signing_hash)
    return [
        _int_to_bytes(chain_id),
        _hex_to_bytes(address),
        _int_to_bytes(nonce),
        _int_to_bytes(y_parity),
        _int_to_bytes(r),
        _int_to_bytes(s),
    ]


def sign_type_4_transaction(profile: ChainProfile, private_key: int, transaction: dict[str, Any]) -> str:
    authorizations = transaction.get("authorizations", [])
    payload = [
        _int_to_bytes(int(profile.chain_id)),
        _int_to_bytes(_hex_to_int(transaction["nonce"])),
        _int_to_bytes(_hex_to_int(transaction["maxPriorityFeePerGas"])),
        _int_to_bytes(_hex_to_int(transaction["maxFeePerGas"])),
        _int_to_bytes(_hex_to_int(transaction["gas"])),
        _hex_to_bytes(transaction.get("to", "0x")),
        _int_to_bytes(_hex_to_int(transaction.get("value", "0x0"))),
        _hex_to_bytes(transaction.get("data", "0x")),
        [],  # access_list
        authorizations,
    ]
    signing_hash = keccak256(b"\x04" + _rlp_encode(payload))
    y_parity, r, s = _sign_digest(private_key, signing_hash)
    signed = payload + [
        _int_to_bytes(y_parity),
        _int_to_bytes(r),
        _int_to_bytes(s),
    ]
    return "0x" + (b"\x04" + _rlp_encode(signed)).hex()


def keccak256(data: bytes) -> bytes:
    process = subprocess.run(
        ["/opt/homebrew/bin/openssl", "dgst", "-binary", "-KECCAK-256"],
        input=data,
        capture_output=True,
        check=True,
    )
    return process.stdout


def _sign_digest(private_key: int, digest: bytes) -> tuple[int, int, int]:
    z = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(SECP256K1_N - 1) + 1
        point = _point_multiply(k, SECP256K1_G)
        if point is None:
            continue
        r = point[0] % SECP256K1_N
        if r == 0:
            continue
        k_inv = pow(k, -1, SECP256K1_N)
        s = (k_inv * (z + r * private_key)) % SECP256K1_N
        if s == 0:
            continue
        recovery_id = (1 if point[1] & 1 else 0) | (2 if point[0] >= SECP256K1_N else 0)
        if s > SECP256K1_N // 2:
            s = SECP256K1_N - s
            recovery_id ^= 1
        return recovery_id, r, s


def _public_key_bytes(private_key: int) -> bytes:
    point = _point_multiply(private_key, SECP256K1_G)
    if point is None:
        raise ValueError("invalid private key")
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def _parse_private_key_hex(value: str) -> int:
    cleaned = value.strip()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64:
        raise ValueError("private key must be 32 bytes hex")
    private_key = int(cleaned, 16)
    if private_key <= 0 or private_key >= SECP256K1_N:
        raise ValueError("private key out of range")
    return private_key


def _hex_to_bytes(value: str) -> bytes:
    if value in ("0x", ""):
        return b""
    cleaned = value[2:] if value.startswith("0x") else value
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return bytes.fromhex(cleaned)


def _hex_to_int(value: str) -> int:
    if value in ("0x", ""):
        return 0
    return int(value, 16)


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _rlp_encode(item: bytes | int | list[object]) -> bytes:
    if isinstance(item, int):
        return _rlp_encode(_int_to_bytes(item))
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        return _encode_length(len(item), 0x80) + item
    if isinstance(item, list):
        payload = b"".join(_rlp_encode(subitem) for subitem in item)
        return _encode_length(len(payload), 0xC0) + payload
    raise TypeError(f"unsupported rlp item: {type(item)!r}")


def _encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([length + offset])
    length_bytes = _int_to_bytes(length)
    return bytes([len(length_bytes) + offset + 55]) + length_bytes


def _point_add(
    left: tuple[int, int] | None,
    right: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, SECP256K1_P)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, SECP256K1_P)
    slope %= SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y3 = (slope * (x1 - x3) - y1) % SECP256K1_P
    return x3, y3


def _point_multiply(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend = point
    k = scalar
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result
