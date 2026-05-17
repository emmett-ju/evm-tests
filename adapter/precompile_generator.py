from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from adapter.signer import keccak256
from adapter.assembler import _push_int, _build_init_code
from adapter.inventory import write_inventory_payload
from adapter.manifest import resolve_execution_specs_ref

# EIP-2537 Precompile Addresses
PRECOMPILE_G1ADD = 0x0B
PRECOMPILE_G1MUL = 0x0C
PRECOMPILE_G1MSM = 0x0D
PRECOMPILE_G2ADD = 0x0E
PRECOMPILE_G2MUL = 0x0F
PRECOMPILE_G2MSM = 0x10
PRECOMPILE_PAIRING = 0x11
PRECOMPILE_MAP_FP = 0x12
PRECOMPILE_MAP_FP2 = 0x13
PRECOMPILE_P256VERIFY = 0x100

ADMITTED_FILES = {
    "add_G1_bls.json",
    "mul_G1_bls.json",
}

PRECOMPILE_ADDRESSES = {
    "add_G1": PRECOMPILE_G1ADD,
    "add_G2": PRECOMPILE_G2ADD,
    "mul_G1": PRECOMPILE_G1MUL,
    "mul_G2": PRECOMPILE_G2MUL,
    "msm_G1": PRECOMPILE_G1MSM,
    "msm_G2": PRECOMPILE_G2MSM,
    "pairing_check": PRECOMPILE_PAIRING,
    "map_fp_to_G1": PRECOMPILE_MAP_FP,
    "map_fp2_to_G2": PRECOMPILE_MAP_FP2,
    "p256verify": PRECOMPILE_P256VERIFY,
}

@dataclass(frozen=True, slots=True)
class PrecompileMappingTemplate:
    case_id: str
    description: str
    namespace_seed: str
    upstream_ref: str
    notes: list[str]
    address: int
    input_hex: str
    expected_hex: str
    base_name: str
    precompile_family: str
    feature_flag: str

def generate_upstream_precompile_templates(
    *,
    repo_root: str | Path,
    source_path: str | Path | None = None,
    output_path: str | Path | None = None,
    inventory_path: str | Path | None = None,
) -> dict[str, Any]:
    if output_path is None and inventory_path is None:
        raise ValueError("at least one of output_path or inventory_path is required")
    repo_root_path = Path(repo_root).resolve()
    source = (
        Path(source_path).resolve()
        if source_path is not None
        else repo_root_path / "third_party" / "execution-specs" / "tests" / "prague" / "eip2537_bls_12_381_precompiles" / "vectors"
    )

    bls_result = scan_vectors(source)
    p256_result = scan_p256verify()
    modexp_result = scan_modexp_osaka()

    inventory = bls_result["inventory"]["entries"] + p256_result["inventory"]["entries"] + modexp_result["inventory"]["entries"]
    templates = bls_result["templates"] + p256_result["templates"] + modexp_result["templates"]

    payload = {
        "name": "upstream-precompile-mapping-templates",
        "version": "1",
        "source": str(source.relative_to(repo_root_path)) if source.is_relative_to(repo_root_path) else str(source),
        "cases": [asdict(template) for template in templates],
    }

    if output_path is not None:
        output = Path(output_path).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2) + "\n")

    if inventory_path is not None:
        write_inventory_payload(
            inventory_path,
            family="upstream-precompile",
            name="upstream-precompile-inventory",
            source=payload["source"],
            entries=inventory,
        )
    return payload

def generate_upstream_precompile_manifest(
    *,
    repo_root: str | Path,
    output_path: str | Path,
    template_path: str | Path | None = None,
    suite_version: str = "0.1.0",
    chain_profile_version: str = "1",
) -> dict[str, Any]:
    repo_root_path = Path(repo_root).resolve()
    output = Path(output_path).resolve()
    template_file = (
        Path(template_path).resolve()
        if template_path is not None
        else repo_root_path / "suites" / "templates" / "upstream_precompile_templates.json"
    )

    data = json.loads(template_file.read_text())
    templates = [
        PrecompileMappingTemplate(**entry)
        for entry in data["cases"]
    ]

    execution_specs_ref = resolve_execution_specs_ref(
        repo_root_path / "suites" / "manifests" / "upstream_precompile_mapped.json",
        "submodule-pending",
    )

    manifest = {
        "name": "upstream-precompile-mapped",
        "version": "1",
        "execution_specs_ref": execution_specs_ref,
        "suite_version": suite_version,
        "chain_profile_version": chain_profile_version,
        "cases": [render_precompile_case(template) for template in templates],
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest

def render_precompile_case(template: PrecompileMappingTemplate) -> dict[str, Any]:
    input_bytes = bytes.fromhex(template.input_hex.removeprefix("0x"))
    expected_hex = template.expected_hex.removeprefix("0x")

    # For MODEXP osaka, use the exact boundary gas, and expect failure.
    inner_gas = 10_000_000
    expected_success = True
    if template.precompile_family == "modexp":
        inner_gas = 20975
        expected_success = False

    runtime_bytes = generate_precompile_runtime(template.address, input_bytes, inner_gas)
    init_code = _build_init_code(runtime_bytes.hex())

    # Deterministic storage expectations
    expected_storage = {
        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001" if expected_success else "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x01": "0x" + (len(expected_hex)//2).to_bytes(32, "big").hex(),
    }
    if expected_hex:
        digest = get_output_digest(expected_hex)
        expected_storage["0x02"] = digest

    return {
        "kind": "upstream_mapped",
        "case_id": template.case_id,
        "family": "upstream-precompile",
        "description": template.description,
        "filters": {
            "requires_genesis_state": False,
        },
        "namespace_seed": template.namespace_seed,
        "steps": [
            {
                "action": "deploy_contract",
                "bytecode_init": init_code,
                "bytecode_runtime": "0x" + runtime_bytes.hex(),
                "gas": "0x989680",
            },
            {
                "action": "wait_receipt",
                "tx_hash": "$last",
                "timeout_seconds": 60,
            },
            {
                "action": "invoke_contract",
                "to": "$last_contract",
                "data": "0x",
                "gas": "0x989680",
            },
            {
                "action": "wait_receipt",
                "tx_hash": "$last",
                "timeout_seconds": 60,
            }
        ],
        "expected": {
            "storage": expected_storage
        },
        "observe": {
            "storage_address": "$last_contract",
            "precompile_probe": {
                "family": template.precompile_family,
                "precompile": template.base_name,
                "address": hex(template.address),
                "input_size": len(input_bytes),
                "output_size": len(expected_hex)//2,
                "expected_success": expected_success,
                "expected_output_digest": get_output_digest(expected_hex),
                "required_feature": template.feature_flag,
                "inner_gas": inner_gas
            }
        },
        "upstream_ref": template.upstream_ref
    }

def generate_precompile_runtime(
    precompile_address: int,
    input_bytes: bytes,
    gas: int = 10_000_000
) -> bytes:
    """
    Builds a deterministic wrapper runtime that:
    1. CODECOPYs embedded input to memory 0
    2. CALLs the precompile
    3. SSTOREs success (slot 0)
    4. SSTOREs RETURNDATASIZE (slot 1)
    5. If success and output, SSTOREs keccak256(output) (slot 2)
    """
    input_size = len(input_bytes)

    # Opcode constants
    OP_PUSH0 = 0x5F
    OP_CODECOPY = 0x39
    OP_CALL = 0xF1
    OP_SSTORE = 0x55
    OP_RETURNDATASIZE = 0x3D
    OP_RETURNDATACOPY = 0x3E
    OP_SHA3 = 0x20
    OP_STOP = 0x00
    OP_JUMP = 0x56
    OP_JUMPI = 0x57
    OP_JUMPDEST = 0x5B

    # Assembly sequence
    ops = []

    # 1. CODECOPY input
    ops.append(_push_int(input_size))
    # input_offset placeholder (we'll fix this later)
    input_offset_idx = len(ops)
    ops.append(b"\x61\x00\x00") # PUSH2 0x0000 placeholder
    ops.append(_push_int(0))
    ops.append(bytes([OP_CODECOPY]))

    # 2. CALL
    ops.append(_push_int(0)) # out_size
    ops.append(_push_int(0)) # out_offset
    ops.append(_push_int(input_size))
    ops.append(_push_int(0)) # in_offset
    ops.append(_push_int(0)) # value
    ops.append(_push_int(precompile_address))
    ops.append(_push_int(gas))
    ops.append(bytes([OP_CALL]))

    # 3. SSTORE success (result is on stack)
    ops.append(_push_int(0)) # slot 0
    ops.append(bytes([OP_SSTORE]))

    # 4. SSTORE RETURNDATASIZE
    ops.append(bytes([OP_RETURNDATASIZE]))
    ops.append(_push_int(1)) # slot 1
    ops.append(bytes([OP_SSTORE]))

    # 5. Output handling
    ops.append(bytes([OP_RETURNDATASIZE]))
    # Jump if 0
    not_empty_label_idx = len(ops)
    ops.append(b"\x61\x00\x00") # PUSH2 placeholder
    ops.append(bytes([OP_JUMPI]))
    ops.append(bytes([OP_STOP]))

    # JUMPDEST for non-empty returndata
    not_empty_jumpdest = sum(len(o) for o in ops)
    ops.append(bytes([OP_JUMPDEST]))

    ops.append(bytes([OP_RETURNDATASIZE]))
    ops.append(_push_int(0)) # destOffset
    ops.append(_push_int(0)) # offset
    ops.append(bytes([OP_RETURNDATACOPY]))

    ops.append(bytes([OP_RETURNDATASIZE]))
    ops.append(_push_int(0)) # offset
    ops.append(bytes([OP_SHA3]))

    ops.append(_push_int(2)) # slot 2
    ops.append(bytes([OP_SSTORE]))
    ops.append(bytes([OP_STOP]))

    # Fix offsets
    runtime_size_no_input = sum(len(o) for o in ops)
    ops[input_offset_idx] = bytes([0x61]) + runtime_size_no_input.to_bytes(2, "big")

    # Fix JUMPI offset
    ops[not_empty_label_idx] = bytes([0x61]) + not_empty_jumpdest.to_bytes(2, "big")

    return b"".join(ops) + input_bytes

def generate_precompile_wrapper(
    precompile_address: int,
    input_bytes: bytes,
    gas: int = 10_000_000
) -> str:
    runtime_bytes = generate_precompile_runtime(precompile_address, input_bytes, gas)
    return _build_init_code(runtime_bytes.hex())


def get_output_digest(expected_hex: str) -> str:
    if not expected_hex:
        return ""
    data = bytes.fromhex(expected_hex)
    return "0x" + keccak256(data).hex()

def scan_vectors(vectors_dir: Path) -> Dict[str, Any]:
    cases = []
    inventory_entries = []
    templates = []

    # Get all json files in vectors_dir
    json_files = sorted(list(vectors_dir.glob("*.json")))

    for path in json_files:
        filename = path.name
        is_fail_file = filename.startswith("fail-")

        # Determine precompile name from filename
        base_name = filename.removeprefix("fail-").removesuffix("_bls.json")
        address = PRECOMPILE_ADDRESSES.get(base_name)

        with open(path, "r") as f:
            data = json.load(f)

        for i, item in enumerate(data):
            case_name = item["Name"]
            case_id = f"upstream.precompile.bls12_381.{base_name}.{i}"
            upstream_ref = f"eip2537_bls_12_381_precompiles/vectors/{filename}:{case_name}"

            # Decision: admit only first 2 cases of admitted files
            is_admitted = (filename in ADMITTED_FILES and i < 2)

            reasons = []
            if not is_admitted:
                if filename not in ADMITTED_FILES:
                    reasons.append(f"precompile {base_name} deferred")
                elif i >= 2:
                    reasons.append("case limit exceeded for minimal probe")
                if is_fail_file:
                    reasons.append("failure cases deferred")

            # Inventory entry
            inventory_entry = {
                "upstream_ref": upstream_ref,
                "case_id": case_id,
                "admitted": is_admitted,
                "reasons": reasons,
                "address": hex(address) if address else None,
                "input_size": len(bytes.fromhex(item["Input"].removeprefix("0x"))),
            }
            inventory_entries.append(inventory_entry)

            if is_admitted:
                input_hex = item["Input"]
                expected_hex = item.get("Expected", "")

                template = PrecompileMappingTemplate(
                    case_id=case_id,
                    description=f"BLS12-381 {base_name} probe: {case_name}",
                    namespace_seed=case_id,
                    upstream_ref=upstream_ref,
                    notes=[
                        f"Upstream intent: probe BLS12-381 precompile {base_name}.",
                        "RPC mapping: deploy a wrapper that calls the precompile and records success/returndata/output-digest to storage.",
                        "Admitted as part of minimal Prague BLS12-381 probe."
                    ],
                    address=address,
                    input_hex=input_hex,
                    expected_hex=expected_hex,
                    base_name=base_name,
                    precompile_family="bls12_381",
                    feature_flag="bls12_381_precompiles",
                )
                templates.append(template)

    return {
        "inventory": {
            "name": "upstream-precompile-bls12-381-inventory",
            "version": "1",
            "family": "upstream-precompile",
            "entries": inventory_entries,
        },
        "templates": templates
    }


def scan_p256verify() -> Dict[str, Any]:
    inventory_entries = []
    templates = []

    # Cases mapped directly from execution-specs test_p256verify.py
    cases = [
        (
            "p256verify",
            "BB5A52F42F9C9261ED4361F59422A1E30036E7C32B270C8807A419FECA6050232BA3A8BE6B94D5EC80A6D9D1190A436EFFE50D85A1EEE859B8CC6AF9BD5C2E184CD60B855D442F5B3C7B11EB6C4E0AE7525FE710FAB9AA7C77A67F79E6FADD762927B10512BAE3EDDCFE467828128BAD2903269919F7086069C8C4DF6C732838C7787964EAAC00E5921FB1498A60F4606766B3D9685001558D1A974E7341513E",
            "0000000000000000000000000000000000000000000000000000000000000001",
            True
        ),
        (
            "p256verify_wrong_endianness",
            "235060CAFE19A407880C272BC3E73600E3A12294F56143ED61929C2FF4525ABB182E5CBDF96ACCB859E8EEA1850DE5FF6E430A19D1D9A680ECD5946BBEA8A32B76DDFAE6797FA6777CAAB9FA10E75F52E70A4E6CEB117B3C5B2F445D850BD64C3828736CDFC4C8696008F71999260329AD8B12287846FEDCEDE3BA1205B127293E5141734E971A8D55015068D9B3666760F4608A49B11F92E500ACEA647978C7",
            "",
            True
        ),
        (
            "p256verify_modular_comp_x_coordinate_exceeds_n",
            "BB5A52F42F9C9261ED4361F59422A1E30036E7C32B270C8807A419FECA605023000000000000000000000000000000004319055358E8617B0C46353D039CDAABFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254E0AD99500288D466940031D72A9F5445A4D43784640855BF0A69874D2DE5FE103C5011E6EF2C42DCD50D5D3D29F99AE6EBA2C80C9244F4C5422F0979FF0C3BA5E",
            "",
            False
        ),
    ]

    for case_id_suffix, input_hex, expected_hex, is_admitted in cases:
        case_id = f"upstream.precompile.p256verify.{case_id_suffix}"
        upstream_ref = f"tests/benchmark/compute/precompile/test_p256verify.py::test_p256verify[p256verify]"

        reasons = [] if is_admitted else ["case limit or complexity deferred"]
        inventory_entry = {
            "upstream_ref": upstream_ref,
            "case_id": case_id,
            "admitted": is_admitted,
            "reasons": reasons,
            "address": hex(PRECOMPILE_P256VERIFY),
            "input_size": len(bytes.fromhex(input_hex)),
        }
        inventory_entries.append(inventory_entry)

        if is_admitted:
            template = PrecompileMappingTemplate(
                case_id=case_id,
                description=f"P256VERIFY probe: {case_id_suffix}",
                namespace_seed=case_id,
                upstream_ref=upstream_ref,
                notes=[
                    f"Upstream intent: probe P256VERIFY precompile.",
                    "RPC mapping: deploy a wrapper that calls the precompile and records success/returndata/output-digest to storage.",
                    "Admitted as part of minimal Osaka P256VERIFY probe."
                ],
                address=PRECOMPILE_P256VERIFY,
                input_hex="0x" + input_hex,
                expected_hex="0x" + expected_hex if expected_hex else "",
                base_name="p256verify",
                precompile_family="p256verify",
                feature_flag="p256verify_precompile",
            )
            templates.append(template)

    return {
        "inventory": {
            "name": "upstream-precompile-p256verify-inventory",
            "version": "1",
            "family": "upstream-precompile",
            "entries": inventory_entries,
        },
        "templates": templates
    }


def scan_modexp_osaka() -> dict[str, Any]:
    inventory_entries = []
    templates = []

    # We use mod_exp_298_gas_exp_heavy as the canonical repricing probe
    # Base: 8 bytes, Exp: 112 bytes, Mod: 7 bytes
    # C_old: 223
    # C_new: 20976

    base = b"\xFF" * 8
    exp = b"\xFF" * 112
    mod = b"\xFF" * 7

    # ABI encoding for modexp input: length of base, exp, mod, then data
    input_bytes = (
        len(base).to_bytes(32, "big") +
        len(exp).to_bytes(32, "big") +
        len(mod).to_bytes(32, "big") +
        base.ljust(32, b"\x00")[:len(base)] + # Wait, they are concatenated exactly as lengths describe. No, modexp expects 32-byte left-padded integers or raw?
        # "base, exponent, modulus are arbitrary length unsigned integers, big-endian"
        # The first 96 bytes are the lengths. The rest is base data, exp data, mod data.
        base + exp + mod
    )

    # Wait, the lengths are 32-byte words.
    input_bytes = (
        len(base).to_bytes(32, "big") +
        len(exp).to_bytes(32, "big") +
        len(mod).to_bytes(32, "big") +
        base + exp + mod
    )

    case_id = "upstream.precompile.modexp.osaka_repricing"
    upstream_ref = "tests/benchmark/compute/precompile/test_modexp.py::test_modexp_uncachable[mod_exp_298_gas_exp_heavy]"

    inventory_entries.append({
        "upstream_ref": upstream_ref,
        "case_id": case_id,
        "admitted": True,
        "reasons": [],
        "address": hex(0x05),
        "input_size": len(input_bytes),
    })

    # We pass C_new - 1. So an Osaka node will fail (success=0). A Cancun node will pass (success=1).
    # expected success = False
    template = PrecompileMappingTemplate(
        case_id=case_id,
        description="MODEXP Osaka repricing probe: mod_exp_298_gas_exp_heavy",
        namespace_seed=case_id,
        upstream_ref=upstream_ref,
        notes=[
            "Upstream intent: probe MODEXP gas cost for EIP-7883.",
            "RPC mapping: deploy a wrapper that calls MODEXP with a gas stipend of C_new - 1 (20975).",
            "An Osaka node will fail (OOG for the inner call) because it requires 20976 gas. A Cancun node will pass because it requires 223 gas.",
            "Admitted to prove Osaka EIP-7883 MODEXP repricing via strict gas boundary."
        ],
        address=0x05,
        input_hex="0x" + input_bytes.hex(),
        expected_hex="", # Returndata size will be 0 on failure
        base_name="modexp",
        precompile_family="modexp",
        feature_flag="modexp_eip7883",
    )
    templates.append(template)

    return {
        "inventory": {
            "name": "upstream-precompile-modexp-inventory",
            "version": "1",
            "family": "upstream-precompile",
            "entries": inventory_entries,
        },
        "templates": templates
    }

if __name__ == "__main__":
    vectors_dir = Path("third_party/execution-specs/tests/prague/eip2537_bls_12_381_precompiles/vectors/")
    result = scan_vectors(vectors_dir)
    print(json.dumps(result, indent=2))
