import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from adapter.signer import keccak256
from adapter.assembler import _push_int, _build_init_code

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

ADMITTED_FILES = {
    "add_G1_bls.json",
    "pairing_check_bls.json",
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
}

def generate_precompile_wrapper(
    precompile_address: int, 
    input_bytes: bytes, 
    gas: int = 10_000_000
) -> str:
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
    
    runtime_code = b"".join(ops) + input_bytes
    return _build_init_code(runtime_code.hex())

def get_output_digest(expected_hex: str) -> str:
    if not expected_hex:
        return ""
    data = bytes.fromhex(expected_hex)
    return "0x" + keccak256(data).hex()

def scan_vectors(vectors_dir: Path) -> Dict[str, Any]:
    cases = []
    inventory_entries = []
    
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
                input_hex = item["Input"].removeprefix("0x")
                input_bytes = bytes.fromhex(input_hex)
                expected_hex = item.get("Expected", "").removeprefix("0x")
                
                init_code = generate_precompile_wrapper(address, input_bytes)
                
                # Deterministic storage expectations
                expected_storage = {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000000000000000000000000000001": "0x" + (len(expected_hex)//2).to_bytes(32, "big").hex(),
                }
                if expected_hex:
                    digest = get_output_digest(expected_hex)
                    expected_storage["0x0000000000000000000000000000000000000000000000000000000000000002"] = digest
                
                case = {
                    "kind": "upstream_mapped",
                    "case_id": case_id,
                    "family": "upstream-precompile",
                    "description": f"BLS12-381 {base_name} probe: {case_name}",
                    "filters": {
                        "requires_genesis_state": False,
                    },
                    "namespace_seed": case_id,
                    "steps": [
                        {
                            "action": "deploy_contract",
                            "bytecode_init": init_code,
                            "bytecode_runtime": "0x",
                            "gas": "0x989680",
                        },
                        {
                            "action": "invoke_contract",
                            "to": "deployed_contract_0",
                            "data": "0x",
                            "gas": "0x989680",
                        }
                    ],
                    "expected": {
                        "storage": {
                            "deployed_contract_0": expected_storage
                        }
                    },
                    "observe": {
                        "precompile_probe": {
                            "family": "bls12_381",
                            "precompile": base_name,
                            "address": hex(address),
                            "input_size": len(input_bytes),
                            "output_size": len(expected_hex)//2,
                            "expected_success": True,
                            "expected_output_digest": get_output_digest(expected_hex),
                            "required_feature": "bls12_381_precompiles"
                        }
                    },
                    "upstream_ref": upstream_ref
                }
                cases.append(case)
                
    return {
        "inventory": {
            "name": "upstream-precompile-bls12-381-inventory",
            "version": "1",
            "family": "upstream-precompile",
            "entries": inventory_entries,
        },
        "manifest": {
            "name": "upstream-precompile-mapped",
            "version": "1",
            "cases": cases,
        }
    }

if __name__ == "__main__":
    vectors_dir = Path("third_party/execution-specs/tests/prague/eip2537_bls_12_381_precompiles/vectors/")
    result = scan_vectors(vectors_dir)
    print(json.dumps(result, indent=2))
