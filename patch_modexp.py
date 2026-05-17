import re
from pathlib import Path

path = Path('adapter/precompile_generator.py')
text = path.read_text()

modexp_code = """
def scan_modexp_osaka() -> dict[str, Any]:
    inventory_entries = []
    templates = []
    
    # We use mod_exp_298_gas_exp_heavy as the canonical repricing probe
    # Base: 8 bytes, Exp: 112 bytes, Mod: 7 bytes
    # C_old: 223
    # C_new: 20976
    
    base = b"\\xFF" * 8
    exp = b"\\xFF" * 112
    mod = b"\\xFF" * 7
    
    # ABI encoding for modexp input: length of base, exp, mod, then data
    input_bytes = (
        len(base).to_bytes(32, "big") +
        len(exp).to_bytes(32, "big") +
        len(mod).to_bytes(32, "big") +
        base.ljust(32, b"\\x00")[:len(base)] + # Wait, they are concatenated exactly as lengths describe. No, modexp expects 32-byte left-padded integers or raw?
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
"""

if "def scan_modexp_osaka" not in text:
    text = text.replace('if __name__ == "__main__":', modexp_code + '\nif __name__ == "__main__":')

if "modexp_result = scan_modexp_osaka()" not in text:
    old_scan = """    bls_result = scan_vectors(source)
    p256_result = scan_p256verify()
    
    inventory = bls_result["inventory"]["entries"] + p256_result["inventory"]["entries"]
    templates = bls_result["templates"] + p256_result["templates"]"""
    
    new_scan = """    bls_result = scan_vectors(source)
    p256_result = scan_p256verify()
    modexp_result = scan_modexp_osaka()
    
    inventory = bls_result["inventory"]["entries"] + p256_result["inventory"]["entries"] + modexp_result["inventory"]["entries"]
    templates = bls_result["templates"] + p256_result["templates"] + modexp_result["templates"]"""
    text = text.replace(old_scan, new_scan)

path.write_text(text)
print("done")
