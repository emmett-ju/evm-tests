import unittest
import json
from pathlib import Path
from adapter.precompile_generator import scan_vectors, generate_precompile_wrapper
from adapter.signer import keccak256

class TestPrecompileGenerator(unittest.TestCase):
    def setUp(self):
        self.vectors_dir = Path("third_party/execution-specs/tests/prague/eip2537_bls_12_381_precompiles/vectors/")

    def test_precompile_generator_emits_minimal_bls_inventory(self):
        result = scan_vectors(self.vectors_dir)
        inventory = result["inventory"]
        templates = result["templates"]
        
        # Verify inventory
        self.assertEqual(inventory["family"], "upstream-precompile")
        
        # Count admitted cases
        admitted = [e for e in inventory["entries"] if e["admitted"]]
        # add_G1_bls.json (2) + pairing_check_bls.json (2) = 4
        self.assertEqual(len(admitted), 4)
        
        # Verify blocked reasons for some unadmitted cases
        blocked = [e for e in inventory["entries"] if not e["admitted"]]
        self.assertTrue(len(blocked) > 0)
        
        # Check reasons for a deferred precompile file
        msm_entry = next(e for e in inventory["entries"] if "msm_G1" in e["case_id"])
        self.assertIn("precompile msm_G1 deferred", msm_entry["reasons"])
        
        # Check reasons for case limit exceeded
        add_g1_2 = next(e for e in inventory["entries"] if "add_G1.2" in e["case_id"])
        self.assertIn("case limit exceeded for minimal probe", add_g1_2["reasons"])

        # Verify templates
        self.assertEqual(len(templates), 4)
        for template in templates:
            self.assertTrue(template.case_id.startswith("upstream.precompile.bls12_381"))
            self.assertEqual(template.address, 0x0B if "add_G1" in template.case_id else 0x11)

    def test_precompile_wrapper_runtime_and_storage_witness_are_deterministic(self):
        # Representative G1ADD case
        address = 0x0B
        input_bytes = bytes.fromhex("00" * 128)
        
        init_code1 = generate_precompile_wrapper(address, input_bytes)
        init_code2 = generate_precompile_wrapper(address, input_bytes)
        
        self.assertEqual(init_code1, init_code2)
        self.assertTrue(init_code1.startswith("0x"))
        
        # Check for specific opcodes in init_code (bytecode after init wrapper)
        # 0xF1 is CALL, 0x55 is SSTORE, 0x3D is RETURNDATASIZE, 0x20 is SHA3
        # The init wrapper is 0x60ac600c60003960ac6000f3 for this size
        runtime_hex = init_code1.split("6000f3")[1]
        self.assertIn("f1", runtime_hex) # CALL
        self.assertIn("55", runtime_hex) # SSTORE
        self.assertIn("3d", runtime_hex) # RETURNDATASIZE
        self.assertIn("20", runtime_hex) # SHA3 (if output exists)
        
        # Verify input is appended
        self.assertTrue(runtime_hex.endswith(input_bytes.hex()))

if __name__ == "__main__":
    unittest.main()
