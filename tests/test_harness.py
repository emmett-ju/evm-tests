from __future__ import annotations

from collections import Counter
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request

from adapter.assembler import _build_init_code
from adapter.bootstrap import StateBootstrapper
from adapter.cli import main
from adapter.env import load_dotenv
from adapter.executor import (
    BALANCE_RUNTIME,
    CODESIZE_RUNTIME,
    SELFBALANCE_RUNTIME,
    SYSTEM_FILL_FF_WORD,
    SYSTEM_RUNTIME_HEADER,
    SYSTEM_SELF_CALL_WRAPPER_SUFFIX,
    JsonRpcBackend,
    MockBackend,
    SystemExecutionError,
)
from adapter.generator import (
    generate_upstream_storage_manifest,
    generate_upstream_storage_templates,
    load_storage_templates,
)
from adapter.manifest import load_manifest
from adapter.memory_generator import (
    generate_upstream_memory_manifest,
    generate_upstream_memory_templates,
    load_memory_templates,
)
from adapter.precompile_generator import (
    generate_upstream_precompile_manifest,
    generate_upstream_precompile_templates,
    generate_precompile_wrapper,
    scan_vectors,
)
from adapter.account_query_generator import (
    _build_codecopy_fixed_runtime,
    generate_upstream_account_query_manifest,
    generate_upstream_account_query_templates,
    load_account_query_templates,
)
from adapter.call_context_generator import (
    generate_upstream_call_context_manifest,
    generate_upstream_call_context_templates,
    load_call_context_templates,
)
from adapter.block_context_generator import (
    generate_upstream_block_context_manifest,
    generate_upstream_block_context_templates,
)
from adapter.arithmetic_generator import (
    generate_upstream_arithmetic_manifest,
    generate_upstream_arithmetic_templates,
)
from adapter.bitwise_generator import (
    generate_upstream_bitwise_manifest,
    generate_upstream_bitwise_templates,
)
from adapter.comparison_generator import (
    generate_upstream_comparison_manifest,
    generate_upstream_comparison_templates,
)
from adapter.control_flow_generator import (
    generate_upstream_control_flow_manifest,
    generate_upstream_control_flow_templates,
    load_control_flow_templates,
)
from adapter.log_generator import NON_ZERO_TOPIC_WORD, derive_receipt_log_expectation, generate_upstream_log_manifest, generate_upstream_log_templates
from adapter.log_probe import validate_log_probe_declaration
from adapter.inventory import summarize_inventory_dir, write_inventory_payload
from adapter.keccak_generator import (
    compute_keccak_max_permutations_input_length,
    derive_upstream_keccak_witness_contract,
    generate_upstream_keccak_manifest,
    generate_upstream_keccak_templates,
    load_keccak_templates,
)
from adapter.stack_generator import (
    generate_upstream_stack_manifest,
    generate_upstream_stack_templates,
)
from adapter.system_generator import (
    generate_upstream_system_manifest,
    generate_upstream_system_templates,
)
from adapter.system_witness import (
    build_create_child_code_system_witness,
    build_create_empty_child_system_witness,
    collect_system_witness_from_storage,
    system_witness_storage_slots,
)
from adapter.tx_context_generator import (
    generate_upstream_tx_context_manifest,
    generate_upstream_tx_context_templates,
    load_tx_context_templates,
)
from adapter.models import ExecutionResult, Report
from adapter.oracle import ResultOracle
from adapter.profile import describe_admin_key_source, load_chain_profile
from adapter.report import durable_report_path, write_report
from adapter.selector import TestSelector
from adapter.signer import keccak256, private_key_to_address, sign_type_2_transaction
from scripts.assert_report_success import main as assert_report_success_main
from scripts.summarize_rpc_reports import main as summarize_rpc_reports_main
from scripts.sync_upstream_artifacts import FAMILY_SPECS, sync_to_staging


ROOT = Path(__file__).resolve().parents[1]


class HarnessTests(unittest.TestCase):
    def test_precompile_checked_in_artifacts_match_generated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            template_path = tmpdir_path / "templates.json"
            inventory_path = tmpdir_path / "inventory.json"
            manifest_path = tmpdir_path / "manifest.json"

            # Generate
            generate_upstream_precompile_templates(
                repo_root=ROOT,
                output_path=template_path,
                inventory_path=inventory_path,
            )
            generate_upstream_precompile_manifest(
                repo_root=ROOT,
                output_path=manifest_path,
                template_path=template_path,
            )

            # Compare templates
            checked_in_templates = json.loads((ROOT / "suites/templates/upstream_precompile_templates.json").read_text())
            generated_templates = json.loads(template_path.read_text())
            self.assertEqual(generated_templates, checked_in_templates)

            # Compare inventory
            checked_in_inventory = json.loads((ROOT / "suites/templates/upstream_precompile_inventory.json").read_text())
            generated_inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated_inventory, checked_in_inventory)

            # Compare manifest
            checked_in_manifest = json.loads((ROOT / "suites/manifests/upstream_precompile_mapped.json").read_text())
            generated_manifest = json.loads(manifest_path.read_text())
            self.assertEqual(generated_manifest, checked_in_manifest)

    def test_cli_scan_upstream_precompile_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            template_path = tmpdir_path / "templates.json"
            inventory_path = tmpdir_path / "inventory.json"
            
            # Execute CLI
            exit_code = main([
                "scan-upstream-precompile",
                "--template-output", str(template_path),
                "--inventory-output", str(inventory_path),
            ])
            self.assertEqual(exit_code, 0)
            
            # Verify files exist and are valid JSON
            self.assertTrue(template_path.exists())
            self.assertTrue(inventory_path.exists())
            json.loads(template_path.read_text())
            json.loads(inventory_path.read_text())

    def test_precompile_generator_emits_minimal_bls_inventory(self):
        vectors_dir = ROOT / "third_party/execution-specs/tests/prague/eip2537_bls_12_381_precompiles/vectors/"
        result = scan_vectors(vectors_dir)
        inventory = result["inventory"]
        templates = result["templates"]
        
        # Verify inventory
        self.assertEqual(inventory["family"], "upstream-precompile")
        
        # Count admitted cases
        admitted = [e for e in inventory["entries"] if e["admitted"]]
        # add_G1_bls.json (2) + pairing_check_bls.json (2) = 4
        self.assertEqual(len(admitted), 4)
        
        # Verify manifest (templates in this context)
        self.assertEqual(len(templates), 4)
        for template in templates:
            self.assertIn("BLS12-381", template.description)

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
        runtime_hex = init_code1.split("6000f3")[1]
        self.assertIn("f1", runtime_hex) # CALL
        self.assertIn("55", runtime_hex) # SSTORE
        self.assertIn("3d", runtime_hex) # RETURNDATASIZE
        
        # Verify input is appended
        self.assertTrue(runtime_hex.endswith(input_bytes.hex()))

    def test_build_init_code_preserves_short_runtime_encoding_and_supports_long_runtime(self) -> None:
        self.assertEqual(_build_init_code("0x00"), "0x6001600c60003960016000f300")
        long_runtime = "0x" + "00" * 300
        self.assertTrue(_build_init_code(long_runtime).startswith("0x61012c600e60003961012c6000f3"))

    def test_load_dotenv_sets_missing_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / ".env"
            env_path.write_text("DOTENV_SAMPLE=value\n")
            os.environ.pop("DOTENV_SAMPLE", None)
            self.assertTrue(load_dotenv(env_path))
            self.assertEqual(os.environ["DOTENV_SAMPLE"], "value")
            os.environ.pop("DOTENV_SAMPLE", None)

    def test_profile_load_and_validate(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/mock.toml")
        self.assertEqual(profile.name, "mock-devnet")
        self.assertEqual(profile.namespace_policy.prefix, "evmtest")
        self.assertEqual(profile.backend, "mock")
        self.assertTrue(profile.supports_feature("clz"))
        self.assertFalse(profile.supports_feature("bls12_381_precompiles"))
        self.assertFalse(profile.supports_feature("p256verify_precompile"))
        self.assertFalse(profile.supports_feature("modexp_eip7883"))
        self.assertFalse(profile.supports_feature("calldata_floor_eip7623"))
        self.assertFalse(profile.supports_feature("eip7702"))
        self.assertFalse(profile.supports_feature("blob_cell_proofs"))
        self.assertFalse(profile.supports_feature("block_access_lists"))

    def test_real_rpc_profile_defaults_to_jsonrpc_backend(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        self.assertEqual(profile.name, "juchain-testnet")
        self.assertEqual(profile.backend, "jsonrpc")
        self.assertEqual(describe_admin_key_source(profile), "env_private_key")

    def test_juchain_profile_enables_clz_without_changing_hardfork(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        self.assertEqual(profile.hardfork, "cancun")
        self.assertTrue(profile.supports_feature("clz"))
        self.assertFalse(profile.supports_feature("bls12_381_precompiles"))
        self.assertFalse(profile.supports_feature("p256verify_precompile"))
        self.assertFalse(profile.supports_feature("modexp_eip7883"))

    def test_selector_filters_block_control_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/mock.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_smoke.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual([case.case_id for case in selected], ["upstream.storage.basic"])
        blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(blocked["upstream.block.control"], ["requires block environment control"])

    def test_selector_filters_mock_only_actions_for_jsonrpc_profiles(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/custom_storage_smoke.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(selected, [])
        blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(
            blocked["custom.balance.and.storage"],
            [
                "case custom.balance.and.storage step 1: action 'set_balance' is mock-only and not runnable on jsonrpc backend",
                "case custom.balance.and.storage step 2: action 'set_storage' is mock-only and not runnable on jsonrpc backend",
                "contains mock-only actions not runnable on jsonrpc backend: set_balance, set_storage",
            ],
        )

    def test_selector_rejects_jsonrpc_profile_when_manifest_contains_mock_only_actions(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.account_query.codesize.success"
        )
        broken_case.steps.insert(0, {"action": "set_balance", "value": "0x1"})
        decision = TestSelector(profile).decide(broken_case)
        self.assertFalse(decision.selected)
        self.assertEqual(
            decision.reasons,
            [
                "case upstream.benchmark.account_query.codesize.success step 1: action 'set_balance' is mock-only and not runnable on jsonrpc backend",
                "contains mock-only actions not runnable on jsonrpc backend: set_balance",
            ],
        )

    def test_load_manifest_rejects_missing_required_case_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "broken.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "name": "broken",
                        "version": "1",
                        "execution_specs_ref": "submodule-pending",
                        "suite_version": "0.1.0",
                        "chain_profile_version": "1",
                        "cases": [
                            {
                                "kind": "custom_chain",
                                "family": "custom/smoke",
                                "description": "missing case id",
                                "namespace_seed": "missing-case-id",
                                "steps": [],
                                "expected": {},
                            }
                        ],
                    }
                )
            )
            with self.assertRaisesRegex(
                ValueError,
                r"manifest case 1\.case_id is required and must be a non-empty string",
            ):
                load_manifest(manifest_path)

    def test_load_manifest_rejects_non_list_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "broken.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "name": "broken",
                        "version": "1",
                        "execution_specs_ref": "submodule-pending",
                        "suite_version": "0.1.0",
                        "chain_profile_version": "1",
                        "cases": [
                            {
                                "kind": "custom_chain",
                                "case_id": "broken.steps",
                                "family": "custom/smoke",
                                "description": "steps has wrong type",
                                "namespace_seed": "broken-steps",
                                "steps": {"action": "set_balance", "value": "0x1"},
                                "expected": {},
                            }
                        ],
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, r"case broken\.steps: steps must be a list"):
                load_manifest(manifest_path)

    def test_load_manifest_rejects_unsupported_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "broken.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "name": "broken",
                        "version": "1",
                        "execution_specs_ref": "submodule-pending",
                        "suite_version": "0.1.0",
                        "chain_profile_version": "1",
                        "cases": [
                            {
                                "kind": "custom_chain",
                                "case_id": "broken.unsupported-action",
                                "family": "custom/smoke",
                                "description": "uses unsupported action",
                                "namespace_seed": "broken-unsupported-action",
                                "steps": [{"action": "explode", "value": "0x1"}],
                                "expected": {},
                            }
                        ],
                    }
                )
            )
            with self.assertRaisesRegex(
                ValueError,
                r"case broken\.unsupported-action step 1: unsupported action 'explode'",
            ):
                load_manifest(manifest_path)

    def test_load_manifest_rejects_malformed_deploy_contract_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "broken.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "name": "broken",
                        "version": "1",
                        "execution_specs_ref": "submodule-pending",
                        "suite_version": "0.1.0",
                        "chain_profile_version": "1",
                        "cases": [
                            {
                                "kind": "custom_chain",
                                "case_id": "broken.deploy-shape",
                                "family": "custom/smoke",
                                "description": "missing bytecode_runtime",
                                "namespace_seed": "broken-deploy-shape",
                                "steps": [
                                    {
                                        "action": "deploy_contract",
                                        "bytecode_init": "0x6000",
                                    }
                                ],
                                "expected": {},
                            }
                        ],
                    }
                )
            )
            with self.assertRaisesRegex(
                ValueError,
                r"case broken\.deploy-shape step 1: action 'deploy_contract' is missing required fields: bytecode_runtime",
            ):
                load_manifest(manifest_path)

    def test_validation_boundary_accepts_current_checked_in_family_shape_manifests(self) -> None:
        scenarios = [
            {
                "manifest_path": ROOT / "suites/manifests/custom_storage_smoke.json",
                "profile": load_chain_profile(ROOT / "profiles/mock.toml"),
                "expected_case_ids": ["custom.balance.and.storage"],
                "expected_rejections": {},
            },
            {
                "manifest_path": ROOT / "suites/manifests/upstream_block_context_mapped.json",
                "profile": load_chain_profile(ROOT / "profiles/juchain.toml"),
                "expected_case_ids": [
                    "upstream.benchmark.block_context.test_block_context_ops.basefee",
                    "upstream.benchmark.block_context.test_block_context_ops.chainid",
                    "upstream.benchmark.block_context.test_block_context_ops.coinbase",
                    "upstream.benchmark.block_context.test_block_context_ops.gaslimit",
                    "upstream.benchmark.block_context.test_block_context_ops.number",
                    "upstream.benchmark.block_context.test_block_context_ops.timestamp",
                    "upstream.benchmark.block_context.test_blockhash.current_block",
                ],
                "expected_rejections": {
                    "upstream.benchmark.block_context.test_block_context_ops.prevrandao": [
                        "block-context mode prevrandao requires feature_flags.prevrandao=true in chain profile"
                    ]
                },
            },
            {
                "manifest_path": ROOT / "suites/manifests/upstream_log_mapped.json",
                "profile": load_chain_profile(ROOT / "profiles/mock.toml"),
                "expected_case_ids": None,
                "expected_rejections": {},
            },
            {
                "manifest_path": ROOT / "suites/manifests/upstream_system_mapped.json",
                "profile": load_chain_profile(ROOT / "profiles/mock.toml"),
                "expected_case_ids": None,
                "expected_rejections": {},
            },
        ]

        for scenario in scenarios:
            with self.subTest(manifest=scenario["manifest_path"].name):
                manifest = load_manifest(scenario["manifest_path"])
                selected, decisions = TestSelector(scenario["profile"]).select(manifest)
                self.assertEqual(manifest.validation_errors(scenario["profile"].backend), [])
                blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
                self.assertEqual(blocked, scenario["expected_rejections"])
                self.assertEqual([case.case_id for case in selected], scenario["expected_case_ids"] or [case.case_id for case in manifest.cases])
                self.assertEqual(len(selected), len(manifest.cases) - len(scenario["expected_rejections"]))

    def test_validation_boundary_rejects_malformed_block_context_manifest_shape(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_block_context_mapped.json").read_text())
        payload["cases"][0]["steps"][0].pop("bytecode_runtime")
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_block_context_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "case upstream.benchmark.block_context.test_block_context_ops.basefee step 1: action 'deploy_contract' is missing required fields: bytecode_runtime",
        )

    def test_validation_boundary_rejects_malformed_log_manifest_shape(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_log_mapped.json").read_text())
        target_case = next(
            case
            for case in payload["cases"]
            if case["case_id"]
            == "upstream.benchmark.log.test_log.log0.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true"
        )
        target_case["steps"][3]["timeout_seconds"] = "60"
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_log_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "case upstream.benchmark.log.test_log.log0.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true step 4: action 'wait_receipt' field 'timeout_seconds' must be an integer",
        )

    def test_validation_boundary_rejects_malformed_log_probe_declaration_at_load_time(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_log_mapped.json").read_text())
        target_case = next(
            case
            for case in payload["cases"]
            if case["case_id"]
            == "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true"
        )
        target_case["observe"]["log_probe"]["opcode"] = "LOG0"
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_log_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.log_probe.topic_count does not match opcode LOG0: expected 0, got 1",
        )

    def test_validate_log_probe_declaration_rejects_non_integer_topic_count(self) -> None:
        with self.assertRaisesRegex(ValueError, "observe.log_probe.topic_count must be an integer"):
            validate_log_probe_declaration(
                {
                    "opcode": "LOG1",
                    "topic_count": "1",
                    "topic_word": "0x" + "00" * 32,
                    "log_size": 0,
                    "memory_seed_kind": "zero",
                    "memory_seed_size": 0,
                    "witness_mode": "exact",
                }
            )

    def test_validation_boundary_rejects_malformed_system_manifest_shape(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["steps"][2]["data"] = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "case upstream.benchmark.system.test_create.create.0_bytes_with_value step 3: action 'invoke_contract' field 'data' must be a string",
        )

    def test_validation_boundary_rejects_malformed_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"]["shape"] = "bogus_system_shape"
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.system_witness.shape must be one of ['create_child_code', 'create_collision', 'create_empty_child', 'return_revert_self_call', 'selfdestruct_single']; unsupported system witness shape: 'bogus_system_shape'",
        )

    def test_validation_boundary_accepts_create_empty_child_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_empty_child",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 0,
            "salt": 42,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            manifest = load_manifest(manifest_path)
        self.assertEqual(manifest.cases[0].observe["system_witness"]["shape"], "create_empty_child")

    def test_validation_boundary_accepts_value_bearing_create_empty_child_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_empty_child",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 1,
            "initcode_size": 0,
            "salt": 42,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            manifest = load_manifest(manifest_path)
        self.assertEqual(manifest.cases[0].observe["system_witness"]["value"], 1)
        bundle = build_create_empty_child_system_witness(opcode="CREATE", value=1)
        self.assertEqual(
            bundle.expected["system_witness"],
            {
                "shape": "create_empty_child",
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": 0,
                "created_balance": 1,
            },
        )

    def test_validation_boundary_rejects_malformed_create_empty_child_system_witness(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_empty_child",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 2,
            "initcode_size": 0,
            "salt": 42,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.system_witness.value must be 0 or 1 for create_empty_child",
        )

    def test_validation_boundary_rejects_create_empty_child_create_with_salt(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_empty_child",
            "subject": "$last_contract",
            "opcode": "CREATE",
            "value": 0,
            "initcode_size": 0,
            "salt": 42,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.system_witness.salt must be omitted for CREATE create_empty_child",
        )

    def test_validation_boundary_rejects_missing_system_witness_subject(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"]["subject"] = ""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.system_witness.subject is required and must be a non-empty string",
        )

    def test_validation_boundary_accepts_create_child_code_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_child_code",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 6144,
            "data_kind": "zero",
            "salt": 42,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            manifest = load_manifest(manifest_path)
        self.assertEqual(manifest.cases[0].observe["system_witness"]["shape"], "create_child_code")
        bundle = build_create_child_code_system_witness(opcode="CREATE", initcode_size=6144, data_kind="zero")
        self.assertEqual(
            bundle.expected["system_witness"],
            {
                "shape": "create_child_code",
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": 6144,
                "created_code_hash": "0x" + keccak256(b"\x00" * 6144).hex(),
            },
        )

    def test_validation_boundary_accepts_non_zero_create_child_code_system_witness(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_child_code",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 6144,
            "data_kind": "non_zero",
            "salt": 42,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            manifest = load_manifest(manifest_path)
        self.assertEqual(manifest.cases[0].observe["system_witness"]["data_kind"], "non_zero")

        for size, prefix_hex in ((6144, "611800805f5f395ff3"), (12288, "613000805f5f395ff3"), (18432, "614800805f5f395ff3"), (24576, "616000805f5f395ff3")):
            non_zero_bundle = build_create_child_code_system_witness(opcode="CREATE", initcode_size=size, data_kind="non_zero")
            zero_bundle = build_create_child_code_system_witness(opcode="CREATE", initcode_size=size, data_kind="zero")
            non_zero_child_prefix = bytes.fromhex(prefix_hex)
            non_zero_child_code = non_zero_child_prefix + bytes(index % 256 for index in range(size - len(non_zero_child_prefix)))
            self.assertEqual(
                non_zero_bundle.expected["system_witness"],
                {
                    "shape": "create_child_code",
                    "success": True,
                    "created_address_nonzero": True,
                    "created_code_size": size,
                    "created_code_hash": "0x" + keccak256(non_zero_child_code).hex(),
                },
            )
            self.assertNotEqual(
                non_zero_bundle.expected["system_witness"]["created_code_hash"],
                zero_bundle.expected["system_witness"]["created_code_hash"],
            )

    def test_validation_boundary_rejects_malformed_create_child_code_system_witness(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_child_code",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 6144,
            "data_kind": "random",
            "salt": 42,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.system_witness.data_kind must be 'zero' or 'non_zero' for create_child_code",
        )

    def test_validation_boundary_accepts_create_collision_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_collision",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 0,
            "salt": 0,
            "proxy_call_gas": 100000,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            manifest = load_manifest(manifest_path)
        self.assertEqual(manifest.cases[0].observe["system_witness"]["shape"], "create_collision")
        from adapter.system_witness import build_create_collision_system_witness

        bundle = build_create_collision_system_witness(opcode="CREATE2", salt=0, proxy_call_gas=100000)
        self.assertEqual(
            bundle.expected["system_witness"],
            {
                "shape": "create_collision",
                "proxy_deploy_success": True,
                "first_create_call_success": True,
                "first_created_address_nonzero": True,
                "first_created_code_size": 0,
                "collision_call_success": False,
                "collision_returndata_size": 0,
            },
        )

    def test_validation_boundary_rejects_create_collision_create_opcode(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "create_collision",
            "subject": "$last_contract",
            "opcode": "CREATE",
            "value": 0,
            "initcode_size": 0,
            "proxy_call_gas": 100000,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.system_witness.opcode must be 'CREATE2' for create_collision under the RPC-only proof model",
        )

    def test_validation_boundary_accepts_selfdestruct_single_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "selfdestruct_single",
            "subject": "$last_contract",
            "scenario": "created",
            "value": 1,
            "hardfork_semantics": "cancun",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            manifest = load_manifest(manifest_path)
        self.assertEqual(manifest.cases[0].observe["system_witness"]["shape"], "selfdestruct_single")
        from adapter.system_witness import build_selfdestruct_single_system_witness

        bundle = build_selfdestruct_single_system_witness(scenario="created", value=1)
        self.assertEqual(
            bundle.expected["system_witness"],
            {
                "shape": "selfdestruct_single",
                "scenario": "created",
                "create_success": True,
                "child_address_nonzero": True,
                "selfdestruct_call_success": True,
                "child_code_size_after": 0,
                "beneficiary_balance_after": 1,
            },
        )

    def test_validation_boundary_accepts_selfdestruct_existing_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "selfdestruct_single",
            "subject": "$last_contract",
            "scenario": "existing",
            "value": 1,
            "hardfork_semantics": "cancun",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            manifest = load_manifest(manifest_path)
        self.assertEqual(manifest.cases[0].observe["system_witness"]["scenario"], "existing")
        from adapter.system_witness import build_selfdestruct_single_system_witness

        bundle = build_selfdestruct_single_system_witness(scenario="existing", value=1)
        self.assertEqual(
            bundle.expected["system_witness"],
            {
                "shape": "selfdestruct_single",
                "scenario": "existing",
                "setup_create_success": True,
                "child_address_nonzero": True,
                "child_code_size_before": 2,
                "selfdestruct_call_success": True,
                "child_code_size_after": 2,
                "beneficiary_balance_after": 1,
            },
        )

    def test_validation_boundary_rejects_selfdestruct_initcode_system_witness_declaration(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
        payload["cases"][0]["observe"]["system_witness"] = {
            "version": 1,
            "shape": "selfdestruct_single",
            "subject": "$last_contract",
            "scenario": "initcode",
            "value": 0,
            "hardfork_semantics": "cancun",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError) as error:
                load_manifest(manifest_path)
        self.assertEqual(
            str(error.exception),
            "observe.system_witness.scenario must be 'created' or 'existing' for selfdestruct_single; unsupported scenario: 'initcode'",
        )

    def test_selector_allows_real_jsonrpc_smoke_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/juchain_smoke.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual([case.case_id for case in selected], ["juchain.self-transfer.receipt"])
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_real_jsonrpc_deploy_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/juchain_deploy_smoke.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual([case.case_id for case in selected], ["juchain.deploy.stop-contract"])
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_real_jsonrpc_storage_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/juchain_storage_smoke.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual([case.case_id for case in selected], ["juchain.deploy-and-store.slot0"])
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_storage_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_storage_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.storage.read.present_slots.success",
                "upstream.benchmark.storage.write_new_value.present_slots.out_of_gas",
                "upstream.benchmark.storage.write_new_value.present_slots.revert",
                "upstream.benchmark.storage.write_new_value.present_slots.success",
                "upstream.benchmark.storage.write_same_value.present_slots.out_of_gas",
                "upstream.benchmark.storage.write_same_value.present_slots.revert",
                "upstream.benchmark.storage.write_same_value.present_slots.success",
                "upstream.benchmark.storage.read.absent_slots.success",
                "upstream.benchmark.storage.write_new_value.absent_slots.out_of_gas",
                "upstream.benchmark.storage.write_new_value.absent_slots.revert",
                "upstream.benchmark.storage.write_new_value.absent_slots.success",
                "upstream.benchmark.storage.write_same_value.absent_slots.out_of_gas",
                "upstream.benchmark.storage.write_same_value.absent_slots.revert",
                "upstream.benchmark.storage.write_same_value.absent_slots.success",
                "upstream.benchmark.storage.warm.read.present_slots.success",
                "upstream.benchmark.storage.warm.write_new_value.present_slots.success",
                "upstream.benchmark.storage.warm.write_same_value.present_slots.success",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        warm_new_case = next(
            case
            for case in selected
            if case.case_id == "upstream.benchmark.storage.warm.write_new_value.present_slots.success"
        )
        deploy_step = next(step for step in warm_new_case.steps if step["action"] == "deploy_contract")
        self.assertTrue(deploy_step["bytecode_init"].endswith("602b60005500"))
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_memory_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_memory_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(len(selected), 125)
        selected_ids = [case.case_id for case in selected]
        self.assertIn("upstream.benchmark.memory.mstore.offset_0.uninitialized.mem_size_0.success", selected_ids)
        self.assertIn("upstream.benchmark.memory.msize.mem_size_1.success", selected_ids)
        self.assertIn("upstream.benchmark.memory.mcopy.mem_size_0.copy_size_32.fixed.success", selected_ids)
        mcopy_256_case = next(
            case
            for case in selected
            if case.case_id == "upstream.benchmark.memory.mcopy.mem_size_0.copy_size_256.fixed.success"
        )
        invoke_step = next(step for step in mcopy_256_case.steps if step["action"] == "invoke_contract")
        self.assertEqual(invoke_step["gas"], "0x030d40")
        self.assertIn("upstream.benchmark.memory.mcopy.mem_size_1024.copy_size_0.dynamic.success", selected_ids)
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_stack_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_stack_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(len(selected), 65)
        selected_ids = [case.case_id for case in selected]
        self.assertIn("upstream.benchmark.stack.test_push.push0", selected_ids)
        self.assertIn("upstream.benchmark.stack.test_push.push32", selected_ids)
        self.assertIn("upstream.benchmark.stack.test_dup.dup16", selected_ids)
        self.assertIn("upstream.benchmark.stack.test_swap.swap16", selected_ids)
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_bitwise_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/mock.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_bitwise_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(len(selected), 12)
        selected_ids = [case.case_id for case in selected]
        self.assertIn("upstream.benchmark.bitwise.test_bitwise.and", selected_ids)
        self.assertIn("upstream.benchmark.bitwise.test_clz_diff.clz", selected_ids)
        self.assertIn("upstream.benchmark.bitwise.test_clz_same.clz", selected_ids)
        self.assertIn("upstream.benchmark.bitwise.test_shifts.shr", selected_ids)
        self.assertIn("upstream.benchmark.bitwise.test_shifts.sar", selected_ids)
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/bitwise"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_selects_juchain_bitwise_clz_cases_when_feature_flag_enabled(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_bitwise_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        selected_ids = [case.case_id for case in selected]
        self.assertEqual(len(selected), 12)
        self.assertEqual(len(selected_ids), len(set(selected_ids)))
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/bitwise"})
        self.assertIn("upstream.benchmark.bitwise.test_clz_diff.clz", selected_ids)
        self.assertIn("upstream.benchmark.bitwise.test_clz_same.clz", selected_ids)
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_rejects_clz_bitwise_cases_when_profile_lacks_feature_flag(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/mock.toml")
        profile.feature_flags["clz"] = False
        manifest = load_manifest(ROOT / "suites/manifests/upstream_bitwise_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        selected_ids = [case.case_id for case in selected]
        all_ids = {case.case_id for case in manifest.cases}
        blocked_ids = {decision.case.case_id for decision in decisions if not decision.selected}
        expected_clz_ids = {
            "upstream.benchmark.bitwise.test_clz_diff.clz",
            "upstream.benchmark.bitwise.test_clz_same.clz",
        }
        self.assertEqual(len(selected), 10)
        self.assertEqual(len(selected_ids), len(set(selected_ids)))
        self.assertEqual(all_ids - set(selected_ids), expected_clz_ids)
        self.assertEqual(blocked_ids, expected_clz_ids)
        self.assertIn("upstream.benchmark.bitwise.test_bitwise.and", selected_ids)
        self.assertIn("upstream.benchmark.bitwise.test_shifts.shr", selected_ids)
        self.assertIn("upstream.benchmark.bitwise.test_shifts.sar", selected_ids)
        self.assertNotIn("upstream.benchmark.bitwise.test_clz_diff.clz", selected_ids)
        self.assertNotIn("upstream.benchmark.bitwise.test_clz_same.clz", selected_ids)
        blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(
            blocked,
            {
                "upstream.benchmark.bitwise.test_clz_diff.clz": [
                    "bitwise opcode CLZ requires feature_flags.clz=true in chain profile"
                ],
                "upstream.benchmark.bitwise.test_clz_same.clz": [
                    "bitwise opcode CLZ requires feature_flags.clz=true in chain profile"
                ],
            },
        )

    def test_selector_allows_upstream_mapped_arithmetic_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_arithmetic_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(len(selected), 65)
        selected_ids = [case.case_id for case in selected]
        self.assertIn("upstream.benchmark.arithmetic.test_arithmetic.add.base.arity_2", selected_ids)
        self.assertIn("upstream.benchmark.arithmetic.test_arithmetic.signextend.base.arity_2", selected_ids)
        self.assertIn("upstream.benchmark.arithmetic.test_mod_arithmetic.mulmod.mod_bits_255", selected_ids)
        self.assertIn("upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_136279841.base_136279841", selected_ids)
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/arithmetic"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_comparison_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_comparison_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.comparison.test_comparison.eq",
                "upstream.benchmark.comparison.test_comparison.gt",
                "upstream.benchmark.comparison.test_comparison.lt",
                "upstream.benchmark.comparison.test_comparison.sgt",
                "upstream.benchmark.comparison.test_comparison.slt",
                "upstream.benchmark.comparison.test_iszero.iszero",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/comparison"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_call_context_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_call_context_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.call_context.address.success",
                "upstream.benchmark.call_context.caller.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_0.nonzero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_1024.nonzero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_256.nonzero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_32.nonzero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_0.zero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_1024.zero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_256.zero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_32.zero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_0.nonzero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_1024.nonzero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_256.nonzero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_32.nonzero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_0.zero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_1024.zero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_256.zero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_32.zero.success",
                "upstream.benchmark.call_context.callvalue.origin.zero.success",
                "upstream.benchmark.call_context.callvalue.origin.nonzero.success",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_tx_context_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_tx_context_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.tx_context.gasprice.success",
                "upstream.benchmark.tx_context.origin.success",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_account_query_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        codecopy_case_ids = [
            "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_bytes.success",
            "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_25x_max_code_size.success",
            "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_50x_max_code_size.success",
            "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_75x_max_code_size.success",
            "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_max_code_size.success",
        ]
        self.assertEqual(
            [case.case_id for case in selected],
            codecopy_case_ids
            + [
                "upstream.benchmark.account_query.codesize.success",
                "upstream.benchmark.account_query.balance.cold.present_accounts.success",
                "upstream.benchmark.account_query.balance.cold.absent_accounts.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_0.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_1.success",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])
        allowed_runtimes = {
            CODESIZE_RUNTIME,
            BALANCE_RUNTIME,
            SELFBALANCE_RUNTIME,
            *{_build_codecopy_fixed_runtime(size) for size in (0, 6144, 12288, 18432, 24576)},
        }
        self.assertEqual(
            {case.steps[0]["bytecode_runtime"] for case in selected if case.steps and case.steps[0]["action"] == "deploy_contract"},
            allowed_runtimes,
        )
        for case in selected:
            step_actions = [step["action"] for step in case.steps]
            self.assertNotIn("set_balance", step_actions)
            self.assertNotIn("set_storage", step_actions)
            self.assertNotIn("set_code", step_actions)
            deploy_steps = [step for step in case.steps if step["action"] == "deploy_contract"]
            self.assertEqual(len(deploy_steps), 1)
            self.assertIn(deploy_steps[0]["bytecode_runtime"], allowed_runtimes)

    def test_selector_allows_upstream_mapped_system_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.system.test_create.create.0_bytes_with_value",
                "upstream.benchmark.system.test_create.create.0_bytes_without_value",
                "upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_bytes_with_value",
                "upstream.benchmark.system.test_create.create2.0_bytes_without_value",
                "upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_return_revert.return.1kib_of_non_zero_data",
                "upstream.benchmark.system.test_return_revert.return.1kib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.return.empty",
                "upstream.benchmark.system.test_return_revert.revert.1kib_of_non_zero_data",
                "upstream.benchmark.system.test_return_revert.revert.1kib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.revert.1mib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.revert.empty",
                "upstream.benchmark.system.test_selfdestruct_existing.value_bearing_false",
                "upstream.benchmark.system.test_selfdestruct_existing.value_bearing_true",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/system"})
        skipped = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(
            skipped,
            {
                "upstream.benchmark.system.test_create.create.max_code_size_with_non_zero_data": [
                    "max CREATE child-code payload requires feature_flags.max_create_child_code=true in chain profile"
                ],
                "upstream.benchmark.system.test_create.create.max_code_size_with_zero_data": [
                    "max CREATE child-code payload requires feature_flags.max_create_child_code=true in chain profile"
                ],
                "upstream.benchmark.system.test_create.create2.max_code_size_with_non_zero_data": [
                    "max CREATE child-code payload requires feature_flags.max_create_child_code=true in chain profile"
                ],
                "upstream.benchmark.system.test_create.create2.max_code_size_with_zero_data": [
                    "max CREATE child-code payload requires feature_flags.max_create_child_code=true in chain profile"
                ],
                "upstream.benchmark.system.test_creates_collisions.create2": [
                    "CREATE collision witness requires feature_flags.create_collision=true in chain profile"
                ],
                "upstream.benchmark.system.test_return_revert.return.1mib_of_non_zero_data": [
                    "1MiB non-zero returndata requires feature_flags.large_nonzero_returndata=true in chain profile"
                ],
                "upstream.benchmark.system.test_return_revert.revert.1mib_of_non_zero_data": [
                    "1MiB non-zero returndata requires feature_flags.large_nonzero_returndata=true in chain profile"
                ],
                "upstream.benchmark.system.test_selfdestruct_created.value_bearing_false": [
                    "created-contract selfdestruct cleanup requires feature_flags.selfdestruct_created_clears_code=true in chain profile"
                ],
                "upstream.benchmark.system.test_selfdestruct_created.value_bearing_true": [
                    "created-contract selfdestruct cleanup requires feature_flags.selfdestruct_created_clears_code=true in chain profile"
                ],
            },
        )
        for case in selected:
            self.assertEqual(case.expected["receipt_status"], "0x1")
            witness = case.observe["system_witness"]
            expected_witness = case.expected["system_witness"]
            if case.case_id.startswith("upstream.benchmark.system.test_create"):
                if witness["shape"] == "create_empty_child":
                    self.assertEqual(expected_witness["shape"], "create_empty_child")
                    if witness["value"] > 0:
                        self.assertEqual(set(expected_witness), {"shape", "success", "created_address_nonzero", "created_code_size", "created_balance"})
                    else:
                        self.assertEqual(set(expected_witness), {"shape", "success", "created_address_nonzero", "created_code_size"})
                elif witness["shape"] == "create_child_code":
                    self.assertEqual(expected_witness["shape"], "create_child_code")
                    self.assertEqual(set(expected_witness), {"shape", "success", "created_address_nonzero", "created_code_size", "created_code_hash"})
                else:
                    self.assertEqual(witness["shape"], "create_collision")
                    self.assertEqual(expected_witness["shape"], "create_collision")
                    self.assertEqual(set(expected_witness), {"shape", "proxy_deploy_success", "first_create_call_success", "first_created_address_nonzero", "first_created_code_size", "collision_call_success", "collision_returndata_size"})
            elif witness["shape"] == "selfdestruct_single":
                self.assertEqual(expected_witness["shape"], "selfdestruct_single")
                expected_fields = {"shape", "scenario", "child_address_nonzero", "selfdestruct_call_success", "child_code_size_after"}
                if witness["scenario"] == "existing":
                    expected_fields.update({"setup_create_success", "child_code_size_before"})
                else:
                    expected_fields.add("create_success")
                if witness["value"] > 0:
                    expected_fields.add("beneficiary_balance_after")
                self.assertEqual(set(expected_witness), expected_fields)
            else:
                self.assertEqual(
                    witness,
                    {
                        "version": 1,
                        "shape": "return_revert_self_call",
                        "subject": "$last_contract",
                    },
                )
                self.assertEqual(set(expected_witness), {"shape", "success", "returndata_size", "returndata_digest"})
        self.assertFalse(
            any(
                "test_selfdestruct_initcode" in case.case_id
                or "test_contract_calling_many_addresses" in case.case_id
                or case.case_id == "upstream.benchmark.system.test_creates_collisions.create"
                for case in selected
            )
        )

    def test_selector_allows_upstream_mapped_system_subset_cases(self) -> None:
        self.test_selector_allows_upstream_mapped_system_cases()

    def test_selector_allows_upstream_mapped_keccak_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_keccak_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(len(selected), 35)
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/keccak"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])
        selected_ids = [case.case_id for case in selected]
        self.assertIn("upstream.benchmark.keccak.test_keccak_max_permutations", selected_ids)
        self.assertIn("upstream.benchmark.keccak.test_keccak.mem_alloc_empty.offset_31.mem_update_true", selected_ids)
        self.assertIn("upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes.mem_size_1024.msg_size_1024", selected_ids)

    def test_selector_allows_upstream_mapped_control_flow_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_control_flow_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.control_flow.test_gas_op",
                "upstream.benchmark.control_flow.test_jump_benchmark",
                "upstream.benchmark.control_flow.test_jumpdests",
                "upstream.benchmark.control_flow.test_jumpi_fallthrough",
                "upstream.benchmark.control_flow.test_jumpis",
                "upstream.benchmark.control_flow.test_jumps",
                "upstream.benchmark.control_flow.test_pc_op",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/control-flow"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])
        self.assertEqual(
            {case.observe["control_flow_probe"]["mode"] for case in selected},
            {"gas", "pc", "jump", "jump_pc_relative", "jumpi_fallthrough", "jumpi_taken", "jumpdest"},
        )

    def test_selector_allows_upstream_mapped_block_context_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_block_context_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.block_context.test_block_context_ops.basefee",
                "upstream.benchmark.block_context.test_block_context_ops.chainid",
                "upstream.benchmark.block_context.test_block_context_ops.coinbase",
                "upstream.benchmark.block_context.test_block_context_ops.gaslimit",
                "upstream.benchmark.block_context.test_block_context_ops.number",
                "upstream.benchmark.block_context.test_block_context_ops.timestamp",
                "upstream.benchmark.block_context.test_blockhash.current_block",
            ],
        )
        blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(
            blocked,
            {
                "upstream.benchmark.block_context.test_block_context_ops.prevrandao": [
                    "block-context mode prevrandao requires feature_flags.prevrandao=true in chain profile"
                ]
            },
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/block-context"})
        self.assertEqual(
            {case.observe["block_context_probe"]["mode"] for case in selected},
            {"basefee", "blockhash_current", "chainid", "coinbase", "gaslimit", "number", "timestamp"},
        )

    def test_selector_rejects_basefee_block_context_case_when_profile_lacks_feature_flag(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.feature_flags["base_fee"] = False
        manifest = load_manifest(ROOT / "suites/manifests/upstream_block_context_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.block_context.test_block_context_ops.chainid",
                "upstream.benchmark.block_context.test_block_context_ops.coinbase",
                "upstream.benchmark.block_context.test_block_context_ops.gaslimit",
                "upstream.benchmark.block_context.test_block_context_ops.number",
                "upstream.benchmark.block_context.test_block_context_ops.timestamp",
                "upstream.benchmark.block_context.test_blockhash.current_block",
            ],
        )
        blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(
            blocked,
            {
                "upstream.benchmark.block_context.test_block_context_ops.basefee": [
                    "block-context mode basefee requires feature_flags.base_fee=true in chain profile"
                ],
                "upstream.benchmark.block_context.test_block_context_ops.prevrandao": [
                    "block-context mode prevrandao requires feature_flags.prevrandao=true in chain profile"
                ],
            },
        )

    def test_selector_rejects_large_log_payload_cases_when_profile_lacks_feature_flag(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.feature_flags["large_log_payload"] = False
        manifest = load_manifest(ROOT / "suites/manifests/upstream_log_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(len(selected), 100)
        self.assertEqual(len(blocked), 30)
        self.assertEqual(
            set(tuple(reasons) for reasons in blocked.values()),
            {("log payload requires feature_flags.large_log_payload=true in chain profile",)},
        )
        self.assertTrue(
            all(
                decision.case.observe["log_probe"].get("log_size", 0) >= 1024 * 1024
                or decision.case.observe["log_probe"].get("memory_seed_size", 0) >= 1024 * 1024
                for decision in decisions
                if not decision.selected
            )
        )

    def test_cli_list_reports_basefee_block_context_capability_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "profile.toml"
            profile_path.write_text((ROOT / "profiles/juchain.toml").read_text().replace("base_fee = true", "base_fee = false", 1))
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "list",
                        "--manifest",
                        str(ROOT / "suites/manifests/upstream_block_context_mapped.json"),
                        "--profile",
                        str(profile_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            by_case = {entry["case_id"]: entry for entry in payload}
            self.assertFalse(by_case["upstream.benchmark.block_context.test_block_context_ops.basefee"]["selected"])
            self.assertEqual(
                by_case["upstream.benchmark.block_context.test_block_context_ops.basefee"]["reasons"],
                ["block-context mode basefee requires feature_flags.base_fee=true in chain profile"],
            )
            self.assertTrue(by_case["upstream.benchmark.block_context.test_block_context_ops.chainid"]["selected"])
            self.assertEqual(
                by_case["upstream.benchmark.block_context.test_block_context_ops.chainid"]["reasons"],
                [],
            )

    def test_manifest_resolves_execution_specs_ref(self) -> None:
        manifest = load_manifest(ROOT / "suites/manifests/upstream_smoke.json")
        head = (
            subprocess.run(
                ["git", "-C", str(ROOT / "third_party/execution-specs"), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            )
            .stdout.strip()
        )
        self.assertEqual(manifest.execution_specs_ref, head)

    def test_storage_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_storage_mapped.json"
            generated = generate_upstream_storage_manifest(
                repo_root=ROOT,
                template_path=ROOT / "suites/templates/upstream_storage_templates.json",
                output_path=generated_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_storage_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            head = (
                subprocess.run(
                    ["git", "-C", str(ROOT / "third_party/execution-specs"), "rev-parse", "HEAD"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                .stdout.strip()
            )
            self.assertEqual(generated["execution_specs_ref"], head)

    def test_memory_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_memory_mapped.json"
            generated = generate_upstream_memory_manifest(
                repo_root=ROOT,
                template_path=ROOT / "suites/templates/upstream_memory_templates.json",
                output_path=generated_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_memory_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)

    def test_call_context_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_call_context_mapped.json"
            generated = generate_upstream_call_context_manifest(
                repo_root=ROOT,
                template_path=ROOT / "suites/templates/upstream_call_context_templates.json",
                output_path=generated_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_call_context_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)

    def _assert_account_query_parity_contract(
        self,
        *,
        templates_payload: dict[str, object],
        inventory_payload: dict[str, object],
        manifest_payload: dict[str, object] | None = None,
    ) -> None:
        checked_in_templates_path = ROOT / "suites/templates/upstream_account_query_templates.json"
        checked_in_inventory_path = ROOT / "suites/templates/upstream_account_query_inventory.json"
        checked_in_templates = json.loads(checked_in_templates_path.read_text())
        checked_in_inventory = json.loads(checked_in_inventory_path.read_text())

        self.assertEqual(templates_payload, checked_in_templates, "account-query template JSON drift")
        self.assertEqual(inventory_payload, checked_in_inventory, "account-query inventory JSON drift")

        self.assertEqual(templates_payload["name"], "upstream-account-query-mapping-templates")
        self.assertEqual(inventory_payload["name"], "upstream-account-query-auto-inventory")
        self.assertEqual(inventory_payload["family"], "account-query")

        entries = inventory_payload["entries"]
        case_ids = [entry["case_id"] for entry in entries]
        upstream_refs = [entry["upstream_ref"] for entry in entries]
        self.assertEqual(upstream_refs, sorted(upstream_refs), "account-query upstream_ref ordering drifted")
        self.assertEqual(len(case_ids), 40)
        self.assertEqual(len(case_ids), len(set(case_ids)))

        admitted = [entry for entry in entries if entry["admitted"]]
        blocked = [entry for entry in entries if not entry["admitted"]]
        self.assertEqual(len(admitted), 10, "account-query admitted count drifted")
        self.assertEqual(len(blocked), 30, "account-query blocked count drifted")

        admitted_case_ids = [entry["case_id"] for entry in admitted]
        codecopy_fixed_case_ids = [entry["case_id"] for entry in admitted if entry["mode"] == "codecopy_fixed"]
        self.assertEqual(
            codecopy_fixed_case_ids,
            [
                "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_bytes.success",
                "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_25x_max_code_size.success",
                "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_50x_max_code_size.success",
                "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_75x_max_code_size.success",
                "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_max_code_size.success",
            ],
        )
        self.assertEqual(
            [entry["copy_size"] for entry in admitted if entry["mode"] == "codecopy_fixed"],
            [0, 6144, 12288, 18432, 24576],
        )
        self.assertEqual(
            admitted_case_ids,
            codecopy_fixed_case_ids
            + [
                "upstream.benchmark.account_query.codesize.success",
                "upstream.benchmark.account_query.balance.cold.present_accounts.success",
                "upstream.benchmark.account_query.balance.cold.absent_accounts.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_0.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_1.success",
            ],
        )
        self.assertEqual(
            {entry["mode"] for entry in admitted},
            {
                "codecopy_fixed",
                "codesize",
                "balance_cold_present_accounts",
                "balance_cold_absent_accounts",
                "selfbalance_contract_balance_0",
                "selfbalance_contract_balance_1",
            },
        )

        blocked_reason_counts = Counter(
            reason
            for entry in blocked
            for reason in entry["reasons"]
        )
        self.assertEqual(
            blocked_reason_counts,
            Counter(
                {
                    "requires byte-range code-copy observation not yet mapped": 25,
                    "requires external-account code-copy fixtures and byte-range observation not yet mapped": 5,
                }
            ),
            "account-query blocked-reason ledger drifted",
        )
        self.assertEqual(
            Counter(entry["source"] for entry in blocked),
            Counter({"codecopy": 5, "codecopy_benchmark": 20, "extcodecopy_warm": 5}),
            "account-query blocked source-family counts drifted",
        )
        self.assertTrue(all(entry["mode"] is None for entry in blocked))

        template_case_ids = [case["case_id"] for case in templates_payload["cases"]]
        self.assertEqual(template_case_ids, admitted_case_ids)

        if manifest_payload is not None:
            checked_in_manifest_path = ROOT / "suites/manifests/upstream_account_query_mapped.json"
            checked_in_manifest = json.loads(checked_in_manifest_path.read_text())
            self.assertEqual(manifest_payload, checked_in_manifest, "account-query manifest JSON drift")
            manifest_case_ids = [case["case_id"] for case in manifest_payload["cases"]]
            self.assertEqual(manifest_case_ids, admitted_case_ids)
            self.assertEqual(len(manifest_payload["cases"]), 10)
            self.assertEqual({case["family"] for case in manifest_payload["cases"]}, {"state/account-query"})
            manifest_by_id = {case["case_id"]: case for case in manifest_payload["cases"]}
            for case_id, copy_size in zip(codecopy_fixed_case_ids, [0, 6144, 12288, 18432, 24576], strict=True):
                case = manifest_by_id[case_id]
                self.assertEqual(case["observe"]["account_query_probe"], {"mode": "codecopy_fixed", "copy_size": copy_size})
                self.assertEqual(case["expected"]["storage"]["0x00"], f"0x{copy_size:064x}")
                self.assertIn("0x01", case["expected"]["storage"])
            present_case = manifest_by_id["upstream.benchmark.account_query.balance.cold.present_accounts.success"]
            self.assertEqual(
                present_case["steps"][0]["capture_balance_before"],
                "$present_target_balance_before",
            )
            self.assertEqual(
                present_case["expected"]["storage"]["0x00"],
                "$present_target_balance_after_word",
            )
            self.assertFalse(
                any("extcodecopy" in case_id for case_id in manifest_case_ids),
                "blocked account-query extcodecopy neighbors leaked into manifest",
            )

    def _assert_keccak_parity_contract(
        self,
        *,
        templates_payload: dict[str, object],
        inventory_payload: dict[str, object],
        manifest_payload: dict[str, object] | None = None,
    ) -> None:
        checked_in_templates_path = ROOT / "suites/templates/upstream_keccak_templates.json"
        checked_in_inventory_path = ROOT / "suites/templates/upstream_keccak_inventory.json"
        checked_in_templates = json.loads(checked_in_templates_path.read_text())
        checked_in_inventory = json.loads(checked_in_inventory_path.read_text())

        self.assertEqual(templates_payload, checked_in_templates, "keccak template JSON drift")
        self.assertEqual(inventory_payload, checked_in_inventory, "keccak inventory JSON drift")

        self.assertEqual(templates_payload["name"], "upstream-keccak-mapping-templates")
        self.assertEqual(inventory_payload["name"], "upstream-keccak-auto-inventory")
        self.assertEqual(inventory_payload["family"], "keccak")

        entries = inventory_payload["entries"]
        case_ids = [entry["case_id"] for entry in entries]
        upstream_refs = [entry["upstream_ref"] for entry in entries]
        self.assertEqual(upstream_refs, sorted(upstream_refs), "keccak upstream_ref ordering drifted")
        self.assertEqual(len(case_ids), 35)
        self.assertEqual(len(case_ids), len(set(case_ids)))

        admitted = [entry for entry in entries if entry["admitted"]]
        blocked = [entry for entry in entries if not entry["admitted"]]
        self.assertEqual(len(admitted), 35, "keccak admitted count drifted")
        self.assertEqual(len(blocked), 0, "keccak blocked count drifted")
        self.assertEqual({entry["mode"] for entry in admitted}, {"keccak", "diff_mem_msg_sizes", "max_permutations"})

        template_case_ids = [case["case_id"] for case in templates_payload["cases"]]
        admitted_case_ids = [entry["case_id"] for entry in admitted]
        self.assertEqual(template_case_ids, admitted_case_ids)
        self.assertEqual(len(templates_payload["cases"]), 35)

        max_case = next(case for case in templates_payload["cases"] if case["mode"] == "max_permutations")
        self.assertEqual(max_case["witness_input_length"], 115329)

        if manifest_payload is not None:
            checked_in_manifest_path = ROOT / "suites/manifests/upstream_keccak_mapped.json"
            checked_in_manifest = json.loads(checked_in_manifest_path.read_text())
            self.assertEqual(manifest_payload, checked_in_manifest, "keccak manifest JSON drift")
            manifest_case_ids = [case["case_id"] for case in manifest_payload["cases"]]
            self.assertEqual(manifest_case_ids, admitted_case_ids)
            self.assertEqual(len(manifest_payload["cases"]), 35)
            self.assertEqual({case["family"] for case in manifest_payload["cases"]}, {"state/keccak"})

    def test_block_context_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_block_context_templates.json"
            inventory_path = Path(tmpdir) / "upstream_block_context_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_block_context_mapped.json"
            templates = generate_upstream_block_context_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_block_context_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_block_context_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated, json.loads(manifest_path.read_text()))
            self.assertEqual(generated["name"], "upstream-block-context-mapped")
            self.assertEqual(len(generated["cases"]), 8)
            self.assertEqual({case["family"] for case in generated["cases"]}, {"state/block-context"})
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [case["case_id"] for case in templates["cases"]],
            )
            self.assertEqual(
                {case["expected"]["storage"]["0x00"] for case in generated["cases"]},
                {
                    "$block_basefee_word",
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "$chain_id_word",
                    "$block_coinbase_word",
                    "$block_gaslimit_word",
                    "$block_number_word",
                    "$block_prevrandao_word",
                    "$block_timestamp_word",
                },
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_keccak_templates.json"
            inventory_path = Path(tmpdir) / "upstream_keccak_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_keccak_mapped.json"
            templates = generate_upstream_keccak_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_keccak_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            self._assert_keccak_parity_contract(
                templates_payload=templates,
                inventory_payload=json.loads(inventory_path.read_text()),
                manifest_payload=generated,
            )
            self.assertEqual(generated["cases"][0]["family"], "state/keccak")

    def test_log_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_log_templates.json"
            inventory_path = Path(tmpdir) / "upstream_log_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_log_mapped.json"
            templates = generate_upstream_log_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_log_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            self._assert_log_parity_contract(
                templates_payload=templates,
                inventory_payload=json.loads(inventory_path.read_text()),
                manifest_payload=generated,
            )
            self.assertEqual(generated["cases"][0]["family"], "state/log")

    def test_arithmetic_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_arithmetic_templates.json"
            inventory_path = Path(tmpdir) / "upstream_arithmetic_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_arithmetic_mapped.json"
            generate_upstream_arithmetic_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_arithmetic_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            checked_in_templates = json.loads(
                (ROOT / "suites/templates/upstream_arithmetic_templates.json").read_text()
            )
            checked_in_inventory = json.loads(
                (ROOT / "suites/templates/upstream_arithmetic_inventory.json").read_text()
            )
            checked_in_manifest = json.loads(
                (ROOT / "suites/manifests/upstream_arithmetic_mapped.json").read_text()
            )
            self.assertEqual(json.loads(generated_template_path.read_text()), checked_in_templates)
            self.assertEqual(json.loads(inventory_path.read_text()), checked_in_inventory)
            self.assertEqual(json.loads(manifest_path.read_text()), checked_in_manifest)
            self.assertEqual(generated["name"], "upstream-arithmetic-mapped")
            self.assertEqual(len(generated["cases"]), 65)
            self.assertEqual({case["family"] for case in generated["cases"]}, {"state/arithmetic"})
            observed_case_ids = {case["case_id"] for case in generated["cases"]}
            self.assertIn("upstream.benchmark.arithmetic.test_arithmetic.add.base.arity_2", observed_case_ids)
            self.assertIn("upstream.benchmark.arithmetic.test_mod.mod.mod_bits_255", observed_case_ids)
            self.assertIn("upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_136279841.base_136279841", observed_case_ids)
            for case in generated["cases"]:
                self.assertIn("arithmetic_probe", case["observe"])
                self.assertIn("0x00", case["expected"]["storage"])

    def test_bitwise_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_bitwise_templates.json"
            inventory_path = Path(tmpdir) / "upstream_bitwise_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_bitwise_mapped.json"
            templates = generate_upstream_bitwise_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_bitwise_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            checked_in = json.loads((ROOT / "suites/manifests/upstream_bitwise_mapped.json").read_text())
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated["name"], "upstream-bitwise-mapped")
            self.assertEqual(len(generated["cases"]), 12)
            case_ids = {case["case_id"] for case in generated["cases"]}
            self.assertIn("upstream.benchmark.bitwise.test_clz_diff.clz", case_ids)
            self.assertIn("upstream.benchmark.bitwise.test_shifts.shr", case_ids)
            self.assertIn("upstream.benchmark.bitwise.test_shifts.sar", case_ids)

    def test_comparison_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_comparison_templates.json"
            inventory_path = Path(tmpdir) / "upstream_comparison_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_comparison_mapped.json"
            generate_upstream_comparison_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_comparison_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            checked_in_pairs = [
                (generated_template_path, ROOT / "suites/templates/upstream_comparison_templates.json"),
                (inventory_path, ROOT / "suites/templates/upstream_comparison_inventory.json"),
                (manifest_path, ROOT / "suites/manifests/upstream_comparison_mapped.json"),
            ]
            for generated_path, checked_in_path in checked_in_pairs:
                self.assertEqual(
                    generated_path.read_text(),
                    checked_in_path.read_text(),
                    f"{checked_in_path.name} byte drift",
                )
            self.assertEqual(generated["name"], "upstream-comparison-mapped")
            self.assertEqual(len(generated["cases"]), 6)
            self.assertEqual({case["family"] for case in generated["cases"]}, {"state/comparison"})
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [
                    "upstream.benchmark.comparison.test_comparison.eq",
                    "upstream.benchmark.comparison.test_comparison.gt",
                    "upstream.benchmark.comparison.test_comparison.lt",
                    "upstream.benchmark.comparison.test_comparison.sgt",
                    "upstream.benchmark.comparison.test_comparison.slt",
                    "upstream.benchmark.comparison.test_iszero.iszero",
                ],
            )
            for case in generated["cases"]:
                self.assertIn("comparison_probe", case["observe"])
                self.assertIn("0x00", case["expected"]["storage"])

    def test_keccak_checked_in_artifacts_match_generated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_keccak_templates.json"
            inventory_path = Path(tmpdir) / "upstream_keccak_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_keccak_mapped.json"
            generate_upstream_keccak_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generate_upstream_keccak_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            checked_in_pairs = [
                (generated_template_path, ROOT / "suites/templates/upstream_keccak_templates.json"),
                (inventory_path, ROOT / "suites/templates/upstream_keccak_inventory.json"),
                (manifest_path, ROOT / "suites/manifests/upstream_keccak_mapped.json"),
            ]
            for generated_path, checked_in_path in checked_in_pairs:
                self.assertEqual(
                    generated_path.read_text(),
                    checked_in_path.read_text(),
                    f"{checked_in_path.name} byte drift",
                )

    def test_keccak_templates_load(self) -> None:
        templates = load_keccak_templates(ROOT / "suites/templates/upstream_keccak_templates.json")
        self.assertEqual(len(templates), 35)
        self.assertEqual(templates[0].mode, "keccak")
        self.assertEqual(templates[-1].mode, "max_permutations")

    def test_account_query_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_account_query_templates.json"
            inventory_path = Path(tmpdir) / "upstream_account_query_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_account_query_mapped.json"
            templates = generate_upstream_account_query_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_account_query_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            self._assert_account_query_parity_contract(
                templates_payload=templates,
                inventory_payload=json.loads(inventory_path.read_text()),
                manifest_payload=generated,
            )
            self.assertEqual(generated["cases"][0]["family"], "state/account-query")

    def test_account_query_checked_in_artifacts_match_generated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_account_query_templates.json"
            inventory_path = Path(tmpdir) / "upstream_account_query_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_account_query_mapped.json"
            generate_upstream_account_query_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generate_upstream_account_query_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            checked_in_pairs = [
                (generated_template_path, ROOT / "suites/templates/upstream_account_query_templates.json"),
                (inventory_path, ROOT / "suites/templates/upstream_account_query_inventory.json"),
                (manifest_path, ROOT / "suites/manifests/upstream_account_query_mapped.json"),
            ]
            for generated_path, checked_in_path in checked_in_pairs:
                self.assertEqual(
                    generated_path.read_text(),
                    checked_in_path.read_text(),
                    f"{checked_in_path.name} byte drift",
                )

    def test_storage_templates_load(self) -> None:
        templates = load_storage_templates(ROOT / "suites/templates/upstream_storage_templates.json")
        self.assertEqual(len(templates), 17)
        self.assertEqual(templates[0].mode, "read_present")

    def test_memory_templates_load(self) -> None:
        templates = load_memory_templates(ROOT / "suites/templates/upstream_memory_templates.json")
        self.assertEqual(len(templates), 125)
        self.assertEqual(templates[0].mode, "mcopy")

    def test_call_context_templates_load(self) -> None:
        templates = load_call_context_templates(ROOT / "suites/templates/upstream_call_context_templates.json")
        self.assertEqual(len(templates), 20)
        self.assertEqual(templates[0].mode, "address")

    def test_account_query_templates_load(self) -> None:
        templates = load_account_query_templates(ROOT / "suites/templates/upstream_account_query_templates.json")
        self.assertEqual(len(templates), 10)
        self.assertEqual(templates[0].mode, "codecopy_fixed")
        self.assertEqual(sum(1 for template in templates if template.mode == "codecopy_fixed"), 5)

    def test_tx_context_templates_load(self) -> None:
        templates = load_tx_context_templates(ROOT / "suites/templates/upstream_tx_context_templates.json")
        self.assertEqual(len(templates), 2)
        self.assertEqual({template.mode for template in templates}, {"origin", "gasprice"})

    def test_storage_template_scanner_matches_checked_in_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_storage_templates.json"
            inventory_path = Path(tmpdir) / "upstream_storage_inventory.json"
            generated = generate_upstream_storage_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/templates/upstream_storage_templates.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            inventory = json.loads(inventory_path.read_text())
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(blocked, [])

    def test_memory_template_scanner_matches_checked_in_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_memory_templates.json"
            inventory_path = Path(tmpdir) / "upstream_memory_inventory.json"
            generated = generate_upstream_memory_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/templates/upstream_memory_templates.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            inventory = json.loads(inventory_path.read_text())
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 125)
            self.assertEqual(len(blocked), 18)

    def test_m022_remaining_blocked_cluster_audit_lock(self) -> None:
        def load_inventory(family_slug: str) -> dict[str, object]:
            return json.loads(
                (ROOT / "suites/templates" / f"upstream_{family_slug}_inventory.json").read_text()
            )

        def entries_for(family_slug: str) -> list[dict[str, object]]:
            return list(load_inventory(family_slug)["entries"])

        inventories = {
            "memory": entries_for("memory"),
            "account-query": entries_for("account_query"),
            "log": entries_for("log"),
            "system": entries_for("system"),
            "block-context": entries_for("block_context"),
            "tx-context": entries_for("tx_context"),
            "bitwise": entries_for("bitwise"),
        }

        expected_counts = {
            "memory": (143, 125, 18),
            "account-query": (40, 10, 30),
            "log": (140, 130, 10),
            "system": (46, 35, 11),
            "block-context": (13, 8, 5),
            "tx-context": (4, 2, 2),
            "bitwise": (12, 12, 0),
        }
        for family, (total_count, admitted_count, blocked_count) in expected_counts.items():
            entries = inventories[family]
            admitted = [entry for entry in entries if entry["admitted"]]
            blocked = [entry for entry in entries if not entry["admitted"]]
            self.assertEqual(len(entries), total_count, family)
            self.assertEqual(len(admitted), admitted_count, family)
            self.assertEqual(len(blocked), blocked_count, family)
            case_ids = [entry["case_id"] for entry in entries]
            self.assertEqual(len(case_ids), len(set(case_ids)), family)

        memory_blocked = [entry for entry in inventories["memory"] if not entry["admitted"]]
        memory_admitted_mcopy = [
            entry
            for entry in inventories["memory"]
            if entry["admitted"] and entry["source"] == "mcopy"
        ]
        self.assertEqual(Counter(entry["source"] for entry in memory_blocked), Counter({"mcopy": 18}))
        self.assertEqual(
            Counter(reason for entry in memory_blocked for reason in entry["reasons"]),
            Counter({"requires gas-derived dynamic MCOPY source/destination expansion observation not yet mapped": 18}),
        )
        self.assertEqual(Counter(entry["fixed_src_dst"] for entry in memory_blocked), Counter({False: 18}))
        self.assertEqual(Counter(entry["copy_size"] for entry in memory_blocked), Counter({32: 6, 256: 6, 1024: 6}))
        self.assertEqual(len(memory_admitted_mcopy), 30)
        self.assertEqual(sum(1 for entry in memory_admitted_mcopy if entry["fixed_src_dst"] is True), 24)
        self.assertEqual(
            sum(
                1
                for entry in memory_admitted_mcopy
                if entry["fixed_src_dst"] is False and entry["copy_size"] == 0
            ),
            6,
        )

        account_blocked = [entry for entry in inventories["account-query"] if not entry["admitted"]]
        self.assertEqual(
            Counter(entry["source"] for entry in account_blocked),
            Counter({"codecopy_benchmark": 20, "codecopy": 5, "extcodecopy_warm": 5}),
        )
        self.assertEqual(
            Counter(reason for entry in account_blocked for reason in entry["reasons"]),
            Counter(
                {
                    "requires byte-range code-copy observation not yet mapped": 25,
                    "requires external-account code-copy fixtures and byte-range observation not yet mapped": 5,
                }
            ),
        )

        log_blocked = [entry for entry in inventories["log"] if not entry["admitted"]]
        self.assertEqual(Counter(entry["source"] for entry in log_blocked), Counter({"test_log": 10}))
        self.assertEqual(
            Counter(reason for entry in log_blocked for reason in entry["reasons"]),
            Counter({"requires gas-derived dynamic log offset observation not yet mapped": 10}),
        )
        self.assertEqual(
            sum(1 for entry in log_blocked if entry["log_size"] == 0),
            0,
        )
        self.assertEqual(
            sum(
                1
                for entry in log_blocked
                if entry["log_size"] == 1048576 and entry["memory_seed_kind"] == "zero"
            ),
            0,
        )
        self.assertEqual(
            sum(
                1
                for entry in log_blocked
                if entry["log_size"] == 1048576 and entry["memory_seed_kind"] == "ff"
            ),
            10,
        )

        system_blocked = [entry for entry in inventories["system"] if not entry["admitted"]]
        self.assertEqual(
            Counter(entry["source"] for entry in system_blocked),
            Counter({"test_contract_calling_many_addresses": 8, "test_selfdestruct_initcode": 2, "test_creates_collisions": 1}),
        )
        self.assertEqual(
            Counter(reason for entry in system_blocked for reason in entry["reasons"]),
            Counter(
                {
                    "requires multi-address external-call orchestration not yet mapped": 8,
                    "requires selfdestruct lifecycle witness not yet mapped": 2,
                    "requires mutable pre-allocation of future CREATE addresses not available through the current RPC-only harness": 1,
                }
            ),
        )

        block_context_blocked = [entry for entry in inventories["block-context"] if not entry["admitted"]]
        self.assertEqual(
            Counter(reason for entry in block_context_blocked for reason in entry["reasons"]),
            Counter(
                {
                    "requires controllable historical block-hash witness not available through the current RPC-only harness": 3,
                    "requires gas-derived dynamic block index plus historical block-hash witness not available through the current RPC-only harness": 1,
                    "requires blob-base-fee opcode support plus a blob-capable profile witness not yet proven": 1,
                }
            ),
        )

        tx_context_blocked = [entry for entry in inventories["tx-context"] if not entry["admitted"]]
        self.assertEqual(
            Counter(reason for entry in tx_context_blocked for reason in entry["reasons"]),
            Counter({"requires blob transaction construction and BLOBHASH environment not yet mapped": 2}),
        )

        bitwise_blocked = [entry for entry in inventories["bitwise"] if not entry["admitted"]]
        self.assertEqual(bitwise_blocked, [])
        bitwise_clz_diff = next(
            entry
            for entry in inventories["bitwise"]
            if entry["case_id"] == "upstream.benchmark.bitwise.test_clz_diff.clz"
        )
        self.assertEqual(bitwise_clz_diff["mode"], "test_clz_diff")
        self.assertEqual(bitwise_clz_diff["reasons"], [])

    def test_call_context_template_scanner_matches_checked_in_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_call_context_templates.json"
            inventory_path = Path(tmpdir) / "upstream_call_context_inventory.json"
            generated = generate_upstream_call_context_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/templates/upstream_call_context_templates.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            inventory = json.loads(inventory_path.read_text())
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 20)
            self.assertEqual(blocked, [])

    def test_account_query_template_scanner_writes_expected_inventory_and_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_account_query_templates.json"
            inventory_path = Path(tmpdir) / "upstream_account_query_inventory.json"
            generated = generate_upstream_account_query_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self._assert_account_query_parity_contract(
                templates_payload=generated,
                inventory_payload=json.loads(inventory_path.read_text()),
            )

    def test_account_query_template_scanner_fails_loudly_on_missing_function(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_account_query.py"
        original = source.read_text()
        broken = original.replace("def test_selfbalance(", "def test_selfbalance_removed(", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_account_query_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "could not find benchmark function test_selfbalance"):
                generate_upstream_account_query_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def test_tx_context_template_scanner_matches_checked_in_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_tx_context_templates.json"
            inventory_path = Path(tmpdir) / "upstream_tx_context_inventory.json"
            generated = generate_upstream_tx_context_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/templates/upstream_tx_context_templates.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            inventory = json.loads(inventory_path.read_text())
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 2)
            self.assertEqual(len(blocked), 2)
            blocked_reasons = Counter(reason for entry in blocked for reason in entry["reasons"])
            self.assertEqual(
                blocked_reasons,
                Counter({"requires blob transaction construction and BLOBHASH environment not yet mapped": 2}),
            )

    def test_arithmetic_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_arithmetic_templates.json"
            inventory_path = Path(tmpdir) / "upstream_arithmetic_inventory.json"
            generated = generate_upstream_arithmetic_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-arithmetic-mapping-templates")
            self.assertEqual(len(generated["cases"]), 65)
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-arithmetic-auto-inventory")
            self.assertEqual(inventory["family"], "arithmetic")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))

    def test_bitwise_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_bitwise_templates.json"
            inventory_path = Path(tmpdir) / "upstream_bitwise_inventory.json"
            generated = generate_upstream_bitwise_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-bitwise-mapping-templates")
            self.assertEqual(len(generated["cases"]), 12)
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-bitwise-auto-inventory")
            self.assertEqual(inventory["family"], "bitwise")
            self.assertEqual(len(inventory["entries"]), 12)
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 12)
            self.assertEqual(blocked, [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            self.assertIn("upstream.benchmark.bitwise.test_shifts.shr", case_ids)
            self.assertIn("upstream.benchmark.bitwise.test_shifts.sar", case_ids)

    def test_comparison_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_comparison_templates.json"
            inventory_path = Path(tmpdir) / "upstream_comparison_inventory.json"
            generated = generate_upstream_comparison_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in_templates_path = ROOT / "suites/templates/upstream_comparison_templates.json"
            checked_in_inventory_path = ROOT / "suites/templates/upstream_comparison_inventory.json"
            checked_in_templates = json.loads(checked_in_templates_path.read_text())
            checked_in_inventory = json.loads(checked_in_inventory_path.read_text())
            self.assertEqual(generated_path.read_text(), checked_in_templates_path.read_text())
            self.assertEqual(generated["name"], "upstream-comparison-mapping-templates")
            self.assertEqual(len(generated["cases"]), 6)
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [
                    "upstream.benchmark.comparison.test_comparison.eq",
                    "upstream.benchmark.comparison.test_comparison.gt",
                    "upstream.benchmark.comparison.test_comparison.lt",
                    "upstream.benchmark.comparison.test_comparison.sgt",
                    "upstream.benchmark.comparison.test_comparison.slt",
                    "upstream.benchmark.comparison.test_iszero.iszero",
                ],
            )
            self.assertEqual(
                {case["opcode"]: tuple(case["args"]) for case in generated["cases"]},
                {
                    "EQ": (1, 1),
                    "GT": (0, 1),
                    "LT": (0, 1),
                    "SGT": ((1 << 256) - 1, 1),
                    "SLT": ((1 << 256) - 1, 1),
                    "ISZERO": (0,),
                },
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory, checked_in_inventory)
            self.assertEqual(inventory["name"], "upstream-comparison-auto-inventory")
            self.assertEqual(inventory["family"], "comparison")
            self.assertEqual(len(inventory["entries"]), 6)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            self.assertEqual(case_ids, [case["case_id"] for case in generated["cases"]])

    def test_comparison_template_scanner_fails_loudly_on_malformed_param_block(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_comparison.py"
        original = source.read_text()
        broken = original.replace("(0, 1),", "(0,),", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_comparison_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "parameter block for test_comparison entry 0 must define exactly two opcode_args"):
                generate_upstream_comparison_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def test_stack_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_stack_templates.json"
            inventory_path = Path(tmpdir) / "upstream_stack_inventory.json"
            generated = generate_upstream_stack_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in_templates = json.loads(
                (ROOT / "suites/templates/upstream_stack_templates.json").read_text()
            )
            checked_in_inventory = json.loads(
                (ROOT / "suites/templates/upstream_stack_inventory.json").read_text()
            )
            self.assertEqual(generated, checked_in_templates)
            self.assertEqual(generated["name"], "upstream-stack-mapping-templates")
            self.assertEqual(len(generated["cases"]), 65)
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory, checked_in_inventory)
            self.assertEqual(inventory["name"], "upstream-stack-auto-inventory")
            self.assertEqual(inventory["family"], "stack")
            self.assertEqual(len(inventory["entries"]), 65)

            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 65)
            self.assertEqual(blocked, [])
            self.assertEqual([case["case_id"] for case in generated["cases"]], [entry["case_id"] for entry in admitted])

            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            self.assertEqual(
                Counter(entry["source"] for entry in inventory["entries"]),
                Counter({"test_push": 33, "test_dup": 16, "test_swap": 16}),
            )
            self.assertEqual(
                Counter(entry["mode"] for entry in inventory["entries"]),
                Counter({"test_push": 33, "test_dup": 16, "test_swap": 16}),
            )
            self.assertEqual({tuple(entry["reasons"]) for entry in inventory["entries"]}, {()})
            self.assertEqual(
                {
                    "upstream.benchmark.stack.test_push.push0",
                    "upstream.benchmark.stack.test_push.push32",
                    "upstream.benchmark.stack.test_dup.dup1",
                    "upstream.benchmark.stack.test_dup.dup16",
                    "upstream.benchmark.stack.test_swap.swap1",
                    "upstream.benchmark.stack.test_swap.swap16",
                }.issubset(case_ids),
                True,
            )

    def test_stack_template_scanner_fails_loudly_on_missing_param_block(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_stack.py"
        original = source.read_text()
        broken = original.replace("@pytest.mark.parametrize(\n    \"opcode\",\n    [", "", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_stack_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "parameter block for test_swap"):
                generate_upstream_stack_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def test_control_flow_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_control_flow_templates.json"
            inventory_path = Path(tmpdir) / "upstream_control_flow_inventory.json"
            generated = generate_upstream_control_flow_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-control-flow-mapping-templates")
            self.assertEqual(len(generated["cases"]), 7)
            templates = load_control_flow_templates(generated_path)
            self.assertEqual(len(templates), 7)
            self.assertEqual(
                [template.mode for template in templates],
                [
                    "gas",
                    "jump_pc_relative",
                    "jumpdest",
                    "jumpi_fallthrough",
                    "jumpi_taken",
                    "jump",
                    "pc",
                ],
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-control-flow-auto-inventory")
            self.assertEqual(inventory["family"], "control-flow")
            self.assertEqual(len(inventory["entries"]), 7)
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            self.assertEqual(len(admitted), 7)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            self.assertEqual(
                case_ids,
                sorted(
                    [
                        "upstream.benchmark.control_flow.test_gas_op",
                        "upstream.benchmark.control_flow.test_jump_benchmark",
                        "upstream.benchmark.control_flow.test_jumpdests",
                        "upstream.benchmark.control_flow.test_jumpi_fallthrough",
                        "upstream.benchmark.control_flow.test_jumpis",
                        "upstream.benchmark.control_flow.test_jumps",
                        "upstream.benchmark.control_flow.test_pc_op",
                    ]
                ),
            )

    def test_control_flow_template_scanner_fails_loudly_on_missing_function(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_control_flow.py"
        original = source.read_text()
        broken = original.replace("def test_jumpdests(", "def test_jumpdests_removed(", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_control_flow_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "could not find benchmark function test_jumpdests"):
                generate_upstream_control_flow_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def test_block_context_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_block_context_templates.json"
            inventory_path = Path(tmpdir) / "upstream_block_context_inventory.json"
            generated = generate_upstream_block_context_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/templates/upstream_block_context_templates.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated["name"], "upstream-block-context-mapping-templates")
            self.assertEqual(len(generated["cases"]), 8)
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [
                    "upstream.benchmark.block_context.test_block_context_ops.basefee",
                    "upstream.benchmark.block_context.test_block_context_ops.chainid",
                    "upstream.benchmark.block_context.test_block_context_ops.coinbase",
                    "upstream.benchmark.block_context.test_block_context_ops.gaslimit",
                    "upstream.benchmark.block_context.test_block_context_ops.number",
                    "upstream.benchmark.block_context.test_block_context_ops.prevrandao",
                    "upstream.benchmark.block_context.test_block_context_ops.timestamp",
                    "upstream.benchmark.block_context.test_blockhash.current_block",
                ],
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-block-context-auto-inventory")
            self.assertEqual(inventory["family"], "block-context")
            self.assertEqual(len(inventory["entries"]), 13)
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 8)
            self.assertEqual(len(blocked), 5)
            self.assertEqual([entry["case_id"] for entry in admitted], [case["case_id"] for case in generated["cases"]])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            blocked_reason_counts = Counter(reason for entry in blocked for reason in entry["reasons"])
            self.assertEqual(
                blocked_reason_counts,
                Counter(
                    {
                        "requires controllable historical block-hash witness not available through the current RPC-only harness": 3,
                        "requires gas-derived dynamic block index plus historical block-hash witness not available through the current RPC-only harness": 1,
                        "requires blob-base-fee opcode support plus a blob-capable profile witness not yet proven": 1,
                    }
                ),
            )
            blocked_case_ids = {entry["case_id"] for entry in blocked}
            self.assertIn("upstream.benchmark.block_context.test_blockhash.random", blocked_case_ids)
            self.assertIn("upstream.benchmark.block_context.test_block_context_ops.blobbasefee", blocked_case_ids)

    def test_block_context_inventory_locks_blobbasefee_as_blocked_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_block_context_templates.json"
            inventory_path = Path(tmpdir) / "upstream_block_context_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_block_context_mapped.json"
            templates = generate_upstream_block_context_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            manifest = generate_upstream_block_context_manifest(
                repo_root=ROOT,
                template_path=generated_path,
                output_path=manifest_path,
            )
            inventory = json.loads(inventory_path.read_text())

        blob_entry = next(
            entry
            for entry in inventory["entries"]
            if entry["case_id"] == "upstream.benchmark.block_context.test_block_context_ops.blobbasefee"
        )
        self.assertEqual(
            blob_entry,
            {
                "upstream_ref": "tests/benchmark/compute/instruction/test_block_context.py::test_block_context_ops[opcode=BLOBBASEFEE]",
                "case_id": "upstream.benchmark.block_context.test_block_context_ops.blobbasefee",
                "admitted": False,
                "mode": None,
                "reasons": [
                    "requires blob-base-fee opcode support plus a blob-capable profile witness not yet proven"
                ],
                "source": "test_block_context_ops",
            },
        )
        self.assertNotIn(
            "upstream.benchmark.block_context.test_block_context_ops.blobbasefee",
            [case["case_id"] for case in templates["cases"]],
        )
        self.assertNotIn(
            "upstream.benchmark.block_context.test_block_context_ops.blobbasefee",
            [case["case_id"] for case in manifest["cases"]],
        )

    def test_block_context_template_scanner_fails_loudly_on_missing_function(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_block_context.py"
        original = source.read_text()
        broken = original.replace("def test_blockhash(", "def test_blockhash_removed(", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_block_context_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "could not find benchmark function test_blockhash"):
                generate_upstream_block_context_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def _assert_log_parity_contract(
        self,
        *,
        templates_payload: dict[str, object],
        inventory_payload: dict[str, object],
        manifest_payload: dict[str, object] | None = None,
    ) -> None:
        checked_in_templates_path = ROOT / "suites/templates/upstream_log_templates.json"
        checked_in_inventory_path = ROOT / "suites/templates/upstream_log_inventory.json"
        checked_in_templates = json.loads(checked_in_templates_path.read_text())
        checked_in_inventory = json.loads(checked_in_inventory_path.read_text())

        self.assertEqual(templates_payload, checked_in_templates, "log template JSON drift")
        self.assertEqual(inventory_payload, checked_in_inventory, "log inventory JSON drift")

        self.assertEqual(templates_payload["name"], "upstream-log-mapping-templates")
        self.assertEqual(inventory_payload["name"], "upstream-log-auto-inventory")
        self.assertEqual(inventory_payload["family"], "log")

        entries = inventory_payload["entries"]
        case_ids = [entry["case_id"] for entry in entries]
        upstream_refs = [entry["upstream_ref"] for entry in entries]
        self.assertEqual(upstream_refs, sorted(upstream_refs), "log upstream_ref ordering drifted")
        self.assertEqual(len(case_ids), 140)
        self.assertEqual(len(case_ids), len(set(case_ids)))

        admitted = [entry for entry in entries if entry["admitted"]]
        blocked = [entry for entry in entries if not entry["admitted"]]
        self.assertEqual(len(admitted), 130, "log admitted count drifted")
        self.assertEqual(len(blocked), 10, "log blocked count drifted")

        admitted_case_ids = [entry["case_id"] for entry in admitted]
        self.assertEqual(
            {entry["mode"] for entry in admitted},
            {"test_log_fixed_offset", "test_log_dynamic_offset", "test_log_benchmark"},
        )
        dynamic_admitted = [entry for entry in admitted if entry["mode"] == "test_log_dynamic_offset"]
        self.assertEqual(len(dynamic_admitted), 20)
        self.assertEqual(
            Counter(entry["log_size"] for entry in dynamic_admitted),
            Counter({0: 10, 1048576: 10}),
        )
        self.assertTrue(
            all(
                entry["log_size"] == 0
                or (entry["log_size"] == 1048576 and entry["memory_seed_kind"] == "zero")
                for entry in dynamic_admitted
            )
        )
        self.assertEqual(
            Counter(reason for entry in blocked for reason in entry["reasons"]),
            Counter({"requires gas-derived dynamic log offset observation not yet mapped": 10}),
        )
        self.assertEqual(
            Counter(entry["source"] for entry in blocked),
            Counter({"test_log": 10}),
        )
        self.assertTrue(all(entry["mode"] is None for entry in blocked))

        template_case_ids = [case["case_id"] for case in templates_payload["cases"]]
        self.assertEqual(template_case_ids, admitted_case_ids)
        self.assertEqual(len(templates_payload["cases"]), 130)

        dynamic_template = next(
            case
            for case in templates_payload["cases"]
            if case["case_id"]
            == "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_false"
        )
        self.assertEqual(dynamic_template["mode"], "test_log_dynamic_offset")

        if manifest_payload is not None:
            checked_in_manifest_path = ROOT / "suites/manifests/upstream_log_mapped.json"
            checked_in_manifest = json.loads(checked_in_manifest_path.read_text())
            self.assertEqual(manifest_payload, checked_in_manifest, "log manifest JSON drift")
            manifest_case_ids = [case["case_id"] for case in manifest_payload["cases"]]
            self.assertEqual(manifest_case_ids, admitted_case_ids)
            self.assertEqual(len(manifest_payload["cases"]), 130)
            self.assertEqual({case["family"] for case in manifest_payload["cases"]}, {"state/log"})
            observed_by_case = {case["case_id"]: case for case in manifest_payload["cases"]}
            dynamic_observed = observed_by_case[
                "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_false"
            ]
            self.assertEqual(dynamic_observed["observe"]["log_probe"]["offset_mode"], "dynamic_gas_mod_7")
            self.assertIn("5a600706a1", dynamic_observed["steps"][0]["bytecode_runtime"])
            self.assertEqual(dynamic_observed["expected"]["receipt_logs"], [{"topics": [NON_ZERO_TOPIC_WORD], "data": "0x"}])
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log.log0.size_0_bytes_data.topic_zeros_topic.fixed_offset_true"
                ]["expected"]["receipt_logs"],
                [{"topics": [], "data": "0x"}],
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log.log4.size_1_mib_non_zero_data.topic_non_zero_topic.fixed_offset_true"
                ]["expected"]["receipt_logs"],
                [
                    {
                        "topics": [
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        ],
                        "data_digest": "0x789682af96df9ddffff256ac9ee0b1b2f2dafd22b19a4e10e9c68d4176c05615",
                        "data_length_bytes": 1048576,
                    }
                ],
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log_benchmark.log4.mem_size_1024.log_size_256"
                ]["expected"]["receipt_logs"],
                [
                    {
                        "topics": [
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        ],
                        "data": "0x" + ("ff" * 256),
                    }
                ],
            )

    def test_log_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_log_templates.json"
            inventory_path = Path(tmpdir) / "upstream_log_inventory.json"
            generated = generate_upstream_log_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self._assert_log_parity_contract(
                templates_payload=generated,
                inventory_payload=json.loads(inventory_path.read_text()),
            )

    def test_log_template_scanner_fails_loudly_on_missing_function(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_log.py"
        original = source.read_text()
        broken = original.replace("def test_log_benchmark(", "def test_log_benchmark_removed(", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_log_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "could not find benchmark function test_log_benchmark"):
                generate_upstream_log_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def test_selector_allows_upstream_mapped_log_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/mock.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_log_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        selected_case_ids = [case.case_id for case in selected]
        manifest_case_ids = [case.case_id for case in manifest.cases]

        self.assertEqual(selected_case_ids, manifest_case_ids)
        self.assertEqual(len(selected_case_ids), 130)
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/log"})
        self.assertEqual(Counter(case.case_id.split(".")[4] for case in selected), Counter({"log0": 26, "log1": 26, "log2": 26, "log3": 26, "log4": 26}))
        self.assertEqual(
            Counter(
                "digest" if "data_digest" in case.expected["receipt_logs"][0] else "exact"
                for case in selected
            ),
            Counter({"exact": 80, "digest": 50}),
        )
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_mock_backend_runs_upstream_mapped_log_cases(self) -> None:
        manifest = load_manifest(ROOT / "suites/manifests/upstream_log_mapped.json")
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        observed_by_case: dict[str, dict[str, object]] = {}
        for index, case in enumerate(manifest.cases):
            tx_hashes, observed, context = backend.execute_case(case, f"log-case-{index}")
            self.assertEqual(len(tx_hashes), 2)
            self.assertEqual(ResultOracle().compare(case.expected, observed, context), [])
            observed_by_case[case.case_id] = observed

        self.assertEqual(len(observed_by_case), 130)
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log.log0.size_0_bytes_data.topic_zeros_topic.fixed_offset_true"
            ]["receipt_logs"],
            [
                {
                    "topics": [],
                    "topic_count": 0,
                    "data": "0x",
                    "data_length_bytes": 0,
                }
            ],
        )
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_zeros_topic.fixed_offset_true"
            ]["receipt_logs"],
            [
                {
                    "topics": ["0x0000000000000000000000000000000000000000000000000000000000000000"],
                    "topic_count": 1,
                    "data": "0x",
                    "data_length_bytes": 0,
                }
            ],
        )
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true"
            ]["receipt_logs"],
            [
                {
                    "topics": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
                    "topic_count": 1,
                    "data": "0x",
                    "data_length_bytes": 0,
                }
            ],
        )
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log.log4.size_1_mib_non_zero_data.topic_non_zero_topic.fixed_offset_true"
            ]["receipt_logs"][0]["topic_count"],
            4,
        )
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log.log4.size_1_mib_non_zero_data.topic_non_zero_topic.fixed_offset_true"
            ]["receipt_logs"][0]["topics"],
            ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] * 4,
        )
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log.log4.size_1_mib_non_zero_data.topic_non_zero_topic.fixed_offset_true"
            ]["receipt_logs"][0]["data_length_bytes"],
            1048576,
        )
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log.log4.size_1_mib_non_zero_data.topic_non_zero_topic.fixed_offset_true"
            ]["receipt_logs"][0]["data"][:66],
            "0x" + ("ff" * 32),
        )
        self.assertEqual(
            observed_by_case[
                "upstream.benchmark.log.test_log_benchmark.log4.mem_size_1024.log_size_256"
            ]["receipt_logs"],
            [
                {
                    "topics": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] * 4,
                    "topic_count": 4,
                    "data": "0x" + ("ff" * 256),
                    "data_length_bytes": 256,
                }
            ],
        )

    def test_cli_run_mock_upstream_log_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_log_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-log-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 130)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log.log0.size_0_bytes_data.topic_zeros_topic.fixed_offset_true"
                ]["observed"]["receipt_logs"],
                [
                    {
                        "topics": [],
                        "topic_count": 0,
                        "data": "0x",
                        "data_length_bytes": 0,
                    }
                ],
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_zeros_topic.fixed_offset_true"
                ]["observed"]["receipt_logs"][0]["topics"],
                ["0x0000000000000000000000000000000000000000000000000000000000000000"],
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true"
                ]["observed"]["receipt_logs"][0]["topics"],
                ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log.log0.size_1_mib_non_zero_data.topic_zeros_topic.fixed_offset_true"
                ]["expected"]["receipt_logs"],
                [
                    {
                        "topics": [],
                        "topic_count": 0,
                        "data_digest": "0x789682af96df9ddffff256ac9ee0b1b2f2dafd22b19a4e10e9c68d4176c05615",
                        "data_length_bytes": 1048576,
                    }
                ],
            )
            large_digest_case = observed_by_case[
                "upstream.benchmark.log.test_log.log4.size_1_mib_non_zero_data.topic_non_zero_topic.fixed_offset_true"
            ]["observed"]["receipt_logs"][0]
            self.assertEqual(large_digest_case["topic_count"], 4)
            self.assertEqual(
                large_digest_case["topics"],
                ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] * 4,
            )
            self.assertEqual(large_digest_case["data_length_bytes"], 1048576)
            self.assertNotIn("data", large_digest_case)
            self.assertTrue(large_digest_case["data_elided"])
            self.assertEqual(
                large_digest_case["data_digest"],
                observed_by_case[
                    "upstream.benchmark.log.test_log.log4.size_1_mib_non_zero_data.topic_non_zero_topic.fixed_offset_true"
                ]["expected"]["receipt_logs"][0]["data_digest"],
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.log.test_log_benchmark.log4.mem_size_1024.log_size_256"
                ]["observed"]["receipt_logs"],
                [
                    {
                        "topics": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] * 4,
                        "topic_count": 4,
                        "data": "0x" + ("ff" * 256),
                        "data_length_bytes": 256,
                    }
                ],
            )

    def test_cli_run_mock_upstream_log_manifest_rejects_declared_witness_mismatch(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_log_mapped.json").read_text())
        target_case = next(
            case
            for case in payload["cases"]
            if case["case_id"]
            == "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true"
        )
        target_case["expected"]["receipt_logs"][0]["topics"] = [
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            manifest_path = tmp_path / "tampered_upstream_log_mapped.json"
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

            self.assertEqual(
                main(
                    [
                        "run",
                        "--profile",
                        str(ROOT / "profiles/mock.toml"),
                        "--manifest",
                        str(manifest_path),
                        "--state-dir",
                        str(state_dir),
                        "--report",
                        str(report_path),
                    ]
                ),
                0,
            )
            report = json.loads(report_path.read_text())
            broken = next(
                result
                for result in report["results"]
                if result["case_id"]
                == "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true"
            )
            self.assertFalse(broken["success"])
            self.assertEqual(
                broken["diffs"],
                [
                    "proof error: declared receipt_logs witness does not match observe.log_probe: receipt_logs[0].topics[0]: expected '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', got '0x0000000000000000000000000000000000000000000000000000000000000000'"
                ],
            )
            self.assertEqual(broken["observed"], {})
            self.assertEqual(broken["context"], {})

    def test_cli_run_mock_upstream_log_manifest_rejects_log_probe_opcode_topic_count_mismatch(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_log_mapped.json").read_text())
        target_case = next(
            case
            for case in payload["cases"]
            if case["case_id"]
            == "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_true"
        )
        target_case["observe"]["log_probe"]["opcode"] = "LOG0"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            manifest_path = tmp_path / "tampered_upstream_log_mapped.json"
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

            with self.assertRaisesRegex(
                ValueError,
                r"observe\.log_probe\.topic_count does not match opcode LOG0: expected 0, got 1",
            ):
                main(
                    [
                        "run",
                        "--profile",
                        str(ROOT / "profiles/mock.toml"),
                        "--manifest",
                        str(manifest_path),
                        "--state-dir",
                        str(state_dir),
                        "--report",
                        str(report_path),
                    ]
                )

    def test_assert_report_success_exits_nonzero_for_failed_report(self) -> None:
        passed = ExecutionResult(
            case_id="passing-case",
            namespace="ns-pass",
            success=True,
            tx_hashes=[],
            context={},
            observed={},
            expected={},
            diffs=[],
        )
        failed = ExecutionResult(
            case_id="failing-case",
            namespace="ns-fail",
            success=False,
            tx_hashes=[],
            context={},
            observed={},
            expected={},
            diffs=["boom"],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            write_report(
                Report(
                    manifest="test-manifest",
                    execution_specs_ref="test-ref",
                    suite_version="0.1.0",
                    chain_profile="mock-devnet",
                    chain_profile_version="1",
                    results=[passed],
                ),
                report_path,
            )
            self.assertEqual(assert_report_success_main([str(report_path)]), 0)
            write_report(
                Report(
                    manifest="test-manifest",
                    execution_specs_ref="test-ref",
                    suite_version="0.1.0",
                    chain_profile="mock-devnet",
                    chain_profile_version="1",
                    results=[passed, failed],
                ),
                report_path,
            )
            self.assertEqual(assert_report_success_main([str(report_path)]), 1)

    def test_write_report_compacts_only_receipt_log_payloads_above_inline_threshold(self) -> None:
        exact_256 = "0x" + ("ab" * 256)
        exact_257 = "0x" + ("cd" * 257)
        report = Report(
            manifest="upstream-log-mapped",
            execution_specs_ref="test-ref",
            suite_version="0.1.0",
            chain_profile="mock-devnet",
            chain_profile_version="1",
            results=[
                ExecutionResult(
                    case_id="inline-256",
                    namespace="ns-inline",
                    success=True,
                    tx_hashes=["0x01"],
                    context={},
                    observed={
                        "receipt_logs": [
                            {
                                "topics": [],
                                "topic_count": 0,
                                "data": exact_256,
                                "data_length_bytes": 256,
                            }
                        ]
                    },
                    expected={"receipt_logs": [{"topics": [], "data": exact_256}]},
                    diffs=[],
                ),
                ExecutionResult(
                    case_id="digest-257",
                    namespace="ns-digest",
                    success=True,
                    tx_hashes=["0x02"],
                    context={},
                    observed={
                        "receipt_logs": [
                            {
                                "topics": [],
                                "topic_count": 0,
                                "data": exact_257,
                                "data_length_bytes": 257,
                            }
                        ]
                    },
                    expected={
                        "receipt_logs": [
                            {
                                "topics": [],
                                "data_digest": "0x" + keccak256(bytes.fromhex(exact_257[2:])).hex(),
                                "data_length_bytes": 257,
                            }
                        ]
                    },
                    diffs=[],
                ),
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            written_paths = write_report(report, report_path)
            payload = json.loads(report_path.read_text())

        observed_by_case = {result["case_id"]: result["observed"] for result in payload["results"]}
        inline_case = observed_by_case["inline-256"]["receipt_logs"][0]
        digest_case = observed_by_case["digest-257"]["receipt_logs"][0]

        self.assertEqual(written_paths[0], report_path)
        self.assertEqual(written_paths[1], durable_report_path(report, report_path))
        self.assertEqual(inline_case["data"], exact_256)
        self.assertEqual(inline_case["data_length_bytes"], 256)
        self.assertNotIn("data_digest", inline_case)
        self.assertNotIn("data_elided", inline_case)

        self.assertNotIn("data", digest_case)
        self.assertEqual(digest_case["data_length_bytes"], 257)
        self.assertTrue(digest_case["data_elided"])
        self.assertEqual(
            digest_case["data_digest"],
            "0x" + keccak256(bytes.fromhex(exact_257[2:])).hex(),
        )

    def test_write_report_skips_durable_copy_for_non_operational_manifest(self) -> None:
        report = Report(
            manifest="custom-storage-smoke",
            execution_specs_ref="test-ref",
            suite_version="0.1.0",
            chain_profile="mock-devnet",
            chain_profile_version="1",
            results=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            written_paths = write_report(report, report_path)
        self.assertEqual(written_paths, [report_path])
        self.assertIsNone(durable_report_path(report, report_path))

    def test_write_report_persists_durable_copy_for_operational_manifest(self) -> None:
        report = Report(
            manifest="upstream-system-mapped",
            execution_specs_ref="test-ref",
            suite_version="0.1.0",
            chain_profile="mock-devnet",
            chain_profile_version="1",
            results=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            durable_path = durable_report_path(report, report_path)
            self.assertIsNotNone(durable_path)
            written_paths = write_report(report, report_path)
            self.assertTrue(report_path.exists())
            self.assertTrue(durable_path.exists())
            self.assertEqual(json.loads(report_path.read_text()), json.loads(durable_path.read_text()))
            self.assertEqual(written_paths, [report_path, durable_path])

    def test_durable_report_path_sanitizes_path_components(self) -> None:
        report = Report(
            manifest="upstream-log-mapped",
            execution_specs_ref="test-ref",
            suite_version="0.1.0",
            chain_profile="../unsafe-profile",
            chain_profile_version="1",
            results=[],
        )
        durable_path = durable_report_path(report, Path("/tmp/out/report.json"))
        self.assertEqual(
            durable_path,
            Path("/tmp/out/evidence/unsafe-profile/upstream-log-mapped/report.json"),
        )

    def test_durable_report_path_rejects_empty_path_component(self) -> None:
        report = Report(
            manifest="upstream-log-mapped",
            execution_specs_ref="test-ref",
            suite_version="0.1.0",
            chain_profile="///",
            chain_profile_version="1",
            results=[],
        )
        with self.assertRaisesRegex(ValueError, "chain_profile must not contain path traversal segments"):
            durable_report_path(report, Path("/tmp/out/report.json"))

    def test_oracle_reports_precise_receipt_log_digest_mismatch(self) -> None:
        observed_data = "0x" + ("ff" * 32)
        wrong_expected_digest = "0x" + keccak256(b"wrong-payload").hex()
        diffs = ResultOracle().compare(
            {
                "receipt_logs": [
                    {
                        "topics": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] * 4,
                        "data_digest": wrong_expected_digest,
                        "data_length_bytes": 32,
                    }
                ]
            },
            {
                "receipt_logs": [
                    {
                        "topics": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] * 4,
                        "topic_count": 4,
                        "data": observed_data,
                        "data_length_bytes": 32,
                    }
                ]
            },
        )
        self.assertEqual(
            diffs,
            [
                f"receipt_logs[0].data_digest: expected {wrong_expected_digest!r}, got {'0x' + keccak256(bytes.fromhex(observed_data[2:])).hex()!r}"
            ],
        )

    def test_oracle_rejects_declared_receipt_log_witness_mismatch_against_runtime_contract(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"declared receipt_logs witness does not match observe\.log_probe: receipt_logs\[0\]\.topics\[0\]: expected '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', got '0x0000000000000000000000000000000000000000000000000000000000000000'",
        ):
            ResultOracle().resolve_expected(
                {
                    "receipt_logs": [
                        {
                            "topics": ["0x0000000000000000000000000000000000000000000000000000000000000000"],
                            "data": "0x",
                        }
                    ]
                },
                observed_contract={
                    "log_probe": {
                        "mode": "parametric_log",
                        "opcode": "LOG1",
                        "topic_count": 1,
                        "topic_word": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        "log_size": 0,
                        "memory_seed_kind": "zero",
                        "memory_seed_size": 0,
                        "witness_mode": "exact",
                    }
                },
            )

    def test_oracle_rejects_malformed_receipt_log_shape_against_runtime_contract(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"expected receipt log 0\.topics must be a list",
        ):
            ResultOracle().resolve_expected(
                {
                    "receipt_logs": [
                        {
                            "topics": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "data": "0x",
                        }
                    ]
                },
                observed_contract={
                    "log_probe": {
                        "mode": "parametric_log",
                        "opcode": "LOG1",
                        "topic_count": 1,
                        "topic_word": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        "log_size": 0,
                        "memory_seed_kind": "zero",
                        "memory_seed_size": 0,
                        "witness_mode": "exact",
                    }
                },
            )

    def test_oracle_rejects_invalid_receipt_log_data_type_against_runtime_contract(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"expected receipt log 0\.data must be a hex string",
        ):
            ResultOracle().resolve_expected(
                {
                    "receipt_logs": [
                        {
                            "topics": [],
                            "data": 123,
                        }
                    ]
                },
                observed_contract={
                    "log_probe": {
                        "mode": "parametric_log",
                        "opcode": "LOG0",
                        "topic_count": 0,
                        "topic_word": None,
                        "log_size": 0,
                        "memory_seed_kind": "zero",
                        "memory_seed_size": 0,
                        "witness_mode": "exact",
                    }
                },
            )

    def test_derive_receipt_log_expectation_matches_runtime_contract(self) -> None:
        self.assertEqual(
            derive_receipt_log_expectation(
                {
                    "mode": "parametric_log",
                    "opcode": "LOG2",
                    "topic_count": 2,
                    "topic_word": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "log_size": 1024,
                    "memory_seed_kind": "ff",
                    "memory_seed_size": 32,
                    "witness_mode": "digest",
                }
            ),
            {
                "topics": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] * 2,
                "data_digest": "0x" + keccak256((b"\xff" * 32) + (b"\x00" * 992)).hex(),
                "data_length_bytes": 1024,
            },
        )

    def test_derive_receipt_log_expectation_rejects_opcode_topic_count_mismatch(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"observe\.log_probe\.topic_count does not match opcode LOG0: expected 0, got 1",
        ):
            derive_receipt_log_expectation(
                {
                    "mode": "parametric_log",
                    "opcode": "LOG0",
                    "topic_count": 1,
                    "topic_word": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "log_size": 0,
                    "memory_seed_kind": "zero",
                    "memory_seed_size": 0,
                    "witness_mode": "exact",
                }
            )

    def test_derive_receipt_log_expectation_rejects_unsupported_log_opcode(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"unsupported log opcode: LOG5",
        ):
            derive_receipt_log_expectation(
                {
                    "mode": "parametric_log",
                    "opcode": "LOG5",
                    "topic_count": 5,
                    "topic_word": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "log_size": 0,
                    "memory_seed_kind": "zero",
                    "memory_seed_size": 0,
                    "witness_mode": "exact",
                }
            )

    def test_oracle_reports_precise_receipt_log_topic_mismatch(self) -> None:
        diffs = ResultOracle().compare(
            {
                "receipt_logs": [
                    {
                        "topics": ["0x0000000000000000000000000000000000000000000000000000000000000000"],
                        "data": "0x",
                    }
                ]
            },
            {
                "receipt_logs": [
                    {
                        "topics": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
                        "topic_count": 1,
                        "data": "0x",
                        "data_length_bytes": 0,
                    }
                ]
            },
        )
        self.assertEqual(
            diffs,
            [
                "receipt_logs[0].topics[0]: expected '0x0000000000000000000000000000000000000000000000000000000000000000', got '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'"
            ],
        )

    def test_keccak_max_permutations_witness_contract_matches_upstream_helper(self) -> None:
        contract = derive_upstream_keccak_witness_contract()
        self.assertTrue(contract.tx_gas_limit_cap_is_none)
        self.assertEqual(contract.benchmark_gas_limit, 120000000)
        self.assertEqual(contract.intrinsic_gas, 21000)
        self.assertEqual(contract.keccak_rate, 136)
        self.assertEqual((contract.iteration_start, contract.iteration_stop, contract.iteration_step), (1, 1000000, 32))
        self.assertEqual((contract.keccak_base_gas, contract.keccak_per_word_gas, contract.pop_gas), (30, 6, 2))
        self.assertEqual(contract.optimal_input_length, 115329)
        self.assertEqual(compute_keccak_max_permutations_input_length(), contract.optimal_input_length)
        templates = load_keccak_templates(ROOT / "suites/templates/upstream_keccak_templates.json")
        max_case = next(template for template in templates if template.mode == "max_permutations")
        self.assertEqual(max_case.witness_input_length, contract.optimal_input_length)

    def test_keccak_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_keccak_templates.json"
            inventory_path = Path(tmpdir) / "upstream_keccak_inventory.json"
            generated = generate_upstream_keccak_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self._assert_keccak_parity_contract(
                templates_payload=generated,
                inventory_payload=json.loads(inventory_path.read_text()),
            )

    def test_keccak_template_scanner_fails_loudly_on_missing_function(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_keccak.py"
        original = source.read_text()
        broken = original.replace("def test_keccak_diff_mem_msg_sizes(", "def test_keccak_diff_mem_msg_sizes_removed(", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_keccak_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "could not find benchmark function test_keccak_diff_mem_msg_sizes"):
                generate_upstream_keccak_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def _assert_system_parity_contract(
        self,
        *,
        templates_payload: dict[str, object],
        inventory_payload: dict[str, object],
        manifest_payload: dict[str, object] | None = None,
    ) -> None:
        checked_in_templates_path = ROOT / "suites/templates/upstream_system_templates.json"
        checked_in_inventory_path = ROOT / "suites/templates/upstream_system_inventory.json"
        checked_in_templates = json.loads(checked_in_templates_path.read_text())
        checked_in_inventory = json.loads(checked_in_inventory_path.read_text())

        self.assertEqual(templates_payload, checked_in_templates, "system template JSON drift")
        self.assertEqual(inventory_payload, checked_in_inventory, "system inventory JSON drift")

        self.assertEqual(templates_payload["name"], "upstream-system-mapping-templates")
        self.assertEqual(inventory_payload["name"], "upstream-system-auto-inventory")
        self.assertEqual(inventory_payload["family"], "system")

        entries = inventory_payload["entries"]
        case_ids = [entry["case_id"] for entry in entries]
        upstream_refs = [entry["upstream_ref"] for entry in entries]
        self.assertEqual(upstream_refs, sorted(upstream_refs), "system upstream_ref ordering drifted")
        self.assertEqual(len(case_ids), 46)
        self.assertEqual(len(case_ids), len(set(case_ids)))

        admitted = [entry for entry in entries if entry["admitted"]]
        blocked = [entry for entry in entries if not entry["admitted"]]
        self.assertEqual(len(admitted), 35, "system admitted count drifted")
        self.assertEqual(len(blocked), 11, "system blocked count drifted")

        admitted_case_ids = [entry["case_id"] for entry in admitted]
        self.assertEqual(
            admitted_case_ids,
            [
                "upstream.benchmark.system.test_create.create.0_bytes_with_value",
                "upstream.benchmark.system.test_create.create.0_bytes_without_value",
                "upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_bytes_with_value",
                "upstream.benchmark.system.test_create.create2.0_bytes_without_value",
                "upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.max_code_size_with_zero_data",
                "upstream.benchmark.system.test_creates_collisions.create2",
                "upstream.benchmark.system.test_return_revert.return.1kib_of_non_zero_data",
                "upstream.benchmark.system.test_return_revert.return.1kib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.return.1mib_of_non_zero_data",
                "upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.return.empty",
                "upstream.benchmark.system.test_return_revert.revert.1kib_of_non_zero_data",
                "upstream.benchmark.system.test_return_revert.revert.1kib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.revert.1mib_of_non_zero_data",
                "upstream.benchmark.system.test_return_revert.revert.1mib_of_zero_data",
                "upstream.benchmark.system.test_return_revert.revert.empty",
                "upstream.benchmark.system.test_selfdestruct_created.value_bearing_false",
                "upstream.benchmark.system.test_selfdestruct_created.value_bearing_true",
                "upstream.benchmark.system.test_selfdestruct_existing.value_bearing_false",
                "upstream.benchmark.system.test_selfdestruct_existing.value_bearing_true",
            ],
        )
        self.assertEqual({entry["mode"] for entry in admitted}, {"create_child_code", "create_collision", "create_empty_child", "return_revert_self_call", "selfdestruct_single"})
        self.assertEqual(
            Counter(reason for entry in blocked for reason in entry["reasons"]),
            Counter(
                {
                    "requires multi-address external-call orchestration not yet mapped": 8,
                    "requires mutable pre-allocation of future CREATE addresses not available through the current RPC-only harness": 1,
                    "requires selfdestruct lifecycle witness not yet mapped": 2,
                }
            ),
        )
        self.assertEqual(
            Counter(entry["source"] for entry in blocked),
            Counter(
                {
                    "test_contract_calling_many_addresses": 8,
                    "test_creates_collisions": 1,
                    "test_selfdestruct_initcode": 2,
                }
            ),
        )
        self.assertTrue(all(entry["mode"] is None for entry in blocked))

        template_case_ids = [case["case_id"] for case in templates_payload["cases"]]
        self.assertEqual(template_case_ids, admitted_case_ids)
        self.assertEqual(len(templates_payload["cases"]), 35)

        if manifest_payload is not None:
            checked_in_manifest_path = ROOT / "suites/manifests/upstream_system_mapped.json"
            checked_in_manifest = json.loads(checked_in_manifest_path.read_text())
            self.assertEqual(manifest_payload, checked_in_manifest, "system manifest JSON drift")
            manifest_case_ids = [case["case_id"] for case in manifest_payload["cases"]]
            self.assertEqual(manifest_case_ids, admitted_case_ids)
            self.assertEqual(len(manifest_payload["cases"]), 35)
            self.assertEqual({case["family"] for case in manifest_payload["cases"]}, {"state/system"})
            observed_by_case = {case["case_id"]: case for case in manifest_payload["cases"]}
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_create.create.0_bytes_with_value"
                ]["expected"],
                {
                    "receipt_status": "0x1",
                    "system_witness": {
                        "shape": "create_empty_child",
                        "success": True,
                        "created_address_nonzero": True,
                        "created_code_size": 0,
                        "created_balance": 1,
                    },
                },
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_create.create.0_bytes_with_value"
                ]["steps"][0]["value"],
                "0x1",
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_create.create.0_bytes_without_value"
                ]["expected"],
                {
                    "receipt_status": "0x1",
                    "system_witness": {
                        "shape": "create_empty_child",
                        "success": True,
                        "created_address_nonzero": True,
                        "created_code_size": 0,
                    },
                },
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_create.create2.0_bytes_without_value"
                ]["observe"]["system_witness"],
                {
                    "version": 1,
                    "shape": "create_empty_child",
                    "subject": "$last_contract",
                    "opcode": "CREATE2",
                    "value": 0,
                    "initcode_size": 0,
                    "salt": 42,
                },
            )
            def expected_non_zero_child_code(size: int) -> bytes:
                prefix = {
                    6144: bytes.fromhex("611800805f5f395ff3"),
                    12288: bytes.fromhex("613000805f5f395ff3"),
                    18432: bytes.fromhex("614800805f5f395ff3"),
                    24576: bytes.fromhex("616000805f5f395ff3"),
                }[size]
                return prefix + bytes(index % 256 for index in range(size - len(prefix)))

            code_hashes = {
                (6144, "zero"): "0x" + keccak256(b"\x00" * 6144).hex(),
                (6144, "non_zero"): "0x" + keccak256(expected_non_zero_child_code(6144)).hex(),
                (12288, "zero"): "0x" + keccak256(b"\x00" * 12288).hex(),
                (12288, "non_zero"): "0x" + keccak256(expected_non_zero_child_code(12288)).hex(),
                (18432, "zero"): "0x" + keccak256(b"\x00" * 18432).hex(),
                (18432, "non_zero"): "0x" + keccak256(expected_non_zero_child_code(18432)).hex(),
                (24576, "zero"): "0x" + keccak256(b"\x00" * 24576).hex(),
                (24576, "non_zero"): "0x" + keccak256(expected_non_zero_child_code(24576)).hex(),
            }
            for case_id, size, data_kind in (
                ("upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_non_zero_data", 6144, "non_zero"),
                ("upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_zero_data", 6144, "zero"),
                ("upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_non_zero_data", 12288, "non_zero"),
                ("upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_zero_data", 12288, "zero"),
                ("upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_non_zero_data", 18432, "non_zero"),
                ("upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_zero_data", 18432, "zero"),
                ("upstream.benchmark.system.test_create.create.max_code_size_with_non_zero_data", 24576, "non_zero"),
                ("upstream.benchmark.system.test_create.create.max_code_size_with_zero_data", 24576, "zero"),
            ):
                self.assertEqual(
                    observed_by_case[case_id]["expected"],
                    {
                        "receipt_status": "0x1",
                        "system_witness": {
                            "shape": "create_child_code",
                            "success": True,
                            "created_address_nonzero": True,
                            "created_code_size": size,
                            "created_code_hash": code_hashes[(size, data_kind)],
                        },
                    },
                )
            for case_id, size, data_kind in (
                ("upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_non_zero_data", 6144, "non_zero"),
                ("upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_zero_data", 6144, "zero"),
                ("upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_non_zero_data", 12288, "non_zero"),
                ("upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_zero_data", 12288, "zero"),
                ("upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_non_zero_data", 18432, "non_zero"),
                ("upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_zero_data", 18432, "zero"),
                ("upstream.benchmark.system.test_create.create2.max_code_size_with_non_zero_data", 24576, "non_zero"),
                ("upstream.benchmark.system.test_create.create2.max_code_size_with_zero_data", 24576, "zero"),
            ):
                self.assertEqual(
                    observed_by_case[case_id]["observe"]["system_witness"],
                    {
                        "version": 1,
                        "shape": "create_child_code",
                        "subject": "$last_contract",
                        "opcode": "CREATE2",
                        "value": 0,
                        "initcode_size": size,
                        "data_kind": data_kind,
                        "salt": 42,
                    },
                )
            default_deploy_gas = "0x186a0"
            create_empty_deploy = observed_by_case[
                "upstream.benchmark.system.test_create.create.0_bytes_without_value"
            ]["steps"][0]
            self.assertEqual(create_empty_deploy["gas"], default_deploy_gas)
            for case_id in (
                "upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create.max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_non_zero_data",
                "upstream.benchmark.system.test_create.create2.max_code_size_with_non_zero_data",
            ):
                deploy_step = observed_by_case[case_id]["steps"][0]
                self.assertGreater(int(deploy_step["gas"], 16), int(default_deploy_gas, 16))
            for case_id in (
                "upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.0_50x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.0_75x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create.max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_50x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.0_75x_max_code_size_with_zero_data",
                "upstream.benchmark.system.test_create.create2.max_code_size_with_zero_data",
            ):
                deploy_step = observed_by_case[case_id]["steps"][0]
                self.assertEqual(deploy_step["gas"], default_deploy_gas)
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_creates_collisions.create2"]["observe"]["system_witness"],
                {
                    "version": 1,
                    "shape": "create_collision",
                    "subject": "$last_contract",
                    "opcode": "CREATE2",
                    "value": 0,
                    "initcode_size": 0,
                    "salt": 0,
                    "proxy_call_gas": 100000,
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_creates_collisions.create2"]["expected"],
                {
                    "receipt_status": "0x1",
                    "system_witness": {
                        "shape": "create_collision",
                        "proxy_deploy_success": True,
                        "first_create_call_success": True,
                        "first_created_address_nonzero": True,
                        "first_created_code_size": 0,
                        "collision_call_success": False,
                        "collision_returndata_size": 0,
                    },
                },
            )
            for case_id, scenario, value in (
                ("upstream.benchmark.system.test_selfdestruct_created.value_bearing_false", "created", 0),
                ("upstream.benchmark.system.test_selfdestruct_created.value_bearing_true", "created", 1),
                ("upstream.benchmark.system.test_selfdestruct_existing.value_bearing_false", "existing", 0),
                ("upstream.benchmark.system.test_selfdestruct_existing.value_bearing_true", "existing", 1),
            ):
                expected_witness = {
                    "shape": "selfdestruct_single",
                    "scenario": scenario,
                    "child_address_nonzero": True,
                    "selfdestruct_call_success": True,
                    "child_code_size_after": 0 if scenario == "created" else 2,
                }
                if scenario == "existing":
                    expected_witness["setup_create_success"] = True
                    expected_witness["child_code_size_before"] = 2
                else:
                    expected_witness["create_success"] = True
                if value > 0:
                    expected_witness["beneficiary_balance_after"] = 1
                self.assertEqual(
                    observed_by_case[case_id]["observe"]["system_witness"],
                    {
                        "version": 1,
                        "shape": "selfdestruct_single",
                        "subject": "$last_contract",
                        "scenario": scenario,
                        "value": value,
                        "hardfork_semantics": "cancun",
                    },
                )
                self.assertEqual(
                    observed_by_case[case_id]["expected"],
                    {"receipt_status": "0x1", "system_witness": expected_witness},
                )
                if scenario == "existing":
                    self.assertEqual(
                        [step["action"] for step in observed_by_case[case_id]["steps"]],
                        ["deploy_contract", "wait_receipt", "invoke_contract", "wait_receipt", "invoke_contract", "wait_receipt"],
                    )
                    self.assertEqual(observed_by_case[case_id]["steps"][2]["data"], "0x" + "00" * 32)
                    self.assertEqual(observed_by_case[case_id]["steps"][4]["data"], "0x" + "00" * 31 + "01")

            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_return_revert.return.empty"
                ]["expected"],
                {
                    "receipt_status": "0x1",
                    "system_witness": {
                        "shape": "return_revert_self_call",
                        "success": True,
                        "returndata_size": 0,
                        "returndata_digest": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    },
                },
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_return_revert.revert.1kib_of_non_zero_data"
                ]["expected"]["system_witness"],
                {
                    "shape": "return_revert_self_call",
                    "success": False,
                    "returndata_size": 1024,
                    "returndata_digest": "0x146071216f9b08d3ffefb9581967e6c5e47e043ca3897b61f5df20c057826054",
                },
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data"
                ]["expected"]["system_witness"]["returndata_size"],
                1048576,
            )
            self.assertFalse(
                any(
                    "test_selfdestruct_initcode" in case_id
                    or "test_contract_calling_many_addresses" in case_id
                    or case_id == "upstream.benchmark.system.test_creates_collisions.create"
                    for case_id in manifest_case_ids
                ),
                "blocked system neighbors leaked into manifest",
            )

    def test_system_template_scanner_writes_admitted_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_system_templates.json"
            inventory_path = Path(tmpdir) / "upstream_system_inventory.json"
            generated = generate_upstream_system_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self._assert_system_parity_contract(
                templates_payload=generated,
                inventory_payload=json.loads(inventory_path.read_text()),
            )

    def test_system_template_scanner_writes_admitted_inventory_subset(self) -> None:
        self.test_system_template_scanner_writes_admitted_inventory()

    def test_system_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_system_templates.json"
            inventory_path = Path(tmpdir) / "upstream_system_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_system_mapped.json"
            templates = generate_upstream_system_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_system_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            self._assert_system_parity_contract(
                templates_payload=templates,
                inventory_payload=json.loads(inventory_path.read_text()),
                manifest_payload=generated,
            )
            self.assertEqual(generated["cases"][0]["family"], "state/system")

    def test_system_manifest_generator_matches_checked_in_manifest_subset(self) -> None:
        self.test_system_manifest_generator_matches_checked_in_manifest()

    def test_system_template_scanner_fails_loudly_on_missing_function(self) -> None:
        source = ROOT / "third_party/execution-specs/tests/benchmark/compute/instruction/test_system.py"
        original = source.read_text()
        broken = original.replace("def test_selfdestruct_initcode(", "def test_selfdestruct_initcode_removed(", 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_path = Path(tmpdir) / "test_system_broken.py"
            broken_path.write_text(broken)
            with self.assertRaisesRegex(ValueError, "could not find benchmark function test_selfdestruct_initcode"):
                generate_upstream_system_templates(
                    repo_root=ROOT,
                    source_path=broken_path,
                    inventory_path=Path(tmpdir) / "inventory.json",
                )

    def test_cli_generate_storage_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-storage-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self.assertEqual(generated["name"], "upstream-storage-mapped")
            self.assertEqual(len(generated["cases"]), 17)

    def test_stack_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_stack_mapped.json"
            generated = generate_upstream_stack_manifest(
                repo_root=ROOT,
                template_path=ROOT / "suites/templates/upstream_stack_templates.json",
                output_path=generated_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_stack_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(len(generated["cases"]), 65)
            self.assertEqual(generated_path.read_text(), (ROOT / "suites/manifests/upstream_stack_mapped.json").read_text())

    def test_cli_generate_stack_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-stack-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_stack_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated["name"], "upstream-stack-mapped")
            self.assertEqual(len(generated["cases"]), 65)
            observed_by_case = {case["case_id"]: case["expected"]["storage"]["0x00"] for case in generated["cases"]}
            self.assertEqual(
                {
                    "upstream.benchmark.stack.test_push.push0": observed_by_case["upstream.benchmark.stack.test_push.push0"],
                    "upstream.benchmark.stack.test_push.push32": observed_by_case["upstream.benchmark.stack.test_push.push32"],
                    "upstream.benchmark.stack.test_dup.dup16": observed_by_case["upstream.benchmark.stack.test_dup.dup16"],
                    "upstream.benchmark.stack.test_swap.swap16": observed_by_case["upstream.benchmark.stack.test_swap.swap16"],
                },
                {
                    "upstream.benchmark.stack.test_push.push0": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.stack.test_push.push32": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "upstream.benchmark.stack.test_dup.dup16": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "upstream.benchmark.stack.test_swap.swap16": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
            )

    def test_cli_scan_upstream_storage_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-storage",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-storage-mapping-templates")
            self.assertEqual(len(generated["cases"]), 17)
            self.assertEqual(len(inventory["entries"]), len(generated["cases"]))

    def test_cli_scan_upstream_arithmetic_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-arithmetic",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-arithmetic-mapping-templates")
            self.assertEqual(len(generated["cases"]), 65)
            self.assertEqual(inventory["name"], "upstream-arithmetic-auto-inventory")
            self.assertEqual(inventory["family"], "arithmetic")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_cli_scan_upstream_bitwise_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-bitwise",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-bitwise-mapping-templates")
            self.assertEqual(len(generated["cases"]), 12)
            self.assertEqual(inventory["name"], "upstream-bitwise-auto-inventory")
            self.assertEqual(inventory["family"], "bitwise")
            self.assertEqual(len(inventory["entries"]), 12)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 12)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])
            clz_diff = next(entry for entry in inventory["entries"] if entry["case_id"] == "upstream.benchmark.bitwise.test_clz_diff.clz")
            self.assertEqual(clz_diff["upstream_ref"], "tests/benchmark/compute/instruction/test_bitwise.py::test_clz_diff")
            self.assertEqual(clz_diff["mode"], "test_clz_diff")
            self.assertEqual(clz_diff["source"], "test_clz_diff")

    def test_cli_scan_upstream_comparison_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-comparison",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-comparison-mapping-templates")
            self.assertEqual(len(generated["cases"]), 6)
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [entry["case_id"] for entry in inventory["entries"]],
            )
            self.assertEqual(
                {case["opcode"]: tuple(case["args"]) for case in generated["cases"]},
                {
                    "EQ": (1, 1),
                    "GT": (0, 1),
                    "LT": (0, 1),
                    "SGT": ((1 << 256) - 1, 1),
                    "SLT": ((1 << 256) - 1, 1),
                    "ISZERO": (0,),
                },
            )
            self.assertEqual(inventory["name"], "upstream-comparison-auto-inventory")
            self.assertEqual(inventory["family"], "comparison")
            self.assertEqual(len(inventory["entries"]), 6)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 6)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_cli_scan_upstream_stack_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-stack",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-stack-mapping-templates")
            self.assertEqual(len(generated["cases"]), 65)
            self.assertEqual(inventory["name"], "upstream-stack-auto-inventory")
            self.assertEqual(inventory["family"], "stack")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_cli_scan_upstream_control_flow_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-control-flow",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-control-flow-mapping-templates")
            self.assertEqual(len(generated["cases"]), 7)
            self.assertEqual(inventory["name"], "upstream-control-flow-auto-inventory")
            self.assertEqual(inventory["family"], "control-flow")
            self.assertEqual(len(inventory["entries"]), 7)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 7)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_control_flow_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_template_path = Path(tmpdir) / "upstream_control_flow_templates.json"
            inventory_path = Path(tmpdir) / "upstream_control_flow_inventory.json"
            manifest_path = Path(tmpdir) / "upstream_control_flow_mapped.json"
            templates = generate_upstream_control_flow_templates(
                repo_root=ROOT,
                output_path=generated_template_path,
                inventory_path=inventory_path,
            )
            generated = generate_upstream_control_flow_manifest(
                repo_root=ROOT,
                template_path=generated_template_path,
                output_path=manifest_path,
            )
            checked_in_manifest = json.loads(
                (ROOT / "suites/manifests/upstream_control_flow_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in_manifest)
            self.assertEqual(
                generated,
                json.loads(manifest_path.read_text()),
            )
            self.assertEqual(generated["name"], "upstream-control-flow-mapped")
            self.assertEqual(len(generated["cases"]), 7)
            self.assertEqual({case["family"] for case in generated["cases"]}, {"state/control-flow"})
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [case["case_id"] for case in templates["cases"]],
            )

    def test_cli_generate_control_flow_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            template_output_path = Path(tmpdir) / "templates.json"
            inventory_output_path = Path(tmpdir) / "inventory.json"
            manifest_output_path = Path(tmpdir) / "generated.json"
            generate_upstream_control_flow_templates(
                repo_root=ROOT,
                output_path=template_output_path,
                inventory_path=inventory_output_path,
            )
            self.assertEqual(
                main(
                    [
                        "generate-control-flow-manifest",
                        "--template",
                        str(template_output_path),
                        "--output",
                        str(manifest_output_path),
                    ]
                ),
                0,
            )
            generated = json.loads(manifest_output_path.read_text())
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_control_flow_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated["name"], "upstream-control-flow-mapped")
            self.assertEqual(len(generated["cases"]), 7)
            self.assertEqual(generated["cases"][0]["family"], "state/control-flow")

    def test_cli_generate_block_context_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            template_output_path = Path(tmpdir) / "templates.json"
            inventory_output_path = Path(tmpdir) / "inventory.json"
            manifest_output_path = Path(tmpdir) / "generated.json"
            generate_upstream_block_context_templates(
                repo_root=ROOT,
                output_path=template_output_path,
                inventory_path=inventory_output_path,
            )
            self.assertEqual(
                main(
                    [
                        "generate-block-context-manifest",
                        "--template",
                        str(template_output_path),
                        "--output",
                        str(manifest_output_path),
                    ]
                ),
                0,
            )
            generated = json.loads(manifest_output_path.read_text())
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_block_context_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated["name"], "upstream-block-context-mapped")
            self.assertEqual(len(generated["cases"]), 8)
            self.assertEqual(generated["cases"][0]["family"], "state/block-context")

    def test_cli_generate_memory_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-memory-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self.assertEqual(generated["name"], "upstream-memory-mapped")
            self.assertEqual(len(generated["cases"]), 125)

    def test_cli_generate_account_query_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            template_output_path = Path(tmpdir) / "templates.json"
            inventory_output_path = Path(tmpdir) / "inventory.json"
            manifest_output_path = Path(tmpdir) / "generated.json"
            templates = generate_upstream_account_query_templates(
                repo_root=ROOT,
                output_path=template_output_path,
                inventory_path=inventory_output_path,
            )
            self.assertEqual(
                main(
                    [
                        "generate-account-query-manifest",
                        "--template",
                        str(template_output_path),
                        "--output",
                        str(manifest_output_path),
                    ]
                ),
                0,
            )
            generated = json.loads(manifest_output_path.read_text())
            self._assert_account_query_parity_contract(
                templates_payload=templates,
                inventory_payload=json.loads(inventory_output_path.read_text()),
                manifest_payload=generated,
            )
            self.assertEqual(generated["name"], "upstream-account-query-mapped")
            self.assertEqual(len(generated["cases"]), 10)
            self.assertEqual(generated["cases"][0]["family"], "state/account-query")

    def test_cli_scan_upstream_memory_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-memory",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-memory-mapping-templates")
            self.assertEqual(len(generated["cases"]), 125)
            self.assertGreater(len(inventory["entries"]), len(generated["cases"]))

    def test_cli_generate_call_context_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-call-context-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self.assertEqual(generated["name"], "upstream-call-context-mapped")
            self.assertEqual(len(generated["cases"]), 20)
            self.assertEqual(generated["cases"][0]["expected"]["storage"]["0x00"], "$last_contract_word")

    def test_cli_generate_tx_context_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-tx-context-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self.assertEqual(generated["name"], "upstream-tx-context-mapped")
            self.assertEqual(len(generated["cases"]), 2)
            expected_by_case = {case["case_id"]: case["expected"]["storage"]["0x00"] for case in generated["cases"]}
            self.assertEqual(
                expected_by_case,
                {
                    "upstream.benchmark.tx_context.gasprice.success": "$gas_price_word",
                    "upstream.benchmark.tx_context.origin.success": "$admin_account_word",
                },
            )

    def test_cli_scan_upstream_call_context_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-call-context",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-call-context-mapping-templates")
            self.assertEqual(len(generated["cases"]), 20)
            self.assertEqual(len(inventory["entries"]), len(generated["cases"]))

    def test_cli_scan_upstream_account_query_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-account-query",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self._assert_account_query_parity_contract(
                templates_payload=generated,
                inventory_payload=inventory,
            )

    def test_cli_scan_upstream_block_context_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-block-context",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-block-context-mapping-templates")
            self.assertEqual(len(generated["cases"]), 8)
            self.assertGreater(len(inventory["entries"]), len(generated["cases"]))
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(blocked), 5)
            self.assertEqual(
                Counter(reason for entry in blocked for reason in entry["reasons"]),
                Counter(
                    {
                        "requires controllable historical block-hash witness not available through the current RPC-only harness": 3,
                        "requires gas-derived dynamic block index plus historical block-hash witness not available through the current RPC-only harness": 1,
                        "requires blob-base-fee opcode support plus a blob-capable profile witness not yet proven": 1,
                    }
                ),
            )

    def test_cli_scan_upstream_tx_context_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-tx-context",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(generated["name"], "upstream-tx-context-mapping-templates")
            self.assertEqual(len(generated["cases"]), 2)
            self.assertGreater(len(inventory["entries"]), len(generated["cases"]))
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(blocked), 2)
            self.assertTrue(
                all(
                    entry["reasons"] == ["requires blob transaction construction and BLOBHASH environment not yet mapped"]
                    for entry in blocked
                )
            )

    def test_cli_scan_upstream_storage_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-storage",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-storage-auto-inventory")
            self.assertEqual(inventory["family"], "storage")
            self.assertEqual(len(inventory["entries"]), 17)

    def test_cli_scan_upstream_arithmetic_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-arithmetic",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-arithmetic-auto-inventory")
            self.assertEqual(inventory["family"], "arithmetic")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_cli_scan_upstream_bitwise_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-bitwise",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-bitwise-auto-inventory")
            self.assertEqual(inventory["family"], "bitwise")
            self.assertEqual(len(inventory["entries"]), 12)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 12)

    def test_cli_scan_upstream_comparison_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-comparison",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-comparison-auto-inventory")
            self.assertEqual(inventory["family"], "comparison")
            self.assertEqual(len(inventory["entries"]), 6)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])
            self.assertEqual(
                [entry["case_id"] for entry in inventory["entries"]],
                [
                    "upstream.benchmark.comparison.test_comparison.eq",
                    "upstream.benchmark.comparison.test_comparison.gt",
                    "upstream.benchmark.comparison.test_comparison.lt",
                    "upstream.benchmark.comparison.test_comparison.sgt",
                    "upstream.benchmark.comparison.test_comparison.slt",
                    "upstream.benchmark.comparison.test_iszero.iszero",
                ],
            )
            self.assertEqual(
                {entry["opcode"]: tuple(entry["args"]) for entry in inventory["entries"]},
                {
                    "EQ": (1, 1),
                    "GT": (0, 1),
                    "LT": (0, 1),
                    "SGT": ((1 << 256) - 1, 1),
                    "SLT": ((1 << 256) - 1, 1),
                    "ISZERO": (0,),
                },
            )

    def test_cli_scan_upstream_stack_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-stack",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-stack-auto-inventory")
            self.assertEqual(inventory["family"], "stack")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_cli_scan_upstream_control_flow_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-control-flow",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-control-flow-auto-inventory")
            self.assertEqual(inventory["family"], "control-flow")
            self.assertEqual(len(inventory["entries"]), 7)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 7)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_cli_scan_upstream_block_context_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-block-context",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-block-context-auto-inventory")
            self.assertEqual(inventory["family"], "block-context")
            self.assertEqual(len(inventory["entries"]), 13)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 8)

    def test_cli_scan_upstream_log_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-log",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self._assert_log_parity_contract(
                templates_payload=json.loads((ROOT / "suites/templates/upstream_log_templates.json").read_text()),
                inventory_payload=inventory,
            )

    def test_cli_generate_log_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-log-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self._assert_log_parity_contract(
                templates_payload=json.loads((ROOT / "suites/templates/upstream_log_templates.json").read_text()),
                inventory_payload=json.loads((ROOT / "suites/templates/upstream_log_inventory.json").read_text()),
                manifest_payload=generated,
            )

    def test_cli_generate_system_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            template_output_path = Path(tmpdir) / "templates.json"
            inventory_output_path = Path(tmpdir) / "inventory.json"
            manifest_output_path = Path(tmpdir) / "generated.json"
            templates = generate_upstream_system_templates(
                repo_root=ROOT,
                output_path=template_output_path,
                inventory_path=inventory_output_path,
            )
            self.assertEqual(
                main(
                    [
                        "generate-system-manifest",
                        "--template",
                        str(template_output_path),
                        "--output",
                        str(manifest_output_path),
                    ]
                ),
                0,
            )
            generated = json.loads(manifest_output_path.read_text())
            self._assert_system_parity_contract(
                templates_payload=templates,
                inventory_payload=json.loads(inventory_output_path.read_text()),
                manifest_payload=generated,
            )
            self.assertEqual(generated["name"], "upstream-system-mapped")
            self.assertEqual(len(generated["cases"]), 35)
            self.assertEqual(generated["cases"][0]["family"], "state/system")

    def test_cli_generate_keccak_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-keccak-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self.assertEqual(generated["name"], "upstream-keccak-mapped")
            self.assertEqual(len(generated["cases"]), 35)
            max_case = next(case for case in generated["cases"] if case["case_id"] == "upstream.benchmark.keccak.test_keccak_max_permutations")
            self.assertEqual(max_case["expected"]["storage"]["0x01"], "0x000000000000000000000000000000000000000000000000000000000001c281")

    def test_cli_generate_bitwise_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-bitwise-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self.assertEqual(generated["name"], "upstream-bitwise-mapped")
            self.assertEqual(len(generated["cases"]), 12)
            case_ids = {case["case_id"] for case in generated["cases"]}
            self.assertIn("upstream.benchmark.bitwise.test_clz_diff.clz", case_ids)
            self.assertIn("upstream.benchmark.bitwise.test_shifts.shr", case_ids)
            self.assertIn("upstream.benchmark.bitwise.test_shifts.sar", case_ids)
            for case in generated["cases"]:
                if case["case_id"] in {
                    "upstream.benchmark.bitwise.test_shifts.shr",
                    "upstream.benchmark.bitwise.test_shifts.sar",
                }:
                    self.assertEqual(case["observe"]["bitwise_probe"]["mode"], "test_shifts")
                    self.assertEqual(case["family"], "state/bitwise")

    def test_cli_generate_comparison_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-comparison-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            checked_in_manifest_path = ROOT / "suites/manifests/upstream_comparison_mapped.json"
            self.assertEqual(
                output_path.read_text(),
                checked_in_manifest_path.read_text(),
                "upstream_comparison_mapped.json byte drift",
            )
            self.assertEqual(generated["name"], "upstream-comparison-mapped")
            self.assertEqual(len(generated["cases"]), 6)
            observed_by_case = {case["case_id"]: case for case in generated["cases"]}
            self.assertEqual(
                observed_by_case["upstream.benchmark.comparison.test_comparison.eq"]["expected"]["storage"]["0x00"],
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.comparison.test_comparison.gt"]["expected"]["storage"]["0x00"],
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.comparison.test_iszero.iszero"]["observe"]["comparison_probe"]["opcode"],
                "ISZERO",
            )
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [
                    "upstream.benchmark.comparison.test_comparison.eq",
                    "upstream.benchmark.comparison.test_comparison.gt",
                    "upstream.benchmark.comparison.test_comparison.lt",
                    "upstream.benchmark.comparison.test_comparison.sgt",
                    "upstream.benchmark.comparison.test_comparison.slt",
                    "upstream.benchmark.comparison.test_iszero.iszero",
                ],
            )
            self.assertTrue(all(case["family"] == "state/comparison" for case in generated["cases"]))

    def test_cli_scan_upstream_log_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-log",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self._assert_log_parity_contract(
                templates_payload=generated,
                inventory_payload=inventory,
            )

    def test_cli_scan_upstream_keccak_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-keccak",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self._assert_keccak_parity_contract(
                templates_payload=generated,
                inventory_payload=inventory,
            )

    def test_cli_scan_upstream_keccak_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-keccak",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-keccak-auto-inventory")
            self.assertEqual(inventory["family"], "keccak")
            self.assertEqual(len(inventory["entries"]), 35)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 35)
            self.assertEqual([entry for entry in inventory["entries"] if not entry["admitted"]], [])

    def test_cli_scan_upstream_system_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-system",
                        "--template-output",
                        str(output_path),
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            generated = json.loads(output_path.read_text())
            inventory = json.loads(inventory_path.read_text())
            self._assert_system_parity_contract(
                templates_payload=generated,
                inventory_payload=inventory,
            )

    def test_cli_scan_upstream_system_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-system",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self._assert_system_parity_contract(
                templates_payload=json.loads((ROOT / "suites/templates/upstream_system_templates.json").read_text()),
                inventory_payload=inventory,
            )

    def test_cli_scan_upstream_memory_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-memory",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-memory-auto-inventory")
            self.assertEqual(inventory["family"], "memory")
            self.assertGreater(len(inventory["entries"]), 5)

    def test_cli_scan_upstream_call_context_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-call-context",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-call-context-auto-inventory")
            self.assertEqual(inventory["family"], "call-context")
            self.assertGreater(len(inventory["entries"]), 9)

    def test_cli_scan_upstream_account_query_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-account-query",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self._assert_account_query_parity_contract(
                templates_payload=json.loads(
                    (ROOT / "suites/templates/upstream_account_query_templates.json").read_text()
                ),
                inventory_payload=inventory,
            )

    def test_cli_scan_upstream_tx_context_inventory_only_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "inventory.json"
            self.assertEqual(
                main(
                    [
                        "scan-upstream-tx-context",
                        "--inventory-output",
                        str(inventory_path),
                    ]
                ),
                0,
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-tx-context-auto-inventory")
            self.assertEqual(inventory["family"], "tx-context")
            self.assertGreater(len(inventory["entries"]), 1)

    def test_cli_scan_upstream_storage_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-storage",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_cli_scan_upstream_stack_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-stack",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_cli_scan_upstream_control_flow_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-control-flow",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_cli_scan_upstream_block_context_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-block-context",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_cli_scan_upstream_log_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-log",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_cli_scan_upstream_keccak_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-keccak",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_cli_scan_upstream_system_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-system",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_cli_scan_upstream_account_query_requires_inventory_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "templates.json"
            with self.assertRaises(SystemExit):
                main(
                    [
                        "scan-upstream-account-query",
                        "--template-output",
                        str(output_path),
                    ]
                )

    def test_first_family_inventory_snapshots_match_checked_in_json(self) -> None:
        families = [
            (
                generate_upstream_arithmetic_templates,
                ROOT / "suites/templates/upstream_arithmetic_inventory.json",
            ),
            (
                generate_upstream_bitwise_templates,
                ROOT / "suites/templates/upstream_bitwise_inventory.json",
            ),
            (
                generate_upstream_comparison_templates,
                ROOT / "suites/templates/upstream_comparison_inventory.json",
            ),
            (
                generate_upstream_stack_templates,
                ROOT / "suites/templates/upstream_stack_inventory.json",
            ),
            (
                generate_upstream_control_flow_templates,
                ROOT / "suites/templates/upstream_control_flow_inventory.json",
            ),
            (
                generate_upstream_block_context_templates,
                ROOT / "suites/templates/upstream_block_context_inventory.json",
            ),
            (
                generate_upstream_log_templates,
                ROOT / "suites/templates/upstream_log_inventory.json",
            ),
            (
                generate_upstream_keccak_templates,
                ROOT / "suites/templates/upstream_keccak_inventory.json",
            ),
            (
                generate_upstream_system_templates,
                ROOT / "suites/templates/upstream_system_inventory.json",
            ),
            (
                generate_upstream_account_query_templates,
                ROOT / "suites/templates/upstream_account_query_inventory.json",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for generator, checked_in_path in families:
                generated_path = tmp_path / checked_in_path.name
                generator(repo_root=ROOT, inventory_path=generated_path)
                generated = json.loads(generated_path.read_text())
                checked_in = json.loads(checked_in_path.read_text())
                self.assertEqual(generated, checked_in, checked_in_path.name)
                if checked_in_path.name == "upstream_account_query_inventory.json":
                    self._assert_account_query_parity_contract(
                        templates_payload=json.loads(
                            (ROOT / "suites/templates/upstream_account_query_templates.json").read_text()
                        ),
                        inventory_payload=generated,
                    )

    def test_inventory_summary_aggregates_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            write_inventory_payload(
                tmp_path / "upstream_alpha_inventory.json",
                family="alpha",
                name="upstream-alpha-auto-inventory",
                source="alpha.py",
                entries=[
                    {
                        "upstream_ref": "alpha::test_ok",
                        "case_id": "alpha.ok",
                        "admitted": True,
                        "reasons": [],
                        "source": "unit",
                    },
                    {
                        "upstream_ref": "alpha::test_blocked",
                        "case_id": "alpha.blocked",
                        "admitted": False,
                        "reasons": ["requires precise gas fixture"],
                        "source": "unit",
                    },
                ],
            )
            write_inventory_payload(
                tmp_path / "upstream_beta_inventory.json",
                family="beta",
                name="upstream-beta-auto-inventory",
                source="beta.py",
                entries=[
                    {
                        "upstream_ref": "beta::test_blocked",
                        "case_id": "beta.blocked",
                        "admitted": False,
                        "reasons": ["requires block environment control"],
                        "source": "unit",
                    }
                ],
            )
            summary = summarize_inventory_dir(tmp_path)
            self.assertEqual(summary["totals"], {"families": 2, "cases": 3, "admitted": 1, "blocked": 2})
            families = {item["family"]: item for item in summary["families"]}
            self.assertEqual(families["alpha"]["blocked_reasons"], {"requires precise gas fixture": 1})
            self.assertEqual(families["beta"]["blocked_reasons"], {"requires block environment control": 1})

    def _assert_checked_in_phase3_inventory_summary(self, summary: dict[str, object]) -> None:
        families = {item["family"]: item for item in summary["families"]}
        phase3_families = {
            family: {
                "total": item["total"],
                "admitted": item["admitted"],
                "blocked": item["blocked"],
                "blocked_reasons": item["blocked_reasons"],
            }
            for family, item in families.items()
            if family in {"arithmetic", "bitwise", "comparison", "stack", "control-flow", "keccak"}
        }
        self.assertEqual(
            phase3_families,
            {
                "arithmetic": {"total": 65, "admitted": 65, "blocked": 0, "blocked_reasons": {}},
                "bitwise": {
                    "total": 12,
                    "admitted": 12,
                    "blocked": 0,
                    "blocked_reasons": {},
                },
                "comparison": {"total": 6, "admitted": 6, "blocked": 0, "blocked_reasons": {}},
                "stack": {"total": 65, "admitted": 65, "blocked": 0, "blocked_reasons": {}},
                "control-flow": {"total": 7, "admitted": 7, "blocked": 0, "blocked_reasons": {}},
                "keccak": {"total": 35, "admitted": 35, "blocked": 0, "blocked_reasons": {}},
            },
        )
        self.assertEqual(
            {
                "families": len(phase3_families),
                "cases": sum(item["total"] for item in phase3_families.values()),
                "admitted": sum(item["admitted"] for item in phase3_families.values()),
                "blocked": sum(item["blocked"] for item in phase3_families.values()),
            },
            {"families": 6, "cases": 190, "admitted": 190, "blocked": 0},
        )

    def _assert_checked_in_first_family_inventory_summary(self, summary: dict[str, object]) -> None:
        self.assertEqual(
            summary["totals"],
            {"families": 14, "cases": 613, "admitted": 537, "blocked": 76},
        )

        families = {item["family"]: item for item in summary["families"]}
        inventories = {item["inventory"]: item for item in summary["families"]}
        self.assertIn("account-query", families)
        self.assertEqual(families["account-query"]["inventory"], "upstream_account_query_inventory.json")
        self.assertEqual(
            inventories["upstream_storage_inventory.json"],
            {
                "family": "storage",
                "inventory": "upstream_storage_inventory.json",
                "total": 17,
                "admitted": 17,
                "blocked": 0,
                "blocked_reasons": {},
            },
        )
        self.assertEqual(
            {
                family: {
                    "total": item["total"],
                    "admitted": item["admitted"],
                    "blocked": item["blocked"],
                }
                for family, item in families.items()
                if family in {"arithmetic", "bitwise", "comparison", "stack", "control-flow", "account-query", "block-context", "call-context", "log", "keccak", "system", "tx-context", "memory"}
            },
            {
                "arithmetic": {"total": 65, "admitted": 65, "blocked": 0},
                "bitwise": {"total": 12, "admitted": 12, "blocked": 0},
                "comparison": {"total": 6, "admitted": 6, "blocked": 0},
                "stack": {"total": 65, "admitted": 65, "blocked": 0},
                "control-flow": {"total": 7, "admitted": 7, "blocked": 0},
                "account-query": {"total": 40, "admitted": 10, "blocked": 30},
                "block-context": {"total": 13, "admitted": 8, "blocked": 5},
                "call-context": {"total": 20, "admitted": 20, "blocked": 0},
                "log": {"total": 140, "admitted": 130, "blocked": 10},
                "keccak": {"total": 35, "admitted": 35, "blocked": 0},
                "system": {"total": 46, "admitted": 35, "blocked": 11},
                "tx-context": {"total": 4, "admitted": 2, "blocked": 2},
                "memory": {"total": 143, "admitted": 125, "blocked": 18},
            },
        )
        self.assertEqual(
            families["account-query"]["blocked_reasons"],
            {
                "requires byte-range code-copy observation not yet mapped": 25,
                "requires external-account code-copy fixtures and byte-range observation not yet mapped": 5,
            },
        )
        self.assertEqual(
            families["log"]["blocked_reasons"],
            {"requires gas-derived dynamic log offset observation not yet mapped": 10},
        )
        self._assert_checked_in_phase3_inventory_summary(summary)

    def test_inventory_summary_aggregates_checked_in_first_family_inventories(self) -> None:
        summary = summarize_inventory_dir(ROOT / "suites/templates")
        self._assert_checked_in_first_family_inventory_summary(summary)

    def test_inventory_summary_ignores_account_query_when_filename_drops_inventory_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for inventory_path in sorted((ROOT / "suites/templates").glob("*_inventory.json")):
                target_name = inventory_path.name
                if inventory_path.name == "upstream_account_query_inventory.json":
                    target_name = "upstream_account_query_renamed.json"
                (tmp_path / target_name).write_text(inventory_path.read_text())

            summary = summarize_inventory_dir(tmp_path)
            families = {item["family"]: item for item in summary["families"]}
            self.assertNotIn("account-query", families)
            self.assertEqual(
                summary["totals"],
                {"families": 13, "cases": 573, "admitted": 527, "blocked": 46},
            )
            self.assertNotEqual(
                summary["totals"],
                {"families": 14, "cases": 613, "admitted": 537, "blocked": 76},
            )

    def test_cli_summarize_upstream_inventory_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            inventory_dir = tmp_path / "inventories"
            output_path = tmp_path / "summary.json"
            write_inventory_payload(
                inventory_dir / "upstream_alpha_inventory.json",
                family="alpha",
                name="upstream-alpha-auto-inventory",
                source="alpha.py",
                entries=[
                    {
                        "upstream_ref": "alpha::test_ok",
                        "case_id": "alpha.ok",
                        "admitted": True,
                        "reasons": [],
                        "source": "unit",
                    }
                ],
            )
            self.assertEqual(
                main(
                    [
                        "summarize-upstream-inventory",
                        "--inventory-dir",
                        str(inventory_dir),
                        "--output",
                        str(output_path),
                    ]
                ),
                0,
            )
            summary = json.loads(output_path.read_text())
            self.assertEqual(summary["totals"], {"families": 1, "cases": 1, "admitted": 1, "blocked": 0})
            self.assertEqual(summary["families"][0]["family"], "alpha")

    def test_cli_summarize_upstream_inventory_matches_checked_in_first_family_inventories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "summary.json"
            self.assertEqual(
                main(
                    [
                        "summarize-upstream-inventory",
                        "--inventory-dir",
                        str(ROOT / "suites/templates"),
                        "--output",
                        str(output_path),
                    ]
                ),
                0,
            )
            summary = json.loads(output_path.read_text())
            self._assert_checked_in_first_family_inventory_summary(summary)
            self.assertEqual(summary, summarize_inventory_dir(ROOT / "suites/templates"))

    def test_cli_summarize_upstream_inventory_detects_account_query_total_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_dir = Path(tmpdir) / "inventories"
            inventory_dir.mkdir()
            for inventory_path in sorted((ROOT / "suites/templates").glob("*_inventory.json")):
                payload = json.loads(inventory_path.read_text())
                if inventory_path.name == "upstream_account_query_inventory.json":
                    payload["entries"] = payload["entries"][:-1]
                (inventory_dir / inventory_path.name).write_text(json.dumps(payload, indent=2) + "\n")

            helper_summary = summarize_inventory_dir(inventory_dir)
            self.assertEqual(
                helper_summary["totals"],
                {"families": 14, "cases": 612, "admitted": 536, "blocked": 76},
            )
            self.assertNotEqual(
                helper_summary["totals"],
                {"families": 14, "cases": 613, "admitted": 537, "blocked": 76},
            )

            output_path = Path(tmpdir) / "summary.json"
            self.assertEqual(
                main(
                    [
                        "summarize-upstream-inventory",
                        "--inventory-dir",
                        str(inventory_dir),
                        "--output",
                        str(output_path),
                    ]
                ),
                0,
            )
            cli_summary = json.loads(output_path.read_text())
            self.assertEqual(cli_summary, helper_summary)
            self.assertEqual(
                cli_summary["totals"],
                {"families": 14, "cases": 612, "admitted": 536, "blocked": 76},
            )
            account_query_row = next(item for item in cli_summary["families"] if item["family"] == "account-query")
            self.assertEqual(
                {
                    "total": account_query_row["total"],
                    "admitted": account_query_row["admitted"],
                    "blocked": account_query_row["blocked"],
                },
                {"total": 39, "admitted": 9, "blocked": 30},
            )

    def test_summarize_rpc_reports_includes_inventory_coverage_reference(self) -> None:
        passed = ExecutionResult(
            case_id="passing-case",
            namespace="ns-pass",
            success=True,
            tx_hashes=[],
            context={},
            observed={},
            expected={},
            diffs=[],
        )
        failed = ExecutionResult(
            case_id="failing-case",
            namespace="ns-fail",
            success=False,
            tx_hashes=[],
            context={},
            observed={},
            expected={},
            diffs=["boom"],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            report_path = tmp_path / "reports" / "sample.json"
            output_path = tmp_path / "summary.json"
            write_report(
                Report(
                    manifest="sample-manifest",
                    execution_specs_ref="test-ref",
                    suite_version="0.1.0",
                    chain_profile="mock-devnet",
                    chain_profile_version="1",
                    results=[passed, failed],
                ),
                report_path,
            )

            self.assertEqual(
                summarize_rpc_reports_main(
                    [
                        "--report",
                        str(report_path),
                        "--inventory-dir",
                        str(ROOT / "suites/templates"),
                        "--output",
                        str(output_path),
                    ]
                ),
                1,
            )
            summary = json.loads(output_path.read_text())

        self.assertEqual(summary["totals"], {"families": 1, "selected": 2, "passed": 1, "failed": 1})
        self.assertEqual(summary["coverage_reference"], {"families": 14, "cases": 613, "admitted": 537, "blocked": 76})
        self.assertEqual(summary["families"][0]["failed_cases"], ["failing-case"])
        self.assertFalse(summary["coverage_alignment"]["selected_equals_admitted"])
        self.assertFalse(summary["coverage_alignment"]["failed_zero"])

    def test_sync_upstream_artifacts_stages_all_families_without_applying(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            staged_templates = tmp_path / "templates"
            staged_manifests = tmp_path / "manifests"
            staged_templates.mkdir()
            staged_manifests.mkdir()
            storage_inventory_before = (ROOT / "suites/templates/upstream_storage_inventory.json").read_text()

            payload = sync_to_staging(ROOT, staged_templates, staged_manifests)

            self.assertEqual(payload["summary"], {"families": 14, "cases": 613, "admitted": 537, "blocked": 76})
            self.assertEqual(len(payload["families"]), len(FAMILY_SPECS))
            for spec in FAMILY_SPECS:
                self.assertTrue((staged_templates / spec.template_file).exists(), spec.template_file)
                self.assertTrue((staged_templates / spec.inventory_file).exists(), spec.inventory_file)
                self.assertTrue((staged_manifests / spec.manifest_file).exists(), spec.manifest_file)
                load_manifest(staged_manifests / spec.manifest_file)
            self.assertEqual((ROOT / "suites/templates/upstream_storage_inventory.json").read_text(), storage_inventory_before)

    def test_benchmark_coverage_status_doc_matches_checked_in_summary(self) -> None:
        summary = summarize_inventory_dir(ROOT / "suites/templates")
        doc = (ROOT / "docs/benchmark-coverage-status.md").read_text()
        totals = summary["totals"]
        self.assertIn(f"| Families scanned | {totals['families']} |", doc)
        self.assertIn(f"| Total cases | {totals['cases']} |", doc)
        self.assertIn(f"| Admitted cases | {totals['admitted']} |", doc)
        self.assertIn(f"| Blocked cases | {totals['blocked']} |", doc)
        self.assertIn("| bitwise | 12 | Completed by the CLZ-diff witness", doc)
        self.assertIn("## Fork capability coverage contract", doc)
        self.assertIn("Juchain's execution layer is expected to support Prague/Osaka capabilities", doc)
        self.assertIn("Proven on Juchain when `feature_flags.clz=true`", doc)
        self.assertIn("RPC-observable final-storage proof", doc)
        self.assertIn("upstream.benchmark.bitwise.test_clz_same.clz", doc)
        self.assertIn("upstream.benchmark.bitwise.test_clz_diff.clz", doc)
        self.assertIn("does not claim broader Osaka CLZ scenario coverage", doc)
        self.assertIn("Planned first: BLS12-381 and P256VERIFY", doc)
        self.assertIn("Deferred: MODEXP gas boundary, EIP-7702, blob/cell, and block access lists", doc)
        self.assertIn("the 76 blocked cases should remain blocked", doc)
        readme = (ROOT / "README.md").read_text()
        self.assertIn("docs/benchmark-coverage-status.md", readme)
        self.assertIn("Prague/Osaka fork capability coverage contract", readme)

    def test_benchmark_coverage_status_documents_proven_clz(self) -> None:
        doc = (ROOT / "docs/benchmark-coverage-status.md").read_text()
        self.assertIn("Proven on Juchain when `feature_flags.clz=true`", doc)
        self.assertIn("RPC-observable final-storage proof", doc)
        self.assertIn("Profiles without that proof skip CLZ with an explicit capability diagnostic", doc)
        self.assertIn("upstream.benchmark.bitwise.test_clz_same.clz", doc)
        self.assertIn("upstream.benchmark.bitwise.test_clz_diff.clz", doc)
        self.assertIn("does not claim broader Osaka CLZ scenario coverage", doc)
        self.assertIn("BLS12-381 and P256VERIFY", doc)
        self.assertIn("MODEXP gas boundary", doc)

    def test_bootstrapper_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            profile = load_chain_profile(ROOT / "profiles/mock.toml")
            manifest = load_manifest(ROOT / "suites/manifests/custom_storage_smoke.json")
            bootstrapper = StateBootstrapper(profile, tmp_path)
            first = bootstrapper.prepare_case_namespace(manifest.cases[0])
            second = bootstrapper.prepare_case_namespace(manifest.cases[0])
            self.assertEqual(first.namespace, second.namespace)
            registry = json.loads((tmp_path / "namespaces.json").read_text())
            self.assertIn(first.namespace, registry)

    def test_oracle_reports_precise_diff(self) -> None:
        diffs = ResultOracle().compare(
            {"storage": {"0x00": "0x01"}},
            {"storage": {"0x00": "0x02"}},
        )
        self.assertEqual(diffs, ["storage.0x00: expected '0x01', got '0x02'"])

    def test_oracle_resolves_runtime_address_placeholders(self) -> None:
        diffs = ResultOracle().compare(
            {"storage": {"0x00": "$last_contract_word", "0x01": "$admin_account_word"}},
            {
                "storage": {
                    "0x00": "0x000000000000000000000000cccccccccccccccccccccccccccccccccccccccc",
                    "0x01": "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                }
            },
            {
                "$last_contract": "0xcccccccccccccccccccccccccccccccccccccccc",
                "$admin_account": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        )
        self.assertEqual(diffs, [])

    def test_oracle_resolves_runtime_scalar_word_placeholders(self) -> None:
        diffs = ResultOracle().compare(
            {"storage": {"0x00": "$gas_price_word"}},
            {
                "storage": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000007b",
                }
            },
            {"$gas_price": "0x7b"},
        )
        self.assertEqual(diffs, [])

    def test_oracle_rejects_unknown_placeholders(self) -> None:
        with self.assertRaises(ValueError):
            ResultOracle().compare(
                {"storage": {"0x00": "$missing_word"}},
                {"storage": {"0x00": "0x00"}},
                {},
            )

    def test_cli_run_writes_report_and_is_repeatable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/custom_storage_smoke.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            first = json.loads(report_path.read_text())
            self.assertIs(first["results"][0]["success"], True)
            self.assertEqual(main(args), 0)
            second = json.loads(report_path.read_text())
            self.assertEqual(second["results"][0]["namespace"], first["results"][0]["namespace"])
            self.assertTrue(second["results"][0]["tx_hashes"])

    def test_cli_run_operational_manifest_writes_durable_report_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "run",
                        "--profile",
                        str(ROOT / "profiles/mock.toml"),
                        "--manifest",
                        str(ROOT / "suites/manifests/upstream_block_context_mapped.json"),
                        "--state-dir",
                        str(state_dir),
                        "--report",
                        str(report_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            durable_path = Path(payload["durable_report"])
            self.assertEqual(payload["report"], str(report_path))
            self.assertIn(str(report_path), payload["report_artifacts"])
            self.assertIn(str(durable_path), payload["report_artifacts"])
            self.assertTrue(report_path.exists())
            self.assertTrue(durable_path.exists())
            self.assertEqual(json.loads(report_path.read_text()), json.loads(durable_path.read_text()))

    def test_cli_run_operational_manifests_preserve_closeout_evidence(self) -> None:
        scenarios = [
            ("upstream_block_context_mapped.json", "upstream-block-context-mapped", 8),
            ("upstream_log_mapped.json", "upstream-log-mapped", 130),
            ("upstream_system_mapped.json", "upstream-system-mapped", 35),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for manifest_filename, manifest_name, expected_results in scenarios:
                with self.subTest(manifest=manifest_name):
                    case_dir = tmp_path / manifest_name
                    state_dir = case_dir / "state"
                    report_path = case_dir / "report.json"
                    stdout = StringIO()
                    with redirect_stdout(stdout):
                        exit_code = main(
                            [
                                "run",
                                "--profile",
                                str(ROOT / "profiles/mock.toml"),
                                "--manifest",
                                str(ROOT / "suites/manifests" / manifest_filename),
                                "--state-dir",
                                str(state_dir),
                                "--report",
                                str(report_path),
                            ]
                        )
                    self.assertEqual(exit_code, 0)
                    payload = json.loads(stdout.getvalue())
                    durable_path = Path(payload["durable_report"])
                    self.assertEqual(payload["report"], str(report_path))
                    self.assertEqual(
                        durable_path,
                        case_dir / "evidence" / "mock-devnet" / manifest_name / "report.json",
                    )
                    self.assertEqual(
                        set(payload["report_artifacts"]),
                        {str(report_path), str(durable_path)},
                    )
                    self.assertTrue(report_path.exists())
                    self.assertTrue(durable_path.exists())
                    report = json.loads(report_path.read_text())
                    self.assertEqual(report["manifest"], manifest_name)
                    self.assertEqual(report["chain_profile"], "mock-devnet")
                    self.assertEqual(len(report["results"]), expected_results)
                    self.assertTrue(all(result["success"] for result in report["results"]))
                    self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
                    self.assertEqual(report, json.loads(durable_path.read_text()))

    def test_jsonrpc_backend_prepares_send_transaction_defaults(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.admin_key_source = "rpc_unlocked"

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.calls: list[tuple[str, list[object]]] = []

            def _rpc(self, method: str, params: list[object]) -> object:
                self.calls.append((method, params))
                if method == "eth_getTransactionCount":
                    return "0x7"
                if method == "eth_sendTransaction":
                    return "0xdeadbeef"
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hash = backend._send_transaction({"to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "value": "0x1"})
        self.assertEqual(tx_hash, "0xdeadbeef")
        self.assertEqual(backend.calls[0][0], "eth_getTransactionCount")
        sent = backend.calls[1][1][0]
        self.assertEqual(backend.calls[1][0], "eth_sendTransaction")
        self.assertEqual(sent["from"], profile.admin_account)
        self.assertEqual(sent["chainId"], hex(profile.chain_id))
        self.assertEqual(sent["nonce"], "0x7")
        self.assertEqual(sent["to"], "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

    def test_jsonrpc_backend_raises_manifest_gas_to_largest_transaction_floor(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        calldata_4096_nonzero = "0x" + "ff" * 4096

        prepared = backend._prepare_transaction(
            {
                "from": profile.admin_account,
                "chainId": hex(profile.chain_id),
                "nonce": "0x1",
                "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "data": calldata_4096_nonzero,
                "gas": "0xc350",
            }
        )

        self.assertEqual(prepared["gas"], hex(21_000 + 4096 * 4 * 10))
        self.assertLess(int(prepared["gas"], 16), profile.gas_policy.gas_limit)

    def test_jsonrpc_backend_raises_manifest_gas_to_floor_data_cost(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        calldata_1024_nonzero = "0x" + "ff" * 1024

        prepared = backend._prepare_transaction(
            {
                "from": profile.admin_account,
                "chainId": hex(profile.chain_id),
                "nonce": "0x1",
                "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "data": calldata_1024_nonzero,
                "gas": "0xc350",
            }
        )

        self.assertEqual(prepared["gas"], hex(21_000 + 1024 * 4 * 10))
        self.assertLess(int(prepared["gas"], 16), profile.gas_policy.gas_limit)

    def test_jsonrpc_backend_preserves_manifest_gas_above_intrinsic_floor(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)

        prepared = backend._prepare_transaction(
            {
                "from": profile.admin_account,
                "chainId": hex(profile.chain_id),
                "nonce": "0x1",
                "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "data": "0x",
                "gas": "0x55f0",
            }
        )

        self.assertEqual(prepared["gas"], "0x55f0")

    def test_jsonrpc_backend_signs_and_sends_raw_transaction_from_env_key(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        private_key_hex = "0x" + "11" * 32
        os.environ["JUCHAIN_PRIVATE_KEY"] = private_key_hex
        profile.admin_account = private_key_to_address(int(private_key_hex, 16))

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.calls: list[tuple[str, list[object]]] = []

            def _rpc(self, method: str, params: list[object]) -> object:
                self.calls.append((method, params))
                if method == "eth_getTransactionCount":
                    return "0x3"
                if method == "eth_sendRawTransaction":
                    return "0xfeedface"
                raise AssertionError(method)

        try:
            backend = StubBackend(profile)
            tx_hash = backend._send_transaction(
                {"to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "value": "0x1"}
            )
        finally:
            os.environ.pop("JUCHAIN_PRIVATE_KEY", None)
        self.assertEqual(tx_hash, "0xfeedface")
        self.assertEqual(backend.calls[1][0], "eth_sendRawTransaction")
        self.assertTrue(str(backend.calls[1][1][0]).startswith("0x02"))

    def test_jsonrpc_backend_records_effective_gas_price_in_context(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_tx_context_mapped.json")
        gasprice_case = next(
            case for case in manifest.cases if case.case_id == "upstream.benchmark.tx_context.gasprice.success"
        )

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "effectiveGasPrice": "0x4a817c800",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "effectiveGasPrice": "0x4a817c800",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getStorageAt":
                    return "0x00000000000000000000000000000000000000000000000000000004a817c800"
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(gasprice_case, "tx-context-gasprice")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(context["$gas_price"], "0x4a817c800")
        self.assertEqual(
            observed["storage"]["0x00"],
            "0x00000000000000000000000000000000000000000000000000000004a817c800",
        )

    def test_jsonrpc_backend_uses_receipt_block_number_for_block_context_probe(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.block_context.rpc_block_tag = "safe"
        manifest = load_manifest(ROOT / "suites/manifests/upstream_block_context_mapped.json")
        number_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.block_context.test_block_context_ops.number"
        )

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.block_calls: list[list[object]] = []

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x2a",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getBlockByNumber":
                    self.block_calls.append(params)
                    block_tag = params[0]
                    if block_tag == "0x99":
                        return {
                            "miner": "0x1111111111111111111111111111111111111111",
                            "timestamp": "0x65000000",
                            "number": "0x99",
                            "mixHash": "0x" + "22" * 32,
                            "gasLimit": "0x1c9c380",
                            "baseFeePerGas": "0x3b9aca00",
                        }
                    if block_tag == "0x2a":
                        return {
                            "miner": "0x1111111111111111111111111111111111111111",
                            "timestamp": "0x6500002a",
                            "number": "0x2a",
                            "mixHash": "0x" + "33" * 32,
                            "gasLimit": "0x1c9c380",
                            "baseFeePerGas": "0x3b9aca00",
                        }
                    raise AssertionError(block_tag)
                if method == "eth_getStorageAt":
                    return "0x000000000000000000000000000000000000000000000000000000000000002a"
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(number_case, "jsonrpc-block-context-number")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(backend.block_calls, [["0x99", False], ["0x2a", False]])
        self.assertEqual(context["$block_number"], "0x2a")
        self.assertEqual(
            observed["storage"]["0x00"],
            "0x000000000000000000000000000000000000000000000000000000000000002a",
        )
        self.assertEqual(ResultOracle().compare(number_case.expected, observed, context), [])
        self.assertEqual(
            ResultOracle().compare(
                {"storage": {"0x00": "0x000000000000000000000000000000000000000000000000000000000000002b"}},
                observed,
                context,
            ),
            [
                "storage.0x00: expected '0x000000000000000000000000000000000000000000000000000000000000002b', got '0x000000000000000000000000000000000000000000000000000000000000002a'"
            ],
        )

    def test_jsonrpc_backend_observes_plain_storage_at_receipt_block(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_arithmetic_mapped.json")
        arithmetic_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_5.base_7"
        )

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.storage_calls: list[list[object]] = []

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x2a",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getStorageAt":
                    self.storage_calls.append(params)
                    return "0x00000000000000000000000000000000000000000000000000000000000041a7"
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(arithmetic_case, "jsonrpc-arithmetic-exp")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(
            backend.storage_calls,
            [["0xcccccccccccccccccccccccccccccccccccccccc", "0x00", "0x2a"]],
        )
        self.assertEqual(
            observed["storage"]["0x00"],
            "0x00000000000000000000000000000000000000000000000000000000000041a7",
        )
        self.assertEqual(ResultOracle().compare(arithmetic_case.expected, observed, context), [])

    def test_jsonrpc_backend_retries_dns_transport_failures_before_request_reaches_rpc(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        calls = {"count": 0}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).encode()

        def fake_urlopen(request, timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                raise urllib.error.URLError(socket.gaierror(8, "nodename nor servname provided, or not known"))
            return Response()

        original_urlopen = urllib.request.urlopen
        try:
            urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
            self.assertEqual(backend._rpc("eth_chainId", []), "0x1")
        finally:
            urllib.request.urlopen = original_urlopen  # type: ignore[assignment]
        self.assertEqual(calls["count"], 2)

    def test_jsonrpc_backend_retries_urlopen_timeout_transport_failures_before_request_reaches_rpc(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        calls = {"count": 0}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).encode()

        def fake_urlopen(request, timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                raise urllib.error.URLError(TimeoutError("The handshake operation timed out"))
            return Response()

        original_urlopen = urllib.request.urlopen
        try:
            urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
            self.assertEqual(backend._rpc("eth_chainId", []), "0x1")
        finally:
            urllib.request.urlopen = original_urlopen  # type: ignore[assignment]
        self.assertEqual(calls["count"], 2)

    def test_jsonrpc_backend_retries_ssl_transport_failures_before_request_reaches_rpc(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        calls = {"count": 0}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).encode()

        def fake_urlopen(request, timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                raise urllib.error.URLError(ssl.SSLError("UNEXPECTED_EOF_WHILE_READING"))
            return Response()

        original_urlopen = urllib.request.urlopen
        try:
            urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
            self.assertEqual(backend._rpc("eth_chainId", []), "0x1")
        finally:
            urllib.request.urlopen = original_urlopen  # type: ignore[assignment]
        self.assertEqual(calls["count"], 2)

    def test_jsonrpc_backend_retries_read_only_rpc_timeouts(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        calls = {"count": 0}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self) -> bytes:
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x7"}).encode()

        def fake_urlopen(request, timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                raise TimeoutError("The read operation timed out")
            return Response()

        original_urlopen = urllib.request.urlopen
        try:
            urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
            self.assertEqual(backend._rpc("eth_getTransactionCount", [profile.admin_account, "pending"]), "0x7")
        finally:
            urllib.request.urlopen = original_urlopen  # type: ignore[assignment]
        self.assertEqual(calls["count"], 2)

    def test_jsonrpc_backend_does_not_retry_raw_transaction_response_timeouts(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        calls = {"count": 0}

        def fake_urlopen(request, timeout):
            calls["count"] += 1
            raise TimeoutError("The read operation timed out")

        original_urlopen = urllib.request.urlopen
        try:
            urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
            with self.assertRaisesRegex(TimeoutError, "rpc timeout for eth_sendRawTransaction"):
                backend._rpc("eth_sendRawTransaction", ["0xdeadbeef"])
        finally:
            urllib.request.urlopen = original_urlopen  # type: ignore[assignment]
        self.assertEqual(calls["count"], 1)

    def test_jsonrpc_backend_retries_storage_read_when_receipt_block_header_lags(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_arithmetic_mapped.json")
        arithmetic_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_5.base_7"
        )

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.storage_attempts = 0

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {"transactionHash": tx_hash, "status": "0x1", "blockNumber": "0x2a"}
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getStorageAt":
                    self.storage_attempts += 1
                    if self.storage_attempts == 1:
                        raise RuntimeError("rpc error for eth_getStorageAt: code=-32000 message='header not found'")
                    return "0x00000000000000000000000000000000000000000000000000000000000041a7"
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(arithmetic_case, "jsonrpc-arithmetic-exp")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(backend.storage_attempts, 2)
        self.assertEqual(ResultOracle().compare(arithmetic_case.expected, observed, context), [])

    def test_jsonrpc_backend_observes_block_context_storage_at_receipt_block(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.block_context.rpc_block_tag = "safe"
        manifest = load_manifest(ROOT / "suites/manifests/upstream_block_context_mapped.json")
        timestamp_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.block_context.test_block_context_ops.timestamp"
        )

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.block_calls: list[list[object]] = []
                self.storage_calls: list[list[object]] = []

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x2a",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getBlockByNumber":
                    self.block_calls.append(params)
                    block_tag = params[0]
                    if block_tag == "0x99":
                        return {
                            "miner": "0x1111111111111111111111111111111111111111",
                            "timestamp": "0x65000099",
                            "number": "0x99",
                            "mixHash": "0x" + "22" * 32,
                            "gasLimit": "0x1c9c380",
                            "baseFeePerGas": "0x3b9aca00",
                        }
                    if block_tag == "0x2a":
                        return {
                            "miner": "0x1111111111111111111111111111111111111111",
                            "timestamp": "0x6500002a",
                            "number": "0x2a",
                            "mixHash": "0x" + "33" * 32,
                            "gasLimit": "0x1c9c380",
                            "baseFeePerGas": "0x3b9aca00",
                        }
                    raise AssertionError(block_tag)
                if method == "eth_getStorageAt":
                    self.storage_calls.append(params)
                    return "0x000000000000000000000000000000000000000000000000000000006500002a"
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(timestamp_case, "jsonrpc-block-context-timestamp")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(backend.block_calls, [["0x99", False], ["0x2a", False]])
        self.assertEqual(
            backend.storage_calls,
            [["0xcccccccccccccccccccccccccccccccccccccccc", "0x00", "0x2a"]],
        )
        self.assertEqual(context["$block_timestamp"], "0x6500002a")
        self.assertEqual(
            observed["storage"]["0x00"],
            "0x000000000000000000000000000000000000000000000000000000006500002a",
        )
        self.assertEqual(ResultOracle().compare(timestamp_case.expected, observed, context), [])

    def test_jsonrpc_backend_observes_system_witness_storage_at_receipt_block(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        return_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_return_revert.return.empty"
        )

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.storage_calls: list[list[object]] = []

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x2a",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getStorageAt":
                    self.storage_calls.append(params)
                    slot = params[1]
                    values = {
                        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                        "0x01": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "0x02": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    }
                    return values[slot]
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(return_case, "jsonrpc-system-witness")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(
            backend.storage_calls,
            [
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x00", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x01", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x02", "0x2a"],
            ],
        )
        self.assertEqual(context["$last_contract"], "0xcccccccccccccccccccccccccccccccccccccccc")
        self.assertEqual(
            observed["system_witness"],
            {
                "shape": "return_revert_self_call",
                "success": True,
                "returndata_size": 0,
                "returndata_digest": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            },
        )
        self.assertEqual(ResultOracle().compare(return_case.expected, observed, context), [])

    def test_create_empty_child_system_witness_storage_slots_include_balance_for_value(self) -> None:
        zero_value_witness = {
            "version": 1,
            "shape": "create_empty_child",
            "subject": "$last_contract",
            "opcode": "CREATE",
            "value": 0,
            "initcode_size": 0,
        }
        value_witness = {
            "version": 1,
            "shape": "create_empty_child",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 1,
            "initcode_size": 0,
            "salt": 42,
        }
        self.assertEqual(system_witness_storage_slots(zero_value_witness), ("0x00", "0x01", "0x02"))
        self.assertEqual(system_witness_storage_slots(value_witness), ("0x00", "0x01", "0x02", "0x03"))
        self.assertEqual(
            collect_system_witness_from_storage(
                witness_config=value_witness,
                storage={
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x01": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                    "0x02": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x03": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            ),
            {
                "shape": "create_empty_child",
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": 0,
                "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                "created_balance": 1,
            },
        )

    def test_create_child_code_system_witness_storage_slots_include_code_hash(self) -> None:
        witness = {
            "version": 1,
            "shape": "create_child_code",
            "subject": "$last_contract",
            "opcode": "CREATE",
            "value": 0,
            "initcode_size": 6144,
            "data_kind": "zero",
        }
        self.assertEqual(system_witness_storage_slots(witness), ("0x00", "0x01", "0x02", "0x03"))

    def test_collect_create_child_code_system_witness_from_storage(self) -> None:
        witness = {
            "version": 1,
            "shape": "create_child_code",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 6144,
            "data_kind": "zero",
            "salt": 42,
        }
        code_hash = "0x" + keccak256(b"\x00" * 6144).hex()
        self.assertEqual(
            collect_system_witness_from_storage(
                witness_config=witness,
                storage={
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x01": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                    "0x02": "0x0000000000000000000000000000000000000000000000000000000000001800",
                    "0x03": code_hash,
                },
            ),
            {
                "shape": "create_child_code",
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": 6144,
                "created_code_hash": code_hash,
                "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
            },
        )

    def test_create_collision_system_witness_storage_slots(self) -> None:
        witness = {
            "version": 1,
            "shape": "create_collision",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 0,
            "salt": 0,
            "proxy_call_gas": 100000,
        }
        self.assertEqual(system_witness_storage_slots(witness), ("0x00", "0x01", "0x02", "0x03", "0x04", "0x05"))

    def test_collect_create_collision_system_witness_from_storage(self) -> None:
        witness = {
            "version": 1,
            "shape": "create_collision",
            "subject": "$last_contract",
            "opcode": "CREATE2",
            "value": 0,
            "initcode_size": 0,
            "salt": 0,
            "proxy_call_gas": 100000,
        }
        self.assertEqual(
            collect_system_witness_from_storage(
                witness_config=witness,
                storage={
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x02": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                    "0x03": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x04": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x05": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
            ),
            {
                "shape": "create_collision",
                "proxy_deploy_success": True,
                "first_create_call_success": True,
                "first_created_address_nonzero": True,
                "first_created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                "first_created_code_size": 0,
                "collision_call_success": False,
                "collision_returndata_size": 0,
            },
        )

    def test_selfdestruct_single_system_witness_storage_slots(self) -> None:
        zero_value_witness = {
            "version": 1,
            "shape": "selfdestruct_single",
            "subject": "$last_contract",
            "scenario": "created",
            "value": 0,
            "hardfork_semantics": "cancun",
        }
        value_witness = dict(zero_value_witness, value=1)
        self.assertEqual(system_witness_storage_slots(zero_value_witness), ("0x00", "0x01", "0x02", "0x03"))
        self.assertEqual(system_witness_storage_slots(value_witness), ("0x00", "0x01", "0x02", "0x03", "0x04"))

    def test_collect_selfdestruct_single_system_witness_from_storage(self) -> None:
        witness = {
            "version": 1,
            "shape": "selfdestruct_single",
            "subject": "$last_contract",
            "scenario": "created",
            "value": 1,
            "hardfork_semantics": "cancun",
        }
        self.assertEqual(
            collect_system_witness_from_storage(
                witness_config=witness,
                storage={
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x01": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                    "0x02": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x03": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x04": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            ),
            {
                "shape": "selfdestruct_single",
                "scenario": "created",
                "create_success": True,
                "child_address_nonzero": True,
                "child_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                "selfdestruct_call_success": True,
                "child_code_size_after": 0,
                "beneficiary_balance_after": 1,
            },
        )

    def test_selfdestruct_existing_system_witness_storage_slots(self) -> None:
        zero_value_witness = {
            "version": 1,
            "shape": "selfdestruct_single",
            "subject": "$last_contract",
            "scenario": "existing",
            "value": 0,
            "hardfork_semantics": "cancun",
        }
        value_witness = dict(zero_value_witness, value=1)
        self.assertEqual(system_witness_storage_slots(zero_value_witness), ("0x00", "0x01", "0x02", "0x03", "0x04"))
        self.assertEqual(system_witness_storage_slots(value_witness), ("0x00", "0x01", "0x02", "0x03", "0x04", "0x05"))

    def test_collect_selfdestruct_existing_system_witness_from_storage(self) -> None:
        witness = {
            "version": 1,
            "shape": "selfdestruct_single",
            "subject": "$last_contract",
            "scenario": "existing",
            "value": 1,
            "hardfork_semantics": "cancun",
        }
        self.assertEqual(
            collect_system_witness_from_storage(
                witness_config=witness,
                storage={
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x01": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                    "0x02": "0x0000000000000000000000000000000000000000000000000000000000000002",
                    "0x03": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x04": "0x0000000000000000000000000000000000000000000000000000000000000002",
                    "0x05": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            ),
            {
                "shape": "selfdestruct_single",
                "scenario": "existing",
                "setup_create_success": True,
                "child_address_nonzero": True,
                "child_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                "child_code_size_before": 2,
                "selfdestruct_call_success": True,
                "child_code_size_after": 2,
                "beneficiary_balance_after": 1,
            },
        )

    def test_jsonrpc_backend_observes_create_empty_child_witness_storage_at_receipt_block(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        create_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_return_revert.return.empty"
        )
        create_case.observe = {
            "system_witness": {
                "version": 1,
                "shape": "create_empty_child",
                "subject": "$last_contract",
                "opcode": "CREATE2",
                "value": 0,
                "initcode_size": 0,
                "salt": 42,
            }
        }
        create_case.expected = {
            "receipt_status": "0x1",
            "system_witness": {
                "shape": "create_empty_child",
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": 0,
            },
        }

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.storage_calls: list[list[object]] = []

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x2a",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getStorageAt":
                    self.storage_calls.append(params)
                    slot = params[1]
                    values = {
                        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                        "0x01": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                        "0x02": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    }
                    return values[slot]
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(create_case, "jsonrpc-create-empty-witness")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(
            backend.storage_calls,
            [
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x00", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x01", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x02", "0x2a"],
            ],
        )
        self.assertEqual(
            observed["system_witness"],
            {
                "shape": "create_empty_child",
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": 0,
                "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
            },
        )
        self.assertEqual(ResultOracle().compare(create_case.expected, observed, context), [])

    def test_jsonrpc_backend_observes_value_bearing_create_empty_child_witness_storage_at_receipt_block(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        create_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_create.create.0_bytes_without_value"
        )
        create_case.observe["system_witness"]["value"] = 1
        create_case.expected["system_witness"]["created_balance"] = 1

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.storage_calls: list[list[object]] = []

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x2a",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getStorageAt":
                    self.storage_calls.append(params)
                    slot = params[1]
                    values = {
                        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                        "0x01": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                        "0x02": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "0x03": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    }
                    return values[slot]
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(create_case, "jsonrpc-create-value-witness")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(
            backend.storage_calls,
            [
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x00", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x01", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x02", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x03", "0x2a"],
            ],
        )
        self.assertEqual(observed["system_witness"]["created_balance"], 1)
        self.assertEqual(ResultOracle().compare(create_case.expected, observed, context), [])

    def test_jsonrpc_backend_observes_create_child_code_witness_storage_at_receipt_block(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        create_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_create.create.0_bytes_without_value"
        )
        code_hash = "0x" + keccak256(b"\x00" * 6144).hex()
        create_case.observe["system_witness"] = {
            "version": 1,
            "shape": "create_child_code",
            "subject": "$last_contract",
            "opcode": "CREATE",
            "value": 0,
            "initcode_size": 6144,
            "data_kind": "zero",
        }
        create_case.expected["system_witness"] = {
            "shape": "create_child_code",
            "success": True,
            "created_address_nonzero": True,
            "created_code_size": 6144,
            "created_code_hash": code_hash,
        }

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.sent = 0
                self.storage_calls: list[list[object]] = []

            def _send_transaction(self, transaction: dict[str, Any]) -> str:
                self.sent += 1
                return f"0xtx{self.sent}"

            def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
                if tx_hash == "0xtx1":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "contractAddress": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "blockNumber": "0x99",
                    }
                if tx_hash == "0xtx2":
                    return {
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x2a",
                    }
                raise AssertionError(tx_hash)

            def _rpc(self, method: str, params: list[object]) -> object:
                if method == "eth_getStorageAt":
                    self.storage_calls.append(params)
                    slot = params[1]
                    values = {
                        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                        "0x01": "0x000000000000000000000000dddddddddddddddddddddddddddddddddddddddd",
                        "0x02": "0x0000000000000000000000000000000000000000000000000000000000001800",
                        "0x03": code_hash,
                    }
                    return values[slot]
                raise AssertionError(method)

        backend = StubBackend(profile)
        tx_hashes, observed, context = backend.execute_case(create_case, "jsonrpc-create-child-code-witness")
        self.assertEqual(tx_hashes, ["0xtx1", "0xtx2"])
        self.assertEqual(
            backend.storage_calls,
            [
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x00", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x01", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x02", "0x2a"],
                ["0xcccccccccccccccccccccccccccccccccccccccc", "0x03", "0x2a"],
            ],
        )
        self.assertEqual(
            observed["system_witness"],
            {
                "shape": "create_child_code",
                "success": True,
                "created_address_nonzero": True,
                "created_code_size": 6144,
                "created_code_hash": code_hash,
                "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
            },
        )
        self.assertEqual(ResultOracle().compare(create_case.expected, observed, context), [])

    def test_jsonrpc_backend_load_block_context_falls_back_to_profile_block_tag(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.block_context.rpc_block_tag = "safe"

        class StubBackend(JsonRpcBackend):
            def __init__(self, profile):
                super().__init__(profile)
                self.block_calls: list[list[object]] = []

            def _rpc(self, method: str, params: list[object]) -> object:
                self.block_calls.append(params)
                if method != "eth_getBlockByNumber":
                    raise AssertionError(method)
                if params != ["safe", False]:
                    raise AssertionError(params)
                return {
                    "miner": "0x1111111111111111111111111111111111111111",
                    "timestamp": "0x65000000",
                    "number": "0x2a",
                    "mixHash": "0x" + "44" * 32,
                    "gasLimit": "0x1c9c380",
                    "baseFeePerGas": "0x3b9aca00",
                }

        backend = StubBackend(profile)
        context = backend._load_block_context({"transactionHash": "0xtx2", "status": "0x1"})
        self.assertEqual(backend.block_calls, [["safe", False]])
        self.assertEqual(
            context,
            {
                "chainid": hex(profile.chain_id),
                "coinbase": "0x1111111111111111111111111111111111111111",
                "timestamp": "0x65000000",
                "number": "0x2a",
                "prevrandao": "0x" + "44" * 32,
                "gaslimit": "0x1c9c380",
                "basefee": "0x3b9aca00",
            },
        )

    def test_jsonrpc_backend_load_block_context_rejects_missing_receipt_block_result(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")

        class StubBackend(JsonRpcBackend):
            def _rpc(self, method: str, params: list[object]) -> object:
                if method != "eth_getBlockByNumber":
                    raise AssertionError(method)
                if params != ["0x2a", False]:
                    raise AssertionError(params)
                return None

        backend = StubBackend(profile)
        with self.assertRaisesRegex(
            ValueError,
            r"block context receipt-block '0x2a' returned no block from eth_getBlockByNumber",
        ):
            backend._load_block_context({"transactionHash": "0xtx2", "status": "0x1", "blockNumber": "0x2a"})

    def test_jsonrpc_backend_load_block_context_rejects_missing_required_field(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")

        class StubBackend(JsonRpcBackend):
            def _rpc(self, method: str, params: list[object]) -> object:
                if method != "eth_getBlockByNumber":
                    raise AssertionError(method)
                if params != ["0x2a", False]:
                    raise AssertionError(params)
                return {
                    "miner": "0x1111111111111111111111111111111111111111",
                    "timestamp": "0x65000000",
                    "number": "0x2a",
                    "mixHash": "0x" + "55" * 32,
                    "gasLimit": None,
                    "baseFeePerGas": "0x3b9aca00",
                }

        backend = StubBackend(profile)
        with self.assertRaisesRegex(
            ValueError,
            "block context receipt-block '0x2a' missing required field gasLimit for gaslimit",
        ):
            backend._load_block_context({"transactionHash": "0xtx2", "status": "0x1", "blockNumber": "0x2a"})

    def test_jsonrpc_backend_wait_for_receipt_reports_poll_count_on_timeout(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")

        class StubBackend(JsonRpcBackend):
            def _rpc(self, method: str, params: list[object]) -> object:
                if method != "eth_getTransactionReceipt":
                    raise AssertionError(method)
                return None

        backend = StubBackend(profile)
        with self.assertRaisesRegex(
            TimeoutError,
            r"timed out waiting for receipt after 2s and 2 polls: 0xtimeout",
        ):
            backend._wait_for_receipt("0xtimeout", timeout_seconds=2)

    def test_jsonrpc_backend_wraps_socket_timeout_with_method_and_endpoint(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)

        original_urlopen = urllib.request.urlopen

        def fake_urlopen(*args: object, **kwargs: object) -> object:
            raise socket.timeout("timed out")

        urllib.request.urlopen = fake_urlopen
        try:
            with self.assertRaisesRegex(
                TimeoutError,
                rf"rpc timeout for eth_blockNumber after {backend.rpc_timeout_seconds}s against https://testnet-rpc\.juchain\.org",
            ):
                backend._rpc("eth_blockNumber", [])
        finally:
            urllib.request.urlopen = original_urlopen

    def test_jsonrpc_backend_timeout_redacts_rpc_credentials(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.rpc_url = "https://user:secret@example.invalid/path?token=abc"
        backend = JsonRpcBackend(profile)

        original_urlopen = urllib.request.urlopen

        def fake_urlopen(*args: object, **kwargs: object) -> object:
            raise socket.timeout("timed out")

        urllib.request.urlopen = fake_urlopen
        try:
            with self.assertRaises(TimeoutError) as error:
                backend._rpc("eth_blockNumber", [])
        finally:
            urllib.request.urlopen = original_urlopen

        message = str(error.exception)
        self.assertIn("against https://example.invalid", message)
        self.assertNotIn("secret", message)
        self.assertNotIn("token=abc", message)

    def test_jsonrpc_backend_passes_explicit_timeout_to_urlopen(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        backend.rpc_timeout_seconds = 3
        observed_timeouts: list[object] = []

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                return False

            def read(self) -> bytes:
                return b'{"jsonrpc":"2.0","id":1,"result":"0x1"}'

        original_urlopen = urllib.request.urlopen

        def fake_urlopen(*args: object, **kwargs: object) -> Response:
            observed_timeouts.append(kwargs.get("timeout"))
            return Response()

        urllib.request.urlopen = fake_urlopen
        try:
            self.assertEqual(backend._rpc("eth_blockNumber", []), "0x1")
        finally:
            urllib.request.urlopen = original_urlopen

        self.assertEqual(observed_timeouts, [3])

    def test_jsonrpc_backend_rejects_transport_error_with_redacted_endpoint(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        profile.rpc_url = "https://user:secret@example.invalid/path?token=abc"
        backend = JsonRpcBackend(profile)

        original_urlopen = urllib.request.urlopen

        def fake_urlopen(*args: object, **kwargs: object) -> object:
            raise urllib.error.URLError("connection refused")

        urllib.request.urlopen = fake_urlopen
        try:
            with self.assertRaises(RuntimeError) as error:
                backend._rpc("eth_blockNumber", [])
        finally:
            urllib.request.urlopen = original_urlopen

        message = str(error.exception)
        self.assertIn("rpc transport error for eth_blockNumber against https://example.invalid", message)
        self.assertIn("connection refused", message)
        self.assertNotIn("secret", message)
        self.assertNotIn("token=abc", message)

    def test_jsonrpc_backend_rejects_jsonrpc_error_response(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                return False

            def read(self) -> bytes:
                return b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}'

        original_urlopen = urllib.request.urlopen

        def fake_urlopen(*args: object, **kwargs: object) -> Response:
            return Response()

        urllib.request.urlopen = fake_urlopen
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                r"rpc error for eth_call: code=-32000 message='execution reverted'",
            ):
                backend._rpc("eth_call", [])
        finally:
            urllib.request.urlopen = original_urlopen

    def test_jsonrpc_backend_rejects_non_object_response(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                return False

            def read(self) -> bytes:
                return b'[]'

        original_urlopen = urllib.request.urlopen

        def fake_urlopen(*args: object, **kwargs: object) -> Response:
            return Response()

        urllib.request.urlopen = fake_urlopen
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                r"rpc response for eth_blockNumber must be a JSON object",
            ):
                backend._rpc("eth_blockNumber", [])
        finally:
            urllib.request.urlopen = original_urlopen

    def test_jsonrpc_backend_rejects_response_without_result_field(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, exc_type, exc, tb) -> bool:
                return False

            def read(self) -> bytes:
                return b'{"jsonrpc":"2.0","id":1}'

        original_urlopen = urllib.request.urlopen

        def fake_urlopen(*args: object, **kwargs: object) -> Response:
            return Response()

        urllib.request.urlopen = fake_urlopen
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                r"rpc response for eth_blockNumber missing result field",
            ):
                backend._rpc("eth_blockNumber", [])
        finally:
            urllib.request.urlopen = original_urlopen

    def test_jsonrpc_backend_rejects_mismatched_admin_account(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        os.environ["JUCHAIN_PRIVATE_KEY"] = "0x" + "11" * 32
        profile.admin_account = "0x0000000000000000000000000000000000000001"
        try:
            backend = JsonRpcBackend(profile)
            with self.assertRaises(ValueError):
                backend._send_transaction({"to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
        finally:
            os.environ.pop("JUCHAIN_PRIVATE_KEY", None)

    def test_sign_type_2_transaction_returns_prefixed_raw_bytes(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        private_key = int("11" * 32, 16)
        raw = sign_type_2_transaction(
            profile,
            private_key,
            {
                "nonce": "0x1",
                "maxPriorityFeePerGas": "0x2",
                "maxFeePerGas": "0x3",
                "gas": "0x5208",
                "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "value": "0x4",
                "data": "0x",
            },
        )
        self.assertTrue(raw.startswith("0x02"))

    def test_mock_backend_records_receipt_status_for_smoke_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/juchain_smoke.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["results"][0]["observed"]["receipt_status"], "0x1")
            self.assertIs(report["results"][0]["success"], True)

    def test_mock_backend_records_deployed_code_for_deploy_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/juchain_deploy_smoke.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            observed = report["results"][0]["observed"]
            self.assertEqual(observed["receipt_status"], "0x1")
            self.assertEqual(observed["receipt_contract_address"], "0xcccccccccccccccccccccccccccccccccccccccc")
            self.assertEqual(observed["code"], "0x00")
            self.assertIs(report["results"][0]["success"], True)

    def test_mock_backend_records_storage_for_storage_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/juchain_storage_smoke.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            observed = report["results"][0]["observed"]
            self.assertEqual(
                observed["storage"]["0x00"],
                "0x000000000000000000000000000000000000000000000000000000000000002a",
            )
            self.assertIs(report["results"][0]["success"], True)

    def test_mock_backend_runs_upstream_mapped_storage_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_storage_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 17)
            expected_storage = {
                "upstream.benchmark.storage.write_new_value.absent_slots.out_of_gas": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.storage.write_new_value.absent_slots.revert": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.storage.write_new_value.absent_slots.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.storage.write_same_value.absent_slots.out_of_gas": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.storage.write_same_value.absent_slots.revert": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.storage.write_same_value.absent_slots.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.storage.write_same_value.present_slots.out_of_gas": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.storage.write_same_value.present_slots.revert": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.storage.write_same_value.present_slots.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.storage.write_new_value.present_slots.out_of_gas": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.storage.write_new_value.present_slots.revert": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.storage.write_new_value.present_slots.success": {
                    "0x00": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                },
                "upstream.benchmark.storage.read.absent_slots.success": {
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.storage.read.present_slots.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "0x01": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.storage.warm.read.present_slots.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "0x01": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.storage.warm.write_same_value.present_slots.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.storage.warm.write_new_value.present_slots.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002b",
                },
            }
            for result in report["results"]:
                self.assertIn(
                    result["case_id"],
                    expected_storage,
                )
                for slot, value in expected_storage[result["case_id"]].items():
                    self.assertEqual(result["observed"]["storage"][slot], value)
                if result["case_id"].endswith(".revert") or result["case_id"].endswith(".out_of_gas"):
                    self.assertEqual(result["observed"]["receipt_status"], "0x0")
                else:
                    self.assertEqual(result["observed"].get("receipt_status"), result["expected"].get("receipt_status"))
                self.assertIs(result["success"], True)

    def test_mock_backend_runs_upstream_mapped_memory_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_memory_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 125)
            
            # Spot-check representative memory-access, MSIZE, and MCOPY cases instead of all 125.
            expected_storage = {
                "upstream.benchmark.memory.mload.offset_0.initialized.mem_size_0.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002b",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.memory.mstore.offset_0.uninitialized.mem_size_0.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.memory.msize.mem_size_1000.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000420",
                },
                "upstream.benchmark.memory.msize.mem_size_1.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000040",
                },
                "upstream.benchmark.memory.mcopy.mem_size_0.copy_size_32.fixed.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000020",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.memory.mcopy.mem_size_1024.copy_size_0.dynamic.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000400",
                },
            }
            
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            for case_id, expected_slots in expected_storage.items():
                self.assertIn(case_id, observed_by_case)
                for slot, value in expected_slots.items():
                    self.assertEqual(observed_by_case[case_id]["observed"]["storage"][slot], value)
            
            for result in report["results"]:
                self.assertEqual(result["diffs"], [])
                self.assertIs(result["success"], True)

    def test_mock_backend_rejects_tampered_mcopy_runtime(self) -> None:
        payload = json.loads((ROOT / "suites/manifests/upstream_memory_mapped.json").read_text())
        target_case = next(
            case
            for case in payload["cases"]
            if case["case_id"] == "upstream.benchmark.memory.mcopy.mem_size_0.copy_size_32.fixed.success"
        )
        target_case["steps"][0]["bytecode_runtime"] = "0x00"
        target_case["steps"][0]["bytecode_init"] = _build_init_code("0x00")
        payload["cases"] = [target_case]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            manifest_path = tmp_path / "tampered_upstream_memory_mapped.json"
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
            self.assertEqual(
                main(
                    [
                        "run",
                        "--profile",
                        str(ROOT / "profiles/mock.toml"),
                        "--manifest",
                        str(manifest_path),
                        "--state-dir",
                        str(state_dir),
                        "--report",
                        str(report_path),
                    ]
                ),
                0,
            )
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 1)
            result = report["results"][0]
            self.assertFalse(result["success"])
            self.assertEqual(result["observed"], {})
            self.assertEqual(
                result["diffs"],
                ["proof error: unsupported mock memory MCOPY contract code path: 0x00"],
            )

    def test_mock_backend_runs_upstream_mapped_stack_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_stack_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 65)

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            representative_storage = {
                "upstream.benchmark.stack.test_push.push0": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.stack.test_push.push32": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.stack.test_dup.dup16": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.stack.test_swap.swap16": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
            }
            self.assertEqual(set(representative_storage).issubset(observed_by_case), True)
            for case_id, expected_slots in representative_storage.items():
                result = observed_by_case[case_id]
                self.assertEqual(result["observed"]["storage"], expected_slots)
                self.assertEqual(result["expected"]["storage"], expected_slots)
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

            for result in report["results"]:
                self.assertEqual(result["diffs"], [])
                self.assertIs(result["success"], True)

    def test_mock_backend_runs_upstream_mapped_control_flow_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_control_flow_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 7)

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            expected_storage = {
                "upstream.benchmark.control_flow.test_gas_op": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.control_flow.test_pc_op": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.control_flow.test_jumps": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.control_flow.test_jump_benchmark": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.control_flow.test_jumpi_fallthrough": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.control_flow.test_jumpis": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.control_flow.test_jumpdests": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            }
            self.assertEqual(set(observed_by_case), set(expected_storage))
            self.assertEqual(
                {result["observed"]["storage"]["0x00"] for result in report["results"]},
                {
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            )
            self.assertEqual(
                {result["context"]["$last_contract"] for result in report["results"]},
                {"0xcccccccccccccccccccccccccccccccccccccccc"},
            )
            for case_id, expected_slots in expected_storage.items():
                result = observed_by_case[case_id]
                self.assertEqual(result["observed"]["storage"], expected_slots)
                self.assertEqual(result["expected"]["storage"], expected_slots)
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

            jumpi_fallthrough = observed_by_case["upstream.benchmark.control_flow.test_jumpi_fallthrough"]
            diffs = ResultOracle().compare(
                {"storage": {"0x00": "0x0000000000000000000000000000000000000000000000000000000000000001"}},
                jumpi_fallthrough["observed"],
                jumpi_fallthrough["context"],
            )
            self.assertEqual(
                diffs,
                [
                    "storage.0x00: expected '0x0000000000000000000000000000000000000000000000000000000000000001', got '0x0000000000000000000000000000000000000000000000000000000000000000'"
                ],
            )

    def test_mock_backend_runs_upstream_mapped_block_context_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            profile = load_chain_profile(ROOT / "profiles/mock.toml")
            coinbase_word = "0x" + profile.block_context.coinbase[2:].lower().rjust(64, "0")
            timestamp_word = "0x" + format(profile.block_context.timestamp, "x").rjust(64, "0")
            number_word = "0x" + format(profile.block_context.number, "x").rjust(64, "0")
            gaslimit_word = "0x" + format(profile.block_context.gas_limit, "x").rjust(64, "0")
            chainid_word = "0x" + format(profile.chain_id, "x").rjust(64, "0")
            basefee_word = "0x" + format(profile.block_context.base_fee, "x").rjust(64, "0")
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_block_context_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 8)

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            expected_storage = {
                "upstream.benchmark.block_context.test_block_context_ops.basefee": {
                    "0x00": basefee_word,
                },
                "upstream.benchmark.block_context.test_blockhash.current_block": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.block_context.test_block_context_ops.chainid": {
                    "0x00": chainid_word,
                },
                "upstream.benchmark.block_context.test_block_context_ops.coinbase": {
                    "0x00": coinbase_word,
                },
                "upstream.benchmark.block_context.test_block_context_ops.gaslimit": {
                    "0x00": gaslimit_word,
                },
                "upstream.benchmark.block_context.test_block_context_ops.number": {
                    "0x00": number_word,
                },
                "upstream.benchmark.block_context.test_block_context_ops.prevrandao": {
                    "0x00": profile.block_context.prevrandao,
                },
                "upstream.benchmark.block_context.test_block_context_ops.timestamp": {
                    "0x00": timestamp_word,
                },
            }
            self.assertEqual(set(observed_by_case), set(expected_storage))
            self.assertEqual(
                {result["context"]["$last_contract"] for result in report["results"]},
                {"0xcccccccccccccccccccccccccccccccccccccccc"},
            )
            for case_id, expected_slots in expected_storage.items():
                result = observed_by_case[case_id]
                self.assertEqual(result["observed"]["storage"], expected_slots)
                self.assertEqual(result["expected"]["storage"], expected_slots)
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

            coinbase = observed_by_case["upstream.benchmark.block_context.test_block_context_ops.coinbase"]
            self.assertEqual(coinbase["context"]["$block_coinbase"], "0x1111111111111111111111111111111111111111")
            chainid = observed_by_case["upstream.benchmark.block_context.test_block_context_ops.chainid"]
            self.assertEqual(chainid["context"]["$chain_id"], "0x539")
            basefee = observed_by_case["upstream.benchmark.block_context.test_block_context_ops.basefee"]
            self.assertEqual(basefee["context"]["$block_basefee"], "0x3b9aca00")

            diffs = ResultOracle().compare(
                {"storage": {"0x00": "$chain_id_word"}},
                chainid["observed"],
                chainid["context"],
            )
            self.assertEqual(diffs, [])

    def test_mock_backend_runs_upstream_mapped_call_context_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_call_context_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 20)
            expected_storage = {
                "upstream.benchmark.call_context.address.success": {
                    "0x00": "0x000000000000000000000000cccccccccccccccccccccccccccccccccccccccc",
                },
                "upstream.benchmark.call_context.caller.success": {
                    "0x00": "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_0.nonzero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_0.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_32.nonzero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_32.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_256.nonzero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000100",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_256.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000100",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_1024.nonzero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000400",
                },
                "upstream.benchmark.call_context.calldatasize.calldata_size_1024.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000400",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_0.nonzero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_0.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_32.nonzero.success": {
                    "0x00": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_32.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_256.nonzero.success": {
                    "0x00": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_256.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_1024.nonzero.success": {
                    "0x00": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_1024.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.callvalue.origin.nonzero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
                "upstream.benchmark.call_context.callvalue.origin.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
            }
            for result in report["results"]:
                self.assertIn(result["case_id"], expected_storage)
                for slot, value in expected_storage[result["case_id"]].items():
                    self.assertEqual(result["observed"]["storage"][slot], value)
                self.assertIs(result["success"], True)

    def test_mock_backend_runs_upstream_mapped_account_query_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_account_query_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 10)
            manifest_payload = json.loads((ROOT / "suites/manifests/upstream_account_query_mapped.json").read_text())
            expected_storage = {case["case_id"]: case["expected"]["storage"] for case in manifest_payload["cases"]}
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(set(observed_by_case), set(expected_storage))
            self.assertEqual(
                [case_id for case_id in observed_by_case if "codecopy.fixed" in case_id],
                [
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_bytes.success",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_25x_max_code_size.success",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_50x_max_code_size.success",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_75x_max_code_size.success",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_max_code_size.success",
                ],
            )
            self.assertNotIn("upstream.benchmark.account_query.extcodecopy", "\n".join(observed_by_case))
            for case_id, expected_slots in expected_storage.items():
                result = observed_by_case[case_id]
                for slot, expected_value in expected_slots.items():
                    self.assertIn(slot, result["observed"]["storage"])
                    if not expected_value.startswith("$"):
                        self.assertEqual(result["observed"]["storage"][slot], expected_value)
                if all(not expected_value.startswith("$") for expected_value in expected_slots.values()):
                    self.assertEqual(result["expected"]["storage"], expected_slots)
                else:
                    for slot in expected_slots:
                        self.assertIn(slot, result["expected"]["storage"])
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

    def test_mock_backend_runs_upstream_mapped_keccak_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_keccak_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 35)

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            representative_storage = {
                "upstream.benchmark.keccak.test_keccak_max_permutations": {
                    "0x00": "0xe75384f0f905e18b92cd7e2618d56152f760b3267ae733c3cfe49953613bb453",
                    "0x01": "0x000000000000000000000000000000000000000000000000000000000001c281",
                    "0x02": "0x000000000000000000000000000000000000000000000000000000000001c2a0",
                },
                "upstream.benchmark.keccak.test_keccak.mem_alloc_empty.offset_0.mem_update_true": {
                    "0x00": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    "0x01": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    "0x02": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.keccak.test_keccak.mem_alloc_ff.offset_31.mem_update_false": {
                    "0x00": "0x979b141b8bcd3ba17815cd76811f1fca1cabaa9d51f7c00712606970f81d6e37",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000066",
                    "0x02": "0x0000000000000000000000000000000000000000000000000000000000000040",
                },
                "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes.mem_size_32.msg_size_1024": {
                    "0x00": "0x0aaeac84b5b031a238322b0ed1d1d21cf1f2021112dc8d7ab6dcaa960f103c7d",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000400",
                    "0x02": "0x0000000000000000000000000000000000000000000000000000000000000400",
                },
            }
            self.assertEqual(set(representative_storage).issubset(observed_by_case), True)
            for case_id, expected_slots in representative_storage.items():
                result = observed_by_case[case_id]
                self.assertEqual(result["observed"]["storage"], expected_slots)
                self.assertEqual(result["expected"]["storage"], expected_slots)
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

            for result in report["results"]:
                self.assertEqual(result["diffs"], [], result["case_id"])
                self.assertTrue(result["success"], result["case_id"])
                self.assertEqual(result["observed"], result["expected"], result["case_id"])

    def test_mock_backend_runs_upstream_mapped_bitwise_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_bitwise_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 12)

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            representative_storage = {
                "upstream.benchmark.bitwise.test_bitwise.and": {
                    "0x00": "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffe00000001",
                },
                "upstream.benchmark.bitwise.test_not_op.not": {
                    "0x00": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                },
                "upstream.benchmark.bitwise.test_clz_same.clz": {
                    "0x00": "0x00000000000000000000000000000000000000000000000000000000000000f8",
                },
                "upstream.benchmark.bitwise.test_shifts.shr": {
                    "0x00": "0x0000100000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.bitwise.test_shifts.sar": {
                    "0x00": "0xfffffffffffffffe000000000000000000000000000000000000000000000000",
                },
            }
            self.assertEqual(set(representative_storage).issubset(observed_by_case), True)
            for case_id, expected_slots in representative_storage.items():
                result = observed_by_case[case_id]
                self.assertEqual(result["observed"]["storage"], expected_slots)
                self.assertEqual(result["expected"]["storage"], expected_slots)
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

            for result in report["results"]:
                self.assertEqual(result["diffs"], [], result["case_id"])
                self.assertTrue(result["success"], result["case_id"])
                self.assertEqual(result["observed"], result["expected"], result["case_id"])

    def test_mock_backend_runs_upstream_mapped_comparison_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_comparison_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 6)

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(
                {case_id: result["observed"]["storage"]["0x00"] for case_id, result in observed_by_case.items()},
                {
                    "upstream.benchmark.comparison.test_comparison.eq": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.comparison.test_comparison.gt": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.comparison.test_comparison.lt": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.comparison.test_comparison.sgt": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.comparison.test_comparison.slt": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.comparison.test_iszero.iszero": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            )
            for result in report["results"]:
                self.assertEqual(result["observed"], result["expected"], result["case_id"])
                self.assertEqual(result["diffs"], [], result["case_id"])
                self.assertTrue(result["tx_hashes"], result["case_id"])
                self.assertIs(result["success"], True)

    def test_cli_run_mock_upstream_control_flow_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_control_flow_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-control-flow-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 7)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(
                {case_id: result["observed"]["storage"]["0x00"] for case_id, result in observed_by_case.items()},
                {
                    "upstream.benchmark.control_flow.test_gas_op": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.control_flow.test_jump_benchmark": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.control_flow.test_jumpdests": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.control_flow.test_jumpi_fallthrough": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.control_flow.test_jumpis": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.control_flow.test_jumps": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.control_flow.test_pc_op": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.control_flow.test_jump_benchmark"]["observed"],
                observed_by_case["upstream.benchmark.control_flow.test_jump_benchmark"]["expected"],
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.control_flow.test_jumpi_fallthrough"]["observed"],
                observed_by_case["upstream.benchmark.control_flow.test_jumpi_fallthrough"]["expected"],
            )

    def test_cli_run_mock_upstream_block_context_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            profile = load_chain_profile(ROOT / "profiles/mock.toml")
            coinbase_word = "0x" + profile.block_context.coinbase[2:].lower().rjust(64, "0")
            timestamp_word = "0x" + format(profile.block_context.timestamp, "x").rjust(64, "0")
            number_word = "0x" + format(profile.block_context.number, "x").rjust(64, "0")
            gaslimit_word = "0x" + format(profile.block_context.gas_limit, "x").rjust(64, "0")
            chainid_word = "0x" + format(profile.chain_id, "x").rjust(64, "0")
            basefee_word = "0x" + format(profile.block_context.base_fee, "x").rjust(64, "0")
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_block_context_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-block-context-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 8)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(
                {case_id: result["observed"]["storage"]["0x00"] for case_id, result in observed_by_case.items()},
                {
                    "upstream.benchmark.block_context.test_block_context_ops.basefee": basefee_word,
                    "upstream.benchmark.block_context.test_blockhash.current_block": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.block_context.test_block_context_ops.chainid": chainid_word,
                    "upstream.benchmark.block_context.test_block_context_ops.coinbase": coinbase_word,
                    "upstream.benchmark.block_context.test_block_context_ops.gaslimit": gaslimit_word,
                    "upstream.benchmark.block_context.test_block_context_ops.number": number_word,
                    "upstream.benchmark.block_context.test_block_context_ops.prevrandao": profile.block_context.prevrandao,
                    "upstream.benchmark.block_context.test_block_context_ops.timestamp": timestamp_word,
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.block_context.test_block_context_ops.coinbase"]["expected"],
                observed_by_case["upstream.benchmark.block_context.test_block_context_ops.coinbase"]["observed"],
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.block_context.test_blockhash.current_block"]["expected"],
                observed_by_case["upstream.benchmark.block_context.test_blockhash.current_block"]["observed"],
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.block_context.test_block_context_ops.prevrandao"]["context"]["$block_prevrandao"],
                profile.block_context.prevrandao,
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.block_context.test_block_context_ops.timestamp"]["context"]["$block_timestamp"],
                hex(profile.block_context.timestamp),
            )

    def test_cli_run_mock_upstream_block_context_manifest_fails_on_missing_witness_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            broken_profile_path = tmp_path / "mock-missing-timestamp.toml"
            broken_profile_path.write_text(
                (ROOT / "profiles/mock.toml").read_text().replace(
                    "timestamp = 1717171717\n",
                    "",
                )
            )
            args = [
                "run",
                "--profile",
                str(broken_profile_path),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_block_context_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-block-context-mapped")
            self.assertEqual(len(report["results"]), 8)
            self.assertTrue(all(not result["success"] for result in report["results"]))
            self.assertTrue(
                all(
                    result["diffs"]
                    == [
                        "proof error: missing mock block-context witness config: block_context.timestamp is required"
                    ]
                    for result in report["results"]
                )
            )
            self.assertTrue(all(result["observed"] == {} for result in report["results"]))
            self.assertTrue(all(result["context"] == {} for result in report["results"]))

    def test_cli_run_mock_upstream_account_query_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_account_query_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-account-query-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 10)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"]["storage"] for result in report["results"]}
            self.assertEqual(
                {case_id: storage["0x00"] for case_id, storage in observed_by_case.items()},
                {
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_bytes.success": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_25x_max_code_size.success": "0x0000000000000000000000000000000000000000000000000000000000001800",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_50x_max_code_size.success": "0x0000000000000000000000000000000000000000000000000000000000003000",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_75x_max_code_size.success": "0x0000000000000000000000000000000000000000000000000000000000004800",
                    "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_max_code_size.success": "0x0000000000000000000000000000000000000000000000000000000000006000",
                    "upstream.benchmark.account_query.codesize.success": "0x0000000000000000000000000000000000000000000000000000000000000005",
                    "upstream.benchmark.account_query.balance.cold.present_accounts.success": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "upstream.benchmark.account_query.balance.cold.absent_accounts.success": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.account_query.selfbalance.contract_balance_0.success": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.account_query.selfbalance.contract_balance_1.success": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            )
            for case_id in observed_by_case:
                if "codecopy.fixed" in case_id:
                    self.assertIn("0x01", observed_by_case[case_id])

    def test_cli_run_mock_upstream_keccak_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_keccak_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-keccak-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 35)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(
                {
                    "upstream.benchmark.keccak.test_keccak_max_permutations": observed_by_case[
                        "upstream.benchmark.keccak.test_keccak_max_permutations"
                    ]["observed"]["storage"],
                    "upstream.benchmark.keccak.test_keccak.mem_alloc_empty.offset_0.mem_update_true": observed_by_case[
                        "upstream.benchmark.keccak.test_keccak.mem_alloc_empty.offset_0.mem_update_true"
                    ]["observed"]["storage"],
                    "upstream.benchmark.keccak.test_keccak.mem_alloc_ff.offset_31.mem_update_false": observed_by_case[
                        "upstream.benchmark.keccak.test_keccak.mem_alloc_ff.offset_31.mem_update_false"
                    ]["observed"]["storage"],
                    "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes.mem_size_32.msg_size_1024": observed_by_case[
                        "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes.mem_size_32.msg_size_1024"
                    ]["observed"]["storage"],
                },
                {
                    "upstream.benchmark.keccak.test_keccak_max_permutations": {
                        "0x00": "0xe75384f0f905e18b92cd7e2618d56152f760b3267ae733c3cfe49953613bb453",
                        "0x01": "0x000000000000000000000000000000000000000000000000000000000001c281",
                        "0x02": "0x000000000000000000000000000000000000000000000000000000000001c2a0",
                    },
                    "upstream.benchmark.keccak.test_keccak.mem_alloc_empty.offset_0.mem_update_true": {
                        "0x00": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                        "0x01": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                        "0x02": "0x0000000000000000000000000000000000000000000000000000000000000020",
                    },
                    "upstream.benchmark.keccak.test_keccak.mem_alloc_ff.offset_31.mem_update_false": {
                        "0x00": "0x979b141b8bcd3ba17815cd76811f1fca1cabaa9d51f7c00712606970f81d6e37",
                        "0x01": "0x0000000000000000000000000000000000000000000000000000000000000066",
                        "0x02": "0x0000000000000000000000000000000000000000000000000000000000000040",
                    },
                    "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes.mem_size_32.msg_size_1024": {
                        "0x00": "0x0aaeac84b5b031a238322b0ed1d1d21cf1f2021112dc8d7ab6dcaa960f103c7d",
                        "0x01": "0x0000000000000000000000000000000000000000000000000000000000000400",
                        "0x02": "0x0000000000000000000000000000000000000000000000000000000000000400",
                    },
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.keccak.test_keccak_max_permutations"]["observed"],
                observed_by_case["upstream.benchmark.keccak.test_keccak_max_permutations"]["expected"],
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes.mem_size_32.msg_size_1024"
                ]["observed"],
                observed_by_case[
                    "upstream.benchmark.keccak.test_keccak_diff_mem_msg_sizes.mem_size_32.msg_size_1024"
                ]["expected"],
            )

    def test_cli_run_mock_upstream_bitwise_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_bitwise_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-bitwise-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 12)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(
                {
                    "upstream.benchmark.bitwise.test_shifts.shr": observed_by_case[
                        "upstream.benchmark.bitwise.test_shifts.shr"
                    ]["observed"]["storage"],
                    "upstream.benchmark.bitwise.test_shifts.sar": observed_by_case[
                        "upstream.benchmark.bitwise.test_shifts.sar"
                    ]["observed"]["storage"],
                },
                {
                    "upstream.benchmark.bitwise.test_shifts.shr": {
                        "0x00": "0x0000100000000000000000000000000000000000000000000000000000000000",
                    },
                    "upstream.benchmark.bitwise.test_shifts.sar": {
                        "0x00": "0xfffffffffffffffe000000000000000000000000000000000000000000000000",
                    },
                },
            )

    def test_cli_run_mock_upstream_comparison_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_comparison_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-comparison-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 6)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"]["storage"]["0x00"] for result in report["results"]}
            self.assertEqual(
                observed_by_case,
                {
                    "upstream.benchmark.comparison.test_comparison.eq": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.comparison.test_comparison.gt": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.comparison.test_comparison.lt": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.comparison.test_comparison.sgt": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.comparison.test_comparison.slt": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.comparison.test_iszero.iszero": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            )

    def test_cli_run_mock_upstream_stack_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_stack_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-stack-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 65)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"]["storage"]["0x00"] for result in report["results"]}
            self.assertEqual(
                {
                    "upstream.benchmark.stack.test_push.push0": observed_by_case["upstream.benchmark.stack.test_push.push0"],
                    "upstream.benchmark.stack.test_push.push32": observed_by_case["upstream.benchmark.stack.test_push.push32"],
                    "upstream.benchmark.stack.test_dup.dup16": observed_by_case["upstream.benchmark.stack.test_dup.dup16"],
                    "upstream.benchmark.stack.test_swap.swap16": observed_by_case["upstream.benchmark.stack.test_swap.swap16"],
                },
                {
                    "upstream.benchmark.stack.test_push.push0": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.stack.test_push.push32": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "upstream.benchmark.stack.test_dup.dup16": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "upstream.benchmark.stack.test_swap.swap16": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
            )

    def test_mock_backend_rejects_jsonrpc_only_manifest_action_before_runtime(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/custom_storage_smoke.json")
        broken_case = manifest.cases[0]
        broken_case.steps = [{"action": "rpc_call", "method": "eth_chainId"}]
        with self.assertRaisesRegex(
            ValueError,
            r"case custom\.balance\.and\.storage step 1: action 'rpc_call' is jsonrpc-only and not runnable on mock backend",
        ):
            backend.execute_case(broken_case, "negative-jsonrpc-only-action-on-mock")

    def test_jsonrpc_backend_rejects_mock_only_manifest_action_before_runtime(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        backend = JsonRpcBackend(profile)
        manifest = load_manifest(ROOT / "suites/manifests/juchain_smoke.json")
        broken_case = manifest.cases[0]
        broken_case.steps.insert(0, {"action": "set_balance", "value": "0x1"})
        with self.assertRaisesRegex(
            ValueError,
            r"case juchain\.self-transfer\.receipt step 1: action 'set_balance' is mock-only and not runnable on jsonrpc backend",
        ):
            backend.execute_case(broken_case, "negative-mock-only-action-on-jsonrpc")

    def test_mock_backend_rejects_unsupported_control_flow_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_control_flow_mapped.json")
        broken_case = next(
            case for case in manifest.cases if case.case_id == "upstream.benchmark.control_flow.test_jumps"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-control-flow-runtime")

    def test_mock_backend_rejects_missing_block_context_witness_config(self) -> None:
        backend = MockBackend(
            admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            block_context_config={
                "coinbase": "0x1111111111111111111111111111111111111111",
                "number": 19_000_001,
                "prevrandao": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "gas_limit": 30_000_000,
                "base_fee": 1_000_000_000,
            },
        )
        manifest = load_manifest(ROOT / "suites/manifests/upstream_block_context_mapped.json")
        case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.block_context.test_block_context_ops.timestamp"
        )
        with self.assertRaisesRegex(
            ValueError,
            "missing mock block-context witness config: block_context.timestamp is required",
        ):
            backend.execute_case(case, "negative-missing-block-context-witness")

    def test_mock_backend_rejects_unsupported_block_context_runtime_code_path(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/mock.toml")
        backend = MockBackend(
            admin_account=profile.admin_account,
            chain_id=profile.chain_id,
            block_context_config={
                "coinbase": profile.block_context.coinbase,
                "timestamp": profile.block_context.timestamp,
                "number": profile.block_context.number,
                "prevrandao": profile.block_context.prevrandao,
                "gas_limit": profile.block_context.gas_limit,
                "base_fee": profile.block_context.base_fee,
            },
        )
        manifest = load_manifest(ROOT / "suites/manifests/upstream_block_context_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.block_context.test_block_context_ops.number"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-block-context-runtime")

    def test_mock_backend_rejects_unsupported_account_query_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id
            == "upstream.benchmark.account_query.codecopy.fixed.max_code_size_ratio_0_25x_max_code_size.success"
        )
        self.assertEqual(broken_case.observe["account_query_probe"], {"mode": "codecopy_fixed", "copy_size": 6144})
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-account-query-runtime")

    def test_mock_backend_rejects_unsupported_system_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_return_revert.return.empty"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-system-runtime")

    def test_mock_backend_rejects_malformed_selfdestruct_existing_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_selfdestruct_existing.value_bearing_true"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-selfdestruct-existing-runtime")

    def test_mock_backend_requires_selfdestruct_existing_setup_before_execution(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_selfdestruct_existing.value_bearing_false"
        )
        broken_case.steps = [
            broken_case.steps[0],
            broken_case.steps[1],
            broken_case.steps[4],
            broken_case.steps[5],
        ]
        with self.assertRaisesRegex(
            ValueError,
            "selfdestruct existing execution mode requires prior setup mode storage",
        ):
            backend.execute_case(broken_case, "negative-selfdestruct-existing-without-setup")

    def test_mock_backend_rejects_malformed_system_wrapper_shape(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_return_revert.return.empty"
        )
        runtime = broken_case.steps[0]["bytecode_runtime"]
        broken_case.steps[0]["bytecode_runtime"] = runtime.replace("57", "56", 1)
        broken_case.steps[0]["bytecode_init"] = "0x60" + broken_case.steps[0]["bytecode_runtime"][2:]
        with self.assertRaisesRegex(
            SystemExecutionError,
            r"malformed system wrapper shape: missing canonical wrapper JUMPI",
        ):
            backend.execute_case(broken_case, "negative-malformed-system-wrapper")

    def test_mock_backend_rejects_oversized_system_returndata_declaration(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data"
        )
        runtime = broken_case.steps[0]["bytecode_runtime"]
        broken_case.steps[0]["bytecode_runtime"] = runtime.replace("62100000", "62100001", 1)
        broken_case.steps[0]["bytecode_init"] = "0x60" + broken_case.steps[0]["bytecode_runtime"][2:]
        with self.assertRaisesRegex(
            SystemExecutionError,
            r"system returndata declaration exceeds admitted maximum: 1048577 > 1048576",
        ):
            backend.execute_case(broken_case, "negative-oversized-system-returndata")

    def test_mock_backend_rejects_malformed_system_runtime_hex(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_system_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.system.test_return_revert.return.empty"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xzz"
        broken_case.steps[0]["bytecode_init"] = "0x60zz"
        with self.assertRaisesRegex(SystemExecutionError, r"malformed system runtime hex"):
            backend.execute_case(broken_case, "negative-malformed-system-hex")

    def test_mock_backend_rejects_additional_malformed_system_wrapper_shapes(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        def runtime_for_child(child: bytes) -> str:
            raw = SYSTEM_RUNTIME_HEADER + b"\x60\x09\x57" + child + SYSTEM_SELF_CALL_WRAPPER_SUFFIX
            return "0x" + raw.hex()

        scenarios = [
            (
                "empty child branch",
                runtime_for_child(b""),
                r"malformed system wrapper shape: empty child branch",
            ),
            (
                "invalid child terminator",
                runtime_for_child(b"\x5f\x5f\x00"),
                r"malformed system wrapper shape: child branch must terminate in RETURN or REVERT",
            ),
            (
                "missing canonical push-size push0 ending",
                runtime_for_child(b"\x60\x01\xf3"),
                r"malformed system wrapper shape: child branch must end with canonical PUSH-size/PUSH0 sequence",
            ),
            (
                "undecodable size operand",
                runtime_for_child(b"\x01\x02\x5f\xf3"),
                r"malformed system wrapper shape: could not decode canonical returndata size operand",
            ),
            (
                "zero-size declaration with fill prefix",
                runtime_for_child(SYSTEM_FILL_FF_WORD + b"\x5f\x5f\xf3"),
                r"malformed system wrapper shape: zero-length returndata declaration must not include a fill prefix",
            ),
        ]

        for label, runtime, expected_error in scenarios:
            with self.subTest(label=label):
                with self.assertRaisesRegex(SystemExecutionError, expected_error):
                    backend._parse_system_self_call_witness(runtime)

    def test_cli_run_mock_system_manifest_bounds_malformed_system_case_as_proof_error(self) -> None:
        scenarios = [
            {
                "label": "missing canonical wrapper JUMPI",
                "case_id": "upstream.benchmark.system.test_return_revert.return.1kib_of_non_zero_data",
                "runtime_factory": lambda runtime: runtime.replace("57", "56", 1),
                "expected_diff": "proof error: malformed system wrapper shape: missing canonical wrapper JUMPI",
            },
            {
                "label": "oversized returndata declaration",
                "case_id": "upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data",
                "runtime_factory": lambda runtime: runtime.replace("62100000", "62100001", 1),
                "expected_diff": "proof error: system returndata declaration exceeds admitted maximum: 1048577 > 1048576",
            },
            {
                "label": "malformed runtime hex",
                "case_id": "upstream.benchmark.system.test_return_revert.return.empty",
                "runtime_factory": lambda runtime: "0xzz",
                "expected_diff": "proof error: malformed system runtime hex",
            },
            {
                "label": "create empty child unsupported runtime",
                "case_id": "upstream.benchmark.system.test_create.create.0_bytes_without_value",
                "runtime_factory": lambda runtime: "0xdeadbeef",
                "expected_diff": "proof error: unsupported mock contract code path: 0xdeadbeef",
            },
        ]

        for scenario in scenarios:
            with self.subTest(case=scenario["case_id"], label=scenario["label"]):
                payload = json.loads((ROOT / "suites/manifests/upstream_system_mapped.json").read_text())
                target_case = next(
                    case for case in payload["cases"] if case["case_id"] == scenario["case_id"]
                )
                runtime = scenario["runtime_factory"](target_case["steps"][0]["bytecode_runtime"])
                target_case["steps"][0]["bytecode_runtime"] = runtime
                target_case["steps"][0]["bytecode_init"] = "0x60" + runtime[2:]

                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp_path = Path(tmpdir)
                    state_dir = tmp_path / "state"
                    report_path = tmp_path / "report.json"
                    manifest_path = tmp_path / "broken-system.json"
                    manifest_path.write_text(json.dumps(payload))
                    args = [
                        "run",
                        "--profile",
                        str(ROOT / "profiles/mock.toml"),
                        "--manifest",
                        str(manifest_path),
                        "--state-dir",
                        str(state_dir),
                        "--report",
                        str(report_path),
                    ]
                    self.assertEqual(main(args), 0)
                    report = json.loads(report_path.read_text())

                self.assertEqual(report["manifest"], "upstream-system-mapped")
                self.assertEqual(len(report["results"]), 35)
                broken = next(
                    result for result in report["results"] if result["case_id"] == scenario["case_id"]
                )
                self.assertFalse(broken["success"])
                self.assertEqual(broken["diffs"], [scenario["expected_diff"]])
                self.assertEqual(broken["observed"], {})
                self.assertEqual(broken["context"], {})
                passing = [
                    result for result in report["results"] if result["case_id"] != scenario["case_id"]
                ]
                self.assertEqual(len(passing), 34)
                self.assertTrue(all(result["success"] for result in passing))
                self.assertTrue(all(result["diffs"] == [] for result in passing))

    def test_mock_backend_rejects_unsupported_log_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_log_mapped.json")
        broken_case = manifest.cases[0]
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-log-runtime")

    def test_mock_backend_rejects_tampered_dynamic_offset_log_runtime(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_log_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id
            == "upstream.benchmark.log.test_log.log1.size_0_bytes_data.topic_non_zero_topic.fixed_offset_false"
        )
        self.assertEqual(broken_case.observe["log_probe"]["offset_mode"], "dynamic_gas_mod_7")
        broken_case.steps[0]["bytecode_runtime"] = broken_case.steps[0]["bytecode_runtime"].replace("5a600706", "6000600060", 1)
        broken_case.steps[0]["bytecode_init"] = _build_init_code(broken_case.steps[0]["bytecode_runtime"])
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path"):
            backend.execute_case(broken_case, "negative-tampered-dynamic-log-runtime")

    def test_mock_backend_rejects_unsupported_keccak_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_keccak_mapped.json")
        broken_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.keccak.test_keccak.mem_alloc_ff.offset_31.mem_update_false"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-keccak-runtime")

    def test_mock_backend_rejects_unsupported_bitwise_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_bitwise_mapped.json")
        broken_case = next(
            case for case in manifest.cases if case.case_id == "upstream.benchmark.bitwise.test_shifts.shr"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-bitwise-runtime")

    def test_mock_backend_rejects_unsupported_comparison_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_comparison_mapped.json")
        broken_case = next(
            case for case in manifest.cases if case.case_id == "upstream.benchmark.comparison.test_comparison.eq"
        )
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-comparison-runtime")

    def test_mock_backend_rejects_unsupported_stack_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_stack_mapped.json")
        broken_case = next(case for case in manifest.cases if case.case_id == "upstream.benchmark.stack.test_push.push0")
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-stack-runtime")

    def test_selector_rejects_mock_only_account_query_shortcuts_on_jsonrpc_profile(self) -> None:
        self.test_selector_rejects_jsonrpc_profile_when_manifest_contains_mock_only_actions()

    def test_selector_rejects_codecopy_neighbor_runtime_shape_for_account_query_manifest(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        selected, _ = TestSelector(profile).select(manifest)
        selected_runtimes = {
            case.steps[0]["bytecode_runtime"]
            for case in selected
            if case.steps and case.steps[0]["action"] == "deploy_contract"
        }
        expected_codecopy_runtimes = {
            _build_codecopy_fixed_runtime(copy_size)
            for copy_size in (0, 6144, 12288, 18432, 24576)
        }
        self.assertEqual(
            selected_runtimes,
            {CODESIZE_RUNTIME, BALANCE_RUNTIME, SELFBALANCE_RUNTIME, *expected_codecopy_runtimes},
        )

    def test_account_query_present_balance_expected_tracks_existing_target_balance(self) -> None:
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        present_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.account_query.balance.cold.present_accounts.success"
        )
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        oracle = ResultOracle()

        _, first_observed, first_context = backend.execute_case(present_case, "reused-present-balance")
        first_expected = oracle.resolve_expected(present_case.expected, first_context, present_case.observe)
        self.assertEqual(first_context["$present_target_balance_before"], "0x0")
        self.assertEqual(first_context["$present_target_balance_after"], "0x2a")
        self.assertEqual(first_expected["storage"]["0x00"], first_observed["storage"]["0x00"])
        self.assertEqual(first_observed["storage"]["0x00"], "0x000000000000000000000000000000000000000000000000000000000000002a")

        _, second_observed, second_context = backend.execute_case(present_case, "reused-present-balance")
        second_expected = oracle.resolve_expected(present_case.expected, second_context, present_case.observe)
        self.assertEqual(second_context["$present_target_balance_before"], "0x000000000000000000000000000000000000000000000000000000000000002a")
        self.assertEqual(second_context["$present_target_balance_after"], "0x54")
        self.assertEqual(second_expected["storage"]["0x00"], second_observed["storage"]["0x00"])
        self.assertEqual(second_observed["storage"]["0x00"], "0x0000000000000000000000000000000000000000000000000000000000000054")

    def test_oracle_reports_wrong_present_balance_seed_for_account_query_case(self) -> None:
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        present_case = next(
            case
            for case in manifest.cases
            if case.case_id == "upstream.benchmark.account_query.balance.cold.present_accounts.success"
        )
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        tx_hashes, observed, context = backend.execute_case(present_case, "negative-present-balance-seed")
        self.assertTrue(tx_hashes)
        diffs = ResultOracle().compare(
            {"storage": {"0x00": "0x000000000000000000000000000000000000000000000000000000000000002b"}},
            observed,
            context,
        )
        self.assertEqual(
            diffs,
            [
                "storage.0x00: expected '0x000000000000000000000000000000000000000000000000000000000000002b', got '0x000000000000000000000000000000000000000000000000000000000000002a'"
            ],
        )

    def test_tx_context_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_tx_context_mapped.json"
            generated = generate_upstream_tx_context_manifest(
                repo_root=ROOT,
                template_path=ROOT / "suites/templates/upstream_tx_context_templates.json",
                output_path=generated_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_tx_context_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [
                    "upstream.benchmark.tx_context.gasprice.success",
                    "upstream.benchmark.tx_context.origin.success",
                ],
            )

    def test_mock_backend_runs_upstream_mapped_tx_context_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_tx_context_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 2)
            observed_by_case = {result["case_id"]: result for result in report["results"]}

            origin = observed_by_case["upstream.benchmark.tx_context.origin.success"]
            self.assertEqual(
                origin["observed"]["storage"]["0x00"],
                "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            self.assertEqual(origin["context"]["$admin_account"], "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            self.assertIs(origin["success"], True)

            gasprice = observed_by_case["upstream.benchmark.tx_context.gasprice.success"]
            self.assertEqual(
                gasprice["observed"]["storage"]["0x00"],
                "0x000000000000000000000000000000000000000000000000000000003b9aca00",
            )
            self.assertEqual(gasprice["context"]["$gas_price"], "0x3b9aca00")
            self.assertIs(gasprice["success"], True)

    def test_mock_backend_runs_upstream_mapped_system_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_system_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(len(report["results"]), 35)
            observed_by_case = {result["case_id"]: result for result in report["results"]}

            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_create.create.0_bytes_with_value"]["observed"]["system_witness"],
                {
                    "shape": "create_empty_child",
                    "success": True,
                    "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                    "created_address_nonzero": True,
                    "created_code_size": 0,
                    "created_balance": 1,
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_create.create.0_bytes_without_value"]["observed"]["system_witness"],
                {
                    "shape": "create_empty_child",
                    "success": True,
                    "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                    "created_address_nonzero": True,
                    "created_code_size": 0,
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_create.create2.0_bytes_without_value"]["observed"]["system_witness"],
                {
                    "shape": "create_empty_child",
                    "success": True,
                    "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                    "created_address_nonzero": True,
                    "created_code_size": 0,
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_create.create2.0_bytes_with_value"]["observed"]["system_witness"],
                {
                    "shape": "create_empty_child",
                    "success": True,
                    "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                    "created_address_nonzero": True,
                    "created_code_size": 0,
                    "created_balance": 1,
                },
            )
            zero_code_hash = "0x" + keccak256(b"\x00" * 6144).hex()
            non_zero_child_prefix = bytes.fromhex("611800805f5f395ff3")
            non_zero_child_code = non_zero_child_prefix + bytes(index % 256 for index in range(6144 - len(non_zero_child_prefix)))
            non_zero_code_hash = "0x" + keccak256(non_zero_child_code).hex()
            for case_id, code_hash in (
                ("upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_non_zero_data", non_zero_code_hash),
                ("upstream.benchmark.system.test_create.create.0_25x_max_code_size_with_zero_data", zero_code_hash),
                ("upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_non_zero_data", non_zero_code_hash),
                ("upstream.benchmark.system.test_create.create2.0_25x_max_code_size_with_zero_data", zero_code_hash),
            ):
                self.assertEqual(
                    observed_by_case[case_id]["observed"]["system_witness"],
                    {
                        "shape": "create_child_code",
                        "success": True,
                        "created_address": "0xdddddddddddddddddddddddddddddddddddddddd",
                        "created_address_nonzero": True,
                        "created_code_size": 6144,
                        "created_code_hash": code_hash,
                    },
                )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"]["observed"]["system_witness"],
                {
                    "shape": "return_revert_self_call",
                    "success": True,
                    "returndata_size": 0,
                    "returndata_digest": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.revert.1kib_of_non_zero_data"]["observed"]["system_witness"],
                {
                    "shape": "return_revert_self_call",
                    "success": False,
                    "returndata_size": 1024,
                    "returndata_digest": "0x146071216f9b08d3ffefb9581967e6c5e47e043ca3897b61f5df20c057826054",
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data"]["observed"]["system_witness"]["returndata_size"],
                1048576,
            )
            for result in report["results"]:
                self.assertEqual(result["observed"].get("receipt_status"), "0x1")
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

            wrong_digest_diffs = ResultOracle().compare(
                {
                    "system_witness": {
                        "returndata_digest": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    }
                },
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"]["observed"],
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"]["context"],
            )
            self.assertEqual(
                wrong_digest_diffs,
                [
                    "system_witness.returndata_digest: expected '0x0000000000000000000000000000000000000000000000000000000000000000', got '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'"
                ],
            )

    def test_mock_backend_runs_upstream_mapped_system_subset_cases(self) -> None:
        self.test_mock_backend_runs_upstream_mapped_system_cases()

    def test_cli_run_mock_upstream_tx_context_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_tx_context_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-tx-context-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 2)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"]["storage"]["0x00"] for result in report["results"]}
            self.assertEqual(
                observed_by_case,
                {
                    "upstream.benchmark.tx_context.origin.success": "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "upstream.benchmark.tx_context.gasprice.success": "0x000000000000000000000000000000000000000000000000000000003b9aca00",
                },
            )

    def test_cli_run_mock_upstream_system_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_system_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-system-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 35)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"] for result in report["results"]}
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"],
                {
                    "receipt_status": "0x1",
                    "system_witness": {
                        "shape": "return_revert_self_call",
                        "success": True,
                        "returndata_size": 0,
                        "returndata_digest": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    },
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.revert.empty"],
                {
                    "receipt_status": "0x1",
                    "system_witness": {
                        "shape": "return_revert_self_call",
                        "success": False,
                        "returndata_size": 0,
                        "returndata_digest": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    },
                },
            )

    def test_cli_run_mock_upstream_arithmetic_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_arithmetic_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-arithmetic-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 65)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"]["storage"]["0x00"] for result in report["results"]}
            self.assertEqual(
                {
                    "upstream.benchmark.arithmetic.test_arithmetic.add.base.arity_2": observed_by_case["upstream.benchmark.arithmetic.test_arithmetic.add.base.arity_2"],
                    "upstream.benchmark.arithmetic.test_arithmetic.signextend.base.arity_2": observed_by_case["upstream.benchmark.arithmetic.test_arithmetic.signextend.base.arity_2"],
                    "upstream.benchmark.arithmetic.test_mod.mod.mod_bits_255": observed_by_case["upstream.benchmark.arithmetic.test_mod.mod.mod_bits_255"],
                    "upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_3.base_3": observed_by_case["upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_3.base_3"],
                },
                {
                    "upstream.benchmark.arithmetic.test_arithmetic.add.base.arity_2": "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffdfffffc30",
                    "upstream.benchmark.arithmetic.test_arithmetic.signextend.base.arity_2": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdadada",
                    "upstream.benchmark.arithmetic.test_mod.mod.mod_bits_255": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "upstream.benchmark.arithmetic.test_exp_bench_arithmetic.exp_3.base_3": "0x000000000000000000000000000000000000000000000000000000000000001b",
                },
            )

    def test_cli_run_mock_upstream_tx_context_manifest_writes_passing_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            state_dir = tmp_path / "state"
            report_path = tmp_path / "report.json"
            args = [
                "run",
                "--profile",
                str(ROOT / "profiles/mock.toml"),
                "--manifest",
                str(ROOT / "suites/manifests/upstream_tx_context_mapped.json"),
                "--state-dir",
                str(state_dir),
                "--report",
                str(report_path),
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertEqual(report["manifest"], "upstream-tx-context-mapped")
            self.assertEqual(report["chain_profile"], "mock-devnet")
            self.assertEqual(len(report["results"]), 2)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"]["storage"]["0x00"] for result in report["results"]}
            self.assertEqual(
                observed_by_case,
                {
                    "upstream.benchmark.tx_context.origin.success": "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "upstream.benchmark.tx_context.gasprice.success": "0x000000000000000000000000000000000000000000000000000000003b9aca00",
                },
            )
