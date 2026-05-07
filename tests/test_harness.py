from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from adapter.bootstrap import StateBootstrapper
from adapter.cli import main
from adapter.env import load_dotenv
from adapter.executor import JsonRpcBackend, MockBackend
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
from adapter.account_query_generator import (
    generate_upstream_account_query_manifest,
    generate_upstream_account_query_templates,
    load_account_query_templates,
)
from adapter.call_context_generator import (
    generate_upstream_call_context_manifest,
    generate_upstream_call_context_templates,
    load_call_context_templates,
)
from adapter.arithmetic_generator import generate_upstream_arithmetic_templates
from adapter.bitwise_generator import generate_upstream_bitwise_templates
from adapter.comparison_generator import generate_upstream_comparison_templates
from adapter.control_flow_generator import generate_upstream_control_flow_templates
from adapter.inventory import summarize_inventory_dir, write_inventory_payload
from adapter.stack_generator import generate_upstream_stack_templates
from adapter.tx_context_generator import (
    generate_upstream_tx_context_manifest,
    generate_upstream_tx_context_templates,
    load_tx_context_templates,
)
from adapter.oracle import ResultOracle
from adapter.profile import describe_admin_key_source, load_chain_profile
from adapter.selector import TestSelector
from adapter.signer import private_key_to_address, sign_type_2_transaction


ROOT = Path(__file__).resolve().parents[1]


class HarnessTests(unittest.TestCase):
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

    def test_real_rpc_profile_defaults_to_jsonrpc_backend(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        self.assertEqual(profile.name, "juchain-testnet")
        self.assertEqual(profile.backend, "jsonrpc")
        self.assertEqual(describe_admin_key_source(profile), "env_private_key")

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
                "contains mock-only actions not runnable on jsonrpc backend: set_balance, set_storage"
            ],
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
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_memory_case(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_memory_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.memory.mstore.offset_0.uninitialized.mem_size_0.success",
                "upstream.benchmark.memory.mload.offset_0.initialized.mem_size_0.success",
                "upstream.benchmark.memory.mstore8.offset_31.initialized.mem_size_32.success",
                "upstream.benchmark.memory.msize.mem_size_0.success",
                "upstream.benchmark.memory.msize.mem_size_1.success",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
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
                "upstream.benchmark.call_context.calldataload.calldata_size_32.nonzero.success",
                "upstream.benchmark.call_context.calldataload.calldata_size_0.zero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_32.nonzero.success",
                "upstream.benchmark.call_context.calldatasize.calldata_size_0.zero.success",
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
            ["upstream.benchmark.tx_context.origin.success"],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

    def test_selector_allows_upstream_mapped_account_query_cases(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        selected, decisions = TestSelector(profile).select(manifest)
        self.assertEqual(
            [case.case_id for case in selected],
            [
                "upstream.benchmark.account_query.codesize.success",
                "upstream.benchmark.account_query.balance.cold.present_accounts.success",
                "upstream.benchmark.account_query.balance.cold.absent_accounts.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_0.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_1.success",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])

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

    def test_account_query_manifest_generator_matches_checked_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_account_query_mapped.json"
            generated = generate_upstream_account_query_manifest(
                repo_root=ROOT,
                template_path=ROOT / "suites/templates/upstream_account_query_templates.json",
                output_path=generated_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_account_query_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated["cases"][0]["family"], "state/account-query")

    def test_storage_templates_load(self) -> None:
        templates = load_storage_templates(ROOT / "suites/templates/upstream_storage_templates.json")
        self.assertEqual(len(templates), 17)
        self.assertEqual(templates[0].mode, "read_present")

    def test_memory_templates_load(self) -> None:
        templates = load_memory_templates(ROOT / "suites/templates/upstream_memory_templates.json")
        self.assertEqual(len(templates), 5)
        self.assertEqual(templates[0].mode, "mstore_offset0_uninitialized_mem0")

    def test_call_context_templates_load(self) -> None:
        templates = load_call_context_templates(ROOT / "suites/templates/upstream_call_context_templates.json")
        self.assertEqual(len(templates), 9)
        self.assertEqual(templates[0].mode, "address")

    def test_account_query_templates_load(self) -> None:
        templates = load_account_query_templates(ROOT / "suites/templates/upstream_account_query_templates.json")
        self.assertEqual(len(templates), 5)
        self.assertEqual(templates[0].mode, "codesize")

    def test_tx_context_templates_load(self) -> None:
        templates = load_tx_context_templates(ROOT / "suites/templates/upstream_tx_context_templates.json")
        self.assertEqual(len(templates), 1)
        self.assertEqual(templates[0].mode, "origin")

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
            self.assertEqual(len(admitted), 5)
            self.assertGreater(len(blocked), 0)

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
            self.assertEqual(len(admitted), 9)
            self.assertGreater(len(blocked), 0)

    def test_account_query_template_scanner_writes_expected_inventory_and_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_account_query_templates.json"
            inventory_path = Path(tmpdir) / "upstream_account_query_inventory.json"
            generated = generate_upstream_account_query_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            checked_in = json.loads(
                (ROOT / "suites/templates/upstream_account_query_templates.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            inventory = json.loads(inventory_path.read_text())
            checked_in_inventory = json.loads(
                (ROOT / "suites/templates/upstream_account_query_inventory.json").read_text()
            )
            self.assertEqual(inventory, checked_in_inventory)
            self.assertEqual(inventory["name"], "upstream-account-query-auto-inventory")
            self.assertEqual(inventory["family"], "account-query")
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 5)
            self.assertEqual(len(blocked), 35)
            self.assertEqual([entry["case_id"] for entry in admitted], [
                "upstream.benchmark.account_query.codesize.success",
                "upstream.benchmark.account_query.balance.cold.present_accounts.success",
                "upstream.benchmark.account_query.balance.cold.absent_accounts.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_0.success",
                "upstream.benchmark.account_query.selfbalance.contract_balance_1.success",
            ])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            blocked_reasons = {reason for entry in blocked for reason in entry["reasons"]}
            self.assertEqual(
                blocked_reasons,
                {
                    "requires byte-range code-copy observation not yet mapped",
                    "requires external-account code-copy fixtures and byte-range observation not yet mapped",
                },
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
            self.assertEqual(len(admitted), 1)
            self.assertEqual(len(blocked), 3)

    def test_arithmetic_template_scanner_writes_blocked_inventory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_arithmetic_templates.json"
            inventory_path = Path(tmpdir) / "upstream_arithmetic_inventory.json"
            generated = generate_upstream_arithmetic_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-arithmetic-mapping-templates")
            self.assertEqual(generated["cases"], [])
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-arithmetic-auto-inventory")
            self.assertEqual(inventory["family"], "arithmetic")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            for entry in inventory["entries"]:
                self.assertIn("not yet mapped", " ".join(entry["reasons"]))

    def test_bitwise_template_scanner_writes_blocked_inventory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_bitwise_templates.json"
            inventory_path = Path(tmpdir) / "upstream_bitwise_inventory.json"
            generated = generate_upstream_bitwise_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-bitwise-mapping-templates")
            self.assertEqual(generated["cases"], [])
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-bitwise-auto-inventory")
            self.assertEqual(inventory["family"], "bitwise")
            self.assertEqual(len(inventory["entries"]), 12)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            for entry in inventory["entries"]:
                self.assertIn("not yet mapped", " ".join(entry["reasons"]))

    def test_comparison_template_scanner_writes_blocked_inventory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_comparison_templates.json"
            inventory_path = Path(tmpdir) / "upstream_comparison_inventory.json"
            generated = generate_upstream_comparison_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-comparison-mapping-templates")
            self.assertEqual(generated["cases"], [])
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-comparison-auto-inventory")
            self.assertEqual(inventory["family"], "comparison")
            self.assertEqual(len(inventory["entries"]), 6)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            for entry in inventory["entries"]:
                self.assertIn("not yet mapped", " ".join(entry["reasons"]))

    def test_stack_template_scanner_writes_blocked_inventory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_stack_templates.json"
            inventory_path = Path(tmpdir) / "upstream_stack_inventory.json"
            generated = generate_upstream_stack_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-stack-mapping-templates")
            self.assertEqual(generated["cases"], [])
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-stack-auto-inventory")
            self.assertEqual(inventory["family"], "stack")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            self.assertIn(
                "upstream.benchmark.stack.test_push.push0",
                case_ids,
            )
            self.assertIn(
                "upstream.benchmark.stack.test_push.push32",
                case_ids,
            )
            self.assertIn(
                "upstream.benchmark.stack.test_dup.dup1",
                case_ids,
            )
            self.assertIn(
                "upstream.benchmark.stack.test_dup.dup16",
                case_ids,
            )
            self.assertIn(
                "upstream.benchmark.stack.test_swap.swap1",
                case_ids,
            )
            self.assertIn(
                "upstream.benchmark.stack.test_swap.swap16",
                case_ids,
            )
            for entry in inventory["entries"]:
                self.assertIn("not yet mapped", " ".join(entry["reasons"]))

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

    def test_control_flow_template_scanner_writes_blocked_inventory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            generated_path = Path(tmpdir) / "upstream_control_flow_templates.json"
            inventory_path = Path(tmpdir) / "upstream_control_flow_inventory.json"
            generated = generate_upstream_control_flow_templates(
                repo_root=ROOT,
                output_path=generated_path,
                inventory_path=inventory_path,
            )
            self.assertEqual(generated["name"], "upstream-control-flow-mapping-templates")
            self.assertEqual(generated["cases"], [])
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-control-flow-auto-inventory")
            self.assertEqual(inventory["family"], "control-flow")
            self.assertEqual(len(inventory["entries"]), 7)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])
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
            for entry in inventory["entries"]:
                self.assertIn("not yet mapped", " ".join(entry["reasons"]))

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
            self.assertEqual(generated["cases"], [])
            self.assertEqual(inventory["name"], "upstream-arithmetic-auto-inventory")
            self.assertEqual(inventory["family"], "arithmetic")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual(generated["cases"], [])
            self.assertEqual(inventory["name"], "upstream-bitwise-auto-inventory")
            self.assertEqual(inventory["family"], "bitwise")
            self.assertEqual(len(inventory["entries"]), 12)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual(generated["cases"], [])
            self.assertEqual(inventory["name"], "upstream-comparison-auto-inventory")
            self.assertEqual(inventory["family"], "comparison")
            self.assertEqual(len(inventory["entries"]), 6)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual(generated["cases"], [])
            self.assertEqual(inventory["name"], "upstream-stack-auto-inventory")
            self.assertEqual(inventory["family"], "stack")
            self.assertEqual(len(inventory["entries"]), 65)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual(generated["cases"], [])
            self.assertEqual(inventory["name"], "upstream-control-flow-auto-inventory")
            self.assertEqual(inventory["family"], "control-flow")
            self.assertEqual(len(inventory["entries"]), 7)
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

    def test_cli_generate_memory_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-memory-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            self.assertEqual(generated["name"], "upstream-memory-mapped")
            self.assertEqual(len(generated["cases"]), 5)

    def test_cli_generate_account_query_manifest_writes_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "generated.json"
            self.assertEqual(
                main(["generate-account-query-manifest", "--output", str(output_path)]),
                0,
            )
            generated = json.loads(output_path.read_text())
            checked_in = json.loads(
                (ROOT / "suites/manifests/upstream_account_query_mapped.json").read_text()
            )
            self.assertEqual(generated, checked_in)
            self.assertEqual(generated["name"], "upstream-account-query-mapped")
            self.assertEqual(len(generated["cases"]), 5)
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
            self.assertEqual(len(generated["cases"]), 5)
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
            self.assertEqual(len(generated["cases"]), 9)
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
            self.assertEqual(len(generated["cases"]), 1)
            self.assertEqual(generated["cases"][0]["expected"]["storage"]["0x00"], "$admin_account_word")

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
            self.assertEqual(len(generated["cases"]), 9)
            self.assertGreater(len(inventory["entries"]), len(generated["cases"]))

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
            self.assertEqual(generated["name"], "upstream-account-query-mapping-templates")
            self.assertEqual(len(generated["cases"]), 5)
            self.assertEqual(inventory["name"], "upstream-account-query-auto-inventory")
            self.assertEqual(inventory["family"], "account-query")
            self.assertEqual(len(inventory["entries"]), 40)

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
            self.assertEqual(len(generated["cases"]), 1)
            self.assertGreater(len(inventory["entries"]), len(generated["cases"]))

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
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual([entry for entry in inventory["entries"] if entry["admitted"]], [])

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
            self.assertEqual(inventory["name"], "upstream-account-query-auto-inventory")
            self.assertEqual(inventory["family"], "account-query")
            self.assertEqual(len(inventory["entries"]), 40)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 5)

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

    def _assert_checked_in_first_family_inventory_summary(self, summary: dict[str, object]) -> None:
        self.assertEqual(
            summary["totals"],
            {"families": 10, "cases": 332, "admitted": 37, "blocked": 295},
        )

        families = {item["family"]: item for item in summary["families"]}
        self.assertEqual(
            {
                family: {
                    "total": item["total"],
                    "admitted": item["admitted"],
                    "blocked": item["blocked"],
                }
                for family, item in families.items()
                if family in {"arithmetic", "bitwise", "comparison", "stack", "control-flow", "account-query"}
            },
            {
                "arithmetic": {"total": 65, "admitted": 0, "blocked": 65},
                "bitwise": {"total": 12, "admitted": 0, "blocked": 12},
                "comparison": {"total": 6, "admitted": 0, "blocked": 6},
                "stack": {"total": 65, "admitted": 0, "blocked": 65},
                "control-flow": {"total": 7, "admitted": 0, "blocked": 7},
                "account-query": {"total": 40, "admitted": 5, "blocked": 35},
            },
        )

    def test_inventory_summary_aggregates_checked_in_first_family_inventories(self) -> None:
        summary = summarize_inventory_dir(ROOT / "suites/templates")
        self._assert_checked_in_first_family_inventory_summary(summary)

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
            self.assertEqual(len(report["results"]), 5)
            expected_storage = {
                "upstream.benchmark.memory.mload.offset_0.initialized.mem_size_0.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.memory.mstore.offset_0.uninitialized.mem_size_0.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.memory.mstore8.offset_31.initialized.mem_size_32.success": {
                    "0x00": "0x2a00000000000000000000000000000000000000000000000000000000000000",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
                "upstream.benchmark.memory.msize.mem_size_0.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.memory.msize.mem_size_1.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000020",
                },
            }
            for result in report["results"]:
                self.assertIn(result["case_id"], expected_storage)
                for slot, value in expected_storage[result["case_id"]].items():
                    self.assertEqual(result["observed"]["storage"][slot], value)
                self.assertIs(result["success"], True)

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
            self.assertEqual(len(report["results"]), 9)
            expected_storage = {
                "upstream.benchmark.call_context.address.success": {
                    "0x00": "0x000000000000000000000000cccccccccccccccccccccccccccccccccccccccc",
                },
                "upstream.benchmark.call_context.caller.success": {
                    "0x00": "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
                "upstream.benchmark.call_context.calldataload.calldata_size_0.zero.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.call_context.calldataload.calldata_size_32.nonzero.success": {
                    "0x00": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
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
            self.assertEqual(len(report["results"]), 5)
            expected_storage = {
                "upstream.benchmark.account_query.codesize.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000005",
                },
                "upstream.benchmark.account_query.balance.cold.present_accounts.success": {
                    "0x00": "0x000000000000000000000000000000000000000000000000000000000000002a",
                },
                "upstream.benchmark.account_query.balance.cold.absent_accounts.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.account_query.selfbalance.contract_balance_0.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                },
                "upstream.benchmark.account_query.selfbalance.contract_balance_1.success": {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            }
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(set(observed_by_case), set(expected_storage))
            self.assertNotIn("upstream.benchmark.account_query.codecopy", "\n".join(observed_by_case))
            self.assertNotIn("upstream.benchmark.account_query.extcodecopy", "\n".join(observed_by_case))
            for case_id, expected_slots in expected_storage.items():
                result = observed_by_case[case_id]
                self.assertEqual(result["observed"]["storage"], expected_slots)
                self.assertEqual(result["expected"]["storage"], expected_slots)
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

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
            self.assertEqual(len(report["results"]), 5)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"]["storage"]["0x00"] for result in report["results"]}
            self.assertEqual(
                observed_by_case,
                {
                    "upstream.benchmark.account_query.codesize.success": "0x0000000000000000000000000000000000000000000000000000000000000005",
                    "upstream.benchmark.account_query.balance.cold.present_accounts.success": "0x000000000000000000000000000000000000000000000000000000000000002a",
                    "upstream.benchmark.account_query.balance.cold.absent_accounts.success": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.account_query.selfbalance.contract_balance_0.success": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "upstream.benchmark.account_query.selfbalance.contract_balance_1.success": "0x0000000000000000000000000000000000000000000000000000000000000001",
                },
            )

    def test_mock_backend_rejects_unsupported_account_query_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        broken_case = manifest.cases[0]
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-account-query-runtime")

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
            self.assertEqual(len(report["results"]), 1)
            result = report["results"][0]
            self.assertEqual(result["case_id"], "upstream.benchmark.tx_context.origin.success")
            self.assertEqual(
                result["observed"]["storage"]["0x00"],
                "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            self.assertEqual(result["context"]["$admin_account"], "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            self.assertIs(result["success"], True)


if __name__ == "__main__":
    unittest.main()
