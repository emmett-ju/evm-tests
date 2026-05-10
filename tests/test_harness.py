from __future__ import annotations

from collections import Counter
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from adapter.bootstrap import StateBootstrapper
from adapter.cli import main
from adapter.env import load_dotenv
from adapter.executor import (
    BALANCE_RUNTIME,
    CODESIZE_RUNTIME,
    SELFBALANCE_RUNTIME,
    JsonRpcBackend,
    MockBackend,
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
from adapter.log_generator import generate_upstream_log_manifest, generate_upstream_log_templates
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
from adapter.tx_context_generator import (
    generate_upstream_tx_context_manifest,
    generate_upstream_tx_context_templates,
    load_tx_context_templates,
)
from adapter.oracle import ResultOracle
from adapter.profile import describe_admin_key_source, load_chain_profile
from adapter.selector import TestSelector
from adapter.signer import keccak256, private_key_to_address, sign_type_2_transaction


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
        self.assertEqual(len(selected), 95)
        selected_ids = [case.case_id for case in selected]
        self.assertIn("upstream.benchmark.memory.mstore.offset_0.uninitialized.mem_size_0.success", selected_ids)
        self.assertIn("upstream.benchmark.memory.msize.mem_size_1.success", selected_ids)
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
        allowed_runtimes = {CODESIZE_RUNTIME, BALANCE_RUNTIME, SELFBALANCE_RUNTIME}
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
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/system"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])
        self.assertTrue(
            all(
                case.observe == {"storage_address": "$last_contract"}
                and case.expected["receipt_status"] == "0x1"
                and set(case.expected["storage"]) == {"0x00", "0x01", "0x02"}
                for case in selected
            )
        )
        self.assertFalse(
            any(
                "test_create" in case.case_id
                or "test_selfdestruct" in case.case_id
                or "test_contract_calling_many_addresses" in case.case_id
                or "test_creates_collisions" in case.case_id
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
                "upstream.benchmark.block_context.test_block_context_ops.prevrandao",
                "upstream.benchmark.block_context.test_block_context_ops.timestamp",
            ],
        )
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/block-context"})
        self.assertEqual([decision for decision in decisions if not decision.selected], [])
        self.assertEqual(
            {case.observe["block_context_probe"]["mode"] for case in selected},
            {"basefee", "chainid", "coinbase", "gaslimit", "number", "prevrandao", "timestamp"},
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
                "upstream.benchmark.block_context.test_block_context_ops.prevrandao",
                "upstream.benchmark.block_context.test_block_context_ops.timestamp",
            ],
        )
        blocked = {decision.case.case_id: decision.reasons for decision in decisions if not decision.selected}
        self.assertEqual(
            blocked,
            {
                "upstream.benchmark.block_context.test_block_context_ops.basefee": [
                    "block-context mode basefee requires feature_flags.base_fee=true in chain profile"
                ]
            },
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
        self.assertEqual(len(admitted), 5, "account-query admitted count drifted")
        self.assertEqual(len(blocked), 35, "account-query blocked count drifted")

        admitted_case_ids = [entry["case_id"] for entry in admitted]
        self.assertEqual(
            admitted_case_ids,
            [
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
                    "requires byte-range code-copy observation not yet mapped": 30,
                    "requires external-account code-copy fixtures and byte-range observation not yet mapped": 5,
                }
            ),
            "account-query blocked-reason ledger drifted",
        )
        self.assertEqual(
            Counter(entry["source"] for entry in blocked),
            Counter({"codecopy": 10, "codecopy_benchmark": 20, "extcodecopy_warm": 5}),
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
            self.assertEqual(len(manifest_payload["cases"]), 5)
            self.assertEqual({case["family"] for case in manifest_payload["cases"]}, {"state/account-query"})
            self.assertFalse(
                any("codecopy" in case_id or "extcodecopy" in case_id for case_id in manifest_case_ids),
                "blocked account-query neighbors leaked into manifest",
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
            self.assertEqual(len(generated["cases"]), 7)
            self.assertEqual({case["family"] for case in generated["cases"]}, {"state/block-context"})
            self.assertEqual(
                [case["case_id"] for case in generated["cases"]],
                [case["case_id"] for case in templates["cases"]],
            )
            self.assertEqual(
                {case["expected"]["storage"]["0x00"] for case in generated["cases"]},
                {
                    "$block_basefee_word",
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
            self.assertEqual(len(generated["cases"]), 11)
            case_ids = {case["case_id"] for case in generated["cases"]}
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
        self.assertEqual(len(templates), 95)
        self.assertEqual(templates[0].mode, "memory_access")

    def test_call_context_templates_load(self) -> None:
        templates = load_call_context_templates(ROOT / "suites/templates/upstream_call_context_templates.json")
        self.assertEqual(len(templates), 20)
        self.assertEqual(templates[0].mode, "address")

    def test_account_query_templates_load(self) -> None:
        templates = load_account_query_templates(ROOT / "suites/templates/upstream_account_query_templates.json")
        self.assertEqual(len(templates), 5)
        self.assertEqual(templates[0].mode, "codesize")

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
            self.assertEqual(len(admitted), 95)
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
            self.assertEqual(len(generated["cases"]), 11)
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-bitwise-auto-inventory")
            self.assertEqual(inventory["family"], "bitwise")
            self.assertEqual(len(inventory["entries"]), 12)
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 11)
            self.assertEqual(len(blocked), 1)
            self.assertEqual(
                blocked[0]["case_id"],
                "upstream.benchmark.bitwise.test_clz_diff.clz",
            )
            self.assertEqual(
                blocked[0]["reasons"],
                ["requires gas-sensitive benchmark shape not yet mapped"],
            )
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
            self.assertEqual(len(generated["cases"]), 7)
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
                ],
            )
            inventory = json.loads(inventory_path.read_text())
            self.assertEqual(inventory["name"], "upstream-block-context-auto-inventory")
            self.assertEqual(inventory["family"], "block-context")
            self.assertEqual(len(inventory["entries"]), 13)
            admitted = [entry for entry in inventory["entries"] if entry["admitted"]]
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(admitted), 7)
            self.assertEqual(len(blocked), 6)
            self.assertEqual([entry["case_id"] for entry in admitted], [case["case_id"] for case in generated["cases"]])
            case_ids = [entry["case_id"] for entry in inventory["entries"]]
            self.assertEqual(len(case_ids), len(set(case_ids)))
            blocked_reason_counts = Counter(reason for entry in blocked for reason in entry["reasons"])
            self.assertEqual(
                blocked_reason_counts,
                Counter(
                    {
                        "requires block environment control": 5,
                        "requires blob-capable profile support not yet enabled": 1,
                    }
                ),
            )
            blocked_case_ids = {entry["case_id"] for entry in blocked}
            self.assertIn("upstream.benchmark.block_context.test_blockhash.random", blocked_case_ids)
            self.assertIn("upstream.benchmark.block_context.test_block_context_ops.blobbasefee", blocked_case_ids)

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
        self.assertEqual(len(admitted), 110, "log admitted count drifted")
        self.assertEqual(len(blocked), 30, "log blocked count drifted")

        admitted_case_ids = [entry["case_id"] for entry in admitted]
        self.assertEqual(
            {entry["mode"] for entry in admitted},
            {"test_log_fixed_offset", "test_log_benchmark"},
        )
        self.assertEqual(
            Counter(reason for entry in blocked for reason in entry["reasons"]),
            Counter({"requires gas-derived dynamic log offset observation not yet mapped": 30}),
        )
        self.assertEqual(
            Counter(entry["source"] for entry in blocked),
            Counter({"test_log": 30}),
        )
        self.assertTrue(all(entry["mode"] is None for entry in blocked))

        template_case_ids = [case["case_id"] for case in templates_payload["cases"]]
        self.assertEqual(template_case_ids, admitted_case_ids)
        self.assertEqual(len(templates_payload["cases"]), 110)

        if manifest_payload is not None:
            checked_in_manifest_path = ROOT / "suites/manifests/upstream_log_mapped.json"
            checked_in_manifest = json.loads(checked_in_manifest_path.read_text())
            self.assertEqual(manifest_payload, checked_in_manifest, "log manifest JSON drift")
            manifest_case_ids = [case["case_id"] for case in manifest_payload["cases"]]
            self.assertEqual(manifest_case_ids, admitted_case_ids)
            self.assertEqual(len(manifest_payload["cases"]), 110)
            self.assertEqual({case["family"] for case in manifest_payload["cases"]}, {"state/log"})
            observed_by_case = {case["case_id"]: case for case in manifest_payload["cases"]}
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
        self.assertEqual(len(selected_case_ids), 110)
        self.assertEqual({case.kind for case in selected}, {"upstream_mapped"})
        self.assertEqual({case.family for case in selected}, {"state/log"})
        self.assertEqual(Counter(case.case_id.split(".")[4] for case in selected), Counter({"log0": 22, "log1": 22, "log2": 22, "log3": 22, "log4": 22}))
        self.assertEqual(
            Counter(
                "digest" if "data_digest" in case.expected["receipt_logs"][0] else "exact"
                for case in selected
            ),
            Counter({"exact": 70, "digest": 40}),
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

        self.assertEqual(len(observed_by_case), 110)
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
            self.assertEqual(len(report["results"]), 110)
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
            self.assertEqual(large_digest_case["data"][:66], "0x" + ("ff" * 32))
            self.assertEqual(
                "0x" + keccak256(bytes.fromhex(large_digest_case["data"][2:])).hex(),
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
        self.assertEqual(len(admitted), 10, "system admitted count drifted")
        self.assertEqual(len(blocked), 36, "system blocked count drifted")

        admitted_case_ids = [entry["case_id"] for entry in admitted]
        self.assertEqual(
            admitted_case_ids,
            [
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
            ],
        )
        self.assertEqual({entry["mode"] for entry in admitted}, {"return_revert_self_call"})
        self.assertEqual(
            Counter(reason for entry in blocked for reason in entry["reasons"]),
            Counter(
                {
                    "requires multi-address external-call orchestration not yet mapped": 8,
                    "requires create/create2 deployed-address witness not yet mapped": 20,
                    "requires gas-capped create collision orchestration not yet mapped": 2,
                    "requires selfdestruct lifecycle witness not yet mapped": 6,
                }
            ),
        )
        self.assertEqual(
            Counter(entry["source"] for entry in blocked),
            Counter(
                {
                    "test_contract_calling_many_addresses": 8,
                    "test_create": 20,
                    "test_creates_collisions": 2,
                    "test_selfdestruct_created": 2,
                    "test_selfdestruct_existing": 2,
                    "test_selfdestruct_initcode": 2,
                }
            ),
        )
        self.assertTrue(all(entry["mode"] is None for entry in blocked))

        template_case_ids = [case["case_id"] for case in templates_payload["cases"]]
        self.assertEqual(template_case_ids, admitted_case_ids)
        self.assertEqual(len(templates_payload["cases"]), 10)

        if manifest_payload is not None:
            checked_in_manifest_path = ROOT / "suites/manifests/upstream_system_mapped.json"
            checked_in_manifest = json.loads(checked_in_manifest_path.read_text())
            self.assertEqual(manifest_payload, checked_in_manifest, "system manifest JSON drift")
            manifest_case_ids = [case["case_id"] for case in manifest_payload["cases"]]
            self.assertEqual(manifest_case_ids, admitted_case_ids)
            self.assertEqual(len(manifest_payload["cases"]), 10)
            self.assertEqual({case["family"] for case in manifest_payload["cases"]}, {"state/system"})
            observed_by_case = {case["case_id"]: case for case in manifest_payload["cases"]}
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_return_revert.return.empty"
                ]["expected"],
                {
                    "receipt_status": "0x1",
                    "storage": {
                        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                        "0x01": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "0x02": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    },
                },
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_return_revert.revert.1kib_of_non_zero_data"
                ]["expected"]["storage"],
                {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000400",
                    "0x02": "0x146071216f9b08d3ffefb9581967e6c5e47e043ca3897b61f5df20c057826054",
                },
            )
            self.assertEqual(
                observed_by_case[
                    "upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data"
                ]["expected"]["storage"]["0x01"],
                "0x0000000000000000000000000000000000000000000000000000000000100000",
            )
            self.assertFalse(
                any(
                    "test_create" in case_id
                    or "test_selfdestruct" in case_id
                    or "test_contract_calling_many_addresses" in case_id
                    or "test_creates_collisions" in case_id
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
            self.assertEqual(len(generated["cases"]), 11)
            self.assertEqual(inventory["name"], "upstream-bitwise-auto-inventory")
            self.assertEqual(inventory["family"], "bitwise")
            self.assertEqual(len(inventory["entries"]), 12)
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 11)
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(blocked), 1)
            self.assertEqual(blocked[0]["upstream_ref"], "tests/benchmark/compute/instruction/test_bitwise.py::test_clz_diff")
            self.assertEqual(blocked[0]["case_id"], "upstream.benchmark.bitwise.test_clz_diff.clz")
            self.assertEqual(blocked[0]["reasons"], ["requires gas-sensitive benchmark shape not yet mapped"])
            self.assertEqual(blocked[0]["source"], "test_clz_diff")

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
            self.assertEqual(len(generated["cases"]), 7)
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
            self.assertEqual(len(generated["cases"]), 95)

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
            self.assertEqual(len(generated["cases"]), 95)
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
            self.assertEqual(len(generated["cases"]), 7)
            self.assertGreater(len(inventory["entries"]), len(generated["cases"]))
            blocked = [entry for entry in inventory["entries"] if not entry["admitted"]]
            self.assertEqual(len(blocked), 6)
            self.assertEqual(
                Counter(reason for entry in blocked for reason in entry["reasons"]),
                Counter(
                    {
                        "requires block environment control": 5,
                        "requires blob-capable profile support not yet enabled": 1,
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
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 11)

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
            self.assertEqual(len([entry for entry in inventory["entries"] if entry["admitted"]]), 7)

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
            self.assertEqual(len(generated["cases"]), 10)
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
            self.assertEqual(len(generated["cases"]), 11)
            case_ids = {case["case_id"] for case in generated["cases"]}
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
                    "admitted": 11,
                    "blocked": 1,
                    "blocked_reasons": {"requires gas-sensitive benchmark shape not yet mapped": 1},
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
            {"families": 6, "cases": 190, "admitted": 189, "blocked": 1},
        )

    def _assert_checked_in_first_family_inventory_summary(self, summary: dict[str, object]) -> None:
        self.assertEqual(
            summary["totals"],
            {"families": 14, "cases": 613, "admitted": 455, "blocked": 158},
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
                "bitwise": {"total": 12, "admitted": 11, "blocked": 1},
                "comparison": {"total": 6, "admitted": 6, "blocked": 0},
                "stack": {"total": 65, "admitted": 65, "blocked": 0},
                "control-flow": {"total": 7, "admitted": 7, "blocked": 0},
                "account-query": {"total": 40, "admitted": 5, "blocked": 35},
                "block-context": {"total": 13, "admitted": 7, "blocked": 6},
                "call-context": {"total": 20, "admitted": 20, "blocked": 0},
                "log": {"total": 140, "admitted": 110, "blocked": 30},
                "keccak": {"total": 35, "admitted": 35, "blocked": 0},
                "system": {"total": 46, "admitted": 10, "blocked": 36},
                "tx-context": {"total": 4, "admitted": 2, "blocked": 2},
                "memory": {"total": 143, "admitted": 95, "blocked": 48},
            },
        )
        self.assertEqual(
            families["account-query"]["blocked_reasons"],
            {
                "requires byte-range code-copy observation not yet mapped": 30,
                "requires external-account code-copy fixtures and byte-range observation not yet mapped": 5,
            },
        )
        self.assertEqual(
            families["log"]["blocked_reasons"],
            {"requires gas-derived dynamic log offset observation not yet mapped": 30},
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
                {"families": 13, "cases": 573, "admitted": 450, "blocked": 123},
            )
            self.assertNotEqual(
                summary["totals"],
                {"families": 14, "cases": 613, "admitted": 455, "blocked": 158},
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
                {"families": 14, "cases": 612, "admitted": 454, "blocked": 158},
            )
            self.assertNotEqual(
                helper_summary["totals"],
                {"families": 14, "cases": 613, "admitted": 455, "blocked": 158},
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
                {"families": 14, "cases": 612, "admitted": 454, "blocked": 158},
            )
            account_query_row = next(item for item in cli_summary["families"] if item["family"] == "account-query")
            self.assertEqual(
                {
                    "total": account_query_row["total"],
                    "admitted": account_query_row["admitted"],
                    "blocked": account_query_row["blocked"],
                },
                {"total": 39, "admitted": 4, "blocked": 35},
            )

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
            self.assertEqual(len(report["results"]), 95)
            
            # Spot-check a few representative cases instead of all 95
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
            }
            
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            for case_id, expected_slots in expected_storage.items():
                self.assertIn(case_id, observed_by_case)
                for slot, value in expected_slots.items():
                    self.assertEqual(observed_by_case[case_id]["observed"]["storage"][slot], value)
            
            for result in report["results"]:
                self.assertEqual(result["diffs"], [])
                self.assertIs(result["success"], True)

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
            self.assertEqual(len(report["results"]), 7)

            observed_by_case = {result["case_id"]: result for result in report["results"]}
            expected_storage = {
                "upstream.benchmark.block_context.test_block_context_ops.basefee": {
                    "0x00": basefee_word,
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
            self.assertEqual(len(report["results"]), 11)

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
            self.assertEqual(len(report["results"]), 7)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result for result in report["results"]}
            self.assertEqual(
                {case_id: result["observed"]["storage"]["0x00"] for case_id, result in observed_by_case.items()},
                {
                    "upstream.benchmark.block_context.test_block_context_ops.basefee": basefee_word,
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
            with self.assertRaisesRegex(
                ValueError,
                "missing mock block-context witness config: block_context.timestamp is required",
            ):
                main(args)
            self.assertFalse(report_path.exists())

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
            self.assertEqual(len(report["results"]), 11)
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
        broken_case = manifest.cases[0]
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

    def test_mock_backend_rejects_unsupported_log_runtime_code_path(self) -> None:
        backend = MockBackend(admin_account="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_log_mapped.json")
        broken_case = manifest.cases[0]
        broken_case.steps[0]["bytecode_runtime"] = "0xdeadbeef"
        broken_case.steps[0]["bytecode_init"] = "0x60deadbeef"
        with self.assertRaisesRegex(ValueError, "unsupported mock contract code path: 0xdeadbeef"):
            backend.execute_case(broken_case, "negative-unsupported-log-runtime")

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
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        broken_case = manifest.cases[0]
        broken_case.steps.insert(0, {"action": "set_balance", "value": "0x1"})
        decision = TestSelector(profile).decide(broken_case)
        self.assertFalse(decision.selected)
        self.assertEqual(
            decision.reasons,
            ["contains mock-only actions not runnable on jsonrpc backend: set_balance"],
        )

    def test_selector_rejects_codecopy_neighbor_runtime_shape_for_account_query_manifest(self) -> None:
        profile = load_chain_profile(ROOT / "profiles/juchain.toml")
        manifest = load_manifest(ROOT / "suites/manifests/upstream_account_query_mapped.json")
        selected, _ = TestSelector(profile).select(manifest)
        selected_runtimes = {
            case.steps[0]["bytecode_runtime"]
            for case in selected
            if case.steps and case.steps[0]["action"] == "deploy_contract"
        }
        self.assertEqual(selected_runtimes, {CODESIZE_RUNTIME, BALANCE_RUNTIME, SELFBALANCE_RUNTIME})
        self.assertNotIn("0x39", selected_runtimes)

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
            self.assertEqual(len(report["results"]), 10)
            observed_by_case = {result["case_id"]: result for result in report["results"]}

            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"]["observed"]["storage"],
                {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x02": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.revert.1kib_of_non_zero_data"]["observed"]["storage"],
                {
                    "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x01": "0x0000000000000000000000000000000000000000000000000000000000000400",
                    "0x02": "0x146071216f9b08d3ffefb9581967e6c5e47e043ca3897b61f5df20c057826054",
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.return.1mib_of_zero_data"]["observed"]["storage"]["0x01"],
                "0x0000000000000000000000000000000000000000000000000000000000100000",
            )
            for result in report["results"]:
                self.assertEqual(result["observed"].get("receipt_status"), "0x1")
                self.assertEqual(result["diffs"], [])
                self.assertTrue(result["tx_hashes"])
                self.assertIs(result["success"], True)

            wrong_digest_diffs = ResultOracle().compare(
                {
                    "storage": {
                        "0x02": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    }
                },
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"]["observed"],
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"]["context"],
            )
            self.assertEqual(
                wrong_digest_diffs,
                [
                    "storage.0x02: expected '0x0000000000000000000000000000000000000000000000000000000000000000', got '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'"
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
            self.assertEqual(len(report["results"]), 10)
            self.assertTrue(all(result["success"] for result in report["results"]))
            self.assertTrue(all(result["diffs"] == [] for result in report["results"]))
            observed_by_case = {result["case_id"]: result["observed"] for result in report["results"]}
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.return.empty"],
                {
                    "receipt_status": "0x1",
                    "storage": {
                        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000001",
                        "0x01": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "0x02": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    },
                },
            )
            self.assertEqual(
                observed_by_case["upstream.benchmark.system.test_return_revert.revert.empty"],
                {
                    "receipt_status": "0x1",
                    "storage": {
                        "0x00": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "0x01": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "0x02": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
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
