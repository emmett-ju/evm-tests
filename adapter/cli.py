from __future__ import annotations

import argparse
import json
from pathlib import Path

from adapter.bootstrap import StateBootstrapper
from adapter.account_query_generator import (
    generate_upstream_account_query_manifest,
    generate_upstream_account_query_templates,
)
from adapter.call_context_generator import (
    generate_upstream_call_context_manifest,
    generate_upstream_call_context_templates,
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
)
from adapter.log_generator import generate_upstream_log_manifest, generate_upstream_log_templates
from adapter.keccak_generator import (
    generate_upstream_keccak_manifest,
    generate_upstream_keccak_templates,
)
from adapter.system_generator import (
    generate_upstream_system_manifest,
    generate_upstream_system_templates,
)
from adapter.env import load_dotenv
from adapter.stack_generator import (
    generate_upstream_stack_manifest,
    generate_upstream_stack_templates,
)
from adapter.executor import JsonRpcBackend, MockBackend, RpcExecutor, result_from_execution
from adapter.generator import generate_upstream_storage_manifest, generate_upstream_storage_templates
from adapter.inventory import summarize_inventory_dir, write_json
from adapter.manifest import load_manifest
from adapter.memory_generator import generate_upstream_memory_manifest, generate_upstream_memory_templates
from adapter.models import Report
from adapter.oracle import ResultOracle
from adapter.profile import load_chain_profile
from adapter.report import write_report
from adapter.selector import TestSelector
from adapter.tx_context_generator import (
    generate_upstream_tx_context_manifest,
    generate_upstream_tx_context_templates,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evm-rpc-tests")
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser("bootstrap")
    bootstrap.add_argument("--profile", required=True)
    bootstrap.add_argument("--state-dir", required=True)

    list_cmd = subparsers.add_parser("list")
    list_cmd.add_argument("--manifest", required=True)
    list_cmd.add_argument("--profile")

    run = subparsers.add_parser("run")
    run.add_argument("--profile", required=True)
    run.add_argument("--manifest", required=True)
    run.add_argument("--state-dir", required=True)
    run.add_argument("--report", default="reports/latest.json")

    generate = subparsers.add_parser("generate-storage-manifest")
    generate.add_argument("--template", default="suites/templates/upstream_storage_templates.json")
    generate.add_argument("--output", required=True)

    scan = subparsers.add_parser("scan-upstream-storage")
    scan.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_storage.py",
    )
    scan.add_argument("--template-output")
    scan.add_argument("--inventory-output", required=True)

    scan_arithmetic = subparsers.add_parser("scan-upstream-arithmetic")
    scan_arithmetic.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_arithmetic.py",
    )
    scan_arithmetic.add_argument("--template-output")
    scan_arithmetic.add_argument("--inventory-output", required=True)

    scan_bitwise = subparsers.add_parser("scan-upstream-bitwise")
    scan_bitwise.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_bitwise.py",
    )
    scan_bitwise.add_argument("--template-output")
    scan_bitwise.add_argument("--inventory-output", required=True)

    scan_comparison = subparsers.add_parser("scan-upstream-comparison")
    scan_comparison.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_comparison.py",
    )
    scan_comparison.add_argument("--template-output")
    scan_comparison.add_argument("--inventory-output", required=True)

    scan_stack = subparsers.add_parser("scan-upstream-stack")
    scan_stack.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_stack.py",
    )
    scan_stack.add_argument("--template-output")
    scan_stack.add_argument("--inventory-output", required=True)

    scan_control_flow = subparsers.add_parser("scan-upstream-control-flow")
    scan_control_flow.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_control_flow.py",
    )
    scan_control_flow.add_argument("--template-output")
    scan_control_flow.add_argument("--inventory-output", required=True)

    scan_block_context = subparsers.add_parser("scan-upstream-block-context")
    scan_block_context.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_block_context.py",
    )
    scan_block_context.add_argument("--template-output")
    scan_block_context.add_argument("--inventory-output", required=True)

    generate_block_context = subparsers.add_parser("generate-block-context-manifest")
    generate_block_context.add_argument("--template", default="suites/templates/upstream_block_context_templates.json")
    generate_block_context.add_argument("--output", required=True)

    scan_log = subparsers.add_parser("scan-upstream-log")
    scan_log.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_log.py",
    )
    scan_log.add_argument("--template-output")
    scan_log.add_argument("--inventory-output", required=True)

    generate_log = subparsers.add_parser("generate-log-manifest")
    generate_log.add_argument("--template", default="suites/templates/upstream_log_templates.json")
    generate_log.add_argument("--output", required=True)

    scan_keccak = subparsers.add_parser("scan-upstream-keccak")
    scan_keccak.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_keccak.py",
    )
    scan_keccak.add_argument("--template-output")
    scan_keccak.add_argument("--inventory-output", required=True)

    generate_keccak = subparsers.add_parser("generate-keccak-manifest")
    generate_keccak.add_argument("--template", default="suites/templates/upstream_keccak_templates.json")
    generate_keccak.add_argument("--output", required=True)

    scan_system = subparsers.add_parser("scan-upstream-system")
    scan_system.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_system.py",
    )
    scan_system.add_argument("--template-output")
    scan_system.add_argument("--inventory-output", required=True)

    generate_system = subparsers.add_parser("generate-system-manifest")
    generate_system.add_argument("--template", default="suites/templates/upstream_system_templates.json")
    generate_system.add_argument("--output", required=True)

    scan_account_query = subparsers.add_parser("scan-upstream-account-query")
    scan_account_query.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_account_query.py",
    )
    scan_account_query.add_argument("--template-output")
    scan_account_query.add_argument("--inventory-output", required=True)

    generate_account_query = subparsers.add_parser("generate-account-query-manifest")
    generate_account_query.add_argument("--template", default="suites/templates/upstream_account_query_templates.json")
    generate_account_query.add_argument("--output", required=True)

    generate_memory = subparsers.add_parser("generate-memory-manifest")
    generate_memory.add_argument("--template", default="suites/templates/upstream_memory_templates.json")
    generate_memory.add_argument("--output", required=True)

    scan_memory = subparsers.add_parser("scan-upstream-memory")
    scan_memory.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_memory.py",
    )
    scan_memory.add_argument("--template-output")
    scan_memory.add_argument("--inventory-output", required=True)

    generate_call_context = subparsers.add_parser("generate-call-context-manifest")
    generate_call_context.add_argument("--template", default="suites/templates/upstream_call_context_templates.json")
    generate_call_context.add_argument("--output", required=True)

    scan_call_context = subparsers.add_parser("scan-upstream-call-context")
    scan_call_context.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_call_context.py",
    )
    scan_call_context.add_argument("--template-output")
    scan_call_context.add_argument("--inventory-output", required=True)

    generate_tx_context = subparsers.add_parser("generate-tx-context-manifest")
    generate_tx_context.add_argument("--template", default="suites/templates/upstream_tx_context_templates.json")
    generate_tx_context.add_argument("--output", required=True)

    scan_tx_context = subparsers.add_parser("scan-upstream-tx-context")
    scan_tx_context.add_argument(
        "--source",
        default="third_party/execution-specs/tests/benchmark/compute/instruction/test_tx_context.py",
    )
    scan_tx_context.add_argument("--template-output")
    scan_tx_context.add_argument("--inventory-output", required=True)

    generate_arithmetic = subparsers.add_parser("generate-arithmetic-manifest")
    generate_arithmetic.add_argument("--template", default="suites/templates/upstream_arithmetic_templates.json")
    generate_arithmetic.add_argument("--output", required=True)

    generate_bitwise = subparsers.add_parser("generate-bitwise-manifest")
    generate_bitwise.add_argument("--template", default="suites/templates/upstream_bitwise_templates.json")
    generate_bitwise.add_argument("--output", required=True)

    generate_comparison = subparsers.add_parser("generate-comparison-manifest")
    generate_comparison.add_argument("--template", default="suites/templates/upstream_comparison_templates.json")
    generate_comparison.add_argument("--output", required=True)

    generate_stack = subparsers.add_parser("generate-stack-manifest")
    generate_stack.add_argument("--template", default="suites/templates/upstream_stack_templates.json")
    generate_stack.add_argument("--output", required=True)

    generate_control_flow = subparsers.add_parser("generate-control-flow-manifest")
    generate_control_flow.add_argument("--template", default="suites/templates/upstream_control_flow_templates.json")
    generate_control_flow.add_argument("--output", required=True)

    summarize_inventory = subparsers.add_parser("summarize-upstream-inventory")
    summarize_inventory.add_argument("--inventory-dir", default="suites/templates")
    summarize_inventory.add_argument("--output", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "bootstrap":
        profile = load_chain_profile(args.profile)
        bootstrapper = StateBootstrapper(profile, args.state_dir)
        print(json.dumps(bootstrapper.bootstrap_global(), indent=2, sort_keys=True))
        return 0

    if args.command == "list":
        manifest = load_manifest(args.manifest)
        if args.profile:
            profile = load_chain_profile(args.profile)
            selector = TestSelector(profile)
            _, decisions = selector.select(manifest)
            payload = [
                {
                    "case_id": decision.case.case_id,
                    "family": decision.case.family,
                    "selected": decision.selected,
                    "reasons": decision.reasons,
                }
                for decision in decisions
            ]
        else:
            payload = [
                {
                    "case_id": case.case_id,
                    "family": case.family,
                    "selected": not case.filters.blocked_reasons(),
                    "reasons": case.filters.blocked_reasons(),
                }
                for case in manifest.cases
            ]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command == "run":
        profile = load_chain_profile(args.profile)
        manifest = load_manifest(args.manifest)
        selector = TestSelector(profile)
        selected_cases, decisions = selector.select(manifest)
        bootstrapper = StateBootstrapper(profile, args.state_dir)
        bootstrapper.bootstrap_global()
        backend = (
            MockBackend(
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
            if profile.backend == "mock"
            else JsonRpcBackend(profile)
        )
        executor = RpcExecutor(backend)
        oracle = ResultOracle()
        results = []
        for case in selected_cases:
            namespace = bootstrapper.prepare_case_namespace(case).namespace
            tx_hashes, observed, context = executor.run_case(case, namespace)
            resolved_expected = oracle.resolve_expected(case.expected, context)
            diffs = oracle.compare(case.expected, observed, context)
            results.append(
                result_from_execution(
                    case,
                    namespace,
                    tx_hashes,
                    context,
                    observed,
                    diffs,
                    expected=resolved_expected,
                )
            )
        report = Report(
            manifest=manifest.name,
            execution_specs_ref=manifest.execution_specs_ref,
            suite_version=manifest.suite_version,
            chain_profile=profile.name,
            chain_profile_version=manifest.chain_profile_version,
            results=results,
        )
        write_report(report, args.report)
        print(
            json.dumps(
                {
                    "selected_cases": [case.case_id for case in selected_cases],
                    "skipped_cases": {
                        decision.case.case_id: decision.reasons
                        for decision in decisions
                        if not decision.selected
                    },
                    "report": str(Path(args.report)),
                    "passed": sum(1 for result in results if result.success),
                    "failed": sum(1 for result in results if not result.success),
                    "selection_summary": {
                        "selected": len(selected_cases),
                        "skipped": len([decision for decision in decisions if not decision.selected]),
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "generate-storage-manifest":
        manifest = generate_upstream_storage_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-storage":
        templates = generate_upstream_storage_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-arithmetic":
        templates = generate_upstream_arithmetic_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-bitwise":
        templates = generate_upstream_bitwise_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-comparison":
        templates = generate_upstream_comparison_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-stack":
        templates = generate_upstream_stack_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-control-flow":
        templates = generate_upstream_control_flow_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-block-context":
        templates = generate_upstream_block_context_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-block-context-manifest":
        manifest = generate_upstream_block_context_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-log":
        templates = generate_upstream_log_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-log-manifest":
        manifest = generate_upstream_log_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-keccak":
        templates = generate_upstream_keccak_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-keccak-manifest":
        manifest = generate_upstream_keccak_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-system":
        templates = generate_upstream_system_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-system-manifest":
        manifest = generate_upstream_system_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-account-query":
        templates = generate_upstream_account_query_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-account-query-manifest":
        manifest = generate_upstream_account_query_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-memory-manifest":
        manifest = generate_upstream_memory_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-memory":
        templates = generate_upstream_memory_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-call-context-manifest":
        manifest = generate_upstream_call_context_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-call-context":
        templates = generate_upstream_call_context_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-tx-context-manifest":
        manifest = generate_upstream_tx_context_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "scan-upstream-tx-context":
        templates = generate_upstream_tx_context_templates(
            repo_root=Path.cwd(),
            source_path=args.source,
            output_path=args.template_output,
            inventory_path=args.inventory_output,
        )
        print(json.dumps(templates, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-arithmetic-manifest":
        manifest = generate_upstream_arithmetic_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-bitwise-manifest":
        manifest = generate_upstream_bitwise_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-comparison-manifest":
        manifest = generate_upstream_comparison_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-stack-manifest":
        manifest = generate_upstream_stack_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "generate-control-flow-manifest":
        manifest = generate_upstream_control_flow_manifest(
            repo_root=Path.cwd(),
            template_path=args.template,
            output_path=args.output,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    if args.command == "summarize-upstream-inventory":
        summary = summarize_inventory_dir(args.inventory_dir)
        write_json(args.output, summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
