from __future__ import annotations

import argparse
import json
from pathlib import Path

from adapter.bootstrap import StateBootstrapper
from adapter.env import load_dotenv
from adapter.executor import JsonRpcBackend, MockBackend, RpcExecutor, result_from_execution
from adapter.generator import generate_upstream_storage_manifest
from adapter.manifest import load_manifest
from adapter.models import Report
from adapter.oracle import ResultOracle
from adapter.profile import load_chain_profile
from adapter.report import write_report
from adapter.selector import TestSelector


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
        backend = MockBackend() if profile.backend == "mock" else JsonRpcBackend(profile)
        executor = RpcExecutor(backend)
        oracle = ResultOracle()
        results = []
        for case in selected_cases:
            namespace = bootstrapper.prepare_case_namespace(case).namespace
            tx_hashes, observed = executor.run_case(case, namespace)
            diffs = oracle.compare(case.expected, observed)
            results.append(result_from_execution(case, namespace, tx_hashes, observed, diffs))
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

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
