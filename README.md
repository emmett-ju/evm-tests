# EVM RPC Tests

This repository contains a Python 3.12 harness for running selected Ethereum `execution-specs` benchmark cases against a dedicated, non-resettable EVM chain via RPC.

The goal is not to run upstream `execution-specs` byte-for-byte through `t8n`. The goal is to migrate every upstream benchmark case that can be proven in an RPC-only environment through final observable behavior: storage, balance, code, receipts, logs, and runtime context captured by the harness. Cases that cannot be proven honestly stay in inventory with an explicit blocked reason.

## Reader guide

Use this README to:

- understand the harness architecture and support boundary;
- run mapped manifests against the mock backend or a real RPC chain;
- regenerate checked-in upstream templates, inventories, and manifests;
- add or extend a benchmark family without losing parity with upstream;
- understand the migration roadmap and why unsupported cases remain blocked.

For current benchmark coverage totals, deferred-family rationale, and the Prague/Osaka fork capability coverage contract, see [`docs/benchmark-coverage-status.md`](docs/benchmark-coverage-status.md). That document is the stable coverage ledger; this README intentionally keeps detailed counts out of the main flow so they do not drift.

## Repository layout

- `third_party/execution-specs/`: read-only upstream checkout, managed as a git submodule.
- `adapter/`: chain profiles, selectors, bootstrap logic, RPC/mock executors, oracles, scanners, manifest generators, and CLI commands.
- `suites/templates/`: checked-in upstream-derived template and inventory snapshots.
- `suites/manifests/`: runnable manifests generated from local templates.
- `profiles/`: mock and real-chain profile examples.
- `tests/`: regression tests for scanners, manifests, CLI flows, mock execution, oracles, and checked-in artifact parity.
- `docs/benchmark-coverage-status.md`: current benchmark coverage summary and deferral notes.

## Core model

The harness is organized around three artifact layers:

1. **Upstream source**
   - `execution-specs` remains read-only.
   - Family scanners inspect upstream benchmark source and derive local case metadata.

2. **Adapter logic**
   - Family-local scanners classify cases as admitted or blocked.
   - Manifest generators render admitted cases into local runnable manifests.
   - Executors run manifests through either a mock backend or a JSON-RPC backend.
   - The oracle compares expected and observed final results.

3. **Suites**
   - Templates describe admitted cases before profile-specific execution.
   - Inventories describe the full scanned family, including blocked reasons.
   - Manifests are the executable test sets consumed by the CLI.

The standard path is:

```text
scan upstream family -> write templates + inventory -> generate manifest -> run manifest -> compare observed final state -> write report
```

## Support boundary

A benchmark case is supportable when its truth can be proven by the current harness without pretending to have upstream-only control surfaces.

Allowed proof surfaces include:

- storage;
- account balance;
- deployed code;
- receipt status;
- receipt contract address;
- receipt logs;
- runtime context captured during execution.

Cases remain blocked when they require capabilities outside the current harness, such as:

- mutable genesis or arbitrary prestate construction;
- exact block assembly or long historical block windows;
- trace equivalence;
- precise gas benchmark parity;
- blob transaction construction where the active profile cannot prove it;
- multi-address lifecycle orchestration that the harness does not yet model;
- byte-range or dynamic-memory observations that are not surfaced through final state, receipt, or logs.

Blocked entries are not failures. They are part of the support contract: the harness must not claim coverage it cannot prove.

## Backends

### Mock backend

The mock backend is for local regression and scanner/manifest/oracle integration tests. It is not a full EVM implementation. It recognizes supported harness bytecode shapes, validates runtime/probe contracts where required, and fails closed on unsupported paths.

Use it for fast development:

```bash
python -m adapter.cli run \
  --profile profiles/mock.toml \
  --manifest suites/manifests/custom_storage_smoke.json \
  --state-dir .state
```

### JSON-RPC backend

The JSON-RPC backend runs against a real dedicated chain. The chain is assumed to be non-resettable and not genesis-configurable.

For real-chain runs, create a local `.env` file from `.env.example` and provide the required private key variables. The CLI and profile loader read `.env` automatically.

```bash
cp .env.example .env
```

For `jsonrpc` profiles, `admin_key_source` is optional:

- omit it or set `rpc_unlocked` when the RPC node can send from `admin_account`;
- set `env:YOUR_PRIVATE_KEY_VAR` or `file:/abs/path/to/key.hex` for local EIP-1559 signing;
- use pre-signed `eth_sendRawTransaction` steps when signing happens outside this harness.

Use `backend = "mock"` only for local harness self-tests.

## Quick start

Show the available operational targets:

```bash
make help
```

Run the local regression suite directly when developing code:

```bash
python3 -m unittest discover -s tests -v
```

Run every upstream-mapped manifest against a real RPC profile. This writes one report per family and a combined summary at `reports/rpc/summary.json`:

```bash
make rpc-all PROFILE=profiles/juchain.toml STATE_DIR=.state REPORT_DIR=reports/rpc
```

Run one upstream family against a real RPC profile. This writes the family report plus a subset summary in the report directory:

```bash
make rpc-subset PROFILE=profiles/juchain.toml FAMILY=bitwise STATE_DIR=.state REPORT_DIR=reports/rpc
```

Run an explicit manifest path and choose report/summary paths:

```bash
make rpc-subset PROFILE=profiles/juchain.toml MANIFEST=suites/manifests/upstream_storage_mapped.json STATE_DIR=.state REPORT=reports/rpc/storage.json SUMMARY=reports/rpc/storage-summary.json
```

Use the mock profile for local smoke checks that should not hit an external chain:

```bash
make rpc-subset PROFILE=profiles/mock.toml FAMILY=bitwise REPORT_DIR=/tmp/evm-rpc-reports
```

Summarize checked-in upstream inventories:

```bash
python -m adapter.cli summarize-upstream-inventory \
  --inventory-dir suites/templates \
  --output /tmp/upstream_inventory_summary.json
```

## Regenerating upstream-derived artifacts

Use the safe sync entry point for routine upstream-derived artifact refreshes:

```bash
make sync-upstream
```

For a non-mutating generation check:

```bash
make sync-upstream SYNC_CHECK_ONLY=1
```

The sync script stages regenerated templates, inventories, and manifests for all supported benchmark families in a temporary directory first. It validates the staged manifests and inventory summary before copying anything back into `suites/templates/` or `suites/manifests/`. If generation or validation fails, the checked-in artifacts are left unchanged.

Family-local scanner and manifest commands still exist for targeted development and debugging. They follow this pattern:

```bash
python -m adapter.cli scan-upstream-<family> \
  --template-output suites/templates/upstream_<family>_templates.json \
  --inventory-output suites/templates/upstream_<family>_inventory.json

python -m adapter.cli generate-<family>-manifest \
  --template suites/templates/upstream_<family>_templates.json \
  --output suites/manifests/upstream_<family>_mapped.json
```

After regenerating checked-in artifacts, run the relevant parity tests and then the full test suite.

## Inventory contract

Inventories are the project’s coverage ledger. They should be regenerated from upstream source, not hand-edited.

A family inventory records:

- a stable family name;
- the upstream source scanned;
- every discovered case;
- each local `case_id`;
- whether the case is admitted;
- the scanner mode/source classification;
- blocked reasons for cases that cannot be admitted.

A typical entry has this shape:

```json
{
  "upstream_ref": "tests/...::test_xxx[...]",
  "case_id": "upstream.benchmark.<family>....",
  "admitted": true,
  "mode": "optional-template-mode",
  "reasons": [],
  "source": "scanner-subgroup"
}
```

For blocked entries, `reasons` must be non-empty and should describe the missing capability, not a vague implementation status. Prefer stable phrases such as:

- `requires genesis state`
- `requires block environment control`
- `requires trace equivalence`
- `requires precise gas fixture`
- `requires blob transaction support`
- `requires unsupported runtime observation`
- `requires unsupported multi-tx orchestration`
- `requires unsupported account or code prestate model`

Existing family-local scanners may use more specific reason strings where those strings are part of checked-in parity; update tests and regenerated artifacts together if those strings change.

## Adding or extending a benchmark family

Use the smallest honest vertical slice:

1. Identify the upstream benchmark family and read its source.
2. Define the support boundary for the family using final observable proof surfaces.
3. Add or extend a family-local scanner.
4. Generate or update the checked-in inventory.
5. Add template generation only for admitted cases.
6. Generate the runnable manifest from templates.
7. Add mock backend semantics for the admitted runtime/probe shapes.
8. Keep the runtime proof fail-closed: do not trust manifest metadata alone when deployed runtime bytes can be reconstructed and checked.
9. Add or update parity tests for scanner output, manifest generation, CLI commands, mock execution, and coverage summaries.
10. Run the full regression suite and `git diff --check`.

Do not copy upstream cases into manifests manually. Do not mark a case admitted just because the scanner can identify it. Admission requires a runnable manifest, expected proof, backend semantics, and regression coverage.

## Runtime placeholders and observations

Some expected values depend on runtime context rather than static template values. The oracle supports placeholders that are resolved after execution and before final comparison.

Common placeholders include:

- `$last_contract_word`
- `$admin_account_word`

Use placeholders when the expected value is deterministic but only known after deployment or transaction execution. Prefer adding a clear runtime observation or placeholder over hard-coding environment-specific values into templates.

## Migration roadmap

The project has progressed from hand-written smoke cases into family-local scanners, checked-in inventories, generated manifests, and regression-protected coverage summaries.

Future work should follow this order:

1. **Preserve the coverage ledger.** Keep every family inventory regenerable from upstream source and locked by tests.
2. **Close supportable subsets before inventing new abstractions.** Extend admitted cases only when final observable proof is available.
3. **Add reusable observation primitives when repeated blocked reasons justify them.** Examples include richer receipt-log checks, byte-window witnesses, runtime-context placeholders, and multi-address orchestration.
4. **Treat high-complexity families as harness capability work.** Block-context, log, system, blob-related, and dynamic memory/log cases should not be forced into approximate mappings.
5. **Seal coverage only when every target family has inventory, every admitted case has a runnable manifest and tests, and every blocked case has a stable capability reason.**

The current benchmark coverage status and the explicit list of deferred families live in [`docs/benchmark-coverage-status.md`](docs/benchmark-coverage-status.md).

## Practical rules for maintainers

- Keep upstream as a read-only submodule.
- Prefer family-local scanner modules and CLI commands over a premature generic benchmark-scanner framework.
- Keep checked-in templates, inventories, manifests, and tests in sync.
- Treat explanatory note strings in generated artifacts as parity-sensitive unless tests are updated intentionally.
- Make mock backend support narrow and fail-closed; it should validate supported harness shapes, not emulate the full EVM.
- Use final state, receipts, logs, and captured context as proof. Do not claim trace or gas benchmark parity unless the harness actually proves it.
- When in doubt, block the case with a precise reason and document the missing capability.

## Upstream submodule

This workspace expects a git submodule at `third_party/execution-specs/`.

If you need to initialize it in a fresh clone:

```bash
git submodule add https://github.com/ethereum/execution-specs.git third_party/execution-specs
git submodule update --init --recursive
```

When a manifest declares `execution_specs_ref` as `submodule-pending`, the harness resolves the actual upstream commit from the local submodule automatically.
