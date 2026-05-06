# EVM RPC Tests

This repository contains a Python 3.12 harness for running selected execution-layer tests against a dedicated, non-resettable EVM chain via RPC.

## Layout

- `third_party/execution-specs/`: read-only upstream checkout, managed as a git submodule.
- `adapter/`: local chain profiles, selectors, bootstrap logic, RPC executors, oracles, and CLI.
- `suites/`: local manifests for upstream-mapped cases and chain-specific cases.

## Quick Start

```bash
python -m pytest
python -m adapter.cli list --manifest suites/manifests/upstream_smoke.json
python -m adapter.cli bootstrap --profile profiles/mock.toml --state-dir .state
python -m adapter.cli run --profile profiles/mock.toml --manifest suites/manifests/custom_storage_smoke.json --state-dir .state
python -m adapter.cli run --profile profiles/juchain.toml --manifest suites/manifests/juchain_smoke.json --state-dir .state
python -m adapter.cli run --profile profiles/juchain.toml --manifest suites/manifests/juchain_deploy_smoke.json --state-dir .state
python -m adapter.cli run --profile profiles/juchain.toml --manifest suites/manifests/juchain_storage_smoke.json --state-dir .state
python -m adapter.cli run --profile profiles/juchain.toml --manifest suites/manifests/upstream_storage_mapped.json --state-dir .state
python -m adapter.cli generate-storage-manifest --template suites/templates/upstream_storage_templates.json --output suites/manifests/upstream_storage_mapped.json
```

For real-chain runs, create a local `.env` file from `.env.example`:

```bash
cp .env.example .env
```

Then set `JUCHAIN_PRIVATE_KEY` in `.env`. The CLI and profile loader read `.env` automatically.

For real chains, `backend` can be omitted in the profile and defaults to `jsonrpc`.
Use `backend = "mock"` only for local harness self-tests.

For `jsonrpc` profiles, `admin_key_source` is optional:

- omit it or set `rpc_unlocked` if the RPC node can send from `admin_account`
- set `env:YOUR_PRIVATE_KEY_VAR` or `file:/abs/path/to/key.hex` for local EIP-1559 signing
- use pre-signed `eth_sendRawTransaction` steps if signing happens outside this harness

## Upstream Submodule

This workspace expects a git submodule at `third_party/execution-specs/`.
If you need to initialize it in a fresh clone:

```bash
git submodule add https://github.com/ethereum/execution-specs.git third_party/execution-specs
git submodule update --init --recursive
```

When a manifest declares `execution_specs_ref` as `submodule-pending`, the harness resolves the actual upstream commit from the local submodule automatically.
