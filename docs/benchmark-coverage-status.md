# Upstream benchmark coverage status

## Reader and purpose

This document is for an internal engineer deciding whether to continue benchmark-family coverage work.

After reading it, the engineer should be able to choose a next coverage target, or decide not to pursue one, without rediscovering the current blocked reasons from the inventory JSON files.

The checked-in inventory files remain the source of truth. This page summarizes their current state and the project decision to stop after the final low-risk `bitwise` increment unless a future milestone expands the harness model.

## Current coverage

Current first-family coverage is:

| Status | Count |
|---|---:|
| Families scanned | 14 |
| Total cases | 613 |
| Admitted cases | 537 |
| Blocked cases | 76 |
| Coverage | 87.6% |

## Completed families

These families are fully admitted and currently have no blocked cases:

| Family | Cases | Notes |
|---|---:|---|
| arithmetic | 65 | Deterministic arithmetic storage witnesses. |
| bitwise | 12 | Completed by the CLZ-diff witness; complex shift and CLZ shapes are represented as deterministic benchmark-shape witnesses, not throughput parity claims. |
| call-context | 20 | Final storage witnesses for call-frame values and calldata-derived operations. |
| comparison | 6 | Deterministic comparison storage witnesses. |
| control-flow | 7 | Deterministic control-flow witnesses. |
| keccak | 35 | Deterministic memory/hash witnesses. |
| stack | 65 | Deterministic stack opcode witnesses. |
| storage | 17 | Final storage/receipt-status witnesses. |

## Deferred families

The remaining blocked cases are intentionally deferred for now. They are not simple scanner omissions; each blocked group requires either byte-window observation, block/blob environment control, multi-address orchestration, or lifecycle/prestate machinery that the current RPC-only final-observable harness does not provide.

| Family | Total | Admitted | Blocked | Deferred reason |
|---|---:|---:|---:|---|
| account-query | 40 | 10 | 30 | Dynamic CODECOPY and EXTCODECOPY require byte-range code-copy observation and external-account code fixtures. The fixed CODECOPY subset is already admitted. |
| block-context | 13 | 8 | 5 | Historical BLOCKHASH and blob-base-fee cases require controllable block/blob environment witnesses that are not available through the current RPC-only model. |
| log | 140 | 130 | 10 | Remaining cases use gas-derived dynamic log offsets with non-zero payloads; truthful admission requires observing the actual byte window, not just receipt existence. |
| memory | 143 | 125 | 18 | Remaining MCOPY cases use gas-derived dynamic source/destination offsets with non-zero copies; final storage proof for the actual copied byte window is not yet mapped. |
| system | 46 | 35 | 11 | Remaining cases require multi-address external-call orchestration, SELFDESTRUCT initcode lifecycle witnesses, or mutable future CREATE address pre-allocation. |
| tx-context | 4 | 2 | 2 | BLOBHASH cases require blob transaction construction and a blob-capable execution/profile witness. |

## What was deliberately stopped

The project now has a useful stopping point for the current harness model:

- Low-risk, final-storage-observable families are complete.
- `bitwise` no longer has the single remaining blocked CLZ-diff gap.
- `account-query`, `memory`, and `log` have already admitted their safe fixed or offset-independent subsets.
- The remaining blocked cases are high-complexity harness-expansion work, not routine family coverage.

Do not admit the deferred cases just to improve the coverage percentage. A case should move from blocked to admitted only when the manifest can prove the upstream intent through deterministic final observables or through an explicitly designed new observation surface.

## Recommended future work

If coverage work resumes, treat it as harness capability design, not as a small scanner patch.

Reasonable future milestones:

1. **External-code byte-window observation** for the remaining account-query EXTCODECOPY cases.
2. **Dynamic byte-window witness design** for memory MCOPY and log payload cases.
3. **Multi-address orchestration** for the remaining system call-family cases.
4. **Blob transaction/profile support** for tx-context and block-context blob cases.
5. **Historical block witness strategy** for BLOCKHASH cases.

Until one of those capabilities is explicitly planned, the 76 blocked cases should remain blocked with their current reasons.
