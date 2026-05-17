# Prague and Osaka Execution-Layer Capabilities Design

## Purpose
This document outlines the harness expansion and proof strategies required to admit the remaining Prague and Osaka capabilities. The initial `M026` milestone provided coverage for simple RPC-observable execution capabilities (Osaka CLZ and Prague BLS12-381 `add_G1`), but deferred complex transaction, gas, and block-level features.

This design sketch guarantees that these deferred capabilities will not be falsely passed via metadata-only expectations. Each capability must be explicitly proven through a specific harness mechanism.

## 1. MODEXP Repricing (Osaka EIP-7883)

### Challenge
The Osaka hardfork includes EIP-7883, which increases the gas cost of the MODEXP precompile. A standard deploy/invoke probe might simply test whether MODEXP is available, falsely passing on a Cancun profile that supports MODEXP but uses the old gas schedule.

### Design Strategy
- **Gas-Boundary Proof:** The probe must distinguish between the old and new gas schedules. 
- **Mechanism:** The harness will construct a `STATICCALL` to MODEXP with a fixed, strictly calculated `gas_stipend`. 
    - The stipend will be chosen such that `stipend >= Osaka required gas` but `stipend < pre-Osaka required gas` (or vice versa depending on the specific cost delta).
- **Observable Evidence:** The wrapper contract will observe the success of the inner call. If the call succeeds, it proves the correct gas schedule is active. The wrapper stores the success bit and returndatasize in storage for the final RPC proof.
- **Feature Gate:** `feature_flags.modexp_eip7883`

## 2. Calldata Floor (Osaka EIP-7623)

### Challenge
EIP-7623 introduces a higher intrinsic gas floor for transactions with large amounts of non-zero calldata. The existing JSON-RPC adapter applies an intrinsic gas ceiling, but we need to prove the chain correctly enforces the EIP-7623 rule at the mempool/RPC level.

### Design Strategy
- **Direct RPC Proof:** This feature cannot be proven via EVM storage because the transaction is rejected before execution.
- **Mechanism:** The harness generates a large non-zero calldata transaction, preserves a caller-declared `gas` value below the EIP-7623 floor, signs it locally as a type-2 transaction, and submits it through `eth_sendRawTransaction`.
- **Observable Evidence:** The JSON-RPC backend matches the RPC rejection error (`code=-32000`, message containing `intrinsic gas`) and records that matched rejection under `observed.rpc_error`. No receipt or storage effects are claimed.
- **Feature Gate:** `feature_flags.calldata_floor_eip7623`

## 3. EIP-7702 Set EOA Account Code (Prague)

### Challenge
EIP-7702 introduces a new transaction type (Type-4) that allows EOAs to temporarily set their code during a transaction via an authorization tuple.

### Design Strategy
- **Harness Expansion:** The transaction signer supports Type-4 transactions and dynamically signs `authorizations_to_sign`.
- **Mechanism:** 
    1. Deploy a simple target contract.
    2. Submit a Type-4 transaction containing an authorization delegating an EOA to the target contract.
    3. The transaction executes a call against the delegated EOA.
- **Observable Evidence:** The EOA performs a storage write, which is verified by `eth_getStorageAt` at the end of the transaction.
- **Feature Gate:** `feature_flags.eip7702`

## 4. Blob Transactions and BLOBHASH (Cancun/Prague)

### Challenge
While blobs were introduced in Cancun, they remain blocked in our harness. Testing `BLOBHASH` or blob limits requires constructing and submitting Type-3 transactions with sidecar KZG proofs.

### Design Strategy
- **Harness Expansion:** The transaction builder must support Type-3 transactions, requiring dependencies capable of constructing KZG commitments and proofs.
- **Mechanism:** Generate a Type-3 transaction with a blob payload, invoking a contract that reads `BLOBHASH`.
- **Observable Evidence:** The contract writes the observed `BLOBHASH` to storage. The harness validates this against the deterministic hash of the submitted blob.
- **Feature Gate:** `feature_flags.blob` (and potentially `blob_cell_proofs` for Osaka extensions).

## 5. Block-Level Access Lists (Amsterdam/Prague EIP-7928)

### Challenge
EIP-7928 shifts access lists to the block level to optimize parallel execution and state prefetching. The current harness evaluates single transactions in isolation.

### Design Strategy
- **Harness Expansion:** Proving block-level optimizations requires submitting a block with overlapping or non-overlapping dependencies across multiple transactions. 
- **Mechanism:** This is fundamentally a client performance benchmark rather than a semantic EVM capability that can be proven via a single storage slot. 
- **Observable Evidence:** A true proof requires tracing or performance metric extraction, which falls outside the scope of the `evm-tests` RPC-only deterministic witness model. 
- **Recommendation:** Keep deferred indefinitely for standard compliance runs. If implemented, it requires a dedicated `block_benchmark` harness mode.
- **Feature Gate:** `feature_flags.block_access_lists`

## Conclusion
The path forward requires expanding the `adapter/transaction.py` and `adapter/signer.py` modules to support Type-3/Type-4 transactions and `expect_error` workflows. Until these harness capabilities are implemented, the associated cases will remain legitimately blocked with specific feature-gate skipping reasons.
