from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


CaseKind = Literal["upstream_mapped", "custom_chain"]


@dataclass(slots=True)
class GasPolicy:
    gas_limit: int
    max_fee_per_gas: int | None = None
    max_priority_fee_per_gas: int | None = None


@dataclass(slots=True)
class NamespacePolicy:
    prefix: str
    reuse_strategy: Literal["idempotent", "always_new"] = "idempotent"


@dataclass(slots=True)
class ChainProfile:
    name: str
    rpc_url: str
    chain_id: int
    hardfork: str
    feature_flags: dict[str, bool]
    gas_policy: GasPolicy
    namespace_policy: NamespacePolicy
    admin_account: str
    admin_key_source: str | None = None
    trace_support: bool = False
    predeployed_allowlist: list[str] = field(default_factory=list)
    backend: Literal["mock", "jsonrpc"] = "jsonrpc"

    def validate(self) -> None:
        if not self.rpc_url:
            raise ValueError("rpc_url is required")
        if self.chain_id <= 0:
            raise ValueError("chain_id must be positive")
        if not self.namespace_policy.prefix:
            raise ValueError("namespace prefix is required")
        if not self.admin_account.startswith("0x"):
            raise ValueError("admin_account must be hex-prefixed")


@dataclass(slots=True)
class FilterRule:
    requires_genesis_state: bool = False
    requires_precise_gas: bool = False
    requires_block_control: bool = False
    requires_trace_equivalence: bool = False

    def blocked_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.requires_genesis_state:
            reasons.append("requires genesis state")
        if self.requires_precise_gas:
            reasons.append("requires precise gas fixture")
        if self.requires_block_control:
            reasons.append("requires block environment control")
        if self.requires_trace_equivalence:
            reasons.append("requires trace equivalence")
        return reasons


@dataclass(slots=True)
class TestCase:
    kind: CaseKind
    case_id: str
    family: str
    description: str
    filters: FilterRule
    namespace_seed: str
    steps: list[dict[str, Any]]
    expected: dict[str, Any]
    observe: dict[str, Any] = field(default_factory=dict)
    upstream_ref: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Manifest:
    name: str
    version: str
    execution_specs_ref: str
    suite_version: str
    chain_profile_version: str
    cases: list[TestCase]
    path: Path


@dataclass(slots=True)
class NamespaceRecord:
    namespace: str
    seed: str
    created_by: str
    resources: dict[str, Any]


@dataclass(slots=True)
class ExecutionResult:
    case_id: str
    namespace: str
    success: bool
    tx_hashes: list[str]
    observed: dict[str, Any]
    expected: dict[str, Any]
    diffs: list[str]


@dataclass(slots=True)
class Report:
    manifest: str
    execution_specs_ref: str
    suite_version: str
    chain_profile: str
    chain_profile_version: str
    results: list[ExecutionResult]
