from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


from adapter.log_probe import validate_log_probe_declaration
from adapter.system_witness import validate_system_witness_declaration


CaseKind = Literal["upstream_mapped", "custom_chain"]
BackendName = Literal["mock", "jsonrpc"]

SUPPORTED_EXECUTION_ACTIONS = frozenset(
    {
        "set_balance",
        "set_code",
        "set_storage",
        "transfer_native",
        "deploy_contract",
        "invoke_contract",
        "wait_receipt",
        "rpc_call",
        "eth_sendRawTransaction",
        "eth_sendTransaction",
    }
)
MOCK_ONLY_ACTIONS = frozenset({"set_balance", "set_code", "set_storage"})
JSONRPC_ONLY_ACTIONS = frozenset({"rpc_call", "eth_sendRawTransaction", "eth_sendTransaction"})
_ACTION_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "set_balance": frozenset({"value"}),
    "set_code": frozenset({"value"}),
    "set_storage": frozenset({"slot", "value"}),
    "transfer_native": frozenset({"to", "value"}),
    "deploy_contract": frozenset({"bytecode_init", "bytecode_runtime"}),
    "invoke_contract": frozenset({"to", "data"}),
    "wait_receipt": frozenset({"tx_hash"}),
    "rpc_call": frozenset({"method"}),
    "eth_sendRawTransaction": frozenset(),
    "eth_sendTransaction": frozenset({"transaction"}),
}
_ACTION_OPTIONAL_FIELDS: dict[str, frozenset[str]] = {
    "set_balance": frozenset(),
    "set_code": frozenset(),
    "set_storage": frozenset(),
    "transfer_native": frozenset({"capture_balance_before", "data", "expected_receipt_status", "gas"}),
    "deploy_contract": frozenset({"gas", "initial_storage", "value"}),
    "invoke_contract": frozenset({"expected_receipt_status", "gas", "gas_price", "value"}),
    "wait_receipt": frozenset({"timeout_seconds"}),
    "rpc_call": frozenset({"params"}),
    "eth_sendRawTransaction": frozenset({"raw_transaction", "transaction", "expect_error"}),
    "eth_sendTransaction": frozenset(),
}
_ACTION_STRING_FIELDS: dict[str, frozenset[str]] = {
    "set_balance": frozenset({"value"}),
    "set_code": frozenset({"value"}),
    "set_storage": frozenset({"slot", "value"}),
    "transfer_native": frozenset({"to", "value", "data", "expected_receipt_status", "gas", "capture_balance_before"}),
    "deploy_contract": frozenset({"bytecode_init", "bytecode_runtime", "gas", "value"}),
    "invoke_contract": frozenset({"to", "data", "expected_receipt_status", "gas", "gas_price", "value"}),
    "wait_receipt": frozenset({"tx_hash"}),
    "rpc_call": frozenset({"method"}),
    "eth_sendRawTransaction": frozenset({"raw_transaction"}),
    "eth_sendTransaction": frozenset(),
}


def _case_label(case_id: Any) -> str:
    if isinstance(case_id, str) and case_id:
        return case_id
    return "<unknown-case>"


def _require_non_empty_string(value: Any, context: str, field_name: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{context}: {field_name} is required and must be a non-empty string")


def _validate_string_mapping(value: Any, context: str, field_name: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{context}: {field_name} must be an object mapping string keys to string values")
        return
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            errors.append(
                f"{context}: {field_name} must be an object mapping string keys to string values"
            )
            return


def validate_execution_step(
    step: Any,
    *,
    case_id: Any,
    step_index: int,
    backend: BackendName | None = None,
) -> list[str]:
    context = f"case {_case_label(case_id)} step {step_index + 1}"
    errors: list[str] = []
    if not isinstance(step, dict):
        return [f"{context}: step must be an object"]

    action = step.get("action")
    if not isinstance(action, str) or not action:
        return [f"{context}: action is required and must be a non-empty string"]
    if action not in SUPPORTED_EXECUTION_ACTIONS:
        supported = ", ".join(sorted(SUPPORTED_EXECUTION_ACTIONS))
        return [f"{context}: unsupported action {action!r}; supported actions: {supported}"]

    required_fields = _ACTION_REQUIRED_FIELDS[action]
    optional_fields = _ACTION_OPTIONAL_FIELDS[action]
    allowed_fields = required_fields | optional_fields | {"action"}
    missing_fields = sorted(required_fields - step.keys())
    if missing_fields:
        errors.append(
            f"{context}: action {action!r} is missing required fields: {', '.join(missing_fields)}"
        )
    extra_fields = sorted(set(step) - allowed_fields)
    if extra_fields:
        errors.append(f"{context}: action {action!r} does not allow fields: {', '.join(extra_fields)}")

    for field_name in _ACTION_STRING_FIELDS[action]:
        if field_name in step and not isinstance(step[field_name], str):
            errors.append(f"{context}: action {action!r} field {field_name!r} must be a string")

    if action == "wait_receipt" and "timeout_seconds" in step and not isinstance(step["timeout_seconds"], int):
        errors.append(f"{context}: action 'wait_receipt' field 'timeout_seconds' must be an integer")
    if action == "rpc_call" and "params" in step and not isinstance(step["params"], list):
        errors.append(f"{context}: action 'rpc_call' field 'params' must be a list")
    if action == "eth_sendRawTransaction":
        has_raw = "raw_transaction" in step
        has_transaction = "transaction" in step
        if has_raw == has_transaction:
            errors.append(
                f"{context}: action 'eth_sendRawTransaction' requires exactly one of 'raw_transaction' or 'transaction'"
            )
        if has_transaction and not isinstance(step["transaction"], dict):
            errors.append(f"{context}: action 'eth_sendRawTransaction' field 'transaction' must be an object")
        if "expect_error" in step:
            expect_error = step["expect_error"]
            if not isinstance(expect_error, dict):
                errors.append(f"{context}: action 'eth_sendRawTransaction' field 'expect_error' must be an object")
            else:
                message_contains = expect_error.get("message_contains")
                if not isinstance(message_contains, str) or not message_contains:
                    errors.append(
                        f"{context}: action 'eth_sendRawTransaction' field 'expect_error.message_contains' must be a non-empty string"
                    )
                if "code" in expect_error and not isinstance(expect_error["code"], int):
                    errors.append(
                        f"{context}: action 'eth_sendRawTransaction' field 'expect_error.code' must be an integer"
                    )
    if action == "eth_sendTransaction" and "transaction" in step and not isinstance(step["transaction"], dict):
        errors.append(f"{context}: action 'eth_sendTransaction' field 'transaction' must be an object")
    if action == "deploy_contract" and "initial_storage" in step:
        _validate_string_mapping(step["initial_storage"], context, "initial_storage", errors)

    if backend == "jsonrpc" and action in MOCK_ONLY_ACTIONS:
        errors.append(f"{context}: action {action!r} is mock-only and not runnable on jsonrpc backend")
    if backend == "mock" and action in JSONRPC_ONLY_ACTIONS:
        errors.append(f"{context}: action {action!r} is jsonrpc-only and not runnable on mock backend")
    return errors


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
class BlockContextConfig:
    coinbase: str | None = None
    timestamp: int | None = None
    number: int | None = None
    prevrandao: str | None = None
    gas_limit: int | None = None
    base_fee: int | None = None
    rpc_block_tag: str = "latest"

    def validate(self) -> None:
        if self.coinbase is not None and not self.coinbase.startswith("0x"):
            raise ValueError("block_context.coinbase must be hex-prefixed")
        if self.prevrandao is not None and not self.prevrandao.startswith("0x"):
            raise ValueError("block_context.prevrandao must be hex-prefixed")
        if self.timestamp is not None and self.timestamp < 0:
            raise ValueError("block_context.timestamp must be non-negative")
        if self.number is not None and self.number < 0:
            raise ValueError("block_context.number must be non-negative")
        if self.gas_limit is not None and self.gas_limit < 0:
            raise ValueError("block_context.gas_limit must be non-negative")
        if self.base_fee is not None and self.base_fee < 0:
            raise ValueError("block_context.base_fee must be non-negative")
        if not self.rpc_block_tag:
            raise ValueError("block_context.rpc_block_tag is required")


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
    block_context: BlockContextConfig = field(default_factory=BlockContextConfig)

    def validate(self) -> None:
        if not self.rpc_url:
            raise ValueError("rpc_url is required")
        if self.chain_id <= 0:
            raise ValueError("chain_id must be positive")
        if not self.namespace_policy.prefix:
            raise ValueError("namespace prefix is required")
        if not self.admin_account.startswith("0x"):
            raise ValueError("admin_account must be hex-prefixed")
        self.block_context.validate()

    def supports_feature(self, feature_name: str) -> bool:
        return bool(self.feature_flags.get(feature_name, False))


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

    def validation_errors(self, backend: BackendName | None = None) -> list[str]:
        context = f"case {_case_label(self.case_id)}"
        errors: list[str] = []
        if self.kind not in {"upstream_mapped", "custom_chain"}:
            errors.append(
                f"{context}: kind must be one of ['custom_chain', 'upstream_mapped'], got {self.kind!r}"
            )
        _require_non_empty_string(self.case_id, context, "case_id", errors)
        _require_non_empty_string(self.family, context, "family", errors)
        _require_non_empty_string(self.description, context, "description", errors)
        _require_non_empty_string(self.namespace_seed, context, "namespace_seed", errors)
        if not isinstance(self.filters, FilterRule):
            errors.append(f"{context}: filters must be a FilterRule")
        if not isinstance(self.steps, list):
            errors.append(f"{context}: steps must be a list")
        else:
            rejection_steps = 0
            for step_index, step in enumerate(self.steps):
                errors.extend(
                    validate_execution_step(
                        step,
                        case_id=self.case_id,
                        step_index=step_index,
                        backend=backend,
                    )
                )
                if isinstance(step, dict) and step.get("action") == "eth_sendRawTransaction" and "expect_error" in step:
                    rejection_steps += 1
                    if step_index != len(self.steps) - 1:
                        errors.append(
                            f"{context}: eth_sendRawTransaction step with expect_error must be the final step"
                        )
            if not isinstance(self.expected, dict):
                errors.append(f"{context}: expected must be an object")
            else:
                if "rpc_error" in self.expected:
                    if rejection_steps != 1:
                        errors.append(
                            f"{context}: expected.rpc_error requires exactly one eth_sendRawTransaction step with expect_error"
                        )
                    rpc_error = self.expected["rpc_error"]
                    if not isinstance(rpc_error, dict):
                        errors.append(f"{context}: expected.rpc_error must be an object")
                    else:
                        message_contains = rpc_error.get("message_contains")
                        if not isinstance(message_contains, str) or not message_contains:
                            errors.append(
                                f"{context}: expected.rpc_error.message_contains must be a non-empty string"
                            )
                        if "code" in rpc_error and not isinstance(rpc_error["code"], int):
                            errors.append(f"{context}: expected.rpc_error.code must be an integer")
        if not isinstance(self.observe, dict):
            errors.append(f"{context}: observe must be an object")
        else:
            log_probe = self.observe.get("log_probe")
            if log_probe is not None:
                try:
                    validate_log_probe_declaration(log_probe)
                except ValueError as exc:
                    errors.append(str(exc))
            system_witness = self.observe.get("system_witness")
            if system_witness is not None:
                try:
                    validate_system_witness_declaration(system_witness)
                except ValueError as exc:
                    errors.append(str(exc))
        if self.upstream_ref is not None and not isinstance(self.upstream_ref, str):
            errors.append(f"{context}: upstream_ref must be a string when present")
        if not isinstance(self.notes, list) or any(not isinstance(note, str) for note in self.notes):
            errors.append(f"{context}: notes must be a list of strings")
        return errors

    def validate(self, backend: BackendName | None = None) -> None:
        errors = self.validation_errors(backend)
        if errors:
            raise ValueError(errors[0])


@dataclass(slots=True)
class Manifest:
    name: str
    version: str
    execution_specs_ref: str
    suite_version: str
    chain_profile_version: str
    cases: list[TestCase]
    path: Path

    def validation_errors(self, backend: BackendName | None = None) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.name, str) or not self.name:
            errors.append("manifest: name is required and must be a non-empty string")
        if not isinstance(self.version, str) or not self.version:
            errors.append("manifest: version is required and must be a non-empty string")
        if not isinstance(self.execution_specs_ref, str) or not self.execution_specs_ref:
            errors.append(
                "manifest: execution_specs_ref is required and must resolve to a non-empty string"
            )
        if not isinstance(self.suite_version, str) or not self.suite_version:
            errors.append("manifest: suite_version is required and must be a non-empty string")
        if not isinstance(self.chain_profile_version, str) or not self.chain_profile_version:
            errors.append(
                "manifest: chain_profile_version is required and must be a non-empty string"
            )
        if not isinstance(self.cases, list):
            errors.append("manifest: cases must be a list")
        else:
            for case in self.cases:
                if not isinstance(case, TestCase):
                    errors.append("manifest: cases must contain TestCase objects")
                    continue
                errors.extend(case.validation_errors(backend))
        if not isinstance(self.path, Path):
            errors.append("manifest: path must be a Path")
        return errors

    def validate(self, backend: BackendName | None = None) -> None:
        errors = self.validation_errors(backend)
        if errors:
            raise ValueError(errors[0])


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
    context: dict[str, Any]
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
