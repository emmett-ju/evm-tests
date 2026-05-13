from __future__ import annotations

from dataclasses import dataclass

from adapter.models import ChainProfile, MOCK_ONLY_ACTIONS, Manifest, TestCase


BLOCK_CONTEXT_MODE_REQUIRED_FEATURES = {
    "basefee": "base_fee",
    "prevrandao": "prevrandao",
}


@dataclass(slots=True)
class SelectionDecision:
    case: TestCase
    selected: bool
    reasons: list[str]


class TestSelector:
    def __init__(self, profile: ChainProfile) -> None:
        self.profile = profile

    def decide(self, case: TestCase) -> SelectionDecision:
        reasons = case.filters.blocked_reasons()
        reasons.extend(case.validation_errors(self.profile.backend))
        reasons.extend(self._capability_blocked_reasons(case))
        if case.filters.requires_trace_equivalence and not self.profile.trace_support:
            reasons.append("trace support unavailable in chain profile")
        if self.profile.backend == "jsonrpc":
            mock_only = sorted(
                {step["action"] for step in case.steps if isinstance(step, dict) and step.get("action") in MOCK_ONLY_ACTIONS}
            )
            if mock_only:
                reasons.append(
                    "contains mock-only actions not runnable on jsonrpc backend: "
                    + ", ".join(mock_only)
                )
        return SelectionDecision(case=case, selected=not reasons, reasons=reasons)

    def _capability_blocked_reasons(self, case: TestCase) -> list[str]:
        block_context_probe = case.observe.get("block_context_probe")
        if block_context_probe is not None:
            mode = block_context_probe.get("mode")
            if isinstance(mode, str):
                required_feature = BLOCK_CONTEXT_MODE_REQUIRED_FEATURES.get(mode)
                if required_feature is not None and not self.profile.supports_feature(required_feature):
                    return [
                        "block-context mode "
                        f"{mode} requires feature_flags.{required_feature}=true in chain profile"
                    ]
        log_probe = case.observe.get("log_probe")
        if log_probe is not None:
            log_size = log_probe.get("log_size")
            memory_seed_size = log_probe.get("memory_seed_size", 0)
            if (
                isinstance(log_size, int)
                and isinstance(memory_seed_size, int)
                and (log_size >= 1024 * 1024 or memory_seed_size >= 1024 * 1024)
                and not self.profile.supports_feature("large_log_payload")
            ):
                return ["log payload requires feature_flags.large_log_payload=true in chain profile"]
        system_witness = case.observe.get("system_witness")
        if system_witness is not None:
            shape = system_witness.get("shape")
            initcode_size = system_witness.get("initcode_size")
            if (
                shape == "create_child_code"
                and isinstance(initcode_size, int)
                and initcode_size >= 24_576
                and not self.profile.supports_feature("max_create_child_code")
            ):
                return ["max CREATE child-code payload requires feature_flags.max_create_child_code=true in chain profile"]
            if shape == "create_collision" and not self.profile.supports_feature("create_collision"):
                return ["CREATE collision witness requires feature_flags.create_collision=true in chain profile"]
            if (
                shape == "return_revert_self_call"
                and "1mib_of_non_zero_data" in case.case_id
                and not self.profile.supports_feature("large_nonzero_returndata")
            ):
                return ["1MiB non-zero returndata requires feature_flags.large_nonzero_returndata=true in chain profile"]
            if (
                shape == "selfdestruct_single"
                and system_witness.get("scenario") == "created"
                and not self.profile.supports_feature("selfdestruct_created_clears_code")
            ):
                return ["created-contract selfdestruct cleanup requires feature_flags.selfdestruct_created_clears_code=true in chain profile"]
        return []

    def select(self, manifest: Manifest) -> tuple[list[TestCase], list[SelectionDecision]]:
        manifest.validate()
        selected: list[TestCase] = []
        decisions: list[SelectionDecision] = []
        for case in manifest.cases:
            decision = self.decide(case)
            decisions.append(decision)
            if decision.selected:
                selected.append(case)
        return selected, decisions
