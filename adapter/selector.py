from __future__ import annotations

from dataclasses import dataclass

from adapter.models import ChainProfile, MOCK_ONLY_ACTIONS, Manifest, TestCase


BLOCK_CONTEXT_MODE_REQUIRED_FEATURES = {
    "basefee": "base_fee",
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
        if block_context_probe is None:
            return []
        mode = block_context_probe.get("mode")
        if not isinstance(mode, str):
            return []
        required_feature = BLOCK_CONTEXT_MODE_REQUIRED_FEATURES.get(mode)
        if required_feature is None or self.profile.supports_feature(required_feature):
            return []
        return [
            "block-context mode "
            f"{mode} requires feature_flags.{required_feature}=true in chain profile"
        ]

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
