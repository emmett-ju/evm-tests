from __future__ import annotations

from dataclasses import dataclass

from adapter.models import ChainProfile, Manifest, TestCase


MOCK_ONLY_ACTIONS = {"set_balance", "set_storage", "set_code"}


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
        if case.filters.requires_trace_equivalence and not self.profile.trace_support:
            reasons.append("trace support unavailable in chain profile")
        if self.profile.backend == "jsonrpc":
            mock_only = sorted(
                {step["action"] for step in case.steps if step["action"] in MOCK_ONLY_ACTIONS}
            )
            if mock_only:
                reasons.append(
                    "contains mock-only actions not runnable on jsonrpc backend: "
                    + ", ".join(mock_only)
                )
        return SelectionDecision(case=case, selected=not reasons, reasons=reasons)

    def select(self, manifest: Manifest) -> tuple[list[TestCase], list[SelectionDecision]]:
        selected: list[TestCase] = []
        decisions: list[SelectionDecision] = []
        for case in manifest.cases:
            decision = self.decide(case)
            decisions.append(decision)
            if decision.selected:
                selected.append(case)
        return selected, decisions
