"""Confidence-aware tool routing between Decider, investigation tools, and Bedrock."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .bedrock_client import (
    BedrockConfigurationError,
    BedrockExplainer,
    BedrockInvocationError,
)
from .decider_client import DeciderClient, DeciderDecision, TOOL_OPTIONS
from .state_builder import build_incident_state
from .tools import (
    ReputationChecker,
    allow_and_monitor,
    analyze_dns,
    analyze_flow,
    analyze_tls,
)


Tool = Callable[[Mapping[str, Any]], dict[str, Any]]


def default_tool_registry(
    reputation_checker: ReputationChecker | None = None,
) -> dict[str, Tool]:
    reputation = reputation_checker or ReputationChecker()
    return {
        "tls_analyzer": analyze_tls,
        "dns_analyzer": analyze_dns,
        "flow_analyzer": analyze_flow,
        "reputation_checker": reputation,
        "allow_and_monitor": allow_and_monitor,
    }


class InvestigationAgent:
    def __init__(
        self,
        decider: DeciderClient,
        bedrock: BedrockExplainer,
        tool_registry: Mapping[str, Tool] | None = None,
        confidence_threshold: float = 0.55,
    ) -> None:
        if not 0 <= confidence_threshold <= 1:
            raise ValueError("Confidence threshold must be between zero and one.")
        self.decider = decider
        self.bedrock = bedrock
        self.tool_registry = dict(
            default_tool_registry() if tool_registry is None else tool_registry
        )
        missing = set(TOOL_OPTIONS) - self.tool_registry.keys()
        if missing:
            raise ValueError(f"Tool registry is missing required tools: {sorted(missing)}")
        self.confidence_threshold = confidence_threshold

    def investigate(
        self,
        flow: Mapping[str, Any],
        prediction: Mapping[str, Any] | None = None,
        incident_text: str = "",
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        state = build_incident_state(flow, prediction, incident_text, context)
        decision: DeciderDecision = self.decider.decide_tool(state["decider_state"])
        selected_tool = decision.choice
        low_confidence = decision.confidence < self.confidence_threshold
        executed_tool = "allow_and_monitor" if low_confidence else selected_tool

        tool_result = self.tool_registry[executed_tool](state)
        decision_summary = {
            "question": "Which investigation tool should the security agent run next?",
            "selected_tool": selected_tool,
            "executed_tool": executed_tool,
            "confidence": decision.confidence,
            "probabilities": decision.probabilities,
            "model_latency_ms": decision.model_latency_ms,
            "request_latency_ms": decision.request_latency_ms,
            "confidence_threshold": self.confidence_threshold,
            "low_confidence_fallback": low_confidence,
        }
        try:
            explanation = self.bedrock.explain(state, decision_summary, tool_result)
            explanation_error = None
        except (BedrockConfigurationError, BedrockInvocationError) as error:
            explanation = None
            explanation_error = str(error)
        return {
            "state": state,
            "decision": decision_summary,
            "tool_result": tool_result,
            "explanation": explanation,
            "explanation_error": explanation_error,
        }
