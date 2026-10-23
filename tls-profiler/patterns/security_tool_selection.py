"""Reusable #tool-selection recipe for security investigation agents."""

from __future__ import annotations

from typing import Any, Mapping

from src.decider_agent.decider_client import DeciderClient, DeciderDecision


QUESTION = "Which investigation tool should the security agent run next?"
OPTIONS = (
    "tls_analyzer",
    "dns_analyzer",
    "flow_analyzer",
    "reputation_checker",
    "allow_and_monitor",
)


def choose_investigation_tool(
    client: DeciderClient,
    structured_incident_state: str,
) -> DeciderDecision:
    """Ask Decider to choose one allowed tool; keep confidence and probabilities."""
    if not structured_incident_state.strip():
        raise ValueError("Provide a concise structured incident state.")
    return client.decide_tool(structured_incident_state)


EXPECTED_RESPONSE_SCHEMA = {
    "choice": "one option from OPTIONS",
    "confidence": "float in [0, 1]",
    "probabilities": "mapping from option name to probability",
    "model_latency_ms": "non-negative number or null",
    "request_latency_ms": "measured HTTP round-trip in milliseconds",
}
