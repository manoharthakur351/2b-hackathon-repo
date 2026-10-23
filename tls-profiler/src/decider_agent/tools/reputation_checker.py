from __future__ import annotations

from typing import Any, Mapping, Protocol


class ReputationProvider(Protocol):
    def lookup(self, indicator: str) -> Mapping[str, Any]: ...


class ReputationChecker:
    def __init__(self, provider: ReputationProvider | None = None) -> None:
        self.provider = provider

    def __call__(self, state: Mapping[str, Any]) -> dict[str, Any]:
        evidence = state.get("evidence", state)
        if not isinstance(evidence, Mapping):
            raise ValueError("Reputation checking requires a structured evidence mapping.")

        indicator = evidence.get("destination_ip") or evidence.get("sni")
        if not indicator:
            return {
                "tool": "reputation_checker",
                "status": "not_checked",
                "summary": "No IP address or hostname was available for a reputation lookup.",
                "findings": [],
            }
        if self.provider is None:
            return {
                "tool": "reputation_checker",
                "status": "provider_not_configured",
                "indicator": indicator,
                "summary": (
                    "No reputation provider is configured. No threat-intelligence "
                    "claim was made."
                ),
                "findings": [],
            }

        result = self.provider.lookup(str(indicator))
        return {
            "tool": "reputation_checker",
            "status": "provider_response",
            "indicator": indicator,
            "summary": "Reputation provider response received.",
            "findings": [dict(result)],
        }
