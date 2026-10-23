from __future__ import annotations

from typing import Any, Mapping


def allow_and_monitor(state: Mapping[str, Any]) -> dict[str, Any]:
    evidence = state.get("evidence", state)
    if not isinstance(evidence, Mapping):
        raise ValueError("Monitoring requires a structured evidence mapping.")
    return {
        "tool": "allow_and_monitor",
        "summary": (
            "No additional investigation action was taken. Retain the available "
            "metadata and monitor for repeated or stronger indicators."
        ),
        "findings": [
            f"Evidence fields available: {len(evidence)}.",
            "This is a monitoring recommendation, not a verdict that the traffic is safe.",
        ],
    }
