from __future__ import annotations

from typing import Any, Mapping


def analyze_flow(state: Mapping[str, Any]) -> dict[str, Any]:
    evidence = state.get("evidence", state)
    if not isinstance(evidence, Mapping):
        raise ValueError("Flow analysis requires a structured evidence mapping.")

    labels = {
        "packet_count": "packet count",
        "total_bytes": "total bytes",
        "bytes_sent": "bytes sent",
        "bytes_received": "bytes received",
        "average_packet_size": "average packet size",
        "flow_duration": "flow duration in seconds",
        "iat_mean": "mean inter-arrival time in seconds",
        "repeated_connections": "repeated-connection indicator",
    }
    findings = [
        f"{label}: {evidence[key]}."
        for key, label in labels.items()
        if evidence.get(key) is not None
    ]
    return {
        "tool": "flow_analyzer",
        "summary": "Connection volume, directionality, and timing evidence were inspected.",
        "findings": findings or ["No flow metrics were available."],
    }
