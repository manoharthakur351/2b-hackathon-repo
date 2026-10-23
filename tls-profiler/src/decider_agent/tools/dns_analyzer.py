from __future__ import annotations

from typing import Any, Mapping


def analyze_dns(state: Mapping[str, Any]) -> dict[str, Any]:
    evidence = state.get("evidence", state)
    if not isinstance(evidence, Mapping):
        raise ValueError("DNS analysis requires a structured evidence mapping.")

    findings: list[str] = []
    hostname = evidence.get("sni")
    if hostname:
        labels = [part for part in str(hostname).rstrip(".").split(".") if part]
        findings.append(f"SNI hostname observed: {hostname}.")
        findings.append(f"Hostname has {len(labels)} non-empty label(s).")
        entropy = evidence.get("domain_entropy")
        if entropy is not None:
            findings.append(f"Recorded hostname character entropy: {entropy}.")
    else:
        findings.append("No SNI hostname was available; DNS-level evidence is limited.")

    seen = evidence.get("destination_previously_seen")
    if seen is not None:
        findings.append(f"Destination previously seen: {seen}.")
    if evidence.get("dns_queries") is not None:
        findings.append(f"DNS query count: {evidence['dns_queries']}.")

    return {
        "tool": "dns_analyzer",
        "summary": "Hostname and available DNS-related metadata were inspected.",
        "findings": findings,
    }
