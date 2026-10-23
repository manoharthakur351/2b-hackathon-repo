from __future__ import annotations

from typing import Any, Mapping


def analyze_tls(state: Mapping[str, Any]) -> dict[str, Any]:
    evidence = state.get("evidence", state)
    if not isinstance(evidence, Mapping):
        raise ValueError("TLS analysis requires a structured evidence mapping.")

    findings: list[str] = []
    version = evidence.get("tls_version")
    if version:
        if str(version).strip().lower() in {"tls 1.0", "tls 1.1", "tls1.0", "tls1.1"}:
            findings.append(f"Deprecated TLS version observed: {version}.")
        else:
            findings.append(f"TLS version observed: {version}.")
    else:
        findings.append("TLS version was not present in the supplied evidence.")

    for field, label in (
        ("ja3_hash", "JA3 fingerprint"),
        ("ja3_rarity", "JA3 rarity"),
        ("cipher_suite_count", "cipher-suite count"),
        ("extension_count", "TLS extension count"),
        ("sni", "SNI hostname"),
    ):
        if evidence.get(field) not in (None, ""):
            findings.append(f"{label}: {evidence[field]}.")

    return {
        "tool": "tls_analyzer",
        "summary": "TLS handshake metadata was inspected; no packet payload was decrypted.",
        "findings": findings,
    }
