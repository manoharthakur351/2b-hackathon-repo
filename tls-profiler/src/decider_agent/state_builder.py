"""Build concise, bounded incident state from existing TLSProfiler evidence."""

from __future__ import annotations

from typing import Any, Mapping


_STATE_FIELDS = (
    ("Flow ID", "flow_id"),
    ("Source IP", "source_ip"),
    ("Source Port", "source_port"),
    ("Destination IP", "destination_ip"),
    ("Destination Port", "destination_port"),
    ("SNI", "sni"),
    ("TLS Version", "tls_version"),
    ("JA3 hash", "ja3_hash"),
    ("JA3 rarity", "ja3_rarity"),
    ("Domain entropy", "domain_entropy"),
    ("Destination previously seen", "destination_previously_seen"),
    ("Repeated connections", "repeated_connections"),
    ("Packets", "packet_count"),
    ("Total bytes", "total_bytes"),
    ("Bytes sent", "bytes_sent"),
    ("Bytes received", "bytes_received"),
    ("Average packet size", "average_packet_size"),
    ("Flow duration (s)", "flow_duration"),
    ("Mean inter-arrival time (s)", "iat_mean"),
    ("Cipher suite count", "cipher_suite_count"),
    ("TLS extension count", "extension_count"),
    ("ML anomaly probability", "ml_anomaly_probability"),
    ("ML prediction confidence", "ml_confidence"),
    ("ML prediction", "ml_prediction"),
)

_CORE_FLOW_FIELDS = {
    "Source IP": "source_ip",
    "Destination IP": "destination_ip",
    "Packet_Count": "packet_count",
    "Total_Bytes": "total_bytes",
    "Flow_Duration": "flow_duration",
}


def _is_missing(value: Any) -> bool:
    return value is None or str(value).strip().lower() in {"", "nan", "none", "<na>"}


def build_incident_state(
    flow: Mapping[str, Any],
    prediction: Mapping[str, Any] | None = None,
    incident_text: str = "",
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize existing flow/prediction data and produce a bounded Decider state."""
    if not isinstance(flow, Mapping):
        raise ValueError("Flow evidence must be a mapping.")
    if not isinstance(incident_text, str):
        raise ValueError("Incident description must be text.")

    raw_values: dict[str, Any] = {
        "flow_id": flow.get("Flow_ID", flow.get("flow_id")),
        "source_ip": flow.get("Source IP", flow.get("source_ip")),
        "source_port": flow.get("Source Port", flow.get("source_port")),
        "destination_ip": flow.get("Destination IP", flow.get("destination_ip")),
        "destination_port": flow.get("Destination Port", flow.get("destination_port")),
        "sni": flow.get("SNI", flow.get("sni")),
        "tls_version": flow.get("TLS Version", flow.get("tls_version")),
        "ja3_hash": flow.get("JA3_Hash", flow.get("ja3_hash")),
        "ja3_rarity": flow.get("JA3_Rarity", flow.get("ja3_rarity")),
        "domain_entropy": flow.get("Domain_Entropy", flow.get("domain_entropy")),
        "destination_previously_seen": flow.get(
            "Destination_Previously_Seen",
            flow.get("destination_previously_seen"),
        ),
        "repeated_connections": flow.get(
            "Repeated_Connections", flow.get("repeated_connections")
        ),
        "packet_count": flow.get("Packet_Count", flow.get("packet_count")),
        "total_bytes": flow.get("Total_Bytes", flow.get("total_bytes")),
        "bytes_sent": flow.get("Bytes_Sent", flow.get("bytes_sent")),
        "bytes_received": flow.get("Bytes_Received", flow.get("bytes_received")),
        "average_packet_size": flow.get(
            "Average_Packet_Size", flow.get("average_packet_size")
        ),
        "flow_duration": flow.get("Flow_Duration", flow.get("flow_duration")),
        "iat_mean": flow.get("IAT_Mean", flow.get("iat_mean")),
        "cipher_suite_count": flow.get(
            "Cipher_Suite_Count", flow.get("cipher_suite_count")
        ),
        "extension_count": flow.get("Extension_Count", flow.get("extension_count")),
    }
    if prediction:
        raw_values["ml_anomaly_probability"] = prediction.get(
            "Malicious_Probability",
            prediction.get("ml_anomaly_probability"),
        )
        raw_values["ml_confidence"] = prediction.get("Confidence", prediction.get("confidence"))
        raw_values["ml_prediction"] = prediction.get(
            "Prediction", prediction.get("Classification")
        )
    if context:
        raw_values.update(context)

    missing_core_fields = [
        field
        for field, key in _CORE_FLOW_FIELDS.items()
        if _is_missing(flow.get(field, flow.get(key)))
    ]
    evidence = {
        key: value
        for key, value in raw_values.items()
        if not _is_missing(value)
    }
    lines = ["TLS NETWORK INCIDENT"]
    if evidence.get("flow_id") is not None:
        lines.append(f"Flow ID: {evidence['flow_id']}")
    lines.append(
        "Capture context: flow features describe the packets observed in this "
        "capture; the capture may begin or end mid-flow."
    )
    if missing_core_fields:
        lines.append(
            "Partial flow evidence: unavailable core fields were omitted, not "
            f"assumed to be zero ({', '.join(missing_core_fields)})."
        )
    clean_text = " ".join(incident_text.strip().split())[:1200]
    if clean_text:
        lines.append(f"Incident description: {clean_text}")
    lines.extend(
        f"{label}: {evidence[key]}"
        for label, key in _STATE_FIELDS
        if key in evidence
    )
    if not evidence and not clean_text:
        raise ValueError("Incident state must contain a description or evidence.")

    return {
        "incident_text": clean_text,
        "evidence": evidence,
        "missing_core_fields": missing_core_fields,
        "flow_evidence_is_partial": bool(missing_core_fields),
        "decider_state": "\n".join(lines)[:3000],
    }
