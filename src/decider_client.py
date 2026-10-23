import os
import time
import requests


DECIDER_URL = os.getenv(
    "DECIDER_API_URL",
    "http://127.0.0.1:8099/v1/systemone"
)


def choose_tool(state: str):
    payload = {
        "state": state,
        "questions": {
            "tool": {
                "type": "choice",
                "instructions": "Which investigation tool should the security agent run next?",
                "criteria": {
                    "tls_analyzer": (
                        "Analyze TLS handshakes, certificates, TLS versions, "
                        "cipher suites, JA3 fingerprints, ALPN and SNI behavior."
                    ),
                    "dns_analyzer": (
                        "Analyze domains, hostnames, DNS queries, SNI names "
                        "and suspicious domain behavior."
                    ),
                    "flow_analyzer": (
                        "Analyze packet counts, byte counts, flow duration, "
                        "directionality and repeated connections."
                    ),
                    "reputation_checker": (
                        "Check whether an IP address, hostname or domain "
                        "has suspicious or malicious reputation."
                    ),
                    "allow_and_monitor": (
                        "Use when evidence is weak and no immediate investigation "
                        "action is justified."
                    )
                }
            }
        }
    }

    start = time.perf_counter()

    response = requests.post(
        DECIDER_URL,
        json=payload,
        timeout=30
    )

    elapsed_ms = (time.perf_counter() - start) * 1000

    response.raise_for_status()

    data = response.json()
    decision = data["answers"]["tool"]

    return {
        "choice": decision["choice"],
        "confidence": decision["confidence"],
        "probabilities": decision["probabilities"],
        "model_latency_ms": data.get("latency_ms"),
        "request_latency_ms": round(elapsed_ms, 2)
    }
