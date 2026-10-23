"""HTTP client for the Strands Decider System One endpoint."""

from __future__ import annotations

from dataclasses import dataclass
import math
import time
from typing import Any, Mapping

import requests

from .config import DECIDER_TIMEOUT_SECONDS, DECIDER_URL


TOOL_OPTIONS = (
    "tls_analyzer",
    "dns_analyzer",
    "flow_analyzer",
    "reputation_checker",
    "allow_and_monitor",
)

TOOL_CRITERIA = {
    "tls_analyzer": (
        "Analyze TLS handshakes, TLS versions, cipher suites, JA3, ALPN, SNI, "
        "certificates and encrypted connection behavior."
    ),
    "dns_analyzer": (
        "Analyze domains, hostnames, DNS-related behavior, SNI names and "
        "suspicious domain patterns."
    ),
    "flow_analyzer": (
        "Analyze packet counts, byte counts, connection duration, directionality "
        "and repeated network-flow behavior."
    ),
    "reputation_checker": (
        "Check whether an unfamiliar IP, hostname or domain should be "
        "investigated for reputation or threat intelligence."
    ),
    "allow_and_monitor": (
        "Use when evidence is weak and no immediate investigation is justified."
    ),
}


class DeciderError(RuntimeError):
    """Base class for Decider request and response errors."""


class DeciderUnavailableError(DeciderError):
    """The configured Decider endpoint could not be reached or timed out."""


class DeciderResponseError(DeciderError):
    """The Decider returned an invalid or unsupported response."""


@dataclass(frozen=True)
class DeciderDecision:
    choice: str
    confidence: float
    probabilities: dict[str, float]
    model_latency_ms: float | None
    request_latency_ms: float
    raw_response: Mapping[str, Any]


def build_systemone_request(state: str) -> dict[str, Any]:
    """Create the typed choice question for the reusable tool-selection pattern."""
    if not isinstance(state, str) or not state.strip():
        raise ValueError("Decider state must be a non-empty string.")

    return {
        "state": state.strip(),
        "questions": {
            "tool": {
                "type": "choice",
                "instructions": "Which investigation tool should the security agent run next?",
                "criteria": TOOL_CRITERIA,
            }
        },
    }


def _answer_object(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    container: Any = payload.get(
        "answers", payload.get("results", payload.get("response", payload))
    )
    if isinstance(container, Mapping):
        container = container.get(
            "answers", container.get("results", container)
        )
    if isinstance(container, Mapping) and "tool" in container:
        answer = container["tool"]
        if isinstance(answer, Mapping):
            normalized = dict(answer)
        else:
            normalized = {"choice": answer}
    elif isinstance(container, Mapping):
        normalized = dict(container)
    else:
        raise DeciderResponseError("Decider response did not contain a tool answer.")

    for key in (
        "confidence",
        "probabilities",
        "probs",
        "model_latency_ms",
        "latency_ms",
    ):
        if key not in normalized and key in payload:
            normalized[key] = payload[key]

    for key in ("confidence", "probabilities", "probs"):
        value = normalized.get(key)
        if isinstance(value, Mapping) and "tool" in value:
            normalized[key] = value["tool"]
    return normalized


def _probabilities(value: Any) -> dict[str, float]:
    if value is None:
        return {}
    if isinstance(value, list):
        parsed: dict[str, float] = {}
        for item in value:
            if isinstance(item, Mapping):
                name = item.get("choice", item.get("option", item.get("name")))
                score = item.get("probability", item.get("score"))
                if isinstance(name, str) and isinstance(score, (int, float)):
                    parsed[name] = float(score)
        probabilities = parsed
    elif isinstance(value, Mapping):
        if isinstance(value.get("tool"), Mapping):
            value = value["tool"]
        probabilities = {
            str(name): float(score)
            for name, score in value.items()
            if isinstance(score, (int, float)) and not isinstance(score, bool)
        }
    else:
        raise DeciderResponseError("Decider probabilities must be an object or list.")

    if any(
        name not in TOOL_OPTIONS
        or not math.isfinite(score)
        or not 0.0 <= score <= 1.0
        for name, score in probabilities.items()
    ):
        raise DeciderResponseError(
            "Decider probabilities must use allowed options and values in [0, 1]."
        )
    return probabilities


def parse_decider_response(
    payload: Mapping[str, Any],
    request_latency_ms: float = 0.0,
) -> DeciderDecision:
    answer = _answer_object(payload)
    choice = answer.get("choice", answer.get("answer", answer.get("value")))
    if not isinstance(choice, str) or choice not in TOOL_OPTIONS:
        raise DeciderResponseError(f"Decider returned an unsupported choice: {choice!r}.")

    probabilities = _probabilities(
        answer.get("probabilities", answer.get("probs"))
    )
    confidence = answer.get("confidence")
    if confidence is None:
        confidence = probabilities.get(choice)
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(float(confidence))
        or not 0.0 <= float(confidence) <= 1.0
    ):
        raise DeciderResponseError(
            "Decider response must include calibrated confidence in the range [0, 1]."
        )

    model_latency = answer.get(
        "model_latency_ms",
        answer.get(
            "latency_ms",
            payload.get("model_latency_ms", payload.get("latency_ms")),
        ),
    )
    if model_latency is not None and (
        not isinstance(model_latency, (int, float))
        or isinstance(model_latency, bool)
        or not math.isfinite(float(model_latency))
        or model_latency < 0
    ):
        raise DeciderResponseError("Decider model latency must be a non-negative number.")

    return DeciderDecision(
        choice=choice,
        confidence=float(confidence),
        probabilities=probabilities,
        model_latency_ms=float(model_latency) if model_latency is not None else None,
        request_latency_ms=float(request_latency_ms),
        raw_response=payload,
    )


class DeciderClient:
    def __init__(
        self,
        url: str = DECIDER_URL,
        timeout_seconds: float = DECIDER_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Decider timeout must be greater than zero.")
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.session = session or requests.Session()

    def decide_tool(self, state: str) -> DeciderDecision:
        request_body = build_systemone_request(state)
        started = time.perf_counter()
        try:
            response = self.session.post(
                self.url,
                json=request_body,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.Timeout as error:
            raise DeciderUnavailableError(
                f"Decider request timed out after {self.timeout_seconds:g}s at "
                f"{self.url}. If this is the local EC2 tunnel endpoint, verify "
                "the SSH tunnel is active."
            ) from error
        except requests.ConnectionError as error:
            raise DeciderUnavailableError(
                f"Decider unavailable at {self.url}. This localhost port is "
                "expected to be forwarded through your SSH tunnel to EC2. "
                "Start the tunnel and verify it with curl; do not expose "
                "port 8099 publicly."
            ) from error
        except requests.HTTPError as error:
            status_code = (
                error.response.status_code
                if error.response is not None
                else "unknown"
            )
            raise DeciderUnavailableError(
                f"Decider at {self.url} returned HTTP {status_code}."
            ) from error
        except requests.RequestException as error:
            raise DeciderUnavailableError(
                f"Could not call Decider at {self.url}: {error}"
            ) from error

        request_latency_ms = (time.perf_counter() - started) * 1000
        try:
            payload = response.json()
        except ValueError as error:
            raise DeciderResponseError("Decider response was not valid JSON.") from error
        if not isinstance(payload, Mapping):
            raise DeciderResponseError("Decider response must be a JSON object.")

        decision = parse_decider_response(payload, request_latency_ms)
        return decision
