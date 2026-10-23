"""Measure Decider choices against documented human expectations."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from src.decider_agent.config import DECIDER_URL
from src.decider_agent.decider_client import DeciderClient
from src.decider_agent.state_builder import build_incident_state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scenarios",
        default=str(Path(__file__).resolve().parents[1] / "scenarios.json"),
    )
    parser.add_argument("--output", help="Optional path to save measured results as JSON.")
    args = parser.parse_args()

    scenarios = json.loads(Path(args.scenarios).read_text(encoding="utf-8"))
    client = DeciderClient()
    results = []
    for scenario in scenarios:
        state = build_incident_state(
            scenario["flow"],
            scenario.get("prediction"),
            scenario["description"],
        )
        started = time.perf_counter()
        decision = client.decide_tool(state["decider_state"])
        total_ms = (time.perf_counter() - started) * 1000
        results.append(
            {
                "scenario": scenario["name"],
                "expected_tool": scenario["expected_tool"],
                "selected_tool": decision.choice,
                "confidence": decision.confidence,
                "probabilities": decision.probabilities,
                "model_latency_ms": decision.model_latency_ms,
                "request_latency_ms": decision.request_latency_ms,
                "client_total_latency_ms": total_ms,
                "matches_expected": decision.choice == scenario["expected_tool"],
            }
        )

    correct = sum(result["matches_expected"] for result in results)
    report = {
        "decider_url": DECIDER_URL,
        "scenarios": results,
        "observed_match_count": correct,
        "scenario_count": len(results),
        "observed_match_rate": correct / len(results) if results else None,
        "note": "This is a small scenario check, not a general accuracy estimate.",
    }
    output = json.dumps(report, indent=2)
    print(output)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
