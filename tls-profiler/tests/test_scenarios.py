from __future__ import annotations

import json
from pathlib import Path
import unittest

from src.decider_agent.agent import InvestigationAgent
from src.decider_agent.decider_client import DeciderDecision
from src.decider_agent.flow_batch import investigate_flows
from src.decider_agent.decider_client import DeciderUnavailableError


class ScenarioCoverageTests(unittest.TestCase):
    def test_each_scenario_routes_to_its_expected_tool_when_decider_selects_it(self) -> None:
        scenarios = json.loads(
            (Path(__file__).resolve().parents[1] / "scenarios.json").read_text(
                encoding="utf-8"
            )
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario["name"]):
                agent = InvestigationAgent(
                    decider=_ScenarioDecider(scenario["expected_tool"]),
                    bedrock=_ScenarioBedrock(),
                )
                result = agent.investigate(
                    scenario["flow"],
                    scenario.get("prediction"),
                    scenario["description"],
                )
                self.assertEqual(
                    result["decision"]["executed_tool"],
                    scenario["expected_tool"],
                )
                self.assertEqual(
                    result["tool_result"]["tool"],
                    scenario["expected_tool"],
                )

    def test_decider_runs_once_per_flow_and_continues_after_incomplete_or_failed_flow(self) -> None:
        agent = _BatchAgent()
        results = investigate_flows(
            [
                {"Flow_ID": 1, "Destination IP": "203.0.113.1"},
                {"Flow_ID": 2, "Packet_Count": 0},
                {"Flow_ID": 3, "Destination IP": "203.0.113.3"},
            ],
            [{"Flow_ID": 1, "Prediction": "Normal"}],
            agent,
        )
        self.assertEqual(agent.called_flow_ids, [1, 2, 3])
        self.assertEqual([item["flow_id"] for item in results], [1, 2, 3])
        self.assertEqual(results[1]["status"], "decider_error")
        self.assertEqual(results[0]["prediction"], "Normal")
        self.assertEqual(results[2]["status"], "complete")
        self.assertTrue(results[2]["partial_flow_evidence"])

    def test_partial_bedrock_failure_does_not_discard_decider_result(self) -> None:
        results = investigate_flows(
            [{"Flow_ID": 1, "Destination IP": "203.0.113.1"}],
            [],
            _BatchAgentWithExplanationError(),
        )
        self.assertEqual(results[0]["status"], "complete")
        self.assertEqual(results[0]["decision"]["selected_tool"], "flow_analyzer")
        self.assertEqual(
            results[0]["explanation_error"],
            "Bedrock permission denied",
        )


class _BatchAgent:
    def __init__(self) -> None:
        self.called_flow_ids = []

    def investigate(self, flow, prediction, incident_text, context):
        flow_id = flow["Flow_ID"]
        self.called_flow_ids.append(flow_id)
        if flow_id == 2:
            raise DeciderUnavailableError("mock Decider unavailable")
        return {
            "state": {
                "flow_evidence_is_partial": True,
                "missing_core_fields": ["Source IP"],
            },
            "decision": {
                "selected_tool": "flow_analyzer",
                "executed_tool": "flow_analyzer",
                "confidence": 0.8,
                "low_confidence_fallback": False,
            },
            "tool_result": {"tool": "flow_analyzer"},
            "explanation": "Mock explanation.",
            "explanation_error": None,
        }


class _BatchAgentWithExplanationError(_BatchAgent):
    def investigate(self, flow, prediction, incident_text, context):
        result = super().investigate(flow, prediction, incident_text, context)
        result["explanation"] = None
        result["explanation_error"] = "Bedrock permission denied"
        return result


class _ScenarioDecider:
    def __init__(self, choice: str) -> None:
        self.choice = choice

    def decide_tool(self, _state: str) -> DeciderDecision:
        return DeciderDecision(
            choice=self.choice,
            confidence=0.95,
            probabilities={self.choice: 0.95},
            model_latency_ms=100.0,
            request_latency_ms=120.0,
            raw_response={},
        )


class _ScenarioBedrock:
    def explain(self, _state, _decision, _tool_result) -> str:
        return "Mocked explanation for routing coverage."


if __name__ == "__main__":
    unittest.main()
