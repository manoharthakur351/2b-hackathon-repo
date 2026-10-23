from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
import requests

from src.decider_agent.agent import InvestigationAgent, default_tool_registry
from src.decider_agent.bedrock_client import (
    BedrockConfigurationError,
    BedrockExplainer,
    BedrockInvocationError,
    UnconfiguredBedrockExplainer,
    bedrock_explainer_from_environment,
)
from src.decider_agent.decider_client import (
    DeciderClient,
    DeciderResponseError,
    DeciderUnavailableError,
    TOOL_OPTIONS,
    build_systemone_request,
    parse_decider_response,
)
from src.decider_agent.state_builder import build_incident_state
from src.decider_agent.tools.dns_analyzer import analyze_dns
from src.decider_agent.tools.flow_analyzer import analyze_flow
from src.decider_agent.tools.monitor import allow_and_monitor
from src.decider_agent.tools.reputation_checker import ReputationChecker
from src.decider_agent.tools.tls_analyzer import analyze_tls


class DeciderClientTests(unittest.TestCase):
    def test_builds_typed_systemone_choice_request(self) -> None:
        request_body = build_systemone_request("TLS version: TLS 1.3")
        self.assertEqual(request_body["state"], "TLS version: TLS 1.3")
        question = request_body["questions"]["tool"]
        self.assertEqual(question["type"], "choice")
        self.assertEqual(set(question["criteria"]), set(TOOL_OPTIONS))

    def test_parses_choice_confidence_probabilities_and_latency(self) -> None:
        decision = parse_decider_response(
            {
                "answers": {
                    "tool": {
                        "choice": "tls_analyzer",
                        "confidence": 0.87,
                        "probabilities": {"tls_analyzer": 0.87, "flow_analyzer": 0.13},
                        "model_latency_ms": 117,
                    }
                }
            },
            request_latency_ms=153,
        )
        self.assertEqual(decision.choice, "tls_analyzer")
        self.assertAlmostEqual(decision.confidence, 0.87)
        self.assertEqual(decision.probabilities["flow_analyzer"], 0.13)
        self.assertEqual(decision.model_latency_ms, 117)
        self.assertEqual(decision.request_latency_ms, 153)

    def test_parses_ec2_systemone_response_with_top_level_latency(self) -> None:
        decision = parse_decider_response(
            {
                "model": "strands-decider-2B-hobson-v19",
                "answers": {
                    "tool": {
                        "type": "choice",
                        "choice": "reputation_checker",
                        "probabilities": {
                            "tls_analyzer": 0.18,
                            "dns_analyzer": 0.15,
                            "flow_analyzer": 0.12,
                            "reputation_checker": 0.55,
                            "allow_and_monitor": 0.0,
                        },
                        "confidence": 0.4,
                    }
                },
                "usage": {},
                "latency_ms": 2800,
            },
            request_latency_ms=2850,
        )
        self.assertEqual(decision.choice, "reputation_checker")
        self.assertEqual(decision.confidence, 0.4)
        self.assertEqual(decision.probabilities["reputation_checker"], 0.55)
        self.assertEqual(decision.model_latency_ms, 2800)
        self.assertEqual(decision.request_latency_ms, 2850)

    def test_invalid_choice_and_missing_confidence_are_rejected(self) -> None:
        with self.assertRaises(DeciderResponseError):
            parse_decider_response({"answers": {"tool": {"choice": "shell"}}})
        with self.assertRaises(DeciderResponseError):
            parse_decider_response({"answers": {"tool": {"choice": "tls_analyzer"}}})
        with self.assertRaises(DeciderResponseError):
            parse_decider_response(
                {
                    "answers": {"tool": {"choice": "tls_analyzer", "confidence": 0.9}},
                    "probabilities": {"tool": {"shell": 0.1}},
                }
            )

    def test_timeout_and_missing_service_are_explicit(self) -> None:
        session = Mock()
        session.post.side_effect = requests.Timeout()
        with self.assertRaises(DeciderUnavailableError):
            DeciderClient(session=session).decide_tool("incident")

        session.post.side_effect = requests.ConnectionError("connection refused")
        with self.assertRaisesRegex(DeciderUnavailableError, "SSH tunnel"):
            DeciderClient(session=session).decide_tool("incident")

    def test_non_json_response_is_rejected(self) -> None:
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("not json")
        session = Mock()
        session.post.return_value = response
        with self.assertRaises(DeciderResponseError):
            DeciderClient(session=session).decide_tool("incident")


class StateBuilderTests(unittest.TestCase):
    def test_creates_concise_state_from_tlsprofiler_features_and_prediction(self) -> None:
        state = build_incident_state(
            {
                "Destination IP": "203.0.113.4",
                "TLS Version": "TLS 1.2",
                "SNI": "example.test",
                "Packet_Count": 8,
                "Total_Bytes": 3400,
                "Flow_Duration": 1.2,
            },
            {"Malicious_Probability": 0.81, "Prediction": "Suspicious"},
            "odd TLS connection",
        )
        self.assertIn("ML anomaly probability: 0.81", state["decider_state"])
        self.assertEqual(state["evidence"]["packet_count"], 8)
        self.assertTrue(state["flow_evidence_is_partial"])
        self.assertIn("Source IP", state["missing_core_fields"])
        self.assertLessEqual(len(state["decider_state"]), 3000)

    def test_incomplete_flow_keeps_available_fields_and_does_not_fail(self) -> None:
        state = build_incident_state(
            {"Flow_ID": 17, "Destination IP": "203.0.113.17", "Packet_Count": 2}
        )
        self.assertEqual(state["evidence"]["flow_id"], 17)
        self.assertEqual(state["evidence"]["destination_ip"], "203.0.113.17")
        self.assertTrue(state["flow_evidence_is_partial"])
        self.assertIn("unavailable core fields were omitted", state["decider_state"])

    def test_rejects_empty_or_malformed_state(self) -> None:
        with self.assertRaises(ValueError):
            build_incident_state({}, incident_text="")
        with self.assertRaises(ValueError):
            build_incident_state([], incident_text="incident")  # type: ignore[arg-type]


class ToolTests(unittest.TestCase):
    def test_each_investigation_tool_returns_typed_output(self) -> None:
        evidence = {
            "tls_version": "TLS 1.0",
            "sni": "random.example.test",
            "domain_entropy": 4.2,
            "packet_count": 100,
            "total_bytes": 20000,
            "destination_ip": "203.0.113.4",
        }
        state = {"evidence": evidence}
        self.assertIn("deprecated", analyze_tls(state)["findings"][0].lower())
        self.assertEqual(analyze_dns(state)["tool"], "dns_analyzer")
        self.assertEqual(analyze_flow(state)["tool"], "flow_analyzer")
        reputation = ReputationChecker()(state)
        self.assertEqual(reputation["status"], "provider_not_configured")
        self.assertIn("No threat-intelligence claim", reputation["summary"])
        self.assertEqual(allow_and_monitor(state)["tool"], "allow_and_monitor")

    def test_reputation_provider_response_is_explicitly_scoped(self) -> None:
        provider = Mock()
        provider.lookup.return_value = {"status": "listed", "source": "test-provider"}
        result = ReputationChecker(provider)({"evidence": {"destination_ip": "203.0.113.8"}})
        provider.lookup.assert_called_once_with("203.0.113.8")
        self.assertEqual(result["status"], "provider_response")


class AgentRoutingTests(unittest.TestCase):
    class FakeDecider:
        def __init__(self, choice: str, confidence: float) -> None:
            self.choice = choice
            self.confidence = confidence

        def decide_tool(self, _state: str):
            from src.decider_agent.decider_client import DeciderDecision

            return DeciderDecision(
                choice=self.choice,
                confidence=self.confidence,
                probabilities={self.choice: self.confidence},
                model_latency_ms=120.0,
                request_latency_ms=140.0,
                raw_response={},
            )

    def test_decider_choice_controls_actual_tool_execution(self) -> None:
        bedrock = Mock()
        bedrock.explain.return_value = "The hostname needs review."
        agent = InvestigationAgent(
            self.FakeDecider("dns_analyzer", 0.9),
            bedrock,
            tool_registry=default_tool_registry(),
        )
        result = agent.investigate(
            {"SNI": "long-random.example.test", "Domain_Entropy": 4.0},
            incident_text="Unexpected domain",
        )
        self.assertEqual(result["decision"]["selected_tool"], "dns_analyzer")
        self.assertEqual(result["decision"]["executed_tool"], "dns_analyzer")
        self.assertEqual(result["tool_result"]["tool"], "dns_analyzer")
        self.assertEqual(result["explanation"], "The hostname needs review.")

    def test_low_confidence_routes_to_monitor_and_bedrock_explains_it(self) -> None:
        bedrock = Mock()
        bedrock.explain.return_value = "Evidence is weak; monitor."
        agent = InvestigationAgent(self.FakeDecider("reputation_checker", 0.4), bedrock)
        result = agent.investigate(
            {"Destination IP": "203.0.113.9"},
            incident_text="Ambiguous connection",
        )
        self.assertEqual(result["decision"]["selected_tool"], "reputation_checker")
        self.assertEqual(result["decision"]["executed_tool"], "allow_and_monitor")
        self.assertTrue(result["decision"]["low_confidence_fallback"])
        self.assertEqual(result["tool_result"]["tool"], "allow_and_monitor")

    def test_bedrock_failure_preserves_decider_choice_and_action(self) -> None:
        bedrock = Mock()
        bedrock.explain.side_effect = BedrockInvocationError("AccessDeniedException")
        agent = InvestigationAgent(self.FakeDecider("flow_analyzer", 0.9), bedrock)
        result = agent.investigate(
            {"Flow_ID": 5, "Packet_Count": 12, "Total_Bytes": 1000},
        )
        self.assertEqual(result["decision"]["executed_tool"], "flow_analyzer")
        self.assertEqual(result["tool_result"]["tool"], "flow_analyzer")
        self.assertIsNone(result["explanation"])
        self.assertIn("AccessDeniedException", result["explanation_error"])


class BedrockTests(unittest.TestCase):
    def test_bedrock_initialization_failure_is_deferred_to_explanation_stage(self) -> None:
        with (
            patch("src.decider_agent.bedrock_client.BEDROCK_MODEL_ID", "test-model"),
            patch.object(
                BedrockExplainer,
                "from_environment",
                side_effect=BedrockConfigurationError(
                    "AWS login provider requires botocore[crt]."
                ),
            ),
        ):
            explainer = bedrock_explainer_from_environment()

        self.assertIsInstance(explainer, UnconfiguredBedrockExplainer)
        agent = InvestigationAgent(
            AgentRoutingTests.FakeDecider("flow_analyzer", 0.9),
            explainer,
        )
        result = agent.investigate(
            {"Flow_ID": 5, "Packet_Count": 12, "Total_Bytes": 1000},
        )
        self.assertEqual(result["decision"]["executed_tool"], "flow_analyzer")
        self.assertEqual(result["tool_result"]["tool"], "flow_analyzer")
        self.assertIn("botocore[crt]", result["explanation_error"])

    def test_uses_converse_with_bounded_output_tokens(self) -> None:
        client = Mock()
        client.converse.return_value = {
            "output": {
                "message": {
                    "content": [{"text": "Observed evidence is inconclusive."}]
                }
            }
        }
        explainer = BedrockExplainer(client, "test-model")
        text = explainer.explain({"evidence": {}}, {"selected_tool": "flow_analyzer"}, {})
        self.assertEqual(text, "Observed evidence is inconclusive.")
        self.assertEqual(client.converse.call_args.kwargs["inferenceConfig"]["maxTokens"], 450)

    def test_bedrock_permission_failure_is_not_hidden(self) -> None:
        client = Mock()
        client.converse.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Not authorized",
                }
            },
            "Converse",
        )
        with self.assertRaises(BedrockInvocationError):
            BedrockExplainer(client, "test-model").explain({}, {}, {})

    def test_missing_bedrock_configuration_is_reported_at_explanation_stage(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "BEDROCK_MODEL_ID"):
            UnconfiguredBedrockExplainer(
                "BEDROCK_MODEL_ID is not set."
            ).explain({}, {}, {})


if __name__ == "__main__":
    unittest.main()
