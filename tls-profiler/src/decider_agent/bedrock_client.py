"""Amazon Bedrock explanation generation using the Converse API."""

from __future__ import annotations

import json
from typing import Any, Mapping

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .config import BEDROCK_MODEL_ID, BEDROCK_REGION


class BedrockConfigurationError(RuntimeError):
    """Bedrock model configuration or SDK is unavailable."""


class BedrockInvocationError(RuntimeError):
    """Bedrock rejected or failed an explanation request."""


class BedrockExplainer:
    def __init__(self, client: Any, model_id: str) -> None:
        if not model_id.strip():
            raise BedrockConfigurationError(
                "Set BEDROCK_MODEL_ID to a model available in your AWS region."
            )
        self.client = client
        self.model_id = model_id

    @classmethod
    def from_environment(cls) -> "BedrockExplainer":
        if not BEDROCK_MODEL_ID:
            raise BedrockConfigurationError(
                "Set BEDROCK_MODEL_ID before requesting a Bedrock explanation."
            )
        try:
            import boto3
        except ImportError as error:
            raise BedrockConfigurationError(
                "boto3 is required; install the project requirements first."
            ) from error

        try:
            client = boto3.client(
                "bedrock-runtime",
                config=Config(retries={"max_attempts": 5, "mode": "adaptive"}),
                region_name=BEDROCK_REGION or None,
            )
        except BotoCoreError as error:
            raise BedrockConfigurationError(
                "Could not initialize Bedrock credentials/client. If you use "
                "the AWS login credential provider, install the project's "
                "requirements, including botocore[crt]. "
                f"Details: {error}"
            ) from error
        return cls(client, BEDROCK_MODEL_ID)

    def explain(
        self,
        incident_state: Mapping[str, Any],
        decision: Mapping[str, Any],
        tool_result: Mapping[str, Any],
    ) -> str:
        prompt = (
            "Explain this network-security investigation to an analyst in "
            "plain, concise language. Separate observed evidence from "
            "interpretation. Do not claim a domain or IP is malicious unless "
            "the supplied evidence explicitly establishes that. Mention "
            "uncertainty and recommend a proportionate next step.\n\n"
            f"Incident state:\n{json.dumps(incident_state, sort_keys=True, default=str)}\n\n"
            f"Decider decision:\n{json.dumps(decision, sort_keys=True, default=str)}\n\n"
            f"Investigation result:\n{json.dumps(tool_result, sort_keys=True, default=str)}"
        )
        try:
            response = self.client.converse(
                modelId=self.model_id,
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": 450, "temperature": 0.2},
            )
        except (BotoCoreError, ClientError) as error:
            raise BedrockInvocationError(
                f"Bedrock Converse failed: {error}"
            ) from error

        try:
            blocks = response["output"]["message"]["content"]
            text = "\n".join(
                block["text"] for block in blocks if isinstance(block, Mapping) and "text" in block
            ).strip()
        except (KeyError, TypeError) as error:
            raise BedrockInvocationError(
                "Bedrock returned an unexpected Converse response."
            ) from error
        if not text:
            raise BedrockInvocationError("Bedrock returned an empty explanation.")
        return text


class UnconfiguredBedrockExplainer:
    """Lets Decider/tool work finish while exposing missing Bedrock setup."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def explain(
        self,
        incident_state: Mapping[str, Any],
        decision: Mapping[str, Any],
        tool_result: Mapping[str, Any],
    ) -> str:
        raise BedrockConfigurationError(self.reason)


def bedrock_explainer_from_environment() -> (
    BedrockExplainer | UnconfiguredBedrockExplainer
):
    """Keep Bedrock setup errors from blocking Decider and tool execution."""
    if not BEDROCK_MODEL_ID:
        return UnconfiguredBedrockExplainer(
            "BEDROCK_MODEL_ID is not set. The Decider choice and action ran, "
            "but no Bedrock explanation was requested."
        )
    try:
        return BedrockExplainer.from_environment()
    except BedrockConfigurationError as error:
        return UnconfiguredBedrockExplainer(str(error))
