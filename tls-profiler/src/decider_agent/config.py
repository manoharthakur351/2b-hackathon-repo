"""Environment-backed configuration for the investigation agent."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_project_environment(project_root: Path = PROJECT_ROOT) -> None:
    load_dotenv(project_root / ".env", override=False)


load_project_environment()


DECIDER_URL = os.getenv(
    "DECIDER_API_URL",
    os.getenv("DECIDER_URL", "http://127.0.0.1:8099/v1/systemone"),
)
DECIDER_TIMEOUT_SECONDS = float(os.getenv("DECIDER_TIMEOUT_SECONDS", "20"))
DECIDER_CONFIDENCE_THRESHOLD = float(
    os.getenv("DECIDER_CONFIDENCE_THRESHOLD", "0.55")
)
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "").strip()
BEDROCK_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "")).strip()
