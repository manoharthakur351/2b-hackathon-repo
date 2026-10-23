"""Network investigation agent using Strands Decider 2B and Amazon Bedrock."""

from .agent import InvestigationAgent
from .flow_batch import investigate_flows

__all__ = ["InvestigationAgent", "investigate_flows"]
