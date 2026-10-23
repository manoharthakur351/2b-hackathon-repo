"""Run an independent Decider investigation for each selected flow."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Mapping, Sequence

from .agent import InvestigationAgent
from .decider_client import DeciderError


def investigate_flows(
    flows: Sequence[Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    agent: InvestigationAgent,
    progress_callback: Callable[[int, int, Any], None] | None = None,
) -> list[dict[str, Any]]:
    """Investigate each flow independently and continue when one flow is incomplete.

    A Decider failure is recorded against that flow so the remaining flow
    records can still be processed. A Bedrock failure is retained separately
    from the completed decision and action.
    """
    predictions_by_id = {
        str(row.get("Flow_ID")): row
        for row in predictions
        if row.get("Flow_ID") is not None
    }
    results: list[dict[str, Any]] = []

    total = len(flows)
    for index, flow in enumerate(flows, start=1):
        flow_id = flow.get("Flow_ID", flow.get("flow_id"))
        prediction = predictions_by_id.get(str(flow_id), {})
        try:
            result = agent.investigate(
                flow=flow,
                prediction=prediction,
                incident_text=(
                    f"Investigate flow {flow_id}. Treat the capture as a "
                    "packet observation that may include only part of the flow."
                ),
                context={"flow_id": flow_id},
            )
        except (DeciderError, ValueError) as error:
            result_record = {
                "flow_id": flow_id,
                "status": (
                    "decider_error" if isinstance(error, DeciderError) else "flow_error"
                ),
                "error": str(error),
                "prediction": prediction.get(
                    "Prediction", prediction.get("Classification", "Unavailable")
                ),
            }
        else:
            result_record = {
                "flow_id": flow_id,
                "status": "complete",
                "prediction": prediction.get(
                    "Prediction", prediction.get("Classification", "Unavailable")
                ),
                "partial_flow_evidence": result["state"]["flow_evidence_is_partial"],
                "missing_core_fields": result["state"]["missing_core_fields"],
                "decision": result["decision"],
                "tool_result": result["tool_result"],
                "explanation": result["explanation"],
                "explanation_error": result["explanation_error"],
            }
        results.append(result_record)
        if progress_callback is not None:
            progress_callback(index, total, flow_id)
    return results
