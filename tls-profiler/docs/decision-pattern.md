# Reusable decision pattern: security tool selection

**Pattern tag: #tool-selection**

## Purpose

Choose the next security investigation action from a short, explicit list using structured incident evidence.

## Typed question and options

The reusable recipe asks:

> Which investigation tool should the security agent run next?

| Option | Use when |
|---|---|
| `tls_analyzer` | TLS version, handshake metadata, JA3, or SNI behavior merits inspection |
| `dns_analyzer` | Hostname/SNI structure or available DNS evidence needs inspection |
| `flow_analyzer` | Volume, directionality, repetition, or timing needs inspection |
| `reputation_checker` | A configured provider can check the destination IP or hostname |
| `allow_and_monitor` | Evidence is insufficient for another action |

Implementation criteria are defined in `src/decider_agent/decider_client.py`. The existing TLSProfiler dashboard integration is in `app.py`; `src/decider_agent/flow_batch.py` iterates independent flow rows and continues past an individual Decider failure.

When a capture truncates a flow, retain available values, identify missing core fields, and state that observed packet metrics may represent a partial flow. Never replace absent information with fabricated values or let one incomplete flow stop the other rows.

## Input and output

Input is one flow's concise state, built from that flow's structured fields and (optionally) its own existing ML label/score. One HTTP request represents one flow. Do not pass a full PCAP, merge multiple flows, send packet payloads, or include unbounded raw logs.

The client returns:

```json
{
  "choice": "tls_analyzer",
  "confidence": 0.87,
  "probabilities": {
    "tls_analyzer": 0.87,
    "flow_analyzer": 0.13
  },
  "model_latency_ms": 117.0,
  "request_latency_ms": 153.2
}
```

The numbers above show the response shape only; they are illustrative, not measured or model output.

## Wiring

`DeciderClient.decide_tool()` sends one System One choice question. `InvestigationAgent` validates the resulting choice, looks up the corresponding function in its tool registry, and runs it. If confidence is below the configured threshold, the agent records the Decider's selected choice but executes `allow_and_monitor` instead.

## Example use

```python
from patterns.security_tool_selection import choose_investigation_tool
from src.decider_agent.decider_client import DeciderClient

state = (
    "TLS NETWORK INCIDENT\n"
    "TLS version: TLS 1.0\n"
    "JA3 rarity: high\n"
    "Packet count: 48\n"
    "ML anomaly probability: 0.81"
)
decision = choose_investigation_tool(DeciderClient(), state)
print(decision.choice, decision.confidence, decision.probabilities)
```

## Reuse guidance

This pattern fits SOC triage, network-monitoring agents, and incident-response assistants. Replace the evidence fields and tool criteria for the target environment, keep the output option set typed and bounded, retain confidence/probabilities, and make sure the selected output controls actual tool execution. Any reputation integration should use a real provider and clearly identify its source.
