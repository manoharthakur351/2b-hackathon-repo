# Demo script (target: 2:55)

## 0:00–0:20 — Problem and architecture

“Encrypted traffic still gives us TLS and flow metadata, but analysts must choose what to inspect. TLSProfiler extracts those signals. Strands Decider 2B chooses the next investigation tool, and Bedrock explains the result.”

Show the architecture diagram in the README or architecture document.

## 0:20–0:45 — Incident input

Open the existing TLSProfiler dashboard and point out the PCAP upload / sample capture entry point. Explain that the existing analysis pipeline remains the primary workflow.

## 0:45–1:10 — Evidence

Click **Start Analysis**. Show TLSProfiler's packet, JA3/SNI, flow, and available ML results. The original profiler tabs and reports remain unchanged.

## 1:10–1:40 — Decider decision

Open **Per-Flow Decider Investigation**, choose two or three Flow IDs, and click investigate. Point out the progress/loading indicator. Explain that the application makes one separate typed decision per flow—not one decision per PCAP.

## 1:40–2:05 — Tool execution

Show the selected flow's choice, confidence, probabilities, latency (if present), action result, and Bedrock explanation. Show that another flow gets its own independent outcome. Clarify that payloads are not decrypted and the tool does not conclude maliciousness from one indicator.

## 2:05–2:30 — Bedrock explanation

Show the concise analyst explanation. Describe Bedrock's role as explanation only; it does not replace the Decider's tool choice.

## 2:30–2:55 — Confidence and reuse

Show an incomplete flow result and the reusable `patterns/security_tool_selection.py` recipe. Explain missing fields are marked and processing continues; low confidence routes to `allow_and_monitor`. End with **#strands-decider-2b #tool-selection**.

## Recording notes

- Confirm the Decider endpoint and Bedrock model access before recording. Demonstrate only a small selection of flows because every flow makes separate model requests.
- Do not record AWS credentials, private traffic, internal hostnames, or real reputation API secrets.
- Use the measured timing shown by the app; do not quote the model's advertised latency as a local benchmark.
- Stop before three minutes.
