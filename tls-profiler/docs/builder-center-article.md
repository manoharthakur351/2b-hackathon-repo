# Choosing the next network investigation with Strands Decider 2B

*Draft for Builder Center — verify endpoint/model details and add live measurements before publishing.*

Encrypted network traffic cannot be read as ordinary text, but a connection still exposes metadata: TLS handshake characteristics, a visible SNI hostname when present, packet and byte counts, directionality, and timing. Analysts reviewing these signals must decide what to inspect next. Should they examine the TLS handshake, investigate a hostname, compare the flow's behavior, check a reputation source, or simply monitor?

This project adds an optional per-flow investigation stage to the existing TLSProfiler dashboard. TLSProfiler continues to parse packet captures without decrypting payloads, derive JA3/SNI and flow features, train/evaluate its classifier, and label flows. The added contribution is a typed Decider decision for each selected flow, dynamic action routing, confidence-aware fallback, a per-flow Bedrock explanation, and a reusable decision recipe.

## Separate detection, decision, action, and explanation

The components have distinct jobs:

- **TLSProfiler's classifier:** “What does this traffic look like?”
- **Strands Decider 2B:** “What should the agent do next?”
- **Investigation tool:** inspect the selected kind of evidence.
- **Amazon Bedrock:** explain the evidence and result in concise analyst-facing language.

Keeping these responsibilities separate lets the decision model choose an action without asking a text-generation model to classify every step. Bedrock does not replace or override the Decider choice.

## The decision

The agent sends a concise, bounded incident state to the Strands Decider System One endpoint and asks:

> Which investigation tool should the security agent run next?

The allowed choices are `tls_analyzer`, `dns_analyzer`, `flow_analyzer`, `reputation_checker`, and `allow_and_monitor`. The Decider response includes a choice and calibrated confidence, as well as probabilities and latency when supplied by the endpoint. The agent dynamically looks up that choice in a registry and runs the corresponding tool; this is a control-flow decision, not a display-only prediction.

If confidence is below the configured threshold (default 0.55), the agent records the selected choice but does not execute it. Instead, it executes `allow_and_monitor`, which makes no claim that the traffic is safe. The policy avoids an unbounded retry or Bedrock-Decider loop.

## Walkthrough

Suppose one captured flow yields TLS 1.0, an unusual JA3 indicator, and packet/flow metadata. TLSProfiler continues to process the whole capture using its existing pipeline. In the separate agent tab, the state builder creates a request for this flow only; other flow rows receive independent decisions. It does not send raw packets or combine a whole PCAP into one model request.

Decider chooses `tls_analyzer`. The registry runs the TLS analyzer, which reports only the available handshake metadata and notes that no payload was decrypted. Bedrock then explains the observed deprecated version and handshake evidence, distinguishing those observations from any interpretation. It does not claim the host is malicious from those signals alone.

Other flows in the same capture can select hostname, flow, reputation-provider, or weak-evidence paths. The reputation tool reports that no lookup was made when a provider is not configured; it does not invent threat-intelligence findings. If a capture starts or ends mid-flow, available fields are retained, missing core fields are marked, and processing continues with the next flow.

## Why Bedrock?

The generative task comes after the decision and investigation. Bedrock Converse receives the structured state, selected and executed tool, and tool result. The prompt asks for concise language, evidence/interpretation separation, and calibrated uncertainty. Output tokens are bounded. AWS credentials are obtained through the standard credential chain, preferably an EC2 instance role.

## What we learned

The model boundary should follow the task boundary. Tool selection has a small, typed output space and can use a decision model; generating an explanation needs a language model. Confidence is useful only when it affects behavior, so low confidence routes to a conservative monitoring path. Likewise, tools should say when an evidence source is absent instead of filling gaps with confident-sounding claims.

The existing TLSProfiler work also has clear boundaries: it extracts JA3/SNI and flow statistics, but does not currently provide a DNS transaction history, certificate chain, ALPN, named cipher suites, or destination history. The agent exposes those gaps rather than implying those fields were measured.

## Reusable pattern

The `#tool-selection` recipe includes the typed question, option set and criteria, HTTP wiring, response schema, dynamic registry, and confidence handling. It is designed to be adapted for SOC triage, network monitoring, or incident-response agents. The core rule is to keep the input concise, options bounded, confidence visible, and the selected output connected to actual execution.

## Measurements and limitations

No live Decider or Bedrock endpoint was available during this implementation, so no new end-to-end latency, accuracy, or cost result is claimed here. The project notes report prior warm CPU Decider latency of approximately 2.7–4.5 seconds on the configured EC2 host; that is context supplied for the project, not a measurement of this application's request path. The included scenario evaluator records actual decisions, confidence, model latency (if returned), request latency, and client elapsed time when run against a live endpoint. Its small scenario match rate is not a general accuracy estimate.

The demo scenarios use documentation-only IP addresses and `.test` hostnames. The default reputation provider is intentionally not configured. PCAP analysis remains local; only bounded derived evidence is sent to Bedrock. Real deployment still requires region-appropriate model access, an IAM role with least-privilege inference permissions, and a protected Decider endpoint.

**Submission tags:** #strands-decider-2b #tool-selection
