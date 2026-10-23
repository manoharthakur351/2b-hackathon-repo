# TLSProfiler + Strands Decider project handoff

This is the current project status and next-step checklist for the project
owner and any AI coding agent continuing work. Do not put credentials, tokens,
private-key paths, or other secrets in this file.

## Project summary

TLSProfiler is the existing Streamlit application in this directory. Its
original workflow must remain intact:

1. PCAP/PCAPNG upload or sample-capture selection
2. Packet parsing
3. TLS/JA3/SNI feature extraction
4. Per-flow feature creation
5. Existing classifier prediction and flow labeling
6. Original dashboard charts, tables, and reports

The additive **Per-Flow Decider Investigation** tab sends one bounded
structured request per selected flow to Strands Decider 2B, executes the
selected registered investigation tool, then asks Amazon Bedrock Converse for
a human-readable explanation. It never sends raw PCAP bytes or makes one
decision for the whole capture. Partial flow evidence is allowed; unavailable
values are omitted and identified. A failure for one flow does not erase the
TLSProfiler results or stop other flows.

Decider choices: `tls_analyzer`, `dns_analyzer`, `flow_analyzer`,
`reputation_checker`, and `allow_and_monitor`. Below the default confidence
threshold (`0.55`), the app records the choice but runs `allow_and_monitor`.
The configured Decider HTTP timeout defaults to 20 seconds.

## Current architecture and endpoints

- Existing app entry point: `app.py` in this directory; do not create a second
  Streamlit app.
- Decider System One endpoint: `http://127.0.0.1:8099/v1/systemone`.
- EC2 Decider is private and listens on EC2 loopback. Never bind it publicly
  or open port 8099 to the internet.
- For local development, SSH local forwarding maps the workstation's
  `127.0.0.1:8099` to EC2's `127.0.0.1:8099`.
- Preferred demo/deployment: run Streamlit on the same EC2 instance as the
  Decider. The app then calls the Decider over EC2 loopback and needs no
  Decider SSH tunnel. Use an EC2 IAM instance role for Bedrock access, scoped
  to the needed `bedrock:InvokeModel` resource. A separate secure access path
  is still needed for a remote browser to view Streamlit.
- Bedrock model ID and region are loaded from the ignored local
  `tls-profiler/.env` at app startup (`python-dotenv`). Do not commit that
  file or put AWS keys in it. AWS credentials must be supplied separately
  through the AWS credential chain.

## Project owner next steps

- [ ] **Refresh local AWS login credentials** before testing Bedrock locally.
  The latest browser test completed the Decider choice and action, but Bedrock
  returned: “Your session has expired or credentials have changed. Please
  reauthenticate using `aws login`.” `.env` preserves the model ID and region;
  it does not preserve AWS login credentials.
- [ ] For a reliable hackathon demo, deploy/run Streamlit on the same EC2 host
  as Decider and attach an IAM instance role for Bedrock. This removes the
  local-to-EC2 Decider tunnel and avoids recurring local AWS login sessions.
- [ ] Keep the Decider private on EC2 loopback. Do not create an inbound public
  rule for port 8099.
- [ ] Test one flow end-to-end after refreshing local credentials or after
  configuring the EC2 role. Confirm the existing TLSProfiler prediction,
  Decider choice, selected action, and Bedrock explanation all display.
- [ ] Before submission, publish the Builder Center article and public
  repository, record a public demo under three minutes, and include
  `#strands-decider-2b` and `#tool-selection`.

## AI coding agent handoff

- [x] Preserve the original profiler pipeline and integrate into its existing
  Streamlit app.
- [x] Implement per-flow state construction, including available ML
  prediction, and preserve partial evidence without fabricating fields.
- [x] Implement typed System One client parsing choice, confidence,
  probabilities, model latency, and total request latency.
- [x] Route the actual selected choice through the investigation tool registry;
  apply the bounded low-confidence fallback.
- [x] Isolate failures by flow and preserve completed Decider/tool results if
  Bedrock setup or invocation fails.
- [x] Load model ID, region, and service settings from the ignored project
  `.env`; provide configuration template and documentation.
- [x] Add `botocore[crt]` for the AWS login credential provider. Its earlier
  missing-dependency exception is resolved.
- [x] Verify local tunnel + live Decider request, UI per-flow routing, and the
  original sample capture pipeline.
- [ ] Do not modify or stop the EC2 systemd Decider server unless explicitly
  requested. Do not expose it publicly.
- [ ] Keep future modifications surgical and rerun the targeted tests.

## Last verified status (2026-10-22)

- All 22 tests passed; Python compilation succeeded.
- Sample `reddit.pcap`: 3,886 IP packets, 216 TLS records, 18 flows, and 18
  predictions.
- A live browser flow reached the EC2 Decider, executed `tls_analyzer`, and
  retained the TLSProfiler label.
- `botocore[crt]` is installed and Bedrock runtime client initialization
  succeeds. The latest live Bedrock invocation did not complete because local
  AWS login credentials had expired/changed; this is an authentication-session
  issue, not a missing model ID or missing EC2 instance.
- Local project `.env` exists, is Git-ignored, and has owner-only permissions.
  Its secret/configuration values are intentionally not copied into this
  handoff.
- Local Streamlit server on port 8765 and local SSH tunnel on port 8099 were
  stopped at the project owner's request. The EC2 Decider itself was not
  stopped.

## Common commands

Run Streamlit locally from this directory:

```bash
../.venv/bin/python -m streamlit run app.py \
  --server.address 127.0.0.1 --server.port 8765
```

For local development, start the local SSH forward in a separate terminal
using the owner's private key and EC2 hostname:

```bash
ssh -i <path-to-key.pem> \
  -L 8099:127.0.0.1:8099 \
  ubuntu@<EC2_PUBLIC_HOSTNAME>
```

Check that forwarding reaches the API with a GET (405 is expected because the
API accepts POST):

```bash
curl -i --max-time 15 http://127.0.0.1:8099/v1/systemone
```

To run focused tests from this directory:

```bash
../.venv/bin/python -m unittest discover -s tests -v
```
