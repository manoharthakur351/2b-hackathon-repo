# Hosting TLSProfiler on Amazon EC2

This guide compares practical ways to run the existing TLSProfiler Streamlit
app on EC2, with the current Strands Decider 2B service and Amazon Bedrock
integration in mind. It describes deployment options; it does not deploy or
change any AWS resources.

## Your app's deployment constraints

- The existing Streamlit entry point is `app.py` in this directory. Keep the
  existing PCAP parsing, TLS extraction, flow generation, classifier, labels,
  and dashboard intact.
- The optional investigation tab calls Decider once for each selected flow at
  `http://127.0.0.1:8099/v1/systemone`.
- Decider currently runs on an EC2 host, bound to that host's loopback
  interface. **Do not bind it to `0.0.0.0`, add a public inbound rule for 8099,
  or make it internet-accessible.**
- Bedrock is called by the app using the AWS SDK credential chain. On EC2,
  use an attached least-privilege IAM instance role rather than saved AWS
  access keys or repeated interactive `aws login`.
- The app writes uploaded captures and analysis outputs under `captures/` and
  `output/` relative to its working directory. The service account must be
  able to write those directories. Treat captures and generated output as
  potentially sensitive.
- The current PCAP parser uses Scapy `rdpcap`, which loads the capture into
  memory. Large PCAPs can therefore create significant RAM pressure. An
  earlier EC2 status snapshot showed 82% memory use and 39% swap use; that is
  historical, not a live measurement, but check current capacity before
  co-hosting another service.
- Streamlit does not provide a complete public-user authentication system by
  itself. Do not expose an unauthenticated app to the internet.

## First decision: runtime and browser access are separate

There are two independent choices:

1. **How the app process runs:** foreground command, `systemd`, or a container.
2. **How your browser reaches it:** SSH/SSM port forwarding for private use, or
   an authenticated HTTPS reverse proxy/load balancer for remote users.

For a hackathon demo, the simplest secure combination is **native Python under
`systemd` on the same EC2 instance as Decider, with browser access through SSM
port forwarding or an SSH tunnel**. Decider remains on loopback, so no
app-to-Decider SSH tunnel is needed.

## Option 1: Run Streamlit in a terminal

### How it works

Connect to the EC2 instance and start Streamlit manually. Bind the dashboard
to loopback, then forward a local browser port over SSH or SSM.

```text
Browser on your computer
    -> local port 8501
    -> SSH/SSM port forwarding
    -> EC2 127.0.0.1:8501 (Streamlit)
    -> EC2 127.0.0.1:8099 (Decider)
```

Example from the EC2 project directory:

```bash
source ../.venv/bin/activate
export DECIDER_API_URL=http://127.0.0.1:8099/v1/systemone
streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

On your computer, use a second terminal:

```bash
ssh -i <path-to-key.pem> \
  -L 8501:127.0.0.1:8501 \
  ubuntu@<EC2_PUBLIC_HOSTNAME>
```

Then browse to `http://127.0.0.1:8501`. Keep the SSH session open.

**Advantages:** quickest way to test; dashboard and Decider can communicate
over EC2 loopback; no public dashboard port is required.

**Disadvantages:** closing the terminal or disconnecting can stop the app;
there is no automatic restart; logs are only in that terminal.

**Best for:** initial setup and short-lived, single-person tests—not a
dependable always-on demo.

## Option 2: Native Python managed by systemd (recommended)

### How it works

Install the project in a Python virtual environment and run Streamlit as a
Linux service. `systemd` starts it at boot, restarts it after a process failure,
and collects logs. Keep the app on the same host as Decider.

```text
EC2 systemd
    -> Streamlit on 127.0.0.1:8501
    -> Decider on 127.0.0.1:8099
    -> Bedrock using the EC2 instance role
```

### Setup outline

1. Use the existing EC2 instance that runs Decider, or provision a suitable
   Ubuntu EC2 instance and install the existing Decider service there. Avoid
   running both services on separate machines unless you intentionally design
   a private network path for the Decider API.
   Before choosing the same instance, inspect current `free -h`, `df -h`,
   CloudWatch CPU/memory metrics if available, and Decider memory usage while
   idle and during inference. If the host has little RAM headroom, first
   consider a larger compatible instance; a separate app instance is also
   possible, but requires a deliberate private Decider network design (see
   Option 7).
2. Transfer the project source through your private Git repository or another
   secure method. Do not transfer the local `.env` file, PEM files, AWS keys,
   local virtual environments, caches, or unrelated PCAPs. Create the
   instance's configuration file separately, without AWS access keys.
3. Install Python and create a venv. From the project root (the parent folder
   containing both `requirements.txt` and `tls-profiler/`):

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

4. Create `tls-profiler/.env` on the instance with the Bedrock model ID,
   region, and any intended app settings. Set restrictive file permissions.
   Do **not** put AWS access keys in it. The app loads this file at startup.
   The default Decider endpoint already uses EC2 localhost.
5. Attach an EC2 IAM role that grants only the Bedrock invocation permission
   required for the selected model/inference profile, and configure the
   appropriate AWS region. Verify the model is enabled in that region.
6. Ensure the service user owns or can write `tls-profiler/captures/` and
   `tls-profiler/output/`. Keep durable captures only as long as needed and
   set an explicit retention/backup policy.
7. Create a service unit. Replace the paths and account with the actual
   deployment paths/user:

   ```ini
   # /etc/systemd/system/tls-profiler.service
   [Unit]
   Description=TLSProfiler Streamlit application
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   User=tlsprofiler
   Group=tlsprofiler
   WorkingDirectory=/opt/tls-profiler-project/tls-profiler
   ExecStart=/opt/tls-profiler-project/.venv/bin/streamlit run app.py --server.address 127.0.0.1 --server.port 8501
   Restart=on-failure
   RestartSec=5
   Environment=PYTHONUNBUFFERED=1

   [Install]
   WantedBy=multi-user.target
   ```

   `WorkingDirectory` matters: the app uses project-relative paths such as
   `captures/` and `output/`. Since the app loads its `.env` from the
   `tls-profiler` project directory, keep that file there and readable only by
   the service owner.
8. Enable and inspect the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now tls-profiler
   sudo systemctl status tls-profiler
   sudo journalctl -u tls-profiler -f
   ```

9. Keep Streamlit bound to `127.0.0.1`. Reach it using one of the private
   access methods below.

**Advantages:** reliable restart/boot behavior; no extra container layer;
direct localhost connectivity to Decider; simplest way to use an EC2 IAM role.

**Disadvantages:** the Python environment and OS need normal patching; a
single instance is a single point of failure; deployment/rollback is manual
unless you automate it.

**Best for:** your current project and a reliable personal/hackathon demo.

## Option 3: Docker or Docker Compose on EC2

### How it works

Package the app and its Python dependencies into an image, then run the
container on EC2. Compose can manage the app and supporting services.

**Important Decider networking detail:** inside a normal bridge-networked
container, `127.0.0.1` means the container itself—not the EC2 host. Therefore
the current Decider URL will not reach a Decider process running on the host.
Do not fix this by exposing port 8099 publicly. A container design must
explicitly preserve private access, for example by using host networking with
appropriate tradeoffs or by placing both services on a private container
network and keeping the Decider inaccessible from outside the host. Test this
carefully before choosing Docker.

The app container also needs a writable persistent location for uploads and
results. Mount only the necessary project data directories or a dedicated
EBS-backed path; do not bake `.env`, AWS credentials, or PCAP datasets into
the image. For Bedrock access, use the EC2 instance role through the AWS
credential chain. With bridge networking and IMDSv2, configure the container
metadata hop limit appropriately (commonly 2) if the container must obtain
role credentials from EC2 metadata.

**Advantages:** reproducible runtime; clean dependency isolation; easier to
move the app between hosts; useful if you already use containers.

**Disadvantages:** extra build/release and persistent-storage work; the
localhost Decider assumption needs an explicit network solution; careless
container metadata settings can break IAM role credentials.

**Best for:** a team or deployment pipeline already based on Docker. For this
project's first EC2 demo, native `systemd` is simpler.

## Option 4: Keep the dashboard private with SSM or SSH port forwarding

This is an **access method** that works with either native `systemd` or
Docker. The Streamlit process remains reachable only on the EC2 host.

### SSH local forwarding

From your workstation:

```bash
ssh -i <path-to-key.pem> \
  -L 8501:127.0.0.1:8501 \
  ubuntu@<EC2_PUBLIC_HOSTNAME>
```

Open `http://127.0.0.1:8501` locally. Port 8501 does not need an inbound
security-group rule. Restrict SSH (port 22) to your trusted IP address if you
use it; do not expose Decider port 8099.

### AWS Systems Manager Session Manager port forwarding

If the instance is configured as an SSM managed node, use port forwarding
without an inbound SSH rule or a private SSH key:

```bash
aws ssm start-session \
  --target <instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8501"],"localPortNumber":["8501"]}'
```

Open `http://127.0.0.1:8501` locally while the SSM session is active. This
requires SSM Agent, an instance role or Default Host Management Configuration,
and a network path from the instance to Systems Manager endpoints.

**Advantages:** private dashboard; ideal for one owner/demo operator; no
public Streamlit listener.

**Disadvantages:** an access session must remain active; not suitable for a
public audience or unattended users.

**Best for:** your current demo while avoiding an unauthenticated public app.

## Option 5: Nginx reverse proxy on the EC2 instance

### How it works

Nginx accepts browser traffic on HTTPS and proxies requests to Streamlit on
`127.0.0.1:8501`. It can terminate TLS with a domain certificate. Configure
proxy headers and WebSocket upgrade forwarding because Streamlit uses
WebSockets.

```text
Browser --HTTPS--> Nginx :443 --> Streamlit 127.0.0.1:8501
                                      |
                                      +--> Decider 127.0.0.1:8099
```

The security group would allow only the intended HTTPS ingress. Do not open
ports 8501 or 8099 to the internet. If using a public hostname, obtain and
renew a valid certificate, patch Nginx, and add an authentication layer before
allowing access. TLS encryption alone does **not** authenticate users.

**Advantages:** one EC2 instance and one public endpoint; HTTPS/domain support;
Streamlit itself can remain on loopback.

**Disadvantages:** you must maintain the proxy, TLS renewal, authentication,
WebSocket proxy behavior, and OS firewall/security-group rules. A single host
has no high availability.

**Best for:** a small, controlled audience when you need a stable HTTPS
dashboard URL and can manage authentication and patching.

## Option 6: Application Load Balancer (ALB) with HTTPS

### How it works

An internet-facing ALB terminates HTTPS using an ACM certificate, then routes
requests to Streamlit on the EC2 instance. The instance should be in private
subnets when practical; its security group should accept the target port only
from the ALB's security group. Add ALB authentication (for example, an
appropriate OIDC/Cognito setup) before exposing the application to users.

```text
Browser --HTTPS--> ALB + certificate/authentication
                         |
                         +--> EC2 Streamlit target
                                  +--> Decider on EC2 loopback
                                  +--> Bedrock via instance role
```

For an ALB to reach Streamlit, Streamlit must listen on an address reachable
from the ALB (typically the EC2 private interface), rather than only
`127.0.0.1`. Restrict the EC2 security group so only the ALB can reach that
target port; never allow public direct access to the Streamlit port. Decider
must remain on `127.0.0.1:8099` and must not be an ALB target.

**Advantages:** managed HTTPS endpoint, ACM certificate lifecycle, and a
cleaner place to add authentication and future scaling.

**Disadvantages:** more AWS resources and configuration; ALB hourly and
capacity charges apply; a single EC2 target is still a single app host.

**Best for:** a demo or app that needs a stable internet-facing URL with
managed HTTPS and controlled users. This is usually unnecessary for a solo
hackathon demo.

## Option 7: Put the app on a separate EC2 instance

This can separate app CPU/memory and patching from Decider, but the current
Decider service binds to its own machine's `127.0.0.1`. `127.0.0.1` on the app
instance will refer to the app instance, not the Decider instance. A normal
private IP address on the Decider host also cannot reach a service that only
listens on loopback.

To use separate instances, you would need to deliberately design a private
VPC-only service path (for example, a tightly restricted private listener or
host-side proxy), along with security-group rules allowing only the app
instance. That changes the current loopback-only network design and should be
reviewed and tested; **do not expose 8099 publicly**. Bedrock would use the
app instance's IAM role. This split also adds instance cost and operational
complexity.

**Best for:** a later multi-user/production architecture where the app and
decision service need independent scaling—not the simplest route for the
current project.

## Comparison

| Method | App survives logout/reboot? | Browser access | Decider localhost works as-is? | Complexity | Fit here |
|---|---:|---|---:|---:|---|
| Foreground Streamlit | No / no | SSH or SSM tunnel | Yes, on same EC2 host | Low | Quick test |
| Native `systemd` | Yes / yes | SSH or SSM tunnel | Yes, on same EC2 host | Low | **Recommended** |
| Docker on EC2 | Yes, if restart policy is set | SSH/SSM, proxy, or ALB | Not automatically on bridge network | Medium | If already using Docker |
| `systemd` + Nginx | Yes / yes | HTTPS via domain | Yes, same EC2 host | Medium | Small controlled audience |
| `systemd` + ALB | Yes / yes | HTTPS via ALB | Yes, same EC2 host | Higher | Stable remote/public URL |
| App and Decider on separate EC2 | Yes / yes | Any of the above | No; private network design needed | Higher | Future scaling |

## Recommended rollout for this project

1. **Start with native Python and `systemd` on the existing Decider EC2
   instance.** It preserves the loopback-only Decider endpoint and avoids an
   SSH tunnel between the app and Decider, provided the host has enough RAM
   headroom for both Decider inference and PCAP parsing.
2. **Use the EC2 instance role for Bedrock.** Grant only the invocation action
   for the selected model/profile. Keep `BEDROCK_MODEL_ID` and region as
   configuration; never store access keys in `.env`.
3. **Initially keep Streamlit on `127.0.0.1:8501`.** Access it over SSM
   port-forwarding (preferred if SSM is already configured) or an SSH local
   forward. Do not add inbound rules for 8501 or 8099.
4. Transfer only required code and model artifacts. Ensure any model files
   required for the original TLSProfiler classifier exist at the expected
   paths; the public-ready source may not include local training data/artifacts.
5. Test the original PCAP pipeline first, then test one selected flow through
   Decider and Bedrock. Review service logs with `journalctl`, and verify the
   app restarts after an EC2 reboot.
6. If you later need a shareable browser URL, add HTTPS and authentication
   using Nginx or an ALB. Keep the Decider endpoint private throughout.

## Operational and security checklist

- [ ] Streamlit and Decider run on the same EC2 instance for the simple
  loopback architecture.
- [ ] Decider listens only on `127.0.0.1:8099`; no security-group ingress
  exists for port 8099.
- [ ] No unauthenticated public access to Streamlit.
- [ ] Use an IAM instance role for Bedrock; no AWS access keys in source,
  `.env`, user data, Docker images, or service files.
- [ ] `.env` is readable only by the app's service account and is not in Git.
- [ ] Uploaded PCAPs and generated output have an explicit access and
  retention policy; EBS is encrypted and sized for expected captures.
- [ ] Service runs as a dedicated non-root Linux account and restarts on
  failure.
- [ ] Streamlit, Python dependencies, the OS, and any reverse proxy are kept
  updated.
- [ ] If making the dashboard remotely accessible, use HTTPS and
  authentication, and restrict target-port access to the reverse proxy/ALB.
- [ ] Check current EC2 instance, EBS, public IPv4, and load-balancer pricing
  for the selected Region before deployment; this guide does not estimate
  your bill.

## More project context

See the [project README](../README.md) for local setup, the [architecture
overview](architecture.md), and the [task handoff](../tasks.md) for the latest
verification and project status.
