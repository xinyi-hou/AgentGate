# Open-Source Design Sources

AgentGate adapts implementation patterns from established open-source security and observability
projects, but narrows them to structured tool calls. These are design references, not bundled
dependencies or claims of behavioral equivalence.

| Project | Pattern adopted | AgentGate boundary |
| --- | --- | --- |
| [ToolHive](https://github.com/stacklok/toolhive) | MCP transport proxy and middleware placement | Current MCP adapter normalizes `tools/list` and `tools/call`; it is not yet a transparent STDIO/HTTP proxy |
| [Snyk agent-scan](https://github.com/snyk/agent-scan) | Automatic discovery and inspection of agent/MCP tool metadata | AgentGate automatically derives capability profiles; it additionally mediates runtime calls |
| [Invariant Gateway](https://github.com/invariantlabs-ai/invariant-gateway) | Gateway insertion without rewriting each application tool | AgentGate exposes in-process adapters and a sidecar, both sharing one security kernel |
| [OpenTelemetry Python](https://opentelemetry.io/docs/zero-code/python/) | Runtime instrumentation as a low-touch integration pattern | Instrumentation is useful for adapter injection, but telemetry alone is not an enforcement point |
| [OpenInference](https://github.com/Arize-ai/openinference) | Cross-framework semantic conventions for tool spans | AgentGate reuses the normalization idea but stores security events rather than full model traces |
| [OPA Envoy plugin](https://github.com/open-policy-agent/opa-envoy-plugin) | Context-aware external authorization at a proxy boundary | AgentGate currently uses a local policy engine; an external policy backend is future work |
| [Microsoft Presidio](https://github.com/microsoft/presidio) | Pluggable deterministic sensitive-data recognizers and redaction | AgentGate uses a smaller field taxonomy and digest provenance; detection is intentionally incomplete |

The MCP tool declaration fields follow the protocol's `name`, `description`, `inputSchema`, optional
`outputSchema`, and `annotations` structure. Annotations are retained as evidence but are not trusted
as authorization contracts. Capability inference records its source, confidence, evidence, and
structural/semantic hashes so an explicit administrator profile can override ambiguous automation.

The content scanner follows an event-condition-action split: it extracts bounded findings, and the
runtime chooses registration rejection or field sanitization. The task authorizer follows an
external-authorization split: a compiler creates a bounded contract, parameter binding creates the
actual call effect, and a deterministic engine checks six dimensions. Provenance state follows a
taint/DLP split: sensitive plaintext is not retained, field objects carry one-way signatures and
parent identifiers, and sequence policy decides whether a matched flow is forbidden.
