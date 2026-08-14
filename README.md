<p align="center">
  <img src="docs/logo.svg" width="200" alt="Aegis Logo" />
</p>

# Aegis

**Network egress control and runtime attestation for AI agent ecosystems.**

Aegis is the enforcement layer of the agent governance ecosystem. It ensures
agents can only reach authorized destinations, verifies agent runtime integrity,
and enforces data residency policies at the network level.

## Role in the Ecosystem

```
Hive          Patroclus       Relay          Miser        Sentiel        Aegis
─────         ─────────       ─────          ─────        ───────        ─────
Agent         Authz           MCP Proxy      Cost         Observability  Network
Runtime       Infrastructure  & Tool         Optimization & DLP          Enforcement
& Orchestration                Gateway                    & Compliance   & Attestation
```

Aegis answers:
- "Is this agent making unauthorized network calls?"
- "Has the agent's runtime been tampered with?"
- "Is data being sent to a non-compliant region?"
- "Can an agent bypass Relay and call external APIs directly?"

## Capabilities

### Network Egress Control
- HTTP/HTTPS proxy that intercepts all outbound agent traffic
- Allowlist/denylist of destinations per agent
- Block direct calls to external APIs (force traffic through Relay)
- Log all network requests for audit

### Runtime Attestation
- Verify agent process identity (PID, binary hash, start time)
- Detect process tampering (hash mismatch, unexpected restart)
- Bind agent identity to Patroclus agent registration
- Attestation tokens for cryptographic verification

### Data Residency Enforcement
- Geo-IP lookup for outbound destinations
- Block requests to non-compliant regions (e.g., GDPR: no data to non-EU)
- Configurable per-agent residency policies

### Rate Limiting (Network-Level)
- Per-agent network bandwidth limits
- Connection count limits
- Request size limits (prevent bulk data exfiltration)

## Quick Start

```bash
cargo build --release
./target/release/aegis serve --config config.toml
# Proxy: http://localhost:8686
# API:   http://localhost:8686/api
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         AEGIS                                     │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐    │
│  │  Egress  │  │  Attest  │  │  Geo-IP  │  │  Rate Limiter│    │
│  │  Proxy   │─▶│  Engine  │  │  Engine  │  │              │    │
│  └────┬─────┘  └──────────┘  └──────────┘  └──────────────┘    │
│       │                                                          │
│       ▼                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐      │
│  │  Policy  │  │  Audit   │  │  Admin Dashboard         │      │
│  │  Store   │  │  Log     │  │  (agent egress status)   │      │
│  └──────────┘  └──────────┘  └──────────────────────────┘      │
└──────────────────────────────────────────────────────────────────┘
         ▲
         │
    Agent traffic (HTTP_PROXY=http://localhost:8686)
```

## Integration

Agents are configured to use Aegis as their HTTP proxy:

```bash
# Set proxy for agent processes
export HTTP_PROXY=http://localhost:8686
export HTTPS_PROXY=http://localhost:8686
```

Aegis checks each outbound request against:
1. **Egress policy**: Is this destination allowed for this agent?
2. **Attestation**: Is the calling process a verified agent?
3. **Data residency**: Is the destination in a compliant region?
4. **Rate limits**: Has the agent exceeded bandwidth/request limits?

If any check fails, the request is blocked and logged.

## Status

**Early development.**

## License

MIT
