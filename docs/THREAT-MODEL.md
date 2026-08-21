# Aegis Threat Model

> Status: reflects the code on `main` as of the enterprise-hardening pass.
> Every claim here is scoped to what Aegis **actually implements today**; the
> README's "Not yet implemented" section lists capabilities that do not exist.

## 1. What Aegis is — and what it is not

Aegis is an **advisory verdict service**. Agents (or their harnesses) call
`POST /api/egress/check` before connecting to a destination and receive an
allow/deny verdict plus an audit-log entry. The **enforcement point is the
caller**: Aegis never observes, intercepts, or terminates network traffic. There
is no proxy, no CONNECT handling, no TLS inspection. A harness that dials first
and asks later — or never asks — renders every Aegis control moot.

Consequences of this design:

- Aegis controls *decisions*, not *traffic*. Its guarantees hold only inside
  systems that reliably call it before connecting and honor non-200 verdicts.
- Any process that can reach Aegis' port can obtain verdicts and write audit
  rows. Reachability ≈ authorization on the data plane.

## 2. Assets

| Asset | Sensitivity | Notes |
|---|---|---|
| Egress policy store | High | Defines what agents may reach; writable only via admin plane |
| Attestation store | High | `(agent_id → sha256)` bindings minted via admin plane |
| Admin token digest | Critical | SHA-256 of `AEGIS_ADMIN_TOKEN`; possession of the raw token = full control |
| `egress_log` audit trail | Medium-High | Evidence of allowed/blocked attempts; tamperable by anyone with DB file access |
| Config file | Medium | Contains bind address, policy defaults; no secrets stored in it |

## 3. Trust boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│ Host running Aegis                                               │
│                                                                  │
│  ┌─────────────┐  data plane (unauthenticated)   ┌────────────┐  │
│  │ Agent proc  │ ─────────────────────────────▶ │            │  │
│  │ / harness   │ ◀───────────────────────────── │   Aegis    │  │
│  └─────────────┘   advisory verdicts (200/403)  │  (axum +   │  │
│                                                  │  SQLite)   │  │
│  ┌─────────────┐  admin plane (bearer token)     │            │  │
│  │ Operator /  │ ─────────────────────────────▶ │            │  │
│  │ platform CI │                                 └─────┬──────┘  │
│  └─────────────┘                                       │         │
│                                                ┌───────▼───────┐ │
│  enforcement point: caller-side                │ aegis.db (WAL)│ │
│  harness honors verdicts                       └───────────────┘ │
└──────────────────────────────────────────────────────────────────┘
        │
        ✗ actual outbound traffic NEVER passes through Aegis
```

| # | Boundary | Assumption today | Failure mode if violated |
|---|---|---|---|
| B1 | Agent → Aegis data plane | Loopback or trusted segment; **no authentication**; `agent_id` is a client-supplied string | Any reachable process can query verdicts for any agent, pollute the audit log, and (with `require_attestation=false`) inherit per-agent policies by naming them |
| B2 | Caller → enforcement point | Harness refuses to connect after a 403 | Total bypass: Aegis becomes an unused logging service |
| B3 | Operator → admin plane | Bearer token secret, delivered over TLS terminated upstream; token never logged | Full control of policies/attestations; attacker can allowlist any destination |
| B4 | Aegis → filesystem (attestation) | Path supplied at registration is hashed with SHA-256 as the Aegis service account | `attestate` reads arbitrary caller-named paths — treat responses as a limited file-probing oracle (readable/not-readable distinction) |
| B5 | Aegis → SQLite | Local file (`aegis.db`, WAL/SHM siblings); no DB-level auth, no encryption at rest | Anyone with read access learns agent destinations; write access forges audit history |
| B6 | Network → listen socket | Default bind `127.0.0.1:8686`; remote exposure requires deliberate reconfiguration | Remote exposure moves B1/B3 off-host without adding transport security |

## 4. Threats & current mitigations

### T1 — Agent bypasses the check entirely
**Status: unmitigated by design.** Without proxy interception there is no way to
make checking unavoidable. Mitigation lives outside Aegis: egress firewall rules
that only permit the harness identity, wrapper scripts around agent runtimes,
or the future interception layer (roadmap).

### T2 — Destination-policy evasion tricks
Userinfo URLs (`https://api.github.com@evil.com`), case/trailing-dot variants,
IPv6 brackets, punycode mismatches, deny-vs-allow ordering. **Mitigated**:
host extraction normalizes these cases, ambiguous input fails closed, and deny
rules are evaluated before allow rules regardless of insertion order
(see the adversarial suite in `src/egress/mod.rs` tests).

### T3 — `agent_id` spoofing between co-located agents
Any caller may claim any `agent_id`. **Partially mitigated**: with
`require_attestation = true`, unregistered IDs are denied fail-closed (including
requests with no `agent_id`), and registration is admin-gated. But a caller who
can reach the port can still *reuse* a registered ID. **Not mitigated until**
per-agent credentials exist (roadmap).

### T4 — Binary swap after registration
Detected *only if* the reference hash was distributed out-of-band at provision
time: `/api/attestation/verify` re-hashes the supplied path and compares.
If registration was performed by the agent itself, the stored hash is
self-reported and proves nothing about integrity. No measurement of the running
process exists (no PID↔binary binding).

### T5 — Malicious or accidental registration
Prevented by the admin bearer token (constant-time digest comparison). In
debug builds without a token the admin plane is open with a warning; release
builds refuse to start unless `AEGIS_INSECURE_DEV=1` is set explicitly.
**Operator discipline required**: never run insecure-dev beyond local testing.

### T6 — Audit-log tampering or loss
The SQLite file is writable by the service account; there is no append-only
signing or external shipping yet. Treat `egress_log` as best-effort evidence,
not forensically sound. Unbounded growth is an availability risk; retention
pruning is tracked separately (#10).

### T7 — Coarse geo check fooled
The residency check maps TLDs to regions (no real GeoIP). Choosing a `.com`
domain hosted anywhere defeats it; this check is demo-grade and must not back
compliance claims.

### T8 — Token exposure via environment
`AEGIS_ADMIN_TOKEN` lives in the process environment, readable by same-user
processes and visible in crash dumps. Prefer a secret manager + systemd
`EnvironmentFile=` with tight permissions; rotate on suspicion.

## 5. Roadmap toward enforceability

1. Per-agent API keys (hashed at rest) closing the B1 spoofing gap.
2. Interception layer (HTTP CONNECT proxy / transparent redirect) moving the
   enforcement point from the caller into Aegis (T1).
3. Measured attestation: hash the mapped executable of the calling process via
   OS facilities (`/proc/<pid>/exe`, `proc_pidinfo`) keyed by peer credentials
   from a local socket (T4).
4. Signed, shipped audit logs (T6).
5. Real GeoIP data feeds behind an explicit accuracy disclaimer (T7).

Until items 1–2 land, position Aegis as a **decision service inside a trusted
harness**, not as a perimeter control.
