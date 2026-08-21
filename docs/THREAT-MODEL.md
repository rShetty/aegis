# Aegis Threat Model

> Status: living document. This file currently focuses on the attestation
> trust model (issue #4); a full trust-boundary walkthrough accompanies the
> README accuracy pass (issue #9).

## What Aegis actually is

Aegis is an **advisory verdict service**. Agents call `POST /api/egress/check`
before connecting to a destination and receive allow/deny. The *enforcement
point is the caller* (agent harness, wrapper script, or surrounding platform):
Aegis cannot observe or block traffic that bypasses it. There is no proxy
interception yet; see README "Not yet implemented".

## Attestation: what it does and does not prove

`require_attestation = true` denies egress for any `agent_id` that has not
been registered via `/api/attestation/attestate`. Registration works like this:

1. The **caller** supplies `binary_path`.
2. Aegis hashes that file with SHA-256 and stores `(agent_id, hash)`.

### Honest limitations

- **Self-reported path**: the caller chooses which file gets hashed. Malware
  can point at a legitimate binary while doing something else entirely.
- **No measurement, no proof of execution**: a stored hash verifies *file
  integrity across restarts* only if the hash was distributed out-of-band
  (e.g. provisioned by the platform at deploy time). It does NOT prove the
  process currently running as `agent_id` is executing that binary.
- **Hash comparison is equality-only**: `/api/attestation/verify` answers
  "does this supplied path/hash match what was registered?" Nothing more.
- **Registration endpoint is admin-gated** (#1), so in a correctly deployed
  setting only operators can mint attestations — but anyone who can reach the
  data plane with an already-registered `agent_id` inherits its verdicts.
  Agent identity authentication (per-agent keys) is on the roadmap.

### When the current model is still useful

- Detecting binary swaps after registration (hash mismatch on re-verify).
- Enabling `require_attestation` as a hard gate so unregistered/unknown
  agents get no egress at all (fail-closed default).
- Audit trail of which hashes were asserted for which agents, when.

### Roadmap to measured attestation

1. Per-agent API keys (hashed at rest) on the check endpoint.
2. Kernel-level measurement: hash the mapped executable of the *calling*
   process via OS facilities (e.g. `proc_pidinfo`/`/proc/<pid>/exe`),
   keyed by the peer PID from a local socket credential check.
3. Remote attestation (TPM/SGX-style signed measurements) for hosts outside
   the trust boundary.

## Trust boundaries (summary)

| Boundary | Assumption |
|---|---|
| Agent -> Aegis | Loopback or trusted network segment; agents are unauthenticated today |
| Operator -> Admin plane | Bearer token over TLS-terminating proxy; token never logged |
| Aegis -> SQLite | Local file access implies full control (no DB-level auth) |
| Caller -> enforcement | Callers must honor deny verdicts; Aegis is advisory |
