# Single-Tenant Scope — v1.0 decision

**Decision (per `workstreams/architect/SHIP_PLAN.md` §2): v1 is single-tenant
only.** Multi-tenancy is explicitly OUT of v1 and deferred to v2:
"tenancy isolation is a second product."

This doc states what that boundary means in concrete, code-grounded
terms. It is not a marketing statement — it is the list of things you
may not assume.

---

## What "single-tenant" means concretely

There is no tenant construct anywhere in the v1 code. The word
"tenant" appears in `gov/` only twice, both descriptive: in the
`PrincipalRegistry` docstring ("the set of principal strings this
deployment recognizes (tenants, teams, service accounts)" —
`gov/identity.py`) and in `gov/egress_ledger.py` docstrings about DNS
public-suffix handling. There is no tenant id on identities, records,
keys, queues, or logs, and no isolation logic keyed on one.

The v1 deployment has exactly one of each:

| Domain | v1 reality | Grounding |
|---|---|---|
| Operator identity | One shared principal for the approval console: every authenticated session decides as `web/human-operator` (`WEB_DECIDED_BY`, `gov/approval_web.py`). There is no per-human identity — anyone holding the startup token *is* the operator. | `gov/approval_web.py` |
| Key set | One key domain per deployment: `GOV_LOG_KEY` (env, process-global) or one `EnvelopeKeyRing` envelope file (e.g. `/etc/governance/log-envelope.json`). Key resolution is not per-actor — every process sees the same env. | `gov/log.py` (R6c strict resolution), `docs/KEY_CUSTODY_RUNBOOK.md` |
| Approval queue | One `approvals.jsonl` per run dir. All records are visible to the single operator; there is no per-tenant queue namespace. | `gov/approvals.py` |
| Audit log | One `actions.jsonl` hash chain per run dir, one chain head, one MAC epoch at a time. No per-tenant chains or partitioning. | `gov/log.py` |
| Policy | One policy per run (`GOV_POLICY_HASH` pins a single policy; a policy change invalidates queued approvals' pin). No per-tenant policies. | `docs/DEPLOYMENT.md` §6 |
| Recovery / halt authority | `gov/recovery.py` takes explicit constructor keys per deployment — one authority set, no delegation across tenants. | `gov/recovery.py` |

## What this excludes

- **Onboarding a second tenant is not supported.** There is no API or
  config surface for it; adding one is building the v2 product, not
  configuring v1.
- **Running two run dirs on one host is NOT multi-tenancy.** Each run
  dir has its own queue/log files, but they share the host, the
  process environment (and therefore the log key unless you isolate
  it), and the operator principal. Isolation between run dirs is
  directory-level only — there is no privilege boundary. A compromise
  of the operator token or the host affects all run dirs equally.
- **Cross-tenant threats are out of scope for v1** because there is no
  cross-tenant surface: confused-deputy between tenants, tenant data
  leakage through a shared queue or log, per-tenant quota exhaustion,
  and tenant-to-tenant privilege escalation have no v1 construct to
  evaluate them against. If you deploy v1, you are asserting there is
  exactly one trust domain.

## What a multi-tenant v2 would additionally need

Deferred, not designed here — listed so v1 operators don't mistake
run-dir separation for tenancy:

1. Tenant-scoped identity: per-tenant principal registries and
   per-tenant `decided_by` binding (v1 binds all web decisions to the
   single `web/human-operator` label).
2. Tenant-scoped key domains: per-tenant envelope keyrings / KMS
   masters, with key-id binding enforced per tenant (v1: one master).
3. Tenant-partitioned chains: per-tenant audit logs with independent
   chain heads and checkpoints, so one tenant's verifier never reads
   another tenant's entries.
4. Per-tenant policy and approval queues (v1: one policy, one queue).
5. Tenant-aware authentication on the approval surface: SSO/OIDC with
   per-tenant IdP configuration (v1 has no SSO at all —
   `docs/APPROVAL_WEB_AUTH.md`).
6. Resource quotas between tenants (v1 has none — velocity guards are
   per-principal, not per-tenant).

## Honest boundary

This decision cannot be verified by the test suite — the suite verifies
the single-tenant product, and it is green. What it does not and cannot
do is make the product safe for a second tenant. **Do not deploy v1
where two trust domains share the deployment.** If that changes, you
are no longer running v1 — you are building v2.

*Status note:* the SHIP_PLAN predates the live Vault validation; the
key-custody facts above reflect the runbook as written. The boundary
itself is independent of the key backend.
