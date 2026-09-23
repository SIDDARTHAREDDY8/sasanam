# Governing the Governors — design (wave-75, Part 7: policy-change control)

**Status: implemented 2026-09-22** (`gov/policy_change.py`;
`gov/provenance.py` record types `policy_change` / `breakglass`;
executor governed-path wiring). Load-bearing inputs:
`research/agent-governance-learnings-2026-09-22.md` Part 7 (ranked
recommendations 1–3, adopted verbatim as the build order),
`workstreams/architect/IDENTITY_DESIGN.md` §9 (the human delegation
key as Wave-75's policy-authorship primitive), `gov/provenance.py`
(the governed event is a provenance record — no parallel schema),
`gov/anchorer.py` + `gov/anchor_backend.py` (wave-72 anchoring —
policy-change events anchor like everything else),
`gov/keyprovider.py` + `KEY_MANAGEMENT_DESIGN.md` (the deployment-mode
vocabulary the approval tiers bind to).

The learnings memo's (c) section is the whole justification: *"Policy-
change as a governed event: who changed the rule, what the diff was,
who approved it, chained and anchored like everything else. Nobody in
the agent space does this. If someone silently rewrites policy, the
other six parts collapse — and nobody is watching that seam."* This
wave closes that seam. It is deliberately promoted early (Part 7 of 7
built before Parts 5–6's detection/response): everything after it is
built *on top of* the guarantee that the rules under it cannot be
moved silently.

---

## 1. The policy-change event as a provenance record

A policy change is not a file edit. It is a governed event with a
first-class provenance record. New record type `policy_change`
(added to `RECORD_TYPES`, §1.2 matrix):

```
prov.record_type = "policy_change"
prov.policy = {
  "change_id":       "<sha256hex of the change artifact>",
  "policy_version":  "<new live version id, e.g. v7.3f9a1c2e>",
  "prior_version":   "<superseded version id, or 'GENESIS'>",
  "status":          "proposed" | "approved" | "applied" | "rejected",
  "tier":            "single-human" | "two-person",
  "author_key_id":   "<human author key id (roster)>",
  "approver_key_ids": ["<distinct roster human key ids>"],
  "policy_digest":   "<sha256hex of canonical new policy bytes>",
  "prior_digest":    "<sha256hex of canonical prior policy bytes>",
  "diff_digest":     "<sha256hex of canonical structured diff>",
  "diff_summary":    {"rules_added": n, "rules_removed": n,
                      "rules_changed": n, "sections_changed": [...]},
  "purpose":         "<human-stated purpose string>",
}
prov.approvals = [ {approval_id, decision, decided_by, decided_at} ... ]
                 (the tier's human approvals, one entry each)
prov.authorship_ref = "<sha256hex ref of the authorship token>"
```

Authorship is the Wave-74 primitive reused verbatim (§9 contract):
the mutation is signed by the **human author's key** (Ed25519,
verified against the same `DelegationTrust` human roster), chained
with `parent_token_hash` → the previous policy version's authorship
token ref. The authorship token shape:

```
token_version: 1, token_kind: "policy_change_authorship"
issuer: "<author key id>", subject: "<policy_digest>"
issued_at: ISO-8601
policy_ref: sha256hex(canonical new policy bytes)
prior_ref: sha256hex(canonical prior policy bytes)
parent_token_hash: "<prior authorship token ref>" | "GENESIS"
claims: {author, diff_digest, tier, deployment_mode, session_id, purpose}
sig: ed25519 over canonical body
```

Full tokens live in deployment memory only; the provenance record
carries refs, never signing-capable material (the Wave-74 storage
rule, unchanged).

**Diff representation.** Canonicalization first: parse with the same
parser the engine uses (`yamlmini`), re-emit as canonical JSON
(`sort_keys`, separators) — two files that parse identically have
identical digests (formatting/comment changes are no-ops, honestly:
the digest covers *enforced meaning*, not bytes). The structured diff
over the parsed tree:

- `rules_added` / `rules_removed`: rule ids (the `id:` field) entering
  or leaving `policies:`.
- `rules_changed`: `{rule_id: [changed fields...]}` — field-level,
  purpose vocabulary only (effect, match keys, thresholds).
- `sections_changed`: top-level sections whose canonical form moved
  (`roles`, `rate_limit`, `egress`, `approvals`, `critical_windows`,
  …).

The diff is content-safe by construction: policy YAML carries rules,
never secrets. `diff_digest` commits the author to exactly the change
the approvers saw — an approval binds to `policy_digest`, not to a
narrative.

**Anchor linkage.** Policy-change records are appended to the same
`ActionLog` as everything else; the wave-72 epoch machinery anchors
them. The provenance export (§wave-73) gains a "governor changes"
section: each `policy_change` record listed with its epoch's anchor
grade (`anchored` / `operator-attested-only`). No new anchor
machinery — the anchor as governor-oversight is the learnings memo's
(a) point, and the existing machinery already covers it.

---

## 2. Approval tiers — the nuclear rule

`required_tier(deployment_mode)` — the wave-69/70 deployment-mode
vocabulary is load-bearing here:

| deployment_mode | tier | meaning |
|---|---|---|
| `production` | **two-person** | author + ≥1 distinct second roster human; author must be among the approvers |
| `staging`, `dev`, `test` | `single-human` | ≥1 roster human approval (may be the author) |

Two-person with the roster model means exactly this, enforced in
code (`approvals_satisfy`): every approval is an Ed25519 signature
over the canonical change body by a key in `DelegationTrust.human_keys`;
all signer key ids are pairwise distinct; in `two-person` there are ≥2
of them. "Same human twice" is structurally refused — distinct *keys*,
not distinct *names*. Key rotation is re-registration in the roster
(an audited deployment act, §Wave-74); the roster's human_keys list is
the entire trust surface.

Single-human is the deliberate weakening for non-production: the memo
says two-person for *production* policy; dev/test policy moves at one
human's speed. This is stated in the tier table, not hidden.

---

## 3. Enforcement by construction — where the no-event change dies

The governed path is `GovernedPolicyStore`, and the executor's live
engine is replaced **only** through `GovernedPolicyStore.apply()`.
There is no reload-from-disk code path: editing the YAML file on disk
mid-run does nothing to the live engine — the executor never re-reads
the file. This is the Wave-74 "construction, not text" lesson applied
to the governor: the check lives in Python on the only mutation path.

The lifecycle, each transition a chained `policy_change` event:

```
propose(text, author_signer)  — YAML loads (PolicyEngine.from_text, the
    same F53 one-buffer rule), lint-shaped validation; authorship
    token issued; status=proposed appended.
approve(change, approver_signer) — signature over the change body;
    distinctness checked per tier; status=approved appended
    (accumulates; a change may carry >2 approvals).
apply(change) — re-verify: authorship sig vs roster, tier satisfied,
    stored text digests to policy_digest; build engine from the STORED
    text (verify the artifact, never the reference — the Plugin4Shell
    lesson: the file is the reference, the change artifact is the
    pinned digest); atomic swap of the live engine; status=applied
    appended with policy_version + prior_version.
```

Refusals raise `PolicyChangeError` and the caller logs
`decision`/`denied` (the provenance refusal contract — auditable,
never silent). A policy that fails lint/validation cannot even be
*proposed* — the malformed rule never becomes a change artifact.

**Bootstrap.** The first engine also goes through the store
(`bootstrap`): the initial `policy_change` record has
`prior_version: "GENESIS"`. There is no unauthored policy on the
governed path — the executor's constructor taking a bare `PolicyEngine`
is the ungoverned bootstrap seam, labeled as such; production
deployments attach the store.

**Version pinning for in-flight executions (Wave-73 substrate).**
`ToolExecutor.call()` snapshots the engine at call start and the
verdict path (role check → `evaluate()` → recorded `policy_version`
+ `policy_hash`) runs against that snapshot — an audit confirmed zero
`self.policy` references remain inside `call()`. Engine swap is a
single atomic attribute assignment, so every read sees exactly one
version — no torn reads. Each decision record carries the digest of
the engine that decided it (`_base()` stamps the snapshot digest on
every verdict-path `tool_call` entry), so "which rule decided this"
is answerable per record across a swap. Documented boundary:
`execute_approved()` is a separate entry point and deliberately uses
the *current* engine — guarded by an explicit policy-staleness
refusal (an approval granted under a different digest is refused,
never silently re-evaluated); grant/approval *minting* stamps the
current engine, which is correct mint-time semantics.

---

## 4. Break-glass ceremony — the PAL model

The learnings memo's recommendation 2: time-boxed, purpose-declared,
dual-recorded (request + use), auto-expiring, post-use review as a
*required* chained event. New record type `breakglass`:

```
prov.record_type = "breakglass"
prov.breakglass = {
  "declaration_id": "<id>", "phase": declared|activated|used|expired|reviewed,
  "purpose": "<human-stated purpose>", "ttl_s": <int>,
  "requested_by": "<roster human key id>", "reviewed_by": "<key id>" | null,
  "review_status": "pending" | "complete" | "n/a",
}
```

The state machine (each transition a chained event; the machine lives
in `gov/policy_change.py::BreakGlass`, not in policy text):

1. **declared** — a roster human requests break-glass with a stated
   purpose and a TTL. Dual recording starts here: the declaration is
   the *request* record.
2. **activated** — the declaration enters its window. Refused while
   another declaration has a `used`-but-unreviewed use pending (the
   ceremony gate: one open PAL at a time, and you cannot open a new
   one while the last one's review is outstanding).
3. **used** — each use appends a `used` record (purpose + action
   summary). Use without an active declaration → refused. Use after
   expiry → refused AND an `expired` record is appended (loud, not
   silent).
4. **expired** — auto: any operation on an expired declaration appends
   `expired` and refuses; a sweeper `expire_due()` lets the deployment
   close windows deterministically.
5. **reviewed** — post-use review is REQUIRED: a *distinct* roster
   human (two eyes — the user cannot review their own PAL) appends
   `reviewed`. Until then the declaration sits in
   `outstanding_reviews()` — surfaced, not hidden.

The PAL analogy is exact about the guarantee, and honest about the
limit: the capability to override exists; using it leaves an
un-erasable, anchored trail. The machine cannot prevent a human from
*using* break-glass — that is the point of break-glass — but every
use is dual-recorded and the review is a blocking gate on the next
declaration.

---

## 5. Break model (what the probes must show)

| Probe | Attack | Must show |
|---|---|---|
| `silent_rewrite_impossible` | rewrite the policy YAML on disk mid-run | live engine unchanged — no reload-from-disk path exists; decision verdicts identical pre/post (impossible-by-construction on the governed path) |
| `forged_authorship_refused` | policy-change event signed by a non-roster key | `apply` refuses — Ed25519, verifier holds only roster pubs |
| `tier_bypass_refused` | production change with only the author's approval | `apply` refuses — two-person unsatisfied |
| `same_key_twice_refused` | author approves twice, counted as two-person | refused — distinct *keys* required |
| `breakglass_undeclared_use` | use without declaration | refused, `used` record never written |
| `breakglass_expired_use` | use after TTL | refused + `expired` record appended (loud) |
| `breakglass_review_gate` | new declaration while a prior use is unreviewed | refused until `reviewed` lands |
| `backdated_change_flagged` | policy_change record with issued_at after its epoch's witness_time | export's anchor cross-check flags impossible timing (the wave-73 backdate lesson: in-chain backdating inside the open epoch is the stated residual; the anchor catches it post-close) |
| `inflight_version_pinned` | apply v4 between two calls | call 1's decision record pins v3 digest, call 2 pins v4 — "which rule decided this" answerable |

---

## 6. Deliberately not done (with rationale)

- **Operator-action audit beyond policy** (governor code/config/key
  changes) — the learnings memo names it as missing everywhere; this
  wave covers *policy* changes. Code/config/key-change control is a
  stated next seam, not smuggled into this one.
- **Cross-deployment policy replication** — out of scope; the local
  model is one deployment, one store.
- **Policy rollback as a primitive** — rollback is a new change
  (prior text re-proposed), not a special path; the chain stays
  append-only.
- **Selective disclosure of diffs** — diffs are purpose vocabulary;
  no payload tier is needed.
- **Commercial evidence pipeline** — strategic context only; the
  export section serves auditors, not billing.
- **Staging tiering** — staging takes the single-human tier (matches
  the keyprovider's non-production grouping). A deployment that wants
  staging two-person can tighten the table; the default is stated.
- **Mid-call helper reads** (§3) — closed in-wave: `call()`'s verdict
  path was audited to zero remaining `self.policy` references; all
  policy reads inside `call()` go through the call-entry snapshot.
  `execute_approved()` as a separate entry point deliberately uses
  the current engine, guarded by the policy-staleness refusal. No
  tool path can trigger `apply`, so it cannot interleave inside a
  call.

## Changelog

- 2026-09-22 (wave-75): v1 — policy-change as provenance record
  (`policy_change` / `breakglass` types), authorship token reusing the
  Wave-74 human key + roster, tier table bound to deployment_mode,
  `GovernedPolicyStore` as the only mutation path, break-glass PAL
  state machine, version-pinning contract, break model, residuals.
