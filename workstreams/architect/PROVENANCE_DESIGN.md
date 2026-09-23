# Provenance record — design (wave-73, Part 3: Proof)

**The letter inside the envelope.** The audit chain (HMAC log, wave ≤72)
is the envelope: tamper-evident, anchored, key-bound. The provenance
record is the letter inside it: an auditor-readable, Art-12-shaped schema
stating who acted, when, on what resource, with what outcome, under which
delegation, approvals, policy version, session timing — versioned,
tiered, and verifiable on its own terms.

Status: design implemented this wave (`gov/provenance.py`,
`demo/make_report.py` provenance export). The three-token identity
machinery is **Wave-74's job**; §7 of this document is the contract
Wave-74 implements against — the schema must not need rework then.

Load-bearing inputs: EU AI Act Art 12 (+ Art 15/26(5)/72/73 adjacency) and
the CSA agentic NIST profile MEASURE (delegation-chain monitoring), per
`research/agent-governance-learnings-2026-09-22.md` Part 3 and
`research/intake-wave73-2026-09-22.md`.

**Scope discipline (from intake):** Art 12(3)'s minimum-content list
(period of use, reference DB, matched input, verifier identity) applies
*only to Annex III 1(a) remote biometric identification* — we do not
claim it for agents. Session start/end appears in our schema as *general
Art 12(2) traceability* ("periods of use"), never as an Art 12(3) claim.

---

## 1. The schema: `prov` envelope, field by field

Every governed record is a log entry carrying a reserved top-level
`prov` object. The envelope version is `PROVENANCE_SCHEMA_VERSION = 1`.
`ActionLog.append` continues to clobber reserved chain metadata
(`seq`, `ts`, `prev_hash`, `format_version`, `key_epoch`, `epoch_id`); the
`prov` section is caller-built and **validated before append** by
`gov/provenance.validate_provenance` (fail-closed: invalid records are
refused, never written half-formed). Entries without `prov` are legacy
records — the schema does not reach back and bless them.

Art-12 mapping: each field's `Art-12:` note names the regulatory
vocabulary it answers. An auditor must recognize the export on sight.

### 1.1 Core envelope (all record types)

| Field | Type | R/O | Art-12: | Semantics |
|---|---|---|---|---|
| `prov.schema_version` | int | R | — | Envelope major version. Currently `1`. A verifier pins to the version it knows (§6). |
| `prov.record_type` | enum str | R | purpose-driven events | One of `decision`, `approval`, `outcome`, `session_open`, `session_close`, `delegation_link`. Determines which per-type fields are required; swapping type without the required fields is record-type confusion → reject (§8). |
| `prov.session_id` | str (uuid) | R | traceability | Groups one principal's interaction across records. All records of a session share it. |
| `prov.session_open` | ISO-8601 str | R | periods of use (12(2) traceability) | Wall-clock session start, stated by the session opener. Present on every record (denormalized) so any single record is self-describing. |
| `prov.session_close` | ISO-8601 str | O (R on `session_close` records) | periods of use | Wall-clock session end. |
| `prov.clock_source` | str | R | traceability | Stated clock discipline, e.g. `"system-wall:UTC+00:00"`. The verifier does not trust the clock; it states it, so timing claims are auditable (§5). |
| `prov.principal` | object | R | **who** acted | `{kind: "user"‖"service"‖"agent", ref: "<opaque id>"}`. Identity *tokens* are Wave-74; this wave carries stable refs only — strings the deploying org maps to real identities out-of-band. No ambient-authority strings like `"system"` without a registered ref (the learnings memo's theater note). |
| `prov.delegation` | object | R | CSA MEASURE delegation-chain monitoring | The chained delegation path, §2. Required on every record: an empty delegation is written as an explicit zero-hop `delegation` object with `hops: []` and a stated reason, never omitted silently. |
| `prov.approvals` | [object] | R on `decision`/`outcome`; O elsewhere | human oversight adjacency (Art 14) | Each `{approval_id, decision, decided_by, decided_at}`. `decision` records without approvals must state `approvals: []` + `approval_basis: "policy-auto"‖"none-required"` — absence is a stated claim, never an omission. |
| `prov.action` | object | R on `decision`/`outcome`; O elsewhere | **what** was decided | `{verb, tool, args_digest}`. `args_digest` is sha256 of canonical args — the *purpose* is recorded, never the payload (§4). |
| `prov.resource` | object | R on `decision`/`outcome`; O elsewhere | **what resource** | `{kind, ref, scope}` — the resource the action touches (file path, URL host, account id class, …). |
| `prov.outcome` | object | R on `outcome`; O elsewhere | **outcome** | `{status: "ok"‖"denied"‖"error"‖"flagged", detail}`. `detail` is a purpose statement (e.g. `"policy R3 denied: egress unallowlisted"`), never raw output. |
| `prov.policy_version` | str | R | traceability of functioning | Policy bundle id + version that governed the decision, e.g. `"demo-policy:2026-09-22"`. |
| `prov.matched_rules` | [str] | R | decision provenance | Rule ids that produced the decision (authensor's `matchedRules` vocabulary). Empty list is legal and means "no rule fired — default posture applied". |
| `prov.payload_tier` | enum str | R | GDPR data-minimisation / purpose limitation | `"decision"` (default) or `"restricted"` (§4). |
| `prov.retention` | object | R | 12(4)/26(5) retention manifest | `{class: "decision"‖"restricted", until: ISO-8601, policy: "<retention-policy ref>"}`. Per-record retention expiry; the export aggregates these into the retention manifest. |
| `prov.anchor_ref` | object | O (export-populated) | tamper-evidence (Art 15 adjacency) | `{epoch_id, grade: "anchored"‖"operator-attested-only", backend, witness_time}`. Written at **export time** from `gov.anchorer.audit_anchors`, never by the actor — the schema *references* Wave-72's grading rather than duplicating it (§3). |
| `prov.supersedes` | [int] | O | schema migration | Entry seqs this record supersedes after a schema migration (§6). Absent on originals. |

Chain metadata the schema *uses but does not duplicate*: `seq`,
`ts` (entry wall clock), `prev_hash`, `key_epoch`, `epoch_id` — all
reserved, log-stamped, inside the HMAC canonical form. The provenance
record never restates them; the export joins them.

### 1.2 Record-type → required-field matrix

| record_type | required beyond §1.1 | forbidden (confusion surface) |
|---|---|---|
| `decision` | `action`, `resource`, `approvals` (+ `approval_basis` when empty) | `outcome` (a decision is not an outcome; `outcome` records follow) |
| `approval` | `approvals[0].approval_id`, `decided_by`, `decided_at` (non-empty list) | `action` without `prov.decision_ref` naming the approved decision |
| `outcome` | `action`, `resource`, `outcome` | — |
| `session_open` | — (carries `delegation` with the opening hop chain) | `session_close`, `outcome` |
| `session_close` | `session_close` | `action`, `outcome` |
| `delegation_link` | `delegation` with ≥1 hop beyond the principal | payload fields |

Violations fail closed at validation: the record is refused, the refusal
itself is a `decision` record with outcome `denied` (so refusals are
auditable, not silent).

---

## 2. Chaining the delegation, not just the actions

Every record carries the delegation path **principal → agent → sub-agent
→ tool** as chained, verifiable structure (CSA MEASURE; learnings memo
recommendation #1). The shape:

```
prov.delegation = {
  "delegation_schema_version": 1,
  "hops": [
    {"kind": "principal", "ref": "user:u_8f31",
     "binds": "GENESIS", "tokens": null},
    {"kind": "agent", "ref": "agent:orchestrator-7",
     "binds": "<sha256hex of canonical(hops[0])>", "tokens": null},
    {"kind": "sub-agent", "ref": "agent:researcher-3",
     "binds": "<sha256hex of canonical(hops[1])>", "tokens": null},
    {"kind": "tool", "ref": "tool:webfetch",
     "binds": "<sha256hex of canonical(hops[2])>", "tokens": null}
  ]
}
```

Semantics:

- **Ordering is fixed and total**: hops are appended in delegation order;
  index 0 is always the principal. A record's acting hop is stated by
  `prov.acting_hop` (int index into `hops`) — an agent acting records the
  full path from its principal, not just itself.
- **`binds` chains the path**: `hops[i].binds = sha256(canonical(hops[i-1]))`
  for i>0, `"GENESIS"` for i=0. Canonical form is
  `json.dumps(hop, sort_keys=True, separators=(",",":"))` over the hop
  **excluding** its own `binds` (binds commits to the *content* of the
  previous hop, not to its binds value — otherwise the chain would be
  self-referential). Dropping a middle hop breaks the binds link of its
  successor → verification fails closed. **This pins the Wave-74
  contract: truncation is detectable by structure, not by policy.**
- **`tokens: null` is the reserved slot.** The three-token shape
  (user token ref + agent token ref + human-signed delegation token ref,
  per South et al. via the learnings memo) lands here. Until Wave-74,
  `tokens` MUST be `null` (or absent); a non-null `tokens` on a v1
  record is rejected — no one invents a fourth token shape in the
  meantime.
- **Scope attenuation (Wave-74):** per-hop scope narrowing is expressed
  inside the delegation token (Wave-74), not in the hop ref. This wave's
  verifier checks only structural continuity; it does not evaluate
  scope — evaluating scope against unissued tokens would be theater.
- **Zero-hop form**: `{delegation_schema_version: 1, hops: [],
  no_delegation_reason: "<stated>"}` for records with genuinely no
  delegation (e.g. daemon housekeeping). The reason is required.

The delegation object is part of the entry's canonical form (it lives in
the entry body), so the HMAC chain commits to the full path — a
key-holder rewriting history must reforge the chain (Wave-72's threat
model), and the binds structure additionally makes *silent edits within
a valid MAC* detectable at the schema layer.

---

## 3. Anchor receipt references (Wave-72, referenced not duplicated)

`gov/anchorer.py` already grades every closed epoch
`anchored` vs `operator-attested-only` (`audit_anchors`), with
`anchor_receipt` records chained in the log. The provenance schema does
not re-derive any of this. Instead:

- At **export time**, `demo/make_report.py` calls `audit_anchors` and
  attaches `prov.anchor_ref` per record: `{epoch_id, grade, backend,
  witness_time}` for the record's epoch (the record's `epoch_id` is the
  join key).
- The export states the anchor grade **per epoch**, and the report's
  traceability table carries a per-record anchor column. An auditor sees,
  for any record, whether its epoch is externally anchored or
  operator-attested-only — the exact F29-honest language Wave-72
  established.
- The "soft window" (open epoch, unanchored records) is reported
  numerically (`open_epoch.unanchored_records`), never hand-waved.

---

## 4. Log purposes, not payloads — the tiering

Default tier is **decision/approval/outcome records only**. Full
prompts, tool outputs, and transcripts live behind an explicit,
retention-bounded, access-controlled tier.

| Tier | `payload_tier` | Content allowed | Retention default | Access annotation |
|---|---|---|---|---|
| Decision (default) | `"decision"` | purpose vocabulary only: verbs, digests, rule ids, approval refs, outcome statuses. **Forbidden keys** (deny-list enforced by the validator): `prompt_text`, `prompt`, `full_output`, `output_text`, `transcript`, `messages`, `tool_result_body`, `pii`. | 6 months (Art 12(4)/26(5) floor) | none required |
| Restricted | `"restricted"` | may carry payload fields, each named explicitly | **bounded**: `retention.until` ≤ 6 months from record time unless a named legal basis is stated in `retention.policy`; the validator rejects unbounded restricted records | `access: ["<role>", …]` required — who may read the payload tier |

Tier enforcement is **validator-enforced, not advisory**:
`validate_provenance` refuses a `"decision"`-tier record carrying any
forbidden key (fail-closed; refusal is itself logged). Smuggling full
prompt content into the default tier is the `payload_tier_bypass`
probe (§8) — it must be refused, and it is.

Residual (stated, not filed): tier enforcement is a schema-layer
control. A key-holder can reforge the whole chain including tier labels;
that attacker is Wave-72's model and is answered by the anchor, not by
this schema. The schema's promise is: *honest writers cannot
accidentally or casually* put payloads in the default tier, and any
auditor can verify the tier claim per record.

---

## 5. Session timing

- **Fields**: `session_open` (R, wall clock), `session_close` (R on
  `session_close`), `clock_source` (R, stated discipline). These are the
  Art-12(2) "periods of use" traceability fields.
- **Chain binding**: session records are ordinary entries; their MAC
  covers the timing claims, and the reserved `epoch_id` (Wave-72,
  stamped inside the HMAC canonical form) binds each record to its
  anchor epoch. Timing binds to the chain the same way content does —
  there is no separate timing MAC.
- **What the binding catches**: anyone *without* the key who alters a
  timestamp breaks the chain (wave-72 probe class, already pinned).
- **The key-holder residual (stated honestly, pinned by probe)**:
  a key-holder can backdate session start/end *within the open epoch*
  and reforge valid MACs — the chain cannot catch this. It is caught
  only after anchoring: at export time,
  `gov/provenance.check_session_timing` compares each session's claimed
  `[session_open, session_close]` against the epoch's anchored wall
  window and `witness_time`; a claim outside the window (beyond skew
  allowance) is flagged loud in the export. **Before the epoch anchors,
  backdating is undetectable by construction** — the export states the
  soft window numerically instead of claiming otherwise. This is a
  designed residual of the anchor cadence (the security parameter), not
  a finding.
- **Clock games by the session opener** (lying about `clock_source` or
  using a skewed clock): the schema states the clock; it does not
  attest to it. Cross-checking wall clocks is deployment hygiene
  (NTP), documented as a boundary note, never a finding.

---

## 6. Schema versioning + migration

- `prov.schema_version` is an integer major version, currently `1`.
  `validate_provenance` **fails closed on any major version it does not
  know** — a v2 record presented to a v1 verifier is refused, never
  silently accepted; a v1 record presented to a v2 verifier verifies
  under the v1 rules (verifiers are version-pinned per record).
- Minor extensions (new optional fields) do not bump the major version;
  they are enumerated in this document's changelog. Unknown *required*
  fields are never introduced without a major bump.
- **Migration** = re-issuance, not in-place rewrite: a migrated record
  is a NEW entry under the new schema version carrying
  `prov.supersedes: [<old seqs>]`. Old entries are never edited (the
  chain is append-only); they verify under their original version
  forever. An export may present the migrated view, but the raw log
  always shows both.
- `delegation.delegation_schema_version` versions the delegation
  sub-schema independently, so Wave-74's token fill can rev the
  delegation version without revving the envelope.

---

## 7. The Wave-74 delegation contract (implementable spec)

Wave-74 implements identity. This section is the contract it builds
against — written so no schema rework is needed.

1. **Fill `tokens`, don't reshape.** Each hop's `tokens` slot takes the
   adopted three-token shape (South et al., learnings memo Part 4):
   ```
   "tokens": {
     "tokens_schema": "south-3token/v1",
     "user_token_ref": "<ref to the user's OIDC ID token>",
     "agent_token_ref": "<ref to the agent's Agent-ID token>",
     "delegation_token_ref": "<ref to the human-signed delegation token>"
   }
   ```
   The delegation token references the hashes of the other two and
   carries scope, expiry, revocation endpoint, audit URLs. Wave-74
   defines the token *contents*; this schema fixes only the slot.
2. **Keep `binds` semantics.** When Wave-74 fills tokens, the binds
   chain MUST continue to commit to hop content *including* the filled
   tokens (tokens are part of the hop content once present). Truncation
   detection keeps working unchanged.
3. **Rev the delegation sub-version.** Token fill bumps
   `delegation_schema_version` to `2`; envelope stays `1`. v1 records
   (tokens null) keep verifying under v1 rules.
4. **Permission intersection is Wave-74's evaluation rule**
   (user ∩ agent ∩ delegation scope); this wave's verifier deliberately
   does not evaluate scope — Wave-74 must not "fix" that by weakening
   the binds check.
5. **Revocation propagation** (the memo's open gap) belongs to Wave-74's
   token design, not to this schema. The schema's only revocation-adjacent
   field is `delegation_token_ref`, which lets an auditor chase the
   revocation endpoint.

What Wave-74 must NOT do: invent a fourth token shape; move identity
into the envelope root (refs stay in hops); evaluate scope at the
provenance layer; or claim that filling tokens retroactively upgrades
v1 records.

---

## 8. Break model (what the probes must show)

| Probe (registry `redteam.provenance_w73.*`) | Attack | Must show |
|---|---|---|
| `provenance_forgery_fails` | forge a record with valid-looking identity/session fields, no key | chain verification fails at the forged seq |
| `session_backdate_keyholder_residual` | key-holder backdates session start/end with valid reforged MACs | in-chain verification passes (residual, stated); post-anchor export check flags the claim outside the witness window |
| `record_type_confusion_rejected` | swap a `decision` record's type/fields to escalate authorization | schema validation rejects (required-field matrix) |
| `schema_version_games_fail_closed` | present v2 fields to a v1 verifier and vice versa | fail closed, never silently accept |
| `delegation_truncation_detected` | drop a middle hop from the delegation path | binds chain breaks → verification fails |
| `payload_tier_bypass_refused` | smuggle full prompt into the default tier | tier enforcement refuses |
| `valid_record_verifies` | control: well-formed v1 record | verifies clean (green closure) |

Every genuine independently-reachable miss → harden same-wave or file
**F129** (next free). Refuted shapes and deployment-hygiene items are
boundary notes, never findings.

## 9. Deliberately not done (Wave-74 or later)

- The three-token identity machinery (Wave-74, per §7).
- Per-hop scope evaluation / permission intersection (Wave-74).
- Token revocation propagation (Wave-74).
- Selective disclosure / zero-knowledge property proofs (research gap,
  no shipped answer anywhere — noted, not started).
- The commercial evidence pipeline: no metering, billing, or SaaS. The
  export is auditor-readable output, not a product surface.
- Live Rekor submission, P-256 SET verification, anchor-key KMS custody
  (Wave-72 residuals, unchanged).

## Changelog

- 2026-09-22 (wave-73): v1 of this document; `PROVENANCE_SCHEMA_VERSION=1`,
  `delegation_schema_version=1`; envelope + delegation + tiering +
  session timing + versioning + Wave-74 contract as above.
