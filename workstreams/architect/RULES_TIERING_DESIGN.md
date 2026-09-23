# Rules-Tiering Design (Wave-79)

**Date:** 2026-09-22. **Theme:** the rules-layer slice of the learnings memo
(`research/agent-governance-learnings-2026-09-22.md` Part 1 + Part 2):
lethal-trifecta tiering, total policy_version + matched_rules, pre-commit
validation for irreversible actions. Second slice of the continuing
rules+enforcement hardening loop.

**Honesty note on prior art.** The lethal-trifecta framing (private data +
untrusted content + external communication) is NIST's threat model and
Simon Willison's prompt-injection coinage — we did not invent the
observation. The invention here is making it a **policy primitive with
enforcement wiring**: a classified tool registry, a composition rule over
delegation hops, and an automatic oversight-tier escalation with a
policy-independent approval floor. The memo's direction ("adopt
lethal-trifecta tiering as a policy primitive") is followed; the
"sterile windows on / canary density up" half of the memo's escalation
vocabulary is deployment configuration, not something this wave claims
as enforced — the wired escalation is stated exactly in §1(c).

---

## 1. Lethal-trifecta tiering

### 1(a). The three axes (definitions)

A tool/capability is classified along three independent axes:

1. **private-data access** — the tool can read data the principal has not
   made public (file reads, API responses, prior tool outputs carrying
   PII/secrets). Read-shaped, not write-shaped: writing is not access.
2. **untrusted-content exposure** — the tool ingests content the agent did
   not author and cannot vouch for (file bodies, fetched pages, downloaded
   code). This is the prompt-injection surface.
3. **external communication** — invoking the tool moves bytes (or effects)
   outside the agent's trust boundary (network sends, email, package
   fetches, environment mutation via install).

The **trifecta** is holding all three axes. A session whose *effective
grant set* holds all three is in the **elevated** oversight tier;
otherwise **standard**.

### 1(b). The tool registry (classification)

`gov/rules_tiering.py::TOOL_AXES` — the operator-owned registry, stated
exactly:

| tool            | private_data | untrusted_content | external_comm |
|-----------------|--------------|-------------------|---------------|
| read_file       | yes          | yes               | no            |
| write_file      | no           | no                | no            |
| delete_file     | no           | no                | no            |
| api_call        | yes          | yes               | yes           |
| http_post       | no           | no                | yes           |
| send_email      | no           | no                | yes           |
| install_package | no           | yes               | yes           |

Notes, stated plainly:
- `api_call` alone holds the full trifecta: it reads private data (params
  carry read content — the F1 class; responses carry private data), ingests
  untrusted content (fetched pages), and communicates externally. An agent
  with `api_call` IS the NIST threat-model shape. This is not a
  classification accident; it is the point.
- `read_file` is private-data + untrusted-content but not external: reading
  cannot exfiltrate by itself (the exfiltration half is the external axis).
- `write_file`/`delete_file` hold no axis: they mutate local state, which
  is an *integrity* concern (handled by the irreversible registry, §3),
  not a trifecta axis.
- Roles fall out of the registry: `coder`/`researcher`/`scout`/
  `publisher` sessions are elevated (they hold `api_call` or an
  untrusted+external pair); `triage`/`builder` sessions are standard.

### 1(c). What escalation means (wired, exact)

When a session's effective grant set completes the trifecta, the session
auto-escalates to the **elevated** tier. Escalation means exactly this,
and only this:

1. **Policy-independent approval floor (explicit deployment opt-in).**
   Any call to a tool carrying the `external_comm` axis requires human
   approval, even when the policy engine verdict is `allow`. The
   verdict is overridden to `require_approval` (queued); the record
   carries flag `trifecta_floor` and `matched_rules` = the engine's
   matched rules + the reserved sentinel `"trifecta-tier-floor"`.
   Policy `deny` still denies; policy `require_approval` still queues
   (the floor only bites where the policy would otherwise allow
   silently). The floor is enabled with `ToolExecutor(...,
   trifecta_floor=True)`; the default is **off** (zero behavior
   change — no tier is computed, no escalation record is chained).
   The opt-in is deliberate and documented: an unconditional floor
   would queue every allowlisted `api_call` for the coder/researcher/
   scout roles, whose sessions are elevated from the first call by
   grant composition — the guarantee is real, and so is the friction,
   so the deployment chooses. This follows the wave-78 opt-in gate
   pattern (`precommit_gate`, `lease_verifier`, `recovery`,
   `detection_monitor`).
2. **A loud, chained escalation record.** The first elevated call in a
   session appends a `trifecta_tier_escalated` decision record naming the
   composing grant sources (role tools, delegation scope, lease scope).
   Totality-stamped (§2).
3. **No silent downgrade.** The tier is recomputed per call from current
   grants; a session that held the trifecta and later sheds a grant
   returns to standard, and that return is also recorded.

Deliberately NOT claimed: sterile-window activation and canary-density
changes are operator deployment configuration, not enforced by this wave.
The design does not pretend the approval floor is the whole memo.

### 1(d). The composition rule (across delegation hops)

Wave-74's strict attenuation is untouched: a child token's scope is a
subset of its parent's, always. The composition rule does not fight it —
it composes **over effective grants, not over token scopes**:

```
effective_grants(session) =
    role_tools(session.role)
    ∪ delegation_scope(verified grant, if any)
    ∪ lease_scope(presented lease, if any)
tier(session) = elevated iff ⋃ axes(effective_grants) == {all three}
```

The attack shape this answers: a parent session holding two axes (e.g.
`triage`: read_file/write_file = private_data + untrusted_content)
spawns a child; the child runs under its own identity whose role adds the
third axis (e.g. `researcher` adds external_comm). Token attenuation held
— the child never exceeded its token — but the *session* now holds the
trifecta. The child's first external-comm call trips the elevated floor.
Composition is evaluated per call, so no spawn-time oracle needs the
child's future role, and no attenuation invariant is weakened.

A spawn-time check inside `spawn_sub_agent` was considered and rejected
as theater: under strict attenuation a child scope can never add an axis
its parent chain lacks, so a token-scope-only composition check is
unreachable by construction. The reachable composition is the
effective-grant union, and that is where the enforcement lives.

### 1(e). Classification procedure (who labels, mislabels)

1. **Who labels:** the operator, at tool registration, in
   `gov/rules_tiering.py::TOOL_AXES` (the single registry; the engine's
   `KNOWN_TOOLS` is the closed tool universe, so an unregistered tool
   cannot execute anyway).
2. **The test for each axis** (applied per tool, documented in the
   registry comments): *could a normal invocation of this tool exhibit
   the axis without any other tool's help?* If yes, the axis is set.
3. **Mislabeled tools:** a tool labeled clean whose behavior exhibits an
   axis is an **incident-class probe** (written this wave:
   `redteam.rules_w79.mislabeled_tool_clean_label_exfiltrates`). The
   labels **only ever escalate** — no enforcement path consults a label
   to *permit* anything, so a mislabeled tool cannot weaken the
   read-before-send / DLP / egress controls; it can only fail to raise
   the tier. The fix for a mislabel is reclassification through the
   governed policy-change path (§3's registry discipline applies to
   `TOOL_AXES` too), never a silent edit.
4. **Review:** the registry is re-reviewed whenever a tool is added or a
   tool's behavior changes; the registry carries a `REGISTRY_VERSION`.

---

## 2. Total policy_version + matched_rules

### 2(a). Definitions (exact)

A **decision record** is a record that **adjudicates**: it allows,
denies, queues, approves, rejects, refuses, escalates, or resumes/halts.
Concretely, the covered families are:
- every executor verdict-path entry (`tool_call` events: allow / deny /
  queued / refused / pre-evaluation structural refusals / tier
  escalations / approved executions),
- every approval-subsystem decision entry (`approval_decision`,
  `approval_decision_attempt`, `approval_delegated`, `quorum_vote`,
  `quorum_finalized`, batch outcomes, break-glass outcomes),
- recovery decisions (`resume_or_halt_decision`, `resume_refused`),
- load-gate decisions (`artifact_load_refused`),
- every provenance record (`gov/provenance.py`).

Boundary, stated plainly: operational audit *events* that do not
adjudicate anything — session open/close, checkpoints, lock-refusal
coalescing counters, ledger appends — are not decision records and
carry no adjudication fields. The gate test asserts the covered
families, not the whole log.

**Total** means: every decision record carries
- `policy_version`: a non-empty string naming the rule set / framework
  version that governed the decision, and
- `matched_rules`: a list of strings — the ids of the rules that fired,
  in evaluation order.

`matched_rules` may be empty **only** when no rule of a policy engine
determined the outcome: structural refusals (identity/lease/delegation
fail-closed), human decisions (approval outcomes name the *queuing*
rule — see below), and governor decisions (policy changes, recovery).
A policy-engine verdict **always** has non-empty `matched_rules`:
`[rule_id]`, or the reserved sentinel `["default_deny"]` when the
fail-closed default fired. The sentinel is documented, not hidden.

`policy_version` values by record family (stated exactly):
- engine verdicts (executor `tool_call` path): the policy file's
  `version:` top-level (`PolicyEngine.policy_version`; default.yaml is
  `"2"`; missing version stamps `"unversioned"` — honest, never blank).
- approval outcomes: the `policy_version` stored on the ticket at queue
  time (the engine version that produced the queuing verdict), propagated
  to the decision record; fallback `"approvals-d1"`.
- approval queuing rule: the ticket also stores the queuing verdict's
  `matched_rules`, so an approval outcome's `matched_rules` truthfully
  names the rule that queued it (fallback `[]` for tickets queued before
  this wave or by non-engine paths).
- recovery decisions (`resume_refused`, resume records):
  `"recovery-v1"`, `matched_rules=[]` (human/governor decision).
- load-gate decisions (`artifact_load_refused`):
  `"supplychain-w78"`, `matched_rules=[]` (digest rules, not policy
  rules — the pinset has artifact ids, not rule ids).

### 2(b). The build gate (what "fails the build" means)

`tests/test_w79_totality.py` is the totality gate, in the canonical suite:
- every executor verdict-path entry (allow / deny / queued / refused /
  pre-evaluation structural refusals) carries both fields with the exact
  types;
- engine verdicts always carry non-empty `matched_rules`;
- approval outcome, recovery decision, and load-gate decision records
  carry both fields;
- provenance validator negative tests: a record missing either field is
  refused (already enforced since wave-73; the gate pins it).

A decision record missing either field is a **build failure**, not a
warning. Where this collided with legacy record types, the schema was
upgraded — no carve-outs. (One honest boundary: third-party adapter
surfaces that re-emit our records verbatim are out of scope; the records
they emit are ours and already stamped.)

### 2(c). Anti-games (break-first)

- **Spoofed matched_rules:** the engine computes `matched_rules` from the
  evaluation it just ran; the executor stamps the decision object, not
  caller input. A probe injects a forged `matched_rules` kwarg into the
  call path and asserts it is ignored/overwritten.
- **Omitted rules:** the verdict entry's `matched_rules` comes from the
  `PolicyDecision`; dropping a fired rule id is structurally impossible
  without editing the engine (governed).
- **Missing policy_version:** provenance validator refuses; the gate test
  asserts every audit decision entry carries it.

---

## 3. Pre-commit validation for irreversible actions

### 3(a). What counts as irreversible (classification procedure, exact)

A tool is **irreversible** iff the executor cannot restore the pre-call
state with any inverse operation it possesses (the "no inverse" test),
**or** the call's effects leave the trust boundary (the "external
effect" test). Classification is operator-declared at registration in
`gov/precommit.py::IRREVERSIBLE_REGISTRY`; the tests are documented per
tool. The registry:

| tool            | class           | why irreversible                          | preview kind |
|-----------------|-----------------|-------------------------------------------|--------------|
| delete_file     | destructive     | no undelete; no inverse                   | diff (path)  |
| send_email      | external-effect | leaves the boundary; no recall            | dry-run      |
| http_post       | external-effect | leaves the boundary; no recall            | dry-run      |
| install_package | external-effect | environment mutation; no governed uninstall | dry-run    |

`read_file`/`api_call` are reversible reads (their exfiltration risk is
the read-before-send/DLP lane, not irreversibility); `write_file` is
reversible (overwrite/restore). A tool that is unflagged but behaves
irreversibly is a **classification gap**: the probe
(`redteam.rules_w79.unflagged_irreversible_executes`) must expose it,
and the fix is reclassification — filed honestly, never silently
patched.

### 3(b). The pre-commit protocol (gate, not undo)

No "undo" is built — the memo's direction is gate, not undo. Before an
irreversible tool executes:

1. **Preview.** `PrecommitGate.preview(tool, args)` returns a preview
   descriptor: `{preview_id, tool, args_digest, summary}` where
   `args_digest = sha256(canonical(tool, args))`. For `delete_file` the
   summary is the target path (the diff); for sends, endpoint/recipient +
   payload-shape summary (never raw secrets — redaction rules apply).
2. **Human approval bound to the exact preview.** The approval ticket
   binds `(preview_id, args_digest)` and is **single-use**.
3. **Commit.** `PrecommitGate.commit(approval, tool, args, execute)`:
   recomputes the digest over the *actual* (tool, args) about to execute
   and compares to the approval's bound digest. Mismatch → `refused`
   (`precommit_preview_mismatch`: approved preview A, executed B).
   Approval replay (approval for A reused for B) → same refusal, plus
   the single-use ticket is consumed on first commit.

Executor wiring follows the wave-78 opt-in gate pattern:
`ToolExecutor(..., precommit_gate=gate)`. When the gate is installed,
on the verdict path after policy evaluation:
- verdict **allow** on a registry tool without a bound, unused approval
  for the exact (tool, args) → denied fail-closed (`decision: denied`,
  `policy_id: precommit-required`), before the tool executes;
- verdict **require_approval** → queued as usual; the queue's MAC-bound
  human approval (F38) is the human moment on this path, and
  auto-approve is disabled for registry tools while the gate is
  installed (the human moment must be real);
- verdict **deny** → unchanged.
The production recommendation is gate-on; the default is off so existing
suites pin behavior explicitly.

### 3(c). The registry is policy-grade

`IRREVERSIBLE_REGISTRY` is frozen at import. There is no public mutator.
Reclassification (add/remove/alter) requires the **wave-75 governed
policy-change path**: a `policy_change` provenance record with status
`applied`, verified through `gov/policy_change.py`, whose change body
names the registry mutation. `PrecommitGate.apply_governed_change`
verifies the applied record and only then mutates. A probe attempts the
bypass (direct mutation / forged applied record) and asserts refusal.

---

## 4. What this wave does NOT do (boundaries)

- No undo/rollback for irreversible actions (memo: gate, not undo).
- No sterile-window or canary-density enforcement (deployment config).
- No new tools, no new adapters, no commercial evidence pipeline (the
  evidence bet is strategic context, not a build license).
- The trifecta floor does not override policy `deny`, and does not apply
  to tools without the `external_comm` axis.
- P8 remains UNCOVERED-by-design; P13 PARTIAL-by-design.

## 5. Verification

- Unit: `tests/test_w79_rules_tiering.py` (classification, tier
  computation, composition, floor override), `tests/test_w79_totality.py`
  (the build gate), `tests/test_w79_precommit.py` (protocol, mismatch,
  replay, governed mutation).
- Break-first: `evals/w79_probes.py` + `redteam.rules_w79.*` registry
  entries — trifecta evasion (single-tool, multi-tool, cross-hop,
  mislabeled), matched_rules games (spoof/omit/missing), irreversible
  bypass (unflagged tool, preview mismatch, replay, governed-change
  bypass).
- Gates: canonical suite → registry gate → adversary matrix → realistic
  battery, sequential.
