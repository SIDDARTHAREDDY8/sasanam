# Bernstein monthly sweep — wave-338 lane 6 (R7)

- **Sweep date:** 2026-10-05 (~08:20 UTC / 04:20 EDT)
- **Access date for all web claims:** 2026-10-05
- **Prior pass:** 2026-10-05 (earlier same day). That pass found: ~244-change
  pile since v3.20.0, v3.21.0 milestone (due 2026-10-04) slipped, two HIGH
  advisories (GHSA-xw82-w5hr-hrm2, GHSA-4r8r-jx5c-w954) fixed in #6404,
  governance PR #5990's backlog window expiring 2026-10-05 12:00 UTC.
- **Method:** primary sources only (release notes, GitHub API, raw files).
  $0 spend. Our tree checked at
  `/home/hatch/workspace/agent-governance-demo/agent-governance-demo-main`
  (no .git; grep only).
- **License:** re-read 2026-10-05 — unchanged. Standard Apache License 2.0,
  "Copyright 2026 Alex Chernysh". No new terms, no NOTICE additions.
  (https://raw.githubusercontent.com/sipyourdrink-ltd/bernstein/main/LICENSE,
  accessed 2026-10-05)

## 1. Releases — v3.21.0 LANDED since the prior pass

**v3.21.0 is now published.** The prior pass saw the milestone slip; the tag
has since shipped:

- Tag: `v3.21.0`, release id 403434565, `draft: false`, `prerelease: false`.
- Tag/release object created `2026-10-04T21:50:33Z`; **published
  `2026-10-05T06:42:53Z`** (i.e. ~1.5h before this pass, after the prior
  pass's observation window).
  (https://api.github.com/repos/sipyourdrink-ltd/bernstein/releases/tags/v3.21.0,
  accessed 2026-10-05)
- Release notes: "Two hundred and forty-four changes since v3.20.0; read the
  two advisories first." Cut via `chore(release): v3.21.0` #6405, on top of
  the security fix #6404.
  (https://github.com/sipyourdrink-ltd/bernstein/releases/tag/v3.21.0,
  accessed 2026-10-05)
- Assets: wheel + sdist + CycloneDX + SPDX SBOMs, all uploaded by
  github-actions[bot] with sha256 digests. Zero downloads at pass time.

**Milestone hygiene signal (WATCH):** the **v3.21.0 milestone is still OPEN**
with **35 open / 19 closed issues**, due_on 2026-10-04 (past due). They shipped
the release with 35 milestone issues unresolved and never closed the
milestone. Their own #6094 (2026-09-20) redefined milestone dates as
"planning targets, not commitments" — consistent, but the open-milestone
shipped release means the milestone no longer gates anything.
(https://api.github.com/repos/sipyourdrink-ltd/bernstein/milestones?state=open,
accessed 2026-10-05)

No v3.22.0 milestone exists yet in the open list (next dated milestones:
volunteer-workers MVP due 2026-10-15, agent-authority due 2026-10-31).

## 2. Security advisories — two HIGHs cited but NOT publicly retrievable

The v3.21.0 notes open with: "read the two advisories first":

- **GHSA-xw82-w5hr-hrm2** (high, reported privately): "An agent could write
  its own identity record and be believed; an empty `<task>.approved` file
  passed for an operator's decision."
- **GHSA-4r8r-jx5c-w954** (high, reported by @Trenyx): "Workflow commands ran
  repository text in untrusted workspaces, a claim took its role from the
  request, and a receipt verified against whatever key it carried."
- Both "Fixed in #6404; every version through 3.20.0 is affected."

**Discrepancy:** as of 2026-10-05 ~08:20 UTC, **neither GHSA ID resolves**:
`https://github.com/sipyourdrink-ltd/bernstein/security/advisories/GHSA-xw82-w5hr-hrm2`
→ 404; `.../GHSA-4r8r-jx5c-w954` → 404; the global
`https://github.com/advisories/GHSA-xw82-w5hr-hrm2` → 404; and the repo's
advisory index lists only 10 advisories, newest GHSA-594x-5h3g-wj34 (Sep 10,
2026) — the two October HIGHs are absent.
(https://github.com/sipyourdrink-ltd/bernstein/security/advisories, accessed
2026-10-05)

So the release notes say "read the two advisories first" while the
advisories are not publicly readable — likely still private/draft or
publication-delayed. For a project whose brand is "records that verify,"
shipping a release whose headline instruction points at unpublished
advisories is a process gap worth watching (does the fix detail in #6404
adequately substitute? — #6404's title: "authenticated identity and approval
records, role-bound claims, trusted-workspace commands, git-dir-only docker
mount"). No NEW advisories beyond these two were found this pass.

**#6404 fix shape (from the release notes' "Before → Now" table):** identity
records now carry a MAC keyed outside the workdir; gates take only signed,
nonce-bound decisions; token scope checked everywhere; workflow nodes need a
trusted workspace; claims are role-bound; receipts need a pinned key; docker
mounts only the git dir. The identity/record trust boundary was the
softest part of their model — an agent-written identity record being
believed is close to our own threat surface (agent identity). WATCH their
MAC-keyed-outside-workdir design when our identity work next moves.

## 3. Governance / quorum — the #5990 window closes today 12:00 UTC

Facts:

- #5990 ("governance: backlog window — maintainer approval alone meets the
  ordinary quorum until 2026-10-05") **merged 2026-09-24T15:24:44Z**
  (commit 675a386c). Window: `BACKLOG_WINDOW_ENDS = 2026-10-05 12:00 UTC`.
  At pass time (~08:20 UTC) the window is still live; **~3.7h remain**.
  (https://api.github.com/repos/sipyourdrink-ltd/bernstein/pulls/5990,
  accessed 2026-10-05)
- **Follow-up removal has NOT landed:** `BACKLOG_WINDOW_ENDS` is still in
  `scripts/quorum_check.py` on main (line 232), with the comment "After the
  date this constant is dead code and the branch below goes with it."
  Expected — the window hasn't expired yet — but it means the promised
  cleanup is still pending and becomes overdue at 12:00 UTC today.
  (https://raw.githubusercontent.com/sipyourdrink-ltd/bernstein/main/scripts/quorum_check.py,
  accessed 2026-10-05)
- The sibling adoption rule #5996 ("adopted pull requests merge as the
  maintainer's own change until 2026-10-05", `ADOPTION_ENDS` = same instant)
  is also still live in the same file (line 154).
- **The window worked as a drain:** open PRs are now **60**
  (https://api.github.com/search/issues?q=repo:sipyourdrink-ltd/bernstein+type:pr+state:open,
  `total_count: 60`, accessed 2026-10-05), down from "over a hundred" on
  2026-09-18 (#5990 body). But 60 PRs remain with under 4h of window left —
  expect a merge burst before 12:00 UTC, then the ordinary two-approval
  quorum snaps back with the same 4 core reviewers (each carrying 40–80
  open review requests per the Sept baseline). **Strain signal: the backlog
  re-accumulates the moment the window closes unless reviewer capacity
  changed — nothing in the tree indicates it did.** No new maintainers
  visible; contributor growth is all external (8 first-time contributors in
  v3.21.0: @xuu33030, @shreyanshj10, @NiteeshGowda72, @Aninda7479,
  @laotoutou, @anishhongekar47-dev, @AyushVUpadhye, @EY3G0R3).
- Repo pushed at 2026-10-05T07:51:27Z — active to within the hour; e.g.
  #6411 (antigravity→agy adapter key fix) opened 2026-10-05T07:43:36Z.
- Open issues: 262. Stars: 1397 (vs 1295 in mid-September search snapshots —
  ~+100 in ~3 weeks). Forks: 177.

**Watch item for next sweep:** whether the BACKLOG_WINDOW_ENDS /
ADOPTION_ENDS cleanup lands promptly after 12:00 UTC, and whether open-PR
count climbs back over ~100 within two weeks (the structural strain
returning).

## 4. Honesty-mechanics inventory (v3.21.0 notes) with steal verdicts

Verdict scale: STEAL (build it) / ADAPT (take the class, reshape to our
architecture) / WATCH (monitor) / SKIP (have it, N/A, or process-only).
Tree-checks below are against
`/home/hatch/workspace/agent-governance-demo/agent-governance-demo-main`.

### STEAL

1. **#6010 — unit tests block DNS (`socket.getaddrinfo` blocked, DNS guard
   test).** Our `tests/` has no hermeticity guard; the five test files that
   touch `socket.` are the network-machinery tests themselves (legitimate),
   but nothing stops the other ~575 test files from phoning home. Small,
   high-value: block `getaddrinfo` in the unit-test harness with exemptions
   for the network-machinery tests. (One-line reason: our suite is big
   enough that silent network dependence is a matter of time.)
2. **#5721 — bounded waits use a monotonic clock.** `gov/egress_proxy.py:796-797`
   runs `deadline = time.time() + timeout; while time.time() < deadline:` —
   wall-clock deadline, vulnerable to clock jumps. Replace with
   `time.monotonic()`. (One-line reason: a wait that can be shortened by an
   NTP step is a wait that lies.)
3. **#4645 — dead-code gate: a `core/` module nobody imports fails CI, and
   the allowlist can only shrink.** We have no import-reachability /
   vulture gate; `gov/` holds hundreds of modules. (One-line reason:
   unowned code is where the next confused-deputy hides.)
4. **#6371 — batch builder returns only verifiable payloads; redact failure
   reasons.** Our evidence-bundle builders (`gov/bundle_*.py`) should be
   checked against the same contract: never emit a bundle containing a
   payload the verifier cannot verify, and failure reasons stay out of the
   artifact. (One-line reason: an unverifiable member poisons the whole
   bundle's claim.)

### ADAPT

5. **#6363 — bench-verify contract: one result per task, score+verdict
   cross-check, Ed25519 signature check; stop signing mock verdicts.** Take
   the contract into our in-flight offline-verifier track (wave-310):
   a bundle verifier that refuses bundles with duplicate/missing task
   results or score/verdict mismatch. Note: our `mock-set-*`
   `signedEntryTimestamp` lives inside an explicitly test-only mock
   (`mock_rekor_transport()`, `gov/anchor_adapter.py:271`) — correctly
   segregated, but worth a "never wired in production" pin.
6. **#5464 — cost per verdict in bundles; `--budget` stops with refusal
   receipts.** Our `evals/realmodel_harness.py` already has hard spend caps
   and loud refusal ("never a silent skip", line 262) — ahead on the
   refusal half. Missing: recording the cost ON each verdict/result record.
   (One-line reason: the spend ledger exists; the per-verdict receipt
   doesn't.)
7. **#6051 / #6063 — refusal-to-fabricate: a run that cannot say who served
   the model refuses rather than gaining a made-up vendor name.** Our
   `gov/kms.py` already raises on unknown provider (good); check the
   real-model driver and adapter registry for any default/inferred provider
   naming on unidentified models.
8. **#6137 — non-interactive approval gate records refusals.** We have
   machine-coded ceremony refusals (`gov/approval_ceremony.py:59`) — check
   that non-interactive paths record refusal artifacts with the same
   durability as approvals, not just log lines.
9. **#5441 — `doctor --unattended` probes like the spawner (probe-environment
   parity).** Our batteries pin `GOV_DEPLOYMENT_MODE=staging` (wave-95
   lesson); the class to adopt is a check that probe harnesses run under
   production-equivalent conditions, never a cushier one.
10. **#5948 — policy precedence proven by test in both insertion orders
    (DENY beats IMMUNE regardless of order).** Adopt order-independence
    testing for our policy/admission precedence rules.
11. **#5920/#5951/#5952/#5954-class — tests must not read state a neighbour
    left behind.** We carry this as convention (AGENTS.md: fresh unique
    TMPDIR per run, wave-112/134/173 lessons) but have no automated check.
    A hermeticity test (fail on cross-test state reads) would turn the
    convention into a gate.
12. **#5852 — signed recall receipts (memory recall is receipted).** Our
    memory/agent-recall paths have no receipt concept; a recall receipt
    (what was recalled, for which decision) is a strong honesty primitive
    for agent memory.
13. **#5443 — archive manifest hashes every member and is verifiable.** Our
    bundle envelope has digests (`gov/bundle_envelope.py`) and a standalone
    verifier; verify member-level hashing is complete (no member covered
    by count alone).
14. **#5069-class — per-run "not covered" panel.** We have the static
    honesty (STANDARDS_MAPPING.md:70 lists what's not covered; FINDINGS.md
    residuals per finding) but no per-run/per-gate panel enumerating what
    the run did NOT cover. Consider adding to gate output.
15. **#6402 — policy limits make no network call without a configured
    endpoint.** Check our policy-limit paths fail closed on unconfigured
    endpoints rather than defaulting.
16. **#6282 — collusion check at admission.** Our `gov/admission.py` exists;
    check whether cross-task collusion is screened at admission time.
17. **#6370 — label honesty: record an approval, not a refusal, when
    approve-on-timeout approves an expired review.** Audit our
    approve-on-timeout paths for mislabeled outcomes.
18. **#6020 — do not record transient host resource exhaustion as findings.**
    Signal-vs-noise discipline for anything we record as quarantine/
    security findings.
19. **#5964 — spawn prompts name the server the run started.** Check our
    spawn prompts carry run provenance.
20. **#6056-class — a crash is reported as a crash (by exit status), never
    as a pass/skip.** Our `tests/run_tests.py` runs in-process via
    unittest; adopt the class for our subprocess-based helpers (evals
    runners, lane harnesses): distinguish crashed / failed / skipped in
    every report.

### WATCH

- **#6339** — they reverted a test that "probed hook and filter
  configuration on the checkout under test": testing the test
  infrastructure against itself is a known-good instinct; watch whether
  they re-land it in a safer form.
- **#5448** — gate-evasion corpus "catches two of eight known evasions":
  honest about the 6/8 gap. Their evasion-coverage honesty is the benchmark
  for our own break-battery reporting.
- **#6239** — "published identifiers must resolve": scope unclear from the
  fragment title alone (docs identifiers?); watch the PR for the exact
  mechanism before judging.
- **#6073 / #6075** — CI ancestry/SHA verification before checkout
  (coverage-ratchet proves `head_sha` is an ancestor of main;
  `workflow_run` SHA verified before checkout): CI-specific; relevant only
  if our CI story grows.
- **#5505** — orphan security module needs an issue or an expiry: process
  hygiene; revisit if our `gov/` module count keeps growing.
- **#6097** — watchdog stays down after a deliberate stop: deliberate-stop
  semantics; check ours when the watchdog next moves.
- **#6392** — run receipts as COSE_Sign1: standard envelope for receipts;
  consider when our receipt format next changes (currently bespoke
  Ed25519).
- **#6254** — signed pass receipts over the batch ledger: check our batch
  paths receipt passes.
- **#5442** — all 31 metric streams have a declared schema: schema-declared
  telemetry; low priority for us.
- **Post-window quorum behavior** (§3 above): the structural question for
  the next sweep.
- **Advisory publication** (§2 above): whether the two HIGH advisories
  become publicly readable and match #6404's scope.

### SKIP (already have / N/A / process-only)

- **#5569-class ("no row claims coverage without a test")** — already have,
  predating theirs: our B3 matrix (docs/STANDARDS_MAPPING.md, Wave-39)
  requires an adversarial-probe column per claimed control ("unit tests
  alone do not qualify") enforced by tests/test_b3_matrix.py.
- **#6328 (tool calls record an effect digest)** — have:
  `gov/action_capsule.py` already emits `effect_digest` alongside
  `capsule_digest`/`verdict_digest`.
- **#6223 (C2PA disclosure)** — have: evals/c2pa_provenance_probes.py.
- **#5117 (reconcile --explain names the layer)** — have: decision-code
  taxonomy names the deciding layer.
- **#6367 (volunteer adapter-before-claim), #6360 (deep-research egress),
  #5965 (MCP scoping for spawned agents)** — product-surface we don't
  have; N/A.
- **#6308 (claim comment ≠ assignment), #6273 (contributor recognition)**
  — contributor-process; not product.
- **#6094 (milestone dates are planning targets)** — already reflected in
  their behavior (§1); nothing to steal.

## 5. Competitive read (one breath)

Bernstein shipped v3.21.0 (244 changes, two HIGH identity/approval
advisories, published 2026-10-05T06:42:53Z) but left its milestone open with
35 issues and its two headline advisories unpublished; the #5990 quorum
window drained the PR backlog from 100+ to 60 and expires today 12:00 UTC
with no reviewer-capacity fix behind it — expect the strain to return.
Stars 1295→1397 in ~3 weeks; 8 new external contributors, still a solo
maintainer. Their honesty-mechanics program (the thing we mine) keeps
deepening: the stealable core this month is test-hermeticity (DNS block,
no neighbour-state reads, dead-code gate), monotonic-clock waits, and
verifiable-only bundle builders — all small, all in our threat surface.

## 6. Verdict counts

- STEAL: 4 (#6010 DNS-block unit tests; #5721 monotonic waits —
  gov/egress_proxy.py:796-797 is the concrete instance; #4645 dead-code
  gate; #6371 verifiable-only bundle payloads)
- ADAPT: 16 (bench-verify contract, per-verdict cost, refusal-to-fabricate,
  refusal artifacts, probe parity, precedence order-independence, test
  hermeticity check, recall receipts, member-hash completeness, per-run
  not-covered panel, endpoint-configured policy limits, admission collusion
  check, timeout label honesty, transient-noise discipline, spawn provenance,
  crash-as-crash reporting)
- WATCH: 10 · SKIP: 7

---

*Report: wave-338 lane 6 (research scout A). All web citations accessed
2026-10-05. No commits made. REPORT AND STOP.*
