# Stream 3 — F136 independent review (2026-09-23)

Reviewer: stream-3 subagent. Main tree NOT modified; all work prototyped in
`workstreams/redteam/f136/` with the main tree imported read-only.

## Task

F82 was confirmed already CLOSED in the tree (FINDINGS.md: "CLOSED
2026-09-22"; NFKC normalization + U+3002 delimiter present in
`gov/adapters/trust.py`), so per the task brief I moved to the next open
item: **F136 (MEDIUM, OPEN)** — review the egress-wall threat-model
residuals against the closure standard. Closed findings (F81, F137, F135)
were not re-litigated.

F136 close criteria (from FINDINGS.md): *"a governed launcher exists, the
wall's components are pinned/digest-verified like other loadables, and the
residual threat model is documented in the sandbox spec."*

## Verdict recommendation: **CLOSE F136**

All three criteria are met in substance; an independent adversarial battery
(7 probes, disjoint from the S7 battery) found **no BREAK** — every closure
property held, and every tested residual (R7/R9/R10/R11) proved real and
accurately documented. Two companion doc-sync edits and one non-blocking
code fix should land with the closure (deltas below); none of them re-opens
the finding.

## Evidence

Independent battery `workstreams/redteam/f136/f136_review_probes.py`
(hermetic, $0, no network; run with
`TMPDIR=/tmp/gov-run-f136 ~/workspace/.gov-venv/bin/python
workstreams/redteam/f136/f136_review_probes.py`):

| probe | verdict | meaning |
|---|---|---|
| control_fresh_launch | CONTROL | fresh wall launches; child runs |
| repin_attack | RESIDUAL-CONFIRMED | R10 is real (see below) |
| run_child_large_output_deadlock | BUG | genuine availability defect, fail-hung not fail-open (see below) |
| wall_death_child_survives | RESIDUAL-CONFIRMED | R7 is real; new launches still refuse |
| child_direct_connect | RESIDUAL-CONFIRMED | R9 is honest: sim proves the launcher, not the topology |
| preexec_reverifies_chain | CLOSED | check() re-verifies the full digest chain; child_recheck() refuses after tamper — the preexec re-assert closes verify→spawn component tamper, not just liveness (a property the S7 battery never pinned; the design is tighter than it first appears) |
| launch_then_tamper_use | RESIDUAL-CONFIRMED | R11 sharpened: post-launch tamper is live-exploitable by the running child (proxy + DNS re-read their files per request); the *next* launch refuses `component_tampered` — pinning is launch-time only |

Summary: `BUG=1 CLOSED=1 CONTROL=1 RESIDUAL-CONFIRMED=4`, F136-REVIEW: GREEN
(zero BREAK / zero ERROR).

unittest subset `workstreams/redteam/f136/test_f136_review.py` (repo has no
pytest installed and none in requirements.lock; repo convention is stdlib
unittest via `tests/run_tests.py`):
`4/5 pass, 1 fails BY DESIGN` — the failing test is the red P2 defect
demonstration (`test_run_child_large_output_deadlock`); it passes once the
fix below lands. Existing related suite `tests.test_s7_egress_launcher`:
**20/20 OK** (no regressions; main tree untouched).

## Criterion-by-criterion review

1. **"A governed launcher exists"** — MET. `gov/egress_launcher.py` (1327
   lines): receipt→manifest→component chain verification under an
   interprocess lock, wall-state UP check, spawn with child-side preexec
   re-assert (exit 99 abort), proxy-env scrubbing, audit chaining. S7
   battery 16 CLOSED / 5 CONTROL / 0 BREAK; unit tests 20/20. My P6 probe
   additionally confirmed the preexec re-assert re-verifies component
   digests (via `check()` → `_pinned_ruleset_digest()` →
   `inventory.verify()`), so the verify→spawn component-tamper window is
   closed down to the documented R7 nanosecond sliver.
2. **"Pinned/digest-verified like other loadables"** — MET in substance.
   sha256+sha512 pins, strongest-common-algorithm negotiation, no silent
   downgrade, symlink-shape checks, tamper→refuse on every component
   (S7 battery covers all six + manifest/receipt). Matches the S5
   tool-definition digest-pinning precedent. One honest asymmetry (below):
   re-pinning requires no authorship token, unlike `gov/load_gate.py`'s
   Ed25519-signed pin mutations — documented as procedural R10, suggested
   as hardening follow-up, not a blocker.
3. **"Residual threat model documented in the sandbox spec"** — MET in
   substance, weak in wiring. `docs/egress_wall_threat_model.md` documents
   R1–R11 + non-goals thoroughly and accurately (my probes confirm the
   tested ones are real, not paper). But **nothing references the doc
   except the launcher's own docstring** — `docs/DEPLOYMENT.md` (the
   sandbox/deployment spec) does not link it, and DEPLOYMENT.md:32 is
   stale: it still says "**No filtered-egress / destination-allowlist
   mode** (finding F81, OPEN)" while F81 is CLOSED (validated-by-lab,
   2026-09-23). Companion doc-sync edits below close this wiring gap.

## Residual-by-residual (R1–R11) assessment

- **R1/R5 covert channels + stego through allowlisted destinations** —
  accepted boundary; destination filter ≠ content filter; mitigation
  assigned to `gov/dlp.py` + volume budgets. Not a closure blocker.
- **R2 no DNSSEC** — deployment requirement documented. Accepted.
- **R3 proxy/DNS are TCB** — on-disk tamper pinned; runtime memory
  compromise out of scope, deployment requirement (isolated UIDs,
  monitoring) documented. Accepted.
- **R4 host root** — outside the agent threat model, stated. Accepted.
- **R6 allowlist operator error** — pins bytes not wisdom; policy-change
  discipline referenced. Accepted.
- **R7 TOCTOU / no lifetime re-check** — CONFIRMED REAL by probe
  (child survives wall death; new launches refuse). Heartbeat re-verify
  documented as deployment requirement. Accepted as documented.
- **R8 child-side resolution inputs** — keep read-only, documented. Accepted.
- **R9 sim is a mechanism model** — CONFIRMED HONEST by probe (sim child
  port-scans loopback and reaches the origin directly; no IP-layer
  containment in the sim). Topology was lab-proved; topology changes need
  a new lab run. Accepted.
- **R10 receipt custody** — CONFIRMED REAL by probe: widened allowlist +
  re-run `install()` → verifies + launches cleanly. The receipt is
  `sha256(manifest bytes)` — self-consistent, not operator-anchored; the
  launcher cannot distinguish operator re-pin from attacker re-pin. This
  is exactly what R10 says; the procedural custody requirement is the
  load-bearing control. Accepted as documented, with the hardening
  follow-up below.
- **R11 launch-time pins** — SHARPENED by probe: because the stub
  proxy/DNS re-read their files per request, tamper-after-launch is
  *live-exploitable by the already-running child* with zero new launches;
  the next launch refuses `component_tampered` (loud, but after the
  exfil). The threat model says "not detected until the next launch" —
  accurate; recommend adding one sentence stating the live-exploit
  consequence explicitly (delta below).

None of R1–R11 re-opens the deployment gap F136 was filed for (no
launcher, no pinning). They are genuine accepted boundaries.

## Deltas for central integration

### D1 (required with closure): DEPLOYMENT.md doc-sync
- Line 32 sandbox row: replace "**No filtered-egress /
  destination-allowlist mode** (finding F81, OPEN)" — F81 is CLOSED
  (validated-by-lab 2026-09-23); the row should describe the
  productized filtered-egress wall (`gov/egress_launcher.py`) and link
  `docs/egress_wall_threat_model.md` (this is the criterion-3 wiring).
- Add the cross-reference to the threat model from the sandbox row.

### D2 (required with closure): threat-model one-liner for R11
In `docs/egress_wall_threat_model.md` R11, add: "Because the proxy and
confined resolver re-read their config files per request, a component
tampered after a child's launch is live-exploitable by that running
child without any new launch; the tamper is caught loudly
(`component_tampered`) at the next launch — after the fact."

### D3 (non-blocking defect): `run_child` large-output deadlock — LOW
`gov/egress_launcher.py::FilteredEgressLauncher.run_child` pops
`capture_output` into `capture` (line 1293) but then branches on
`popen_kw.get("capture_output")` (line 1301, always None post-pop), so
with `capture_output=True` it takes `proc.wait()` with stdout=PIPE and
**deadlocks once the child writes past the 64KB pipe buffer**.
Fail-hung, not fail-open (availability defect in the launcher API; the
S7 battery never caught it because its children print bytes). One-line
fix prototype for central integration:
```diff
-        if popen_kw.get("capture_output"):
+        if capture:
             out, err = proc.communicate(timeout=30)
             rc = proc.returncode
```
Red-test evidence: `test_run_child_large_output_deadlock` in
`workstreams/redteam/f136/test_f136_review.py` FAILS before, passes
after. Does not block F136 closure (fail-closed posture unaffected).

### D4 (hardening follow-up, suggest LOW candidate — do NOT consume F138
unilaterally): wall re-pinning has no authorship bar
`WallComponentInventory.install()` is a bare function call — no Ed25519
authorship token, no approval, no provenance chain — while
`gov/load_gate.py::ArtifactPinset.pin` (wave-78) requires a roster-human
Ed25519 authorship token with chained `artifact_pinned` records for the
same class of operation (pin mutation). R10's procedural receipt-custody
rule is the current control; adopting load_gate-style signed re-pinning
for wall components would retire the procedural caveat and make
criterion 2 hold without qualification. Recommend filing as a LOW
hardening finding at central triage.

## Notes / caveats

- pytest is not installed in `~/workspace/.gov-venv` and is not in
  `requirements.lock`; the repo's canonical runner is
  `tests/run_tests.py` (stdlib unittest). All verification above used
  the venv python with unittest + standalone probe scripts, per repo
  convention.
- Pre-created distinct TMPDIRs per run (`/tmp/gov-run-f136`,
  `/tmp/gov-run-f136b`); broad runs were sequential.
- No commits made; main tree untouched. Proposed FINDINGS.md delta for
  central integration: append to F136 — "Status: CLOSED 2026-09-23 —
  independent review (stream 3): 7-probe battery GREEN, 0 BREAK;
  closure properties verified incl. preexec re-verification of the
  component chain; R7/R9/R10/R11 confirmed real and accurately
  documented; companion deltas D1–D3 landed; D4 filed as hardening
  follow-up."
