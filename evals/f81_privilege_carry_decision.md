# F81 privileged rerun — v2-carry decision (Wave-113 LANE 3, 2026-09-26)

**Decision: CARRY.** The real privileged re-run of `evals/f81launcher_privileged.py`
was attempted and is genuinely blocked. F81's status in the tree is NOT changed by
this lane (see the recorded-status note below — the lane brief and the tree disagree,
and a subagent lane does not unilaterally flip a finding status).

## What was attempted (exact failure evidence)

1. **Read the F81 entry and close-when bar.** The bar (FINDINGS.md wave-96 entry):
   "the close bar ("a real wall + deployment probes" passing) still needs the genuine
   privileged run on f81-lab/privileged CI" — i.e. `evals/f81launcher_privileged.py`
   (10 close-when probes + 1 control: governed control, wall-down refusal, helper
   tamper refusal, ruleset drift refusal, child netns placement, allowlist/block/
   direct-egress end-to-end, live seccomp, prefix-strip audit visibility, audit
   verification procedure, unauthored pin refusal, preexec_abort_on_flap) running under
   real privilege with `GOV_F81_PRIVILEGED=1`, root, `ip`, `nft`. A skip-clean run
   (probes skipped for lack of privilege) does NOT count.

2. **Recovered candidate VM IPs from browser-task snapshots** (TOOLS.md route:
   `~/workspace/.hatch-browser/snapshots/browser-task:*/**/ax.json`, IP-looking
   strings). Newest task dirs are dated 2026-09-24 (no browser snapshots exist from
   today). Candidates:
   - `34.28.10.155` — task `0d7346e7-8bd9-46bf-a701-67274d00fb3a` (2026-09-24; this
     task's snapshots show the GCP console serial-port page for `f81-lab`, i.e. the
     wave-98 session).
   - `34.16.52.219` — task `2952695e-3331-4b8d-a516-8da0193f4b94` (2026-09-23).

3. **SSH attempts (explicit key per TOOLS.md, `~` resolves to /root here):**
   ```
   timeout 15 ssh -i /home/hatch/.ssh/id_ed25519 -o BatchMode=yes \
       -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
       root@34.28.10.155 'echo SSH_OK; hostname'
   ```
   Result for **both** IPs, verbatim:
   `Connection timed out during banner exchange` /
   `Connection to 198.19.0.1 port 3128 timed out`
   (tried with the root user; the timeout happens at banner exchange, before any
   user auth — the `hatch` user would hit the same wall).

4. **Control check (SSH egress itself is healthy):**
   `ssh -F /home/hatch/.ssh/config_abs -o BatchMode=yes -T git@github.com` →
   `Hi SIDDARTHAREDDY8! You've successfully authenticated` (rc=0). The egress proxy
   and the key work; the two stale IPs are simply dead — consistent with the VM being
   stopped after wave-98 (standing $0 order: stop the VM after use) and its ephemeral
   external IP being released on stop.

5. **No route to START the VM from this lane:**
   - No gcloud CLI on this machine (`which gcloud` empty).
   - No GCP service-account/OAuth credentials anywhere on this machine (searched the
     workspace and the repo tree).
   - Live-browser operation is unavailable to a depth-2 subagent; the wave-98 start
     route was the GCP console via a browser task (the Sep-24 snapshots are literally
     the console serial-port page for `f81-lab`).
   - No recorded current IP anywhere else: searched `~/workspace/f81-lab-evidence/`
     and `~/workspace/workstreams/f81-launcher/` — nothing.

6. **Local privilege is insufficient (fresh check, 2026-09-26):**
   `ip netns add f81localtest` as uid 0 → `setns: Operation not permitted`, rc=1.
   This container lacks CAP_SYS_ADMIN, so the battery would skip-clean locally —
   which does not count. Same conclusion the wave-96 entry reached.

## Recorded-status note (honest discrepancy — parent adjudicates)

- The **working tree at wave-112** records F81 as **CLOSED since wave-98**
  (FINDINGS.md wave-98 paragraph: "The f81-lab VM was started and
  `evals/f81launcher_privileged.py` ran under genuine privilege (root,
  `GOV_F81_PRIVILEGED=1`, netns `f81test0`) ... the battery re-ran **11/11 CLOSED,
  exit 0, deterministic x2 runs**"; BUILD_LOG wave-98 pushed as `4000791` with
  "F81 CLOSED (privileged 11/11 ×2)"; F148 FILED+CLOSED for the one break the first
  run caught). No later wave re-opened F81 in FINDINGS.md or BUILD_LOG; wave-112's
  F81 sustaining lane (MaxKB shell-break probe) ran under the assumption it is closed.
- The **lane brief** asserts F81 is **LOW/OPEN** and the privileged battery "has NEVER
  run under real privilege" — directly contradicting the tree.
- There is **no durable artifact of the wave-98 privileged run in the tree** — no run
  log, no per-probe output file, only the BUILD_LOG/FINDINGS.md prose claims. So the
  wave-98 closure cannot be re-verified from here even in principle; and waves 99–112
  changed code around these seams (the F148 witnessed-launch fix, the wave-112 evidence
  bundle, the MaxKB sustaining probe), so even a valid wave-98 result no longer covers
  today's tree.
- **This lane did not change the recorded status.** Flipping a finding status on a
  disputed record is a parent decision, not a lane decision. The per-standing-rule
  red-first re-verification of the wave-98 closure is exactly what the rerun was for —
  and the rerun is blocked.

## Rationale for carrying

Not a choice — a genuine block. The only authorized privileged runner (f81-lab,
terminalbench-508900, us-central1-a) is stopped with no live IP, and the only start
routes (GCP console via live browser, gcloud) are outside this lane's tool access.
Local privilege is provably insufficient (EPERM). Faking a run or trusting a skip-clean
run would violate the standing red-first rule. Carry to v2 with the residual stated
explicitly below.

## EXACT residual risk

Two cases, depending on which record is true:

- **If the lane brief is right (no real privileged run ever happened):** the
  `NetnsWallProvider` production path — `ip netns exec agent0 <pinned run_seccomp> …argv`,
  the `filtered_egress` cage mode in `gov/sandbox.py`, `wrap_argv`, the pin-chain
  verification against the live nft ruleset, the child-side preexec wall re-check
  with the F148 witness pipe — has **only ever been proven by sim**. The defect
  classes that only real privilege can expose are unknown: child landing in the host
  netns instead of `agent0`; seccomp helper pin mismatch under a real kernel; live
  ruleset vs pin-ledger divergence that `_normalize_nft_ruleset` misses in practice;
  the F148 witness-pipe semantics under real scheduler timing; the audit
  `egress_wall_launch` record semantics on a real deployment. The launcher is the
  production filtered-egress path; an untested-under-privilege defect here is a
  containment failure, not a feature gap.

- **If the tree is right (wave-98 validated it):** the claim is currently
  **unverifiable** — no run artifact exists, and the code moved since (waves 99–112).
  Under the standing rule ("no wave ships on green tests alone; re-verify closures
  break-first at the public seams"), the F81 closure is an un-audited claim until a
  fresh privileged run re-verifies it.

Either way, the operative fact is the same: **there is no currently valid,
re-verifiable privileged validation of the F81 launcher path on today's tree.**

## Concrete conditions that would reopen / re-run it

1. **Parent (or an eligible browser-capable agent) starts `f81-lab` via the GCP
   console and hands this lane the fresh ephemeral external IP.** Then: copy the
   repo (or `git clone` with `GIT_SSH_COMMAND="ssh -F /home/hatch/.ssh/config_abs
   -o BatchMode=yes"`), `python3 -m venv`, install requirements, and run per the
   battery's own docstring (TMPDIR pre-created with `mkdir -p` — the wave-112 lesson:
   Python 3.12 silently ignores a nonexistent TMPDIR):
   ```
   sudo GOV_F81_PRIVILEGED=1 TMPDIR=/tmp/gov-f81priv <venv>/bin/python evals/f81launcher_privileged.py
   ```
   Record per-probe verdicts in a dated note; stop the VM afterwards with
   `sudo -n /sbin/poweroff` and confirm stopped with 3 consecutive SSH timeouts
   ($0 discipline).
2. **A local root-capable runner** (CAP_SYS_ADMIN + `ip` + `nft` present).
3. **Privileged CI.**
4. On success: evaluate F81's close-when criteria break-first at the battery's public
   seams. On any BREAK: file a new finding (next free finding number: **F173**),
   never quietly patch.

## VM billing state

The VM was **not started by this lane** (it could not be), so there is nothing to stop.
No billing was incurred by this lane.
