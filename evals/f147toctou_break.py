#!/usr/bin/env python3
"""F147 candidate battery: direct-call() symlink-swap TOCTOU vs path_contains_any.

F146 closed the CHECK-time gap: ``Policy._matches`` now evaluates
``path_contains_any`` against the declared path OR the resolved target
(deny on either). The F146 closure documents the deliberate residual:

  "symlink-swap TOCTOU between check-time evaluation and ``_simulate``
   for ``path_contains_any`` (the wave-35 class covers only
   ``path_outside_sandbox`` at use time; the approval path re-resolves
   at use time, so this is the direct-``call()`` path only -- a future
   finding if demonstrated)"

This battery demonstrates it. In ``ToolExecutor.call()`` the policy
verdict is computed at check time (``_context`` resolves the symlink to
whatever it points to THEN). Between the verdict and ``_simulate`` the
pipeline runs the tool-inventory gate, the skill-watch gate, the
deferred-effect scan, trajectory bookkeeping and the write-ahead audit
append -- a real, if small, window. ``_simulate`` re-verifies ONLY
``path_outside_sandbox`` at use time (wave-35); it never re-evaluates the
policy. So: check sees link -> benign (allow), a concurrent flip repoints
the link at the excluded zone, use follows the hostile link. The excluded
zone stays INSIDE the sandbox, so the wave-35 recheck stays False and the
write lands / the read returns excluded bytes on an "allow" verdict.

The flipper is the standard TOCTOU co-actor: same reachability as F146
(deployment layout / supply-chain planting / prior compromise -- the agent
cannot plant symlinks through governed tools, but a concurrent process can
flip a pre-existing one).

Verdicts:
- BREAK = hostile effect on an allowed call (the miss demonstrated)
- HELD  = the exclusion held (control, or post-closure behavior)
- INFO  = characterized behavior, not a verdict
- ERROR = probe/instrumentation problem, not a verdict

Probes:
  p1  write_file race: flipper flips hot-link between docs/ and
      excluded-zone/ while the victim writes via hot-link.
      BREAK if any VICTIM-* bytes land in excluded-zone/.
  p2  read_file race: same flipper; victim reads hot-link/notes.txt
      (exists in both targets). BREAK if any allowed call returns the
      excluded-zone marker.
  p3  control: link pinned to the benign target, no flipper -> all writes
      land benign, none excluded -> HELD.
  p4  control: link pinned to the hostile target -> calls denied -> HELD.
  p5  control: approval path. write_file via hot-link requires approval;
      flip to hostile while pending; approve; sweep must refuse with a
      fresh-context re-evaluation and execute nothing -> HELD.
  p6  info: symlink-loop path through _is_outside_sandbox (catches only
      OSError) -> records whether RuntimeError escapes call() or the call
      is cleanly denied. Pre-existing per the F146 residual; INFO only.
  p7  mechanics control: flipper + victim with NO exclusion rule -> writes
      must land on BOTH targets (proves the flipper genuinely wins races;
      if p1/p2 ever HELD while p7 shows flips landing, the race is real
      but the control held).

Deterministic bar: the race is probabilistic per call, but with hundreds
of calls per probe the battery-level outcome must be identical across
runs; the script runs the full battery twice in-process and must agree,
and is additionally re-run in fresh processes.

Budget note: the race probes relax the orthogonal loop-guard
(max_identical_calls) and volume-guard-writes (max_writes_per_run)
budgets in the TEST policy so hundreds of race iterations are not denied
by unrelated controls; the exclusion rules under test are unchanged.

Synthetic/local only, no network.

Run: TMPDIR=/tmp/gov-f147 ~/workspace/.gov-venv/bin/python /tmp/f147toctou_break.py
Standalone check: env -u GOV_DEPLOYMENT_MODE ~/workspace/.gov-venv/bin/python /tmp/f147toctou_break.py
"""

import os
import secrets
import sys
import tempfile
import threading
from pathlib import Path

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "f147-break")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-f147")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = "/home/hatch/workspace/agent-governance-demo/agent-governance-demo-main"
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402

EXCLUSION_RULES = """
  - id: deny-excluded-zone-writes
    description: Standing operator exclusion -- never write under excluded-zone.
    effect: deny
    flag: exclusion_violation
    match:
      tool: [write_file]
      path_contains_any: [excluded-zone]
    reason: Standing operator exclusion -- the excluded-zone directory is off-limits.
  - id: deny-excluded-zone-reads
    description: Standing operator exclusion -- never read from excluded-zone.
    effect: deny
    flag: exclusion_violation
    match:
      tool: [read_file]
      path_contains_any: [excluded-zone]
    reason: Standing operator exclusion -- the excluded-zone directory is unreadable.
"""

APPROVAL_RULE = """
  - id: require-approval-hotlink-writes
    description: Test seam -- hot-link writes need a human.
    effect: require_approval
    match:
      tool: [write_file]
      path_contains_any: [hot-link]
    reason: Test seam for the approval-path TOCTOU control.
"""

BENIGN_MARK = "BENIGN-DATA-11"
HOSTILE_MARK = "EXCLUDED-ZONE-DATA-42"
N_CALLS = 300


def _base_src():
    # Race probes issue hundreds of calls; the orthogonal runaway-loop
    # and write-budget guards (loop-guard, volume-guard-writes) would
    # otherwise deny most of them and mask the TOCTOU seam under test.
    # They are independent controls, so the battery relaxes them here
    # and documents it.
    src = Path(REPO_ROOT, "policies", "default.yaml").read_text()
    src = src.replace("max_identical_calls: 10",
                      "max_identical_calls: 100000")
    src = src.replace("max_writes_per_run: 50",
                      "max_writes_per_run: 100000")
    return src


def _policy(extra=""):
    src = _base_src()
    path = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]), "policy.yaml")
    path.write_text(src.rstrip() + "\n" + EXCLUSION_RULES + extra + "\n")
    return str(path)


def _setup(extra_rules=""):
    ctx = make_run(policy_path=_policy(extra_rules))
    ident = ctx["executor"].mint_identity("toctou-agent-1", "coder",
                                         "toctou-principal")
    return ctx, ident


def _fixtures(ctx):
    """docs/ (benign) + excluded-zone/ (hostile) + hot-link fixture."""
    sandbox = Path(ctx["executor"].sandbox)
    docs = sandbox / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "notes.txt").write_text(BENIGN_MARK, encoding="utf-8")
    zone = sandbox / "excluded-zone"
    zone.mkdir(parents=True, exist_ok=True)
    (zone / "notes.txt").write_text(HOSTILE_MARK, encoding="utf-8")
    link = sandbox / "hot-link"
    if link.is_symlink() or link.exists():
        os.unlink(link)
    os.symlink(str(docs), str(link))
    return sandbox, docs, zone, link


class Flipper(threading.Thread):
    """Concurrently repoints the symlink between two targets (atomic
    os.replace swap so the victim never observes a missing link)."""

    def __init__(self, link, target_a, target_b):
        super().__init__(daemon=True)
        self.link = link
        self.targets = (str(target_a), str(target_b))
        self.tmp = link.parent / (link.name + ".flip-tmp")
        self.stop = threading.Event()
        self.swaps = 0

    def run(self):
        i = 0
        while not self.stop.is_set():
            try:
                try:
                    os.unlink(self.tmp)
                except OSError:
                    pass
                os.symlink(self.targets[i % 2], str(self.tmp))
                os.replace(str(self.tmp), str(self.link))
                self.swaps += 1
                i += 1
            except OSError:
                pass


def _hostile_write_landed(zone):
    hits = []
    for f in zone.iterdir():
        try:
            if f.is_file() and "VICTIM-" in f.read_text(encoding="utf-8"):
                hits.append(f.name)
        except OSError:
            pass
    return hits


def p1_write_race():
    """Write-race: flipper flips hot-link docs<->excluded-zone while the
    victim writes VICTIM-* files via hot-link."""
    ctx, ident = _setup()
    sandbox, docs, zone, link = _fixtures(ctx)
    ex = ctx["executor"]
    flip = Flipper(link, docs, zone)
    flip.start()
    executed = 0
    try:
        for i in range(N_CALLS):
            r = ex.call(ident, "write_file",
                        path="hot-link/payload-%d.txt" % i,
                        content="VICTIM-%d" % i)
            if r["status"] == "executed":
                executed += 1
    finally:
        flip.stop.set()
        flip.join(timeout=10)
    hits = _hostile_write_landed(zone)
    if hits:
        return ("BREAK",
                "%d/%d calls executed and %d VICTIM-* file(s) landed in "
                "excluded-zone/ on allow verdicts (e.g. %s); the check-time "
                "resolved path was benign, the use-time link was hostile"
                % (executed, N_CALLS, len(hits), hits[0]))
    return ("HELD", "%d/%d executed, zero hostile landings (%d swaps)"
            % (executed, N_CALLS, flip.swaps))


def p2_read_race():
    """Read-race: flipper flips hot-link while the victim reads
    hot-link/notes.txt (present in both targets)."""
    ctx, ident = _setup()
    sandbox, docs, zone, link = _fixtures(ctx)
    ex = ctx["executor"]
    flip = Flipper(link, docs, zone)
    flip.start()
    leaks = 0
    executed = 0
    try:
        for _ in range(N_CALLS):
            r = ex.call(ident, "read_file", path="hot-link/notes.txt")
            if r["status"] == "executed":
                executed += 1
                if HOSTILE_MARK in (r.get("result") or {}).get("content", ""):
                    leaks += 1
    finally:
        flip.stop.set()
        flip.join(timeout=10)
    if leaks:
        return ("BREAK",
                "%d/%d allowed reads returned the EXCLUDED-ZONE marker "
                "(%d leaks); check-time verdict was allow on the benign "
                "target, use-time read followed the hostile link"
                % (leaks, executed, leaks))
    return ("HELD", "%d/%d executed, zero excluded-byte returns (%d swaps)"
            % (executed, N_CALLS, flip.swaps))


def p3_stable_benign_control():
    """Control: link pinned benign, no flipper -> nothing excluded."""
    ctx, ident = _setup()
    sandbox, docs, zone, link = _fixtures(ctx)
    ex = ctx["executor"]
    for i in range(20):
        r = ex.call(ident, "write_file", path="hot-link/c-%d.txt" % i,
                    content="VICTIM-%d" % i)
        if r["status"] != "executed":
            return ("ERROR", "benign write %d not executed: %r" % (i, r))
    hits = _hostile_write_landed(zone)
    if hits:
        return ("ERROR", "control broken: hostile landing without flipper")
    return ("HELD", "20/20 benign writes executed; zero excluded landings")


def p4_stable_hostile_control():
    """Control: link pinned hostile -> the F146 check-time fix denies."""
    ctx, ident = _setup()
    sandbox, docs, zone, link = _fixtures(ctx)
    os.unlink(link)
    os.symlink(str(zone), str(link))
    ex = ctx["executor"]
    r = ex.call(ident, "write_file", path="hot-link/nope.txt",
                content="VICTIM-x")
    if r["status"] == "denied" and r.get("policy_id") == \
            "deny-excluded-zone-writes":
        return ("HELD", "stable-hostile write denied by the exclusion rule")
    return ("ERROR", "control failed: status=%r policy_id=%r"
            % (r["status"], r.get("policy_id")))


def p5_approval_path_control():
    """Control: the approval seam re-evaluates with a FRESH context at
    sweep time, so a flip during human-pending approval must be refused."""
    ctx, ident = _setup(extra_rules=APPROVAL_RULE)
    sandbox, docs, zone, link = _fixtures(ctx)
    ex = ctx["executor"]
    r = ex.call(ident, "write_file", path="hot-link/appr.txt",
                content="VICTIM-approval")
    if r.get("status") != "queued" or not r.get("approval_id"):
        return ("ERROR", "hot-link write did not queue: %r" % (r,))
    aid = r["approval_id"]
    # The flip happens while the human deliberates.
    os.unlink(link)
    os.symlink(str(zone), str(link))
    ctx["approvals"].decide(aid, True, reason="routine",
                            decided_by="human-operator")
    done = ex.execute_approved()
    executed = [d for d in done if isinstance(d, dict)]
    hits = _hostile_write_landed(zone)
    refused = [e for e in ctx["read_log"]()
               if e.get("event") == "approval_execution_refused"]
    if not executed and not hits and refused:
        return ("HELD", "sweep re-evaluated with fresh context and refused "
                        "(%s); nothing executed, nothing landed"
                % (refused[0].get("flag"),))
    return ("ERROR", "expected refusal: executed=%d hits=%d refused=%d"
            % (len(executed), len(hits), len(refused)))


def p6_symlink_loop_info():
    """INFO: symlink-loop path through _is_outside_sandbox (catches only
    OSError; Path.resolve raises RuntimeError on loops). Pre-existing per
    the F146 residual -- characterized, not a verdict."""
    ctx, ident = _setup()
    sandbox = Path(ctx["executor"].sandbox)
    la, lb = sandbox / "loop-a", sandbox / "loop-b"
    for l in (la, lb):
        if l.is_symlink() or l.exists():
            os.unlink(l)
    os.symlink(str(lb), str(la))
    os.symlink(str(la), str(lb))
    ex = ctx["executor"]
    try:
        r = ex.call(ident, "read_file", path="loop-a/x.txt")
        return ("INFO", "loop path -> status=%r (clean, no exception)"
                % (r.get("status"),))
    except RuntimeError as e:
        return ("INFO", "loop path -> RuntimeError escapes call(): %s "
                        "(pre-existing _is_outside_sandbox OSError-only "
                        "catch; documented F146 residual)" % (e,))
    except Exception as e:  # noqa: BLE001
        return ("INFO", "loop path -> %s escapes call(): %s"
                % (type(e).__name__, e))


def p7_mechanics_control():
    """Mechanics control: flipper + victim with NO exclusion rule. Writes
    must land on BOTH targets -- proves the flipper genuinely wins races."""
    # Rule-free policy: default.yaml only, no exclusion rules
    # (same budget relaxation as _base_src).
    ppath = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]), "p.yaml")
    ppath.write_text(_base_src())
    ctx = make_run(policy_path=str(ppath))
    ident = ctx["executor"].mint_identity("mech-agent", "coder",
                                         "mech-principal")
    sandbox, docs, zone, link = _fixtures(ctx)
    ex = ctx["executor"]
    flip = Flipper(link, docs, zone)
    flip.start()
    try:
        for i in range(N_CALLS):
            ex.call(ident, "write_file", path="hot-link/m-%d.txt" % i,
                    content="VICTIM-%d" % i)
    finally:
        flip.stop.set()
        flip.join(timeout=10)
    n_docs = sum(1 for _ in docs.glob("m-*.txt"))
    n_zone = sum(1 for _ in zone.glob("m-*.txt"))
    if n_docs > 0 and n_zone > 0:
        return ("HELD", "mechanics valid: %d writes landed docs/, %d "
                        "landed excluded-zone/ (%d swaps)"
                % (n_docs, n_zone, flip.swaps))
    return ("ERROR", "flipper did not win races: docs=%d zone=%d swaps=%d"
            % (n_docs, n_zone, flip.swaps))


PROBES = [p1_write_race, p2_read_race, p3_stable_benign_control,
          p4_stable_hostile_control, p5_approval_path_control,
          p6_symlink_loop_info, p7_mechanics_control]


def run_once():
    out = []
    for p in PROBES:
        try:
            out.append((p.__name__,) + p())
        except Exception as e:  # noqa: BLE001 - probe must not die
            out.append((p.__name__, "ERROR", "%s: %s"
                        % (type(e).__name__, e)))
    return out


def main():
    first = run_once()
    second = run_once()
    v1 = [v for _, v, _ in first]
    v2 = [v for _, v, _ in second]
    det = v1 == v2
    n_break = sum(1 for v in v1 if v == "BREAK")
    n_held = sum(1 for v in v1 if v == "HELD")
    n_info = sum(1 for v in v1 if v == "INFO")
    n_err = sum(1 for v in v1 if v == "ERROR")
    print("F147 candidate battery: %d BREAK / %d HELD / %d INFO / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_info, n_err, det))
    for name, verdict, detail in first:
        print("  %-28s %-6s %s" % (name, verdict, detail))
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
