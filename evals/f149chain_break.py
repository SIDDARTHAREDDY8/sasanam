"""F149 candidate battery: chain-failure false-positive launch event.

F148 made the ``egress_wall_launch`` audit event witnessed (child-to-parent
ack pipe: the ack is written AFTER the wall re-check passes). But the ack
is written BEFORE the embedder chain runs. If a chain entry fails after
the ack, the child exits 99 -- yet the parent has already emitted
``egress_wall_launch``. Same false-positive class as F148, one stage
later.

Break = ``egress_wall_launch`` emitted for a child that died in the chain
and never exec'd.
Held = no launch event (or a correlated refusal) when the chain fails.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tempfile

from gov.egress_launcher import (
    EgressLaunchRefused,
    FilteredEgressLauncher,
    SimulatedWallFixture,
    install_simulated_wall,
    repin_after_fixture_fixup,
    PREEXEC_ABORT_CODE,
    PREEXEC_CHAIN_ABORT_CODE,
)


def _mk_tmp():
    return tempfile.mkdtemp(prefix="f149-",
                            dir=os.environ.get("TMPDIR", "/tmp"))


def _up_wall():
    tmp = _mk_tmp()
    sim = os.path.join(tmp, "wall")
    install_simulated_wall(sim, wall_id="f149")
    fix = SimulatedWallFixture(sim)
    fix.__enter__()
    inv = repin_after_fixture_fixup(sim)
    fix.inventory = inv
    events = []
    launcher = FilteredEgressLauncher(
        manifest_path=os.path.join(sim, "wall_pins.json"),
        receipt_path=os.path.join(sim, "wall_receipt.json"),
        wall_provider=fix.provider(), audit=events.append,
        trust=inv.trust)
    return sim, fix, inv, events, launcher


def _failing_chain():
    def _boom():
        raise RuntimeError("simulated chain failure")
    return (_boom,)


def p1_chain_failure_false_launch():
    """HELD if no egress_wall_launch is emitted for a chain-failed child.

    Post-fix contract (F149): a fast chain failure makes launch()
    refuse fail-closed (EgressLaunchRefused, no launch event, truthful
    preexec_chain_failed refusal). HELD iff the audit shows no launch
    event and the refusal names the chain failure.
    """
    sim, fix, inv, events, launcher = _up_wall()
    try:
        sentinel = os.path.join(sim, "sentinel")
        try:
            proc = launcher.launch(
                [sys.executable, "-c",
                 "open(%r, 'w').write('x')" % sentinel],
                preexec_chain=_failing_chain())
        except EgressLaunchRefused as e:
            launches = [ev for ev in events
                        if ev["event"] == "egress_wall_launch"]
            refusals = [ev for ev in events
                        if ev["event"] == "egress_wall_launch_refused"]
            truthful = any(r.get("reason") == "preexec_chain_failed"
                           for r in refusals)
            if (len(launches) == 0 and truthful
                    and not os.path.exists(sentinel)
                    and "preexec_chain_failed" in str(e)):
                return ("HELD",
                        "chain failed: launch() refused, no launch "
                        "event, truthful preexec_chain_failed refusal")
            return ("ERROR",
                    "refused but launches=%d reasons=%r sentinel=%s" %
                    (len(launches),
                     [r.get("reason") for r in refusals],
                     os.path.exists(sentinel)))
        # launch() returned: the child survived preexec (unexpected
        # for a fast-failing chain -- Popen blocks until the chain
        # completes). The close-when requires the refusal to name the
        # chain failure, so HELD needs a truthful refusal, not just
        # the absence of a launch event.
        rc = proc.wait(timeout=30)
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        child_died = (rc in (PREEXEC_ABORT_CODE,
                             PREEXEC_CHAIN_ABORT_CODE))
        never_execd = not os.path.exists(sentinel)
        false_launch = len(launches) > 0
        truthful = any(r.get("reason") == "preexec_chain_failed"
                       for r in refusals)
        if child_died and never_execd and false_launch:
            return ("BREAK",
                    "chain failed (exit %r), never exec'd, but "
                    "%d egress_wall_launch event(s) emitted"
                    % (rc, len(launches)))
        if child_died and never_execd and not false_launch and truthful:
            return ("HELD",
                    "chain failed, no launch event, truthful "
                    "preexec_chain_failed refusal")
        return ("ERROR",
                "unexpected: rc=%r sentinel=%s launches=%d truthful=%s"
                % (rc, os.path.exists(sentinel), len(launches),
                   truthful))
    finally:
        fix.__exit__()


def p2_healthy_chain_control():
    """CONTROL: healthy chain -> launch event, child exec's."""
    sim, fix, inv, events, launcher = _up_wall()
    try:
        sentinel = os.path.join(sim, "sentinel")
        proc = launcher.launch(
            [sys.executable, "-c",
             "open(%r, 'w').write('x')" % sentinel],
            preexec_chain=())
        rc = proc.wait(timeout=30)
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        if rc == 0 and os.path.exists(sentinel) and len(launches) == 1:
            return ("HELD", "healthy launch: 1 event, child exec'd")
        return ("ERROR",
                "unexpected: rc=%r sentinel=%s launches=%d"
                % (rc, os.path.exists(sentinel), len(launches)))
    finally:
        fix.__exit__()


def main():
    results = []
    for name, fn in [("p1_chain_failure_false_launch",
                      p1_chain_failure_false_launch),
                     ("p2_healthy_chain_control",
                      p2_healthy_chain_control)]:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - battery must not crash
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        results.append((name, verdict, detail))
        print("  %-32s %-6s %s" % (name, verdict, detail))
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_held = sum(1 for _, v, _ in results if v == "HELD")
    n_err = sum(1 for _, v, _ in results if v == "ERROR")
    print("F149 candidate battery: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    return 1 if n_break else 0


if __name__ == "__main__":
    sys.exit(main())
