"""F150 candidate battery: chain-exit false-positive launch event.

F149 fixed the chain-RAISES case: a chain entry that raises is converted
to exit 98 (PREEXEC_CHAIN_ABORT_CODE) and launch() refuses with no
``egress_wall_launch``. But the wrapper only converts *raised exceptions*.
A chain entry that terminates via ``os._exit(N)`` with N != 98 bypasses
the conversion entirely -- and ``os._exit(127)`` before exec is the
sandbox's own documented fail-closed behavior (gov/sandbox.py: "the
child is stopped with _exit(127) *before* exec when the layer cannot be
established").

Break = ``egress_wall_launch`` emitted for a child that _exit'd in the
chain (never exec'd) via a non-98 exit code.
Held = no launch event (or a correlated truthful refusal) when the
chain exits directly.
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
    PREEXEC_CHAIN_ABORT_CODE,
)


def _mk_tmp():
    return tempfile.mkdtemp(prefix="f150-",
                            dir=os.environ.get("TMPDIR", "/tmp"))


def _up_wall():
    tmp = _mk_tmp()
    sim = os.path.join(tmp, "wall")
    install_simulated_wall(sim, wall_id="f150")
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


def _exit127_chain():
    # Models gov/sandbox.py's documented fail-closed behavior: the
    # sandbox preexec stops the child with os._exit(127) BEFORE exec
    # when a required layer cannot be established.
    def _halt():
        os._exit(127)
    return (_halt,)


def _raising_chain():
    def _boom():
        raise RuntimeError("simulated chain failure")
    return (_boom,)


def _probe(chain, sim, events, launcher, sentinel):
    """Run one launch; return (launches, refusals, rc, sentinel_exists)."""
    try:
        proc = launcher.launch(
            [sys.executable, "-c",
             "open(%r, 'w').write('x')" % sentinel],
            preexec_chain=chain)
    except EgressLaunchRefused as e:
        launches = [ev for ev in events
                    if ev["event"] == "egress_wall_launch"]
        refusals = [ev for ev in events
                    if ev["event"] == "egress_wall_launch_refused"]
        return launches, refusals, "refused:%s" % e, os.path.exists(
            sentinel)
    rc = proc.wait(timeout=30)
    launches = [ev for ev in events
                if ev["event"] == "egress_wall_launch"]
    refusals = [ev for ev in events
                if ev["event"] == "egress_wall_launch_refused"]
    return launches, refusals, rc, os.path.exists(sentinel)


def p1_chain_exit127_false_launch():
    """BREAK if the _exit(127) chain produces a launch event.

    The child never exec'd (sentinel absent, rc 127) but the audit log
    asserts a witnessed launch -- the F149 false-positive, via the
    exit-code path the 98-check does not cover.
    """
    sim, fix, inv, events, launcher = _up_wall()
    try:
        sentinel = os.path.join(sim, "sentinel")
        launches, refusals, rc, made = _probe(
            _exit127_chain(), sim, events, launcher, sentinel)
        if launches and not made and rc == 127:
            return ("BREAK",
                    "chain _exit(127): never exec'd (rc 127, no "
                    "sentinel) but %d egress_wall_launch event(s) "
                    "emitted; refusals=%r" % (
                        len(launches),
                        [r.get("reason") for r in refusals]))
        if not launches and not made:
            return ("HELD",
                    "chain _exit(127): no launch event, child never "
                    "exec'd (rc=%r)" % (rc,))
        return ("ERROR",
                "unexpected: launches=%d rc=%r sentinel=%s" % (
                    len(launches), rc, made))
    finally:
        fix.__exit__()


def p2_chain_raise_control():
    """CONTROL: the F149-fixed path (chain raises) must still hold."""
    sim, fix, inv, events, launcher = _up_wall()
    try:
        sentinel = os.path.join(sim, "sentinel")
        launches, refusals, rc, made = _probe(
            _raising_chain(), sim, events, launcher, sentinel)
        truthful = any(r.get("reason") == "preexec_chain_failed"
                       for r in refusals)
        refused = isinstance(rc, str) and rc.startswith("refused:")
        if refused and "preexec_chain_failed" in rc and not launches \
                and not made and truthful:
            return ("HELD",
                    "chain raise: refused, no launch event, truthful "
                    "preexec_chain_failed")
        return ("ERROR",
                "unexpected: launches=%d rc=%r sentinel=%s truthful=%s"
                % (len(launches), rc, made, truthful))
    finally:
        fix.__exit__()


def p3_healthy_chain_control():
    """CONTROL: healthy chain -> exactly one launch event, child runs."""
    sim, fix, inv, events, launcher = _up_wall()
    try:
        sentinel = os.path.join(sim, "sentinel")
        proc = launcher.launch(
            [sys.executable, "-c",
             "open(%r, 'w').write('x')" % sentinel],
            preexec_chain=())
        rc = proc.wait(timeout=30)
        launches = [ev for ev in events
                    if ev["event"] == "egress_wall_launch"]
        if rc == 0 and os.path.exists(sentinel) and len(launches) == 1:
            return ("HELD", "healthy launch: 1 event, child exec'd")
        return ("ERROR",
                "unexpected: rc=%r sentinel=%s launches=%d"
                % (rc, os.path.exists(sentinel), len(launches)))
    finally:
        fix.__exit__()


def main():
    results = []
    for name, fn in [("p1_chain_exit127_false_launch",
                      p1_chain_exit127_false_launch),
                     ("p2_chain_raise_control",
                      p2_chain_raise_control),
                     ("p3_healthy_chain_control",
                      p3_healthy_chain_control)]:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - battery must not crash
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        results.append((name, verdict, detail))
        print("  %-32s %-6s %s" % (name, verdict, detail))
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_held = sum(1 for _, v, _ in results if v == "HELD")
    n_err = sum(1 for _, v, _ in results if v == "ERROR")
    print("F150 candidate battery: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    return 1 if n_break else 0


if __name__ == "__main__":
    sys.exit(main())
