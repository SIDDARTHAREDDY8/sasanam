#!/usr/bin/env python3
"""Row-12 pinned-inventory battery (wave-141 lane 1).

Row-12 residual after wave-140: a compromised same-process executor
can forge the wave-140 coverage-gap report -- e.g. silently shrink
the declared inventory so a blind spot never appears as a gap. The
report compared whatever inventory it was handed.

This battery is RED-first: probes p1/p2 run the forgery against the
best available seam and go BREAK while the operator-pinned inventory
is missing; they flip to HELD once ``gov.artifact_sweep`` pins the
declared inventory with a deployment-key HMAC at configuration time
and the gap report verifies the pin before trusting the list.

Pin contract under test:
  - ``pin_inventory(declared_roots)``: operator ceremony. Resolves
    the declared roots (no walking) and returns a pinned dict
    carrying the inventory, a pin timestamp, and an HMAC-SHA256 pin
    keyed by ``gov.keyprovider.resolve_active_key()`` output --
    domain-separated, never hard-coded. Unprovisioned key ->
    fail-closed ``NoKeyConfiguredError`` at ceremony time.
  - The gap report binds to the PINNED inventory: a verifier
    recomputes the report from (pinned inventory, configured roots).
  - A shrunk or tampered inventory fails verification LOUD: one
    ``artifact_sweep_inventory_unverifiable`` evidence event and a
    fail-closed FULL-GAP report (every declared directory treated
    as uncovered -- nothing is silently "covered").
  - No pin configured -> the report carries an explicit ``unpinned``
    verdict (documented downgrade, never silently treated as
    pinned).

Probes:
  p1_shrunk_inventory_fails_loud: pin [A, B]; present [A] with the
     ORIGINAL pin (the compromised-executor shrink) -> LOUD
     ``artifact_sweep_inventory_unverifiable``, verdict
     "unverifiable", full-gap (both A and B listed as gaps).
  p2_tampered_pin_fails_loud: pin [A, B]; flip one hex char of the
     pin -> same LOUD failure.
  p3_valid_pin_gap_reported: pin [A, B]; watch root covers A ->
     exactly one LOUD gap event naming B; verdict "pinned".
  p4_unpinned_downgrade_explicit: plain list [A, B] (no pin) ->
     gaps still reported (visibility preserved) but the report and
     the summary event carry verdict "unpinned" -- the downgrade is
     explicit, never silent.
  p5_executor_wiring: the shrink from p1 driven through
     ``ToolExecutor.run_artifact_sweep`` with
     ``artifact_sweep={"declared_inventory": shrunk}`` -> the LOUD
     unverifiable event lands in the chained audit log and
     ``verify_chain`` is OK.
  p6_deterministic_x2: the whole battery runs twice; verdicts must
     be identical.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic (no RNG in verdicts;
secrets.token_hex is used only for the deployment key and temp-dir
isolation). Stdlib only.

Run:
  mkdir -p /tmp/gov-invpin
  TMPDIR=/tmp/gov-invpin ~/workspace/.gov-venv/bin/python \
      evals/artifact_inventory_pin_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-invpinb \
      ~/workspace/.gov-venv/bin/python evals/artifact_inventory_pin_probes.py
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "invpin")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-invpin-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import artifact_sweep as _sweep  # noqa: E402
from gov.artifacts import ArtifactInventory  # noqa: E402
from gov.log import read_entries, verify_chain, ActionLog  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

_HAVE_PIN = hasattr(_sweep, "pin_inventory") and hasattr(
    _sweep, "verify_inventory_pin")

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"

_UNGOVERNED_ACK = (
    "inventory-pin eval: synthetic red-team harness; raw pre-wave-74/75 "
    "pipeline by design, declared and chained")

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


# ------------------------------------------------------------ fixtures

def _data_root(name):
    root = Path(tempfile.mkdtemp(prefix="govinvpin-data-%s-" % name,
                                 dir=os.environ["TMPDIR"]))
    (root / "keep.txt").write_text("deployed baseline file\n",
                                   encoding="utf-8")
    return root


def _snapshot(root):
    inv = ArtifactInventory()
    return _sweep.register_watch_root(str(root), inv,
                                     agent_id="operator",
                                     run_id="baseline")


def _session(**ex_kw):
    run_dir = Path(tempfile.mkdtemp(prefix="govinvpin-",
                                    dir=os.environ["TMPDIR"]))
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack=_UNGOVERNED_ACK,
                      **ex_kw)
    return {"run_dir": run_dir, "executor": ex, "log": log,
            "approvals": approvals}


def _events(ctx, name):
    return [ev for ev in read_entries(ctx["run_dir"] / "actions.jsonl")
            if isinstance(ev, dict) and ev.get("event") == name]


def _pin(roots):
    return _sweep.pin_inventory([str(r) for r in roots])


def _shrunk(pinned, keep):
    """Compromised-executor shrink: drop roots but keep the old pin."""
    return dict(pinned, inventory=[str(r) for r in keep])


def _report(pinned_or_list, watch_roots):
    events = []
    rep = _sweep.report_coverage_gaps(
        pinned_or_list, watch_roots, audit=events.append, run_id="pin")
    return rep, events


def _unverifiable_ok(rep, events, roots):
    """Shared assertion: LOUD unverifiable + fail-closed full-gap."""
    evs = [e for e in events
           if e.get("event") == _sweep.INVENTORY_UNVERIFIABLE_EVENT]
    if len(evs) != 1:
        return (False, "expected exactly 1 %s event, got %d"
                % (_sweep.INVENTORY_UNVERIFIABLE_EVENT, len(evs)))
    ev = evs[0]
    if ev.get("severity") != "LOUD" or not ev.get("reason"):
        return (False, "unverifiable event not LOUD-shaped: %r" % (ev,))
    if rep.get("verdict") != "unverifiable":
        return (False, "report verdict is %r, want 'unverifiable'"
                % (rep.get("verdict"),))
    # Fail-closed full-gap: every declared directory is uncovered.
    want = {os.path.realpath(str(r)) for r in roots}
    if set(rep.get("gaps", [])) != want or rep.get("covered"):
        return (False, "not full-gap: gaps=%r covered=%r"
                % (rep.get("gaps"), rep.get("covered")))
    return (True, "LOUD %s; fail-closed full-gap over %d declared"
            % (_sweep.INVENTORY_UNVERIFIABLE_EVENT, len(want)))


# ---------------------------------------------------------------- probes

def p1_shrunk_inventory_fails_loud():
    name = "p1_shrunk_inventory_fails_loud"
    if not _HAVE_PIN:
        _record(name, "BREAK",
                "pin_inventory seam MISSING -- a compromised executor can "
                "silently shrink the declared inventory (not implemented)")
        return
    rootA = _data_root("a")
    rootB = _data_root("b")
    pinned = _pin([rootA, rootB])
    shrunk = _shrunk(pinned, [rootA])  # B silently dropped, old pin kept
    rep, events = _report(shrunk, [(str(rootA), _snapshot(rootA))])
    # Full-gap is over the PRESENTED (untrusted) declared list: the
    # verifier cannot recover rootB from a shrunk list -- the LOUD
    # unverifiable event is the signal that the true inventory is
    # unknown.
    ok, detail = _unverifiable_ok(rep, events, [rootA])
    _record(name, "HELD" if ok else "BREAK", detail)


def p2_tampered_pin_fails_loud():
    name = "p2_tampered_pin_fails_loud"
    if not _HAVE_PIN:
        _record(name, "BREAK",
                "pin_inventory seam MISSING -- a forged pin is "
                "indistinguishable from a real one (not implemented)")
        return
    rootA = _data_root("c")
    rootB = _data_root("d")
    pinned = _pin([rootA, rootB])
    bad = dict(pinned)
    pin = bad["pin"]
    # Flip the last hex char (deterministic tamper, no RNG).
    bad["pin"] = pin[:-1] + ("0" if pin[-1] != "0" else "1")
    rep, events = _report(bad, [(str(rootA), _snapshot(rootA))])
    ok, detail = _unverifiable_ok(rep, events, [rootA, rootB])
    _record(name, "HELD" if ok else "BREAK", detail)


def p3_valid_pin_gap_reported():
    name = "p3_valid_pin_gap_reported"
    if not _HAVE_PIN:
        _record(name, "BREAK",
                "pin_inventory seam MISSING (not implemented)")
        return
    rootA = _data_root("e")
    rootB = _data_root("f")
    pinned = _pin([rootA, rootB])
    rep, events = _report(pinned, [(str(rootA), _snapshot(rootA))])
    gaps = [e for e in events
            if e.get("event") == _sweep.COVERAGE_GAP_EVENT]
    named = [g.get("declared_root") for g in gaps]
    bad = [e for e in events
           if e.get("event") == _sweep.INVENTORY_UNVERIFIABLE_EVENT]
    if bad:
        _record(name, "BREAK",
                "valid pin rejected as unverifiable: %r" % (bad,))
        return
    if len(gaps) != 1 or os.path.realpath(str(rootB)) not in named:
        _record(name, "BREAK",
                "expected exactly 1 gap naming rootB, got %r" % (named,))
        return
    if rep.get("verdict") != "pinned":
        _record(name, "BREAK",
                "report verdict is %r, want 'pinned'" % (rep.get("verdict"),))
        return
    comps = [e for e in events
             if e.get("event") == _sweep.COVERAGE_COMPLETE_EVENT]
    if not comps or comps[0].get("inventory_verdict") != "pinned":
        _record(name, "BREAK",
                "summary event missing inventory_verdict='pinned': %r"
                % (comps,))
        return
    _record(name, "HELD",
            "valid pin: 1 LOUD gap names rootB; verdict 'pinned'")


def p4_unpinned_downgrade_explicit():
    name = "p4_unpinned_downgrade_explicit"
    if not _HAVE_PIN:
        _record(name, "BREAK",
                "pin_inventory seam MISSING (not implemented)")
        return
    rootA = _data_root("g")
    rootB = _data_root("h")
    # Plain list: the wave-140 form, no pin configured.
    rep, events = _report([str(rootA), str(rootB)],
                          [(str(rootA), _snapshot(rootA))])
    gaps = [e for e in events
            if e.get("event") == _sweep.COVERAGE_GAP_EVENT]
    named = [g.get("declared_root") for g in gaps]
    if len(gaps) != 1 or os.path.realpath(str(rootB)) not in named:
        _record(name, "BREAK",
                "unpinned visibility regressed: gaps=%r" % (named,))
        return
    if rep.get("verdict") != "unpinned":
        _record(name, "BREAK",
                "plain-list report verdict is %r, want explicit 'unpinned'"
                % (rep.get("verdict"),))
        return
    comps = [e for e in events
             if e.get("event") == _sweep.COVERAGE_COMPLETE_EVENT]
    if not comps or comps[0].get("inventory_verdict") != "unpinned":
        _record(name, "BREAK",
                "summary event missing inventory_verdict='unpinned': %r"
                % (comps,))
        return
    _record(name, "HELD",
            "no pin: gap still LOUD; verdict explicitly 'unpinned' "
            "(documented downgrade, never silently pinned)")


def p5_executor_wiring():
    name = "p5_executor_wiring"
    if not _HAVE_PIN:
        _record(name, "BREAK",
                "pin_inventory seam MISSING (not implemented)")
        return
    rootA = _data_root("i")
    rootB = _data_root("j")
    pinned = _pin([rootA, rootB])
    shrunk = _shrunk(pinned, [rootA])
    ctx = _session(artifact_sweep={
        "watch_roots": [(str(rootA), _snapshot(rootA))],
        "declared_inventory": shrunk,
    })
    ctx["executor"].run_artifact_sweep()
    evs = _events(ctx, _sweep.INVENTORY_UNVERIFIABLE_EVENT)
    if len(evs) != 1 or evs[0].get("severity") != "LOUD":
        _record(name, "BREAK",
                "executor path: expected 1 LOUD unverifiable event, got %r"
                % (evs,))
        return
    if not verify_chain(str(ctx["run_dir"] / "actions.jsonl")):
        _record(name, "BREAK",
                "audit chain broken after the unverifiable event")
        return
    _record(name, "HELD",
            "shrunk inventory through run_artifact_sweep: LOUD "
            "unverifiable event inside the verified chain")


def p7_pin_stripped_envelope_fails_loud():
    name = "p7_pin_stripped_envelope_fails_loud"
    if not _HAVE_PIN:
        _record(name, "BREAK",
                "pin_inventory seam MISSING (not implemented)")
        return
    # F182: a pin-shaped dict WITHOUT the "pin" key used to be
    # silently reinterpreted as an unpinned inventory of its dict
    # keys -- real declared dirs dropped from the report with no
    # LOUD event. Any dict must claim the pinned envelope and fail
    # LOUD through pin verification.
    rootA = _data_root("k")
    rootB = _data_root("l")
    pinned = _pin([rootA, rootB])
    stripped = {k: v for k, v in pinned.items() if k != "pin"}
    rep, events = _report(stripped, [(str(rootA), _snapshot(rootA))])
    ok, detail = _unverifiable_ok(rep, events, [rootA, rootB])
    _record(name, "HELD" if ok else "BREAK",
            "F182 pin-stripped envelope: " + detail)
    # The worse variant: a dict whose KEYS are covered paths used to
    # report COVERED with verdict "unpinned" and zero LOUD events.
    rep2, events2 = _report({str(rootA): "junk"},
                            [(str(rootA), _snapshot(rootA))])
    evs2 = [e for e in events2
            if e.get("event") == _sweep.INVENTORY_UNVERIFIABLE_EVENT]
    if rep2.get("verdict") != "unverifiable" or len(evs2) != 1:
        _record(name + "_covered_keys", "BREAK",
                "dict-keyed envelope not LOUD-unverifiable: verdict=%r "
                "unverifiable_events=%d"
                % (rep2.get("verdict"), len(evs2)))
    else:
        _record(name + "_covered_keys", "HELD",
                "dict-keyed envelope: LOUD unverifiable, no silent "
                "covered verdict")


def _run_all():
    global _RESULTS
    _RESULTS = []
    p1_shrunk_inventory_fails_loud()
    p2_tampered_pin_fails_loud()
    p3_valid_pin_gap_reported()
    p4_unpinned_downgrade_explicit()
    p5_executor_wiring()
    p7_pin_stripped_envelope_fails_loud()
    return list(_RESULTS)


def p6_deterministic_x2():
    name = "p6_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r" % (v1, v2))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    _run_all()
    p6_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("artifact_inventory_pin_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())

