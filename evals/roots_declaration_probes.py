#!/usr/bin/env python3
"""Row-12 watch-root declaration-audit battery (wave-143 lane).

Measured residual: undeclared watch roots are invisible; a compromised
operator path or direct config edit can silently narrow the
artifact-sweep watch roots and the sweep stays quiet.

This battery is RED-first: every probe goes BREAK while the
declaration seam is missing from ``gov/artifact_sweep.py`` (no
``declare_watch_roots``, no ``check_roots_declaration``, no
``artifact_sweep_roots_declared`` / ``artifact_sweep_roots_undeclared_change``
events, no ``verify_declaration_chained``). They flip to HELD once
the seam lands:

  - ``declare_watch_roots``: the declaration ceremony. Binds the
    watch-root set with an HMAC (deployment key chokepoint or explicit
    override; never hard-coded), emits a chained
    ``artifact_sweep_roots_declared`` audit event carrying operator
    identity, old root set -> new root set, and reason.
  - ``check_roots_declaration``: enforcement. When the effective
    (configured) watch-root set differs from the last declared set
    (roots added/removed out-of-band, config edited directly), emits a
    LOUD ``artifact_sweep_roots_undeclared_change`` event and the
    sweep verdict is "unverifiable" -- fail-closed, never silently
    sweeping a narrowed set as if it were the declared one.
  - ``verify_declaration_chained``: auditor path. Confirms the
    ceremony event for a declaration is present in the chained audit
    log and the chain verifies -- a tampered ceremony event fails
    LOUD.

Probes:
  r1_narrowed_out_of_band_loud: declare {A, B} through the ceremony
     into a chained log; then narrow the configured roots out-of-band
     (drop B, as a direct config edit would) and run the REAL
     executor sweep path (``ToolExecutor.run_artifact_sweep`` with
     ``artifact_sweep={"roots_declaration": env, "watch_roots": ...}``)
     -> exactly one LOUD ``artifact_sweep_roots_undeclared_change``
     event naming removed root B in the chained log, and the
     ``artifact_sweep_complete`` event carries
     ``roots_verdict="undeclared_change"`` (unverifiable sweep, never
     presented as declared).
  r2_ceremony_change_quiet: declare {A, B}; then change {A, B} -> {A}
     THROUGH the ceremony (previous envelope supplied, old -> new
     carried in the chained ceremony event). Effective roots {A} ->
     quiet (no undeclared_change event), verdict "declared"; the new
     baseline is adopted (the OLD envelope against {A} now reads
     undeclared_change -- stale baselines do not linger).
  r3_unchanged_quiet: declare {A, B}; effective roots {A, B} ->
     quiet, verdict "declared".
  r4_ceremony_event_tampered_chain_loud: declare through the ceremony
     into a chained log (control: ``verify_declaration_chained`` is
     clean); tamper the ceremony event bytes in the log file ->
     ``verify_declaration_chained`` fails LOUD (and the chain itself
     is broken).
  r5_deterministic_x2: the whole battery runs twice; verdicts must be
     identical.

Honest ceilings (documented, not hidden): this lane audits the watch-root
*configuration*, not the sweeping. A compromised same-process executor
can still lie about what it actually swept (it can pass different roots
to the sweep than to the declaration check, or skip either call) --
the standing row-12 same-process residual. Key custody underpins the
ceremony chain exactly like every other chained event: a key-holder can
declare a malicious-but-authorized set and it verifies cleanly; the
ceremony (who declared, when, audited) is the control, not the MAC.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic (no RNG in verdicts;
secrets.token_hex is used only for keys and temp-dir isolation).
Stdlib only.

Run:
  mkdir -p /tmp/gov-rootsdecl
  TMPDIR=/tmp/gov-rootsdecl ~/workspace/.gov-venv/bin/python \
      evals/roots_declaration_probes.py
Also standalone (deployment-mode unset):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-rootsdeclb \
      ~/workspace/.gov-venv/bin/python evals/roots_declaration_probes.py
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "rootsdecl-A")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-rootsdecl-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import artifact_sweep as _sweep  # noqa: E402
from gov.artifacts import ArtifactInventory  # noqa: E402
from gov.log import ActionLog, read_entries, verify_chain  # noqa: E402

_RESULTS = []

TEST_KEY = b"wave143-roots-decl-test-key-32b!!"

_SEAM = all(hasattr(_sweep, n) for n in (
    "declare_watch_roots",
    "verify_roots_declaration",
    "check_roots_declaration",
    "verify_declaration_chained",
    "declaration_digest",
    "ROOTS_DECLARED_EVENT",
    "ROOTS_UNDECLARED_CHANGE_EVENT",
    "ROOTS_DECLARATION_VERSION",
))

DECLARED_EVENT = "artifact_sweep_roots_declared"
UNDECLARED_EVENT = "artifact_sweep_roots_undeclared_change"


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-36s %-10s %s" % (name, verdict, detail))


def _seam_missing(name):
    _record(name, "BREAK",
            "declaration seam MISSING from gov/artifact_sweep.py "
            "(not implemented)")


# ------------------------------------------------------------ fixtures

def _data_root(name):
    root = Path(tempfile.mkdtemp(prefix="govrootsdecl-%s-" % name,
                                 dir=os.environ["TMPDIR"]))
    (root / "keep.txt").write_text("watch-root baseline file\n",
                                   encoding="utf-8")
    return root


def _baseline(root):
    inv = ArtifactInventory()
    _sweep.register_watch_root(str(root), inv)
    return inv


def _declare(roots, **kw):
    kw.setdefault("hmac_key", TEST_KEY)
    return _sweep.declare_watch_roots(roots, **kw)


def _executor(run_dir, **kw):
    from gov.executor import ToolExecutor
    from gov.policy import PolicyEngine
    from gov.approvals import ApprovalQueue
    policy = PolicyEngine(
        str(Path(REPO_ROOT) / "policies" / "default.yaml"))
    log = ActionLog(str(run_dir / "actions.jsonl"))
    approvals = ApprovalQueue(run_dir, log)
    return ToolExecutor(
        run_dir, policy, log, approvals,
        ledger_path=str(run_dir / "egress_ledger.jsonl"),
        ungoverned_ack=("roots-declaration battery: synthetic harness; "
                        "raw pre-wave-74/75 pipeline by design, declared "
                        "and chained"),
        **kw)


def _events_of(run_dir, name):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if isinstance(e, dict) and e.get("event") == name]


# ---------------------------------------------------------------- probes

def r1_narrowed_out_of_band_loud():
    name = "r1_narrowed_out_of_band_loud"
    if not _SEAM:
        _seam_missing(name)
        return
    rootA = _data_root("a")
    rootB = _data_root("b")
    run_dir = Path(tempfile.mkdtemp(prefix="govrootsdecl-run-",
                                    dir=os.environ["TMPDIR"]))
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    ex = _executor(run_dir)
    # The ceremony: operator declares {A, B}, chained into the log.
    # hmac_key=None -> the deployment key (env), so the executor's
    # keyprovider-side verification sees the same key epoch.
    env = _declare([str(rootA), str(rootB)], operator_id="ops-1",
                   reason="initial watch-root declaration",
                   hmac_key=None, audit=ex.log.append,
                   run_id="rootsdecl-r1")
    # Out-of-band narrowing: a direct config edit drops root B. The
    # sweep is run through the REAL executor path with the narrowed
    # configuration.
    ex.artifact_sweep = {
        "roots_declaration": env,
        "watch_roots": [(str(rootA), _baseline(rootA))],
    }
    ex.run_artifact_sweep()
    loud = _events_of(run_dir, UNDECLARED_EVENT)
    if len(loud) != 1:
        _record(name, "BREAK",
                "expected exactly 1 %s event, got %d"
                % (UNDECLARED_EVENT, len(loud)))
        return
    ev = loud[0]
    if ev.get("severity") != "LOUD":
        _record(name, "BREAK",
                "undeclared-change event not LOUD: %r" % (ev,))
        return
    removed = ev.get("removed") or []
    if os.path.realpath(str(rootB)) not in [os.path.realpath(r)
                                            for r in removed]:
        _record(name, "BREAK",
                "LOUD event does not name removed root B: %r"
                % (removed,))
        return
    comp = _events_of(run_dir, _sweep.SWEEP_COMPLETE_EVENT)
    if len(comp) != 1:
        _record(name, "BREAK",
                "expected exactly 1 %s event, got %d"
                % (_sweep.SWEEP_COMPLETE_EVENT, len(comp)))
        return
    if comp[0].get("roots_verdict") != "undeclared_change":
        _record(name, "BREAK",
                "complete event roots_verdict is %r, want "
                "'undeclared_change' (the narrowed sweep must never "
                "read as declared)" % (comp[0].get("roots_verdict"),))
        return
    if comp[0].get("roots_verified"):
        _record(name, "BREAK",
                "complete event claims roots_verified on a narrowed "
                "sweep")
        return
    if not verify_chain(str(run_dir / "actions.jsonl"))[0]:
        _record(name, "BREAK", "audit chain broken after the run")
        return
    _record(name, "HELD",
            "out-of-band narrowing -> 1 LOUD %s naming removed root; "
            "sweep verdict 'undeclared_change', roots_verified False; "
            "chain intact" % UNDECLARED_EVENT)


def r2_ceremony_change_quiet():
    name = "r2_ceremony_change_quiet"
    if not _SEAM:
        _seam_missing(name)
        return
    rootA = _data_root("c")
    rootB = _data_root("d")
    run_dir = Path(tempfile.mkdtemp(prefix="govrootsdecl-run2-",
                                    dir=os.environ["TMPDIR"]))
    log = ActionLog(str(run_dir / "actions.jsonl"))
    old = _declare([str(rootA), str(rootB)], operator_id="ops-1",
                   reason="initial", audit=log.append, run_id="r2a")
    # The legitimate change goes THROUGH the ceremony: {A, B} -> {A}.
    new = _declare([str(rootA)], previous=old, operator_id="ops-1",
                   reason="decommissioned B", audit=log.append,
                   run_id="r2b")
    # The ceremony event carries old -> new.
    cer = [e for e in read_entries(run_dir / "actions.jsonl")
           if isinstance(e, dict) and e.get("event") == DECLARED_EVENT]
    if len(cer) != 2:
        _record(name, "BREAK",
                "expected 2 chained ceremony events, got %d" % len(cer))
        return
    ev2 = cer[1]
    if (os.path.realpath(str(rootB)) not in
            [os.path.realpath(r) for r in (ev2.get("old_roots") or [])]
            or os.path.realpath(str(rootA)) not in
            [os.path.realpath(r) for r in (ev2.get("new_roots") or [])]):
        _record(name, "BREAK",
                "second ceremony event does not carry old {A,B} -> "
                "new {A}: %r" % (ev2,))
        return
    if ev2.get("operator_id") != "ops-1" or not ev2.get("reason"):
        _record(name, "BREAK",
                "ceremony event missing operator identity/reason: %r"
                % (ev2,))
        return
    # Effective roots {A} against the NEW declaration: quiet.
    events = []
    rep = _sweep.check_roots_declaration(
        [str(rootA)], new, audit=events.append, run_id="r2c",
        hmac_key=TEST_KEY)
    if rep.get("verdict") != "declared" or events:
        _record(name, "BREAK",
                "ceremony change was not quiet: verdict=%r events=%d"
                % (rep.get("verdict"), len(events)))
        return
    # New baseline adopted: the OLD declaration against {A} no longer
    # verifies as declared (stale baselines do not linger).
    rep_old = _sweep.check_roots_declaration(
        [str(rootA)], old, run_id="r2d", hmac_key=TEST_KEY)
    if rep_old.get("verdict") != "undeclared_change":
        _record(name, "BREAK",
                "old declaration against narrowed roots should read "
                "undeclared_change, got %r" % (rep_old.get("verdict"),))
        return
    if not verify_chain(str(run_dir / "actions.jsonl"))[0]:
        _record(name, "BREAK", "audit chain broken after ceremonies")
        return
    _record(name, "HELD",
            "ceremony change {A,B}->{A} quiet, new baseline adopted "
            "(old envelope reads undeclared_change); chain intact")


def r3_unchanged_quiet():
    name = "r3_unchanged_quiet"
    if not _SEAM:
        _seam_missing(name)
        return
    rootA = _data_root("e")
    rootB = _data_root("f")
    events = []
    env = _declare([str(rootA), str(rootB)], operator_id="ops-1",
                   reason="steady state")
    rep = _sweep.check_roots_declaration(
        [(str(rootA), None), (str(rootB), None)], env,
        audit=events.append, run_id="r3", hmac_key=TEST_KEY)
    # Note: (root, None) tuples exercise the tuple-normalization path.
    if rep.get("verdict") != "declared":
        _record(name, "BREAK",
                "unchanged roots did not verify declared: %r"
                % (rep.get("verdict"),))
        return
    if events:
        _record(name, "BREAK",
                "unchanged roots emitted %d events (want quiet)"
                % len(events))
        return
    _record(name, "HELD",
            "unchanged roots -> verdict 'declared', zero events")


def r4_ceremony_event_tampered_chain_loud():
    name = "r4_ceremony_event_tampered_chain_loud"
    if not _SEAM:
        _seam_missing(name)
        return
    rootA = _data_root("g")
    run_dir = Path(tempfile.mkdtemp(prefix="govrootsdecl-run4-",
                                    dir=os.environ["TMPDIR"]))
    log_path = run_dir / "actions.jsonl"
    log = ActionLog(str(log_path))
    env = _declare([str(rootA)], operator_id="ops-1",
                   reason="tamper target", audit=log.append,
                   run_id="r4")
    # Control: before tampering the ceremony verifies chained.
    ok, reason = _sweep.verify_declaration_chained(str(log_path), env)
    if not ok:
        _record(name, "ERROR",
                "pre-tamper control failed: %s" % (reason,))
        return
    # Tamper: rewrite the ceremony event's reason bytes in the log.
    lines = log_path.read_text(encoding="utf-8").splitlines()
    hit = [i for i, ln in enumerate(lines)
           if '"%s"' % DECLARED_EVENT in ln]
    if len(hit) != 1:
        _record(name, "ERROR",
                "expected exactly 1 ceremony line in the log, got %d"
                % len(hit))
        return
    lines[hit[0]] = lines[hit[0]].replace("tamper target",
                                          "tampered by attacker")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok2, reason2 = _sweep.verify_declaration_chained(str(log_path),
                                                     env)
    if ok2:
        _record(name, "BREAK",
                "tampered ceremony event still verifies chained")
        return
    if "LOUD" not in str(reason2):
        _record(name, "BREAK",
                "tamper failure is not LOUD: %r" % (reason2,))
        return
    chain_ok = verify_chain(str(log_path))[0]
    if chain_ok:
        _record(name, "BREAK",
                "tampered log still passes verify_chain")
        return
    _record(name, "HELD",
            "tampered ceremony event -> verify_declaration_chained "
            "fails LOUD; chain broken at the ceremony entry")


def _run_all():
    global _RESULTS
    _RESULTS = []
    r1_narrowed_out_of_band_loud()
    r2_ceremony_change_quiet()
    r3_unchanged_quiet()
    r4_ceremony_event_tampered_chain_loud()
    return list(_RESULTS)


def r5_deterministic_x2():
    name = "r5_deterministic_x2"
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
    r5_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("roots_declaration_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
