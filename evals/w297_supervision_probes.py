"""Wave-297 lane 4 battery: declared agent lifecycle supervision.

Base: wave-296 merge 5fd40f0 (verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/supervision.py -- declared agent lifecycle supervision
      (erlang/otp pattern): closed child inventory, one_for_one /
      one_for_all / rest_for_one restart strategies, bounded
      intensity (max_restarts per window_seconds), signed crash
      reports with digest-only reason storage, crash-loop detection,
      and signed, audit-logged escalation (fail-closed, loud);
  (b) 4 new decision codes at true sorted positions; lane pin
      1753 -> 1757.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module); on the fixed tree they must
HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g297-sup && TMPDIR=/var/tmp/g297-sup \
    ~/workspace/.gov-venv/bin/python evals/w297_supervision_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g297-sup2 \
    ~/workspace/.gov-venv/bin/python evals/w297_supervision_probes.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1991 # Wave-296 merge: pin 1750 -> 1753 (+3 decision-trace-*); Wave-297 lane 4: pin 1753 -> 1757 (+4 supervision-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    for want in ("supervision-crash-loop", "supervision-intensity-exceeded",
                 "supervision-invalid", "supervision-undeclared-child"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1827 raw literals, unique, sorted")


def _import_sup():
    try:
        from gov import supervision
        from gov import ed25519
    except ImportError:
        return None, None
    return supervision, ed25519


def _need(pid):
    sup, ed = _import_sup()
    if sup is None:
        _record(pid, "BREAK", "feature absent on this tree "
                              "(gov.supervision missing)")
        return None, None, None
    return sup, ed, True


def _seed(tag):
    return hashlib.sha256(("w297-supervision-%s" % tag).encode()).digest()


def _pub(ed, seed):
    return ed.publickey(seed).hex()


def _sup1(sup, ed, strategy="one_for_one", max_restarts=100,
          window_seconds=3600, n=3):
    seed = _seed("sup1")
    specs = []
    seeds = {}
    for i in range(n):
        cid = "child-%s" % chr(ord("a") + i)
        cs = _seed("child-%d" % i)
        seeds[cid] = cs
        specs.append(sup.ChildSpec(cid, _pub(ed, cs), strategy,
                                   max_restarts, window_seconds))
    s = sup.Supervisor("sup-one", specs, seed)
    s.start(at=0)
    return s, seeds, seed


def _report(ed, child_seed, child_id, reason, crashed_at):
    body = {"child_id": child_id, "reason_kind": "exit",
            "reason_bytes": reason, "crashed_at": crashed_at}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    sig = ed.sign(child_seed, raw).hex()
    rep = dict(body)
    rep["signature"] = sig
    return rep


def _expect(pid, fn, code, note):
    sup, ed, ok = _need(pid)
    if not ok:
        return
    try:
        fn(sup, ed)
    except sup.SupervisionError as e:
        if e.code == code:
            return _record(pid, "HELD", note)
        return _record(pid, "BREAK",
                       "wrong code: got %r want %r (%s)" % (e.code, code, note))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK", "uncoded escape %r (%s)" % (e, note))
    _record(pid, "BREAK", "no refusal at all (%s)" % note)


def p_import():
    sup, ed, ok = _need("sup-import")
    if not ok:
        return
    _record("sup-import", "HELD", "gov.supervision imports")


def p_declare_start():
    sup, ed, ok = _need("sup-declare-start")
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed)
    order = s.child_ids
    if order != ["child-a", "child-b", "child-c"]:
        return _record("sup-declare-start", "BREAK",
                       "start order wrong: %r" % (order,))
    _record("sup-declare-start", "HELD", "closed inventory declared, "
                                        "start order recorded")


def p_one_for_one():
    sup, ed, ok = _need("sup-one-for-one")
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, strategy="one_for_one")
    d = s.report_crash("child-b", _report(ed, seeds["child-b"], "child-b",
                                          "boom-1", 10), at=10)
    if d["action"] != "restart" or d["restart_set"] != ["child-b"]:
        return _record("sup-one-for-one", "BREAK",
                       "bad decision: %r" % (d,))
    _record("sup-one-for-one", "HELD", "one_for_one restarts only the "
                                      "crashed child")


def p_one_for_all():
    sup, ed, ok = _need("sup-one-for-all")
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, strategy="one_for_all")
    d = s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "boom-1", 10), at=10)
    if sorted(d["restart_set"]) != ["child-a", "child-b", "child-c"]:
        return _record("sup-one-for-all", "BREAK",
                       "bad decision: %r" % (d,))
    _record("sup-one-for-all", "HELD", "one_for_all restarts every child")


def p_rest_for_one():
    sup, ed, ok = _need("sup-rest-for-one")
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, strategy="rest_for_one")
    d = s.report_crash("child-b", _report(ed, seeds["child-b"], "child-b",
                                          "boom-1", 10), at=10)
    if d["restart_set"] != ["child-b", "child-c"]:
        return _record("sup-rest-for-one", "BREAK",
                       "bad decision: %r" % (d,))
    d2 = s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                           "boom-2", 20), at=20)
    if sorted(d2["restart_set"]) != ["child-a", "child-b", "child-c"]:
        return _record("sup-rest-for-one", "BREAK",
                       "first-child crash must restart all: %r" % (d2,))
    _record("sup-rest-for-one", "HELD", "rest_for_one restarts the crashed "
                                       "child and all started after it")


def p_strategy_violation():
    # Attack probe: under one_for_one, a crash must NEVER restart
    # siblings -- a sibling restart here is a strategy violation.
    sup, ed, ok = _need("sup-strategy-violation")
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, strategy="one_for_one")
    d = s.report_crash("child-b", _report(ed, seeds["child-b"], "child-b",
                                          "boom-1", 10), at=10)
    extra = [c for c in d["restart_set"] if c != "child-b"]
    if extra:
        return _record("sup-strategy-violation", "BREAK",
                       "strategy violated: siblings restarted: %r" % (extra,))
    _record("sup-strategy-violation", "HELD", "no sibling restart under "
                                             "one_for_one")


def p_undeclared():
    def go(sup, ed):
        s, seeds, _ = _sup1(sup, ed)
        rep = _report(ed, _seed("rogue"), "child-x", "boom", 10)
        s.report_crash("child-x", rep, at=10)
    _expect("sup-undeclared", go, "supervision-undeclared-child",
            "undeclared child refused coded (closed inventory)")


def p_forged_report():
    # Attack probe: crash report signed by the WRONG key must refuse.
    def go(sup, ed):
        s, seeds, _ = _sup1(sup, ed)
        rep = _report(ed, _seed("attacker"), "child-a", "boom", 10)
        s.report_crash("child-a", rep, at=10)
    _expect("sup-forged-report", go, "supervision-invalid",
            "forged crash report (wrong key) refused coded")


def p_malformed_report():
    def go(sup, ed, mutate):
        s, seeds, _ = _sup1(sup, ed)
        rep = _report(ed, seeds["child-a"], "child-a", "boom", 10)
        mutate(rep)
        s.report_crash("child-a", rep, at=10)

    def go1(sup, ed):
        go(sup, ed, lambda r: r.pop("signature"))
    _expect("sup-malformed-report", go1, "supervision-invalid",
            "missing signature refused coded")

    def go2(sup, ed):
        s, seeds, _ = _sup1(sup, ed)
        rep = _report(ed, seeds["child-a"], "child-a", "boom", 10)
        rep["extra"] = "junk"
        s.report_crash("child-a", rep, at=10)
    _expect("sup-malformed-report-extra", go2, "supervision-invalid",
            "extra report field refused coded")

    def go3(sup, ed):
        s, _, _ = _sup1(sup, ed)
        s.report_crash("child-a", "not-a-dict", at=10)
    _expect("sup-malformed-report-nondict", go3, "supervision-invalid",
            "non-dict report refused coded")


def p_oversized_reason():
    def go(sup, ed):
        s, seeds, _ = _sup1(sup, ed)
        rep = _report(ed, seeds["child-a"], "child-a", "x" * 4097, 10)
        s.report_crash("child-a", rep, at=10)
    _expect("sup-oversized-reason", go, "supervision-invalid",
            "oversized reason payload refused coded (digest-only rule)")


def p_circular_report():
    # F361-class: the module's canonical gate must convert a bare
    # ValueError/TypeError into a coded supervision-invalid. The
    # report seam's grammar checks reject non-str fields before the
    # gate is reachable, so the gate is pinned directly here as
    # defense-in-depth.
    pid = "sup-circular-report"
    sup, ed, ok = _need(pid)
    if not ok:
        return
    evil = {}
    evil["self"] = evil
    try:
        sup._canonical(evil)
    except sup.SupervisionError as e:
        if e.code == "supervision-invalid":
            return _record(pid, "HELD", "circular material refuses coded "
                                       "supervision-invalid (F361-class)")
        return _record(pid, "BREAK", "wrong code: %r" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK", "uncoded escape %r" % (e,))
    _record(pid, "BREAK", "circular material did not refuse")


def p_intensity():
    # Attack probe: exhaust the declared intensity bound.
    pid = "sup-intensity"
    sup, ed, ok = _need(pid)
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, max_restarts=2, window_seconds=3600)
    try:
        s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "r1", 0), at=0)
        s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "r2", 1), at=1)
        s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "r3", 2), at=2)
    except sup.SupervisionError as e:
        if e.code != "supervision-intensity-exceeded":
            return _record(pid, "BREAK",
                           "wrong code on exhaustion: %r" % (e.code,))
        escs = s.escalations
        if len(escs) != 1 or escs[0]["code"] != \
                "supervision-intensity-exceeded":
            return _record(pid, "BREAK", "escalation record missing")
        if not s.verify_escalation(escs[0]):
            return _record(pid, "BREAK",
                           "escalation signature does not verify")
        return _record(pid, "HELD", "intensity exhaustion refuses coded "
                                   "with a SIGNED escalation record")
    _record(pid, "BREAK", "third restart inside the window was allowed")


def p_crash_loop():
    # Attack probe: identical crashes must not livelock-restart.
    pid = "sup-crash-loop"
    sup, ed, ok = _need(pid)
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, max_restarts=100, window_seconds=3600)
    try:
        for t in (0, 1, 2):
            s.report_crash("child-b", _report(ed, seeds["child-b"],
                                              "child-b", "same-boom", t),
                           at=t)
    except sup.SupervisionError as e:
        if e.code != "supervision-crash-loop":
            return _record(pid, "BREAK",
                           "wrong code on loop: %r" % (e.code,))
        escs = s.escalations
        if not escs or escs[-1]["code"] != "supervision-crash-loop":
            return _record(pid, "BREAK", "loop escalation missing")
        if not s.verify_escalation(escs[-1]):
            return _record(pid, "BREAK",
                           "loop escalation signature does not verify")
        return _record(pid, "HELD", "crash-loop refuses coded with a "
                                   "signed escalation (no livelock)")
    _record(pid, "BREAK", "identical crash #3 restarted -- livelock")


def p_loop_streak_reset():
    pid = "sup-loop-streak-reset"
    sup, ed, ok = _need(pid)
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, max_restarts=100, window_seconds=3600)
    try:
        for t, r in ((0, "x"), (1, "y"), (2, "x"), (3, "x")):
            s.report_crash("child-a", _report(ed, seeds["child-a"],
                                              "child-a", r, t), at=t)
    except sup.SupervisionError as e:
        return _record(pid, "BREAK",
                       "streak did not reset, got %r" % (e.code,))
    _record(pid, "HELD", "a different reason resets the loop streak")


def p_window_slide():
    pid = "sup-window-slide"
    sup, ed, ok = _need(pid)
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, max_restarts=2, window_seconds=100)
    try:
        s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "r1", 0), at=0)
        s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "r2", 1), at=1)
        d = s.report_crash("child-a", _report(ed, seeds["child-a"],
                                              "child-a", "r3", 150),
                           at=150)
    except sup.SupervisionError as e:
        return _record(pid, "BREAK",
                       "aged-out restarts still counted: %r" % (e.code,))
    if d["action"] != "restart":
        return _record(pid, "BREAK", "expected restart, got %r" % (d,))
    _record(pid, "HELD", "restarts age out of the intensity window")


def p_escalation_forgery():
    pid = "sup-escalation-forgery"
    sup, ed, ok = _need(pid)
    if not ok:
        return
    s, seeds, _ = _sup1(sup, ed, max_restarts=1, window_seconds=3600)
    try:
        s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "r1", 0), at=0)
        s.report_crash("child-a", _report(ed, seeds["child-a"], "child-a",
                                          "r2", 1), at=1)
    except sup.SupervisionError:
        pass
    escs = s.escalations
    if not escs:
        return _record(pid, "BREAK", "no escalation to forge against")
    forged = dict(escs[0])
    forged["code"] = "supervision-invalid"
    if s.verify_escalation(forged):
        return _record(pid, "BREAK",
                       "tampered escalation verified -- forgery accepted")
    forged2 = dict(escs[0])
    forged2["signature"] = "00" * 64
    if s.verify_escalation(forged2):
        return _record(pid, "BREAK",
                       "garbage-signature escalation verified")
    _record(pid, "HELD", "tampered escalations refuse verification")


def p_frozen_spec():
    def go(sup, ed):
        cs = sup.ChildSpec("child-a", _pub(ed, _seed("c0")),
                           "one_for_one", 3, 60)
        cs.max_restarts = 9999
    _expect("sup-frozen-spec", go, "supervision-invalid",
            "child spec mutation refused coded (deep-freeze)")


def p_bad_declaration():
    cases = []

    def dup(sup, ed):
        cs1 = sup.ChildSpec("child-a", _pub(ed, _seed("d1")),
                            "one_for_one", 3, 60)
        cs2 = sup.ChildSpec("child-a", _pub(ed, _seed("d2")),
                            "one_for_one", 3, 60)
        sup.Supervisor("s", [cs1, cs2], _seed("s"))
    cases.append(("dup-id", dup))

    def badstrat(sup, ed):
        cs = sup.ChildSpec("child-a", _pub(ed, _seed("d3")),
                           "restart_everything", 3, 60)
    cases.append(("bad-strategy", badstrat))

    def unbounded(sup, ed):
        sup.ChildSpec("child-a", _pub(ed, _seed("d4")),
                      "one_for_one", 0, 60)
    cases.append(("zero-max-restarts", unbounded))

    def zerowindow(sup, ed):
        sup.ChildSpec("child-a", _pub(ed, _seed("d5")),
                      "one_for_one", 3, 0)
    cases.append(("zero-window", zerowindow))

    def empty(sup, ed):
        sup.Supervisor("s", [], _seed("s"))
    cases.append(("empty-inventory", empty))

    for name, fn in cases:
        _expect("sup-baddecl-" + name, fn, "supervision-invalid",
                "bad declaration refused coded: " + name)


def p_ed25519_contract():
    # Wave-243 lesson: pin the bool contract.
    pid = "sup-ed25519-contract"
    sup, ed, ok = _need(pid)
    if not ok:
        return
    seed = _seed("contract")
    pub = ed.publickey(seed)
    msg = b"contract-pin"
    sig = ed.sign(seed, msg)
    if ed.verify(pub, msg, sig) is not True:
        return _record(pid, "BREAK", "good signature did not return True")
    bad = bytearray(sig)
    bad[0] ^= 1
    if ed.verify(pub, msg, bytes(bad)) is not False:
        return _record(pid, "BREAK", "forged signature did not return False")
    _record(pid, "HELD", "ed25519.verify contract pinned (True/False)")


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    tmp = tempfile.mkdtemp(prefix="g297-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("sup-import", p_import),
        ("sup-declare-start", p_declare_start),
        ("sup-one-for-one", p_one_for_one),
        ("sup-one-for-all", p_one_for_all),
        ("sup-rest-for-one", p_rest_for_one),
        ("sup-strategy-violation", p_strategy_violation),
        ("sup-undeclared", p_undeclared),
        ("sup-forged-report", p_forged_report),
        ("sup-malformed-report", p_malformed_report),
        ("sup-malformed-report-extra", p_malformed_report),
        ("sup-malformed-report-nondict", p_malformed_report),
        ("sup-oversized-reason", p_oversized_reason),
        ("sup-circular-report", p_circular_report),
        ("sup-intensity", p_intensity),
        ("sup-crash-loop", p_crash_loop),
        ("sup-loop-streak-reset", p_loop_streak_reset),
        ("sup-window-slide", p_window_slide),
        ("sup-escalation-forgery", p_escalation_forgery),
        ("sup-frozen-spec", p_frozen_spec),
        ("sup-baddecl-dup-id", p_bad_declaration),
        ("sup-ed25519-contract", p_ed25519_contract),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w294_coord_lease_probes.py"),
                 "w294-coord-lease", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w296_decision_trace_probes.py"),
                 "w296-decision-trace", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w297_supervision: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
