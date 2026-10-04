"""Wave-312 lane A battery: F396 CLOSED (defaults bound by value).

Base: wave-311 merge e8cdd51f (F395 CLOSED wave-311 lane A via the
coded refusal of non-JSON-native closed-over values; F396 OPEN -- the
F393 code binding ignored __defaults__/__kwdefaults__: two fns with
identical bytecode but different default-argument values yielded
identical code_digest and therefore identical plan digests, so the
run->plan binding passed, _begin_unit returned REPLAY, every
_resolve_replay check passed, and the victim's fn never executed).

Closure direction (this lane): `_code_fingerprint` now binds
`__defaults__` and `__kwdefaults__` via `_defaults_fingerprint`.
JSON-native defaults bind by value (positional order preserved,
keyword-only sorted by name); non-JSON-native ("exotic") defaults
refuse coded `workflow-composed-definition-invalid` (F395-shaped fail
closed: a type-name binding would collide exactly as in F395, and a
repr binding would break crash-recovery stability). The binding flows
through `_unit_code_digest` into `ComposedPlan.digest`, so the
run->plan binding, `op_digest`, and `_begin_unit`/`_resolve_replay`
all compare default-bound digests. JSON-native defaults keep
crash-recovery stability (same source reconstructs the same digest;
line numbers excluded per F393); F393/F394/F395 contracts not
weakened. No new decision codes: pin stays 1851; footer open none /
next F398 (F397 closed wave-313 lane A). This battery's expected BREAKs: none (all F396 probes
assert the fix).

Run:
  mkdir -p /var/tmp/g312-f396 && TMPDIR=/var/tmp/g312-f396 \\
    ~/workspace/.gov-venv/bin/python evals/w312_f396_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g312-f396b \\
    ~/workspace/.gov-venv/bin/python evals/w312_f396_probes.py
"""

import functools
import hashlib
import os
import re
import sys
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check
import probe_lines

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# F396 closure mints no new decision codes (reuses
# workflow-composed-definition-invalid): pin stays 1851.
TAXONOMY_PIN = 1933 # wave-311 merge: pin 1829 -> 1841 (evidence-bundle codes); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)

AT = 1000000
REFUSAL = "workflow-composed-definition-invalid"
MISMATCH = "workflow-composed-plan-mismatch"

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
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1933/1933/0 sorted")


def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    matches = re.findall(
        r"Next free finding: \*\*F(\d+)\*\*\.\s*\*\*Open findings: ([^*]*)\.\*\*",
        text)
    if not matches:
        return _record("footer-state", "ERROR", "footer pattern not found")
    nxt, open_s = int(matches[-1][0]), matches[-1][1]
    # Wave-313 lane A footer: F397 CLOSED; no open findings.
    if nxt != 405 or open_s != "none":
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d (want F398), open '%s' "
                       "(want 'none')" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open F405 / next F406")


def _seed(s):
    return hashlib.sha256(("w312-f396-" + s).encode()).digest()


def _composed_scaffold(tag):
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    from gov import workflow_composed as wc
    from gov import delegation as dg
    from gov import ed25519
    from gov import delegation_revocation as rv
    sa, sb = _seed(tag + "-a"), _seed(tag + "-b")
    pa, pb = ed25519.publickey(sa).hex(), ed25519.publickey(sb).hex()
    cons = {"expires_at": AT + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    root = dg.issue(sa, "agent-a", "agent-b", pb, ("tool.invoke",),
                    issued_at=AT, constraints=dict(cons))
    ledger = rv.DelegationRevoker(sa, "agent-a")
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": [root], "trust_roots": [pa],
            "revocation_ledger": ledger}
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    comp = wc.WorkflowComposer(ws, sm, im)
    ws.start_run("probe", run_id="R", authority=auth, at=AT)
    return wc, wf, saga, idem, comp, ws, sm, im, auth


class _Exotic:
    """Non-JSON-native default value (the F396 exotic channel)."""


def _mkdefault_fn(client):
    # Shared factory: identical bytecode whatever object is bound as
    # the default -- the realistic per-deployment-client shape.
    def fn(i, c=client):
        return {"data": "from-" + c["endpoint"]}
    return fn


def _mkdefault_kwfn(client):
    def fn(i, *, c=client):
        return {"data": "from-" + c["endpoint"]}
    return fn


def _refusal_code(build):
    try:
        build()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return None


def _fn_plan(wc, fn, idem_key="k2"):
    return wc.ComposedPlan([
        {"kind": "fn", "name": "u2", "fn": fn,
         "inputs": {}, "idem_key": idem_key}])


def p_f396_defaults_fn_distinguished():
    # Channel 1 (fn path): identical bytecode, different JSON-native
    # __defaults__ -> different code digests, different plan digests;
    # the victim's plan under the attacker's run refuses coded
    # workflow-composed-plan-mismatch; a fresh run executes the
    # victim's fn natively.
    pid = "F396-defaults-fn-distinguished"
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f396a")
    evil_fn = _mkdefault_fn({"endpoint": "evil"})
    victim_fn = _mkdefault_fn({"endpoint": "real"})
    if evil_fn.__code__.co_code != victim_fn.__code__.co_code:
        return _record(pid, "ERROR", "bytecode differs; probe void")
    if wc._code_fingerprint(evil_fn) == wc._code_fingerprint(victim_fn):
        return _record(pid, "BREAK",
                       "F396: identical bytecode with different "
                       "JSON-native defaults shares a code fingerprint")
    evil, victim = _fn_plan(wc, evil_fn), _fn_plan(wc, victim_fn)
    if evil.digest == victim.digest:
        return _record(pid, "BREAK",
                       "F396: descriptor-identical plans with different "
                       "defaults share a plan digest")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    code = _refusal_code(
        lambda: comp.execute(victim, run_id="R", authority=auth, at=AT))
    if code != MISMATCH:
        return _record(pid, "BREAK" if code is None else "ERROR",
                       "victim plan under attacker's run: want coded %r, "
                       "got %r" % (MISMATCH, code))
    ws.start_run("probe", run_id="R-fresh", authority=auth, at=AT)
    res = comp.execute(_fn_plan(wc, victim_fn, "k2-fresh"),
                       run_id="R-fresh", authority=auth, at=AT)
    out = res["units"]["u2"]["outputs"]
    if out != {"data": "from-real"}:
        return _record(pid, "ERROR",
                       "victim fn did not execute natively: %r" % (out,))
    _record(pid, "HELD",
            "JSON-native __defaults__ distinguished by value; run->plan "
            "binding refuses coded; victim executes natively (F396 closed)")


def p_f396_kwdefaults_fn_distinguished():
    # Channel 3 (kwdefaults): same assertions on the keyword-only
    # channel.
    pid = "F396-kwdefaults-fn-distinguished"
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f396b")
    evil_fn = _mkdefault_kwfn({"endpoint": "evil"})
    victim_fn = _mkdefault_kwfn({"endpoint": "real"})
    if evil_fn.__code__.co_code != victim_fn.__code__.co_code:
        return _record(pid, "ERROR", "bytecode differs; probe void")
    if wc._code_fingerprint(evil_fn) == wc._code_fingerprint(victim_fn):
        return _record(pid, "BREAK",
                       "F396: identical bytecode with different "
                       "JSON-native kwdefaults shares a code fingerprint")
    evil, victim = _fn_plan(wc, evil_fn), _fn_plan(wc, victim_fn)
    if evil.digest == victim.digest:
        return _record(pid, "BREAK",
                       "F396: descriptor-identical plans with different "
                       "kwdefaults share a plan digest")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    code = _refusal_code(
        lambda: comp.execute(victim, run_id="R", authority=auth, at=AT))
    if code != MISMATCH:
        return _record(pid, "BREAK" if code is None else "ERROR",
                       "victim plan under attacker's run: want coded %r, "
                       "got %r" % (MISMATCH, code))
    ws.start_run("probe", run_id="R-fresh", authority=auth, at=AT)
    res = comp.execute(_fn_plan(wc, victim_fn, "k2-fresh"),
                       run_id="R-fresh", authority=auth, at=AT)
    out = res["units"]["u2"]["outputs"]
    if out != {"data": "from-real"}:
        return _record(pid, "ERROR",
                       "victim fn did not execute natively: %r" % (out,))
    _record(pid, "HELD",
            "JSON-native __kwdefaults__ distinguished by value; run->plan "
            "binding refuses coded; victim executes natively (F396 closed)")


def p_f396_defaults_saga_distinguished():
    # Channel 2 (saga action path): descriptor-identical saga plans
    # whose action_fns differ only in JSON-native default values must
    # have different digests; the victim saga under the attacker's run
    # refuses coded; a fresh run succeeds natively.
    pid = "F396-defaults-saga-distinguished"
    from gov import workflow_saga as saga_mod
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold(
        "f396c")

    def mkaction(client):
        def act(params, c=client):
            return ({"data": "from-" + c["endpoint"]}, [])
        return act

    def mkcomp(params):
        return {"undone": True}, []

    def mkplan(act, idem_key="ksg"):
        return wc.ComposedPlan([{
            "kind": "saga", "name": "sg",
            "definition": saga_mod.SagaDefinition([
                saga_mod.SagaStepDef(
                    step_id="s1", action_op="a1", action_params={},
                    compensation_op="c1", compensation_params={})]),
            "action_fns": {"s1": act},
            "comp_fns": {"s1": mkcomp},
            "idem_key": idem_key}])

    evil = mkplan(mkaction({"endpoint": "evil"}))
    victim = mkplan(mkaction({"endpoint": "real"}))
    if evil.digest == victim.digest:
        return _record(pid, "BREAK",
                       "F396: descriptor-identical saga plans with "
                       "different default values share a plan digest")
    comp.execute(evil, run_id="R", authority=auth, at=AT)
    code = _refusal_code(
        lambda: comp.execute(victim, run_id="R", authority=auth, at=AT))
    if code != MISMATCH:
        return _record(pid, "BREAK" if code is None else "ERROR",
                       "victim saga plan under attacker's run: want coded "
                       "%r, got %r" % (MISMATCH, code))
    ws.start_run("probe", run_id="R-fresh", authority=auth, at=AT)
    res = comp.execute(mkplan(mkaction({"endpoint": "real"}), "ksg-fresh"),
                       run_id="R-fresh", authority=auth, at=AT)
    if res["units"]["sg"]["status"] != "succeeded":
        return _record(pid, "ERROR",
                       "victim saga did not succeed natively: %r"
                       % (res["units"]["sg"]["status"],))
    _record(pid, "HELD",
            "saga action __defaults__ distinguished by value; run->plan "
            "binding refuses coded; victim saga succeeds natively "
            "(F396 closed)")


def p_f396_exotic_default_refused():
    # Channel 4: non-JSON-native defaults refuse coded
    # workflow-composed-definition-invalid (F395-shaped fail closed) on
    # the positional channel, the kwdefaults channel, nested inside a
    # JSON container, and the saga action path.
    pid = "F396-exotic-default-refused"
    from gov import workflow_saga as saga_mod
    wc = _composed_scaffold("f396d")[0]

    def mkpos(client):
        def fn(i, c=client):
            return i
        return fn

    def mkkw(client):
        def fn(i, *, c=client):
            return i
        return fn

    def mknested(client):
        def fn(i, c={"wrapped": client}):
            return i
        return fn

    cases = [
        ("positional", lambda: _fn_plan(wc, mkpos(_Exotic()))),
        ("kwdefaults", lambda: _fn_plan(wc, mkkw(_Exotic()))),
        ("nested", lambda: _fn_plan(wc, mknested(_Exotic()))),
    ]
    for label, build in cases:
        code = _refusal_code(build)
        if code != REFUSAL:
            return _record(pid, "BREAK",
                           "F396: exotic default (%s) not refused coded: "
                           "%r" % (label, code))

    def mkaction(client):
        def act(params, c=client):
            return {}, []
        return act

    def mkcomp(params):
        return {}, []

    code = _refusal_code(
        lambda: wc.ComposedPlan([{
            "kind": "saga", "name": "sg",
            "definition": saga_mod.SagaDefinition([
                saga_mod.SagaStepDef(
                    step_id="s1", action_op="a1", action_params={},
                    compensation_op="c1", compensation_params={})]),
            "action_fns": {"s1": mkaction(_Exotic())},
            "comp_fns": {"s1": mkcomp},
            "idem_key": "ksg"}]))
    if code != REFUSAL:
        return _record(pid, "BREAK",
                       "F396: exotic saga action default not refused "
                       "coded: %r" % (code,))
    _record(pid, "HELD",
            "exotic defaults refuse coded "
            "workflow-composed-definition-invalid on all channels "
            "(F396 closed)")


def p_f396_json_defaults_stable():
    # Crash-recovery stability: the same JSON-native defaults rebuilt
    # from the same source yield the same digest (no memory addresses,
    # no identity hashes); different values change it. Covers nested
    # defaults, kwdefaults-only, None/empty defaults, and kwdefaults
    # key ordering.
    pid = "F396-json-defaults-stable"
    wc = _composed_scaffold("f396e")[0]

    def mknested(cfg):
        def fn(i, c=cfg):
            return i
        return fn

    a1, a2 = mknested({"e": "x", "r": [1, 2]}), mknested(
        {"e": "x", "r": [1, 2]})
    b = mknested({"e": "y", "r": [1, 2]})
    fa1, fa2, fb = (wc._code_fingerprint(f) for f in (a1, a2, b))
    if fa1 != fa2:
        return _record(pid, "BREAK",
                       "same JSON-native defaults yield different "
                       "digests (crash-recovery stability broken)")
    if fa1 == fb:
        return _record(pid, "BREAK",
                       "different JSON-native defaults yield the same "
                       "digest")

    def mkkwonly():
        def fn(i, *, retries=3, endpoint="x"):
            return i
        return fn

    k1, k2 = mkkwonly(), mkkwonly()
    if wc._code_fingerprint(k1) != wc._code_fingerprint(k2):
        return _record(pid, "BREAK",
                       "kwdefaults-only fns unstable across rebuild")
    if (wc._code_fingerprint(k1)["defaults"] !=
            {"pos": [], "kw": [["endpoint", "x"], ["retries", 3]]}):
        return _record(pid, "BREAK",
                       "kwdefaults-only binding wrong: %r"
                       % (wc._code_fingerprint(k1)["defaults"],))

    def mkdefstyle(style):
        if style == "none":
            def fn(i):
                return i
        elif style == "empty":
            def fn(i, *a):
                return i
        else:
            def fn(i, x=1, *a, y=2):
                return i
        return fn

    # None vs empty defaults: both bind the empty marker; the
    # calling-convention difference (argcount/varnames) is already
    # covered by _code_fingerprint_inner.
    d_none, d_empty = mkdefstyle("none"), mkdefstyle("empty")
    if (wc._code_fingerprint(d_none)["defaults"] !=
            wc._code_fingerprint(d_empty)["defaults"]):
        return _record(pid, "BREAK",
                       "None vs empty defaults bind differently")

    # kwdefaults dict order cannot leak into the digest.
    def mkkworder(v):
        def fn(i, *, z=v, a=v):
            return i
        return fn

    o1, o2 = mkkworder(1), mkkworder(1)
    if wc._code_fingerprint(o1) != wc._code_fingerprint(o2):
        return _record(pid, "BREAK",
                       "kwdefaults key order leaks into the digest")
    _record(pid, "HELD",
            "JSON-native defaults bind by value, stable across rebuild "
            "(F396 closed)")


def p_f396_mutation_after_construction():
    # Documents the construction-time binding residual (same TOCTOU
    # class as F395 closures): the digest binds the defaults as of
    # plan construction; mutating __defaults__ afterwards does not
    # change the plan digest.
    pid = "F396-mutation-after-construction"
    wc = _composed_scaffold("f396f")[0]

    def mk(v):
        def fn(i, c=v):
            return i
        return fn

    fn = mk({"e": "real"})
    plan = _fn_plan(wc, fn)
    fn.__defaults__ = ({"e": "evil"},)
    # A fresh fingerprint sees the mutation (sanity: the probe's
    # mutation actually took effect at the fingerprinter level).
    if wc._code_fingerprint(fn) == wc._code_fingerprint(mk({"e": "real"})):
        return _record(pid, "ERROR",
                       "mutation did not change a fresh fingerprint; "
                       "probe void")
    # The plan digest still binds the construction-time values: it
    # matches a freshly built plan with the original defaults.
    if plan.digest != _fn_plan(wc, mk({"e": "real"})).digest:
        return _record(pid, "BREAK",
                       "plan digest does not reflect construction-time "
                       "defaults")
    _record(pid, "HELD",
            "plan digest binds construction-time defaults "
            "(post-construction mutation is a documented residual)")


def p_f396_f395_still_holds():
    # F395 not weakened: an exotic CLOSED-OVER value still refuses
    # coded.
    pid = "F396-f395-still-holds"
    wc = _composed_scaffold("f396g")[0]

    def mkfn(client):
        def fn(i):
            return client
        return fn

    code = _refusal_code(
        lambda: _fn_plan(wc, mkfn(_Exotic())))
    if code != REFUSAL:
        return _record(pid, "BREAK",
                       "F395 regressed: exotic closure not refused "
                       "coded: %r" % (code,))
    _record(pid, "HELD",
            "exotic closures still refuse coded (F395 holds)")


def p_f396_f393_still_holds():
    # F393 not weakened: different bytecode -> different digests;
    # uninspectable callables still refuse coded.
    pid = "F396-f393-still-holds"
    wc = _composed_scaffold("f396h")[0]

    def fna(i, c="x"):
        return i + 1

    def fnb(i, c="x"):
        return i + 2

    if wc._code_fingerprint(fna) == wc._code_fingerprint(fnb):
        return _record(pid, "BREAK",
                       "F393 regressed: different bytecode shares a "
                       "fingerprint")

    def add(i, x):
        return i

    for fn, label in [(functools.partial(add, 1), "partial"),
                      (len, "builtin")]:
        code = _refusal_code(
            lambda: _fn_plan(wc, fn))
        if code != REFUSAL:
            return _record(pid, "BREAK",
                           "F393 regressed: uninspectable %s not refused "
                           "coded: %r" % (label, code))
    _record(pid, "HELD",
            "bytecode binding and uninspectable refusal hold (F393 holds)")


# ------------------------------------------------------------------
# Green checks (depth-1; GOV_SKIP_GREEN=1 honored by green_check)
# ------------------------------------------------------------------

def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "green check skipped (GOV_SKIP_GREEN=1)")
        return
    # F396 CLOSED (this lane): the w311 red-team battery's F396 probes
    # now assert the fix; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w311_redteam", "evals/w311_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F395 closure regressions: the w311_f395 battery; no BREAKs.
    green_check.check_battery(
        _rec, "green-w311_f395", "evals/w311_f395_probes.py",
        repo=REPO, expect_break_ids=())
    # F394 closure regressions: the w310_f394 battery; no BREAKs.
    green_check.check_battery(
        _rec, "green-w310_f394", "evals/w310_f394_probes.py",
        repo=REPO, expect_break_ids=())
    # F393 closure regressions: the w309_f393 battery; no BREAKs.
    green_check.check_battery(
        _rec, "green-w309_f393", "evals/w309_f393_probes.py",
        repo=REPO, expect_break_ids=())


# ------------------------------------------------------------------
# Probe table + main
# ------------------------------------------------------------------

_PROBES = [
    ("pin-taxonomy", p_taxonomy_pin),
    ("footer-state", p_footer_state),
    # F396 CLOSED (this lane): all assert the fix.
    ("F396-defaults-fn-distinguished", p_f396_defaults_fn_distinguished),
    ("F396-kwdefaults-fn-distinguished", p_f396_kwdefaults_fn_distinguished),
    ("F396-defaults-saga-distinguished", p_f396_defaults_saga_distinguished),
    ("F396-exotic-default-refused", p_f396_exotic_default_refused),
    ("F396-json-defaults-stable", p_f396_json_defaults_stable),
    ("F396-mutation-after-construction", p_f396_mutation_after_construction),
    ("F396-f395-still-holds", p_f396_f395_still_holds),
    ("F396-f393-still-holds", p_f396_f393_still_holds),
]

_EXPECTED_BREAKS = frozenset()  # F396 CLOSED: no expected BREAKs.


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                _safe(pid, fn)
                break
        else:
            print("unknown probe", args.probe)
            sys.exit(2)
    else:
        for pid, fn in _PROBES:
            _safe(pid, fn)
        _green_checks()
    probe_lines.emit(_results)
    brk = sum(1 for r in _results if r[1] == "BREAK")
    held = sum(1 for r in _results if r[1] == "HELD")
    err = sum(1 for r in _results if r[1] == "ERROR")
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    # Open-findings sweep: exactly the expected BREAKs (all OPEN).
    # Exit 1 when any BREAK is present (open findings).
    if args.probe:
        return 0
    unexpected = [pid for pid, v, _ in _results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - frozenset(
        pid for pid, v, _ in _results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
