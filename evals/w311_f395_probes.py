"""Wave-311 lane A battery: F395 CLOSED (exotic closures refuse coded).

Base: wave-310 merge 38650946 (F394 CLOSED wave-310 lane A via the
composer-level retry API; F395 OPEN -- the F393 code binding collided
for exotic closures: `_closure_fingerprint` bound non-JSON-native
closure values by `type(value).__name__` only, so two fns with
identical bytecode closing over different instances of the same type
yielded identical plan digests, the run->plan binding passed, and the
victim's fn never executed).

Closure direction (this lane): `ComposedPlan` refuses coded
`workflow-composed-definition-invalid` for any non-JSON-native
("exotic") closed-over value, recursively (a nested exotic inside a
dict/list/tuple refuses too). Binding by type name collides (the F395
break); binding by repr is unstable across processes (memory
addresses) and would break crash-recovery re-execution. Refusal is
deterministic -- a plan that refuses refuses identically on every
rebuild. JSON-native closures keep the F393 by-value binding
(crash-recovery stable); uninspectable callables still refuse coded
(F393 not weakened). No new decision codes: pin stays 1851; footer
open none / next F396. This battery's expected BREAKs: none (all
F395 probes assert the coded refusal).

Run:
  mkdir -p /var/tmp/g311-f395 && TMPDIR=/var/tmp/g311-f395 \\
    ~/workspace/.gov-venv/bin/python evals/w311_f395_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g311-f395b \\
    ~/workspace/.gov-venv/bin/python evals/w311_f395_probes.py
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

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# F395 closure mints no new decision codes (reuses
# workflow-composed-definition-invalid): pin stays 1829.
TAXONOMY_PIN = 1857  # wave-310 merge: +1 workflow-composed-plan-mismatch

AT = 1000000
REFUSAL = "workflow-composed-definition-invalid"

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
    _record("pin-taxonomy", "HELD", "1857/1857/0 sorted")


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
    if nxt != 398 or open_s != "none":
        return _record("footer-state", "BREAK",
                       "footer drift: next F%d (want F398), open '%s' "
                       "(want 'none')" % (nxt, open_s))
    _record("footer-state", "HELD", "footer pins open none / next F398")


def _seed(s):
    return hashlib.sha256(("seed:" + s).encode()).digest()


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


class _Client:
    """Exotic (non-JSON-native) closure value: the F395 shape."""

    def __init__(self, endpoint):
        self.endpoint = endpoint

    def fetch(self):
        return {"data": "from-" + self.endpoint}


def _mkfn(client):
    # Shared factory: identical bytecode whatever client is closed
    # over. The realistic shape is a shared library closing over
    # per-deployment client/config objects.
    def fn(i):
        return client.fetch()
    return fn


def _refusal_code(build):
    try:
        build()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", None)
    return None


def p_f395_exotic_closure_fn_refused():
    # The F395 fn-path shape: a plan whose fn closes over an exotic
    # object must refuse coded at construction -- the confusion
    # scenario can no longer be built.
    wc = _composed_scaffold("f395a")[0]
    code = _refusal_code(
        lambda: wc.ComposedPlan([
            {"kind": "fn", "name": "u2", "fn": _mkfn(_Client("evil")),
             "inputs": {}, "idem_key": "k2"}]))
    if code != REFUSAL:
        return _record("F395-exotic-closure-fn-refused", "BREAK",
                       "exotic-closure fn plan not refused coded: %r" % (code,))
    _record("F395-exotic-closure-fn-refused", "HELD",
            "exotic-closure fn plan refuses coded "
            "workflow-composed-definition-invalid (F395 closed)")


def p_f395_exotic_closure_saga_refused():
    # Same defect class on the saga action path.
    from gov import workflow_saga as saga_mod
    wc = _composed_scaffold("f395b")[0]

    def mkaction(client):
        def action(params):
            return client.fetch(), []
        return action

    def mkdef():
        return saga_mod.SagaDefinition([
            saga_mod.SagaStepDef(step_id="s1", action_op="a",
                                 action_params={},
                                 compensation_op="c",
                                 compensation_params={}),
        ])

    code = _refusal_code(
        lambda: wc.ComposedPlan([{
            "kind": "saga", "name": "sg", "definition": mkdef(),
            "action_fns": {"s1": mkaction(_Client("evil"))},
            "comp_fns": {"s1": lambda p: None},
            "idem_key": "ksg"}]))
    if code != REFUSAL:
        return _record("F395-exotic-closure-saga-refused", "BREAK",
                       "exotic-closure saga plan not refused coded: %r" % (code,))
    _record("F395-exotic-closure-saga-refused", "HELD",
            "exotic-closure saga plan refuses coded "
            "workflow-composed-definition-invalid (F395 closed)")


def p_f395_fingerprint_refuses_coded():
    # The fingerprint seam itself refuses: no silent type-name
    # binding remains for exotic closures.
    wc = _composed_scaffold("f395c")[0]
    code = _refusal_code(lambda: wc._code_fingerprint(_mkfn(_Client("x"))))
    if code != REFUSAL:
        return _record("F395-fingerprint-refuses-coded", "BREAK",
                       "_code_fingerprint accepted an exotic closure: %r"
                       % (code,))
    _record("F395-fingerprint-refuses-coded", "HELD",
            "_code_fingerprint refuses exotic closures coded")


def p_f395_nested_exotic_refused():
    # An exotic nested inside JSON-native containers must refuse too
    # -- _canon's default=str would otherwise bind its repr silently
    # (the same defect class one level down).
    wc = _composed_scaffold("f395d")[0]

    def mknested(client):
        def fn(i):
            return ("a", client)
        return fn

    code = _refusal_code(lambda: wc._code_fingerprint(mknested(_Client("x"))))
    if code != REFUSAL:
        return _record("F395-nested-exotic-refused", "BREAK",
                       "nested exotic closure not refused coded: %r" % (code,))
    _record("F395-nested-exotic-refused", "HELD",
            "nested exotic closure refuses coded")


def p_f395_json_native_stable():
    # JSON-native closures keep the F393 by-value binding: a
    # same-source rebuild has the same digest (crash-recovery
    # stability) and different values have different digests.
    wc = _composed_scaffold("f395e")[0]

    def mkj(v):
        def fn(i):
            return v
        return fn

    v = {"a": [1, 2, ("x", None)], "b": True}
    p1 = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": mkj(v),
         "inputs": {}, "idem_key": "k"}])
    p2 = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": mkj({"a": [1, 2, ("x", None)],
                                               "b": True}),
         "inputs": {}, "idem_key": "k"}])
    p3 = wc.ComposedPlan([
        {"kind": "fn", "name": "u", "fn": mkj({"a": [1, 2, ("y", None)],
                                               "b": True}),
         "inputs": {}, "idem_key": "k"}])
    if p1.digest != p2.digest:
        return _record("F395-json-native-stable", "BREAK",
                       "same-source rebuild changed the digest "
                       "(crash-recovery regression)")
    if p1.digest == p3.digest:
        return _record("F395-json-native-stable", "BREAK",
                       "different JSON-native closure values share a digest")
    _record("F395-json-native-stable", "HELD",
            "JSON-native closures: rebuild-stable, value-distinguishing")


def p_f395_uninspectable_still_refused():
    # F393's uninspectable-callable refusal must not be weakened by
    # the F395 change (the refusal check order is unchanged).
    wc = _composed_scaffold("f395f")[0]
    for label, bad_fn in (("builtin", len),
                          ("partial", functools.partial(lambda i, x: x, x=1))):
        code = _refusal_code(
            lambda: wc.ComposedPlan([
                {"kind": "fn", "name": "u", "fn": bad_fn,
                 "inputs": {}, "idem_key": "k"}]))
        if code != REFUSAL:
            return _record("F395-uninspectable-still-refused", "BREAK",
                           "%s: uninspectable fn not refused coded: %r"
                           % (label, code))
    _record("F395-uninspectable-still-refused", "HELD",
            "builtin and functools.partial still refuse coded (F393 intact)")


def p_f395_attack_scenario_dead():
    # End-to-end: the original F395 attack (evil plan executes, victim
    # plan replays the attacker's record) cannot be constructed --
    # both the evil and the victim plan refuse coded at construction,
    # so the victim's fn is never at risk of silent non-execution.
    wc, wf, saga, idem, comp, ws, sm, im, auth = _composed_scaffold("f395g")
    evil_code = _refusal_code(
        lambda: wc.ComposedPlan([
            {"kind": "fn", "name": "u2", "fn": _mkfn(_Client("evil")),
             "inputs": {}, "idem_key": "k2"}]))
    victim_code = _refusal_code(
        lambda: wc.ComposedPlan([
            {"kind": "fn", "name": "u2", "fn": _mkfn(_Client("real")),
             "inputs": {}, "idem_key": "k2"}]))
    if evil_code != REFUSAL or victim_code != REFUSAL:
        return _record("F395-attack-scenario-dead", "BREAK",
                       "attack plans not refused: evil=%r victim=%r"
                       % (evil_code, victim_code))
    _record("F395-attack-scenario-dead", "HELD",
            "evil and victim exotic-closure plans both refuse coded; "
            "the replay-confusion scenario cannot be constructed")


def p_f395_lying_container_refused():
    # Spec-review residual: json.dumps honors overridden .items()/
    # __iter__ on dict/list/tuple subclasses, so a lying subclass
    # could make the digest bind different bytes than the fn reads
    # at runtime (an F395-shaped collision channel). Containers must
    # be the exact builtin types; subclasses refuse coded.
    wc = _composed_scaffold("f395h")[0]

    class LyingDict(dict):
        def items(self):
            return [("x", 1)]

    def mkfn(hidden):
        def fn(i):
            return dict.__getitem__(hidden, "real")
        return fn

    code = _refusal_code(
        lambda: wc.ComposedPlan([
            {"kind": "fn", "name": "u2", "fn": mkfn(LyingDict({"real": 1})),
             "inputs": {}, "idem_key": "k2"}]))
    if code != REFUSAL:
        return _record("F395-lying-container-refused", "BREAK",
                       "lying dict subclass plan not refused: %r" % code)
    _record("F395-lying-container-refused", "HELD",
            "dict-subclass closure refuses coded "
            "workflow-composed-definition-invalid")


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
    # F395 CLOSED (this lane): the w310 red-team battery's F395
    # probes now assert the coded refusal; expect no BREAKs.
    green_check.check_battery(
        _rec, "green-w310_redteam", "evals/w310_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # F393 closure regressions: the w309_f393 battery; no BREAKs.
    green_check.check_battery(
        _rec, "green-w309_f393", "evals/w309_f393_probes.py",
        repo=REPO, expect_break_ids=())
    # F394 closure regressions: the w310_f394 battery; no BREAKs.
    green_check.check_battery(
        _rec, "green-w310_f394", "evals/w310_f394_probes.py",
        repo=REPO, expect_break_ids=())
    # F391 closure regressions: the w308_f391 battery; no BREAKs.
    green_check.check_battery(
        _rec, "green-w308_f391", "evals/w308_f391_probes.py",
        repo=REPO, expect_break_ids=())


# ------------------------------------------------------------------
# Probe table + main
# ------------------------------------------------------------------

_PROBES = [
    ("pin-taxonomy", p_taxonomy_pin),
    ("footer-state", p_footer_state),
    # F395 CLOSED (this lane): all assert the coded refusal.
    ("F395-exotic-closure-fn-refused", p_f395_exotic_closure_fn_refused),
    ("F395-exotic-closure-saga-refused", p_f395_exotic_closure_saga_refused),
    ("F395-fingerprint-refuses-coded", p_f395_fingerprint_refuses_coded),
    ("F395-nested-exotic-refused", p_f395_nested_exotic_refused),
    ("F395-json-native-stable", p_f395_json_native_stable),
    ("F395-uninspectable-still-refused", p_f395_uninspectable_still_refused),
    ("F395-attack-scenario-dead", p_f395_attack_scenario_dead),
    ("F395-lying-container-refused", p_f395_lying_container_refused),
]

_EXPECTED_BREAKS = frozenset()  # F395 CLOSED: no expected BREAKs.


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
    for pid, verdict, note in _results:
        first = note.splitlines()[0] if note else ""
        print("[VERDICT] %s: %s: %s" % (verdict, pid, first))
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
