#!/usr/bin/env python3
"""Break-first probes for wave-194 R1: typed context-attribute schema
(the Cedar D1 steal).

The engine used to coerce context signals with bool()/int() at match
time, so a mistyped attribute was SILENTLY evaluated: ``
domain_allowlisted="false"`` (a truthy STRING) on an unallowlisted
domain skipped the ``deny-egress-unallowlisted`` forbid, and
``read_classified="false"`` made a ``read_classified: true`` rule fire.
The fix: a declared schema at the Request layer -- mistyped attributes
are refused LOUD (ContextTypeError, a TypeError) at construction, never
coerced.

RED-PHASE (--red-phase): the gap demonstration on the pristine tree --
mistyped attributes are silently evaluated and change verdicts or
diagnostics. Exit 0 = gap shown.

GREEN-PHASE (default): the closure battery. Mistyped attributes must be
REFUSED with a machine-distinguishable error; well-typed contexts must
evaluate EXACTLY as before (verdict + deciding rule pinned); None stays
the absence sentinel; unknown keys pass through; the policy-file side
refuses mistyped match values at load; and a self-maintaining pin
asserts every bool-compare key in _matches is declared in the schema.

Usage:
  python3 evals/typed_context_probes.py --red-phase   # gap demo
  python3 evals/typed_context_probes.py               # closure battery

Deterministic: no time, randomness, or network anywhere. main() runs
the battery twice and requires identical statuses.

Conventions: module-level GOV_DEPLOYMENT_MODE=staging; verify standalone
under `env -u GOV_DEPLOYMENT_MODE`; GOV_SKIP_GREEN honored; green check
is depth-1 (adjacent unit modules only, child env GOV_SKIP_GREEN=1);
the battery never touches the shared tree -- TREE is the tree it lives in.
"""

import os
import re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TREE = REPO_ROOT  # this battery lives in the tree it tests
sys.path.insert(0, TREE)


def _eng():
    from gov.policy import PolicyEngine, default_policy_path
    return PolicyEngine(default_policy_path())


def _custom(text):
    from gov.policy import PolicyEngine
    return PolicyEngine.from_text(text, source_label="<typed-ctx-probe>")


def _req(context, tool="http_post", args=None, role="analyst"):
    from gov.decision_contract import Request
    return Request(principal="alice", action=tool, resource=None,
                   role=role, args=args or {}, context=context)


def _decide(eng, context, tool="http_post", args=None, role="analyst"):
    return eng.decide(_req(context, tool=tool, args=args, role=role))


EVIL = {"url": "https://evil.example/x"}
ALLOWLISTED = {"url": "https://synthetic.local/x"}


# --------------------------------------------------------------------------
# Red-phase: the gap demonstration (pristine tree only).
# --------------------------------------------------------------------------

def red_egress_string_false_flips_verdict():
    """domain_allowlisted="false" (str) on an unallowlisted domain: the
    deny-egress-unallowlisted forbid silently MISSES."""
    eng = _eng()
    mistyped = _decide(eng, {"domain_allowlisted": "false"}, args=EVIL)
    control = _decide(eng, {"domain_allowlisted": False}, args=EVIL)
    assert mistyped.effect == "require_approval", mistyped.effect
    assert mistyped.policy_id == "approval-outbound-sends", mistyped.policy_id
    assert control.effect == "deny", control.effect
    assert control.policy_id == "deny-egress-unallowlisted", control.policy_id
    return ("PASS",
            "gap: str 'false' -> %s/%s, bool False -> %s/%s"
            % (mistyped.effect, mistyped.policy_id,
               control.effect, control.policy_id))


def red_classified_string_false_fires_true_rule():
    """read_classified="false" (truthy str) makes a rule requiring
    read_classified: TRUE fire -- the diagnostic names the wrong rule."""
    eng = _eng()
    ctx = {"read_classified": "false", "domain_allowlisted": True}
    mistyped = _decide(eng, ctx, args=ALLOWLISTED)
    control = _decide(eng, {"read_classified": False,
                            "domain_allowlisted": True}, args=ALLOWLISTED)
    assert mistyped.policy_id == "approval-classified-egress", \
        mistyped.policy_id
    assert control.policy_id == "approval-outbound-sends", control.policy_id
    return ("PASS",
            "gap: str 'false' decided by %s, bool False by %s"
            % (mistyped.policy_id, control.policy_id))


def red_counter_string_coerced():
    """counters={"api_call": "5"} (str) is silently int()-coerced."""
    eng = _custom(
        "version: 2\npolicies:\n"
        "  - id: allow-api-after-five\n    effect: allow\n"
        "    match:\n      tool: [api_call]\n      min_external_calls: 5\n"
        "    reason: enough prior calls\n")
    mistyped = _decide(eng, {"counters": {"api_call": "5"}},
                       tool="api_call",
                       args={"endpoint": "https://synthetic.local/x"})
    control = _decide(eng, {"counters": {"api_call": 3}},
                      tool="api_call",
                      args={"endpoint": "https://synthetic.local/x"})
    assert mistyped.effect == "allow", mistyped.effect
    assert control.effect == "deny", control.effect
    return ("PASS",
            "gap: counters '5' (str) -> allow, counters 3 (int) -> deny")


def red_policy_side_string_loads_silently():
    """A policy file with domain_allowlisted: "false" (YAML string)
    loads without complaint -- the authoring-side twin of the bug."""
    _custom(
        "version: 2\npolicies:\n"
        "  - id: x\n    effect: deny\n"
        "    match:\n      tool: [http_post]\n      domain_allowlisted: \"false\"\n"
        "    reason: r\n")
    return "PASS", "gap: mistyped policy match value loads silently"


RED_PROBES = [
    ("red_egress_string_false_flips_verdict",
     red_egress_string_false_flips_verdict),
    ("red_classified_string_false_fires_true_rule",
     red_classified_string_false_fires_true_rule),
    ("red_counter_string_coerced", red_counter_string_coerced),
    ("red_policy_side_string_loads_silently",
     red_policy_side_string_loads_silently),
]


# --------------------------------------------------------------------------
# Green-phase: the closure battery.
# --------------------------------------------------------------------------

def _expect_type_refusal(fn, key):
    """fn() must raise TypeError naming the offending key."""
    from gov.decision_contract import Request  # noqa: F401 (seam check)
    try:
        fn()
    except TypeError as e:
        assert key in str(e), \
            "refusal must name the key %r: %s" % (key, e)
        return "PASS", "refused loud, names %r" % key
    raise AssertionError("mistyped %r was NOT refused" % key)


def probe_string_false_refused():
    """T1: domain_allowlisted="false" is REFUSED at construction."""
    return _expect_type_refusal(
        lambda: _req({"domain_allowlisted": "false"}, args=EVIL),
        "domain_allowlisted")


def probe_classified_string_refused():
    """T2: read_classified="false" is REFUSED at construction."""
    return _expect_type_refusal(
        lambda: _req({"read_classified": "false"}, args=ALLOWLISTED),
        "read_classified")


def probe_int_for_bool_refused():
    """T3: domain_allowlisted=1 (int) is REFUSED -- truthy ints are not
    bools."""
    return _expect_type_refusal(
        lambda: _req({"domain_allowlisted": 1}, args=EVIL),
        "domain_allowlisted")


def probe_counter_string_refused():
    """T4: counters={"api_call": "5"} is REFUSED."""
    return _expect_type_refusal(
        lambda: _req({"counters": {"api_call": "5"}},
                      tool="api_call",
                      args={"endpoint": "https://synthetic.local/x"}),
        "api_call")


def probe_counter_bool_refused():
    """T5: counters={"api_call": True} is REFUSED -- bool is not int."""
    return _expect_type_refusal(
        lambda: _req({"counters": {"api_call": True}},
                      tool="api_call",
                      args={"endpoint": "https://synthetic.local/x"}),
        "api_call")


def probe_policy_side_string_refused():
    """T6: policy with domain_allowlisted: "false" (string) is REFUSED
    at load."""
    try:
        _custom(
            "version: 2\npolicies:\n"
            "  - id: x\n    effect: deny\n"
            "    match:\n      tool: [http_post]\n      domain_allowlisted: \"false\"\n"
            "    reason: r\n")
    except ValueError as e:
        assert "domain_allowlisted" in str(e), e
        return "PASS", "policy load refused, names the key"
    raise AssertionError("mistyped policy match value loaded silently")


def probe_policy_side_threshold_string_refused():
    """T7: policy with min_external_calls: "5" (string) is REFUSED at
    load."""
    try:
        _custom(
            "version: 2\npolicies:\n"
            "  - id: x\n    effect: allow\n"
            "    match:\n      tool: [api_call]\n      min_external_calls: \"5\"\n"
            "    reason: r\n")
    except ValueError as e:
        assert "min_external_calls" in str(e), e
        return "PASS", "policy load refused, names the key"
    raise AssertionError("mistyped threshold loaded silently")


def probe_valid_contexts_unchanged():
    """T8: well-typed contexts evaluate EXACTLY as the pristine pins
    (verdict + deciding rule)."""
    eng = _eng()
    pins = [
        ({"domain_allowlisted": False}, EVIL, "http_post",
         ("deny", "deny-egress-unallowlisted")),
        ({"domain_allowlisted": True}, ALLOWLISTED, "http_post",
         ("require_approval", "approval-outbound-sends")),
        ({"read_classified": False, "domain_allowlisted": True},
         ALLOWLISTED, "http_post",
         ("require_approval", "approval-outbound-sends")),
        ({"counters": {"api_call": 7}}, {"path": "/sandbox/a.txt"},
         "read_file", ("allow", "allow-sandbox-reads")),
    ]
    for ctx, args, tool, (effect, policy_id) in pins:
        d = _decide(eng, dict(ctx), tool=tool, args=args)
        assert (d.effect, d.policy_id) == (effect, policy_id), \
            "pin drift for %r: got (%s, %s)" % (ctx, d.effect, d.policy_id)
    return "PASS", "%d pristine pins identical" % len(pins)


def probe_none_is_absence():
    """T9: None for a bool signal == the key being absent (the
    documented absence convention), and evaluate() accepts it."""
    eng = _eng()
    with_none = _decide(eng, {"domain_allowlisted": None}, args=EVIL)
    absent = _decide(eng, {}, args=EVIL)
    assert (with_none.effect, with_none.policy_id) == \
        (absent.effect, absent.policy_id) == \
        ("deny", "deny-egress-unallowlisted"), \
        (with_none.effect, with_none.policy_id)
    # evaluate() (the legacy seam) also accepts None contexts.
    pd = eng.evaluate({"tool": "http_post", "role": "analyst",
                       "agent_id": "alice", "args": EVIL},
                      {"domain_allowlisted": None})
    assert (pd.effect, pd.policy_id) == ("deny", "deny-egress-unallowlisted")
    return "PASS", "None == absent, no false-positive refusal"


def probe_unknown_keys_pass_through():
    """T10: undeclared keys pass through (forward compatibility)."""
    eng = _eng()
    d = _decide(eng, {"domain_allowlisted": False,
                      "some_future_signal": "x", "role": "analyst"},
                args=EVIL)
    assert (d.effect, d.policy_id) == ("deny", "deny-egress-unallowlisted"), \
        (d.effect, d.policy_id)
    return "PASS", "unknown keys ignored, verdict unaffected"


def probe_direct_matches_also_strict():
    """T11: _matches itself refuses mistyped input (defense in depth
    for direct callers)."""
    eng = _eng()
    match = {"tool": ["http_post"], "domain_allowlisted": False}
    action = {"tool": "http_post", "role": "analyst",
              "agent_id": "alice", "args": EVIL}
    try:
        eng._matches(match, action, {"domain_allowlisted": "false"})
    except TypeError as e:
        assert "domain_allowlisted" in str(e), e
        return "PASS", "_matches refused, names the key"
    raise AssertionError("_matches silently coerced")


def probe_schema_covers_match_keys():
    """T12: self-maintaining pin -- every bool signal read in _matches
    goes through the strict accessor AND is declared in the schema, so
    a future bool-compare key that skips the schema fails this probe."""
    from gov import context_schema as cs
    import gov.policy as pol
    src = open(pol.__file__).read()
    # No bare bool()/int() coercion of context/counters may remain in
    # _matches: all reads go through the checked accessors.
    assert not re.search(r'bool\(context\.get\("', src), \
        "bare bool(context.get(...)) coercion remains in policy.py"
    assert not re.search(r'int\(counters\.get\("', src), \
        "bare int(counters.get(...)) coercion remains in policy.py"
    strict_bool_reads = set(
        re.findall(r'checked_bool\(context, "([a-z_]+)"\)', src))
    undeclared = strict_bool_reads - cs.BOOL_SIGNALS
    assert not undeclared, "bool signal keys missing from schema: %r" \
        % (undeclared,)
    counter_reads = set(
        re.findall(r'checked_counter\(counters, "([a-z_]+)"\)', src))
    assert strict_bool_reads, "pin vacuous: no checked_bool reads found"
    assert counter_reads, "pin vacuous: no checked_counter reads found"
    return ("PASS",
            "%d bool keys + %d counter reads via strict accessors, "
            "no bare coercions"
            % (len(strict_bool_reads), len(counter_reads)))


PROBES = [
    ("string_false_refused", probe_string_false_refused),
    ("classified_string_refused", probe_classified_string_refused),
    ("int_for_bool_refused", probe_int_for_bool_refused),
    ("counter_string_refused", probe_counter_string_refused),
    ("counter_bool_refused", probe_counter_bool_refused),
    ("policy_side_string_refused", probe_policy_side_string_refused),
    ("policy_side_threshold_string_refused",
     probe_policy_side_threshold_string_refused),
    ("valid_contexts_unchanged", probe_valid_contexts_unchanged),
    ("none_is_absence", probe_none_is_absence),
    ("unknown_keys_pass_through", probe_unknown_keys_pass_through),
    ("direct_matches_also_strict", probe_direct_matches_also_strict),
    ("schema_covers_match_keys", probe_schema_covers_match_keys),
]


def _run_once(probes):
    results = []
    for name, fn in probes:
        try:
            status, detail = fn()
        except AssertionError as e:
            status, detail = "FAIL", "assertion: %s" % (e,)
        except Exception as e:  # noqa: BLE001 - probes must not crash
            status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
        results.append((name, status, detail))
    return results


def _green_check():
    """Depth-1: adjacent unit modules only, child env GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="typedctx-green-")
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_decision_contract",
             "tests.test_policy_d1",
             "tests.test_typed_context"],
            capture_output=True, text=True, timeout=600, cwd=TREE,
            env=env)
        tail = (p.stdout + p.stderr)[-1500:]
        print("green check (decision_contract/policy_d1/typed_context):\n%s"
              % tail)
        return p.returncode == 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    red_phase = "--red-phase" in argv
    probes = RED_PROBES if red_phase else PROBES
    first = _run_once(probes)
    second = _run_once(probes)
    det_ok = ([(n, s) for n, s, _ in first]
              == [(n, s) for n, s, _ in second])
    width = max(len(n) for n, _, _ in first)
    print("== typed_context probes (%s) =="
          % ("RED-PHASE: gap demonstration" if red_phase else
             "GREEN-PHASE: closure battery"))
    for name, status, detail in first:
        print("%-*s %s  %s" % (width, name, status, detail))
    print("determinism x2: %s" % ("IDENTICAL" if det_ok else "DIVERGED"))
    if red_phase:
        # Gap demonstration: mistyped attributes are silently
        # evaluated on the pristine tree. Exit 0 = gap shown.
        if all(s == "PASS" for _, s, _ in first) and det_ok:
            print("GAP SHOWN: %d/%d reds demonstrated, statuses identical x2"
                  % (len(first), len(first)))
            return 0
        print("RED-PHASE INCONCLUSIVE")
        return 1
    if not _green_check():
        print("GREEN CHECK FAILED")
        return 1
    bad = [(n, d) for n, s, d in first if s != "PASS"]
    if bad or not det_ok:
        print("%d probe(s) failing" % len(bad))
        for n, d in bad:
            print("  FAIL %s: %s" % (n, d))
        return 1
    print("ALL %d PROBES PASS" % len(first))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
