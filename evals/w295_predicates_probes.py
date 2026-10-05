"""Wave-295 lane 3 red-first battery: bounded predicate language.

Probes the two-phase CHECK/EVALUATE discipline of gov/rule_predicates.py
and its wiring into Conditional tool rules in gov/tool_rules.py:

* undeclared fields refuse coded at COMPILE time (cel-go check phase);
* type confusion refuses at compile time (never a silent runtime False);
* over-bound ASTs refuse coded budget (expr MemoryBudget discipline);
* evaluation is pure/synchronous/bounded -- no uncoded escapes (F351);
* post-freeze spec mutation cannot change a compiled predicate;
* the predicate observes aggregates only (side channel closed);
* rule-set wiring: false -> toolcall-sequence-violated; old shapes
  unchanged (additive).

Red-first: on the pristine base (no gov/rule_predicates.py) every probe
BREAKs (feature absent). After the lane: 0 BREAK / 28 HELD / 0 ERROR.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import re
import subprocess
import tempfile

TAXONOMY_PIN = 2088 # Wave-295 lane 3: pin 1742 -> 1745 (+3 toolcall-predicate-*).; Wave-295 merge: pin 1745 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*)



SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

REPO = os.path.join(os.path.dirname(__file__), "..")

try:
    from gov import rule_predicates as rp
    from gov import tool_rules as tr
    from gov import decision_codes
    HAVE_FEATURE = True
except ImportError:
    HAVE_FEATURE = False


def _expect_code(fn, code):
    """Run fn; return 'held' iff it raises with the expected coded refusal."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - battery classifies
        got = getattr(exc, "code", None)
        if got == code:
            return "held"
        return "break: wrong code %r (wanted %r): %s" % (got, code, exc)
    return "break: no refusal (wanted %r)" % (code,)


def _ruleset_with_predicate(predicate, extra=None):
    doc = {
        "format": "sasanam-tool-rule-set/v1",
        "name": "w295-probe",
        "tools": ["read", "write"],
        "rules": [
            {"kind": "Conditional", "tool": "write", "predicate": predicate},
        ],
    }
    if extra:
        doc.update(extra)
    return tr.compile_rule_set(doc)


PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


@probe("undeclared-field compile-time refuse")
def _p1():
    return _expect_code(
        lambda: rp.compile_predicate({"field": "caller_ssn"}),
        "toolcall-predicate-undeclared-field")


@probe("undeclared field nested deep in AST")
def _p2():
    spec = {"op": "and", "args": [
        {"field": "started"},
        {"op": "not", "args": [{"field": "wall_clock"}]},
    ]}
    return _expect_code(lambda: rp.compile_predicate(spec),
                        "toolcall-predicate-undeclared-field")


@probe("unknown builtin refuses")
def _p3():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "exec", "args": [{"field": "started"}]}),
        "toolcall-predicate-invalid")


@probe("arity violation refuses")
def _p4():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "and", "args": [{"field": "started"}]}),
        "toolcall-predicate-invalid")


@probe("type confusion gt(str,int) refuses at compile")
def _p5():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "gt",
             "args": [{"field": "last_tool"}, {"const": 1}]}),
        "toolcall-predicate-invalid")


@probe("bool/int confusion eq(true,1) refuses at compile")
def _p6():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "eq", "args": [{"const": True}, {"const": 1}]}),
        "toolcall-predicate-invalid")


@probe("non-bool result refuses (result pinned to bool)")
def _p7():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "len", "args": [{"field": "last_tool"}]}),
        "toolcall-predicate-invalid")


@probe("float const refuses")
def _p8():
    return _expect_code(
        lambda: rp.compile_predicate({"const": 1.5}),
        "toolcall-predicate-invalid")


@probe("over-node AST refuses coded budget at compile")
def _p9():
    big = {"field": "started"}
    for _ in range(rp.MAX_AST_NODES + 10):
        big = {"op": "and", "args": [big, {"field": "started"}]}
    return _expect_code(lambda: rp.compile_predicate(big),
                        "toolcall-predicate-budget")


@probe("oversized const string refuses")
def _p10():
    return _expect_code(
        lambda: rp.compile_predicate({"const": "x" * (rp.MAX_CONST_STR_LEN + 1)}),
        "toolcall-predicate-invalid")


@probe("heterogeneous const list refuses")
def _p11():
    return _expect_code(
        lambda: rp.compile_predicate({"const": [1, "two"]}),
        "toolcall-predicate-invalid")


@probe("in with mismatched list type refuses")
def _p12():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "in",
             "args": [{"field": "last_tool"}, {"const": [1, 2]}]}),
        "toolcall-predicate-invalid")


@probe("contains on non-str refuses")
def _p13():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "contains",
             "args": [{"field": "calls"}, {"const": "x"}]}),
        "toolcall-predicate-invalid")


@probe("len on non-str refuses")
def _p14():
    return _expect_code(
        lambda: rp.compile_predicate(
            {"op": "len", "args": [{"field": "calls"}]}),
        "toolcall-predicate-invalid")


@probe("empty spec dict refuses")
def _p15():
    return _expect_code(lambda: rp.compile_predicate({}),
                        "toolcall-predicate-invalid")


@probe("non-dict spec refuses")
def _p16():
    return _expect_code(lambda: rp.compile_predicate([{"field": "started"}]),
                        "toolcall-predicate-invalid")


@probe("post-freeze spec mutation cannot change the compiled predicate")
def _p17():
    spec = {"op": "gte",
            "args": [{"field": "calls"}, {"const": 5}]}
    compiled = rp.compile_predicate(spec)
    spec["args"][1]["const"] = 0  # attacker mutates the caller's dict
    fields = {"calls": 1, "last_tool": "", "distinct_tools": 0,
              "started": True}
    if compiled.evaluate(fields) is False:
        return "held"
    return "break: compiled predicate followed the mutated spec"


@probe("CompiledPredicate attribute assignment refuses coded")
def _p18():
    compiled = rp.compile_predicate({"field": "started"})
    return _expect_code(lambda: setattr(compiled, "x", 1),
                        "toolcall-predicate-invalid")


@probe("wrong runtime value type refuses coded (never uncoded)")
def _p19():
    compiled = rp.compile_predicate(
        {"op": "gte", "args": [{"field": "calls"}, {"const": 1}]})
    return _expect_code(
        lambda: compiled.evaluate({"calls": "1", "last_tool": "",
                                   "distinct_tools": 0, "started": True}),
        "toolcall-predicate-invalid")


@probe("missing runtime field refuses coded")
def _p20():
    compiled = rp.compile_predicate({"field": "started"})
    return _expect_code(lambda: compiled.evaluate({"started": True}),
                        "toolcall-predicate-invalid")


@probe("predicate observes aggregates only (side channel closed)")
def _p21():
    fields = rp.session_fields([{"tool": "read", "args": {"k": "sk-secret"}}])
    if set(fields) != {"calls", "last_tool", "distinct_tools", "started"}:
        return "break: env exposes %r" % (sorted(fields),)
    if fields != {"calls": 1, "last_tool": "read", "distinct_tools": 1,
                  "started": True}:
        return "break: env values wrong: %r" % (fields,)
    return "held"


@probe("rule-set wiring: false predicate -> sequence-violated")
def _p22():
    rs = _ruleset_with_predicate(
        {"op": "gte", "args": [{"field": "calls"}, {"const": 1}]})
    return _expect_code(lambda: rs.check_call("write", {}, []),
                        "toolcall-sequence-violated")


@probe("rule-set wiring: true predicate -> allowed")
def _p23():
    rs = _ruleset_with_predicate(
        {"op": "gte", "args": [{"field": "calls"}, {"const": 1}]})
    rec = rs.check_call("write", {}, [{"tool": "read"}])
    return "held" if rec.get("allowed") else "break: true predicate denied"


@probe("when+predicate together refuse compile-invalid")
def _p24():
    doc = {
        "format": "sasanam-tool-rule-set/v1",
        "name": "w295-probe",
        "tools": ["read", "write"],
        "predicates": {"p1": {"kind": "flag", "flag": "f"}},
        "rules": [{"kind": "Conditional", "tool": "write",
                   "when": "p1", "predicate": {"field": "started"}}],
    }
    return _expect_code(lambda: tr.compile_rule_set(doc),
                        "toolcall-rule-compile-invalid")


@probe("predicate_env widening refuses undeclared-field")
def _p25():
    return _expect_code(
        lambda: _ruleset_with_predicate(
            {"field": "started"}, {"predicate_env": {"evil": "str"}}),
        "toolcall-predicate-undeclared-field")


@probe("predicate_env type lie refuses compile-invalid")
def _p26():
    return _expect_code(
        lambda: _ruleset_with_predicate(
            {"op": "gte", "args": [{"field": "calls"}, {"const": 1}]},
            {"predicate_env": {"calls": "str"}}),
        "toolcall-rule-compile-invalid")


@probe("over-bound predicate in rule doc refuses compile-invalid")
def _p27():
    big = {"field": "started"}
    for _ in range(rp.MAX_AST_NODES + 10):
        big = {"op": "and", "args": [big, {"field": "started"}]}
    # At the rule-set seam every predicate compile violation except the
    # undeclared-field code surfaces as toolcall-rule-compile-invalid
    # (composition contract); the budget code is observable on direct
    # compile_predicate calls (probe 9).
    return _expect_code(lambda: _ruleset_with_predicate(big),
                        "toolcall-rule-compile-invalid")


@probe("old rule shapes unchanged (additive)")
def _p28():
    doc = {
        "format": "sasanam-tool-rule-set/v1",
        "name": "w295-probe-old",
        "tools": ["a", "b"],
        "predicates": {"p1": {"kind": "history", "tool": "a",
                              "min_calls": 1}},
        "rules": [
            {"kind": "Init", "tool": "a"},
            {"kind": "Conditional", "tool": "b", "when": "p1"},
        ],
    }
    rs = tr.compile_rule_set(doc)
    if not rs.check_call("a", {}, [])["allowed"]:
        return "break: Init rule changed behavior"
    try:
        rs.check_call("b", {}, [])
        return "break: when-rule stopped enforcing"
    except tr.ToolRuleError as exc:
        if exc.code != "toolcall-sequence-violated":
            return "break: wrong code %r" % (exc.code,)
    return "held"


def _taxonomy_pin_check():
    got = len(decision_codes.TAXONOMY)
    if got != TAXONOMY_PIN:
        return "break: taxonomy pin %d != %d" % (got, TAXONOMY_PIN)
    return "held"


def main():
    # Depth-1 green checks: adjacent batteries must stay green. Runs their
    # mains with GOV_SKIP_GREEN=1 in the child env (the wave-173
    # convention: never nest green checks).
    if not SKIP_GREEN:
        for rel, expected, label in (
                ("evals/w293_tool_rules_probes.py", 0, "w293-tool-rules"),
                ("evals/w294_filter_pipeline_probes.py", 0,
                 "w294-filter-pipeline")):
            d = tempfile.mkdtemp(prefix="w295-green-")
            try:
                proc = subprocess.run(
                    [sys.executable, os.path.join(REPO, rel)],
                    capture_output=True, text=True, timeout=900,
                    env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                             GOV_RUN_ROOT=os.path.join(d, "gov-run")))
            except Exception as exc:  # noqa: BLE001 - battery classifies
                print("GREEN-CHECK %s: ERROR %r" % (label, exc))
                return 2
            out = proc.stdout + proc.stderr
            ms = re.findall(r"(\d+)\s+BREAK", out)
            nbreak = int(ms[-1]) if ms else -1
            if nbreak != expected:
                print("GREEN-CHECK %s: BREAK (got %d, wanted %d)\n%s"
                      % (label, nbreak, expected, out[-2000:]))
                return 2
            print("GREEN-CHECK %s: HELD (%d BREAK as expected)"
                  % (label, nbreak))
    if not HAVE_FEATURE:
        print("BREAK: gov/rule_predicates.py absent (feature not built)")
        print("RESULT: %d BREAK / 0 HELD / 0 ERROR" % (len(PROBES),))
        return 1
    breaks, held, errors = [], [], []
    for name, fn in PROBES:
        try:
            outcome = fn()
        except Exception as exc:  # noqa: BLE001 - uncoded escape is a BREAK
            errors.append((name, "ERROR: uncoded %r: %s"
                           % (type(exc).__name__, exc)))
            continue
        if outcome == "held":
            held.append(name)
        else:
            breaks.append((name, outcome))
    pin = _taxonomy_pin_check()
    if pin != "held":
        breaks.append(("taxonomy pin", pin))
    else:
        held.append("taxonomy pin")
    for name, why in breaks:
        print("BREAK %s: %s" % (name, why))
    for name, why in errors:
        print("%s: %s" % (name, why))
    print("RESULT: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
