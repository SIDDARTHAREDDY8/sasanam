"""Wave-294 lane 4 red-first battery: typed tool schemas.

Builds gov/tool_schemas.py (pydantic/pydantic-ai ADAPT, MIT, mechanism
only, stdlib only): declarative typed field schemas (string/integer/
boolean/enum, bounded list/dict of typed members, optional-with-default),
frozen at compile, validated at call time before the tool body runs;
credential-field names refused at compile; secret-shaped values refused
at call time; opt-in composition with gov/tool_call_policy.py's decide
seam.

Base: wave-293 push 8fa5bbeb3bea7ca16b0c82b3e65ddfdca551acb6
(verified via git rev-parse HEAD before work).

Pin 1742 -> 1742 (+4 toolcall-schema-*: compile-invalid, invalid,
secret-field, unknown-tool); the repoint is tree-wide (value-token-only,
code/comment splitter, history comments extended), so adjacent batteries'
own pin probes stay green.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g294-ts && TMPDIR=/var/tmp/g294-ts \\
    ~/workspace/.gov-venv/bin/python evals/w294_tool_schemas_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g294-tsb \\
    ~/workspace/.gov-venv/bin/python evals/w294_tool_schemas_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-294 lane 4: pin 1730 -> 1734 (+4 toolcall-schema-*).
TAXONOMY_PIN = 1753  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

try:
    from gov import tool_schemas as TS
except ImportError:
    TS = None

try:
    from gov import tool_call_policy as TP
except ImportError:
    TP = None

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _have_ts(pid):
    if TS is None:
        _record(pid, "BREAK", "gov.tool_schemas absent (feature not built)")
        return False
    return True


def _have_tp(pid):
    if TP is None:
        _record(pid, "BREAK", "gov.tool_call_policy absent")
        return False
    return True


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
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN,
                                                       TAXONOMY_PIN))


def _schema_doc(**over):
    doc = {
        "format": "sasanam-tool-schema-set/v1",
        "name": "w294-probe-schemas",
        "tools": {
            "search": {"args": {
                "query": {"type": "string", "max_len": 64},
                "limit": {"type": "integer", "min_value": 1,
                          "max_value": 100, "optional": True,
                          "default": 10},
                "mode": {"type": "enum",
                         "choices": ["fast", "deep"],
                         "optional": True, "default": "fast"},
                "tags": {"type": "list",
                         "element": {"type": "string", "max_len": 16},
                         "max_items": 8, "optional": True},
                "flags": {"type": "dict",
                          "value": {"type": "boolean"},
                          "max_items": 16, "optional": True},
            }},
        },
    }
    doc.update(over)
    return doc


def _expect_coded(pid, fn, code):
    """fn must raise with .code == code -> HELD; anything else -> BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        got = getattr(e, "code", None)
        if got == code:
            return _record(pid, "HELD", "refused coded %s" % (code,))
        return _record(pid, "BREAK",
                       "refused with code=%r, want %r (%r)" % (got, code, e))
    _record(pid, "BREAK", "no refusal raised; want coded %s" % (code,))


# ---------------------------------------------------------------------------
# compile_schema_set
# ---------------------------------------------------------------------------

def p_compile_valid():
    if not _have_ts("ts-compile-valid"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    ss2 = TS.compile_schema_set(_schema_doc())
    if ss.digest != ss2.digest or not ss.digest:
        _record("ts-compile-valid", "BREAK", "digest unstable/empty")
    elif ss.tools != ("search",):
        _record("ts-compile-valid", "BREAK",
                "closed inventory wrong: %r" % (ss.tools,))
    else:
        _record("ts-compile-valid", "HELD",
                "compiles; digest stable; inventory closed")


def p_compile_rejects_credential_field():
    if not _have_ts("ts-compile-credential-field"):
        return
    for bad in ("api_key", "password", "clientSecret", "ACCESS-TOKEN",
                "session_token"):
        doc = _schema_doc()
        doc["tools"]["search"]["args"][bad] = {"type": "string",
                                               "max_len": 8}
        _expect_coded("ts-compile-credential-field-%s" % bad,
                      lambda d=doc: TS.compile_schema_set(d),
                      "toolcall-schema-secret-field")


def p_compile_rejects_unbounded():
    if not _have_ts("ts-compile-unbounded"):
        return
    doc = _schema_doc()
    del doc["tools"]["search"]["args"]["query"]["max_len"]
    _expect_coded("ts-compile-unbounded-string",
                  lambda: TS.compile_schema_set(doc),
                  "toolcall-schema-compile-invalid")
    doc = _schema_doc()
    doc["tools"]["search"]["args"]["n"] = {"type": "integer"}
    _expect_coded("ts-compile-unbounded-integer",
                  lambda: TS.compile_schema_set(doc),
                  "toolcall-schema-compile-invalid")


def p_compile_rejects_unsafe_pattern():
    if not _have_ts("ts-compile-unsafe-pattern"):
        return
    doc = _schema_doc()
    doc["tools"]["search"]["args"]["query"]["pattern"] = r"(a+)+$"
    _expect_coded("ts-compile-unsafe-pattern",
                  lambda: TS.compile_schema_set(doc),
                  "toolcall-schema-compile-invalid")


def p_compile_rejects_bad_default():
    if not _have_ts("ts-compile-bad-default"):
        return
    doc = _schema_doc()
    doc["tools"]["search"]["args"]["limit"]["default"] = 500
    _expect_coded("ts-compile-bad-default",
                  lambda: TS.compile_schema_set(doc),
                  "toolcall-schema-compile-invalid")


def p_compile_frozen():
    if not _have_ts("ts-compile-frozen"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    try:
        ss._doc["tools"]["search"]["args"]["query"]["max_len"] = 99999
    except TypeError:
        _record("ts-compile-frozen", "HELD",
                "post-compile mutation raises TypeError at the source")
        return
    _record("ts-compile-frozen", "BREAK", "frozen doc was mutable")


# ---------------------------------------------------------------------------
# validate_args
# ---------------------------------------------------------------------------

def p_validate_ok_defaults():
    if not _have_ts("ts-validate-ok-defaults"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    out = ss.validate_args("search", {"query": "hello"})
    if out != {"query": "hello", "limit": 10, "mode": "fast"}:
        _record("ts-validate-ok-defaults", "BREAK",
                "defaults not injected: %r" % (out,))
    else:
        _record("ts-validate-ok-defaults", "HELD",
                "validates; defaults injected; order stable")


def p_type_confusion():
    if not _have_ts("ts-type-confusion"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-type-confusion-int-as-string",
                  lambda: ss.validate_args("search", {"query": 42}),
                  "toolcall-schema-invalid")


def p_range_escape():
    if not _have_ts("ts-range-escape"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-range-escape",
                  lambda: ss.validate_args("search",
                                           {"query": "q", "limit": 101}),
                  "toolcall-schema-invalid")


def p_bool_is_not_int():
    if not _have_ts("ts-bool-is-not-int"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-bool-is-not-int",
                  lambda: ss.validate_args("search",
                                           {"query": "q", "limit": True}),
                  "toolcall-schema-invalid")


def p_oversized_list():
    if not _have_ts("ts-oversized-list"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-oversized-list",
                  lambda: ss.validate_args(
                      "search", {"query": "q",
                                 "tags": ["t"] * 9}),
                  "toolcall-schema-invalid")


def p_undeclared_tool():
    if not _have_ts("ts-undeclared-tool"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-undeclared-tool",
                  lambda: ss.validate_args("shell", {}),
                  "toolcall-schema-unknown-tool")


def p_unknown_arg():
    if not _have_ts("ts-unknown-arg"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-unknown-arg",
                  lambda: ss.validate_args("search",
                                           {"query": "q", "oops": 1}),
                  "toolcall-schema-invalid")


def p_missing_required():
    if not _have_ts("ts-missing-required"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-missing-required",
                  lambda: ss.validate_args("search", {"limit": 5}),
                  "toolcall-schema-invalid")


def p_null_value():
    if not _have_ts("ts-null-value"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-null-value",
                  lambda: ss.validate_args("search",
                                           {"query": None}),
                  "toolcall-schema-invalid")


def p_enum_violation():
    if not _have_ts("ts-enum-violation"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-enum-violation",
                  lambda: ss.validate_args("search",
                                           {"query": "q",
                                            "mode": "warp"}),
                  "toolcall-schema-invalid")


def p_secret_value():
    if not _have_ts("ts-secret-value"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-secret-value",
                  lambda: ss.validate_args(
                      "search", {"query": "sk-abcdef1234567890XY"}),
                  "toolcall-secret-in-args")


def p_nested_members():
    if not _have_ts("ts-nested-members"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    _expect_coded("ts-nested-members-bad-element",
                  lambda: ss.validate_args(
                      "search", {"query": "q", "tags": ["ok", 7]}),
                  "toolcall-schema-invalid")
    out = ss.validate_args("search",
                           {"query": "q", "tags": ["a", "b"],
                            "flags": {"verbose": True}})
    if out["tags"] == ["a", "b"] and out["flags"] == {"verbose": True}:
        _record("ts-nested-members-ok", "HELD",
                "typed list/dict members validate")
    else:
        _record("ts-nested-members-ok", "BREAK", "bad nested output")


def p_mutation_post_freeze():
    if not _have_ts("ts-mutation-post-freeze"):
        return
    ss = TS.compile_schema_set(_schema_doc())
    d0 = ss.digest
    try:
        ss._doc["tools"]["search"]["args"]["query"]["max_len"] = 1
        mutated = True
    except TypeError:
        mutated = False
    if mutated or ss.digest != d0:
        _record("ts-mutation-post-freeze", "BREAK",
                "digest or doc changed under mutation")
    else:
        _record("ts-mutation-post-freeze", "HELD",
                "mutation fails at source; digest stable")


# ---------------------------------------------------------------------------
# Composition with gov/tool_call_policy.py
# ---------------------------------------------------------------------------

def _policy_doc(**over):
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w294-probe-policy",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [{"action": "ALLOW", "tool": "*", "operation": "run"}],
    }
    doc.update(over)
    return doc


def _caller():
    return {"identity": "agent-1", "authenticated": True}


def p_compose_decide_schema():
    if not (_have_ts("ts-compose-decide-schema")
            and _have_tp("ts-compose-decide-schema")):
        return
    ss = TS.compile_schema_set(_schema_doc())
    pol = TP.compile_policy(_policy_doc())
    pol.bind_schema_registry(ss)
    good = pol.decide(_caller(), "search", "run", {"query": "ok"})
    bad = pol.decide(_caller(), "search", "run", {"query": 5})
    unknown = pol.decide(_caller(), "nosuch", "run", {})
    if good.verdict != "ALLOW":
        _record("ts-compose-decide-schema", "BREAK",
                "valid call not allowed: %s" % (good.verdict,))
    elif bad.verdict != "DENY" or bad.code != "toolcall-schema-invalid" \
            or bad.rejection_layer != "schema":
        _record("ts-compose-decide-schema", "BREAK",
                "bad call not coded-DENY at schema layer: %s %s %s"
                % (bad.verdict, bad.code, bad.rejection_layer))
    elif unknown.verdict != "DENY" \
            or unknown.code != "toolcall-schema-unknown-tool":
        _record("ts-compose-decide-schema", "BREAK",
                "unknown tool not coded-DENY: %s %s"
                % (unknown.verdict, unknown.code))
    else:
        _record("ts-compose-decide-schema", "HELD",
                "bound schema pre-filter refuses coded at the schema "
                "rejection layer; valid calls pass")


def p_compose_optin():
    if not (_have_ts("ts-compose-optin")
            and _have_tp("ts-compose-optin")):
        return
    pol = TP.compile_policy(_policy_doc())
    # No registry bound: decide behaves exactly as before (shape is not
    # checked; the ALLOW rule covers the call).
    d = pol.decide(_caller(), "search", "run", {"query": 5})
    if d.verdict == "ALLOW":
        _record("ts-compose-optin", "HELD",
                "unbound policy unchanged (shape not checked)")
    else:
        _record("ts-compose-optin", "BREAK",
                "unbound decide changed: %s" % (d.verdict,))


def p_compose_audit_mode():
    if not (_have_ts("ts-compose-audit-mode")
            and _have_tp("ts-compose-audit-mode")):
        return
    ss = TS.compile_schema_set(_schema_doc())
    pol = TP.compile_policy(_policy_doc(mode="audit"))
    pol.bind_schema_registry(ss)
    d = pol.decide(_caller(), "search", "run", {"query": 5})
    if d.verdict == "ALLOW" and d.code == "toolcall-audit-would-deny":
        _record("ts-compose-audit-mode", "HELD",
                "audit mode records would-deny, does not enforce")
    else:
        _record("ts-compose-audit-mode", "BREAK",
                "audit mode wrong: %s %s" % (d.verdict, d.code))


# ---------------------------------------------------------------------------
# Depth-1 green checks: adjacent batteries must stay green. The lane's
# tree-wide pin repoint (1742 -> 1742) keeps every adjacent battery's own
# pin probe green, so expectations are the batteries' intrinsic counts.
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w294-green-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=900,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("green-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("green-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("green-" + label, "BREAK",
                "%s: %d BREAK, expected %d" % (rel, nbreak, expected_breaks))


def _green_checks():
    if SKIP_GREEN:
        return
    # w293_tool_rules (typed-schemas sibling lane): 0 BREAK expected.
    _run_battery("evals/w293_tool_rules_probes.py", 0, "w293toolrules")
    # w292_redteam: 0 BREAK expected (F360 closed by wave-293 lane 1;
    # pins repointed tree-wide with the lane).
    _run_battery("evals/w292_redteam_probes.py", 0, "w292redteam")


def main():
    p_taxonomy_pin()
    p_compile_valid()
    p_compile_rejects_credential_field()
    p_compile_rejects_unbounded()
    p_compile_rejects_unsafe_pattern()
    p_compile_rejects_bad_default()
    p_compile_frozen()
    p_validate_ok_defaults()
    p_type_confusion()
    p_range_escape()
    p_bool_is_not_int()
    p_oversized_list()
    p_undeclared_tool()
    p_unknown_arg()
    p_missing_required()
    p_null_value()
    p_enum_violation()
    p_secret_value()
    p_nested_members()
    p_mutation_post_freeze()
    p_compose_decide_schema()
    p_compose_optin()
    p_compose_audit_mode()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w294_tool_schemas: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
