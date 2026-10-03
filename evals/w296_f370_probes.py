"""Wave-296 lane 4 red-first battery: F370 closure.

F370 (LOW): call-time validation in gov/tool_schemas.py never name-checked
dict keys nested in arg values -- {"config": {"password": ...}} and the
two-level {"config": {"db": {"secret": ...}}} passed both gates.

BASE: wave-295 merge 10777555 (F367, F368, F369, F370 OPEN).
EXPECTATIONS ON BASE: 2 BREAK (f370-nested-credkey-1, f370-nested-credkey-2);
everything else HELD.
EXPECTATIONS ON THE FIXED TREE: 0 BREAK / 14 HELD / 0 ERROR.

New batteries set the deployment mode at module level (wave-95 lesson)
and are verified under `env -u GOV_DEPLOYMENT_MODE`. Depth-1 green
checks: this battery's green check runs the adjacent batteries' mains
with GOV_SKIP_GREEN=1; every green-check function honors the var.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import re
import subprocess
import sys
import tempfile

_RESULTS = []

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def _record(pid, verdict, note):
    _RESULTS.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note))


# ---------------------------------------------------------------------------
# Depth-1 green checks (GOV_SKIP_GREEN=1 in the child env; children spawn
# nothing further). On the F370-fixed tree the w295 red-team's F370 probes
# flip HELD; F367/F368/F369 stay open this wave (3 BREAK expected).
# ---------------------------------------------------------------------------

_REPIN_EXPECT = {
    # name: (expected BREAKs, expected BREAK ids or None)
    # On the composed wave-296 tree F367/F368/F369/F370 are all CLOSED:
    # 0 BREAK expected (the lane-local tree had 3 still open).
    "w295_redteam_probes.py": (0, None),
    "w294_tool_schemas_probes.py": (0, None),
    "w293_tool_rules_probes.py": (0, None),
}


def _run_repin(name):
    pid = "repin-" + name.replace("_probes.py", "")
    want_breaks, want_ids = _REPIN_EXPECT[name]
    d = tempfile.mkdtemp(prefix="g296-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, "evals/" + name],
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
            capture_output=True, text=True, timeout=1500)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR", "repin run failed: %r" % (e,))
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", proc.stdout)
    if not m:
        return _record(pid, "ERROR",
                       "no summary line in repin output; rc=%d tail=%r"
                       % (proc.returncode, proc.stdout[-300:]))
    breaks = int(m.group(1))
    break_ids = re.findall(r"\[BREAK\] ([A-Za-z0-9_.-]+)", proc.stdout)
    if breaks != want_breaks or (want_ids is not None
                                 and break_ids != want_ids):
        return _record(pid, "BREAK",
                       "%s: %d BREAK ids=%r, want %d ids=%r"
                       % (name, breaks, break_ids, want_breaks, want_ids))
    _record(pid, "HELD",
            "%s re-pinned: %d BREAK as expected" % (name, breaks))


def green_check():
    """Depth-1 green check. Honors GOV_SKIP_GREEN (wave-173 lesson)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped via GOV_SKIP_GREEN=1 (depth-1)")
        return
    for name in _REPIN_EXPECT:
        _run_repin(name)


# ---------------------------------------------------------------------------
# Taxonomy pin (closure lane: gov/decision_codes.py untouched, pin 1750)
# ---------------------------------------------------------------------------

TAXONOMY_PIN = 1851  # Wave-295 merge; F370 closure reuses toolcall-schema-secret-field -- no new codes.; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)


def p_taxonomy_pin():
    src = open("gov/decision_codes.py").read()
    codes = re.findall(r"""['"]code['"]\s*:\s*['"]([^'"]+)['"]""", src)
    if len(codes) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "raw literals %d, want pin %d" % (len(codes),
                                                        TAXONOMY_PIN))
    if len(set(codes)) != len(codes):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if codes != sorted(codes):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD",
            "raw literals %d/%d/0/sorted" % (len(codes), TAXONOMY_PIN))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk_schema(fields):
    from gov import tool_schemas as ts
    doc = {"format": ts.SCHEMA_SET_FORMAT, "name": "rt",
           "tools": {"t": {"args": fields}}}
    return ts.compile_schema_set(doc), ts


_STRF = {"type": "string", "min_len": 0, "max_len": 65536}


def _dict_of(v):
    return {"type": "dict", "value": v, "min_items": 0, "max_items": 10}


def _list_of(v):
    return {"type": "list", "element": v, "min_items": 0, "max_items": 10}


# ---------------------------------------------------------------------------
# F370 attack probes (red-first: 2 BREAK on base, 0 on the fixed tree)
# ---------------------------------------------------------------------------

def _attack(pid, schema, args, want_code):
    from gov import tool_schemas as ts
    try:
        schema.validate_args("t", args)
    except ts.ToolSchemaError as e:
        if e.code != want_code:
            return _record(pid, "BREAK",
                           "refused with %r, want %r" % (e.code, want_code))
        return _record(pid, "HELD",
                       "nested credential-named key refuses coded %s"
                       % (want_code,))
    _record(pid, "BREAK",
            "F370: credential-named key nested in an arg value passed "
            "both gates")


def p_f370_nested_credkey_1():
    # The exact probe from the F370 close-when criteria.
    ss, ts = _mk_schema({"config": _dict_of(_STRF)})
    _attack("f370-nested-credkey-1", ss, {"config": {"password": "x1"}},
            ts.SCHEMA_SECRET_FIELD)


def p_f370_nested_credkey_2():
    # The two-level probe from the F370 close-when criteria.
    ss, ts = _mk_schema({"config": _dict_of(_dict_of(_STRF))})
    _attack("f370-nested-credkey-2", ss,
            {"config": {"db": {"secret": "x2"}}}, ts.SCHEMA_SECRET_FIELD)


# ---------------------------------------------------------------------------
# Adjacent-behavior probes (all HELD on both base and fixed tree)
# ---------------------------------------------------------------------------

def p_f370_benign_nested_keys():
    # Innocent nested keys still validate clean.
    ss, ts = _mk_schema({"config": _dict_of(_STRF)})
    try:
        out = ss.validate_args("t", {"config": {"host": "db.internal",
                                                "region": "us"}})
    except ts.ToolSchemaError as e:
        return _record("f370-benign-nested-keys", "BREAK",
                       "benign nested keys refused coded %s" % (e.code,))
    if out != {"config": {"host": "db.internal", "region": "us"}}:
        return _record("f370-benign-nested-keys", "BREAK",
                       "validated args mangled: %r" % (out,))
    _record("f370-benign-nested-keys", "HELD",
            "benign nested keys validate clean")


def p_f370_undeclared_top_arg():
    # Top-level coverage is unchanged: undeclared args still refuse with
    # the closed-inventory code.
    ss, ts = _mk_schema({"config": _dict_of(_STRF)})
    try:
        ss.validate_args("t", {"config": {"host": "x"}, "evil": 1})
    except ts.ToolSchemaError as e:
        if e.code != ts.SCHEMA_INVALID:
            return _record("f370-undeclared-top-arg", "BREAK",
                           "refused with %r, want toolcall-schema-invalid"
                           % (e.code,))
        return _record("f370-undeclared-top-arg", "HELD",
                       "undeclared top-level arg still refuses coded")
    _record("f370-undeclared-top-arg", "BREAK", "undeclared arg ALLOWED")


def p_f370_compile_gate_intact():
    # The compile-time credential-name gate is untouched.
    try:
        _mk_schema({"apiKey": _STRF})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "toolcall-schema-secret-field":
            return _record("f370-compile-gate-intact", "BREAK",
                           "compile refused with %r" % (getattr(e, "code", None),))
        return _record("f370-compile-gate-intact", "HELD",
                       "declared apiKey still refuses at compile time")
    _record("f370-compile-gate-intact", "BREAK", "apiKey field compiled")


def p_f370_secret_value_gate_intact():
    # The secret-SHAPE value gate is untouched.
    ss, ts = _mk_schema({"config": _dict_of(_STRF)})
    try:
        ss.validate_args("t", {"config": {"note": "xoxb-" + "Q" * 12}})
    except ts.ToolSchemaError as e:
        if e.code != ts.SECRET_IN_ARGS:
            return _record("f370-secret-value-gate-intact", "BREAK",
                           "refused with %r" % (e.code,))
        return _record("f370-secret-value-gate-intact", "HELD",
                       "secret-shaped value still refuses coded")
    _record("f370-secret-value-gate-intact", "BREAK",
            "secret-shaped value ALLOWED")


def p_f370_leetspeak_key_passes():
    # Bounded token list residual (documented in F370): leetspeak keys
    # are not in the token list, consistent with the compile-time gate.
    ss, ts = _mk_schema({"config": _dict_of(_STRF)})
    try:
        ss.validate_args("t", {"config": {"passw0rd": "x"}})
    except ts.ToolSchemaError as e:
        return _record("f370-leetspeak-key-passes", "BREAK",
                       "leetspeak key refused coded %s (residual changed)"
                       % (e.code,))
    _record("f370-leetspeak-key-passes", "HELD",
            "leetspeak key passes: bounded-token-list residual intact")


def p_f370_deep4_credkey():
    # The gate fires at the deepest schema-allowed nesting level too.
    ss, ts = _mk_schema({"a": _dict_of(_dict_of(_dict_of(_dict_of(_STRF))))})
    _attack("f370-deep4-credkey", ss,
            {"a": {"b": {"c": {"d": {"password": "x"}}}}},
            ts.SCHEMA_SECRET_FIELD)


def p_f370_list_of_dicts_credkey():
    # Dicts nested inside lists are walked by the same validator, so the
    # key gate covers them.
    ss, ts = _mk_schema({"items": _list_of(_dict_of(_STRF))})
    _attack("f370-list-of-dicts-credkey", ss,
            {"items": [{"ok": "1"}, {"token": "abc"}]},
            ts.SCHEMA_SECRET_FIELD)


def p_f370_credkey_before_value_shape():
    # The key gate fires on the key itself, independent of the value's
    # shape: a non-string value under a credential-named key refuses
    # with the key code, not a shape code.
    ss, ts = _mk_schema({"config": _dict_of(_dict_of(_STRF))})
    _attack("f370-credkey-before-value-shape", ss,
            {"config": {"password": {"nested": "x"}}},
            ts.SCHEMA_SECRET_FIELD)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    green_check()
    p_taxonomy_pin()
    p_f370_nested_credkey_1()
    p_f370_nested_credkey_2()
    p_f370_benign_nested_keys()
    p_f370_undeclared_top_arg()
    p_f370_compile_gate_intact()
    p_f370_secret_value_gate_intact()
    p_f370_leetspeak_key_passes()
    p_f370_deep4_credkey()
    p_f370_list_of_dicts_credkey()
    p_f370_credkey_before_value_shape()

    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
