"""Wave-246 tool-schema $ref poisoning probes (red-first).

W246-3 (second MCP SDK advisory GHSA-rwrf-2pqf-9j8j shape): a tool
schema whose ``$ref`` points outside the document triggers an SSRF
fetch, and adversarial ``$ref`` graphs (cycles, deep chains, ref
storms) freeze the resolver's event loop. The guard under test is
pure: schema dict in, verdict out, no network, bounded CPU budget.

  external-absolute-ref-refused-never-fetched -- ``$ref`` to an
      absolute https URL -> schema-ref-external; socket/urllib are
      patched to raise, so any fetch attempt becomes an ERROR.
  external-relative-ref-refused -- ``$ref`` to ``other.json#/x`` ->
      schema-ref-external (relative is still out-of-document).
  cyclic-refs-refused -- #/definitions/a <-> #/definitions/b ->
      schema-ref-depth-exceeded.
  self-root-ref-refused -- ``$ref: "#"`` at the root ->
      schema-ref-depth-exceeded (infinite self-resolution).
  deep-nesting-refused -- 30-link in-document chain with
      max_ref_depth=16 -> schema-ref-depth-exceeded.
  budget-exhausted -- 2000 sibling $refs with
      max_resolution_steps=100 -> schema-ref-budget-exhausted.
  valid-refs-allow -- ordinary in-document refs ->
      allow / schema-refs-resolved with refs_resolved > 0.
  dangling-ref-malformed -- ``$ref: "#/definitions/missing"`` ->
      schema-record-malformed.
  non-dict-input-malformed -- list input -> schema-record-malformed.
  non-string-ref-malformed -- ``$ref: 42`` -> schema-record-malformed.
  input-not-mutated -- the guard never mutates its input.
  dynamic-recursive-external-refused -- ``$recursiveRef`` /
      ``$dynamicRef`` to absolute URLs -> schema-ref-external.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import copy
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_SRG = False
try:
    from gov import schema_ref_guard as _srg
    HAVE_SRG = all(hasattr(_srg, n) for n in (
        "check_tool_schema", "SchemaRefGuardError",
        "SCHEMA_REF_EXTERNAL", "SCHEMA_REF_DEPTH_EXCEEDED",
        "SCHEMA_REF_BUDGET_EXHAUSTED", "SCHEMA_RECORD_MALFORMED",
        "SCHEMA_REFS_RESOLVED"))
except ImportError:
    _srg = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "external-absolute-ref-refused-never-fetched",
    "external-relative-ref-refused",
    "cyclic-refs-refused",
    "self-root-ref-refused",
    "deep-nesting-refused",
    "budget-exhausted",
    "valid-refs-allow",
    "dangling-ref-malformed",
    "non-dict-input-malformed",
    "non-string-ref-malformed",
    "input-not-mutated",
    "dynamic-recursive-external-refused",
]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    try:
        fn()
    except _srg.SchemaRefGuardError as exc:
        assert exc.code == code, "want %s, got %s" % (code, exc.code)
        return exc
    raise AssertionError("expected refusal %s, got allow" % (code,))


def _no_fetch_guard():
    """Patch network entry points to raise; returns unpatch callable."""
    import socket  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    def _boom(*a, **k):
        raise AssertionError("network fetch attempted by the guard")

    orig_socket = socket.socket
    orig_urlopen = urllib.request.urlopen
    socket.socket = _boom
    urllib.request.urlopen = _boom

    def _restore():
        socket.socket = orig_socket
        urllib.request.urlopen = orig_urlopen
    return _restore


def _probe_external_absolute_ref_refused_never_fetched():
    restore = _no_fetch_guard()
    try:
        schema = {"type": "object",
                  "properties": {
                      "x": {"$ref": "https://attacker.example/schema"}}}
        _expect_refusal(lambda: _srg.check_tool_schema(schema),
                        "schema-ref-external")
    finally:
        restore()
    return "absolute-URL $ref refused, no fetch attempted"


def _probe_external_relative_ref_refused():
    schema = {"$ref": "other.json#/definitions/x",
              "definitions": {"x": {"type": "string"}}}
    _expect_refusal(lambda: _srg.check_tool_schema(schema),
                    "schema-ref-external")
    return "relative out-of-document $ref refused"


def _probe_cyclic_refs_refused():
    schema = {"definitions": {
        "a": {"$ref": "#/definitions/b"},
        "b": {"$ref": "#/definitions/a"}},
        "$ref": "#/definitions/a"}
    _expect_refusal(lambda: _srg.check_tool_schema(schema),
                    "schema-ref-depth-exceeded")
    return "two-node $ref cycle refused"


def _probe_self_root_ref_refused():
    schema = {"$ref": "#", "type": "object"}
    _expect_refusal(lambda: _srg.check_tool_schema(schema),
                    "schema-ref-depth-exceeded")
    return "self-root $ref refused"


def _probe_deep_nesting_refused():
    defs = {}
    for i in range(30):
        nxt = "#/definitions/n%d" % (i + 1) if i < 29 else "#/definitions/n29"
        defs["n%d" % i] = {"$ref": nxt}
    schema = {"definitions": defs, "$ref": "#/definitions/n0"}
    _expect_refusal(
        lambda: _srg.check_tool_schema(schema, max_ref_depth=16),
        "schema-ref-depth-exceeded")
    return "30-link chain refused at max_ref_depth=16"


def _probe_budget_exhausted():
    schema = {"type": "object", "properties": {
        "p%d" % i: {"$ref": "#/definitions/s"} for i in range(2000)} ,
        "definitions": {"s": {"type": "string"}}}
    _expect_refusal(
        lambda: _srg.check_tool_schema(schema, max_resolution_steps=100),
        "schema-ref-budget-exhausted")
    return "2000 sibling $refs refused at max_resolution_steps=100"


def _probe_valid_refs_allow():
    schema = {"type": "object",
              "definitions": {"name": {"type": "string", "minLength": 1}},
              "properties": {
                  "first": {"$ref": "#/definitions/name"},
                  "last": {"$ref": "#/definitions/name"}}}
    verdict = _srg.check_tool_schema(schema)
    assert verdict["decision"] == "allow", verdict
    assert verdict["code"] == "schema-refs-resolved", verdict
    assert verdict["refs_resolved"] >= 2, verdict
    return "in-document refs resolve: refs_resolved=%d" % (
        verdict["refs_resolved"],)


def _probe_dangling_ref_malformed():
    schema = {"$ref": "#/definitions/missing"}
    _expect_refusal(lambda: _srg.check_tool_schema(schema),
                    "schema-record-malformed")
    return "dangling in-document pointer is malformed"


def _probe_non_dict_input_malformed():
    _expect_refusal(lambda: _srg.check_tool_schema(["$ref"]),
                    "schema-record-malformed")
    return "non-dict schema fails closed"


def _probe_non_string_ref_malformed():
    schema = {"properties": {"x": {"$ref": 42}}}
    _expect_refusal(lambda: _srg.check_tool_schema(schema),
                    "schema-record-malformed")
    return "non-string $ref fails closed"


def _probe_input_not_mutated():
    schema = {"type": "object",
              "definitions": {"s": {"type": "string"}},
              "properties": {"x": {"$ref": "#/definitions/s"}}}
    before = copy.deepcopy(schema)
    _srg.check_tool_schema(schema)
    assert schema == before, "guard mutated its input"
    return "input schema byte-stable across the check"


def _probe_dynamic_recursive_external_refused():
    for key in ("$recursiveRef", "$dynamicRef"):
        schema = {key: "https://attacker.example/other"}
        _expect_refusal(lambda: _srg.check_tool_schema(schema),
                        "schema-ref-external")
    return "$recursiveRef/$dynamicRef URLs refused like $ref"


_PROBES = {
    name: (globals()["_probe_" + name.replace("-", "_")], HAVE_SRG)
    for name in PROBE_NAMES
}


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1 (never spawns another battery's main).
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_schema_ref_guard", "-v"],
        cwd=root, env=env, capture_output=True, text=True, timeout=300)
    notes.append("unit tests.test_schema_ref_guard rc=%d"
                 % (proc.returncode,))
    if proc.returncode != 0:
        notes.append("unit tail: %s" % (proc.stderr[-400:],))
    return notes


def main():
    print("wave-246 schema-ref probes (module: %s)" % (HAVE_SRG,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-44s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
