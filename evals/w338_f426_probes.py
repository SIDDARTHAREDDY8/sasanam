"""Wave-338 lane 1 regression battery: F426 closure.

F426 (LOW, CLOSED 2026-10-05 wave-338 lane 1): audit_agent_coverage in
gov/adapters/openai_agents.py certified an SDK Agent when every
FunctionTool carried one of this module's issued guardrails, but never
checked the guardrail was built for THAT tool -- a delete_file tool
carrying a read_file guardrail got certified and calls were mediated
under the wrong tool's policy (role-policy bypass on a certified
agent); arg-shape mismatches escaped the guardrail as a bare KeyError
(F417-class, uncoded).

Fix (red-first verified on the base tree for all three break shapes):
  * the issued guardrail function now exposes framework_tool and
    expect_sdk_tool_name as attributes;
  * audit_agent_coverage raises UncoveredSurfaceError for any
    FunctionTool whose issued guardrail declares no expect_sdk_tool_name
    or declares one that does not equal the SDK tool's name (both the
    undeclared and the mismatched shapes refuse at audit);
  * arg-shape access is wrapped: a bare KeyError from mediation refuses
    coded guardrail_argument_shape_mismatch via the tripwire instead of
    escaping uncoded.

No new decision codes (the new error string is guardrail output_info,
not taxonomy); pin 2124->2126 at the wave-338 merge (+2 oci-*). Footer: open none / next F428.

$0 spend; synthetic/local; no model calls.

Run:
  mkdir -p /var/tmp/g338-f426
  TMPDIR=/var/tmp/g338-f426 ~/workspace/.gov-venv/bin/python evals/w338_f426_probes.py
Clean env:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g338-f426b ~/workspace/.gov-venv/bin/python evals/w338_f426_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w338_f426_probes.py P1a
"""
import json
import os
import re
import subprocess
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tests.keyfixture import provision_test_key  # noqa: E402
provision_test_key()

from tests.harness import make_run  # noqa: E402
from gov.adapters.core import GovernedBinding  # noqa: E402
from gov.adapters import openai_agents as OAI_SHIM  # noqa: E402

# Red-first battery: on the unfixed tree the F426 probes BREAK. Empty on
# the closed tree (wave-331 lesson: empty set, never {}).
_EXPECTED_BREAKS = set()

TAXONOMY_PIN = 2131  # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-338 lane 1: no new decision codes; pin unchanged.; Wave-339 merge: pin 2128 -> 2130 (+4 codes: oci-bundle-not-verifiable, witness-policy-dual-threshold-unmet, witness-daemon-state-failed, oci-registry-onboarding-refused); wave-340 merge: pin 2130 -> 2131

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0][:160]))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


class _OAIContext:
    def __init__(self, tool_name, tool_arguments):
        self.tool_name = tool_name
        self.tool_arguments = tool_arguments


class _OAIData:
    def __init__(self, context):
        self.context = context


class _OAIFunctionTool:
    def __init__(self, name, guardrails=()):
        self.name = name
        self.tool_input_guardrails = list(guardrails)


class _OAIWrapper:
    """SDK ToolInputGuardrail-shaped wrapper (carries the raw function as
    .guardrail_function -- the audit must unwrap it)."""

    def __init__(self, fn):
        self.guardrail_function = fn


class _OAIAgent:
    def __init__(self, name, tools, handoffs=()):
        self.name = name
        self.tools = list(tools)
        self.handoffs = list(handoffs)


# F427: the audit trusts the declaration only against the
# deployment-declared SDK-tool->framework-tool mapping. The F426 probes
# below pass the mapping so the F426-class refusals are exercised on
# the name correspondence, not the (also fail-closed) no-mapping path.
_F426_MAP = {"delete_file": "delete_file", "write_file": "write_file"}


def _oai_data(tool_name, arguments):
    return _OAIData(_OAIContext(tool_name, json.dumps(arguments)))


def _support_binding(ctx):
    ident = ctx["mint_identity"]("support-1", "support", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _audit_refuses(pid, agent, want_fragment):
    """HELD iff the audit raises UncoveredSurfaceError mentioning
    want_fragment. BREAK if it certifies (F426 live)."""
    try:
        OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=_F426_MAP)
    except OAI_SHIM.UncoveredSurfaceError as e:
        if want_fragment in str(e):
            _held(pid, "audit refused: %s" % (str(e)[:120],))
        else:
            _break(pid, "audit refused but message lacks %r: %s"
                   % (want_fragment, str(e)[:160]))
        return
    _break(pid, "F426 LIVE: audit certified a miswired agent")


# ---------------------------------------------------------------------------
# P1: F426 closure probes (all three break shapes red-first on the base).
# ---------------------------------------------------------------------------

def P1a():
    """F426 primary shape: guardrail built for read_file (no declared
    name) attached to the delete_file FunctionTool -> audit must refuse
    (undeclared name)."""
    pid = "P1a-misattached-undeclared-name-refused"
    ctx = make_run()
    guard_r = OAI_SHIM.make_tool_input_guardrail(_support_binding(ctx),
                                                 "read_file")
    agent = _OAIAgent("miswired",
                      [_OAIFunctionTool("delete_file", [guard_r])])
    _audit_refuses(pid, agent, "no expect_sdk_tool_name")


def P1b():
    """F426 variant: guardrail declaring expect_sdk_tool_name='read_file'
    attached to the delete_file FunctionTool -> audit must refuse
    (mismatched name; the declared name is consulted, not ignored)."""
    pid = "P1b-misattached-mismatched-name-refused"
    ctx = make_run()
    guard_r = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "read_file",
        expect_sdk_tool_name="read_file")
    agent = _OAIAgent("miswired",
                      [_OAIFunctionTool("delete_file", [guard_r])])
    _audit_refuses(pid, agent, "'read_file'")


def P1c():
    """F426 second shape: arg-shape mismatch must refuse CODED
    (guardrail_argument_shape_mismatch via the tripwire), never let a
    bare KeyError escape the guardrail."""
    pid = "P1c-arg-shape-mismatch-coded-refusal"
    ctx = make_run()
    guard_w = OAI_SHIM.make_tool_input_guardrail(_coder_binding(ctx),
                                                 "write_file")
    try:
        out = guard_w(_oai_data("write_file",
                                {"to": "x@synthetic.local",
                                 "subject": "s", "body": "b"}))
    except KeyError as e:
        _break(pid, "F426 LIVE: bare KeyError escaped uncoded: %r" % (e,))
        return
    except Exception as e:  # noqa: BLE001
        _break(pid, "unexpected uncoded escape: %r" % (e,))
        return
    if out.behavior.get("type") != "raise_exception":
        _break(pid, "want raise_exception, got %r" % (out.behavior,))
        return
    if (out.output_info or {}).get("error") != \
            "guardrail_argument_shape_mismatch":
        _break(pid, "wrong coded error: %r" % (out.output_info,))
        return
    _held(pid, "arg-shape mismatch -> raise_exception "
               "(guardrail_argument_shape_mismatch)")


def P1d():
    """Correct wiring still certifies: guardrail declaring
    expect_sdk_tool_name='delete_file' on the delete_file tool."""
    pid = "P1d-correct-wiring-certifies"
    ctx = make_run()
    guard_d = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "delete_file",
        expect_sdk_tool_name="delete_file")
    agent = _OAIAgent("ok", [_OAIFunctionTool("delete_file", [guard_d])])
    try:
        rep = OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=_F426_MAP)
    except OAI_SHIM.UncoveredSurfaceError as e:
        _break(pid, "correctly wired agent refused: %s" % (str(e)[:120],))
        return
    if rep["tools"] != ["delete_file"]:
        _break(pid, "wrong coverage report: %r" % (rep,))
        return
    _held(pid, "correctly wired agent certified")


def P1e():
    """The issued guardrail exposes framework_tool and
    expect_sdk_tool_name as attributes (the audit verifies the
    correspondence even in principle)."""
    pid = "P1e-guardrail-exposes-attributes"
    ctx = make_run()
    guard = OAI_SHIM.make_tool_input_guardrail(
        _coder_binding(ctx), "write_file",
        expect_sdk_tool_name="write_file")
    if getattr(guard, "framework_tool", None) != "write_file":
        _break(pid, "framework_tool attribute missing/wrong: %r"
               % (getattr(guard, "framework_tool", "<ABSENT>"),))
        return
    if getattr(guard, "expect_sdk_tool_name", None) != "write_file":
        _break(pid, "expect_sdk_tool_name attribute missing/wrong: %r"
               % (getattr(guard, "expect_sdk_tool_name", "<ABSENT>"),))
        return
    plain = OAI_SHIM.make_tool_input_guardrail(_coder_binding(ctx),
                                               "write_file")
    if getattr(plain, "expect_sdk_tool_name", "<ABSENT>") is not None:
        _break(pid, "undeclared guardrail's attribute should be None")
        return
    _held(pid, "framework_tool/expect_sdk_tool_name exposed as attributes")


def P1f():
    """Wrapped entries (SDK ToolInputGuardrail shape) are unwrapped for
    the correspondence check: misattached wrapper refused, correct
    wrapper certifies."""
    pid = "P1f-wrapped-entry-correspondence"
    ctx = make_run()
    wrong = _OAIWrapper(OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "read_file",
        expect_sdk_tool_name="read_file"))
    agent = _OAIAgent("miswired",
                      [_OAIFunctionTool("delete_file", [wrong])])
    _audit_refuses(pid + "-refuse", agent, "'read_file'")
    right = _OAIWrapper(OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "delete_file",
        expect_sdk_tool_name="delete_file"))
    agent2 = _OAIAgent("ok", [_OAIFunctionTool("delete_file", [right])])
    try:
        rep = OAI_SHIM.audit_agent_coverage(agent2, sdk_tool_map=_F426_MAP)
    except OAI_SHIM.UncoveredSurfaceError as e:
        _break(pid, "correctly wrapped guardrail refused: %s"
               % (str(e)[:120],))
        return
    if rep["tools"] != ["delete_file"]:
        _break(pid, "wrong coverage report: %r" % (rep,))
        return
    _held(pid, "wrapped entries unwrapped; misattached refused, "
               "correct certified")


def P1g():
    """Strict close-when: a guardrail with NO declared name is refused
    even when its framework_tool name happens to equal the SDK tool's
    name -- undeclared correspondence is certifiable nothing."""
    pid = "P1g-undeclared-name-refused-despite-name-coincidence"
    ctx = make_run()
    guard = OAI_SHIM.make_tool_input_guardrail(_coder_binding(ctx),
                                               "write_file")
    agent = _OAIAgent("coincidence",
                      [_OAIFunctionTool("write_file", [guard])])
    _audit_refuses(pid, agent, "no expect_sdk_tool_name")

# ---------------------------------------------------------------------------
# P2: pin + footer honesty.
# ---------------------------------------------------------------------------

def P2a():
    """Pin 2131: taxonomy 2131/2131/0 sorted-unique on raw literals
    (wave-260 lesson)."""
    pid = "P2a-pin-taxonomy-2131-sorted"
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    found = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(found) != TAXONOMY_PIN or len(set(found)) != TAXONOMY_PIN:
        _break(pid, "want %d/%d/0 sorted-unique, got %d/%d"
               % (TAXONOMY_PIN, TAXONOMY_PIN, len(found), len(set(found))))
        return
    if found != sorted(found):
        _break(pid, "code literals not sorted")
        return
    _held(pid, "taxonomy 2131/2131/0 sorted-unique on raw literals")


def P2b():
    """Footer: open F428 / next F429; F426 and F427 marked CLOSED; F428 marked OPEN."""
    pid = "P2b-footer-open-f428-next-f429"
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    lines = text.splitlines()
    last = lines[-1] if lines else ""
    if "Next free finding: **F429**" not in last:
        _break(pid, "footer does not read next F429")
        return
    if "Open findings: F428." not in last:
        _break(pid, "footer does not read open F428: %r" % (last[:120],))
        return
    import re as _re

    def _section(tag):
        m = _re.search(r"^## %s\b.*$" % tag, text, _re.M)
        if not m:
            return ""
        rest = text[m.end():]
        n = _re.search(r"^## \S", rest, _re.M)
        return rest[:n.start()] if n else rest
    if "**Status: OPEN.**" in _section("F426"):
        _break(pid, "F426 section still marked OPEN")
        return
    if "**Status: OPEN.**" in _section("F427"):
        _break(pid, "F427 section still marked OPEN")
        return
    _held(pid, "footer open F428 / next F429, F426+F427 closed, F428 open")


_PROBES = [
    ("P1a-misattached-undeclared-name-refused", P1a),
    ("P1b-misattached-mismatched-name-refused", P1b),
    ("P1c-arg-shape-mismatch-coded-refusal", P1c),
    ("P1d-correct-wiring-certifies", P1d),
    ("P1e-guardrail-exposes-attributes", P1e),
    ("P1f-wrapped-entry-correspondence", P1f),
    ("P1g-undeclared-name-refused-despite-name-coincidence", P1g),
    ("P2a-pin-taxonomy-2131-sorted", P2a),
    ("P2b-footer-open-f428-next-f429", P2b),
]


def _run_root():
    base = os.environ.get("TMPDIR") or "/var/tmp"
    root = os.path.join(base, "w338-f426")
    os.makedirs(root, exist_ok=True)
    return root


# Depth-1 green checks over the wave-337 batteries this lane touched
# (P3b correspondence update + footer cascade). Children run with
# GOV_SKIP_GREEN=1, so their own green children collapse into the
# GREEN-SKIPPED HELD; tuples measured on the closed tree. The deeper
# footer cascade (w336_f423 etc. asserting open F426) is the wave-338
# merge coordinator's standard sweep, not this lane's.
_CHILD_BATTERIES = [
    ("w337_redteam_probes.py", 0, "0/35/0"),
    ("w337_f424f425_probes.py", 0, "0/16/0"),
]


def _run_child_output(name):
    """Run an adjacent battery's main with green checks skipped
    (depth-1 green checks, wave-173 lesson) and return its stdout tail."""
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    root = _run_root()
    sub = os.path.join(root, "child-%s" % name)
    os.makedirs(sub, exist_ok=True)
    env["TMPDIR"] = sub
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    p = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", name)],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=900)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-4:])
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", tail)
    if m is None:
        m = re.search(r"(\d+)/(\d+)/(\d+) \(break/held/error\)", tail)
    return m, tail


def _green_check():
    """Depth-1 green checks. Honors GOV_SKIP_GREEN (wave-320 lesson)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("GREEN-SKIPPED", "HELD",
                "green check skipped (child mode)")
        return
    for name, want_breaks, want_tuple in _CHILD_BATTERIES:
        pid = "GREEN-" + name.replace(".py", "")
        m, tail = _run_child_output(name)
        if m is None:
            _record(pid, "ERROR", "no B/H/E tuple in child output:\n%s"
                    % tail)
            continue
        b, h, e = int(m.group(1)), int(m.group(2)), int(m.group(3))
        got = "%d/%d/%d" % (b, h, e)
        if b != want_breaks or (want_tuple is not None
                                and got != want_tuple):
            _record(pid, "BREAK",
                    "child drift: got %s, want %s:\n%s" % (got, want_tuple,
                                                          tail))
        else:
            _record(pid, "HELD", "child %s as expected" % got)


def _summary():
    b = sum(1 for _, v, _ in _results if v == "BREAK")
    h = sum(1 for _, v, _ in _results if v == "HELD")
    e = sum(1 for _, v, _ in _results if v == "ERROR")
    return b, h, e


def main(argv=None):
    argv = list(argv or sys.argv[1:])
    only = [a for a in argv if not a.startswith("-")]
    todo = _PROBES
    if only:
        matched = []
        for want in only:
            hits = [(pid, fn) for pid, fn in _PROBES
                    if pid == want or pid.startswith(want + "-")]
            if not hits:
                print("unknown probe id: %r" % (want,))
                return 1
            matched.extend(hits)
        todo = matched
    _run_root()
    for pid, fn in todo:
        _safe(pid, fn)
    _green_check()
    b, h, e = _summary()
    print("\nw338_f426: %d/%d/%d (break/held/error)" % (b, h, e))
    for pid in _EXPECTED_BREAKS:
        if pid not in [p for p, _, _ in _results]:
            print("WARNING: expected-break probe %r not present" % (pid,))
    return 1 if (b or e) else 0


if __name__ == "__main__":
    sys.exit(main())
