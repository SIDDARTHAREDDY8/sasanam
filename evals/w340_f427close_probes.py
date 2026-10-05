"""F427 closure battery (wave-340 lane 1) + R34 0.23.x re-audit probes.

F427 (LOW, OPEN on the base): audit_agent_coverage trusted the
guardrail's declared expect_sdk_tool_name without verifying the
framework_tool correspondence -- a guardrail built for read_file
declaring expect_sdk_tool_name="delete_file", attached to the
delete_file SDK tool, was CERTIFIED, re-enabling the F426-class
allow-direction role-policy bypass through the declared-name path.

RED-FIRST (base 9351ab86, evals/w339_f427_redfirst.py): the candidate
shape audit-certified (certified=True); a delete_file call through the
guardrail returned allow with framework_tool=read_file while direct
binding.call("delete_file") was denied for the support role.

CLOSE-WHEN: audit_agent_coverage verifies the guardrail's
framework_tool against a deployment-declared SDK-tool-name ->
framework-tool mapping (sdk_tool_map): a tool is certified only when
at least one issued guardrail satisfies BOTH
expect_sdk_tool_name == <sdk tool name> AND
framework_tool == sdk_tool_map[<sdk tool name>]; tools with no mapping
entry, or guardrails whose framework_tool disagrees with the mapping,
are uncovered surfaces (UncoveredSurfaceError). Deployments that cannot
declare the mapping (sdk_tool_map=None) treat SDK tools as uncovered.

R34 (wave-340 research heads-up): openai-agents 0.23.0/0.23.1 shipped
four governance-adjacent fixes touching this surface (semantics read
from the upstream PRs, MIT -- patterns described, nothing copied):
  #5066 conditional approvals now inspect VALIDATED tool arguments
        (approval callbacks could previously see different args than
        the function received);
  #5144 permanent function-tool approvals/rejections are scoped to the
        OWNING agent (no reuse by another agent's same-named tool
        after a handoff);
  #5124 tools are resolved AFTER agent start hooks (hooks can change
        the tool set post-audit);
  #4632 server-wide input/output guardrails for MCP tools (one
        guardrail mediating many converted tools).
P3a-P3d re-audit F426/F427 against those shapes red-first.

$0 API: deterministic only. No real-model calls.
"""

import json
import os
import re
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.getcwd()
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.adapters import openai_agents as OAI_SHIM  # noqa: E402
from gov.adapters.core import GovernedBinding  # noqa: E402
from tests.keyfixture import provision_test_key  # noqa: E402

provision_test_key()
from tests.harness import make_run  # noqa: E402

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


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


class _OAIAgent:
    def __init__(self, name, tools, handoffs=()):
        self.name = name
        self.tools = list(tools)
        self.handoffs = list(handoffs)


def _oai_data(tool_name, arguments):
    return _OAIData(_OAIContext(tool_name, json.dumps(arguments)))


def _support_binding(ctx):
    ident = ctx["mint_identity"]("support-1", "support", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


_MAP = {"delete_file": "delete_file", "write_file": "write_file",
        "read_file": "read_file"}


def _audit_certifies(agent, mapping):
    try:
        return OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=mapping)
    except OAI_SHIM.UncoveredSurfaceError:
        return None


# ---------------------------------------------------------------------------
# P1: F427 closure probes.
# ---------------------------------------------------------------------------

def P1a():
    """F427 break shape: guardrail built for read_file declaring
    expect_sdk_tool_name='delete_file' on the delete_file tool, with a
    deployment-declared mapping -> audit must REFUSE (the declaration's
    truth is checked, not just its spelling)."""
    pid = "P1a-f427-declared-name-lie-refused"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "read_file", expect_sdk_tool_name="delete_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [g])])
    try:
        OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=_MAP)
    except OAI_SHIM.UncoveredSurfaceError as e:
        text = str(e)
        if "F427" not in text or "read_file" not in text:
            _break(pid, "refused but misdiagnosed: %s" % (text[:160],))
            return
        _held(pid, "declared-name lie refused (F427): %s" % (text[:120],))
        return
    _break(pid, "F427 LIVE: audit certified the declared-name lie")


def P1b():
    """Mapping present but disagreeing with the guardrail's
    framework_tool -> refuse."""
    pid = "P1b-f427-disagreeing-mapping-refused"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _coder_binding(ctx), "delete_file",
        expect_sdk_tool_name="delete_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [g])])
    if _audit_certifies(agent, {"delete_file": "read_file"}) is not None:
        _break(pid, "certified despite mapping disagreement")
        return
    _held(pid, "disagreeing mapping refused")


def P1c():
    """Honest mapping-consistent construction still certifies
    (close-when regression)."""
    pid = "P1c-f427-honest-mapping-certifies"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "delete_file",
        expect_sdk_tool_name="delete_file")
    agent = _OAIAgent("ok", [_OAIFunctionTool("delete_file", [g])])
    rep = _audit_certifies(agent, _MAP)
    if rep is None:
        _break(pid, "honest mapping-consistent agent refused")
        return
    if rep["tools"] != ["delete_file"]:
        _break(pid, "wrong coverage report: %r" % (rep,))
        return
    _held(pid, "honest construction certifies")


def P1d():
    """No mapping (sdk_tool_map=None): the tool is uncovered -- the
    declaration alone is never trusted (close-when)."""
    pid = "P1d-f427-no-mapping-uncovered"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "delete_file",
        expect_sdk_tool_name="delete_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [g])])
    try:
        OAI_SHIM.audit_agent_coverage(agent)
    except OAI_SHIM.UncoveredSurfaceError as e:
        if "F427" not in str(e):
            _break(pid, "refused but misdiagnosed: %s" % (str(e)[:120],))
            return
        _held(pid, "no-mapping agent refused (F427)")
        return
    _break(pid, "certified on the declaration alone (F427 violated)")


def P1e():
    """Tool missing from the mapping -> uncovered."""
    pid = "P1e-f427-missing-mapping-entry-refused"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "delete_file",
        expect_sdk_tool_name="delete_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [g])])
    if _audit_certifies(agent, {"read_file": "read_file"}) is not None:
        _break(pid, "certified with no mapping entry for the tool")
        return
    _held(pid, "missing mapping entry refused")


def P1f():
    """Two-guardrail shape (lane-5 WATCH note): [correct, miswired] and
    [miswired, correct] -- the miswired one is a declared-name lie
    present on the tool, never certifiable coverage."""
    pid = "P1f-f427-two-guardrail-miswired-present-refused"
    ctx = make_run()
    binding = _support_binding(ctx)
    honest = OAI_SHIM.make_tool_input_guardrail(
        binding, "delete_file", expect_sdk_tool_name="delete_file")
    lie = OAI_SHIM.make_tool_input_guardrail(
        binding, "read_file", expect_sdk_tool_name="delete_file")
    for order, guardrails in (("honest-first", [honest, lie]),
                              ("lie-first", [lie, honest])):
        agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", guardrails)])
        if _audit_certifies(agent, _MAP) is not None:
            _break(pid, "certified with miswired guardrail present (%s)"
                   % order)
            return
    _held(pid, "miswired guardrail present refused in both orders")


def P1g():
    """Stale guardrail (no declared name) still refused with a mapping
    (F426 regression under the new parameter)."""
    pid = "P1g-f427-stale-no-declared-name-refused"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(_support_binding(ctx),
                                           "read_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [g])])
    try:
        OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=_MAP)
    except OAI_SHIM.UncoveredSurfaceError as e:
        if "expect_sdk_tool_name" not in str(e):
            _break(pid, "refused but misdiagnosed: %s" % (str(e)[:120],))
            return
        _held(pid, "stale guardrail refused")
        return
    _break(pid, "stale guardrail certified")


def P1h():
    """Declared-name mismatch (F426) still refused with a mapping."""
    pid = "P1h-f427-declared-name-mismatch-refused"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "read_file",
        expect_sdk_tool_name="read_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [g])])
    try:
        OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=_MAP)
    except OAI_SHIM.UncoveredSurfaceError:
        _held(pid, "declared-name mismatch refused")
        return
    _break(pid, "declared-name mismatch certified")


def _refuses_coded_f427(pid, agent, mapping):
    """HELD iff the audit refuses with an F427-coded diagnosis."""
    try:
        OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=mapping)
    except OAI_SHIM.UncoveredSurfaceError as e:
        if "F427" not in str(e):
            _break(pid, "refused but not F427-coded: %s" % (str(e)[:160],))
            return
        _held(pid, "refused coded (F427)")
        return
    _break(pid, "F427 variant CERTIFIED with mapping supplied")


def P1i():
    """Round-8 V1 (attack lane red target): canonical construction-lie
    with the mapping supplied -> refused CODED (mapping disagreement,
    not just the no-mapping fallback)."""
    pid = "P1i-r8v1-construction-lie-coded-refusal"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "read_file",
        expect_sdk_tool_name="delete_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [g])])
    _refuses_coded_f427(pid, agent, _MAP)


def P1j():
    """Round-8 V2 (attack lane red target): wrapper-delegate -- the
    issued fn wrapped with .guardrail_function pointing at it. The
    audit unwraps to the issued fn and refuses coded."""
    pid = "P1j-r8v2-wrapper-delegate-coded-refusal"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "read_file",
        expect_sdk_tool_name="delete_file")

    def _wrapper(data):
        return g(data)
    _wrapper.guardrail_function = g
    agent = _OAIAgent("x", [_OAIFunctionTool("delete_file", [_wrapper])])
    _refuses_coded_f427(pid, agent, _MAP)


def P1k():
    """Round-8 V3 (attack lane red target): attr-mutation shape --
    write_file guardrail declaring read_file on the read_file tool.
    The audit hole is real even though the runtime effect over-blocks
    (fail-closed); the mapping fix refuses it coded."""
    pid = "P1k-r8v3-attr-mutation-coded-refusal"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(
        _support_binding(ctx), "write_file",
        expect_sdk_tool_name="read_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("read_file", [g])])
    _refuses_coded_f427(pid, agent, _MAP)


# ---------------------------------------------------------------------------
# P2: pin + footer honesty.
# ---------------------------------------------------------------------------

def P2a():
    """Pin 2131: taxonomy 2134/2134/0 sorted-unique on raw literals
    (wave-260 lesson)."""
    pid = "P2a-pin-taxonomy-2134-sorted"
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    found = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(found) != TAXONOMY_PIN or len(set(found)) != TAXONOMY_PIN:
        _break(pid, "want %d/%d/0 sorted-unique, got %d/%d"
               % (TAXONOMY_PIN, TAXONOMY_PIN, len(found), len(set(found))))
        return
    _held(pid, "taxonomy %d/%d/0 sorted-unique" % (TAXONOMY_PIN,
                                                  TAXONOMY_PIN))


def P2b():
    """Footer: open none / next F430; F426 and F427 marked CLOSED."""
    pid = "P2b-footer-open-f430-f431-next-f432"
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    lines = text.splitlines()
    last = lines[-1] if lines else ""
    if "Next free finding: **F432**" not in last:
        _break(pid, "footer does not read next F430: %r" % (last[:120],))
        return
    if "Open findings: F430, F431." not in last:
        _break(pid, "footer does not read open none: %r" % (last[:120],))
        return

    def _section(tag):
        m = re.search(r"^## %s\b.*$" % tag, text, re.M)
        if not m:
            return ""
        rest = text[m.end():]
        n = re.search(r"^## \S", rest, re.M)
        return rest[:n.start()] if n else rest
    for tag in ("F426", "F427"):
        if "**Status: OPEN.**" in _section(tag):
            _break(pid, "%s section still marked OPEN" % tag)
            return
    if "CLOSED" not in _section("F427"):
        _break(pid, "F427 section has no CLOSED marker")
        return
    _held(pid, "footer open none / next F430, F426+F427 closed")


# ---------------------------------------------------------------------------
# P3: R34 -- re-audit against openai-agents 0.23.0/0.23.1 shapes.
# ---------------------------------------------------------------------------

def P3a():
    """#5144 analog: approvals scoped to the owning agent. Two agents
    with the same tool queue the same call -> two DISTINCT per-call
    approval_ids, each record agent-bound; deciding one leaves the
    other pending (no standing grant leaks across agents)."""
    pid = "P3a-r34-approvals-scoped-to-owning-agent"
    ctx = make_run()

    def _bind(aid):
        return GovernedBinding(ctx["executor"],
                               ctx["mint_identity"](aid, "coder", "dev-org"))
    g_a = OAI_SHIM.make_tool_input_guardrail(_bind("agent-A"), "write_file")
    g_b = OAI_SHIM.make_tool_input_guardrail(_bind("agent-B"), "write_file")
    args = {"path": "/tmp/r34-a.txt", "content": "x"}
    o_a = g_a(_oai_data("write_file", args))
    o_b = g_b(_oai_data("write_file", args))
    id_a = (o_a.output_info or {}).get("approval_id")
    id_b = (o_b.output_info or {}).get("approval_id")
    if not id_a or not id_b:
        _error(pid, "queued calls produced no approval_ids")
        return
    if id_a == id_b:
        _break(pid, "two agents' queued calls share one approval_id "
                    "(#5144-class standing grant)")
        return
    rec_a = ctx["approvals"].get(id_a)
    rec_b = ctx["approvals"].get(id_b)
    if rec_a["agent_id"] == rec_b["agent_id"]:
        _break(pid, "approval records not agent-bound")
        return
    ctx["approvals"].decide(id_a, True, "ok", decided_by="human-operator")
    if ctx["approvals"].get(id_a)["status"] != "approved":
        _error(pid, "decision on A did not land")
        return
    if ctx["approvals"].get(id_b)["status"] != "pending":
        _break(pid, "deciding A's approval settled B's call "
                    "(cross-agent grant leak)")
        return
    _held(pid, "per-call approval_ids agent-bound; no cross-agent reuse")


def P3b():
    """#5066 analog: the approval sees the VALIDATED arguments. The
    queued approval record's args are exactly the kwargs the guardrail
    passed to binding.call -- no defaults added, no values transformed
    between what the human reviews and what executes."""
    pid = "P3b-r34-approval-sees-validated-arguments"
    ctx = make_run()
    g = OAI_SHIM.make_tool_input_guardrail(_coder_binding(ctx), "write_file")
    seen = {"path": "/tmp/r34-b.txt", "content": "hello"}
    out = g(_oai_data("write_file", seen))
    info = out.output_info or {}
    if info.get("decision") != "queued" or not info.get("approval_id"):
        _error(pid, "expected a queued call, got %r" % (info.get("decision"),))
        return
    rec = ctx["approvals"].get(info["approval_id"])
    if set(rec["args"].keys()) != set(seen.keys()):
        _break(pid, "approval record args differ from guardrail-seen args: "
                    "%r vs %r (#5066-class)" % (sorted(rec["args"].keys()),
                                               sorted(seen.keys())))
        return
    if not rec.get("args_digest"):
        _break(pid, "approval record carries no args digest")
        return
    _held(pid, "approval record binds exactly the seen args "
               "(args_digest=%s)" % str(rec["args_digest"])[:16])


def P3c():
    """#5124 analog: tools resolved after start hooks. coverage_drift
    names added/removed tools between the audit report and the agent's
    current tool set; a hook-style post-audit mutation is refused on
    re-audit."""
    pid = "P3c-r34-post-audit-tool-mutation-drift"
    ctx = make_run()
    binding = _coder_binding(ctx)
    g = OAI_SHIM.make_tool_input_guardrail(
        binding, "write_file", expect_sdk_tool_name="write_file")
    agent = _OAIAgent("x", [_OAIFunctionTool("write_file", [g])])
    rep = OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=_MAP)
    drift = OAI_SHIM.coverage_drift(rep, agent)
    if drift != {"added": [], "removed": []}:
        _break(pid, "no-drift case misreported: %r" % (drift,))
        return
    # Start-hook-style mutation: a tool appears after the audit.
    agent.tools.append(_OAIFunctionTool("evil_tool", []))
    drift = OAI_SHIM.coverage_drift(rep, agent)
    if drift["added"] != ["evil_tool"]:
        _break(pid, "added tool not named by drift: %r" % (drift,))
        return
    try:
        OAI_SHIM.audit_agent_coverage(agent, sdk_tool_map=_MAP)
    except OAI_SHIM.UncoveredSurfaceError:
        pass
    else:
        _break(pid, "re-audit certified the mutated agent")
        return
    # Removal is drift too.
    agent.tools.pop()
    agent.tools.pop()
    drift = OAI_SHIM.coverage_drift(rep, agent)
    if drift["removed"] != ["write_file"]:
        _break(pid, "removed tool not named by drift: %r" % (drift,))
        return
    _held(pid, "drift named (added/removed); re-audit refuses mutation")


def P3d():
    """#4632 analog: one issued guardrail shared across many SDK tools
    (server-wide style). The audit is per-tool: the guardrail certifies
    only the SDK tool it declares; every other tool carrying it is
    refused."""
    pid = "P3d-r34-shared-guardrail-scoped-per-tool"
    ctx = make_run()
    binding = _coder_binding(ctx)
    g = OAI_SHIM.make_tool_input_guardrail(
        binding, "write_file", expect_sdk_tool_name="t1")
    mapping = {"t1": "write_file", "t2": "write_file"}
    rep = _audit_certifies(_OAIAgent("a", [_OAIFunctionTool("t1", [g])]),
                           mapping)
    if rep is None or rep["tools"] != ["t1"]:
        _break(pid, "declared tool not certified")
        return
    if _audit_certifies(_OAIAgent("b", [_OAIFunctionTool("t2", [g])]),
                        mapping) is not None:
        _break(pid, "shared guardrail certified an undeclared tool "
                    "(#4632-class over-broad mediation)")
        return
    _held(pid, "shared guardrail certifies only its declared tool")


_PROBES = [
    ("P1a-f427-declared-name-lie-refused", P1a),
    ("P1b-f427-disagreeing-mapping-refused", P1b),
    ("P1c-f427-honest-mapping-certifies", P1c),
    ("P1d-f427-no-mapping-uncovered", P1d),
    ("P1e-f427-missing-mapping-entry-refused", P1e),
    ("P1f-f427-two-guardrail-miswired-present-refused", P1f),
    ("P1g-f427-stale-no-declared-name-refused", P1g),
    ("P1h-f427-declared-name-mismatch-refused", P1h),
    ("P1i-r8v1-construction-lie-coded-refusal", P1i),
    ("P1j-r8v2-wrapper-delegate-coded-refusal", P1j),
    ("P1k-r8v3-attr-mutation-coded-refusal", P1k),
    ("P2a-pin-taxonomy-2134-sorted", P2a),
    ("P2b-footer-open-f430-f431-next-f432", P2b),
    ("P3a-r34-approvals-scoped-to-owning-agent", P3a),
    ("P3b-r34-approval-sees-validated-arguments", P3b),
    ("P3c-r34-post-audit-tool-mutation-drift", P3c),
    ("P3d-r34-shared-guardrail-scoped-per-tool", P3d),
]


def _run_root():
    base = os.environ.get("TMPDIR") or "/var/tmp"
    root = os.path.join(base, "w340-f427close")
    os.makedirs(root, exist_ok=True)
    return root


# Depth-1 green checks over the batteries this lane touched (w338_f426
# P2b footer update + mapping threading; w337_redteam P3b mapping).
# Children run with GOV_SKIP_GREEN=1, so their own green children
# collapse into the GREEN-SKIPPED HELD; tuples measured on the closed
# tree.
_CHILD_BATTERIES = [
    ("w338_f426_probes.py", 0, "0/11/0"),
]


def _run_child_output(name):
    """Run an adjacent battery's main with green checks skipped
    (depth-1 green checks) and return its stdout tail."""
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
    """Depth-1 green checks. Honors GOV_SKIP_GREEN."""
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
                print("unknown probe %r" % want)
                sys.exit(2)
            matched.extend(hits)
        todo = matched
    for pid, fn in todo:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - loud, never a skip
            _error(pid, "%s: %s" % (type(e).__name__, e))
    _green_check()
    b, h, e = _summary()
    for pid, verdict, note in _results:
        print("%s: %s -- %s" % (pid, verdict, note[:200]))
    print("%d BREAK / %d HELD / %d ERROR" % (b, h, e))
    sys.exit(1 if b or e else 0)


if __name__ == "__main__":
    main()
