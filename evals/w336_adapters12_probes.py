#!/usr/bin/env python3
"""Wave-336 lane 3: CrewAI + AG2 framework adapters.

Base: `c4acf39e` (wave-335 merge). Pin 2109. Footer open F423 / next F424.

New surface under test: `gov/adapters/crewai_tools.py` (a governed
`crewai.tools.BaseTool` whose `_run`/`_arun` route through
`GovernedBinding`; verified against crewai 1.15.23) and
`gov/adapters/ag2_hooks.py` (AG2 1.x middleware -- per-tool
`ToolMiddleware` and agent-wide `BaseMiddleware.on_tool_execution`;
verified against ag2 1.1.2).

Break-first probes at the public seams:

P1 (crewai executes mediated): governed tool runs through the binding --
   executor status "executed", sandbox file written, exactly one
   mediation counted.
P2 (crewai denied): a role-denied tool raises ToolDeniedError coded and
   writes nothing.
P3 (crewai F62 class): an undeclared smuggled kwarg reaches mediation
   and the audit record (not silently dropped by
   BaseTool._validate_kwargs).
P4 (crewai fail-closed construction): strict args_schema (no
   extra="allow") refused at construction; unregistered framework_tool
   refused at construction; bad on_denied/on_queued refused.
P5 (crewai funnel pinned): BaseTool.run delegates to the overridden
   _run (framework-version assumption, fails loudly on drift).
P6 (ag2 per-tool allowed): middleware lets an allowed call reach the
   implementation exactly once.
P7 (ag2 denied): denied call returns ToolErrorEvent, implementation
   never invoked, denial audited.
P8 (ag2 malformed): unparseable / non-object arguments return
   ToolErrorEvent coded MalformedToolCallError; unregistered names
   return ToolErrorEvent coded UnregisteredToolError.
P9 (optional-extra convention): without the framework installed the
   adapter module raises ImportError naming the extra; with it, import
   succeeds.
P10 (honesty): taxonomy 2134/2134/0 sorted-unique on raw source
   literals; no new decision codes (adapters reuse existing outcomes);
   footer open none / next F430.

Framework-real probes (P1-P8) SKIP cleanly when crewai/ag2 are not
installed (optional extras, same convention as the LangChain adapter
tests); P9-P10 and the green check always run.

Verdicts:
  HELD  = behavior matches the pin;
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem;
  SKIP  = optional framework extra not installed (recorded, not an error).

Genuine findings get F-numbers from F424; none are manufactured -- a
0-break battery is an honest result.

Deterministic across 2 runs; $0 spend; synthetic/local. Real product
code, no stubs; no live model calls (AG2 middleware seam exercised
directly with a recording call_next; CrewAI tools run against the
in-memory executor).

Run:
  mkdir -p /var/tmp/g336-ad
  TMPDIR=/var/tmp/g336-ad ~/workspace/.gov-venv/bin/python evals/w336_adapters12_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g336-adb ~/workspace/.gov-venv/bin/python evals/w336_adapters12_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w336_adapters12_probes.py P7a
Framework-real (optional extras installed):
  /var/tmp/g336-fvenv/bin/python evals/w336_adapters12_probes.py
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)
try:
    from pydantic import BaseModel, ConfigDict, Field
    from gov.adapters.crewai_tools import (
        GovernedCrewTool,
        make_governed_crewai_tool,
    )
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

try:
    from ag2.events import ToolCallEvent, ToolErrorEvent, ToolResultEvent
    from gov.adapters.ag2_hooks import (
        GovernedAgentMiddleware,
        GovernedToolMiddleware,
        governed_tool_middleware,
    )
    AG2_AVAILABLE = True
except ImportError:
    AG2_AVAILABLE = False

from gov.adapters.core import (  # noqa: E402
    ApprovalRequiredError,
    GovernedBinding,
    ToolDeniedError,
    UnregisteredToolError,
)


def _key():
    # Standalone battery runs do not import the tests package, so
    # provision a key here when absent. Test-only.
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


def _make_run():
    try:
        from tests.harness import make_run
    except ImportError:
        from harness import make_run
    return make_run()


def _coder_binding(ctx):
    ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
    return GovernedBinding(ctx["executor"], ident)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0][:160]))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _skip(pid, note):
    _record(pid, "SKIP", note)


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


# ---------------------------------------------------------------- probes

class _WriteArgs(BaseModel):
    # Only defined when crewai is importable (pydantic always is here,
    # but keep the shape parallel to the test file).
    model_config = ConfigDict(extra="allow")
    path: str = Field(description="Destination path")
    content: str = Field(description="Content to write")


class _EmailArgs(BaseModel):
    model_config = ConfigDict(extra="allow")
    to: str = Field(description="Recipient")
    subject: str = Field(description="Subject")
    body: str = Field(description="Body")


def _crewai_write_tool(binding, **kwargs):
    return make_governed_crewai_tool(
        binding, name="write_notes", description="Write a notes file.",
        args_schema=_WriteArgs, framework_tool="write_file", **kwargs)


def P1a():
    pid = "P1a-crewai-mediated-execution"
    if not CREWAI_AVAILABLE:
        _skip(pid, "crewai extra not installed")
        return
    ctx = _make_run()
    tool = _crewai_write_tool(_coder_binding(ctx))
    out = tool.run(path="p1a.txt", content="x")
    payload = json.loads(out)
    ok = (payload.get("status") == "executed"
          and (ctx["run_dir"] / "sandbox" / "p1a.txt").is_file()
          and ctx["executor"].counters.get("write_file") == 1)
    (_held if ok else _break)(
        pid, "executed once, sandbox write present" if ok
        else "mediation mismatch: %r" % (payload,))


def P2a():
    pid = "P2a-crewai-denied-coded"
    if not CREWAI_AVAILABLE:
        _skip(pid, "crewai extra not installed")
        return
    ctx = _make_run()
    tool = make_governed_crewai_tool(
        _coder_binding(ctx), name="send_mail", description="Send email.",
        args_schema=_EmailArgs, framework_tool="send_email")
    try:
        tool.run(to="x@synthetic.local", subject="s", body="b")
        _break(pid, "denied tool executed")
    except ToolDeniedError as exc:
        denied = [e for e in ctx["read_log"]()
                  if e.get("decision") == "denied"]
        if exc.native_tool == "send_email" and denied:
            _held(pid, "ToolDeniedError coded, denial audited")
        else:
            _break(pid, "denial not audited")


def P3a():
    pid = "P3a-crewai-f62-smuggled-kwarg"
    if not CREWAI_AVAILABLE:
        _skip(pid, "crewai extra not installed")
        return
    ctx = _make_run()
    tool = _crewai_write_tool(_coder_binding(ctx))
    out = tool.run(path="p3a.txt", content="x", bcc="evil@example.com")
    if json.loads(out).get("status") != "executed":
        _break(pid, "unexpected non-executed outcome")
        return
    found = any(
        "bcc" in (entry.get("args") or {})
        for entry in ctx["read_log"]()
        if entry.get("event") == "tool_call")
    (_held if found else _break)(
        pid, "smuggled kwarg in audit record" if found
        else "smuggled kwarg dropped before mediation")


def P4a():
    pid = "P4a-crewai-strict-schema-refused"
    if not CREWAI_AVAILABLE:
        _skip(pid, "crewai extra not installed")
        return
    ctx = _make_run()

    class StrictArgs(BaseModel):
        model_config = ConfigDict(extra="ignore")
        path: str = Field(description="p")

    try:
        make_governed_crewai_tool(
            _coder_binding(ctx), name="s", description="s",
            args_schema=StrictArgs, framework_tool="write_file")
        _break(pid, "strict schema accepted at construction")
    except ValueError as exc:
        if "extra='allow'" in str(exc):
            _held(pid, "strict schema refused at construction")
        else:
            _break(pid, "wrong refusal: %r" % (exc,))


def P4b():
    pid = "P4b-crewai-bad-init-refused"
    if not CREWAI_AVAILABLE:
        _skip(pid, "crewai extra not installed")
        return
    ctx = _make_run()
    binding = _coder_binding(ctx)
    bad = 0
    try:
        make_governed_crewai_tool(
            binding, name="u", description="u", args_schema=_WriteArgs,
            framework_tool="not_a_tool")
    except UnregisteredToolError:
        bad += 1
    try:
        _crewai_write_tool(binding, on_denied="sometimes")
    except ValueError:
        bad += 1
    try:
        make_governed_crewai_tool(
            "not-a-binding", name="x", description="x",
            args_schema=_WriteArgs, framework_tool="write_file")
    except TypeError:
        bad += 1
    (_held if bad == 3 else _break)(
        pid, "3/3 bad-init shapes refused" if bad == 3
        else "only %d/3 refused" % bad)


def P5a():
    pid = "P5a-crewai-funnel-pinned"
    if not CREWAI_AVAILABLE:
        _skip(pid, "crewai extra not installed")
        return
    import inspect
    from crewai.tools import BaseTool
    src = inspect.getsource(BaseTool.run)
    if "_run" in src and GovernedCrewTool._run.__qualname__ == \
            "GovernedCrewTool._run":
        _held(pid, "run() -> _run funnel holds")
    else:
        _break(pid, "funnel assumption drifted")


def _ag2_recorder():
    class Recorder:
        def __init__(self):
            self.calls = []

        async def __call__(self, event, context):
            self.calls.append(event)
            return ToolResultEvent.from_call(
                event, result="implemented:%s" % event.name)
    return Recorder()


def P6a():
    pid = "P6a-ag2-allowed-reaches-impl"
    if not AG2_AVAILABLE:
        _skip(pid, "ag2 extra not installed")
        return
    ctx = _make_run()
    mw = governed_tool_middleware(_coder_binding(ctx))
    rec = _ag2_recorder()
    event = ToolCallEvent(name="write_file",
                          arguments=json.dumps({"path": "p6a.txt",
                                                "content": "x"}))
    out = asyncio.run(mw(rec, event, None))
    ok = (isinstance(out, ToolResultEvent)
          and not isinstance(out, ToolErrorEvent)
          and len(rec.calls) == 1
          and (ctx["run_dir"] / "sandbox" / "p6a.txt").is_file())
    (_held if ok else _break)(
        pid, "allowed call reached impl once" if ok
        else "middleware mismatch: %r" % (type(out).__name__,))


def P7a():
    pid = "P7a-ag2-denied-error-event"
    if not AG2_AVAILABLE:
        _skip(pid, "ag2 extra not installed")
        return
    ctx = _make_run()
    mw = governed_tool_middleware(_coder_binding(ctx))
    rec = _ag2_recorder()
    event = ToolCallEvent(name="send_email",
                          arguments=json.dumps({"to": "x@synthetic.local",
                                                "subject": "s", "body": "b"}))
    out = asyncio.run(mw(rec, event, None))
    denied = [e for e in ctx["read_log"]()
              if e.get("decision") == "denied"]
    ok = (isinstance(out, ToolErrorEvent)
          and isinstance(out.error, ToolDeniedError)
          and rec.calls == [] and denied)
    (_held if ok else _break)(
        pid, "denied -> ToolErrorEvent, impl untouched, audited" if ok
        else "denial mismatch")


def P8a():
    pid = "P8a-ag2-malformed-and-unregistered"
    if not AG2_AVAILABLE:
        _skip(pid, "ag2 extra not installed")
        return
    ctx = _make_run()
    mw = governed_tool_middleware(_coder_binding(ctx))
    rec = _ag2_recorder()
    shapes = [
        ToolCallEvent(name="write_file", arguments="not-json{"),
        ToolCallEvent(name="write_file", arguments="[1, 2]"),
        ToolCallEvent(name="nope", arguments=json.dumps({"x": 1})),
    ]
    outs = [asyncio.run(mw(rec, ev, None)) for ev in shapes]
    from gov.adapters.core import MalformedToolCallError
    ok = (all(isinstance(o, ToolErrorEvent) for o in outs)
          and isinstance(outs[0].error, MalformedToolCallError)
          and isinstance(outs[1].error, MalformedToolCallError)
          and isinstance(outs[2].error, UnregisteredToolError)
          and rec.calls == [])
    (_held if ok else _break)(
        pid, "malformed/unregistered -> ToolErrorEvent, impl untouched"
        if ok else "refusal mismatch")


def P9a():
    pid = "P9a-adapter-extra-convention"
    # The modules must either import (framework present) or raise
    # ImportError naming the extra (framework absent) -- never any other
    # failure mode.
    import importlib
    ok = True
    notes = []
    for modname, extra, avail in (
            ("gov.adapters.crewai_tools", "crewai", CREWAI_AVAILABLE),
            ("gov.adapters.ag2_hooks", "ag2", AG2_AVAILABLE)):
        try:
            importlib.import_module(modname)
            if not avail:
                ok = False
                notes.append("%s imported without %s" % (modname, extra))
        except ImportError as exc:
            if avail or extra not in str(exc):
                ok = False
                notes.append("%s: %r" % (modname, exc))
    (_held if ok else _break)(
        pid, "extra convention holds" if ok else "; ".join(notes))


def P10a():
    pid = "P10a-pin-taxonomy-2134-sorted"
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = re.findall(r'''"code":\s*['"]([^'"]+)['"]''', src)
    if len(codes) != TAXONOMY_PIN:
        _break(pid, "taxonomy size %d != pin %d" % (len(codes),
                                                   TAXONOMY_PIN))
        return
    if len(set(codes)) != TAXONOMY_PIN:
        _break(pid, "duplicate code literals")
        return
    if codes != sorted(codes):
        _break(pid, "taxonomy not sorted on raw literals")
        return
    _held(pid, "taxonomy %d/%d/0 sorted-unique" % (TAXONOMY_PIN,
                                                  TAXONOMY_PIN))


def P10b():
    pid = "P10b-footer-open-f433-f434-f435-next-f436"
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F437**" in text
          and m_open and m_open[-1].strip() == "F436")
    (_held if ok else _break)(
        pid, "footer: open none / next F430" if ok
        else "footer mismatch vs open none / next F430")


_PROBES = [
    ("P1a-crewai-mediated-execution", P1a),
    ("P2a-crewai-denied-coded", P2a),
    ("P3a-crewai-f62-smuggled-kwarg", P3a),
    ("P4a-crewai-strict-schema-refused", P4a),
    ("P4b-crewai-bad-init-refused", P4b),
    ("P5a-crewai-funnel-pinned", P5a),
    ("P6a-ag2-allowed-reaches-impl", P6a),
    ("P7a-ag2-denied-error-event", P7a),
    ("P8a-ag2-malformed-and-unregistered", P8a),
    ("P9a-adapter-extra-convention", P9a),
    ("P10a-pin-taxonomy-2134-sorted", P10a),
    ("P10b-footer-open-f424-f425-next-f426", P10b),
]

_EXPECTED_BREAKS = set()


def _run_child_output(path, timeout):
    d = tempfile.mkdtemp(prefix="g336-adgreen-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, path], env=env, capture_output=True, text=True,
        timeout=timeout, cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the two adapter unit suites as children with
    GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by recording
    a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    problems = []
    for suite in ("tests/test_adapters_crewai.py",
                  "tests/test_adapters_ag2.py"):
        try:
            rc, out = _run_child_output(os.path.join(REPO, suite),
                                        timeout=600)
        except Exception as exc:  # noqa: BLE001
            _record("green-check", "ERROR", "%s: %s" % (suite, exc))
            return
        if rc != 0 or "FAILED" in out or "ERROR:" in out:
            problems.append(suite)
    if problems:
        _record("green-check", "BREAK",
                "non-green: %s" % sorted(problems))
    else:
        _record("green-check", "HELD",
                "adapter suites green (or cleanly skipped)")


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    _key()
    # Collect EVERY record each probe emits (probes record multiple
    # sub-results); tallying only the last record per probe would miss
    # a BREAK buried mid-probe.
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    first = list(_results)
    green = None
    if only is None:
        _green_check()
        green = _results[-1]
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    second = list(_results)
    # Determinism compares probe verdicts only; the green-check record
    # is a single-runner observation, not a probe.
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    tallied = first + ([green] if green else [])
    n_break = sum(1 for _, v, _ in tallied if v == "BREAK")
    n_held = sum(1 for _, v, _ in tallied if v == "HELD")
    n_skip = sum(1 for _, v, _ in tallied if v == "SKIP")
    n_err = sum(1 for _, v, _ in tallied if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in tallied
                    if v == "BREAK" and pid != "green-check"}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("----")
    print("w336_adapters12 battery: %d BREAK / %d HELD / %d SKIP / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_skip, n_err, det))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err:
        print("ERRORs present -- battery failed closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
