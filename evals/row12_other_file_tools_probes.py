#!/usr/bin/env python3
"""Row-12 NON-`write_file` FILE-CREATING TOOLS enumeration + proof battery.

Wave-162 closed the undeclared-path residual AT THE `write_file` SEAM but
left row 12 PARTIAL for "undeclared paths via non-`write_file` tools".
This battery ENUMERATES the full agent-reachable file-creation surface of
``gov.executor.ToolExecutor`` and dispositions every candidate:

  Agent-reachable file creation (executor tool surface, gov/policy.py
  KNOWN_TOOLS; _simulate dispatch; sandbox backend execute()):
    write_file      -- the ONLY tool whose _simulate branch performs a
                       real filesystem write (plain executor AND the
                       SandboxedToolBackend._write child path).
    read_file       -- reads only.
    delete_file     -- deletes only (correctly out of the write binding's
                       scope: no write_undeclared_path event).
    api_call / http_post / send_email -- synthetic; no real side effects.
    install_package -- SIMULATED install (gov/supplychain_install.py:
                       allowlist + pin + integrity over canonical bytes);
                       writes no files.
    window_close    -- governance primitive, denied as a tool.

  Dispatch paths that reach write_file:
    D1 direct executor.call(identity, "write_file", ...) -- the wave-162
       binding fires here (gov/executor.py call(), tool == "write_file").
    D2 SandboxedToolBackend via gov/sandbox.py::install(executor) --
       replaces ONLY executor._simulate; the binding sits ABOVE it in
       call(), so the backend inherits the binding.
    D3 framework aliases via gov/adapters/core.py::GovernedBinding --
       resolves framework->NATIVE name BEFORE executor.call(), so the
       binding sees the native "write_file". Aliases cannot dodge the
       `tool == "write_file"` check.
    D4 langchain / MCP / openai_loop adapters -- all funnel through
       binding.call() (D3).
    D5 approved sweep -- calls _invoke_simulate directly, but only with
       MAC-bound HUMAN-APPROVED args (by design, wave-162 docstring).
    D6 governed(..., run_body=True) split -- the executor-side call is
       still bound (queued -> ApprovalRequiredError -> body never runs);
       a deployer deliberately invoking the body after a denial is the
       documented dishonest-ceremony boundary (OUT of scope).

  Conclusion under test: there is NO unbound non-write_file
  file-creating tool in the agent-reachable surface. The probes below
  prove each disposition red-first: with the wave-162 seam neutralized
  (monkeypatched to silent-allow -- the honest equivalent of the
  pre-seam tree for THESE paths), D1/D2/D3/D6 execute silently (BREAK);
  with the seam present, all are HELD. D5 is pinned as approved-only;
  install_package/delete_file/unknown-tool are pinned as non-creating.

$0 spend, synthetic/local. Run:
  mkdir -p /tmp/gov-row12-filetools
  TMPDIR=/tmp/gov-row12-filetools ~/workspace/.gov-venv/bin/python \\
      evals/row12_other_file_tools_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-row12-filetools2 \\
      ~/workspace/.gov-venv/bin/python evals/row12_other_file_tools_probes.py
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "row12-file-tools")
# Wave-95 lesson: the harness's declared ungoverned_ack is refused in
# production mode, so the module default must be staging.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-row12-filetools")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests"),
           os.path.join(REPO_ROOT, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import probe_lines  # noqa: E402  (canonical probe-line form)

from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov import artifact_inventory_manifest as _manifest_mod  # noqa: E402
from gov.adapters.core import (  # noqa: E402
    GovernedBinding, ApprovalRequiredError)
from gov.adapters.generic import governed  # noqa: E402

HAVE_SEAM = hasattr(ToolExecutor, "check_write_declared_path")

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"
PRINCIPAL = "user-1"
AGENT = "coder-1"

_UNGOVERNED_ACK = (
    "row12-file-tools eval: synthetic red-team harness; raw "
    "pre-wave-74/75 pipeline by design, declared and chained")

DECLARED_SHA = "ab" * 32


# ---------------------------------------------------------------------------
# Harness (wave-162 pattern)
# ---------------------------------------------------------------------------

def _pin(entries):
    return _manifest_mod.pin_manifest(entries)


def _session(manifest=None, declared_write_dirs=None):
    run_dir = Path(tempfile.mkdtemp(prefix="govrow12ft-",
                                    dir=os.environ["TMPDIR"]))
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    kw = {}
    if manifest is not None:
        kw["deployment_manifest"] = manifest
    else:
        kw["deployment_manifest_opt_out"] = (
            "row12-file-tools eval: no deployment-critical files")
    if declared_write_dirs is not None:
        kw["declared_write_dirs"] = declared_write_dirs
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack=_UNGOVERNED_ACK, **kw)
    return {"run_dir": run_dir, "executor": ex, "log": log,
            "approvals": approvals}


def _ident(ctx):
    return ctx["executor"].mint_identity(AGENT, "coder", PRINCIPAL)


def _events(ctx):
    return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
            if isinstance(e, dict)]


def _write_events(ctx):
    return [e for e in _events(ctx)
            if e.get("event") == "write_undeclared_path"]


def _on_disk(ctx, rel):
    return (ctx["run_dir"] / "sandbox" / rel).is_file()


def _sandbox_files(ctx):
    root = ctx["run_dir"] / "sandbox"
    return {p.relative_to(root).as_posix()
            for p in root.rglob("*") if p.is_file()}


# ---------------------------------------------------------------------------
# Seam neutralization (red phase): the honest pre-seam equivalent for the
# D1/D2/D3/D6 dispatch paths -- the binding is the ONLY thing that can
# hold them, so neutralizing it must produce silent execution (BREAK).
# ---------------------------------------------------------------------------

_ORIG_CHECK = ToolExecutor.check_write_declared_path


def _neutralize():
    def _silent_allow(self, agent_id, path_resolved, declared_path=None):
        return {"verdict": "allow", "declared": True,
                "reason": "red-phase-neutralized", "path": path_resolved}
    ToolExecutor.check_write_declared_path = _silent_allow


def _restore():
    ToolExecutor.check_write_declared_path = _ORIG_CHECK


# ---------------------------------------------------------------------------
# Probes. Each returns (verdict, detail). `red` selects the phase.
# ---------------------------------------------------------------------------

def e1_direct_write_file(red):
    """D1 anchor: undeclared write_file via executor.call."""
    ctx = _session(manifest=_pin({"a.bin": DECLARED_SHA}))
    ident = _ident(ctx)
    res = ctx["executor"].call(ident, "write_file", path="evil.bin",
                              content="hostile bytes")
    evs = _write_events(ctx)
    if red:
        if (res.get("status") == "executed" and _on_disk(ctx, "evil.bin")
                and not evs):
            return ("BREAK", "seam neutralized: undeclared write_file "
                    "executed silently")
        return ("ERROR", "red phase unexpected: %r" % (res,))
    if (res.get("status") == "queued" and res.get("approval_id")
            and not _on_disk(ctx, "evil.bin") and len(evs) == 1
            and evs[0].get("flag") == "undeclared_write_path"):
        return ("HELD", "D1 bound: queued loud, not on disk")
    return ("BREAK", "D1 REGRESSION: undeclared write_file not held: %r"
            % (res,))


def e2_framework_alias(red):
    """D3: framework alias write_notes -> native write_file cannot dodge
    the `tool == \"write_file\"` check (binding resolves native first)."""
    ctx = _session(manifest=_pin({"a.bin": DECLARED_SHA}))
    ident = _ident(ctx)
    binding = GovernedBinding(ctx["executor"], ident,
                              tool_map={"write_notes": "write_file"})
    try:
        res = binding.call("write_notes", path="evil.bin",
                           content="hostile bytes")
        raised = None
    except ApprovalRequiredError as exc:
        res, raised = None, exc
    evs = _write_events(ctx)
    if red:
        if (res is not None and res.get("status") == "executed"
                and _on_disk(ctx, "evil.bin") and not evs):
            return ("BREAK", "seam neutralized: aliased write executed "
                    "silently -- proves the alias path relies on the seam")
        return ("ERROR", "red phase unexpected: %r raised=%r" % (res, raised))
    if (raised is not None and not _on_disk(ctx, "evil.bin")
            and len(evs) == 1
            and evs[0].get("flag") == "undeclared_write_path"):
        return ("HELD", "D3 bound: alias queued loud via ApprovalRequiredError")
    return ("BREAK", "D3 REGRESSION: alias write not held: res=%r raised=%r"
            % (res, raised))


def e3_sandboxed_backend(red):
    """D2: SandboxedToolBackend (install() replaces _simulate only) --
    the binding sits above it in call()."""
    from gov.sandbox import install as install_backend
    ctx = _session(manifest=_pin({"a.bin": DECLARED_SHA}))
    install_backend(ctx["executor"])
    ident = _ident(ctx)
    res = ctx["executor"].call(ident, "write_file", path="evil.bin",
                              content="hostile bytes")
    evs = _write_events(ctx)
    if red:
        if (res.get("status") == "executed" and _on_disk(ctx, "evil.bin")
                and not evs):
            return ("BREAK", "seam neutralized: sandboxed-backend write "
                    "executed silently -- proves the backend relies on the "
                    "call()-level seam")
        return ("ERROR", "red phase unexpected: %r" % (res,))
    if (res.get("status") == "queued" and res.get("approval_id")
            and not _on_disk(ctx, "evil.bin") and len(evs) == 1
            and evs[0].get("flag") == "undeclared_write_path"):
        return ("HELD", "D2 bound: backend write queued loud, not on disk")
    return ("BREAK", "D2 REGRESSION: backend write not held: %r" % (res,))


def e4_install_package_writes_nothing(red):
    """install_package is simulated: a pinned install succeeds but writes
    no files anywhere in the sandbox. Not a file-creating tool."""
    ctx = _session(manifest=_pin({"a.bin": DECLARED_SHA}))
    ident = _ident(ctx)
    before = _sandbox_files(ctx)
    res = ctx["executor"].call(ident, "install_package", name="requests",
                              version="2.32.3")
    after = _sandbox_files(ctx)
    new_files = after - before
    installed = (res.get("result") or {}).get("installed")
    if installed is True and not new_files:
        return ("HELD", "install_package simulated: installed=True, "
                "zero new files in sandbox")
    return ("BREAK", "install_package wrote files or misbehaved: %r new=%r"
            % (res, sorted(new_files)))


def e5_delete_file_creates_nothing(red):
    """delete_file is correctly OUT of the write binding's scope and
    creates nothing."""
    ctx = _session(manifest=_pin({"a.bin": DECLARED_SHA}))
    ident = _ident(ctx)
    before = _sandbox_files(ctx)
    res = ctx["executor"].call(ident, "delete_file", path="evil.bin")
    after = _sandbox_files(ctx)
    evs = _write_events(ctx)
    if not evs and after == before:
        return ("HELD", "delete_file: no write_undeclared_path event, "
                "no files created (correctly out of scope)")
    return ("BREAK", "delete_file anomaly: %r events=%d" % (res, len(evs)))


def e6_run_body_split(red):
    """D6: governed(run_body=True) -- the executor-side call is still
    bound; on queue the wrapper raises BEFORE the body runs, so the
    body's own file write never happens. (A deployer deliberately
    invoking the body after a denial = dishonest-ceremony, out of
    scope -- this probe pins the seam-side behavior.)"""
    ctx = _session(manifest=_pin({"a.bin": DECLARED_SHA}))
    ident = _ident(ctx)
    binding = GovernedBinding(ctx["executor"], ident)
    marker = Path(tempfile.mkdtemp(prefix="govrow12ft-body-",
                                   dir=os.environ["TMPDIR"])) / "body.txt"

    @governed(binding, tool="write_file", run_body=True)
    def _writer(path, content):
        marker.write_text("body ran", encoding="utf-8")
        return {"body": "wrote"}

    raised = None
    try:
        res = _writer(path="evil.bin", content="hostile bytes")
    except ApprovalRequiredError as exc:
        res, raised = None, exc
    evs = _write_events(ctx)
    if red:
        if (res is not None and res.get("status") == "executed"
                and marker.is_file() and not evs):
            return ("BREAK", "seam neutralized: split body ran and wrote "
                    "outside the boundary silently")
        return ("ERROR", "red phase unexpected: %r raised=%r" % (res, raised))
    if (raised is not None and not marker.is_file() and len(evs) == 1
            and evs[0].get("flag") == "undeclared_write_path"):
        return ("HELD", "D6 bound at seam: queued loud, body never ran")
    return ("BREAK", "D6 REGRESSION: split call not held: res=%r raised=%r "
            "marker=%s" % (res, raised, marker.is_file()))


def e7_unknown_tool_noop(red):
    """Unknown tools simulate a no-op: no files, no binding event."""
    ctx = _session(manifest=_pin({"a.bin": DECLARED_SHA}))
    ident = _ident(ctx)
    before = _sandbox_files(ctx)
    res = ctx["executor"].call(ident, "copy_file", path="evil.bin",
                              content="hostile bytes")
    after = _sandbox_files(ctx)
    evs = _write_events(ctx)
    if after == before and not evs:
        return ("HELD", "unknown tool: simulated no-op, no files, no event")
    return ("BREAK", "unknown tool anomaly: %r new=%r" % (
        res, sorted(after - before)))


PROBES = [e1_direct_write_file, e2_framework_alias, e3_sandboxed_backend,
          e4_install_package_writes_nothing, e5_delete_file_creates_nothing,
          e6_run_body_split, e7_unknown_tool_noop]


def _run_phase(red):
    results = []
    for probe in PROBES:
        try:
            verdict, detail = probe(red)
        except Exception as exc:  # noqa: BLE001 -- battery must not crash
            verdict, detail = ("ERROR", "%s raised %r"
                               % (probe.__name__, exc))
        results.append((probe.__name__, verdict, detail))
    return results


def main():
    if not HAVE_SEAM:
        print("NO SEAM: check_write_declared_path absent -- cannot run")
        return 2
    print("== RED phase (seam neutralized: D1/D2/D3/D6 must BREAK) ==")
    _neutralize()
    red_results = _run_phase(red=True)
    _restore()
    # Phase-prefixed pids keep per-line pid uniqueness for coherence
    # (pid-class safe); verdicts here are already canonical.
    probe_lines.emit([("red_" + n, v, d) for n, v, d in red_results])
    print("== GREEN phase (seam present: all must HELD) ==")
    green_results = _run_phase(red=False)
    probe_lines.emit([("green_" + n, v, d) for n, v, d in green_results])
    # Determinism x2: repeat the green phase.
    print("== GREEN phase repeat (determinism x2) ==")
    green2 = _run_phase(red=False)
    probe_lines.emit([("green2_" + n, v, d) for n, v, d in green2])

    # Canonical summary over the union of all three phases.
    union = ([("red_" + n, v, d) for n, v, d in red_results]
             + [("green_" + n, v, d) for n, v, d in green_results]
             + [("green2_" + n, v, d) for n, v, d in green2])
    brk = sum(1 for _, v, _ in union if v == "BREAK")
    held = sum(1 for _, v, _ in union if v == "HELD")
    err = sum(1 for _, v, _ in union if v == "ERROR")
    print("row12_other_file_tools: %d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        union, brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))

    expect_break = {"e1_direct_write_file", "e2_framework_alias",
                    "e3_sandboxed_backend", "e6_run_body_split"}
    bad = []
    for name, verdict, _ in red_results:
        want = "BREAK" if name in expect_break else "HELD"
        if verdict != want:
            bad.append("red/%s: got %s want %s" % (name, verdict, want))
    for name, verdict, _ in green_results + green2:
        if verdict != "HELD":
            bad.append("green/%s: got %s" % (name, verdict))
    n_held = sum(1 for _, v, _ in green_results if v == "HELD")
    print("GREEN: %d/%d HELD (x2 deterministic)" % (n_held, len(PROBES)))
    if bad:
        print("FAILURES:")
        for b in bad:
            print("  " + b)
        return 1
    print("ALL EXPECTATIONS MET")
    return 0


if __name__ == "__main__":
    sys.exit(main())
