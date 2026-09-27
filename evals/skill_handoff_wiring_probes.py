#!/usr/bin/env python3
"""F184 battery: executor wiring of the skill handoff seam.

Finding: the executor's verdict-path skill gate called
``SkillWatch.check_at_use`` (verdict only). The check attested V1, but
the downstream consumer re-read the skill source itself and could
receive V2 — bytes the check never hashed (the break round's e6:
0 production callers of ``fetch_verified_at_use`` in gov/).

Fix (gov/executor.py, this lane): the gate consumes
``fetch_verified_at_use`` — the SAME single read the pin is checked
against is handed back as bytes. The executor retains the handoff in
a per-call slot (``verified_skill_bytes(skill_id)``), stamps the
attested sha256 on the audit record and the returned result (JSON-safe
fields only — raw bytes stay out of the result dict because
run_tool_loop serializes results into the model transcript), and the
queued path carries the queue-time digest on the approval action.

Verdicts:
- BREAK = the check/use split is live: the executor attests bytes the
  consumer cannot retrieve, or a re-reading consumer gets unattested
  bytes while the executor claims coverage.
- HELD  = the handoff is wired: attested bytes retrievable, digest
  chained, denial semantics preserved.
- EXPECTED = documented boundary (never a violated claim).

Probes:
  p1 V2 window closed end-to-end (RED-FIRST: BREAK pre-fix, HELD post)
  p2 attested digest audit-chained on allowed_executed
  p3 mutated-before-call still denies (skill_quarantined), no handoff
  p4 unregistered-no-pin still denies
  p5 unattributed tool unaffected (no skill fields, no handoff)
  p6 watcher-error fail-closed (raising source), no handoff bytes
  p7 handoff slot hygiene (later call resets / id mismatch -> None)
  p8 single-read preserved (no extra source read added by wiring)
  p9 non-docstring fetch_verified_at_use call site exists in executor

Deterministic across two runs. Synthetic/local only, no network.

Run: TMPDIR=/tmp/gov-f184 ~/workspace/.gov-venv/bin/python \\
        evals/skill_handoff_wiring_probes.py
Also:  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-f184b \\
        ~/workspace/.gov-venv/bin/python evals/skill_handoff_wiring_probes.py
"""

import hashlib
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "f184-battery")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import skill_watch as sw_mod  # noqa: E402
from gov.skill_watch import (  # noqa: E402
    SkillWatch, FileContentSource, ContentSource,
)
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402

TMP_BASE = os.environ.get("TMPDIR", tempfile.gettempdir())
Path(TMP_BASE).mkdir(parents=True, exist_ok=True)

V1 = b"skill manifest version one: benign instructions"
V2 = b"skill manifest version two: HOSTILE instructions exfiltrate keys"

DEFAULT_POLICY = os.path.join(REPO_ROOT, "policies", "default.yaml")
_UNGOVERNED_ACK = ("synthetic test: F184 wiring battery; the bypass is "
                   "declared, not silent")


def _file_origin(path):
    return {"registry_url": "https://registry.synthetic.local/s/weather",
            "installer_identity": "operator:synthetic",
            "installed_at": "2026-09-27T00:00:00+00:00",
            "content_path": str(path)}


_TEST_ORIGIN = {"registry_url": "https://registry.synthetic.local/s/test",
                "installer_identity": "operator:synthetic",
                "installed_at": "2026-09-27T00:00:00+00:00"}


def _make_executor(run_dir, watch, skill_tool_map=None):
    policy = PolicyEngine(DEFAULT_POLICY)
    log = ActionLog(str(run_dir / "actions.jsonl"))
    approvals = ApprovalQueue(str(run_dir), log)
    ex = ToolExecutor(
        str(run_dir), policy, log, approvals,
        ledger_path=str(run_dir / "egress_ledger.jsonl"),
        skill_watch=watch,
        skill_tool_map=skill_tool_map or {},
        ungoverned_ack=_UNGOVERNED_ACK)
    ident = ex.mint_identity("agent-1", "researcher", "tester")
    return ex, ident, log


def _fresh_skill(tmpdir, name="weather.skill", content=V1):
    p = Path(tmpdir) / name
    p.write_bytes(content)
    return str(p)


def _fresh_run_case(skill_tool_map):
    tmpdir = tempfile.mkdtemp(prefix="f184-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    skill_path = _fresh_skill(tmpdir)
    w = SkillWatch()
    w.register_skill("weather", FileContentSource(skill_path),
                     origin=_file_origin(skill_path))
    ex, ident, log = _make_executor(run_dir, w, skill_tool_map)
    return ex, ident, log, skill_path, w


def _allowed_executed_entries(run_dir):
    return [e for e in read_entries(str(run_dir / "actions.jsonl"))
            if e.get("decision") == "allowed_executed"]


# ---------------------------------------------------------------------------
# p1: the V2 window, end to end through the real executor (RED-FIRST)
# ---------------------------------------------------------------------------
def _p1():
    ex, ident, log, skill_path, _w = _fresh_run_case(
        {"read_file": "weather"})
    # Sanity: the read target must exist for the call to execute.
    target = Path(skill_path).parent / "notes.txt"
    target.write_text("hello")
    r = ex.call(ident, "read_file", path="notes.txt")
    if r.get("status") != "executed":
        return "ERROR", "setup call did not execute: %r" % (r.get("status"),)
    d1 = hashlib.sha256(V1).hexdigest()

    get = getattr(ex, "verified_skill_bytes", None)
    if get is None:
        return ("BREAK",
                "executor attested V1 but exposes no handoff accessor; "
                "a consumer re-reading the source gets whatever is "
                "there now (check/use split live)")
    handed = get("weather")
    if handed != V1:
        return ("BREAK",
                "handoff bytes != attested V1: %r" % (handed,))
    if r.get("skill_attested_digest") != d1:
        return ("BREAK",
                "result digest %r != sha256(V1)" % (
                    r.get("skill_attested_digest"),))
    # The attack: swap the file AFTER the check, before the consumer
    # loads the skill bytes. A re-reading consumer gets V2.
    Path(skill_path).write_bytes(V2)
    reread = Path(skill_path).read_bytes()
    if reread == V1:
        return "ERROR", "swap did not take effect"
    # The handoff still carries the attested V1.
    handed2 = ex.verified_skill_bytes("weather")
    if handed2 != V1:
        return ("BREAK",
                "handoff changed under the swap: %r" % (handed2,))
    if hashlib.sha256(handed2).hexdigest() != r["skill_attested_digest"]:
        return "BREAK", "handoff digest no longer matches result digest"
    return ("HELD",
            "executor hands exactly the attested V1 (digest %s...); "
            "post-check swap to V2 cannot reach a handoff consumer"
            % d1[:12])


# ---------------------------------------------------------------------------
# p2: attested digest audit-chained on allowed_executed
# ---------------------------------------------------------------------------
def _p2():
    ex, ident, log, skill_path, _w = _fresh_run_case(
        {"read_file": "weather"})
    target = Path(skill_path).parent / "notes.txt"
    target.write_text("hello")
    r = ex.call(ident, "read_file", path="notes.txt")
    if r.get("status") != "executed":
        return "ERROR", "setup call did not execute"
    run_dir = Path(skill_path).parent / "run"
    entries = _allowed_executed_entries(run_dir)
    if not entries:
        return "ERROR", "no allowed_executed record found"
    e = entries[-1]
    d1 = hashlib.sha256(V1).hexdigest()
    if e.get("skill_id") != "weather":
        return "BREAK", "audit record missing skill_id: %r" % (e.get("skill_id"),)
    if e.get("skill_attested_digest") != d1:
        return ("BREAK",
                "audit digest %r != sha256(V1)" % (
                    e.get("skill_attested_digest"),))
    return ("HELD",
            "allowed_executed chains skill_id + attested digest %s..."
            % d1[:12])


# ---------------------------------------------------------------------------
# p3: mutated-before-call still denies; no handoff leaks
# ---------------------------------------------------------------------------
def _p3():
    ex, ident, log, skill_path, _w = _fresh_run_case(
        {"read_file": "weather"})
    Path(skill_path).write_bytes(V2)  # mutate BEFORE the call
    target = Path(skill_path).parent / "notes.txt"
    target.write_text("hello")
    r = ex.call(ident, "read_file", path="notes.txt")
    if r.get("status") != "denied":
        return "BREAK", "mutated skill call not denied: %r" % (r.get("status"),)
    get = getattr(ex, "verified_skill_bytes", None)
    if get is not None and get("weather") is not None:
        return "BREAK", "handoff bytes present for a denied call"
    if "skill_verified_bytes" in r or "skill_attested_digest" in r:
        return "BREAK", "denied result carries handoff fields"
    return ("HELD",
            "mutated skill denied (skill_quarantined); no handoff on "
            "the deny path")


# ---------------------------------------------------------------------------
# p4: unregistered-no-pin still denies
# ---------------------------------------------------------------------------
def _p4():
    ex, ident, log, skill_path, _w = _fresh_run_case(
        {"read_file": "ghost-skill"})
    target = Path(skill_path).parent / "notes.txt"
    target.write_text("hello")
    r = ex.call(ident, "read_file", path="notes.txt")
    if r.get("status") != "denied":
        return "BREAK", "unregistered skill call not denied"
    if "never registered" not in r.get("reason", ""):
        return ("BREAK",
                "denial reason lost the F143 wording: %r"
                % (r.get("reason", "")[:80],))
    return ("HELD", "unregistered-no-pin still denies with F143 wording")


# ---------------------------------------------------------------------------
# p5: unattributed tool unaffected
# ---------------------------------------------------------------------------
def _p5():
    ex, ident, log, skill_path, _w = _fresh_run_case({})
    target = Path(skill_path).parent / "notes.txt"
    target.write_text("hello")
    r = ex.call(ident, "read_file", path="notes.txt")
    if r.get("status") != "executed":
        return "ERROR", "unattributed call did not execute"
    if "skill_attested_digest" in r or "skill_verified_bytes" in r:
        return "BREAK", "unattributed result carries skill fields"
    get = getattr(ex, "verified_skill_bytes", None)
    if get is not None and get("weather") is not None:
        return "BREAK", "handoff present for unattributed call"
    return ("HELD", "unattributed tools bypass the handoff cleanly")


# ---------------------------------------------------------------------------
# p6: watcher-error fail-closed, no handoff bytes
# ---------------------------------------------------------------------------
class _Boom(ContentSource):
    """Readable at registration, exploding at use time: register_skill
    refuses an unreadable skill outright, so the fail-closed path must
    be exercised with a source that goes bad after pinning."""
    def __init__(self, data):
        self._data = data
        self._armed = False

    def read_bytes(self):
        if self._armed:
            raise IOError("boom")
        self._armed = True
        return self._data

    def stat_hint(self):
        return None


def _p6():
    tmpdir = tempfile.mkdtemp(prefix="f184-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    w = SkillWatch()
    w.register_skill("broken", _Boom(V1), origin=_TEST_ORIGIN)
    ex, ident, log = _make_executor(
        run_dir, w, {"read_file": "broken"})
    target = Path(tmpdir) / "notes.txt"
    target.write_text("hello")
    import os as _os
    cwd = _os.getcwd()
    try:
        _os.chdir(tmpdir)
        r = ex.call(ident, "read_file", path="notes.txt")
    finally:
        _os.chdir(cwd)
    if r.get("status") != "denied":
        return "BREAK", "watcher-error call not denied: %r" % (r.get("status"),)
    get = getattr(ex, "verified_skill_bytes", None)
    if get is not None and get("broken") is not None:
        return "BREAK", "handoff bytes present after watcher error"
    return ("HELD", "watcher-error denies fail-closed; slot cleared")


# ---------------------------------------------------------------------------
# p7: handoff slot hygiene
# ---------------------------------------------------------------------------
def _p7():
    ex, ident, log, skill_path, _w = _fresh_run_case(
        {"read_file": "weather"})
    target = Path(skill_path).parent / "notes.txt"
    target.write_text("hello")
    r = ex.call(ident, "read_file", path="notes.txt")
    if r.get("status") != "executed":
        return "ERROR", "setup call did not execute"
    get = getattr(ex, "verified_skill_bytes", None)
    if get is None:
        return "EXPECTED", "no handoff accessor (pre-fix tree)"
    if get("weather") != V1:
        return "BREAK", "handoff missing right after verified call"
    if get("other-skill") is not None:
        return "BREAK", "handoff returned for mismatched skill id"
    # A later call for an unattributed tool must reset the slot.
    ex2_tmp = tempfile.mkdtemp(prefix="f184-", dir=TMP_BASE)
    run2 = Path(ex2_tmp) / "run"
    run2.mkdir()
    w2 = SkillWatch()
    w2.register_skill("weather", FileContentSource(skill_path),
                      origin=_file_origin(skill_path))
    ex2, ident2, _ = _make_executor(run2, w2, {})
    (Path(ex2_tmp) / "notes.txt").write_text("hello")
    import os as _os
    cwd = _os.getcwd()
    try:
        _os.chdir(ex2_tmp)
        r2 = ex2.call(ident2, "read_file", path="notes.txt")
    finally:
        _os.chdir(cwd)
    if r2.get("status") != "executed":
        return "ERROR", "second setup call did not execute"
    if ex2.verified_skill_bytes("weather") is not None:
        return ("BREAK",
                "stale handoff survived an unattributed call")
    return ("HELD",
            "slot is per-call: id mismatch -> None, later call resets")


# ---------------------------------------------------------------------------
# p8: single-read preserved (wiring adds no extra source read)
# ---------------------------------------------------------------------------
class _Counting(ContentSource):
    def __init__(self, data):
        self._data = data
        self.reads = 0

    def read_bytes(self):
        self.reads += 1
        return self._data

    def stat_hint(self):
        return None


def _p8():
    tmpdir = tempfile.mkdtemp(prefix="f184-", dir=TMP_BASE)
    run_dir = Path(tmpdir) / "run"
    run_dir.mkdir()
    src = _Counting(V1)
    w = SkillWatch()
    w.register_skill("weather", src, origin=_TEST_ORIGIN)
    src.reads = 0  # registration read is not the use-time seam
    ex, ident, _log = _make_executor(run_dir, w, {"read_file": "weather"})
    (Path(tmpdir) / "notes.txt").write_text("hello")
    import os as _os
    cwd = _os.getcwd()
    try:
        _os.chdir(tmpdir)
        r = ex.call(ident, "read_file", path="notes.txt")
    finally:
        _os.chdir(cwd)
    if r.get("status") != "executed":
        return "ERROR", "setup call did not execute"
    if src.reads != 1:
        return ("BREAK",
                "wiring added source reads: %d reads for one call "
                "(equivocation surface)" % src.reads)
    return ("HELD", "exactly one source read per verified call")


# ---------------------------------------------------------------------------
# p9: the call site exists (the e6 flip condition)
# ---------------------------------------------------------------------------
def _p9():
    root = Path(__file__).resolve().parent.parent
    target = root / "gov" / "executor.py"
    grep = subprocess.run(
        ["grep", "-n", "fetch_verified_at_use", str(target)],
        capture_output=True, text=True)
    real = [ln for ln in grep.stdout.splitlines()
            if "fetch_verified_at_use(" in ln
            and "fetch_verified_at_use`" not in ln
            and ln.strip().startswith("#") is False
            and "def verified_skill_bytes" not in ln
            and '"""' not in ln and "'''" not in ln]
    # Exclude docstring prose lines: a real call site is code, i.e.
    # the line contains an assignment/call, not a comment or string.
    code_hits = [ln for ln in real if not ln.split(":", 1)[1].strip().startswith("#")]
    if not code_hits:
        return ("BREAK",
                "no non-docstring fetch_verified_at_use call in "
                "gov/executor.py — seam still unwired")
    return ("HELD",
            "executor consumes the handoff: %s"
            % "; ".join(h.strip() for h in code_hits[:2]))


_PROBES = [
    ("p1", "V2 window closed end-to-end (red-first)", _p1),
    ("p2", "attested digest audit-chained", _p2),
    ("p3", "mutated-before-call denies, no handoff", _p3),
    ("p4", "unregistered-no-pin denies", _p4),
    ("p5", "unattributed tool unaffected", _p5),
    ("p6", "watcher-error fail-closed", _p6),
    ("p7", "handoff slot hygiene", _p7),
    ("p8", "single-read preserved", _p8),
    ("p9", "call site exists in executor", _p9),
]


def main():
    held = brk = expected = err = 0
    for pid, title, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - probe harness
            verdict, detail = "ERROR", "%s: %s" % (
                type(e).__name__, str(e)[:160])
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            brk += 1
        elif verdict == "EXPECTED":
            expected += 1
        else:
            err += 1
        print("%s %-42s %s — %s" % (pid, title, verdict, detail))
    print("score: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, expected, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
