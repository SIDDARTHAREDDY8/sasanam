#!/usr/bin/env python3
"""Wave-120 (F-RA3) closure battery: escaping read_file is fail-closed.

Red pin (WAVE-117/H2): ``read_file`` with an escaping ``..`` path
executed with synthetic content returned -- loud (chained
``sandbox_traversal_contained``) since H2, but the agent received
fabricated data as the real file.

Green (WAVE-120): the policy queues the escaping read
(``quarantine-outside-reads``, mirroring the write side); even an
approved execution refuses with NO content returned (neither real
outside bytes nor synthetic); the chained
``sandbox_traversal_contained`` event still fires exactly once; benign
in-sandbox reads (real file and missing file) are unchanged and
quiet.

Run:
    mkdir -p /tmp/gov-fra3
    TMPDIR=/tmp/gov-fra3 ~/workspace/.gov-venv/bin/python evals/fra3_read_traversal.py

$0 spend, synthetic/local only, no network.
"""

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "fra3-h2-probe")

_TMP = os.environ.get("TMPDIR", "/tmp") + "/gov-fra3"
Path(_TMP).mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = _TMP
tempfile.tempdir = None

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402

RESULTS = []


def _traversal_events(entries, agent_id=None):
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "sandbox_traversal_contained":
            continue
        if agent_id is not None and e.get("agent_id") != agent_id:
            continue
        out.append(e)
    return out


def p1_traversal_read_is_fail_closed():
    """read_file '../plan.txt' -> queued, then refused on approval, loud."""
    ctx = make_run()
    ident = ctx["executor"].mint_identity("fra3-agent", "coder",
                                          "fra3-principal")
    outside = Path(ctx["run_dir"]).parent / "plan.txt"
    res = ctx["executor"].call(ident, "read_file", path="../plan.txt",
                               justification="wave-120 probe")
    # 1. Fail-closed at the policy seam: queued, nothing returned.
    queued = (res.get("status") == "queued"
              and "result" not in res)
    untouched = not outside.exists()
    # 2. The quarantine is loud at the queue seam (even if the
    # approval is denied and _simulate never runs).
    events_at_queue = _traversal_events(ctx["read_log"](),
                                        agent_id="fra3-agent")
    loud_at_queue = len(events_at_queue) == 1
    # 3. Even approved, the execution refuses with no content, and no
    # second event is emitted (exactly-once).
    refused = False
    if queued and res.get("approval_id"):
        ctx["approvals"].decide(res["approval_id"], True,
                                "wave-120 probe", "test-operator")
        executed = ctx["executor"].execute_approved()
        summaries = [e.get("result_summary", "")
                     for e in ctx["read_log"]()
                     if isinstance(e, dict)
                     and e.get("decision") == "approved_executed"]
        refused = (len(executed) == 1 and len(summaries) == 1
                   and "refused=True" in summaries[0])
    events = _traversal_events(ctx["read_log"](), agent_id="fra3-agent")
    loud = len(events) == 1
    note = ("queued=%s untouched=%s loud_at_queue=%s refused=%s "
            "traversal_events=%d"
            % (queued, untouched, loud_at_queue, refused, len(events)))
    if queued and untouched and loud_at_queue and refused and loud:
        return ("GREEN", note)
    return ("RED", note + " <- fail-closed closure broken!")


def p2_benign_read_stays_quiet():
    """In-sandbox read -> NO sandbox_traversal_contained events (regression)."""
    ctx = make_run()
    ident = ctx["executor"].mint_identity("fra3-benign", "coder",
                                          "fra3-principal")
    inside = Path(ctx["executor"]._sandbox_resolved) / "notes.txt"
    inside.write_text("hello", encoding="utf-8")
    res = ctx["executor"].call(ident, "read_file", path="notes.txt",
                               justification="h2 probe")
    got = res.get("result", {}).get("content")
    events = _traversal_events(ctx["read_log"](), agent_id="fra3-benign")
    quiet = len(events) == 0
    note = ("read_back=%r traversal_events=%d"
            % (got, len(events)))
    return ("GREEN" if (got == "hello" and quiet) else "RED",
            note + ("" if quiet else " <- noise on benign read!"))


def p3_missing_in_sandbox_read_stays_quiet():
    """Missing in-sandbox read -> quiet, synthetic, unchanged."""
    ctx = make_run()
    ident = ctx["executor"].mint_identity("fra3-missing", "coder",
                                          "fra3-principal")
    res = ctx["executor"].call(ident, "read_file",
                               path="does-not-exist.txt",
                               justification="wave-120 probe")
    result = res.get("result", {})
    ok = (res.get("status") == "executed"
          and result.get("content") == "[synthetic file contents]")
    events = _traversal_events(ctx["read_log"](), agent_id="fra3-missing")
    quiet = len(events) == 0
    note = ("synthetic=%s traversal_events=%d" % (ok, len(events)))
    return ("GREEN" if (ok and quiet) else "RED",
            note + ("" if quiet else " <- noise on missing read!"))


def main():
    for name, fn in (("p1_traversal_read_is_fail_closed",
                      p1_traversal_read_is_fail_closed),
                     ("p2_benign_read_stays_quiet",
                      p2_benign_read_stays_quiet),
                     ("p3_missing_in_sandbox_read_stays_quiet",
                      p3_missing_in_sandbox_read_stays_quiet)):
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 - probe must report, not crash
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        RESULTS.append((name, verdict, note))
        print("%s %s: %s" % (verdict, name, note))
    reds = [r for r in RESULTS if r[1] != "GREEN"]
    print("\n%d/%d green" % (len(RESULTS) - len(reds), len(RESULTS)))
    return 0 if not reds else 1


if __name__ == "__main__":
    sys.exit(main())
