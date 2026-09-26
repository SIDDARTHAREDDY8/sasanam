#!/usr/bin/env python3
"""H2 (F-RA3) red-first probe: read-side traversal containment must be LOUD.

Red pin (TODAY): ``read_file`` with an escaping ``..`` path is
sandbox-contained silently — synthetic content returned, zero audit
entries that name the containment (no chained
``sandbox_traversal_contained`` event).

Green (AFTER): containment still holds (synthetic content, no real
outside path touched) AND a chained ``sandbox_traversal_contained``
event is emitted; benign in-sandbox reads emit no such event
(regression guard).

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


def p1_traversal_read_is_loud():
    """read_file '../plan.txt' -> contained AND chained event emitted."""
    ctx = make_run()
    ident = ctx["executor"].mint_identity("fra3-agent", "coder",
                                          "fra3-principal")
    outside = Path(ctx["run_dir"]).parent / "plan.txt"
    res = ctx["executor"].call(ident, "read_file", path="../plan.txt",
                               justification="h2 probe")
    result = res.get("result", {})
    contained = (res.get("status") == "executed"
                 and result.get("content") == "[synthetic file contents]")
    untouched = not outside.exists()
    events = _traversal_events(ctx["read_log"](), agent_id="fra3-agent")
    loud = len(events) >= 1
    note = ("contained=%s untouched=%s traversal_events=%d"
            % (contained, untouched, len(events)))
    if contained and untouched and loud:
        return ("GREEN", note)
    if contained and untouched and not loud:
        return ("RED", note + " <- silent containment (F-RA3)")
    return ("RED", note + " <- containment broken!")


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


def main():
    for name, fn in (("p1_traversal_read_is_loud", p1_traversal_read_is_loud),
                     ("p2_benign_read_stays_quiet",
                      p2_benign_read_stays_quiet)):
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
