#!/usr/bin/env python3
"""GAP-5 candidate battery: continuous re-verification of use-time bindings.

Research-backed attack shapes (research/agent-attack-futures-2026-09-23.md,
"Wave proposal 5"):

1. MCPoison (Cursor): trust bound to the MCP server NAME; the server is
   swapped silently after approval. Same name, different server.
2. postmark-mcp: clean releases, then a malicious one -- the version
   label moves and nobody re-binds the approval to what changed.
3. Deadbugz: benign for the first N observations, hostile after -- the
   rug pull lands AFTER the pin.

What the product already has (verified by this battery, not assumed):
- skill_watch.check_at_use re-hashes the pinned CONTENT bytes on every
  use (stat prefilter, full re-hash on change) and verify_all always
  re-hashes; manifest mutations quarantine fail-closed.
- F142 Leg B binds referenced URLs inside the skill content.

The gap this battery demonstrates: the use-time check binds ONLY the
content digest (+ referenced URLs). It has NO observation of
(a) the MCP server's live wire identity -- attribution is by server
name, so a swapped server behind the same name passes; and
(b) the version label -- origin may carry one, but nothing verifies it.
A deployment that wants these bindings has no seam: ContentSource
exposes only read_bytes()/stat_hint().

Probes model a deployment whose ContentSource ALSO observes the live
wire (identity_bytes) and the version label (version_hint) -- the seam
the spec (docs/gap5-continuous-reverification-spec.md) adds. Pre-fix the
watcher ignores both observations, so every rug pull below executes.

Verdicts:
- BREAK = the rug pull executes: a swapped/unverifiable server identity
  or a drifted version passes the use-time check (or the re-pin ceremony
  approves bytes the wire no longer serves).
- HELD  = the watcher quarantines fail-closed (or the control is a
  pre-existing one, noted as baseline).
- ERROR = probe/instrumentation problem, not a verdict.

Probes:
  g1 BASELINE: manifest content swap post-approval -> check_at_use
     denies (pre-existing control) -> HELD.
  g2 MCPoison: wire identity X -> Y (same server name, content bytes
     unchanged) -> pre-fix check_at_use passes -> BREAK.
  g3 Version drift: pinned "1.0", wire reports "2.0", content unchanged
     -> pre-fix passes -> BREAK.
  g4 Dark wire: identity_bytes() raises (server stops answering
     identity) -> pre-fix passes -> BREAK.
  g5 Version unobservable: version_hint() -> None while a version is
     pinned -> pre-fix passes -> BREAK.
  g6 EXECUTOR LEVEL: g2 through ToolExecutor.call with mcp_server
     attribution -> pre-fix the swapped server's tool EXECUTES -> BREAK.
  g7 CONTROL: skill with no identity/version binding, manifest clean ->
     passes (opt-in bindings; absence is not failure) -> HELD.
  g8 CONTROL: governed recovery -- request_repin + approve_repin binding
     the fresh identity/version unquarantines and calls pass -> HELD.
  g9 Re-pin bait-and-switch: wire moves again between request_repin and
     approve_repin(new_identity_digest=Y) -> pre-fix the approval lands
     while the wire serves Z -> BREAK.

Deterministic. Synthetic/local only, no network.

Run: TMPDIR=/tmp/gov-gap5 ~/workspace/.gov-venv/bin/python evals/gap5_reverify_break.py
Also:  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-gap5 ~/workspace/.gov-venv/bin/python evals/gap5_reverify_break.py
"""

import hashlib
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "gap5-break")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-gap5")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import skill_watch  # noqa: E402
from gov.skill_watch import (  # noqa: E402
    SkillWatch, SkillWatchError, ContentSource)
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402

RESULTS = []

ORIGIN = {"registry_url": "https://registry.synthetic.local/mcp/svc",
          "installer_identity": "operator:alice",
          "installed_at": "2026-09-24T00:00:00+00:00",
          "version": "1.0"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def _identity_bytes(server_id, tools, instructions_sha):
    return json.dumps(
        {"server_id": server_id, "instructions_sha256": instructions_sha,
         "tools": tools}, sort_keys=True).encode()


IDENTITY_X = _identity_bytes("svc", [{"name": "notes_search"}], sha(b"i-x"))
IDENTITY_Y = _identity_bytes("svc", [{"name": "notes_search"},
                                     {"name": "notes_exfil"}],
                             sha(b"i-y"))
IDENTITY_Z = _identity_bytes("svc", [{"name": "notes_search"},
                                     {"name": "notes_ransom"}],
                             sha(b"i-z"))


class LiveSource(ContentSource):
    """Content + live wire identity + version observations.

    The deployment observes the MCP server through the governed adapter:
    read_bytes() is the approved artifact; identity_bytes() is the live
    wire identity; version_hint() is the live version label. Pre-fix the
    watcher ignores the latter two (no such seam); post-fix it binds them.
    """

    def __init__(self, content_box, wire):
        self._content_box = content_box
        self._wire = wire

    def read_bytes(self):
        return self._content_box["bytes"]

    def stat_hint(self):
        return None  # every check re-hashes; no mtime games in battery

    def identity_bytes(self):
        mode = self._wire.get("identity_mode", "ok")
        if mode == "raise":
            raise OSError("wire dark: server stopped answering identity")
        if mode == "none":
            return None
        return self._wire["identity"]

    def version_hint(self):
        return self._wire.get("version")


def _watch():
    return SkillWatch()


def _register(watch, skill_id="mcp/svc", content=b"approved artifact v1",
              identity=IDENTITY_X, version="1.0"):
    content_box = {"bytes": content}
    wire = {"identity": identity, "version": version}
    origin = dict(ORIGIN)
    if version is None:
        del origin["version"]
    watch.register_skill(skill_id, LiveSource(content_box, wire),
                         origin=origin)
    return content_box, wire


def _record(name, verdict, detail):
    RESULTS.append((name, verdict, detail))
    print("%-4s %-6s %s" % (name, verdict, detail))


# --------------------------------------------------------------------------
# g1: baseline -- manifest content swap (pre-existing control)
# --------------------------------------------------------------------------
def _g1():
    w = _watch()
    content_box, _wire = _register(w)
    content_box["bytes"] = b"MUTATED after approval"
    ok, detail = w.check_at_use("mcp/svc")
    if not ok and w.is_quarantined("mcp/svc"):
        return "HELD", "baseline: manifest swap quarantined (%s)" % detail
    return "BREAK", "manifest swap NOT caught: %s" % detail


# --------------------------------------------------------------------------
# g2: MCPoison -- same server name, swapped wire identity
# --------------------------------------------------------------------------
def _g2():
    w = _watch()
    _content_box, wire = _register(w)
    wire["identity"] = IDENTITY_Y  # server swapped behind the same name
    ok, detail = w.check_at_use("mcp/svc")
    if not ok and w.is_quarantined("mcp/svc"):
        return "HELD", "identity drift quarantined (%s)" % detail
    return ("BREAK",
            "swapped server identity passes use-time check (%s): "
            "the watcher never observes the wire" % detail)


# --------------------------------------------------------------------------
# g3: version drift, content unchanged
# --------------------------------------------------------------------------
def _g3():
    w = _watch()
    _content_box, wire = _register(w)
    wire["version"] = "2.0"  # postmark-mcp shape: version moved
    ok, detail = w.check_at_use("mcp/svc")
    if not ok and w.is_quarantined("mcp/svc"):
        return "HELD", "version drift quarantined (%s)" % detail
    return ("BREAK",
            "version 1.0 -> 2.0 passes use-time check (%s): "
            "the pinned version label is never verified" % detail)


# --------------------------------------------------------------------------
# g4: dark wire -- identity source raises
# --------------------------------------------------------------------------
def _g4():
    w = _watch()
    _content_box, wire = _register(w)
    wire["identity_mode"] = "raise"
    ok, detail = w.check_at_use("mcp/svc")
    if not ok and w.is_quarantined("mcp/svc"):
        return "HELD", "dark wire quarantined fail-closed (%s)" % detail
    return ("BREAK",
            "unverifiable server identity passes use-time check (%s)"
            % detail)


# --------------------------------------------------------------------------
# g5: version becomes unobservable while pinned
# --------------------------------------------------------------------------
def _g5():
    w = _watch()
    _content_box, wire = _register(w)
    wire["version"] = None
    ok, detail = w.check_at_use("mcp/svc")
    if not ok and w.is_quarantined("mcp/svc"):
        return "HELD", "unobservable pinned version quarantined (%s)" % detail
    return ("BREAK",
            "pinned version silently unobservable, check passes (%s)"
            % detail)


# --------------------------------------------------------------------------
# g6: executor level -- the swapped server's tool executes
# --------------------------------------------------------------------------
def _g6():
    run_dir = Path(tempfile.mkdtemp(prefix="gap5-g6-", dir="/tmp/gov-gap5"))
    run_dir.mkdir(exist_ok=True)
    policy = PolicyEngine(str(Path(REPO_ROOT) / "policies" / "default.yaml"))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    w = _watch()
    _content_box, wire = _register(w)
    ex = ToolExecutor(
        run_dir, policy, log, approvals,
        ledger_path=run_dir / "egress_ledger.jsonl",
        skill_watch=w, skill_mcp_map={"svc": "mcp/svc"},
        ungoverned_ack=("synthetic test: gap5 executor-level rug-pull "
                        "probe; the bypass is declared, not silent"))
    ident = ex.mint_identity("agent-1", "researcher", "tester")
    before = ex._executed.get("read_file", 0)
    wire["identity"] = IDENTITY_Y  # MCPoison: same name, new server
    r = ex.call(ident, "read_file", path="notes.txt", mcp_server="svc")
    if r.get("status") == "denied" and r.get("policy_id") == "skill-watch":
        return ("HELD",
                "executor denied the swapped server's call "
                "(skill-watch quarantine)")
    if ex._executed.get("read_file", 0) > before:
        return ("BREAK",
                "the swapped server's tool EXECUTED (status=%r): "
                "use-time check never saw the wire" % (r.get("status"),))
    return ("ERROR", "unexpected outcome: %r" % (r,))


# --------------------------------------------------------------------------
# g7: control -- unbound skill, clean manifest
# --------------------------------------------------------------------------
def _g7():
    w = _watch()
    content_box = {"bytes": b"plain skill, no wire"}
    wire = {"identity_mode": "none", "version": None}
    w.register_skill("plain", LiveSource(content_box, wire),
                     origin={k: v for k, v in ORIGIN.items()
                             if k != "version"})
    ok, detail = w.check_at_use("plain")
    if ok and not w.is_quarantined("plain"):
        return "HELD", "unbound skill passes on manifest check (%s)" % detail
    return "BREAK", "unbound skill wrongly denied: %s" % detail


# --------------------------------------------------------------------------
# g8: control -- governed recovery re-binds fresh identity/version
# --------------------------------------------------------------------------
def _g8():
    w = _watch()
    content_box, wire = _register(w)
    wire["identity"] = IDENTITY_Y
    wire["version"] = "2.0"
    req = w.request_repin("mcp/svc", operator="operator:alice")
    if not req:
        return "ERROR", "request_repin returned no request id"
    try:
        w.approve_repin("mcp/svc", {
            "operator": "operator:alice",
            "new_digest": sha(content_box["bytes"]),
            "new_identity_digest": sha(IDENTITY_Y),
            "new_version": "2.0",
            "reason": "reviewed: legitimate server upgrade to 2.0"})
    except SkillWatchError as e:
        return "BREAK", "legitimate re-pin refused: %s" % e
    ok, detail = w.check_at_use("mcp/svc")
    if ok and not w.is_quarantined("mcp/svc"):
        return "HELD", "re-bound identity/version passes (%s)" % detail
    return "BREAK", "re-pinned skill still denied: %s" % detail


# --------------------------------------------------------------------------
# g9: re-pin bait-and-switch -- wire moves between request and approve
# --------------------------------------------------------------------------
def _g9():
    w = _watch()
    content_box, wire = _register(w)
    wire["identity"] = IDENTITY_Y
    w.check_at_use("mcp/svc")  # drift quarantines (post-fix)
    w.request_repin("mcp/svc", operator="operator:alice")
    wire["identity"] = IDENTITY_Z  # attacker moves the wire under review
    try:
        w.approve_repin("mcp/svc", {
            "operator": "operator:alice",
            "new_digest": sha(content_box["bytes"]),
            "new_identity_digest": sha(IDENTITY_Y),  # reviewed Y...
            "reason": "reviewed identity Y"})
    except SkillWatchError as e:
        if w.is_quarantined("mcp/svc"):
            return ("HELD",
                    "stale identity approval refused, stays quarantined "
                    "(%s)" % str(e)[:120])
        return "ERROR", "refused but not quarantined: %s" % e
    # Approval landed while the wire serves Z != approved Y.
    if not w.is_quarantined("mcp/svc"):
        return ("BREAK",
                "re-pin approved identity Y while the wire serves Z: "
                "the approval did not bind the wire")
    return "ERROR", "approved yet quarantined (unexpected state)"


def main():
    probes = [("g1", _g1), ("g2", _g2), ("g3", _g3), ("g4", _g4),
              ("g5", _g5), ("g6", _g6), ("g7", _g7), ("g8", _g8),
              ("g9", _g9)]
    for name, fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- ERROR, not a verdict
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:200]))
        _record(name, verdict, detail)
    n_break = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    n_held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    n_err = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
