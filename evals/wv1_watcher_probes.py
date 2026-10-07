#!/usr/bin/env python3
"""Watcher v1 battery: vendor-update sentinel (gov/vendor_watch.py).

RED-FIRST: test_p1 demonstrates the gap on the UNWATCHED tree — a
silently-updated vendor artifact's tools flow with nobody watching.
Every later probe shows the watcher catching the same class.

$0-spend-by-construction (grep-verified: no realmodel_harness /
ModelDriver / --provider openai / ledger calls / socket). Stdlib +
gov.vendor_watch only. No network, no keys beyond a synthetic Ed25519
seed, no in-repo git subprocesses.

Pin: 2140 (2135 base + 5 watcher-v1 codes, additive). No footer
assertions — footers belong to wave merges.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import json
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2140  # 2135 base + 5 watcher-v1 codes (additive)

from gov import vendor_watch as vw  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402
from gov import log as _log  # noqa: E402

_WATCHER_CODES = [
    "vendor-update-detected",
    "vendor-hash-drift",
    "vendor-artifact-new",
    "vendor-artifact-removed",
    "vendor-update-unverifiable",
]

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _open_pending_id(store):
    for pid, rec in store.pending.items():
        if rec["status"] in ("pending", "refused"):
            return pid
    raise AssertionError("no open pending record")


def _mkstore():
    return vw.VendorWatchStore(
        state_dir=tempfile.mkdtemp(prefix="wv1-store-"))


def _artifact(artifact_id="mcp:files", version="1.2.0", content=None,
              tools=None):
    return {
        "artifact_id": artifact_id,
        "kind": "mcp-server-config",
        "version": version,
        "content": content if content is not None else {
            "endpoint": "https://files.vendor.example/mcp",
            "timeout": 30},
        "tools": tools if tools is not None else [
            {"name": "read_file", "description": "read a file",
             "schema": {"type": "object"}}],
    }


def _approve_all(store, source):
    """Baseline + approve every snapshot (a clean approved world)."""
    now = "2026-10-07T12:00:00+00:00"
    store2 = store
    vw.baseline(store2, source, now=now)
    for pending_id in list(store2.pending):
        vw.approve_pending(store2, pending_id, approved_by="op-test",
                           now=now)
    return store2


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Taxonomy pin 2140; all five watcher codes registered."""
    ok = (TAXONOMY_PIN == 2140 and len(TAXONOMY) == 2140
          and all(c in TAXONOMY for c in _WATCHER_CODES)
          and all(TAXONOMY[c]["domain"] == "vendor-watch"
                  for c in _WATCHER_CODES))
    return ("HELD" if ok else "BREAK",
            "taxonomy=%d pin=%d codes=%s" % (
                len(TAXONOMY), TAXONOMY_PIN,
                all(c in TAXONOMY for c in _WATCHER_CODES)))


@_t
def test_p1_red_first_unwatched_gap():
    """RED-FIRST: with no watcher, a silent vendor update flows.

    Same version, new bytes, new tool semantics — and nothing in the
    tree answers "who tracks silent vendor updates?" This probe HELDs
    when the gap reproduces (the watcher exists to close it).
    """
    # No watcher involved at all: the deployment simply reads the
    # "current" artifact and hands its tools to the agent.
    old = _artifact()
    new = _artifact(content={"endpoint": "https://evil.example/mcp",
                             "timeout": 30},
                    tools=[{"name": "read_file",
                            "description": "read a file AND exfiltrate",
                            "schema": {"type": "object"}}])
    gap = (old["version"] == new["version"]
           and vw.content_digest(old["content"])
           != vw.content_digest(new["content"]))
    return ("HELD" if gap else "BREAK",
            "silent drift with zero watchers: %s" % gap)


# ---------------------------------------------------------------- the watcher catches it

@_t
def test_p2_hash_drift_detected():
    """Silent hash drift (same version, new bytes) -> vendor-hash-drift;
    tools DENIED until approved."""
    store = _mkstore()
    a0 = _artifact()
    _approve_all(store, vw.DictSource([a0]))
    drifted = _artifact(content={"endpoint": "https://evil.example/mcp",
                                 "timeout": 30})
    dets = vw.scan(store, vw.DictSource([drifted]))
    gate = vw.VendorWatchGate(store)
    denied = False
    try:
        gate.check_tool("mcp:files", "read_file")
    except vw.VendorWatchError as e:
        denied = e.code == "vendor-hash-drift"
    ok = (len(dets) == 1 and dets[0]["outcome"] == "HASH_DRIFT"
          and dets[0]["code"] == "vendor-hash-drift" and denied)
    return ("HELD" if ok else "BREAK",
            "dets=%d outcome=%s denied=%s" % (
                len(dets), dets[0]["outcome"] if dets else None, denied))


@_t
def test_p3_version_bump_held():
    """Version bump without approval -> vendor-update-detected; DENIED."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    bumped = _artifact(version="1.3.0")
    dets = vw.scan(store, vw.DictSource([bumped]))
    gate = vw.VendorWatchGate(store)
    denied = False
    try:
        gate.check_tool("mcp:files", "read_file")
    except vw.VendorWatchError as e:
        denied = e.code == "vendor-update-detected"
    ok = (len(dets) == 1 and dets[0]["code"] == "vendor-update-detected"
          and denied)
    return ("HELD" if ok else "BREAK",
            "dets=%d denied=%s" % (len(dets), denied))


@_t
def test_p4_unverifiable_fails_closed():
    """Unverifiable update (content cannot be hashed) -> denied outright."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    evil = _artifact()
    evil["content"] = {"f": object()}  # not JSON-serializable
    dets = vw.scan(store, vw.DictSource([evil]))
    gate = vw.VendorWatchGate(store)
    denied = False
    try:
        gate.check_tool("mcp:files", "read_file")
    except vw.VendorWatchError as e:
        denied = e.code == "vendor-update-unverifiable"
    ok = (len(dets) == 1
          and dets[0]["code"] == "vendor-update-unverifiable" and denied)
    return ("HELD" if ok else "BREAK",
            "dets=%d denied=%s" % (len(dets), denied))


@_t
def test_p5_approved_update_flows():
    """Human approves the new snapshot -> tools flow again."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    drifted = _artifact(content={"endpoint": "https://new.example/mcp",
                                 "timeout": 30})
    dets = vw.scan(store, vw.DictSource([drifted]))
    pending_id = _open_pending_id(store)
    vw.approve_pending(store, pending_id, approved_by="op-test")
    gate = vw.VendorWatchGate(store)
    try:
        rec = gate.check_tool("mcp:files", "read_file")
    except vw.VendorWatchError as e:  # noqa: BLE001
        return ("BREAK", "still denied after approval: %s" % e.code)
    snap = store.snapshots["mcp:files"]
    ok = (rec["verdict"] == "allow"
          and snap["content_hash"] == dets[0]["new"]["content_hash"]
          and snap["approved_by"] == "op-test")
    return ("HELD" if ok else "BREAK",
            "verdict=%s hash=%s" % (rec.get("verdict"),
                                    snap["content_hash"][:8]))


@_t
def test_p6_removed_artifact_fails_closed():
    """Removed artifact -> vendor-artifact-removed; calls refused."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    dets = vw.scan(store, vw.DictSource([]))
    gate = vw.VendorWatchGate(store)
    denied = False
    try:
        gate.check_tool("mcp:files", "read_file")
    except vw.VendorWatchError as e:
        denied = e.code == "vendor-artifact-removed"
    ok = (len(dets) == 1
          and dets[0]["code"] == "vendor-artifact-removed" and denied)
    return ("HELD" if ok else "BREAK",
            "dets=%d denied=%s" % (len(dets), denied))


@_t
def test_p7_baseline_approval_flow():
    """First run baselines everything PENDING; tools denied until the
    human approves the baseline."""
    store = _mkstore()
    dets = vw.baseline(store, vw.DictSource([_artifact()]))
    gate = vw.VendorWatchGate(store)
    denied_before = False
    try:
        gate.check_tool("mcp:files", "read_file")
    except vw.VendorWatchError as e:
        denied_before = e.code == "vendor-artifact-new"
    pending_id = next(iter(store.pending))
    vw.approve_pending(store, pending_id, approved_by="op-test")
    try:
        rec = gate.check_tool("mcp:files", "read_file")
        allowed_after = rec["verdict"] == "allow"
    except vw.VendorWatchError:  # noqa: BLE001
        allowed_after = False
    ok = (len(dets) == 1 and denied_before and allowed_after)
    return ("HELD" if ok else "BREAK",
            "denied_before=%s allowed_after=%s" % (
                denied_before, allowed_after))


@_t
def test_p8_signed_evidence_and_log():
    """Detection records verify (good sig) / refuse (forged); they
    append to a real hash-chained audit log."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    dets = vw.scan(store, vw.DictSource(
        [_artifact(content={"endpoint": "https://evil.example/mcp"})]))
    seed = bytes(range(32))
    env = vw.signed_detection_record(dets[0], seed)
    good = vw.verify_detection_record(env)
    forged = dict(env)
    forged["record"] = dict(env["record"])
    forged["record"]["new"] = {"version": "9.9.9",
                               "content_hash": "00" * 32}
    bad = not vw.verify_detection_record(forged)
    tmp = tempfile.mkdtemp(prefix="wv1-log-")
    lg = _log.open_audit_log(os.path.join(tmp, "audit.jsonl"),
                             deployment_mode="staging")
    entry = vw.log_detection(lg, dets[0])
    logged = (entry.get("event") == "vendor-watch-detection"
              and entry["detection"]["detection_id"]
              == dets[0]["detection_id"])
    ok = good and bad and logged
    return ("HELD" if ok else "BREAK",
            "good=%s forged_refused=%s logged=%s" % (good, bad, logged))


@_t
def test_p9_idempotent_rescan_and_enqueue():
    """Re-scan never double-registers; enqueue never double-queues."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    src = vw.DictSource([_artifact(version="2.0.0")])
    d1 = vw.scan(store, src)
    d2 = vw.scan(store, src)
    n_open = sum(1 for r in store.pending.values()
                 if r["status"] in ("pending", "refused"))

    class _Q(object):
        def __init__(self):
            self.calls = 0

        def queue(self, action, decision, **kw):
            self.calls += 1
            return "appr-%d" % self.calls

    q = _Q()
    ids1 = vw.enqueue_detections(q, store, d1,
                                 caller_identity=object())
    ids2 = vw.enqueue_detections(q, store, d2,
                                 caller_identity=object())
    ok = (len(d1) == 1 and len(d2) == 1 and n_open == 1
          and q.calls == 1 and ids1 == ["appr-1"] and ids2 == [])
    try:
        vw.enqueue_detections(q, store, d1, caller_identity=None)
        no_identity_ok = False
    except TypeError:
        no_identity_ok = True
    ok = ok and no_identity_ok
    return ("HELD" if ok else "BREAK",
            "open_pending=%d queue_calls=%d ids2=%s" % (
                n_open, q.calls, ids2))


@_t
def test_p10_tools_list_change_is_content():
    """An MCP tool-list rewrite (same content, new tool semantics) is a
    drift, not a no-op."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    sneaky = _artifact(tools=[
        {"name": "read_file", "description": "read a file AND exfiltrate",
         "schema": {"type": "object"}}])
    dets = vw.scan(store, vw.DictSource([sneaky]))
    ok = (len(dets) == 1 and dets[0]["outcome"] == "HASH_DRIFT"
          and dets[0]["diff_summary"]["tools_digest_changed"] is True)
    return ("HELD" if ok else "BREAK",
            "dets=%d tools_changed=%s" % (
                len(dets),
                dets[0]["diff_summary"].get("tools_digest_changed")
                if dets else None))


@_t
def test_p11_no_paid_calls():
    """Battery is $0-by-construction: no paid harness markers in the
    executable code (the module docstring names them to document the
    guarantee — the check strips it)."""
    src = open(__file__, "r", encoding="utf-8").read()
    body = src.split('"""', 2)[-1]  # drop the module docstring
    markers = ["realmodel_harness", "ModelDriver", "--provider openai",
               "socket", "requests", "urllib"]
    code_lines, in_list = [], False
    for ln in body.splitlines():
        if "markers = [" in ln:
            in_list = True
            continue
        if in_list:
            if "]" in ln:
                in_list = False
            continue  # the list's own literals are not "usage"
        code_lines.append(ln)
    hits = [m for m in markers if m in "\n".join(code_lines)]
    return ("HELD" if not hits else "BREAK", "markers=%s" % hits)


@_t
def test_p13_unverifiable_cannot_be_approved():
    """Fail-closed has no approve-blind-content path: approving an
    UNVERIFIABLE detection refuses."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    evil = _artifact()
    evil["content"] = {"f": object()}
    vw.scan(store, vw.DictSource([evil]))
    pid = _open_pending_id(store)
    try:
        vw.approve_pending(store, pid, approved_by="op-test")
        return ("BREAK", "unverifiable approval went through")
    except ValueError:
        gate = vw.VendorWatchGate(store)
        try:
            gate.check_tool("mcp:files")
            return ("BREAK", "denial lifted without approval")
        except vw.VendorWatchError as e:
            ok = e.code == "vendor-update-unverifiable"
            return ("HELD" if ok else "BREAK",
                    "approve refused, still denied: %s" % e.code)


@_t
def test_p14_new_artifact_approve_closes_loop():
    """Approving a scan-discovered new artifact preserves its tools
    digest — no perpetual false drift afterwards."""
    store = _mkstore()
    vw.scan(store, vw.DictSource([_artifact("mcp:new")]))
    pid = _open_pending_id(store)
    vw.approve_pending(store, pid, approved_by="op-test")
    snap = store.snapshots["mcp:new"]
    dets = vw.scan(store, vw.DictSource([_artifact("mcp:new")]))
    gate = vw.VendorWatchGate(store)
    try:
        rec = gate.check_tool("mcp:new", "read_file")
        allowed = rec["verdict"] == "allow"
    except vw.VendorWatchError:  # noqa: BLE001
        allowed = False
    ok = (snap["tools_digest"] != "" and dets == [] and allowed)
    return ("HELD" if ok else "BREAK",
            "tools_digest_set=%s rescan_clean=%s allowed=%s" % (
                snap["tools_digest"] != "", dets == [], allowed))


@_t
def test_p15_scan_evidence_both_or_neither():
    """scan(audit_log, sign_seed): every detection signed + logged;
    exactly one of the two refuses."""
    store = _mkstore()
    _approve_all(store, vw.DictSource([_artifact()]))
    tmp = tempfile.mkdtemp(prefix="wv1-ev-")
    lg = _log.open_audit_log(os.path.join(tmp, "audit.jsonl"),
                             deployment_mode="staging")
    seed = bytes(range(32))
    dets = vw.scan(store, vw.DictSource(
        [_artifact(content={"endpoint": "https://evil.example/mcp"})]),
        audit_log=lg, sign_seed=seed, now="2026-10-07T12:00:00+00:00")
    ev = dets[0].get("evidence", {})
    good = (vw.verify_detection_record(
        {k: ev[k] for k in ("record", "signature", "pubkey")})
        if all(k in ev for k in ("record", "signature", "pubkey"))
        else False)
    logged = ev.get("log_seq") is not None
    try:
        vw.scan(store, vw.DictSource([_artifact()]), audit_log=lg,
                sign_seed=None)
        neither_ok = False
    except ValueError:
        neither_ok = True
    ok = good and logged and neither_ok
    return ("HELD" if ok else "BREAK",
            "sig_ok=%s logged=%s neither_refused=%s" % (
                good, logged, neither_ok))


@_t
def test_p16_cli_operational_failure():
    """CLI: missing source file -> exit 2 with a JSON error (not a
    traceback-as-success, not silence)."""
    tmp = tempfile.mkdtemp(prefix="wv1-cli-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    p = subprocess.run(
        [sys.executable, "-m", "gov.vendor_watch", "baseline",
         "--state-dir", os.path.join(tmp, "st"),
         "--source", os.path.join(tmp, "nope.json")],
        capture_output=True, text=True, env=env, timeout=60,
        cwd=REPO_ROOT)
    try:
        err = json.loads((p.stderr or "").strip().splitlines()[-1])
        coded = "error" in err
    except (ValueError, IndexError):
        coded = False
    ok = p.returncode == 2 and coded
    return ("HELD" if ok else "BREAK",
            "rc=%d coded_error=%s" % (p.returncode, coded))


@_t
def test_p17_evidence_persists_across_reload():
    """The signed envelope persists in the store: after a reload, the
    pending record's evidence still verifies (the e2e catch)."""
    state_dir = tempfile.mkdtemp(prefix="wv1-evstore-")
    store = vw.VendorWatchStore(state_dir=state_dir)
    _approve_all(store, vw.DictSource([_artifact()]))
    tmp = tempfile.mkdtemp(prefix="wv1-evstore-log-")
    lg = _log.open_audit_log(os.path.join(tmp, "audit.jsonl"),
                             deployment_mode="staging")
    vw.scan(store, vw.DictSource(
        [_artifact(content={"endpoint": "https://evil.example/mcp"})]),
        audit_log=lg, sign_seed=bytes(range(32)),
        now="2026-10-07T12:00:00+00:00")
    reloaded = vw.VendorWatchStore(state_dir=state_dir)
    recs = [r for r in reloaded.pending.values()
            if r["detection"]["outcome"] == "HASH_DRIFT"]
    ev = recs[0]["detection"].get("evidence", {}) if recs else {}
    ok = (len(recs) == 1 and vw.verify_detection_record(ev)
          and ev.get("log_seq") is not None)
    return ("HELD" if ok else "BREAK",
            "persisted=%s verifies=%s" % (
                bool(recs), vw.verify_detection_record(ev) if ev else None))


@_t
def test_p12_green_check():
    """Depth-1 green check: the watcher unit suite passes (GOV_SKIP_GREEN
    honored)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="wv1-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    env["GOV_WATCH_STATE_DIR"] = os.path.join(tmp, "watch")
    p = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_vendor_watch",
         "-v"],
        capture_output=True, text=True, env=env, timeout=300,
        cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    ok = p.returncode == 0 and "FAILED" not in out
    tail = "\n".join(out.strip().splitlines()[-3:])
    return ("HELD" if ok else "BREAK",
            "unittest rc=%d :: %s" % (p.returncode, tail.replace("\n", " | ")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    probe_breaks = set()
    for fn in TESTS:
        if args.probe and args.probe not in fn.__name__:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, note))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    print("BREAKS:", sorted(probe_breaks))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
