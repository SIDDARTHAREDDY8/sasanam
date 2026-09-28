#!/usr/bin/env python3
"""Wave-174 lane 2: display≡execution assertion battery (OpenClaw CVE-2026-32065).

The 32065 shape: the approval surface shows the human a trimmed/normalized
rendering while the executor acts on the raw untrimmed bytes. The product
invariant: at the approved sweep, the stored MAC-bound ``preview`` (what the
human saw) must equal the preview re-derived from the exact args about to
execute, under the same normalization (``gov.approvals.
verify_display_execution_preview`` -- one shared seam, one normalizer).
Mismatch refuses fail-closed as ``display_execution_mismatch`` before any
side effect.

Probes:
  trimmed_display_refuses  -- OpenClaw shape: preview hides the payload
                              tail; approve + sweep must refuse and the
                              bytes must never land.
  exact_match_passes       -- executor-built preview; approve + sweep
                              executes normally.
  whitespace_edge_refuses  -- preview differs by trailing whitespace only;
                              refuses (documents the rule: printable
                              whitespace is NOT trimmed/collapsed -- it is
                              meaningful, because the executor acts on the
                              raw bytes).
  preview_mac_tamper       -- rewriting the stored preview breaks the F34
                              keyed digest first; refuses as
                              approval_integrity_violation (layering: the
                              MAC catches tampering, the display check
                              catches semantic mismatch on intact records).
  determinism              -- the whole battery runs twice in-process;
                              verdicts must agree.

Deterministic; synthetic/local only; $0.
"""

import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "display-exec-battery")

REPO_ROOT = str(Path(__file__).resolve().parents[1])
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402

APPROVAL_RULE = """
  - id: require-approval-display-exec-writes
    description: Test seam -- display/execution battery writes need a human.
    effect: require_approval
    match:
      tool: [write_file]
      path_contains_any: [display-exec-target]
    reason: Test seam for the display/execution battery.
"""

VISIBLE_HEAD = "VISIBLE-HEAD-INVOICE-DRAFT"
HIDDEN_TAIL = "HIDDEN-TAIL-EXFILTRATE-LEDGER"

_records = []


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


def _policy():
    src = Path(REPO_ROOT, "policies", "default.yaml").read_text()
    src = src.replace("max_identical_calls: 10",
                      "max_identical_calls: 100000")
    src = src.replace("max_writes_per_run: 50",
                      "max_writes_per_run: 100000")
    path = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]), "policy.yaml")
    path.write_text(src.rstrip() + "\n" + APPROVAL_RULE + "\n")
    return str(path)


def _setup(tag):
    ctx = make_run(policy_path=_policy())
    ident = ctx["executor"].mint_identity("display-exec-%s" % tag, "coder",
                                         "display-exec-p")
    return ctx, ident


def _refusals(ctx, flag=None):
    out = [e for e in ctx["read_log"]()
           if isinstance(e, dict)
           and e.get("event") == "approval_execution_refused"]
    if flag is not None:
        out = [e for e in out if e.get("flag") == flag]
    return out


def _queue_direct(ctx, ident, tool, args, preview):
    return ctx["approvals"].queue(
        {"tool": tool, "args": args,
         "identity": ident.as_dict(),
         "agent_justification": "display/execution battery",
         "redactions": []},
        PolicyDecision("require_approval", "battery write",
                       policy_id="battery", flag="battery"),
        "agent_direct", preview,
        policy_hash=ctx["executor"].policy.policy_hash,
        caller_identity=ident)


def _approve_and_sweep(ctx, aid):
    ctx["approvals"].decide(aid, True, reason="looks fine",
                           decided_by="human-operator")
    done = ctx["executor"].execute_approved()
    return [d for d in done if isinstance(d, dict)]


def p_trimmed_display_refuses():
    """OpenClaw 32065 shape: trimmed preview hides the tail -> refuse."""
    name = "trimmed_display_refuses"
    ctx, ident = _setup("trim")
    target = str(Path(ctx["executor"].sandbox) / "display-exec-target-a.txt")
    full = VISIBLE_HEAD + "\n" + HIDDEN_TAIL
    trimmed = "would write file with content %r..." % VISIBLE_HEAD
    aid = _queue_direct(ctx, ident, "write_file",
                        {"path": target, "content": full}, trimmed)
    rec = ctx["approvals"].get(aid)
    if HIDDEN_TAIL in (rec.get("preview") or ""):
        return "ERROR", "setup broken: tail leaked into the preview"
    executed = _approve_and_sweep(ctx, aid)
    refusals = _refusals(ctx, flag="display_execution_mismatch")
    landed = Path(target).read_text() if Path(target).exists() else ""
    ok = (len(refusals) == 1 and not executed
          and HIDDEN_TAIL not in landed)
    return ("PASS" if ok else "FAIL",
            "refusals=%d executed=%d tail_landed=%s"
            % (len(refusals), len(executed), HIDDEN_TAIL in landed))


def p_exact_match_passes():
    """Executor-built preview; approve + sweep executes normally."""
    name = "exact_match_passes"
    ctx, ident = _setup("exact")
    target = str(Path(ctx["executor"].sandbox) / "display-exec-target-b.txt")
    r = ctx["executor"].call(ident, "write_file", path=target,
                            content="exact-bytes")
    if r.get("status") != "queued" or not r.get("approval_id"):
        return "ERROR", "call did not queue: %r" % (r,)
    executed = _approve_and_sweep(ctx, r["approval_id"])
    refusals = _refusals(ctx, flag="display_execution_mismatch")
    ok = (len(executed) == 1 and not refusals
          and Path(target).exists())
    return ("PASS" if ok else "FAIL",
            "executed=%d mismatch_refusals=%d file_exists=%s"
            % (len(executed), len(refusals), Path(target).exists()))


def p_whitespace_edge_refuses():
    """Whitespace-only preview difference -> refuse (documented rule)."""
    name = "whitespace_edge_refuses"
    ctx, ident = _setup("ws")
    target = str(Path(ctx["executor"].sandbox) / "display-exec-target-c.txt")
    # Build the faithful preview first, then add trailing whitespace the
    # human never meaningfully saw: printable whitespace is NOT
    # trimmed/collapsed by the normalizer, so this is a mismatch.
    faithful = ctx["executor"]._preview(
        "write_file", {"path": target, "content": "ws-bytes"})
    from gov.approvals import sanitize_preview_text
    stored_preview = sanitize_preview_text(faithful) + "   \n  "
    aid = _queue_direct(ctx, ident, "write_file",
                        {"path": target, "content": "ws-bytes"},
                        stored_preview)
    executed = _approve_and_sweep(ctx, aid)
    refusals = _refusals(ctx, flag="display_execution_mismatch")
    ok = (len(refusals) == 1 and not executed
          and not Path(target).exists())
    return ("PASS" if ok else "FAIL",
            "refusals=%d executed=%d (whitespace is meaningful: the "
            "normalizer only escapes non-printables)" % (len(refusals),
                                                        len(executed)))


def p_preview_mac_tamper():
    """Rewriting the stored preview breaks the F34 digest -> refuse."""
    name = "preview_mac_tamper"
    ctx, ident = _setup("tamper")
    target = str(Path(ctx["executor"].sandbox) / "display-exec-target-d.txt")
    r = ctx["executor"].call(ident, "write_file", path=target,
                            content="tamper-bytes")
    if r.get("status") != "queued" or not r.get("approval_id"):
        return "ERROR", "call did not queue: %r" % (r,)
    aid = r["approval_id"]
    ctx["approvals"].decide(aid, True, reason="looks fine",
                           decided_by="human-operator")
    # Tamper with the stored preview behind the MAC's back, AFTER the
    # human decided (decide-time integrity would already have refused).
    ctx["approvals"]._rewrite(lambda records: [
        dict(rec, preview=(rec.get("preview") or "") + " [tampered]")
        if rec["id"] == aid else rec for rec in records])
    done = ctx["executor"].execute_approved()
    executed = [d for d in done if isinstance(d, dict)]
    refusals = _refusals(ctx, flag="approval_integrity_violation")
    ok = (len(refusals) == 1 and not executed
          and not Path(target).exists())
    return ("PASS" if ok else "FAIL",
            "integrity_refusals=%d executed=%d (MAC layer catches "
            "tampering before the display check)" % (len(refusals),
                                                    len(executed)))


PROBES = [
    ("trimmed_display_refuses", p_trimmed_display_refuses, "PASS"),
    ("exact_match_passes", p_exact_match_passes, "PASS"),
    ("whitespace_edge_refuses", p_whitespace_edge_refuses, "PASS"),
    ("preview_mac_tamper", p_preview_mac_tamper, "PASS"),
]

ADJACENT_UNIT_TESTS = [
    "tests.test_ceremony_timing",
    "tests.test_approvals_d1",
]


def f_green():
    name = "f_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record(name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "standalone for full depth-1 adjacency")
        return
    if "TMPDIR" not in os.environ:
        _record(name, "FAIL", "TMPDIR not set (AGENTS.md lesson: Python "
                "ignores a nonexistent TMPDIR)")
        return
    failures = []
    for i, mod in enumerate(ADJACENT_UNIT_TESTS):
        tmp = os.path.join(os.environ["TMPDIR"], "de-ut-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "unittest", mod],
                capture_output=True, text=True, env=env, cwd=REPO_ROOT,
                timeout=600)
        except Exception as exc:
            failures.append("%s -> %s" % (mod, exc))
            continue
        if proc.returncode != 0:
            tail = proc.stderr.strip().splitlines()
            tail = tail[-1] if tail else ""
            failures.append("%s -> rc=%d (%s)" % (mod, proc.returncode,
                                                 tail))
    if failures:
        _record(name, "FAIL", "; ".join(failures))
    else:
        _record(name, "PASS",
                "adjacent unit suites green (depth-1, GOV_SKIP_GREEN=1 "
                "in children)")


def main():
    if "TMPDIR" not in os.environ:
        print("TMPDIR not set; refusing to run (AGENTS.md lesson)")
        return 2
    results = []
    for name, fn, expect in PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = "ERROR", "raised %r" % (exc,)
        results.append((name, verdict, expect, detail))
        print("[%s] %s (expect %s)\n      %s" % (verdict, name, expect,
                                                detail))
    # Twice in-process; the outcomes must agree (determinism probe).
    results2 = []
    for name, fn, expect in PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001
            verdict, detail = "ERROR", "raised %r" % (exc,)
        results2.append((name, verdict))
    agree = all(a[1] == b[1] for a, b in zip(results, results2))
    print("in-process repeat agreement: %s" % agree)
    f_green()
    for name, verdict, detail in _records:
        print("[%s] %s\n      %s" % (verdict, name, detail))
    mism = [(n, v, e) for n, v, e, _ in results if v != e]
    green_bad = [r for r in _records if r[1] not in ("PASS", "HELD")]
    if mism:
        print("MISMATCHES: %s" % mism)
    if green_bad:
        print("GREEN-CHECK ISSUES: %s" % green_bad)
    ok = agree and not mism and not green_bad
    print("BATTERY: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
