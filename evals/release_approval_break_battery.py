"""Break-first battery: pre-release approval / licensing primitive.

Run this against the UNMODIFIED tree first (RED), then again after
implementing gov/release_approval.py (GREEN). Each probe attempts an
attack on the release ceremony; the verdicts are:

* BREAK — the attack succeeded (bad; the tree does not stop it)
* HELD  — the attack was refused (good)
* ERROR — the probe itself failed to run

Probes:
  P1  ship with a FORGED approval (approval record that never passed
      the queue) -> must be refused
  P2  ship with an approval for a DIFFERENT digest (approval minted for
      release A, presented for release B) -> must be refused
  P3  ship with a REPLAYED approval from an older release (candidate
      changed since) -> must be refused
  P4  ship with a SINGLE approver when the quorum is 2 -> must be refused
  C1  CONTROL: a legitimately quorum-approved release ships and verifies
      (proves the gate does not just refuse everything)

Honest residual (also in the spec and the module docstring): this
governs OUR release process (ceremony + evidence before ship). It is
NOT a DRM that stops someone copying the code and shipping without the
ceremony. Under the public development log key, the keyed record MAC is
forgeable by anyone who read the docs (the same F34 residual as the
rest of the approval system); production needs a real log key.
"""

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _env()+_dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

# The harness deliberately exercises the raw pre-wave-74/75 pipeline via a
# declared ungoverned_ack; that declaration is refused in production mode.
# This battery is synthetic, not production — pin staging like every other
# eval battery (cf. evals/b1sept_probes.py, evals/f142_break.py).
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import harness  # noqa: E402

import contextlib  # noqa: E402


@contextlib.contextmanager
def _env(**kw):
    saved = {k: os.environ.get(k) for k in kw}
    try:
        for k, v in kw.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Per-probe random dev log key (restored afterwards).

    Wave-81 removed the dev key from gov/ entirely: no key, no chain.
    The battery is synthetic — each probe mints a fresh random key and
    restores the environment afterwards, like evals/b1exp_probes.py.
    """
    if not enabled:
        yield
        return
    import secrets as _secrets
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = _secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for n, v in _saved.items():
            if _had[n]:
                os.environ[n] = v
            else:
                os.environ.pop(n, None)


try:
    from gov import release_approval as ra  # noqa: E402
    HAS_GATE = True
except ImportError:
    ra = None
    HAS_GATE = False

ELIGIBLE = ["rel-alice", "rel-bob", "rel-carol"]


# ---------------------------------------------------------------------------
# fixture builders
# ---------------------------------------------------------------------------

def _make_candidate(tag, tamper=b""):
    """Build a synthetic release candidate: code tree + eval results + SAR."""
    root = Path(tempfile.mkdtemp(prefix="relcand-%s-" % tag))
    code = root / "code"
    code.mkdir()
    (code / "main.py").write_bytes(b"# release %s\nprint('hello')\n" % tag.encode())
    (code / "util.py").write_bytes(b"def f():\n    return %d\n" % len(tag) + tamper)
    evals = root / "eval_results.json"
    evals.write_text(json.dumps({"release": tag, "battery": "stratified_100",
                                 "pass": True, "score": 0.99}),
                     encoding="utf-8")
    sar = root / "sar.md"
    sar.write_text("# Safeguard Assessment Report\n\nRelease: %s\n\n"
                   "Verdict: PASS\n" % tag, encoding="utf-8")
    return root


def _harness_ctx():
    ctx = harness.make_run()
    return ctx


def _propose(ctx, cand, release_id, eligible=ELIGIBLE, min_approvals=2):
    queue = ctx["approvals"]
    executor = ctx["executor"]
    return ra.propose_release(
        queue, executor,
        code_dir=str(cand / "code"),
        eval_results_path=str(cand / "eval_results.json"),
        sar_path=str(cand / "sar.md"),
        release_id=release_id,
        eligible_principals=eligible,
        min_approvals=min_approvals,
    )


def _voter(ctx, principal):
    return ctx["executor"].mint_identity("voter-%s" % principal, "voter",
                                         principal)


def _vote(ctx, approval_id, principal, approve=True):
    queue = ctx["approvals"]
    return ra.record_release_vote(
        queue, approval_id, _voter(ctx, principal), approve,
        reason="release %s reviewed: evidence checked, digests match" % principal)


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def probe_forged_approval():
    """P1: ship with an approval record that never passed the queue."""
    cand = _make_candidate("p1")
    if not HAS_GATE:
        return ("BREAK", "no release gate exists in the tree: a hand-written "
                         "'approval' JSON is never consulted — the release "
                         "ships with zero ceremony")
    with _dev_keys(True):
        ctx = _harness_ctx()
        approval_id = _propose(ctx, cand, "rel-p1")
        forged_id = "forged01"
        # Forge: hand-build a record that LOOKS approved but never went
        # through queue()/cast_vote() — correct release digest (public
        # knowledge), plausible votes, but a garbage keyed MAC — and write
        # it straight into the queue store (attacker with filesystem write
        # access). verify_release must refuse it anyway.
        forged = {
            "id": forged_id,
            "tool": "ship_release",
            "status": "approved",
            "decision_mode": "quorum",
            "decided_by": "quorum:2-of-3",
            "decided_at": "2026-09-24T12:00:00+00:00",
            "digest_scheme": "hmac-sha256-v1",
            "args_digest": "0" * 64,
            "args": {"release_id": "rel-p1",
                     "release_digest": ra.release_digest(
                         ra.tree_digest(str(cand / "code")),
                         ra.sha256_file(str(cand / "eval_results.json")),
                         ra.sha256_file(str(cand / "sar.md")),
                         release_id="rel-p1")},
            "quorum": {"min_approvals": 2,
                       "eligible_principals": list(ELIGIBLE),
                       "deny_veto": True},
            "votes": [{"voter_principal": p, "approve": True,
                       "reason": "forged", "ts": "2026-09-24T00:00:00",
                       "vote_id": p, "nonce": "x"}
                      for p in ELIGIBLE[:2]],
            "egress_bytes": 0,
        }
        with open(Path(ctx["run_dir"]) / "approvals.jsonl", "a",
                   encoding="utf-8") as f:
            f.write(json.dumps(forged, ensure_ascii=True,
                               default=str) + "\n")
        ok, reason = ra.verify_release(
            queue=ctx["approvals"], approval_id=forged_id,
            code_dir=str(cand / "code"),
            eval_results_path=str(cand / "eval_results.json"),
            sar_path=str(cand / "sar.md"))
        if ok:
            return ("BREAK", "forged approval VERIFIED — forgery not "
                             "detected: %s" % reason)
        return ("HELD", "forged approval refused: %s" % reason)


def probe_wrong_digest_approval():
    """P2: approval minted for release A, presented for release B."""
    cand_a = _make_candidate("a")
    cand_b = _make_candidate("b")  # one byte different -> different digest
    if not HAS_GATE:
        return ("BREAK", "no release gate exists in the tree: approvals do "
                         "not bind a release digest, so an approval for "
                         "release A can be presented for release B and "
                         "nothing refuses")
    with _dev_keys(True):
        ctx = _harness_ctx()
        approval_id = _propose(ctx, cand_a, "rel-a")
        _vote(ctx, approval_id, ELIGIBLE[0])
        _vote(ctx, approval_id, ELIGIBLE[1])
        ok, reason = ra.verify_release(
            queue=ctx["approvals"], approval_id=approval_id,
            code_dir=str(cand_b / "code"),
            eval_results_path=str(cand_b / "eval_results.json"),
            sar_path=str(cand_b / "sar.md"))
        if ok:
            return ("BREAK", "approval for digest A verified against "
                             "candidate B — digest binding absent: %s"
                    % reason)
        return ("HELD", "cross-digest approval refused: %s" % reason)


def probe_replayed_approval():
    """P3: replay an older release's approval against a changed candidate."""
    cand_old = _make_candidate("old")
    if not HAS_GATE:
        return ("BREAK", "no release gate exists in the tree: an approval "
                         "from an older release binds nothing about the "
                         "current bits, so it can be replayed against a "
                         "changed candidate")
    with _dev_keys(True):
        ctx = _harness_ctx()
        approval_id = _propose(ctx, cand_old, "rel-old")
        _vote(ctx, approval_id, ELIGIBLE[0])
        _vote(ctx, approval_id, ELIGIBLE[1])
        # The release changes after approval (bit flip in the code tree).
        cand_new = _make_candidate("old", tamper=b"# backdoor\n")
        ok, reason = ra.verify_release(
            queue=ctx["approvals"], approval_id=approval_id,
            code_dir=str(cand_new / "code"),
            eval_results_path=str(cand_new / "eval_results.json"),
            sar_path=str(cand_new / "sar.md"))
    if ok:
        return ("BREAK", "replayed old approval verified against a CHANGED "
                         "candidate — replay not detected: %s" % reason)
    return ("HELD", "replayed approval refused: %s" % reason)


def probe_single_approver():
    """P4: only one approver votes when the quorum is 2."""
    cand = _make_candidate("p4")
    if not HAS_GATE:
        return ("BREAK", "no release gate exists in the tree: no quorum is "
                         "required anywhere — a single party (or zero) can "
                         "declare the release approved")
    with _dev_keys(True):
        ctx = _harness_ctx()
        approval_id = _propose(ctx, cand, "rel-p4")
        _vote(ctx, approval_id, ELIGIBLE[0])  # only ONE vote; quorum is 2
        ok, reason = ra.verify_release(
            queue=ctx["approvals"], approval_id=approval_id,
            code_dir=str(cand / "code"),
            eval_results_path=str(cand / "eval_results.json"),
            sar_path=str(cand / "sar.md"))
    if ok:
        return ("BREAK", "single-approver release VERIFIED against a "
                         "quorum-2 requirement: %s" % reason)
    return ("HELD", "single-approver release refused: %s" % reason)


def probe_control_legit_release():
    """C1: CONTROL — a properly quorum-approved release ships and verifies."""
    if not HAS_GATE:
        return ("ERROR", "control needs the gate (post-fix only)")
    with _dev_keys(True):
        cand = _make_candidate("control")
        ctx = _harness_ctx()
        approval_id = _propose(ctx, cand, "rel-control")
        _vote(ctx, approval_id, ELIGIBLE[0])
        rec, finalized = _vote(ctx, approval_id, ELIGIBLE[1])
        if not finalized or rec["status"] != "approved":
            return ("ERROR", "legit quorum did not finalize: %r"
                    % rec["status"])
        dest = Path(tempfile.mkdtemp(prefix="ship-"))
        try:
            shipped = ra.ship_release(
                queue=ctx["approvals"], approval_id=approval_id,
                code_dir=str(cand / "code"),
                eval_results_path=str(cand / "eval_results.json"),
                sar_path=str(cand / "sar.md"),
                dest_dir=str(dest))
        except Exception as e:  # noqa: BLE001
            return ("ERROR", "legit release failed to ship: %r" % e)
        if not (shipped / "code" / "main.py").exists():
            return ("ERROR", "shipped bundle missing expected files")
        return ("CONTROL", "legit 2-of-3 release shipped to %s and verified"
                % shipped)


PROBES = [
    ("P1_forged_approval", probe_forged_approval),
    ("P2_wrong_digest", probe_wrong_digest_approval),
    ("P3_replayed_approval", probe_replayed_approval),
    ("P4_single_approver", probe_single_approver),
    ("C1_control_legit", probe_control_legit_release),
]


def main():
    print("release-approval break battery — gate present: %s" % HAS_GATE)
    counts = {"BREAK": 0, "HELD": 0, "ERROR": 0, "CONTROL": 0}
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "probe raised: %r" % e
        counts[verdict] = counts.get(verdict, 0) + 1
        print("[%s] %s: %s" % (verdict, name, detail))
    print("counts: %d BREAK / %d HELD / %d ERROR / %d CONTROL"
          % (counts["BREAK"], counts["HELD"], counts["ERROR"],
             counts["CONTROL"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
