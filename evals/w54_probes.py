"""Wave-54 RT21 probes (2026-09-22): sterile-cockpit break-first pins.

Break-first (``/tmp/w54_rt21_breakfirst.py``): 24 probes — 17 HOLD,
0 MISS, 2 RESIDUAL, 5 BOUNDARY. One genuine miss found and hardened
same-wave: **F124** — a human_approval window-close approval was not
consumed on use, so an approved close approval could be re-presented
to close a NEW entry of the same window id with no fresh human
decision (probe rt21.c2). Fix: single-use consumption — the record is
flagged ``window_close_consumed`` and re-MACed on successful close
(F38/F57 pattern); a second presentation fails closed in
``_verify_close_approval``. RT21 a6 also hardened (audit-only): a loop
contract attached while windows are open now emits
``loop_contract_attached_with_windows_open``.

Pins registered here (registry.yaml, ``redteam.rt21.*``):
  fix-verified (closure: green, "stopped" expected):
    close_approval_replay_stopped, close_approval_consumed_bound,
    fresh_approval_per_entry, failed_close_no_burn, late_attach_audited
  documented asymmetries (closure: residual-accepted, "break" is the
  documented steady state; "stopped" is a strict improvement and is
  reported distinctly by the gate):
    expiry_pending_approval_asymmetry, human_close_pending_asymmetry

Pure boundary re-probes (silent-loop no-op trust, contract re-attach
routing, poisoned reissue auditing, no detach API, static taxonomy)
are documented in workstreams/evals/RT21_REPORT.md, not the registry.

All runs synthetic/local, $0. Deterministic per probe run_id. Env
hygiene restores every mutated variable in finally.
"""

import contextlib
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

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.approvals import approval_digest_ok  # noqa: E402
from gov.sterile import LoopContract  # noqa: E402

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit test-key provisioning.

    Replaces the deleted gov.log dev-key opt-in. With enabled=True,
    yields with an explicit random GOV_LOG_KEY/GOV_LOG_KEY_EPOCH set
    and GOV_LOG_KEY_ARCHIVE cleared, restoring everything afterwards.
    enabled=False is a plain passthrough (no key provisioned).
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
        for _n in _saved:
            if _had[_n]:
                os.environ[_n] = _saved[_n]
            else:
                os.environ.pop(_n, None)
def _govrun():
    d = tempfile.mkdtemp(prefix="rt21reg-")
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = d
    tempfile.tempdir = d
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached

_govrun = contextlib.contextmanager(_govrun)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    with _dev_keys(True):
                        detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


_POLICY_TMPL = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
critical_windows:
%s
policies: []
"""


def _window_block(**kw):
    lines = ["  - id: %s" % kw.get("id", "pay")]
    lines.append('    on_tools: [%s]' % ", ".join(
        '"%s"' % p for p in kw.get("on_tools", ["http_post"])))
    lines.append("    suspend: [%s]" % ", ".join(
        kw.get("suspend", ["web_fetch"])))
    lines.append("    close_policy: %s" % kw.get("close_policy",
                                                "agent_declared"))
    lines.append("    max_duration_s: %s" % kw.get("max_duration_s", 300))
    lines.append('    rationale: "%s"' % kw.get("rationale", "test"))
    return "\n".join(lines)


def _run_with_windows(multi=None, **kw):
    with open(REPO_ROOT / "policies" / "default.yaml") as f:
        base = f.read()
    blocks = "\n".join(_window_block(**w) for w in (multi or [kw]))
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="govw54reg-")
    with os.fdopen(fd, "w") as f:
        f.write(base + "\ncritical_windows:\n" + blocks + "\n")
    run = harness.make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _events(run, name):
    return [e for e in run["read_log"]() if e.get("event") == name]


def _approve_close(run, ident):
    ex = run["executor"]
    q = ex.request_window_close(ident)
    assert q.get("status") == "queued", q
    aid = q["approval_id"]
    ex.approvals.decide(aid, True, "looks done")
    return aid


def _stop_if(cond, note):
    return {"verdict": "stopped" if cond else "break", "note": note}


class FakeLoop(LoopContract):
    def freeze_context(self, snapshot_ref):
        return None

    def withhold(self, channel):
        return None

    def release(self, channel):
        return None

    def reissue_reads(self, reads):
        return []


# ------------------------------------------------------------------
# RT21: F124 fix-verified pins (closure: green)
# ------------------------------------------------------------------

@_sit("redteam.rt21.close_approval_replay_stopped")
def sit_close_approval_replay_stopped():
    """F124: a consumed close approval cannot close a NEW window entry.

    Approved close approval closes entry 1; the same approval id
    re-presented for entry 2 (same window id, same run, within TTL)
    must be denied ("already used"), and the window stays open.
    """
    run, ident = _run_with_windows(close_policy="human_approval")
    ex = run["executor"]
    ex.call(ident, "http_post", url="https://synthetic.local/x",
            data="d")
    aid = _approve_close(run, ident)
    out1 = ex.request_window_close(ident, approval_id=aid)
    assert out1.get("closed"), out1
    ex.call(ident, "http_post", url="https://synthetic.local/z",
            data="d2")
    assert ex.sterile.open_windows() == ["pay"]
    out2 = ex.request_window_close(ident, approval_id=aid)
    held = (not out2.get("closed")
            and "already used" in out2.get("reason", "")
            and ex.sterile.open_windows() == ["pay"])
    return _stop_if(held,
                    "replay denied=%s reason=%r windows=%s"
                    % (not out2.get("closed"), out2.get("reason"),
                       ex.sterile.open_windows()))


@_sit("redteam.rt21.close_approval_consumed_bound")
def sit_close_approval_consumed_bound():
    """F124: the consumed flag is MAC-bound and consumption is audited.

    After a close, the record carries window_close_consumed=True, the
    re-MAC verifies, flipping the flag without the key breaks the
    digest, and a window_close_approval_consumed audit exists.
    """
    run, ident = _run_with_windows(close_policy="human_approval")
    ex = run["executor"]
    ex.call(ident, "http_post", url="https://synthetic.local/x",
            data="d")
    aid = _approve_close(run, ident)
    ex.request_window_close(ident, approval_id=aid)
    rec = ex.approvals.get(aid)
    audited = any(e.get("approval_id") == aid
                  for e in _events(run, "window_close_approval_consumed"))

    def _flip(records):
        for r in records:
            if r["id"] == aid:
                r["window_close_consumed"] = False
        return records
    ex.approvals._rewrite(_flip)
    flipped_breaks = not approval_digest_ok(ex.approvals.get(aid))
    held = (bool(rec.get("window_close_consumed"))
            and approval_digest_ok(rec) and audited and flipped_breaks)
    return _stop_if(held,
                    "consumed=%s remac_ok=%s audited=%s flip_breaks=%s"
                    % (rec.get("window_close_consumed"),
                       approval_digest_ok(rec), audited, flipped_breaks))


@_sit("redteam.rt21.fresh_approval_per_entry")
def sit_fresh_approval_per_entry():
    """F124: the fix does not break the legitimate flow — two window
    entries, two separate human approvals, both close."""
    run, ident = _run_with_windows(close_policy="human_approval")
    ex = run["executor"]
    ex.call(ident, "http_post", url="https://synthetic.local/x",
            data="d")
    aid1 = _approve_close(run, ident)
    ok1 = ex.request_window_close(ident, approval_id=aid1).get("closed")
    ex.call(ident, "http_post", url="https://synthetic.local/z",
            data="d2")
    aid2 = _approve_close(run, ident)
    ok2 = ex.request_window_close(ident, approval_id=aid2).get("closed")
    held = ok1 and ok2 and aid1 != aid2 and not ex.sterile.open_windows()
    return _stop_if(held, "entry1_closed=%s entry2_closed=%s" % (ok1, ok2))


@_sit("redteam.rt21.failed_close_no_burn")
def sit_failed_close_no_burn():
    """F124: a denied close presentation does not consume the approval
    — the same approval still closes the right window afterwards."""
    run, ident = _run_with_windows(multi=[
        {"id": "pay", "on_tools": ["http_post"],
         "suspend": ["web_fetch"], "close_policy": "human_approval",
         "rationale": "p"},
        {"id": "pay2", "on_tools": ["send_email"],
         "suspend": ["web_fetch"], "close_policy": "human_approval",
         "rationale": "p2"},
    ])
    ex = run["executor"]
    ex.call(ident, "http_post", url="https://synthetic.local/x",
            data="d")
    aid = _approve_close(run, ident)
    bad = ex.request_window_close(ident, window_id="other",
                                  approval_id=aid)
    not_burned = (not bad.get("closed")
                  and not ex.approvals.get(aid).get(
                      "window_close_consumed"))
    out = ex.request_window_close(ident, window_id="pay",
                                  approval_id=aid)
    held = not_burned and out.get("closed")
    return _stop_if(held, "wrong_window_denied=%s then_closed=%s"
                    % (not bad.get("closed"), out.get("closed")))


@_sit("redteam.rt21.late_attach_audited")
def sit_late_attach_audited():
    """RT21 a6: attaching the loop contract while a window is open
    audits loop_contract_attached_with_windows_open (the open window
    is NOT retro-engaged)."""
    run, ident = _run_with_windows()
    ex = run["executor"]
    ex.call(ident, "http_post", url="https://synthetic.local/x",
            data="d")
    ex.attach_loop_contract(FakeLoop())
    evs = _events(run, "loop_contract_attached_with_windows_open")
    held = len(evs) == 1 and evs[0].get("windows") == ["pay"]
    return _stop_if(held, "late-attach audits=%d" % len(evs))


# ------------------------------------------------------------------
# RT21: documented asymmetries (closure: residual-accepted)
# ------------------------------------------------------------------

@_sit("redteam.rt21.expiry_pending_approval_asymmetry")
def sit_expiry_pending_approval_asymmetry():
    """RT21 b1: expiry does NOT run the §3.2 pending-approval check
    (agent_declared close does). The pending approval stays pending —
    no auto-decision — and the window exits task:incomplete. That
    asymmetry is the documented steady state (break); if expiry ever
    starts refusing on pending approvals, this flips to stopped and
    the lead reclassifies."""
    run, ident = _run_with_windows(
        multi=[{"id": "pay", "on_tools": ["http_post"],
                "suspend": ["web_fetch"], "max_duration_s": 60,
                "rationale": "t"}])
    ex = run["executor"]
    ex.call(ident, "http_post", url="https://synthetic.local/x",
            data="d")
    pend_before = {r["id"] for r in ex.approvals.pending()}
    ex.sterile_tick(t=10 ** 12)
    pend_after = {r["id"] for r in ex.approvals.pending()}
    exits = [e for e in _events(run, "sterile_window_exit")
             if e.get("reason") == "expired"]
    asymmetry_holds = (bool(exits)
                       and exits[0].get("task") == "incomplete"
                       and pend_before <= pend_after)
    # "break" = documented steady state; "stopped" = strict improvement
    return {"verdict": "break" if asymmetry_holds else "stopped",
            "note": "expiry ignores pending approvals; they stay "
                    "pending (no auto-decision), window incomplete"}


@_sit("redteam.rt21.human_close_pending_asymmetry")
def sit_human_close_pending_asymmetry():
    """RT21 c7: the §3.2 pending-approval check applies to
    agent_declared close only. A human_approval close succeeds while
    a consequential in-window approval is still pending — the pending
    approval still needs its own human decision (no auto-execution),
    so this is an asymmetry, not a bypass. Documented steady state
    (break); a future check would flip this to stopped."""
    run, ident = _run_with_windows(close_policy="human_approval")
    ex = run["executor"]
    ex.call(ident, "http_post", url="https://synthetic.local/x",
            data="d")
    # Queue the close and approve it, leaving the trigger call's own
    # approval pending (queued by the default policy for http_post).
    ex = run["executor"]
    q = ex.request_window_close(ident)
    aid = q["approval_id"]
    ex.approvals.decide(aid, True, "close ok")
    out = ex.request_window_close(ident, approval_id=aid)
    pend = [r["id"] for r in ex.approvals.pending()]
    asymmetry_holds = bool(out.get("closed")) and bool(pend)
    return {"verdict": "break" if asymmetry_holds else "stopped",
            "note": "human close succeeded with %d in-window "
                    "approval(s) still pending (still need their own "
                    "decision)" % len(pend)}
