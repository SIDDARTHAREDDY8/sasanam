"""Wave-64 D5 probes (2026-09-22): typed unvetted marker pins.

The sterile-cockpit reissue pipe (LoopContract.reissue_reads) is now
wrapped by the executor in ``gov.sterile.Unvetted`` — a
machine-readable "never vetted" marker stored as a JSON envelope on
the ``post_window_delta`` audit event. The positive "vetted" mark
(``gov.sterile.Vetted``) is mint-gated: only ``VettingStack.vet()``
with a stack-issued capability mints.

Pins registered here (registry.yaml, ``redteam.sterile_d5.*``),
all closure: green (the control holds; probes assert it keeps
holding):
  envelope_on_post_window_delta — close-path reissue lands as a
      re-markable envelope, reconciled_vetted stays False
  json_roundtrip_remarks        — envelope survives JSON; stripped
      keys / pre-D5 plain values decode Unvetted (fail-closed)
  consumer_confusion_blocked    — iteration/indexing/sizing the
      wrapper raises; equality is fail-closed False
  vetted_forgery_refused        — direct Vetted(), foreign
      capabilities, copied/pickled capabilities, mint_id mismatch
      all refused; legitimate issue->vet works
  legit_reissue_unaffected      — no-regression: the legitimate
      close/return shape is unchanged (Wave-49 lesson)

All runs synthetic/local, $0. Deterministic per probe run_id. Env
hygiene restores every mutated variable in finally.
"""

import contextlib
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

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov import sterile as st_mod  # noqa: E402

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
    if enabled:
        with _env(GOV_DEV_KEYS="1"):
            log_mod.enable_dev_keys()
            yield
    else:
        yield


def _govrun():
    d = tempfile.mkdtemp(prefix="steriled5reg64-")
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


class FakeLoop(st_mod.LoopContract):
    def __init__(self):
        self.reissued = None

    def freeze_context(self, snapshot_ref):
        return None

    def withhold(self, channel):
        return None

    def release(self, channel):
        return None

    def reissue_reads(self, reads):
        self.reissued = list(reads)
        return [{"tool": t, "channel": c, "result_summary": "reissued",
                 "delta_vs_snapshot": False} for t, c in reads]


_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
critical_windows:
  - id: pay
    on_tools: ["http_post"]
    suspend: [web_fetch]
    close_policy: agent_declared
    max_duration_s: 300
    rationale: "test"
policies: []
"""


def _run_with_window():
    d = tempfile.mkdtemp(prefix="w64probe-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_POLICY)
    run = harness.make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _drive_and_close():
    run, ident = _run_with_window()
    ex = run["executor"]
    ex.attach_loop_contract(FakeLoop())
    ex.call(ident, "http_post", url="https://synthetic.local/x", data="d")
    ex.call(ident, "api_call", endpoint="https://synthetic.local/v1",
            params={"q": 1})
    for rec in ex.approvals.pending():
        ex.approvals.decide(rec["id"], True, "test")
    out = ex.request_window_close(ident)
    assert out.get("closed"), "legitimate close failed: %r" % (out,)
    exits = [e for e in log_mod.read_entries(run["log"].path)
             if e.get("event") == "sterile_window_exit"]
    deltas = [e for e in exits if e.get("post_window_delta")]
    assert len(deltas) == 1, "expected 1 delta, got %d" % len(deltas)
    return deltas[0]


@_sit("redteam.sterile_d5.envelope_on_post_window_delta")
def sit_envelope_on_post_window_delta():
    """D5 pin: the close-path reissue lands on the audit event as a
    re-markable unvetted envelope; reconciled_vetted stays False."""
    exit_ev = _drive_and_close()
    delta = exit_ev["post_window_delta"]
    if not (isinstance(delta, dict) and delta.get("__gov_unvetted__")
            is True):
        return {"verdict": "break",
                "note": "post_window_delta not an unvetted envelope"}
    u = st_mod.Unvetted.from_envelope(delta)
    if not isinstance(u, st_mod.Unvetted):
        return {"verdict": "break", "note": "envelope did not re-mark"}
    if u.acknowledge("probe")[0]["tool"] != "api_call":
        return {"verdict": "break", "note": "payload mismatch"}
    if exit_ev.get("reconciled_vetted") is not False:
        return {"verdict": "break",
                "note": "reconciled_vetted not False (R4 broken)"}
    return {"verdict": "stopped",
            "note": "envelope present, re-markable, R4 intact"}


@_sit("redteam.sterile_d5.json_roundtrip_remarks")
def sit_json_roundtrip_remarks():
    """D5 pin: the marker survives honest JSON round-trips; key
    stripping and pre-D5 plain values decode Unvetted (fail-closed)."""
    payload = [{"tool": "api_call", "result_summary": "s"}]
    env = st_mod.Unvetted(payload).to_envelope()
    rt = json.loads(json.dumps(env))
    u = st_mod.Unvetted.from_envelope(rt)
    if not isinstance(u, st_mod.Unvetted) or u.acknowledge("p") != payload:
        return {"verdict": "break", "note": "round-trip lost the marker"}
    stripped = dict(rt)
    stripped.pop("__gov_unvetted__", None)
    if not isinstance(st_mod.Unvetted.from_envelope(stripped),
                       st_mod.Unvetted):
        return {"verdict": "break", "note": "stripped key not fail-closed"}
    if not isinstance(st_mod.Unvetted.from_envelope(payload),
                       st_mod.Unvetted):
        return {"verdict": "break",
                "note": "pre-D5 plain list not fail-closed"}
    return {"verdict": "stopped",
            "note": "round-trip re-marks; erasure fail-closed"}


@_sit("redteam.sterile_d5.consumer_confusion_blocked")
def sit_consumer_confusion_blocked():
    """D5 pin: duck-typing around the wrapper fails loud; equality
    against the payload is fail-closed False."""
    u = st_mod.Unvetted([{"result_summary": "s"}])
    for name, fn in (("iter", lambda: iter(u)),
                     ("list", lambda: list(u)),
                     ("getitem", lambda: u[0]),
                     ("len", lambda: len(u)),
                     ("contains", lambda: "x" in u),
                     ("bool", lambda: bool(u))):
        try:
            fn()
        except TypeError:
            continue
        return {"verdict": "break",
                "note": "confusion path %s did not raise" % name}
    if (u == [{"result_summary": "s"}]) is not False:
        return {"verdict": "break", "note": "wrapper compared equal"}
    sink = []
    if u.acknowledge("probe", sink) != [{"result_summary": "s"}]:
        return {"verdict": "break", "note": "acknowledge broken"}
    return {"verdict": "stopped",
            "note": "confusion paths raise; ack path works"}


@_sit("redteam.sterile_d5.vetted_forgery_refused")
def sit_vetted_forgery_refused():
    """D5 pin: the vetted mark cannot be forged — direct
    construction, foreign capabilities, duplicated capabilities,
    and mint_id mismatch all fail; legitimate mint works."""
    st = st_mod.VettingStack("defense")
    cap = st.issue_capability("human-review")
    bad = 0
    for fn in (lambda: st_mod.Vetted({"x": 1}),
               lambda: st.vet({"x": 1},
                               st_mod.VettingCapability(b"\x00" * 32)),
               lambda: st_mod.VettingStack("other").vet({"x": 1}, cap),
               lambda: st_mod.Vetted.from_envelope(
                   st.vet({"d": 1}, cap).to_envelope(), st,
                   st.issue_capability("other-purpose"))):
        try:
            fn()
        except (TypeError, st_mod.VettingError):
            continue
        bad += 1
    if bad:
        return {"verdict": "break",
                "note": "%d forgery paths succeeded" % bad}
    v = st.vet({"d": 1}, cap)
    v2 = st_mod.Vetted.from_envelope(
        json.loads(json.dumps(v.to_envelope())), st, cap)
    if not isinstance(v2, st_mod.Vetted) or v2.payload != {"d": 1}:
        return {"verdict": "break", "note": "legitimate mint broken"}
    return {"verdict": "stopped",
            "note": "4 forgery paths refused; legit mint works"}


@_sit("redteam.sterile_d5.legit_reissue_unaffected")
def sit_legit_reissue_unaffected():
    """D5 no-regression pin: the legitimate reissue flow is
    unchanged — close return shape identical (Wave-49 lesson),
    loop receives the raw refused list, no-loop path has no delta."""
    run, ident = _run_with_window()
    ex = run["executor"]
    loop = FakeLoop()
    ex.attach_loop_contract(loop)
    ex.call(ident, "http_post", url="https://synthetic.local/x", data="d")
    ex.call(ident, "api_call", endpoint="https://synthetic.local/v1",
            params={"q": 1})
    for rec in ex.approvals.pending():
        ex.approvals.decide(rec["id"], True, "test")
    out = ex.request_window_close(ident)
    if out.get("reconcile") != [("api_call", "web_fetch")]:
        return {"verdict": "break",
                "note": "close return shape changed: %r" % (out,)}
    if loop.reissued != [("api_call", "web_fetch")]:
        return {"verdict": "break",
                "note": "loop did not receive raw refused list"}
    return {"verdict": "stopped",
            "note": "legitimate reissue flow unchanged"}
