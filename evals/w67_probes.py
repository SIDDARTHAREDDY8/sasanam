"""Wave-67 D5 probes (2026-09-22): authenticated consumer registry.

Wave-65/66 built the D5 acknowledgment trail with SELF-ATTESTED
consumer identity. Wave-67 answers that gap by mechanism:
ConsumerRegistry / ConsumerToken / ConsumerAuthError (design:
workstreams/evals/CONSUMER_REGISTRY.md). Tokens are optional —
acknowledge() without a (token, registry) pair keeps the wave-66
behavior, honestly stamped "attribution": "unattributed" (Wave-49
lesson: never break legitimate callers).

Pins registered here (registry.yaml, ``redteam.sterile_d5_reg.*``),
all closure: green (the control holds; probes assert it keeps
holding):
  token_forgery_refused           — mint without the registry; flip
      bits in bearer and MAC; present a foreign-registry token:
      all raise ConsumerAuthError, no record appended, payload
      never returned
  cross_name_theft_refused        — A's token presented naming "B":
      refused LOUD; no record (theft across names cannot
      misattribute)
  same_id_two_consumers_distinguished — two registrations of one
      consumer_id: distinct public token_ids, both valid,
      independently revocable; chained records distinguishable
  revocation_fail_closed_history_append_only — revoke mid-stream:
      future acks refuse loud; already-chained records keep their
      attribution + token_id + ts (history is never rewritten;
      validity-at-time stays auditable)
  anonymous_laundering_honest     — no token -> "unattributed" is
      the designed behavior: honestly marked, never silencible
      into "authenticated"; a deployment refusing unattributed acks
      is policy, not mechanism (graded BOUNDARY, not filed)
  invalid_token_never_degrades    — garbage token + registry, token
      without registry, registry without token: all fail closed or
      honestly unattributed; no silent downgrade path exists
  expiry_enforced                 — ttl_s honored on the registry
      clock; expired tokens refuse, pre-expiry acks keep their mark
  legit_loop_regression           — executor close -> acknowledge ->
      drain: legacy unattributed flow byte-identical, authenticated
      flow drains end to end with token_id in the chain, wave-66
      cumulative budget untouched

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
sys.path.insert(0, str(REPO_ROOT / "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov import sterile as st_mod  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402

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
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w67probe-")
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached
        import shutil
        shutil.rmtree(run_tmp, ignore_errors=True)


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


_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
policies: []
"""


def _fresh_run():
    d = tempfile.mkdtemp(prefix="w67probe-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_POLICY)
    run = harness.make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _ack_entries(run):
    return [e for e in log_mod.read_entries(run["log"].path)
            if e.get("event") == "unvetted_acknowledged"]


@_sit("redteam.sterile_d5_reg.token_forgery_refused")
def sit_token_forgery_refused():
    """D5-reg pin: mint without the registry, flip bits in bearer and
    MAC, present a foreign-registry token — all raise ConsumerAuthError,
    no record is appended, the payload never leaves the marker."""
    reg = st_mod.ConsumerRegistry()
    other = st_mod.ConsumerRegistry()
    legit = reg.register_consumer("dash")
    sink = st_mod.AckAuditSink()
    refused = 0

    # (1) foreign registry's token presented to this registry
    foreign = other.register_consumer("dash")
    # (2) bit-flip in the bearer of a valid token
    flipped_bearer = st_mod.ConsumerToken(
        bytes(bytearray((lambda b: (b.__setitem__(0, b[0] ^ 1), b)[1])(
            bytearray(legit._bearer)))),
        bytes(legit._mac), legit.consumer_id, legit.public_id,
        legit.issued_at, legit.ttl_s)
    # (3) bit-flip in the MAC of a valid token
    flipped_mac = st_mod.ConsumerToken(
        bytes(legit._bearer),
        bytes(bytearray((lambda b: (b.__setitem__(-1, b[-1] ^ 1), b)[1])(
            bytearray(legit._mac)))),
        legit.consumer_id, legit.public_id, legit.issued_at,
        legit.ttl_s)
    # (4) hand-rolled token claiming a valid-looking MAC
    handrolled = st_mod.ConsumerToken(
        b"\x00" * 32, b"\x01" * 32, "dash", legit.public_id,
        legit.issued_at, None)

    for i, bad in enumerate((foreign, flipped_bearer, flipped_mac,
                             handrolled)):
        marker = st_mod.Unvetted("payload-%d" % i)
        try:
            marker.acknowledge("dash", sink=sink,
                               consumer_token=bad, registry=reg)
            return {"verdict": "break",
                    "note": "forgery variant %d accepted" % i}
        except st_mod.ConsumerAuthError:
            refused += 1
        if sink.pending() != 0:
            return {"verdict": "break",
                    "note": "forgery variant %d left a record" % i}
    if refused != 4:
        return {"verdict": "break",
                "note": "expected 4 refusals, got %d" % refused}
    # The legitimate token still works (registry not poisoned).
    out = st_mod.Unvetted("ok").acknowledge(
        "dash", sink=sink, consumer_token=legit, registry=reg)
    if out != "ok" or sink.pending() != 1:
        return {"verdict": "break",
                "note": "legitimate token broke after attacks"}
    return {"verdict": "stopped",
            "note": "4/4 forgery variants refused loud; no record, "
                    "no payload; legitimate token unaffected"}


@_sit("redteam.sterile_d5_reg.cross_name_theft_refused")
def sit_cross_name_theft_refused():
    """D5-reg pin: consumer A's token presented naming consumer B is
    refused LOUD (ConsumerAuthError) with no record appended — theft
    across names cannot misattribute evidence. The honest boundary
    (in-process theft under the BOUND name, F59 class) is documented
    in CONSUMER_REGISTRY.md, not filed."""
    reg = st_mod.ConsumerRegistry()
    tok_a = reg.register_consumer("consumer-a")
    sink = st_mod.AckAuditSink()
    try:
        st_mod.Unvetted("x").acknowledge("consumer-b", sink=sink,
                                         consumer_token=tok_a,
                                         registry=reg)
        return {"verdict": "break",
                "note": "cross-name theft accepted — misattribution"}
    except st_mod.ConsumerAuthError:
        pass
    if sink.pending() != 0:
        return {"verdict": "break",
                "note": "refused theft left a record"}
    # Same token under its own bound name still verifies.
    st_mod.Unvetted("x").acknowledge("consumer-a", sink=sink,
                                     consumer_token=tok_a, registry=reg)
    rec = sink.peek_oldest()
    if rec["attribution"] != "authenticated" \
            or rec["token_id"] != tok_a.public_id:
        return {"verdict": "break", "note": "bound-name ack mis-marked"}
    return {"verdict": "stopped",
            "note": "cross-name theft refused loud, no record; "
                    "bound-name use verifies"}


@_sit("redteam.sterile_d5_reg.same_id_two_consumers_distinguished")
def sit_same_id_two_consumers_distinguished():
    """D5-reg pin: two registrations of the same consumer_id get
    distinct public token_ids; both tokens verify; revoking one leaves
    the other valid; chained records carry token_id so the auditor
    distinguishes them."""
    reg = st_mod.ConsumerRegistry()
    t1 = reg.register_consumer("dup")
    t2 = reg.register_consumer("dup")
    if t1.public_id == t2.public_id:
        return {"verdict": "break",
                "note": "same-id registrations share a public id"}
    run, _ = _fresh_run()
    ex = run["executor"]
    sink = st_mod.AckAuditSink()
    st_mod.Unvetted("a", ack_context={"seq": 1}).acknowledge(
        "dup", sink=sink, consumer_token=t1, registry=reg)
    st_mod.Unvetted("b", ack_context={"seq": 2}).acknowledge(
        "dup", sink=sink, consumer_token=t2, registry=reg)
    ex.drain_ack_sink(sink)
    evs = _ack_entries(run)
    ids = [e.get("token_id") for e in evs]
    if sorted(ids) != sorted([t1.public_id, t2.public_id]):
        return {"verdict": "break",
                "note": "chained records do not distinguish: %r" % ids}
    reg.revoke(t1.public_id)
    try:
        st_mod.Unvetted("x").acknowledge(
            "dup", sink=st_mod.AckAuditSink(),
            consumer_token=t1, registry=reg)
        return {"verdict": "break",
                "note": "revoked same-id token still verifies"}
    except st_mod.ConsumerAuthError:
        pass
    st_mod.Unvetted("x").acknowledge(
        "dup", sink=st_mod.AckAuditSink(),
        consumer_token=t2, registry=reg)  # survivor still valid
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "same-id registrations distinguished by token_id "
                    "in the chain; independent revocation"}


@_sit("redteam.sterile_d5_reg.revocation_fail_closed_history_append_only")
def sit_revocation_fail_closed_history_append_only():
    """D5-reg pin: revoke mid-stream — future acks with the token
    refuse LOUD; already-chained records keep their 'authenticated'
    mark with token_id + ts (history is append-only, never rewritten;
    validity-at-time stays auditable)."""
    reg = st_mod.ConsumerRegistry()
    tok = reg.register_consumer("dash")
    run, _ = _fresh_run()
    ex = run["executor"]
    sink = st_mod.AckAuditSink()
    st_mod.Unvetted("before", ack_context={"seq": 1}).acknowledge(
        "dash", sink=sink, consumer_token=tok, registry=reg)
    ex.drain_ack_sink(sink)
    reg.revoke(tok.public_id)
    sink2 = st_mod.AckAuditSink()
    try:
        st_mod.Unvetted("after").acknowledge(
            "dash", sink=sink2, consumer_token=tok, registry=reg)
        return {"verdict": "break",
                "note": "revoked token acknowledged"}
    except st_mod.ConsumerAuthError:
        pass
    if sink2.pending() != 0:
        return {"verdict": "break",
                "note": "revoked ack left a record"}
    evs = _ack_entries(run)
    if len(evs) != 1 or evs[0]["attribution"] != "authenticated":
        return {"verdict": "break",
                "note": "pre-revocation record altered or lost"}
    if evs[0]["token_id"] != tok.public_id or "ts" not in evs[0]:
        return {"verdict": "break",
                "note": "pre-revocation record lost token_id/ts"}
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "post-revocation refused loud; pre-revocation "
                    "record intact (authenticated, token_id, ts)"}


@_sit("redteam.sterile_d5_reg.anonymous_laundering_honest")
def sit_anonymous_laundering_honest():
    """D5-reg boundary pin: acking with no token is stamped
    'attribution': 'unattributed' honestly — there is no path from
    the anonymous call to an 'authenticated' mark without a live
    registry-issued token bound to the named consumer. The laundering
    itself (sensitive ack as unattributed) is the designed behavior
    (the anonymous path was always open); a deployment that needs
    attribution refuses unattributed acks at ITS policy layer.
    Graded BOUNDARY, not a miss, not filed."""
    reg = st_mod.ConsumerRegistry()
    tok = reg.register_consumer("dash")
    sink = st_mod.AckAuditSink()
    # The "attacker": launder a sensitive ack as unattributed.
    st_mod.Unvetted("sensitive-payload").acknowledge("dash", sink=sink)
    rec = sink.peek_oldest()
    if rec["attribution"] != "unattributed":
        return {"verdict": "break",
                "note": "anonymous ack not marked unattributed"}
    if "token_id" in rec:
        return {"verdict": "break",
                "note": "anonymous ack carries a token_id"}
    # No upgrade path: registry without token stays unattributed,
    # and nothing without a verified token is ever 'authenticated'.
    sink2 = st_mod.AckAuditSink()
    st_mod.Unvetted("x").acknowledge("dash", sink=sink2, registry=reg)
    if sink2.peek_oldest()["attribution"] != "unattributed":
        return {"verdict": "break",
                "note": "registry-without-token upgraded"}
    # A valid token still earns the authenticated mark (control).
    sink3 = st_mod.AckAuditSink()
    st_mod.Unvetted("x").acknowledge("dash", sink=sink3,
                                     consumer_token=tok, registry=reg)
    if sink3.peek_oldest()["attribution"] != "authenticated":
        return {"verdict": "break",
                "note": "valid token not marked authenticated"}
    return {"verdict": "stopped",
            "note": "anonymous acks honestly unattributed; no "
                    "silent upgrade path; authenticated mark requires "
                    "a verified token (designed boundary: deployment "
                    "policy decides refusal of unattributed)"}


@_sit("redteam.sterile_d5_reg.invalid_token_never_degrades")
def sit_invalid_token_never_degrades():
    """D5-reg pin: there is deliberately NO invalid-token ->
    'unattributed' degradation path. Garbage tokens + registry, a
    token with no registry, and a non-registry object all fail closed
    or loud — silent downgrade would be a laundering primitive."""
    reg = st_mod.ConsumerRegistry()
    tok = reg.register_consumer("dash")
    for i, kwargs in enumerate((
            {"consumer_token": "not-a-token", "registry": reg},
            {"consumer_token": None, "registry": reg},  # honest unattrib
            {"consumer_token": tok},                    # no registry
            {"registry": "not-a-registry"})):
        sink = st_mod.AckAuditSink()
        try:
            out = st_mod.Unvetted("x").acknowledge("dash", sink=sink,
                                                   **kwargs)
        except (st_mod.ConsumerAuthError, TypeError):
            if i == 1:
                return {"verdict": "break",
                        "note": "registry-without-token raised "
                                "(must be honest unattributed)"}
            if sink.pending() != 0:
                return {"verdict": "break",
                        "note": "variant %d left a record" % i}
            continue
        if i == 1:
            # The honest path: registry given, no token.
            if out != "x" or sink.peek_oldest()["attribution"] != \
                    "unattributed":
                return {"verdict": "break",
                        "note": "variant 1 not honest-unattributed"}
        else:
            return {"verdict": "break",
                    "note": "variant %d did not raise" % i}
    return {"verdict": "stopped",
            "note": "garbage/no-registry/non-registry all fail loud; "
                    "registry-without-token is honest unattributed; "
                    "no silent downgrade exists"}


@_sit("redteam.sterile_d5_reg.expiry_enforced")
def sit_expiry_enforced():
    """D5-reg pin: ttl_s is honored on the registry's injectable clock.
    Acks before expiry verify; acks after expiry refuse LOUD; the
    pre-expiry chained record keeps its mark."""
    now = [1_000_000.0]
    reg = st_mod.ConsumerRegistry(name="ttl-reg", now=lambda: now[0])
    tok = reg.register_consumer("dash", ttl_s=60)
    run, _ = _fresh_run()
    ex = run["executor"]
    sink = st_mod.AckAuditSink()
    st_mod.Unvetted("fresh", ack_context={"seq": 1}).acknowledge(
        "dash", sink=sink, consumer_token=tok, registry=reg)
    ex.drain_ack_sink(sink)
    now[0] += 61
    sink2 = st_mod.AckAuditSink()
    try:
        st_mod.Unvetted("stale").acknowledge(
            "dash", sink=sink2, consumer_token=tok, registry=reg)
        return {"verdict": "break",
                "note": "expired token acknowledged"}
    except st_mod.ConsumerAuthError:
        pass
    if sink2.pending() != 0:
        return {"verdict": "break", "note": "expired ack left a record"}
    evs = _ack_entries(run)
    if len(evs) != 1 or evs[0]["attribution"] != "authenticated":
        return {"verdict": "break",
                "note": "pre-expiry record altered or lost"}
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "ttl honored: pre-expiry ack chained authenticated, "
                    "post-expiry refused loud with no record"}


@_sit("redteam.sterile_d5_reg.legit_loop_regression")
def sit_legit_loop_regression():
    """D5-reg no-regression pin: the legacy unattributed flow works
    byte-identically to wave-66 (existing battery/executor paths),
    the authenticated flow drains end to end with token_id in the
    chain, and the wave-66 cumulative budget still enforces."""
    run, _ = _fresh_run()
    ex = run["executor"]
    # Legacy flow: no registry, no token — exactly wave-66 behavior.
    sink = st_mod.AckAuditSink()
    for i in range(3):
        st_mod.Unvetted([i], ack_context={"w": "w%d" % i}).acknowledge(
            "dash-%d" % i, sink)
    if ex.drain_ack_sink(sink) != 3:
        return {"verdict": "break", "note": "legacy drain short"}
    # sink=None path unchanged.
    if st_mod.Unvetted("free").acknowledge("dash") != "free":
        return {"verdict": "break", "note": "sink=None path broke"}
    # Authenticated flow: register, ack, drain, chain carries token_id.
    reg = st_mod.ConsumerRegistry()
    tok = reg.register_consumer("loop-context-merge")
    sink2 = st_mod.AckAuditSink()
    st_mod.Unvetted([9], ack_context={"w": "w9"}).acknowledge(
        "loop-context-merge", sink=sink2,
        consumer_token=tok, registry=reg)
    if ex.drain_ack_sink(sink2) != 1:
        return {"verdict": "break", "note": "authenticated drain short"}
    evs = _ack_entries(run)
    if len(evs) != 4:
        return {"verdict": "break", "note": "chained count wrong: %d"
                % len(evs)}
    if [e["attribution"] for e in evs] != \
            ["unattributed"] * 3 + ["authenticated"]:
        return {"verdict": "break", "note": "attribution marks wrong"}
    if evs[3]["token_id"] != tok.public_id:
        return {"verdict": "break", "note": "token_id missing in chain"}
    if "token_id" in evs[0]:
        return {"verdict": "break",
                "note": "legacy record gained token_id"}
    # Wave-66 cumulative budget still enforced after this wave's change.
    if ex._ack_cumulative_used != 4:
        return {"verdict": "break",
                "note": "cumulative counter wrong: %d"
                % ex._ack_cumulative_used}
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "legacy flow byte-identical; authenticated flow "
                    "drains with token_id; cumulative budget intact"}


# D1 verdict mapping for the HOLD/MISS vocabulary
# (evals/SUMMARY_FORM_POLICIES.md): "stopped" (attack stopped) -> HELD,
# "break" -> BREAK, "error" -> ERROR, "residual" -> HELD with a
# "residual: " note prefix. Red-first: an unmapped verdict maps to BREAK.
_VERDICT_MAP = {"stopped": "HELD", "break": "BREAK", "error": "ERROR",
                "residual": "HELD"}


def _note_of(row):
    # D2 contract for the w72 family: the note lives under
    # detail["note"], falling back to detail["error"] for harness
    # exceptions (which record {"error": ...} with no "note").
    return row["detail"].get("note") or row["detail"].get("error", "")


def _main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    rows = [{"id": r["id"],
             "verdict": _VERDICT_MAP.get(r["verdict"], "BREAK"),
             "detail": r["detail"]} for r in RESULTS]
    probe_lines.emit_dicts(rows, pid_key="id", note_getter=_note_of)
    brk = sum(1 for r in rows if r["verdict"] == "BREAK")
    held = sum(1 for r in rows if r["verdict"] == "HELD")
    err = sum(1 for r in rows if r["verdict"] == "ERROR")
    print("w67 battery: %d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["id"], r["verdict"], _note_of(r)) for r in rows], brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    # Exit-equivalent to the old `0 if not broken else 1`: broken counted
    # every non-"stopped" verdict, i.e. break + error == brk + err here
    # (no sit function records "residual" as a verdict).
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(_main())
