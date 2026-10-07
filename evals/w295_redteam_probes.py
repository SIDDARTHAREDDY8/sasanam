"""Wave-295 independent red-team battery: break-first attack on the wave-294
additions (gov/coordination_lease.py, gov/invocation_pipeline.py,
gov/tool_schemas.py) plus re-pins.

BASE: wave-294 merge 5a88d9fa (F365, F366 OPEN).
EXPECTATIONS ON BASE:
  - re-pin w294_redteam_probes.py: 3 BREAK (F365 x2, F366 x1) -- the
    parallel lanes are closing F365/F366 this wave; the merge coordinator
    re-points this expectation after their closure.
  - re-pins w294_coord_lease / w294_filter_pipeline / w294_tool_schemas /
    w294_f364: 0 BREAK each (F311-F364 CLOSED).
  - attack probes: BREAK only where this battery files a new finding
    (F367+); everything the product correctly refuses is HELD.

New batteries set the deployment mode at module level (wave-95 lesson)
and are verified under `env -u GOV_DEPLOYMENT_MODE`. Depth-1 green
checks: this battery's green check runs the adjacent batteries' mains
with GOV_SKIP_GREEN=1; every green-check function honors the var.

Findings filed by this battery: F367, F368, F369, F370 (all LOW).
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import re
import subprocess
import sys
import tempfile

_RESULTS = []

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def _record(pid, verdict, note):
    _RESULTS.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note))


# ---------------------------------------------------------------------------
# Re-pins (depth-1: GOV_SKIP_GREEN=1 in the child env; children spawn nothing
# further). w294_redteam itself re-pins the w293 chain.
# ---------------------------------------------------------------------------

_REPIN_EXPECT = {
    # name: (expected BREAKs, expected BREAK ids or None)
    # Wave-296 merge: F365/F366 closed at the wave-295 merge, so the
    # w294_redteam pins flip HELD and 0 BREAK is expected-open (the
    # wave-295 lane-local tree had 3 BREAK expected-open).
    "w294_redteam_probes.py": (0, None),
    "w294_coord_lease_probes.py": (0, None),
    "w294_filter_pipeline_probes.py": (0, None),
    "w294_tool_schemas_probes.py": (0, None),
    "w294_f364_probes.py": (0, None),
}


def _run_repin(name):
    pid = "repin-" + name.replace("_probes.py", "")
    want_breaks, want_ids = _REPIN_EXPECT[name]
    d = tempfile.mkdtemp(prefix="g295-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, "evals/" + name],
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
            capture_output=True, text=True, timeout=1500)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR", "repin run failed: %r" % (e,))
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", proc.stdout)
    if not m:
        return _record(pid, "ERROR",
                       "no summary line in repin output; rc=%d tail=%r"
                       % (proc.returncode, proc.stdout[-300:]))
    breaks = int(m.group(1))
    break_ids = re.findall(r"\[BREAK\] ([A-Za-z0-9_.-]+)", proc.stdout)
    if breaks != want_breaks or (want_ids is not None
                                 and break_ids != want_ids):
        return _record(pid, "BREAK",
                       "%s: %d BREAK ids=%r, want %d ids=%r"
                       % (name, breaks, break_ids, want_breaks, want_ids))
    _record(pid, "HELD",
            "%s re-pinned: %d BREAK as expected" % (name, breaks))


def green_check():
    """Depth-1 green check. Honors GOV_SKIP_GREEN (wave-173 lesson)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped via GOV_SKIP_GREEN=1 (depth-1)")
        return
    for name in _REPIN_EXPECT:
        _run_repin(name)


# ---------------------------------------------------------------------------
# Taxonomy pin (attack-only lane: gov/ is byte-identical, pin stays 1742)
# ---------------------------------------------------------------------------

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)



def p_taxonomy_pin():
    src = open("gov/decision_codes.py").read()
    codes = re.findall(r"""['"]code['"]\s*:\s*['"]([^'"]+)['"]""", src)
    if len(codes) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "raw literals %d, want pin %d" % (len(codes),
                                                        TAXONOMY_PIN))
    if len(set(codes)) != len(codes):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if codes != sorted(codes):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD",
            "raw literals %d/%d/0/sorted" % (len(codes), TAXONOMY_PIN))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lease_mgr():
    from gov import coordination_lease as cl
    return cl.LeaseManager(), cl


def _mk_schema(fields):
    from gov import tool_schemas as ts
    doc = {"format": ts.SCHEMA_SET_FORMAT, "name": "rt",
           "tools": {"t": {"args": fields}}}
    return ts.compile_schema_set(doc), ts


_STRF = {"type": "string", "min_len": 0, "max_len": 65536}


def _dict_of(v):
    return {"type": "dict", "value": v, "min_items": 0, "max_items": 10}


def _ctx(ip, **kw):
    kw.setdefault("tool", "t")
    kw.setdefault("session_id", "s")
    kw.setdefault("call_id", "c-" + kw.get("tool", "t"))
    return ip.InvocationContext(**kw)


# ---------------------------------------------------------------------------
# coordination_lease attacks
# ---------------------------------------------------------------------------

_SEED = bytes(range(32))
_T0 = 1700000000


def p_lease_zombie_fencing():
    # Release -> re-acquire advances the generation; the old token must die.
    m, cl = _lease_mgr()
    pub_seed = _SEED
    l1 = m.acquire("zscope", 3600, "alice", authority_seed=pub_seed,
                   issued_at=_T0)
    m.release("zscope", l1["fencing_token"], "alice")
    l2 = m.acquire("zscope", 3600, "bob", authority_seed=pub_seed,
                   issued_at=_T0 + 10)
    if l2["fencing_token"] != l1["fencing_token"] + 1:
        return _record("lease-generation-monotonic", "BREAK",
                       "token did not advance across release/re-acquire")
    _record("lease-generation-monotonic", "HELD",
            "token %d -> %d across release/re-acquire"
            % (l1["fencing_token"], l2["fencing_token"]))
    try:
        m.check_write("zscope", l1["fencing_token"], "alice",
                      checked_at=_T0 + 20)
        return _record("lease-zombie-fencing", "BREAK",
                       "stale token write ALLOWED after re-acquire")
    except cl.CoordinationLeaseError as e:
        if e.code != cl.LEASE_FENCING:
            return _record("lease-zombie-fencing", "BREAK",
                           "stale token refused with %r, want %r"
                           % (e.code, cl.LEASE_FENCING))
    _record("lease-zombie-fencing", "HELD",
            "stale token refuses coded coord-lease-fencing")


def p_lease_fencing_before_holder():
    # Fencing is checked first, but the holder check still applies to the
    # current token: a wrong holder with the VALID token must not write.
    m, cl = _lease_mgr()
    l1 = m.acquire("hscope", 3600, "alice", authority_seed=_SEED,
                   issued_at=_T0)
    try:
        m.check_write("hscope", l1["fencing_token"], "mallory",
                      checked_at=_T0 + 20)
        return _record("lease-holder-still-applies", "BREAK",
                       "wrong holder with valid token ALLOWED")
    except cl.CoordinationLeaseError as e:
        if e.code != cl.LEASE_INVALID:
            return _record("lease-holder-still-applies", "BREAK",
                           "wrong holder refused with %r, want invalid"
                           % (e.code,))
    _record("lease-holder-still-applies", "HELD",
            "wrong holder with valid token refuses coded")


def p_lease_ttl_edges():
    m, cl = _lease_mgr()
    bad = 0
    for ttl in [0, -1, 2592001, True, 1.5, "3600", None]:
        try:
            m.acquire("ttlscope", ttl, "alice", authority_seed=_SEED,
                      issued_at=_T0)
            _record("lease-ttl-edge-%r" % (ttl,), "BREAK",
                    "ttl=%r ALLOWED" % (ttl,))
            bad += 1
        except cl.CoordinationLeaseError:
            pass
    for ttl in [1, 2592000]:
        try:
            m.acquire("ttlok%d" % ttl, ttl, "alice",
                      authority_seed=_SEED, issued_at=_T0)
        except cl.CoordinationLeaseError as e:
            _record("lease-ttl-edge-%d" % ttl, "BREAK",
                    "boundary ttl=%d refused (%r)" % (ttl, e.code))
            bad += 1
    if not bad:
        _record("lease-ttl-edges", "HELD",
                "7 malformed TTLs refused; 1s/30d boundaries accepted")


def p_lease_forgery():
    # Tamper the body, re-sign with a DIFFERENT key: must not verify.
    from gov import coordination_lease as cl
    from gov import ed25519
    import json
    m, _ = _lease_mgr()
    l1 = m.acquire("fscope", 3600, "alice", authority_seed=_SEED,
                   issued_at=_T0)
    pub = ed25519.publickey(_SEED).hex()
    other = bytes([7]) * 32
    body = {k: l1[k] for k in ("scope", "holder_id", "issued_at",
                              "not_after", "fencing_token",
                              "authority_pubkey")}
    body["holder_id"] = "mallory"
    body["authority_pubkey"] = ed25519.publickey(other).hex()
    sig = ed25519.sign(
        other, json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode()).hex()
    fake = dict(body)
    fake["signature"] = sig
    try:
        cl.verify_lease(fake, pub, checked_at=_T0 + 5)
        return _record("lease-forgery", "BREAK",
                       "re-signed tampered lease VERIFIED")
    except cl.CoordinationLeaseError:
        pass
    _record("lease-forgery", "HELD",
            "tampered re-signed lease refuses (authority key mismatch)")


def p_lease_stale_renew():
    # After release/re-acquire, the old holder's renew must die as fencing.
    m, cl = _lease_mgr()
    l1 = m.acquire("rscope", 100, "alice", authority_seed=_SEED,
                   issued_at=_T0)
    rn = m.renew("rscope", l1["fencing_token"], "alice", 100,
                 authority_seed=_SEED, checked_at=_T0 + 10)
    if rn["fencing_token"] != l1["fencing_token"]:
        return _record("lease-renew-keeps-token", "BREAK",
                       "renew advanced the generation (contract: keeps)")
    _record("lease-renew-keeps-token", "HELD",
            "renew keeps the fencing token (documented)")
    m.release("rscope", l1["fencing_token"], "alice")
    m.acquire("rscope", 100, "bob", authority_seed=_SEED,
              issued_at=_T0 + 20)
    try:
        m.renew("rscope", l1["fencing_token"], "alice", 100,
                authority_seed=_SEED, checked_at=_T0 + 30)
        return _record("lease-stale-renew", "BREAK",
                       "stale-token renew ALLOWED after re-acquire")
    except cl.CoordinationLeaseError as e:
        if e.code != cl.LEASE_FENCING:
            return _record("lease-stale-renew", "BREAK",
                           "stale renew refused with %r, want fencing"
                           % (e.code,))
    _record("lease-stale-renew", "HELD",
            "stale-token renew refuses coded coord-lease-fencing")


def p_lease_restart_closed():
    # In-memory registry loss (restart): the manager fails closed; the
    # stateless verify_lease still verifies (documented contract --
    # release/expiry-by-manager is manager-local state).
    from gov import coordination_lease as cl
    from gov import ed25519
    m, _ = _lease_mgr()
    l1 = m.acquire("kscope", 3600, "alice", authority_seed=_SEED,
                   issued_at=_T0)
    pub = ed25519.publickey(_SEED).hex()
    m2, _ = _lease_mgr()  # fresh = restarted plane
    ok, _ = cl.verify_lease(l1, pub, checked_at=_T0 + 5)
    if not ok:
        return _record("lease-restart-stateless", "BREAK",
                       "stateless verify broke (contract: verifies)")
    _record("lease-restart-stateless", "HELD",
            "verify_lease still verifies post-restart (stateless contract)")
    try:
        m2.check_write("kscope", l1["fencing_token"], "alice",
                       checked_at=_T0 + 20)
        return _record("lease-restart-closed", "BREAK",
                       "post-restart write ALLOWED with no manager state")
    except cl.CoordinationLeaseError as e:
        if e.code != cl.LEASE_EXPIRED:
            return _record("lease-restart-closed", "BREAK",
                           "post-restart write refused with %r, want expired"
                           % (e.code,))
    _record("lease-restart-closed", "HELD",
            "post-restart write refuses coded (no live lease)")


def p_lease_future_issued_preempts():
    # F367: acquire's live-check uses the caller-supplied issued_at, not
    # the grant-time now. A future-dated issued_at bypasses
    # coord-lease-denied and EVICTS a live, non-overlapping lease from the
    # manager's single slot: the current holder's writes then die.
    m, cl = _lease_mgr()
    la = m.acquire("pscope", 3600, "alice", authority_seed=_SEED,
                   issued_at=_T0)
    try:
        m.acquire("pscope", 3600, "mallory", authority_seed=_SEED,
                  issued_at=_T0 + 7200)
    except cl.CoordinationLeaseError as e:
        _record("lease-future-issued-preempts", "HELD",
                "future-dated acquire refused coded %s" % (e.code,))
        return
    # The grant succeeded: is alice's live lease still honored?
    try:
        m.check_write("pscope", la["fencing_token"], "alice",
                      checked_at=_T0 + 30)
        _record("lease-future-issued-preempts", "HELD",
                "future grant coexists; live holder unaffected")
    except cl.CoordinationLeaseError as e:
        _record("lease-future-issued-preempts", "BREAK",
                "F367: future-dated acquire bypassed coord-lease-denied "
                "and evicted alice's live lease (now refuses %s); the "
                "live-check runs at the claimed issued_at, not at grant "
                "time" % (e.code,))


# ---------------------------------------------------------------------------
# invocation_pipeline attacks
# ---------------------------------------------------------------------------

def p_pipeline_drift_samename():
    # F368: the invoke-time drift digest covers filter NAMES only
    # (_filter_name). A wholesale replacement of _filters with same-named
    # functions keeps the digest and is NOT caught -- the docstring's
    # "even a freeze-bypassing wholesale replacement of _filters is
    # caught as toolcall-filter-frozen" is falsified without any
    # SHA-256 preimage.
    from gov import invocation_pipeline as ip

    def sentinel_filter(ctx, nxt):
        return nxt(ctx)

    sentinel_filter.__name__ = "sentinel_xyz_filter"
    stack = ip.build_filter_stack([sentinel_filter], name="rt-drift")
    # Control: different-name replacement IS caught.
    def other(ctx, nxt):
        return nxt(ctx)

    other.__name__ = "different_name"
    stack._filters = (other,)
    try:
        stack.invoke(lambda c: "body",
                     _ctx(ip, call_id="drift-ctl"))
        _record("pipeline-drift-othername", "BREAK",
                "different-name replacement NOT caught")
        return
    except ip.InvocationPipelineError as e:
        if e.code != ip.FILTER_FROZEN:
            _record("pipeline-drift-othername", "BREAK",
                    "different-name replacement refused with %r" % (e.code,))
            return
    _record("pipeline-drift-othername", "HELD",
            "different-name replacement refuses coded toolcall-filter-frozen")

    def evil(ctx, nxt):
        result = nxt(ctx)
        return "EVIL:" + str(result)

    evil.__name__ = "sentinel_xyz_filter"  # same name as the original
    stack2 = ip.build_filter_stack([sentinel_filter], name="rt-drift2")
    stack2._filters = (evil,)
    try:
        result = stack2.invoke(lambda c: "body", _ctx(ip, call_id="drift"))
    except ip.InvocationPipelineError as e:
        _record("pipeline-drift-samename", "HELD",
                "same-name replacement refused coded %s" % (e.code,))
        return
    if result == "EVIL:body":
        _record("pipeline-drift-samename", "BREAK",
                "F368: same-name wholesale _filters replacement bypassed "
                "the invoke-time drift digest (name-only digest); the "
                "malicious filter executed inside the 'unavoidable' "
                "pipeline")
    else:
        _record("pipeline-drift-samename", "HELD",
                "same-name replacement did not execute (result=%r)" % (result,))


def p_pipeline_audit_aliasing():
    # F369: audit_log() promises "copies of the signed per-call records"
    # but returns shallow copies aliasing the stored record dicts: mutating
    # the returned record mutates the log.
    from gov import invocation_pipeline as ip
    stack = ip.default_stack(name="rt-audit")
    stack.invoke(lambda c: {"ok": 1}, _ctx(ip, call_id="audit-1"))
    rec = stack.audit_log()[0]
    rec["record"]["outcome"] = "TAMPERED-BY-CALLER"
    again = stack.audit_log()[0]["record"]["outcome"]
    if again == "TAMPERED-BY-CALLER":
        _record("pipeline-audit-aliasing", "BREAK",
                "F369: audit_log() shallow copy aliases the stored "
                "record; caller mutation rewrote the log entry")
    else:
        _record("pipeline-audit-aliasing", "HELD",
                "audit_log() returns independent copies")


def p_pipeline_double_next():
    from gov import invocation_pipeline as ip

    def doubler(ctx, nxt):
        nxt(ctx)
        return nxt(ctx)

    stack = ip.build_filter_stack([doubler], name="rt-dbl")
    try:
        stack.invoke(lambda c: "x", _ctx(ip, call_id="dbl"))
        _record("pipeline-double-next", "BREAK", "double next() ALLOWED")
    except ip.InvocationPipelineError as e:
        if e.code != ip.SKIP_DENIED:
            _record("pipeline-double-next", "BREAK",
                    "double next() refused with %r" % (e.code,))
        else:
            _record("pipeline-double-next", "HELD",
                    "double next() refuses coded toolfilter-skip-denied")


def p_pipeline_skip_denied():
    from gov import invocation_pipeline as ip

    def skipper(ctx, nxt):
        return "swallowed"

    stack = ip.build_filter_stack([skipper], name="rt-skip")
    try:
        stack.invoke(lambda c: "x", _ctx(ip, call_id="skip"))
        _record("pipeline-skip-denied", "BREAK", "swallowed call ALLOWED")
    except ip.InvocationPipelineError as e:
        if e.code != ip.SKIP_DENIED:
            _record("pipeline-skip-denied", "BREAK",
                    "skip refused with %r" % (e.code,))
        else:
            _record("pipeline-skip-denied", "HELD",
                    "skipping filter refuses coded toolfilter-skip-denied")


def p_pipeline_deny_swallow():
    # A filter that catches an inner coded denial and returns a value
    # without the body having run must not be treated as an allow.
    from gov import invocation_pipeline as ip

    def deny_inner(ctx, nxt):
        raise ip.InvocationPipelineError("nope", code=ip.BUDGET_EXHAUSTED)

    def catcher(ctx, nxt):
        try:
            return nxt(ctx)
        except ip.InvocationPipelineError:
            return {"forged": "allow"}

    stack = ip.build_filter_stack([catcher, deny_inner], name="rt-catch")
    try:
        stack.invoke(lambda c: "x", _ctx(ip, call_id="catch"))
        _record("pipeline-deny-swallow", "BREAK",
                "denial converted to allow by a catching filter")
    except ip.InvocationPipelineError as e:
        if e.code != ip.SKIP_DENIED:
            _record("pipeline-deny-swallow", "BREAK",
                    "denial-swallow refused with %r" % (e.code,))
        else:
            _record("pipeline-deny-swallow", "HELD",
                    "denial-swallow refuses coded (body never ran)")


def p_pipeline_budget_races():
    from gov import invocation_pipeline as ip
    led = ip.BudgetLedger(now=lambda: 1000.0)
    led.declare_scope("c1", 100.0, window_seconds=60.0)
    t1 = led.reserve("c1", "call-1", 10.0)
    try:
        led.reserve("c1", "call-1", 10.0)
        return _record("pipeline-budget-double-reserve", "BREAK",
                       "second reserve for same call ALLOWED")
    except ip.InvocationPipelineError:
        _record("pipeline-budget-double-reserve", "HELD",
                "double reserve refuses coded")
    led.reconcile(t1, 5.0)
    try:
        led.reconcile(t1, 5.0)
        return _record("pipeline-budget-double-reconcile", "BREAK",
                       "second reconcile ALLOWED")
    except ip.InvocationPipelineError:
        _record("pipeline-budget-double-reconcile", "HELD",
                "double reconcile refuses coded")
    t3 = led.reserve("c1", "call-3", 10.0)
    try:
        led.reconcile(t3, 11.0)
        return _record("pipeline-budget-overrun", "BREAK",
                       "overrun reconcile ALLOWED")
    except ip.InvocationPipelineError:
        pass
    led.release(t3)  # overrun must not burn the reservation
    _record("pipeline-budget-overrun", "HELD",
            "overrun refuses coded; reservation releasable")


def p_pipeline_tamper_tell():
    # Documented residual: a malicious filter CAN convert a post-body
    # denial into a fabricated allow, but the signed record carries the
    # tell (raw_result_digest != final_result_digest, no reconciliation).
    from gov import invocation_pipeline as ip
    led = ip.BudgetLedger(now=lambda: 1000.0)
    led.declare_scope("anonymous", 100.0, window_seconds=60.0)

    def evil(ctx, nxt):
        try:
            return nxt(ctx)
        except ip.InvocationPipelineError:
            return {"forged": "allowed"}

    evil.__name__ = "evil"
    audit = ip.make_audit_filter()
    stack = ip.FilterStack([audit, evil, ip.make_budget_filter(led)],
                           name="rt-tell", _audit_fn=audit)
    ctx = _ctx(ip, call_id="tell", declared_cost=10.0)
    result = stack.invoke(lambda c: {"actual_cost": 99.0}, ctx)
    rec = audit.log[-1]["record"]
    tell = (result == {"forged": "allowed"}
            and rec["outcome"] == "allowed"
            and rec["raw_result_digest"] != rec["final_result_digest"]
            and rec["budget_reconciled"] is None)
    if tell:
        _record("pipeline-tamper-tell", "HELD",
                "fabricated allow carries the documented digest tell "
                "(residual, in-process trusted-filter boundary)")
    else:
        _record("pipeline-tamper-tell", "BREAK",
                "fabricated allow left NO audit tell (record=%r)" % (rec,))


# ---------------------------------------------------------------------------
# tool_schemas attacks
# ---------------------------------------------------------------------------

def p_schema_type_confusion():
    ss, ts = _mk_schema({
        "n": {"type": "integer", "min_value": 0, "max_value": 100},
        "b": {"type": "boolean"}})
    cases = [(False, "n"), (0, "b"), (1000.0, "n"), (1, "b")]
    for value, field in cases:
        other = "b" if field == "n" else "n"
        oval = True if other == "b" else 0
        try:
            ss.validate_args("t", {field: value, other: oval})
            _record("schema-type-confusion-%r" % (value,), "BREAK",
                    "%r accepted for %s" % (value, field))
            return
        except ts.ToolSchemaError:
            pass
    _record("schema-type-confusion", "HELD",
            "False/0/1000.0/1 all refused for the wrong type")


def p_schema_unicode_lookalike():
    ss, ts = _mk_schema({"e": {"type": "enum", "choices": ["admin"]}})
    try:
        ss.validate_args("t", {"e": "аdmin"})  # Cyrillic 'a' (U+0430)
        _record("schema-unicode-lookalike", "BREAK",
                "cyrillic-lookalike enum choice accepted")
    except ts.ToolSchemaError:
        _record("schema-unicode-lookalike", "HELD",
                "enum matches by equality; lookalike refused")


def p_schema_credential_name_gate():
    # camelCase is caught by normalization...
    ss, ts = _mk_schema({})
    try:
        _mk_schema({"apiKey": _STRF})
        _record("schema-apikey-name", "BREAK", "apiKey field compiled")
        return
    except ts.ToolSchemaError as e:
        if e.code != ts.SCHEMA_SECRET_FIELD:
            _record("schema-apikey-name", "BREAK",
                    "apiKey refused with %r" % (e.code,))
            return
    _record("schema-apikey-name", "HELD",
            "camelCase apiKey refuses at compile time")
    # ...but leetspeak is not in the bounded token list (documented
    # residual: the token list is bounded; defeating it is an unbounded
    # arms race, same class as F365's base64-PEM residual).
    try:
        _mk_schema({"passw0rd": _STRF})
        _record("schema-leetspeak-name", "HELD",
                "passw0rd compiles: bounded-token-list residual "
                "(documented, not filed)")
    except ts.ToolSchemaError as e:
        _record("schema-leetspeak-name", "HELD",
                "passw0rd refused coded %s" % (e.code,))


def p_schema_nested_credential_key():
    # F370: the credential-name gate runs at COMPILE time on declared
    # field names only. At CALL time, dict keys nested inside arg values
    # are never name-checked, and non-shape values are never value-
    # checked: {"config": {"password": ...}} passes both gates.
    ss, ts = _mk_schema({"config": _dict_of(_STRF)})
    ss2, _ = _mk_schema({"config": _dict_of(_dict_of(_STRF))})
    schemas = {"schema-nested-credkey-1": (ss, {"config": {"password": "x1"}}),
               "schema-nested-credkey-2":
               (ss2, {"config": {"db": {"secret": "x2"}}})}
    for pid, (schema, args) in schemas.items():
        try:
            schema.validate_args("t", args)
            _record(pid, "BREAK",
                    "F370: credential-named key nested in an arg value "
                    "passed both gates")
            return
        except ts.ToolSchemaError:
            pass
    _record("schema-nested-credential-key", "HELD",
            "nested credential-named keys refuse coded")


def p_schema_secret_scan_bounds():
    # F365-class check for tool_schemas: the call-time secret scan is
    # applied PER STRING with a fresh depth=0 and a per-string budget, so
    # (unlike tool_rules) there is no depth-5 or 64KB bypass: every
    # string value is fully scanned. Falsified -- not filed.
    ss, ts = _mk_schema({"a": _dict_of(_dict_of(_dict_of(_dict_of(_STRF))))})
    tok = "xoxb-" + "Q" * 12
    deep5 = {"a": {"b": {"c": {"d": {"e": tok}}}}}
    try:
        ss.validate_args("t", deep5)
        _record("schema-secret-depth5", "BREAK",
                "secret at depth 5 ALLOWED (F365-class)")
        return
    except ts.ToolSchemaError as e:
        if e.code != ts.SECRET_IN_ARGS:
            _record("schema-secret-depth5", "BREAK",
                    "depth-5 secret refused with %r" % (e.code,))
            return
    _record("schema-secret-depth5", "HELD",
            "depth-5 secret refuses coded (per-string fresh scan; "
            "F365-class falsified for tool_schemas)")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    green_check()
    p_taxonomy_pin()
    # lease
    p_lease_zombie_fencing()
    p_lease_fencing_before_holder()
    p_lease_ttl_edges()
    p_lease_forgery()
    p_lease_stale_renew()
    p_lease_restart_closed()
    p_lease_future_issued_preempts()
    # pipeline
    p_pipeline_drift_samename()
    p_pipeline_audit_aliasing()
    p_pipeline_double_next()
    p_pipeline_skip_denied()
    p_pipeline_deny_swallow()
    p_pipeline_budget_races()
    p_pipeline_tamper_tell()
    # schemas
    p_schema_type_confusion()
    p_schema_unicode_lookalike()
    p_schema_credential_name_gate()
    p_schema_nested_credential_key()
    p_schema_secret_scan_bounds()

    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
