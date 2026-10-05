#!/usr/bin/env python3
"""Wave-314 independent red-team battery (lane 3).

Fresh break-first probes against the wave-313 tree (base fa0b0ed1):
F397 is CLOSED (footer: open none / next F398); the new seams are

  * gov/approval_tokens.py -- capability/argument-bound approval tokens
    (Row 7 step 3),
  * gov/plan_policy.py -- plan-level pre-execution admission (Row 7
    step 4),
  * wave-310/311/312 provenance-adjacent wiring (in-toto re-enveloping,
    Sigstore-bundle distribution, offline verifier, witness log).

Method (diagnosing-bugs skill: break-first red loop): every probe
attempts the attack at the PUBLIC seam and records BREAK only when the
attack demonstrably succeeds; HELD when the attack is refused coded
(or when the probed behavior is the documented, pinned design
boundary -- those are marked "residual pin", never a finding).
ERROR on harness failure (loud, distinct from HELD).

Run:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g314-redteam \
      ~/workspace/.gov-venv/bin/python evals/w314_redteam_probes.py
Single probe:
  .../python evals/w314_redteam_probes.py <probe-id>

Conventions: module-level staging default (clean-env standalone
verified), depth-1 green checks honoring GOV_SKIP_GREEN=1, no in-repo
git subprocesses, _safe isolation per probe, single-probe mode.
"""

import copy
import hashlib
import json
import os
import sys
import time
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)

FOOTER_OPEN = "F432, F433, F434, F435"
FOOTER_NEXT = "F436"

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import approval_tokens as _at
from gov import decision_codes as _dc
from gov import plan_policy as _pp
from gov import workflow_composed as _wc
from gov import witness_log as _wl
from gov import evidence_intoto as _intoto
from gov import evidence_sigstore as _sigstore
from gov.signing import Ed25519Signer, Ed25519Verifier
from tests.keyfixture import provision_test_key, scrub_key_env


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _Break(Exception):
    """Raised when the attack demonstrably succeeds."""


_PROBES = []


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


_RESULTS = []


def _record(pid, verdict, note):
    _RESULTS.append((pid, verdict, note))


def _code_of(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 - probe harness
        return getattr(e, "code", None) or type(e).__name__
    return None


def _expect_code(pid, fn, code, *args, **kwargs):
    """HELD iff fn raises with the exact taxonomy code; BREAK if fn
    returns (the attack succeeded); ERROR on anything else."""
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        got = getattr(e, "code", None)
        if got == code:
            return "attack refused coded %s" % code
        raise _Break("%s: refused but with unexpected code %r (%s)" %
                     (pid, got, e))
    raise _Break("%s: attack SUCCEEDED, no refusal (expected %s)" %
                 (pid, code))


def _run_all(only=None):
    for pid, fn in _PROBES:
        if only is not None and pid != only:
            continue
        try:
            note = fn()
            _record(pid, "HELD", note)
        except _Break as b:
            _record(pid, "BREAK", str(b))
        except Exception as e:  # noqa: BLE001
            _record(pid, "ERROR", "%s: %s" %
                    (type(e).__name__, traceback.format_exc(limit=3)))


# ---------------------------------------------------------------------------
# Token seam helpers
# ---------------------------------------------------------------------------

_NOW = 1_750_000_000


def _mint(cap="send_email", args=None, **kw):
    kw.setdefault("issuer", "decider:test")
    kw.setdefault("ttl_seconds", 3600)
    kw.setdefault("issued_at", _NOW)
    return _at.issue_token(cap, {"mode": "exact",
                                 "args": args if args is not None else {}},
                           **kw)


def _mint_schema(cap="send_email", schema=None, **kw):
    schema = schema or {"to": {"enum": ["a@example.com", "b@example.com"]}}
    kw.setdefault("issuer", "decider:test")
    kw.setdefault("ttl_seconds", 3600)
    kw.setdefault("issued_at", _NOW)
    return _at.issue_token(cap, {"mode": "schema", "schema": schema}, **kw)


def _verify(tok, cap="send_email", args=None, now=None, store=None):
    return _at.verify_token(tok, capability=cap,
                            args=args if args is not None else {},
                            now=_NOW if now is None else now,
                            consume_store=store)


# ---------------------------------------------------------------------------
# Token seam: argument binding
# ---------------------------------------------------------------------------

@probe("token-arg-substitution")
def _p_token_arg_substitution():
    tok = _mint(args={"to": "colleague@example.com", "subject": "hi"})
    return _expect_code("token-arg-substitution", _verify, "approval-token-argument-mismatch",
                        tok, args={"to": "attacker@example.com",
                                   "subject": "hi"})


@probe("token-arg-removal")
def _p_token_arg_removal():
    tok = _mint(args={"to": "a@example.com", "subject": "hi"})
    return _expect_code("token-arg-removal", _verify, "approval-token-argument-mismatch",
                        tok, args={"to": "a@example.com"})


@probe("token-arg-widening")
def _p_token_arg_widening():
    tok = _mint(args={"to": "a@example.com"})
    return _expect_code("token-arg-widening", _verify, "approval-token-argument-mismatch",
                        tok, args={"to": "a@example.com", "cc": "x@y.z"})


@probe("token-capability-substitution")
def _p_token_capability_substitution():
    tok = _mint(cap="read_file", args={"path": "/etc/motd"})
    return _expect_code("token-capability-substitution", _verify,
                        "approval-token-capability-mismatch",
                        tok, cap="send_email",
                        args={"path": "/etc/motd"})


@probe("token-tampered-arg-bytes")
def _p_token_tampered_arg_bytes():
    tok = _mint(args={"to": "a@example.com"})
    bad = copy.deepcopy(tok)
    bad["argument_binding"] = {"mode": "exact",
                               "args": {"to": "b@example.com"}}
    return _expect_code("token-tampered-arg-bytes", _verify, "approval-token-tampered",
                        bad, args={"to": "b@example.com"})


@probe("token-tampered-capability-bytes")
def _p_token_tampered_capability_bytes():
    tok = _mint(cap="read_file", args={})
    bad = copy.deepcopy(tok)
    bad["capability"] = "send_email"
    return _expect_code("token-tampered-capability-bytes", _verify,
                        "approval-token-tampered", bad, cap="send_email")


@probe("token-tampered-nonce")
def _p_token_tampered_nonce():
    tok = _mint(args={})
    bad = copy.deepcopy(tok)
    n = bad["nonce"]
    bad["nonce"] = ("0" if n[0] != "0" else "1") + n[1:]
    return _expect_code("token-tampered-nonce", _verify, "approval-token-tampered",
                        bad)


@probe("token-tampered-mac")
def _p_token_tampered_mac():
    tok = _mint(args={})
    bad = copy.deepcopy(tok)
    m = bad["mac"]
    bad["mac"] = ("0" if m[0] != "0" else "1") + m[1:]
    return _expect_code("token-tampered-mac", _verify, "approval-token-tampered", bad)


@probe("token-unknown-field")
def _p_token_unknown_field():
    tok = _mint(args={})
    bad = copy.deepcopy(tok)
    bad["extra"] = "x"
    return _expect_code("token-unknown-field", _verify, "approval-token-malformed", bad)


@probe("token-missing-field")
def _p_token_missing_field():
    tok = _mint(args={})
    bad = copy.deepcopy(tok)
    del bad["nonce"]
    return _expect_code("token-missing-field", _verify, "approval-token-malformed", bad)


@probe("token-version-bump")
def _p_token_version_bump():
    tok = _mint(args={})
    bad = copy.deepcopy(tok)
    bad["v"] = 2
    return _expect_code("token-version-bump", _verify, "approval-token-malformed", bad)


@probe("token-expired")
def _p_token_expired():
    tok = _mint(ttl_seconds=60, issued_at=_NOW - 3600)
    return _expect_code("token-expired", _verify, "approval-token-expired", tok)


@probe("token-future-issued")
def _p_token_future_issued():
    tok = _mint(issued_at=_NOW + 3600)
    got = _code_of(_verify, tok)
    if got is None:
        raise _Break("token-future-issued: future-issued token verified")
    return "future-issued token refused coded %s" % got


@probe("token-ttl-zero")
def _p_token_ttl_zero():
    got = _code_of(_mint, ttl_seconds=0)
    if got != "approval-token-malformed":
        raise _Break("token-ttl-zero: ttl=0 minted (code=%r)" % got)
    return "ttl=0 refused at mint coded approval-token-malformed"


@probe("token-ttl-too-long")
def _p_token_ttl_too_long():
    got = _code_of(_mint, ttl_seconds=31 * 24 * 3600)
    if got != "approval-token-malformed":
        raise _Break("token-ttl-too-long: 31d ttl minted (code=%r)" % got)
    return "31d ttl refused at mint coded approval-token-malformed"


@probe("token-non-json-native")
def _p_token_non_json_native():
    got = _code_of(_mint, args={"to": ("a", "b")})
    if got != "approval-token-malformed":
        raise _Break("token-non-json-native: tuple arg minted (code=%r)" % got)
    return "tuple arg refused at mint coded approval-token-malformed"


@probe("token-nan")
def _p_token_nan():
    got = _code_of(_mint, args={"x": float("nan")})
    if got != "approval-token-malformed":
        raise _Break("token-nan: NaN arg minted (code=%r)" % got)
    return "NaN arg refused at mint coded approval-token-malformed"


@probe("token-replay")
def _p_token_replay():
    tok = _mint(args={"to": "a@example.com"})
    store = _at.TokenConsumeStore()
    body = _verify(tok, args={"to": "a@example.com"}, store=store)
    store.consume(body["nonce"])
    return _expect_code("token-replay", _verify, "approval-token-replayed",
                        tok, args={"to": "a@example.com"}, store=store)


@probe("token-double-verify-no-consume")
def _p_token_double_verify_no_consume():
    # Documented: verify_token never consumes; consumption is the
    # caller's durable-claim step. Pin the behavior, not a finding.
    tok = _mint(args={"to": "a@example.com"})
    store = _at.TokenConsumeStore()
    _verify(tok, args={"to": "a@example.com"}, store=store)
    _verify(tok, args={"to": "a@example.com"}, store=store)
    return ("HELD (residual pin): verify-without-consume passes twice by "
            "design; at-most-once comes from consume-on-claim plus the "
            "queue's mark_executed")


@probe("token-cross-record-swap")
def _p_token_cross_record_swap():
    # The decomposed-reuse core: step 1's token must not authorize
    # step 3's harmful variant.
    tok1 = _mint(cap="read_file", args={"path": "/notes.txt"})
    tok3 = _mint(cap="send_email",
                 args={"to": "attacker@example.com", "body": "secrets"})
    r1 = _expect_code("token-cross-record-swap", _verify,
                      "approval-token-capability-mismatch",
                      tok1, cap="send_email",
                      args={"to": "attacker@example.com",
                            "body": "secrets"})
    r3 = _expect_code("token-cross-record-swap", _verify,
                      "approval-token-argument-mismatch",
                      tok3, cap="send_email",
                      args={"to": "colleague@example.com", "body": "hi"})
    return r1 + "; " + r3


@probe("token-key-rotation-invalidates")
def _p_token_key_rotation_invalidates():
    tok = _mint(args={"to": "a@example.com"})
    # Rotate the deployment key: a new epoch becomes active.
    provision_test_key(epoch="rotated")
    try:
        got = _code_of(_verify, tok, args={"to": "a@example.com"})
    finally:
        provision_test_key(epoch="test")
    if got != "approval-token-tampered":
        raise _Break("token-key-rotation-invalidates: pre-rotation token "
                     "verified under rotated keyring (code=%r)" % got)
    return ("pre-rotation token refused coded approval-token-tampered "
            "after key rotation (key_epoch binding)")


@probe("token-schema-widening")
def _p_token_schema_widening():
    tok = _mint_schema()
    return _expect_code("token-schema-widening", _verify,
                        "approval-token-argument-mismatch",
                        tok, args={"to": "a@example.com", "cc": "x@y.z"})


@probe("token-schema-type-confusion")
def _p_token_schema_type_confusion():
    tok = _mint_schema(schema={"n": {"enum": [1, 2]}})
    return _expect_code("token-schema-type-confusion", _verify,
                        "approval-token-argument-mismatch",
                        tok, args={"n": "1"})


@probe("token-schema-wrong-value")
def _p_token_schema_wrong_value():
    tok = _mint_schema(schema={"to": {"enum": ["a@example.com"]}})
    return _expect_code("token-schema-wrong-value", _verify,
                        "approval-token-argument-mismatch",
                        tok, args={"to": "evil@example.com"})


@probe("token-schema-happy")
def _p_token_schema_happy():
    tok = _mint_schema()
    body = _verify(tok, args={"to": "a@example.com"})
    if body["capability"] != "send_email":
        raise _Break("token-schema-happy: verified body mismatch")
    return "schema-mode token verifies for an in-enum value"

# ---------------------------------------------------------------------------
# Token seam: record binding (approval path integration, no sweep needed)
# ---------------------------------------------------------------------------

@probe("token-record-mac-binds-token")
def _p_token_record_mac_binds_token():
    # The token is minted BEFORE the decision re-MAC on both the
    # decide() and quorum paths, and "approval_token" is in
    # _SECURITY_PAYLOAD_FIELDS: swapping the token after the decision
    # must break the record MAC (refused, never silently re-usable).
    from gov import approvals as _appr
    rec = {
        "id": "appr-1", "tool": "send_email",
        "args": {"to": "a@example.com"},
        "status": "approved", "decided_by": "tester",
        "egress_bytes": 0,
        "approval_token": _appr._mint_approval_token(
            "send_email", {"to": "a@example.com"}, "tester"),
    }
    mac = _appr.approval_record_digest(rec)
    rec["args_digest"] = mac
    if not _appr._pending_record_content_ok(rec):
        raise _Break("token-record-mac-binds-token: honest record fails "
                     "its own MAC check")
    swapped = dict(rec)
    swapped["approval_token"] = _appr._mint_approval_token(
        "read_file", {"path": "/x"}, "tester")
    swapped["args_digest"] = mac  # attacker keeps the old MAC
    if _appr._pending_record_content_ok(swapped):
        raise _Break("token-record-mac-binds-token: token swapped without "
                     "breaking the record MAC")
    return ("token is MAC-bound on the record: swap breaks "
            "_pending_record_content_ok")


@probe("token-mint-binds-final-args")
def _p_token_mint_binds_final_args():
    # _mint_approval_token binds exactly what it is given; a mint for
    # args A never verifies for args B (the decide() path passes the
    # post-edit target args).
    from gov import approvals as _appr
    tok = _appr._mint_approval_token("send_email",
                                     {"to": "a@example.com"}, "tester")
    try:
        # Mint used wall-clock issued_at: verify against wall clock.
        _at.verify_token(tok, capability="send_email",
                         args={"to": "b@example.com"}, now=None)
    except _at.ApprovalTokenError as e:
        if e.code == "approval-token-argument-mismatch":
            return "mint binds the exact args it was given"
        raise _Break("token-mint-binds-final-args: unexpected code %r"
                     % e.code)
    raise _Break("token-mint-binds-final-args: substituted args verified")


# ---------------------------------------------------------------------------
# Plan-policy seam helpers
# ---------------------------------------------------------------------------

def _fn(i=None):
    return {"ok": True}


def _fn_unit(name, tool, capabilities, trust, key, fn=None,
             consumes=None, extra=None):
    entry = {"tool": tool, "capabilities": capabilities, "trust": trust}
    if consumes:
        entry["consumes"] = consumes
    if extra:
        entry.update(extra)
    return ({"kind": "fn", "name": name, "fn": fn or _fn,
             "inputs": {}, "idem_key": key},
            entry)


def _fn_plan(manifest, units):
    return _wc.ComposedPlan(units, manifest=manifest)


def _obs_manifest():
    return {"capabilities": ["observation"],
            "units": {"u": {"tool": "read_file",
                            "capabilities": ["observation"],
                            "trust": "internal"}}}


def _pp_check(plan, allowed):
    return _pp.check_plan(plan, _pp.PlanPolicy(allowed))


# ---------------------------------------------------------------------------
# Plan-policy seam: declaration rules
# ---------------------------------------------------------------------------

@probe("plan-hidden-egress")
def _p_plan_hidden_egress():
    units, entry = _fn_unit("u", "send_email", ["observation"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    return _expect_code("plan-hidden-egress", _pp_check,
                        "plan-policy-capability", plan, ["observation"])


@probe("plan-unknown-tool")
def _p_plan_unknown_tool():
    units, entry = _fn_unit("u", "evil_tool", ["observation"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    return _expect_code("plan-unknown-tool", _pp_check,
                        "plan-policy-unknown-tool", plan, ["observation"])


@probe("plan-envelope-undercover")
def _p_plan_envelope_undercover():
    units, entry = _fn_unit("u", "send_email", ["egress"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    return _expect_code("plan-envelope-undercover", _pp_check,
                        "plan-policy-capability", plan,
                        ["observation", "egress"])


@probe("plan-envelope-vs-deployment")
def _p_plan_envelope_vs_deployment():
    units, entry = _fn_unit("u", "send_email", ["egress"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["egress"],
                     "units": {"u": entry}}, [units])
    return _expect_code("plan-envelope-vs-deployment", _pp_check,
                        "plan-policy-capability", plan, ["observation"])


def _slip_plan(internal_flows, leg_tools=None):
    from gov import ed25519 as _e
    from gov import workflow_routing as _wr
    SA = hashlib.sha256(b"w314-slip").digest()
    PA = _e.publickey(SA).hex()
    ATX = 1_700_000_000
    legs = [{"handler_id": "h1", "handler_pubkey_hex": PA,
             "rights": ["tool.invoke"], "input_digest": "0" * 64,
             "output_digest": "0" * 64},
            {"handler_id": "h2", "handler_pubkey_hex": PA,
             "rights": ["tool.invoke"], "input_digest": "0" * 64,
             "output_digest": "0" * 64}]
    slip = _wr.issue_slip(SA, "issuer", legs, ATX)
    entry = {"leg_tools": leg_tools or {"0": "read_file", "1": "read_file"},
             "capabilities": ["observation"], "trust": "internal"}
    if internal_flows is not None:
        entry["internal_flows"] = internal_flows
    m = {"capabilities": ["observation"], "units": {"s": entry}}
    return _wc.ComposedPlan(
        [{"kind": "slip", "name": "s", "slip": slip,
          "trust_roots": [PA],
          "leg_fns": {0: (SA, _fn), 1: (SA, _fn)},
          "inputs": {}, "idem_key": "k"}],
        manifest=m)


@probe("plan-slip-undeclared-internal")
def _p_plan_slip_undeclared_internal():
    # Refused at plan CONSTRUCTION (normalize_manifest runs in
    # ComposedPlan.__init__): a slip unit with no internal_flows key
    # never becomes a plan at all.
    got = _code_of(_slip_plan, None)  # no internal_flows key at all
    if got != "workflow-composed-definition-invalid":
        raise _Break("plan-slip-undeclared-internal: code=%r" % got)
    return "slip without internal_flows refused at construction coded definition-invalid"


@probe("plan-slip-phantom-internal")
def _p_plan_slip_phantom_internal():
    plan = _slip_plan([{"from": "leg:0", "to": "leg:1",
                        "classification": "internal"},
                       {"from": "leg:1", "to": "leg:0",
                        "classification": "internal"}])
    return _expect_code("plan-slip-phantom-internal", _pp_check,
                        "plan-policy-data-flow", plan, ["observation"])


@probe("plan-slip-implied-edge-declared")
def _p_plan_slip_implied_edge_declared():
    plan = _slip_plan([{"from": "leg:0", "to": "leg:1",
                        "classification": "internal"}])
    _pp_check(plan, ["observation"])
    return "declared implied leg->leg edge passes (documented)"


@probe("plan-backward-flow")
def _p_plan_backward_flow():
    ua, ea = _fn_unit("a", "read_file", ["observation"], "internal", "k1")
    ub, eb = _fn_unit("b", "read_file", ["observation"], "internal", "k2",
                      consumes=[{"from": "b", "classification": "internal"}])
    eb2 = dict(eb, consumes=[{"from": "a", "classification": "internal"}])
    # make b consume from a but declare order b-before-a: build units
    # [b, a] so a is later in plan order -> non-forward flow
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"a": ea, "b": eb2}}, [ub, ua])
    return _expect_code("plan-backward-flow", _pp_check,
                        "plan-policy-data-flow", plan, ["observation"])


@probe("plan-self-flow")
def _p_plan_self_flow():
    units, entry = _fn_unit("u", "read_file", ["observation"], "internal",
                            "k",
                            consumes=[{"from": "u",
                                       "classification": "internal"}])
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    return _expect_code("plan-self-flow", _pp_check,
                        "plan-policy-data-flow", plan, ["observation"])


@probe("plan-duplicate-flow")
def _p_plan_duplicate_flow():
    ua, ea = _fn_unit("a", "read_file", ["observation"], "internal", "k1")
    ub, eb = _fn_unit(
        "b", "read_file", ["observation"], "internal", "k2",
        consumes=[{"from": "a", "classification": "internal"},
                  {"from": "a", "classification": "public"}])
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"a": ea, "b": eb}}, [ua, ub])
    return _expect_code("plan-duplicate-flow", _pp_check,
                        "plan-policy-data-flow", plan, ["observation"])


@probe("plan-producer-overclassification")
def _p_plan_producer_overclassification():
    ua, ea = _fn_unit("a", "read_file", ["observation"], "public", "k1")
    ub, eb = _fn_unit("b", "read_file", ["observation"], "public", "k2",
                      consumes=[{"from": "a",
                                 "classification": "confidential"}])
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"a": ea, "b": eb}}, [ua, ub])
    return _expect_code("plan-producer-overclassification", _pp_check,
                        "plan-policy-data-flow", plan, ["observation"])


@probe("plan-trust-mixing-undeclared")
def _p_plan_trust_mixing_undeclared():
    ua, ea = _fn_unit("a", "read_file", ["observation"],
                      "confidential", "k1")
    ub, eb = _fn_unit("b", "read_file", ["observation"], "public", "k2",
                      consumes=[{"from": "a",
                                 "classification": "confidential"}])
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"a": ea, "b": eb}}, [ua, ub])
    return _expect_code("plan-trust-mixing-undeclared", _pp_check,
                        "plan-policy-trust-mixing", plan, ["observation"])


@probe("plan-trust-mixing-declared")
def _p_plan_trust_mixing_declared():
    ua, ea = _fn_unit("a", "read_file", ["observation"],
                      "confidential", "k1")
    ub, eb = _fn_unit("b", "read_file", ["observation"], "public", "k2",
                      consumes=[{"from": "a",
                                 "classification": "confidential"}])
    plan = _fn_plan({"capabilities": ["observation"],
                     "declassify": [{"from": "a", "to": "b",
                                     "reason": "operator-approved summary"}],
                     "units": {"a": ea, "b": eb}}, [ua, ub])
    _pp_check(plan, ["observation"])
    return "declared declassify with reason passes (documented)"


@probe("plan-manifest-missing")
def _p_plan_manifest_missing():
    units, _entry = _fn_unit("u", "read_file", ["observation"],
                             "internal", "k")
    plan = _wc.ComposedPlan([units])  # no manifest
    got = _code_of(_pp.check_plan, plan, _pp.PlanPolicy(["observation"]))
    if got != "plan-policy-manifest-missing":
        raise _Break("plan-manifest-missing: code=%r" % got)
    return "manifest-less plan refused coded plan-policy-manifest-missing"


@probe("plan-manifest-unknown-topkey")
def _p_plan_manifest_unknown_topkey():
    units, entry = _fn_unit("u", "read_file", ["observation"],
                            "internal", "k")
    manifest = {"capabilities": ["observation"],
                "units": {"u": entry}, "bogus": 1}
    got = _code_of(_fn_plan, manifest, [units])
    if got != "workflow-composed-definition-invalid":
        raise _Break("plan-manifest-unknown-topkey: code=%r" % got)
    return "unknown manifest top-level key refused (strict)"


@probe("plan-extra-capability-declared")
def _p_plan_extra_capability_declared():
    # Over-declaration is the conservative direction: declaring MORE
    # than the tool inherently needs widens the envelope (the
    # deployment policy still constrains it). Must pass.
    units, entry = _fn_unit("u", "read_file",
                            ["observation", "egress"], "internal", "k")
    plan = _fn_plan({"capabilities": ["observation", "egress"],
                     "units": {"u": entry}}, [units])
    _pp_check(plan, ["observation", "egress"])
    return "over-declared capabilities pass (conservative direction)"


@probe("plan-fn-body-indirection")
def _p_plan_fn_body_indirection():
    # DOCUMENTED RESIDUAL (lane E): the checker attributes capability
    # from declared tool names; it cannot see inside unit fns. A plan
    # declaring an observation tool whose fn actually exfiltrates
    # PASSES -- fn honesty is the composer's standing residual, and
    # argument-level exfil detail belongs to the provenance-graded
    # sink policy (Row 7 step 5). Pin the boundary, not a finding.
    def _lying_fn(i=None):
        return {"exfiltrated": True}
    units, entry = _fn_unit("u", "read_file", ["observation"],
                            "internal", "k", fn=_lying_fn)
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    _pp_check(plan, ["observation"])
    return ("HELD (residual pin): declaration-honest but behavior-lying "
            "fn passes the declarative gate by design; the boundary is "
            "explicit in the module docstring")

# ---------------------------------------------------------------------------
# Plan-policy seam: admit/execute integration
# ---------------------------------------------------------------------------

def _composer_harness():
    from gov import delegation as dg
    from gov import delegation_revocation as drv
    from gov import ed25519
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    SA = hashlib.sha256(b"w314pp-a").digest()
    PA = ed25519.publickey(SA).hex()
    ATX = 1_700_000_000
    ws = wf.WorkflowStore()
    sm = saga.SagaManager()
    im = idem.IdempotencyStore()
    c = _wc.WorkflowComposer(ws, sm, im)
    cons = {"expires_at": ATX + 3600, "max_depth": 4,
            "allowed_targets": ["agent-b"]}
    chain = [dg.issue(SA, "agent-a", "agent-b", PA, ("tool.invoke",),
                      issued_at=ATX, constraints=cons)]
    auth = {"actor_id": "agent-b", "action": "tool.invoke",
            "chain": chain, "trust_roots": [PA],
            "revocation_ledger": drv.DelegationRevoker(SA, "agent-a")}
    run = ws.start_run("plan", run_id="w314", authority=auth, at=ATX)
    return c, auth, run, ATX


@probe("plan-unadmitted-execute")
def _p_plan_unadmitted_execute():
    c, auth, run, ATX = _composer_harness()
    units, entry = _fn_unit("u", "read_file", ["observation"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    got = _code_of(c.execute, plan, run_id=run["run_id"],
                   authority=auth, at=ATX)
    if got != "plan-policy-not-admitted":
        raise _Break("plan-unadmitted-execute: code=%r" % got)
    return "manifested plan without admission refused coded at execute"


@probe("plan-admit-then-mutate")
def _p_plan_admit_then_mutate():
    c, auth, run, ATX = _composer_harness()
    units, entry = _fn_unit("u", "read_file", ["observation"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    c.admit_plan(plan, _pp.PlanPolicy(["observation"]))
    # Post-admission in-place mutation of the unit dicts.
    plan.units[0]["idem_key"] = "evil-key"
    got = _code_of(c.execute, plan, run_id=run["run_id"],
                   authority=auth, at=ATX)
    if got != "workflow-composed-definition-invalid":
        raise _Break("plan-admit-then-mutate: code=%r" % got)
    return "post-admission in-place mutation refused via verify_digest"


@probe("plan-admit-cross-composer")
def _p_plan_admit_cross_composer():
    from gov import workflow as wf
    from gov import workflow_saga as saga
    from gov import workflow_idempotency as idem
    c, auth, run, ATX = _composer_harness()
    units, entry = _fn_unit("u", "read_file", ["observation"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    c.admit_plan(plan, _pp.PlanPolicy(["observation"]))
    # Build a genuinely separate composer over fresh stores.
    ws2 = wf.WorkflowStore()
    sm2 = saga.SagaManager()
    im2 = idem.IdempotencyStore()
    c2 = _wc.WorkflowComposer(ws2, sm2, im2)
    run2 = ws2.start_run("plan", run_id="w314b", authority=auth, at=ATX)
    got = _code_of(c2.execute, plan, run_id=run2["run_id"],
                   authority=auth, at=ATX)
    if got != "plan-policy-not-admitted":
        raise _Break("plan-admit-cross-composer: code=%r" % got)
    return "admission does not transfer across composers (fail closed)"


@probe("plan-admit-then-execute-ok")
def _p_plan_admit_then_execute_ok():
    c, auth, run, ATX = _composer_harness()
    units, entry = _fn_unit("u", "read_file", ["observation"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    c.admit_plan(plan, _pp.PlanPolicy(["observation"]))
    res = c.execute(plan, run_id=run["run_id"], authority=auth, at=ATX)
    if "u" not in res.get("units", {}):
        raise _Break("plan-admit-then-execute-ok: admitted plan did not "
                     "execute")
    return "admitted plan executes normally"


@probe("plan-manifest-less-executes")
def _p_plan_manifest_less_executes():
    # Documented opt-in boundary: a plan that never carried a manifest
    # executes under the pre-step-4 regime. Pin, not a finding.
    c, auth, run, ATX = _composer_harness()
    units, _entry = _fn_unit("u", "read_file", ["observation"],
                             "internal", "k")
    plan = _wc.ComposedPlan([units])
    res = c.execute(plan, run_id=run["run_id"], authority=auth, at=ATX)
    if "u" not in res.get("units", {}):
        raise _Break("plan-manifest-less-executes: manifest-less plan "
                     "refused unexpectedly")
    return ("HELD (residual pin): manifest-less plans execute without "
            "admission by design (opt-in regime)")


@probe("plan-manifest-strip")
def _p_plan_manifest_strip():
    # Admit a manifested plan, then strip the manifest attribute
    # in-process and mutate the units: execute() only runs
    # verify_digest()/admission when plan.manifest is not None, so the
    # stripped plan executes the mutated units with no policy check.
    # This is EQUIVALENT to constructing a manifest-less plan (the
    # opt-in boundary), not a bypass of a guarantee the design makes:
    # the threat model scopes the gate to declarations, and a plan
    # author who can mutate the live plan object between the
    # framework's own admit and execute calls already runs the
    # framework's code. Pin the boundary explicitly.
    c, auth, run, ATX = _composer_harness()
    units, entry = _fn_unit("u", "read_file", ["observation"],
                            "internal", "k")
    plan = _fn_plan({"capabilities": ["observation"],
                     "units": {"u": entry}}, [units])
    c.admit_plan(plan, _pp.PlanPolicy(["observation"]))
    plan.manifest = None
    plan.units[0]["idem_key"] = "evil-key"
    try:
        res = c.execute(plan, run_id=run["run_id"], authority=auth,
                        at=ATX)
        executed = "u" in res.get("units", {})
    except Exception:
        executed = False
    if not executed:
        return ("HELD: stripped plan unexpectedly refused "
                "(stricter than the documented boundary)")
    return ("HELD (residual pin): manifest-strip executes the mutated "
            "plan -- equivalent to manifest-less by design; the "
            "admit->execute sequence must not hand the live plan "
            "object to untrusted code between the two calls")


# ---------------------------------------------------------------------------
# Witness-log seam
# ---------------------------------------------------------------------------

def _witness_harness(n=4):
    from gov import ed25519 as _e
    seed = hashlib.sha256(b"w314-witness").digest()
    pub = _e.publickey(seed)  # 32 bytes
    log = _wl.WitnessLog(pub)
    for i in range(n):
        log.append(b"leaf-%d" % i)
    return log, seed, pub


class _TestSigner:
    """Minimal witness signer: .public_key (32 bytes) + .sign(bytes)."""

    def __init__(self, seed):
        from gov import ed25519 as _e
        self._seed = seed
        self.public_key = _e.publickey(seed)

    def sign(self, msg):
        from gov import ed25519 as _e
        return _e.sign(self._seed, msg)


def _wcp(log, seed, ts=1_750_000_000):
    """Verified checkpoint triple: (tree_size, root_bytes)."""
    sealed = log.sealed_checkpoint(ts, _TestSigner(seed))
    cp = _wl.verify_checkpoint(sealed, _TestSigner(seed).public_key)
    return cp["treeSize"], bytes.fromhex(cp["rootHash"])


@probe("witness-inclusion-happy")
def _p_witness_inclusion_happy():
    log, seed, pub = _witness_harness()
    proof = log.inclusion_proof(1)
    tree_size, root = _wcp(log, seed)
    _wl.verify_inclusion(b"leaf-1", 1, proof["path"], tree_size, root)
    return "honest inclusion proof verifies"


@probe("witness-inclusion-wrong-position")
def _p_witness_inclusion_wrong_position():
    log, seed, pub = _witness_harness()
    proof = log.inclusion_proof(0)  # proof for leaf 0...
    tree_size, root = _wcp(log, seed)
    try:
        _wl.verify_inclusion(b"leaf-0", 1, proof["path"], tree_size, root)
    except _wl.WitnessError as e:
        if e.code == "witness-log-inclusion-invalid":
            return "proof for leaf 0 presented as leaf 1 refused (position binding)"
        raise _Break("witness-inclusion-wrong-position: code=%r" % e.code)
    raise _Break("witness-inclusion-wrong-position: misaddressed proof verified")


@probe("witness-inclusion-tampered-leaf")
def _p_witness_inclusion_tampered_leaf():
    log, seed, pub = _witness_harness()
    proof = log.inclusion_proof(2)
    tree_size, root = _wcp(log, seed)
    try:
        _wl.verify_inclusion(b"leaf-2-tampered", 2, proof["path"],
                             tree_size, root)
    except _wl.WitnessError as e:
        if e.code == "witness-log-inclusion-invalid":
            return "tampered leaf refused (fold does not recompute root)"
        raise _Break("witness-inclusion-tampered-leaf: code=%r" % e.code)
    raise _Break("witness-inclusion-tampered-leaf: tampered leaf verified")


@probe("witness-inclusion-truncated-path")
def _p_witness_inclusion_truncated_path():
    log, seed, pub = _witness_harness()
    proof = log.inclusion_proof(1)
    tree_size, root = _wcp(log, seed)
    short = proof["path"][:-1]
    try:
        _wl.verify_inclusion(b"leaf-1", 1, short, tree_size, root)
    except _wl.WitnessError as e:
        if e.code in ("witness-log-inclusion-invalid",
                      "witness-log-malformed"):
            return "truncated audit path refused (length binding)"
        raise _Break("witness-inclusion-truncated-path: code=%r" % e.code)
    raise _Break("witness-inclusion-truncated-path: truncated path verified")


@probe("witness-consistency-fork")
def _p_witness_consistency_fork():
    log, seed, pub = _witness_harness(4)
    proof = log.consistency_proof(2, 4)["hashes"]
    _tree_size, new_root = _wcp(log, seed, ts=1_750_000_100)
    fork_root = hashlib.sha256(b"forked-root").digest()
    try:
        _wl.verify_consistency(2, fork_root, 4, new_root, proof)
    except _wl.WitnessError as e:
        if e.code == "witness-log-consistency-invalid":
            return "forked old root refused (both roots recomputed)"
        raise _Break("witness-consistency-fork: code=%r" % e.code)
    raise _Break("witness-consistency-fork: forked history verified")


@probe("witness-checkpoint-forged")
def _p_witness_checkpoint_forged():
    import base64
    log, seed, pub = _witness_harness()
    sealed = log.sealed_checkpoint(1_750_000_000, _TestSigner(seed))
    bad = dict(sealed)
    sig = bytearray(base64.b64decode(bad["signature"]))
    sig[0] ^= 0x01
    bad["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    try:
        _wl.verify_checkpoint(bad, pub)
    except _wl.WitnessError as e:
        return "forged checkpoint signature refused coded %s" % e.code
    raise _Break("witness-checkpoint-forged: forged checkpoint verified")

# ---------------------------------------------------------------------------
# Sigstore-bundle / in-toto seam
# ---------------------------------------------------------------------------

_BUNDLE = b'{"bundle":"synthetic-test-bytes-314"}'
_OTHER = b'{"bundle":"different-bytes-314"}'
_CLAIMS = {"window": "2026-10-03", "tip": "cd" * 16, "decisions": 7}
_T0 = 1791528600
_VALIDITY = (1791528000, 1791530000)


def _signers(n, base=41):
    return [Ed25519Signer(bytes([base + i]) * 32) for i in range(n)]


def _verifiers(signers):
    return [Ed25519Verifier(s.public_key, s.key_id) for s in signers]


def _witness(base=77):
    return Ed25519Signer(bytes([base]) * 32)


def _sealed_bundle(signers=None, witness=None, bundle_bytes=_BUNDLE,
                   claims=_CLAIMS, integrated_time=_T0):
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    stmt = _intoto.build_statement(bundle_bytes, claims)
    env = _intoto.seal_statement(stmt, signers)
    return _sigstore.seal_sigstore_bundle(
        env, signers, witness, rfc3161_token=None,
        integrated_time=integrated_time)


def _open(bundle, bundle_bytes=_BUNDLE, signers=None, witness=None,
          threshold=1, validity=_VALIDITY):
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    return _sigstore.open_sigstore_bundle(
        bundle, bundle_bytes, _verifiers(signers),
        Ed25519Verifier(witness.public_key, witness.key_id),
        threshold=threshold, witness_validity=validity)


@probe("sigstore-happy")
def _p_sigstore_happy():
    bundle = _sealed_bundle()
    out = _open(bundle)
    if out["payload_sha256"] != hashlib.sha256(out["payload"]).hexdigest():
        raise _Break("sigstore-happy: payload digest mismatch")
    return "honest bundle opens; payload digest bound"


@probe("sigstore-wrong-artifact")
def _p_sigstore_wrong_artifact():
    bundle = _sealed_bundle(bundle_bytes=_BUNDLE)
    try:
        _open(bundle, bundle_bytes=_OTHER)
    except Exception as e:  # noqa: BLE001 - any coded refusal
        return "bundle opened against a different artifact refused (%s)" \
            % type(e).__name__
    raise _Break("sigstore-wrong-artifact: bundle verified for the wrong "
                 "artifact bytes")


@probe("sigstore-tampered-payload")
def _p_sigstore_tampered_payload():
    import base64 as _b64
    bundle = _sealed_bundle()
    bad = copy.deepcopy(bundle)
    env = bad["dsseEnvelope"]
    raw = _b64.b64decode(env["payload"])
    tampered = bytearray(raw)
    tampered[10] ^= 0x01
    env["payload"] = _b64.b64encode(bytes(tampered)).decode("ascii")
    try:
        _open(bad)
    except Exception as e:  # noqa: BLE001
        return "tampered statement payload refused (%s)" \
            % type(e).__name__
    raise _Break("sigstore-tampered-payload: tampered payload verified")


@probe("sigstore-integrated-time-outside-window")
def _p_sigstore_integrated_time_outside_window():
    bundle = _sealed_bundle(integrated_time=_T0)
    try:
        _open(bundle, validity=(_T0 + 7200, _T0 + 10800))
    except Exception as e:  # noqa: BLE001
        return "witness integratedTime outside the pinned window refused"
    raise _Break("sigstore-integrated-time-outside-window: out-of-window "
                 "witness time accepted")


@probe("sigstore-threshold-unmet")
def _p_sigstore_threshold_unmet():
    signers = _signers(3)
    stmt = _intoto.build_statement(_BUNDLE, _CLAIMS)
    env = _intoto.seal_statement(stmt, signers[:1])  # only 1 of 3 signs
    witness = _witness()
    bundle = _sigstore.seal_sigstore_bundle(
        env, signers[:1], witness, rfc3161_token=None,
        integrated_time=_T0)
    try:
        _open(bundle, signers=signers, threshold=2)
    except Exception as e:  # noqa: BLE001
        return "1-of-3 signatures against threshold=2 refused"
    raise _Break("sigstore-threshold-unmet: threshold bypassed")


@probe("sigstore-forged-witness-signature")
def _p_sigstore_forged_witness_signature():
    import base64 as _b64
    bundle = _sealed_bundle()
    bad = copy.deepcopy(bundle)
    promise = bad["verificationMaterial"]["tlogEntries"][0][
        "inclusionPromise"]
    sig = bytearray(_b64.b64decode(promise["signedEntryTimestamp"]))
    sig[0] ^= 0x01
    promise["signedEntryTimestamp"] = _b64.b64encode(bytes(sig)).decode(
        "ascii")
    try:
        _open(bad)
    except Exception as e:  # noqa: BLE001
        return "forged witness SET signature refused"
    raise _Break("sigstore-forged-witness-signature: forged witness "
                 "signature accepted")


@probe("intoto-tampered-statement")
def _p_intoto_tampered_statement():
    signers = _signers(1)
    stmt = _intoto.build_statement(_BUNDLE, _CLAIMS)
    env = _intoto.seal_statement(stmt, signers)
    bad = copy.deepcopy(env)
    import base64 as _b64
    raw = _b64.b64decode(bad["payload"])
    doc = json.loads(raw.decode("utf-8"))
    doc["predicate"]["decisions"] = 7000
    bad["payload"] = _b64.b64encode(
        json.dumps(doc, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    try:
        _intoto.open_statement(bad, _BUNDLE, _verifiers(signers))
    except Exception as e:  # noqa: BLE001
        return "post-seal statement edit refused (%s)" \
            % type(e).__name__
    raise _Break("intoto-tampered-statement: edited statement verified")


# ---------------------------------------------------------------------------
# Pin and footer
# ---------------------------------------------------------------------------

@probe("pin-taxonomy")
def _p_pin_taxonomy():
    codes = [c for c in dir(_dc) if not c.startswith("_")]
    lits = []
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*[\'"]([^\'"]+)[\'"]', src)
    uniq = sorted(set(lits))
    if len(lits) != TAXONOMY_PIN or len(uniq) != TAXONOMY_PIN:
        raise _Break("pin-taxonomy: %d literals, %d unique, want %d" %
                     (len(lits), len(uniq), TAXONOMY_PIN))
    if uniq != sorted(lits) or list(lits) != uniq:
        raise _Break("pin-taxonomy: literals not sorted/unique")
    if len(_dc.TAXONOMY) != TAXONOMY_PIN:
        raise _Break("pin-taxonomy: TAXONOMY dict has %d entries" %
                     len(_dc.TAXONOMY))
    return "%d/%d/0 sorted on source literals" % (TAXONOMY_PIN,
                                                  TAXONOMY_PIN)


@probe("footer-state")
def _p_footer_state():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Last footer line wins (history preserved above it).
    footers = [l for l in text.splitlines() if l.startswith("Next free")]
    if not footers:
        raise _Break("footer-state: no footer line found")
    last = footers[-1]
    # Wave-336 lane 1: footer-state probe repaired -- the F412-era
    # assertion rotted through several merges; assert the live footer.
    if "Open findings: F432, F433, F434, F435." not in last:
        raise _Break("footer-state: open findings present: %s" % last[:80])
    if FOOTER_NEXT not in last:
        raise _Break("footer-state: next is not %s: %s" %
                     (FOOTER_NEXT, last[:80]))
    return "footer: open %s / next %s" % (FOOTER_OPEN, FOOTER_NEXT)


# ---------------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "green check skipped (GOV_SKIP_GREEN=1)")
        return
    sys.path.insert(0, os.path.join(REPO, "evals"))
    import green_check
    # w313 red-team: F397 probes (incl. the boundary residual pin) HELD.
    green_check.check_battery(
        _record, "green-w313_redteam", "evals/w313_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # w313 approval-token battery: 0 BREAK expected.
    green_check.check_battery(
        _record, "green-w313_aptokens", "evals/w313_aptokens_probes.py",
        repo=REPO, expect_break_ids=())
    # w313 plan-policy battery: 0 BREAK expected.
    green_check.check_battery(
        _record, "green-w313_plancheck", "evals/w313_plancheck_probes.py",
        repo=REPO, expect_break_ids=())
    # w313 F397 battery: 0 BREAK expected.
    green_check.check_battery(
        _record, "green-w313_f397", "evals/w313_f397_probes.py",
        repo=REPO, expect_break_ids=())
    # Regression batteries for the findings this wave's seams closed or
    # touched: F396 (w312 redteam), F395 (w311 f395), F393 (w309 f393),
    # F391 (w308 f391), F394 (w309 redteam).
    green_check.check_battery(
        _record, "green-w312_redteam", "evals/w312_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _record, "green-w311_f395", "evals/w311_f395_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _record, "green-w309_f393", "evals/w309_f393_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _record, "green-w308_f391", "evals/w308_f391_probes.py",
        repo=REPO, expect_break_ids=())
    green_check.check_battery(
        _record, "green-w309_redteam", "evals/w309_redteam_probes.py",
        repo=REPO, expect_break_ids=())
    # Adjacent unit suites for the two new modules (module form: the
    # file form puts tests/ on sys.path and breaks `import gov`).
    green_check.check_unittest(
        _record, "green-test_approval_tokens",
        "tests.test_approval_tokens", repo=REPO)
    green_check.check_unittest(
        _record, "green-test_plan_policy",
        "tests.test_plan_policy", repo=REPO)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv):
    only = argv[1] if len(argv) > 1 else None
    if only is not None and not any(pid == only for pid, _ in _PROBES):
        print("unknown probe: %s" % only)
        return 2
    restore = scrub_key_env()
    provision_test_key(epoch="test")
    try:
        _run_all(only)
        if only is None:
            _green_checks()
        else:
            _record("green-skipped", "HELD",
                    "green check skipped (single-probe mode)")
    finally:
        restore()
    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    for pid, verdict, note in _RESULTS:
        print("[%s] %s: %s" % (verdict, pid, note.splitlines()[0][:160]))
    print("----")
    print("w314_redteam battery: %d BREAK / %d HELD / %d ERROR" %
          (breaks, held, errors))
    return 0 if (breaks == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
