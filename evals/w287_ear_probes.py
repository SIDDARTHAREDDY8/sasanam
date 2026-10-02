"""Wave-287 lane 8 red-first battery: veraison-pattern trust-vector appraisal.

Gap under test: Sasanam's evidence model separates the thing measured from
the policy that decides, but the *endorsement* half is missing -- golden
values live with the producer's word. veraison/veraison (+ veraison/services,
Apache-2.0; meta-repo archived, real code in services) supplies the
mechanisms: evidence -> endorsements -> appraisal-policy -> EAR trust-vector
pipeline, per-scheme plugin interface (SchemeDescriptor + claim grammar +
appraise dispatch), policy-as-data, and the trust *vector* result schema
(per-dimension affirmed/contraindicated/insufficient, never a bare
boolean). Traps NOT followed: CBOR/COSE wire formats, the multi-service
deployment, OPA as a runtime dependency.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and under
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g287-ear && TMPDIR=/var/tmp/g287-ear \\
    ~/workspace/.gov-venv/bin/python evals/w287_ear_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g287-ear2 \\
    ~/workspace/.gov-venv/bin/python evals/w287_ear_probes.py
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w287-ear")
os.environ.setdefault("TMPDIR", "/var/tmp/g287-ear")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-287 lane 8: pin 1660 -> 1670 (+10 trustvec-* codes).; Wave-287 merge: pin 1670 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*)
TAXONOMY_PIN = 1700

_RESULTS = []

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict,
                     "note": note})


def _needs_module(probe_id):
    try:
        from gov import trust_vector as tv
        return tv
    except ImportError:
        _record(probe_id, "BREAK", "gov.trust_vector absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


def _register_test_scheme(tv):
    """A firmware-attestation-shaped test scheme. Deterministic."""
    desc = tv.SchemeDescriptor(
        scheme_id="test-firmware/v1",
        claim_grammar={"fw_digest": "digest",
                       "fw_version": "str",
                       "debug_fuse": "bool"},
        dimensions=[
            {"name": "sw_integrity", "rule": "endorsed-match",
             "claims": ["fw_digest"]},
            {"name": "sw_up_to_dateness", "rule": "endorsed-match",
             "claims": ["fw_version"]},
            {"name": "config_integrity", "rule": "operator-trust",
             "claims": ["debug_fuse"]},
        ])
    try:
        tv.register_scheme(desc)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-scheme-duplicate":
            raise
    return desc


def _evidence(tv, claims=None, producer="prod-a"):
    return tv.submit_evidence(
        "test-firmware/v1",
        claims if claims is not None else {
            "fw_digest": "ab" * 32,
            "fw_version": "1.2.3",
            "debug_fuse": False,
        },
        producer)


def _policy(tv, trust_anchors=None):
    doc = {
        "format": "sasanam-appraisal-policy/v1",
        "policy_id": "probe-policy",
        "scheme_id": "test-firmware/v1",
        "trust_anchors": trust_anchors or {},
    }
    return tv.compile_policy(doc)


def _pins(tv, policy, digest=None):
    d = tempfile.mkdtemp(prefix="w287-ear-pin-")
    path = os.path.join(d, "pins.json")
    tv.pin_appraisal_policy(policy.policy_id,
                            digest if digest is not None else policy.digest,
                            path)
    return tv.load_appraisal_pins(path)


def _digest_value(v):
    return hashlib.sha256(
        json.dumps({"v": v}, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 1. The result is a vector, not a boolean; a failing dimension surfaces.
# ---------------------------------------------------------------------------

def p_vector_not_boolean():
    tv = _needs_module("vector-not-boolean")
    if tv is None:
        return
    _register_test_scheme(tv)
    ev = _evidence(tv)
    # Endorsement CONTRADICTS the evidence on fw_digest: a boolean check
    # over the rest would pass, the vector must not.
    end = tv.endorse(ev, "fw_digest", "ff" * 32, "endorser-1")
    pol = _policy(tv, trust_anchors={"prod-a": "key-1"})
    ear = tv.appraise(ev, [end], pol, _pins(tv, pol))
    if not isinstance(ear, dict) or "vector" not in ear:
        return _record("vector-not-boolean", "BREAK",
                       "appraisal did not return a vector-shaped EAR")
    if ear["vector"].get("sw_integrity") != "contraindicated":
        return _record("vector-not-boolean", "BREAK",
                       "contradicted dimension not surfaced as "
                       "contraindicated: %r" % (ear["vector"],))
    if ear.get("overall") == "affirmed":
        return _record("vector-not-boolean", "BREAK",
                       "overall affirmed while a dimension is "
                       "contraindicated")
    _record("vector-not-boolean", "HELD",
            "vector surfaces sw_integrity=contraindicated; "
            "overall=%s" % ear["overall"])


# ---------------------------------------------------------------------------
# 2. No endorsement => at most INSUFFICIENT, never affirmed (honest limit
#    made structural).
# ---------------------------------------------------------------------------

def p_no_endorsement_insufficient():
    tv = _needs_module("no-endorsement-insufficient")
    if tv is None:
        return
    _register_test_scheme(tv)
    ev = _evidence(tv)
    pol = _policy(tv)
    ear = tv.appraise(ev, [], pol, _pins(tv, pol))
    bad = [d for d, g in ear["vector"].items() if g == "affirmed"]
    if bad:
        return _record("no-endorsement-insufficient", "BREAK",
                       "affirmed without any endorsement: %r" % (bad,))
    if ear.get("overall") == "affirmed":
        return _record("no-endorsement-insufficient", "BREAK",
                       "overall affirmed with zero endorsements")
    _record("no-endorsement-insufficient", "HELD",
            "unendorsed dimensions insufficient: %r" % (ear["vector"],))


# ---------------------------------------------------------------------------
# 3. Endorsements must be separately sourced: the producer cannot
#    endorse its own evidence.
# ---------------------------------------------------------------------------

def p_endorsement_must_be_independent():
    tv = _needs_module("endorsement-independent")
    if tv is None:
        return
    _register_test_scheme(tv)
    ev = _evidence(tv, producer="prod-a")
    try:
        tv.endorse(ev, "fw_digest", "ab" * 32, "prod-a")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") == "trustvec-endorsement-not-independent":
            return _record("endorsement-independent", "HELD",
                           "self-endorsement refused LOUD with the coded "
                           "refusal")
        return _record("endorsement-independent", "BREAK",
                       "self-endorsement refused with wrong code: %r"
                       % (getattr(e, "code", type(e).__name__),))
    _record("endorsement-independent", "BREAK",
            "producer endorsed its own evidence silently")


# ---------------------------------------------------------------------------
# 4. Scheme grammar fails closed: unknown scheme, missing claim, wrong
#    type.
# ---------------------------------------------------------------------------

def p_scheme_grammar_fail_closed():
    tv = _needs_module("scheme-grammar")
    if tv is None:
        return
    _register_test_scheme(tv)
    cases = [
        (lambda: tv.submit_evidence("nope/v9", {}, "p"),
         "trustvec-scheme-unknown", "unknown scheme"),
        (lambda: tv.submit_evidence("test-firmware/v1",
                                    {"fw_digest": "ab" * 32}, "p"),
         "trustvec-evidence-invalid", "missing required claims"),
        (lambda: tv.submit_evidence("test-firmware/v1",
                                    {"fw_digest": "ab" * 32,
                                     "fw_version": 123,
                                     "debug_fuse": False}, "p"),
         "trustvec-evidence-invalid", "wrong claim type"),
    ]
    for fn, want, label in cases:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", "") == want:
                continue
            return _record("scheme-grammar", "BREAK",
                           "%s: wrong code %r, want %r"
                           % (label, getattr(e, "code", type(e).__name__),
                              want))
        else:
            return _record("scheme-grammar", "BREAK",
                           "%s: accepted silently" % (label,))
    _record("scheme-grammar", "HELD",
            "unknown scheme / missing claim / wrong type all refused LOUD")


# ---------------------------------------------------------------------------
# 5. Appraisal policy is pinned: unpinned and drifted policies refuse.
# ---------------------------------------------------------------------------

def p_policy_pin_required():
    tv = _needs_module("policy-pin")
    if tv is None:
        return
    _register_test_scheme(tv)
    ev = _evidence(tv)
    pol = _policy(tv)
    try:
        tv.appraise(ev, [], pol, {})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-policy-unpinned":
            return _record("policy-pin", "BREAK",
                           "unpinned policy: wrong code %r"
                           % (getattr(e, "code", type(e).__name__),))
    else:
        return _record("policy-pin", "BREAK",
                       "appraisal under unpinned policy accepted")
    try:
        tv.appraise(ev, [], pol, _pins(tv, pol, digest="00" * 32))
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-policy-drift":
            return _record("policy-pin", "BREAK",
                           "drifted pin: wrong code %r"
                           % (getattr(e, "code", type(e).__name__),))
    else:
        return _record("policy-pin", "BREAK",
                       "appraisal under drifted pin accepted")
    ear = tv.appraise(ev, [], pol, _pins(tv, pol))
    if ear["policy_digest"] != pol.digest:
        return _record("policy-pin", "BREAK",
                       "EAR does not bind the policy digest")
    _record("policy-pin", "HELD",
            "unpinned/drifted refuse LOUD; pinned appraises and binds")


# ---------------------------------------------------------------------------
# 6. require_affirmed gate: affirmed passes; contraindicated ALWAYS
#    refuses (exceptions never upgrade it); insufficient needs a live
#    governed exception or refuses.
# ---------------------------------------------------------------------------

def p_require_affirmed_gate():
    tv = _needs_module("require-affirmed")
    if tv is None:
        return
    _register_test_scheme(tv)

    def _store_with(live=True, expired=False):
        from gov import governed_exceptions as ge
        reg = ge.CheckRegistry()
        reg.register("SAS_TRUSTVEC_ACCEPT_RISK", "trust-vector accept risk",
                     "attestation", "medium",
                     "accept an insufficient trust vector at operator risk",
                     ["policy"])
        store = ge.ExceptionStore(reg)
        store.set_approvers(["op-1"])
        now = time.time()
        if live or expired:
            store.grant(
                "SAS_TRUSTVEC_ACCEPT_RISK", ("policy", "probe-policy"),
                "accepting insufficient vector at operator risk for probe",
                "op-1", now + 3600, now - 5, now=now)
            if expired:
                # Grant live, then let the clock do its job: expiry is
                # never granted in the past, it is swept.
                store.sweep_expired(now=now + 7200)
        return store

    # (a) fully affirmed ear passes
    ev = _evidence(tv)
    pol = _policy(tv, trust_anchors={"prod-a": "key-1"})
    ends = [tv.endorse(ev, "fw_digest", "ab" * 32, "endorser-1"),
            tv.endorse(ev, "fw_version", "1.2.3", "endorser-1")]
    ear_ok = tv.appraise(ev, ends, pol, _pins(tv, pol))
    if ear_ok["overall"] != "affirmed":
        return _record("require-affirmed", "BREAK",
                       "expected affirmed ear, got %r" % (ear_ok["vector"],))
    res = tv.require_affirmed(ear_ok)
    if res.get("status") != "affirmed":
        return _record("require-affirmed", "BREAK",
                       "affirmed ear did not pass the gate")

    # (b) contraindicated ear refuses, even WITH a live exception
    bad_end = tv.endorse(ev, "fw_digest", "ff" * 32, "endorser-1")
    ear_bad = tv.appraise(ev, [bad_end], pol, _pins(tv, pol))
    for store in (None, _store_with(live=True)):
        try:
            tv.require_affirmed(ear_bad,
                                exception_store=store)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", "") != \
                    "trustvec-appraisal-contraindicated":
                return _record("require-affirmed", "BREAK",
                               "contraindicated: wrong code %r"
                               % (getattr(e, "code",
                                          type(e).__name__),))
        else:
            return _record("require-affirmed", "BREAK",
                           "contraindicated ear passed the gate "
                           "(exception must never upgrade it)")

    # (c) insufficient ear without a store refuses
    ear_ins = tv.appraise(ev, [], pol, _pins(tv, pol))
    try:
        tv.require_affirmed(ear_ins)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-appraisal-insufficient":
            return _record("require-affirmed", "BREAK",
                           "insufficient without store: wrong code %r"
                           % (getattr(e, "code", type(e).__name__),))
    else:
        return _record("require-affirmed", "BREAK",
                       "insufficient ear passed without an exception")

    # (d) insufficient ear, store but no covering exception refuses
    try:
        tv.require_affirmed(ear_ins,
                            exception_store=_store_with(live=False))
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-no-covering-exception":
            return _record("require-affirmed", "BREAK",
                           "no covering exception: wrong code %r"
                           % (getattr(e, "code", type(e).__name__),))
    else:
        return _record("require-affirmed", "BREAK",
                       "insufficient ear passed with no covering exception")

    # (e) insufficient ear + live exception => accepted-at-risk, vector
    # unchanged (SKIPPED-shaped, never PASSED/affirmed)
    res = tv.require_affirmed(ear_ins,
                              exception_store=_store_with(live=True))
    if res.get("status") != "accepted-at-risk" or \
            "exception_digest" not in res:
        return _record("require-affirmed", "BREAK",
                       "live exception did not yield accepted-at-risk: %r"
                       % (res,))
    if res["ear"]["vector"] != ear_ins["vector"]:
        return _record("require-affirmed", "BREAK",
                       "exception changed the vector -- it must stay "
                       "insufficient")

    # (f) expired covering exception refuses LOUD (never silent fallthrough)
    try:
        tv.require_affirmed(ear_ins,
                            exception_store=_store_with(live=False,
                                                        expired=True))
    except Exception:  # noqa: BLE001
        pass
    else:
        return _record("require-affirmed", "BREAK",
                       "expired exception silently accepted")
    _record("require-affirmed", "HELD",
            "affirmed passes; contraindicated never upgraded; insufficient "
            "needs a live exception (accepted-at-risk, vector unchanged); "
            "expired is loud")


# ---------------------------------------------------------------------------
# 7. Scheme plugin registry: duplicates refused; custom appraise hook
#    dispatches per scheme; bad hook output fails closed.
# ---------------------------------------------------------------------------

def p_scheme_plugin_registry():
    tv = _needs_module("scheme-registry")
    if tv is None:
        return
    _register_test_scheme(tv)
    dup = tv.SchemeDescriptor(
        scheme_id="test-firmware/v1",
        claim_grammar={"fw_digest": "digest"},
        dimensions=[])
    try:
        tv.register_scheme(dup)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-scheme-duplicate":
            return _record("scheme-registry", "BREAK",
                           "duplicate scheme: wrong code %r"
                           % (getattr(e, "code", type(e).__name__),))
    else:
        return _record("scheme-registry", "BREAK",
                       "duplicate scheme registration accepted")

    def _hook(evidence, endorsements, policy, grade):
        # A scheme-specific rule the built-ins cannot express.
        vec = grade(evidence, endorsements, policy)
        if evidence.claims.get("debug_fuse") is True:
            vec = dict(vec)
            vec["config_integrity"] = "contraindicated"
        return vec

    hooked = tv.SchemeDescriptor(
        scheme_id="test-hooked/v1",
        claim_grammar={"fw_digest": "digest", "debug_fuse": "bool"},
        dimensions=[
            {"name": "sw_integrity", "rule": "endorsed-match",
             "claims": ["fw_digest"]},
            {"name": "config_integrity", "rule": "operator-trust",
             "claims": ["debug_fuse"]},
        ],
        appraise_fn=_hook)
    try:
        tv.register_scheme(hooked)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-scheme-duplicate":
            raise
    ev = tv.submit_evidence("test-hooked/v1",
                            {"fw_digest": "ab" * 32, "debug_fuse": True},
                            "prod-a")
    pol_doc = {"format": "sasanam-appraisal-policy/v1",
               "policy_id": "hook-policy", "scheme_id": "test-hooked/v1",
               "trust_anchors": {"prod-a": "key-1"}}
    pol = tv.compile_policy(pol_doc)
    ear = tv.appraise(ev, [], pol, _pins(tv, pol))
    if ear["vector"].get("config_integrity") != "contraindicated":
        return _record("scheme-registry", "BREAK",
                       "custom appraise hook did not dispatch: %r"
                       % (ear["vector"],))

    def _bad_hook(evidence, endorsements, policy, grade):
        return {"sw_integrity": "maybe"}

    bad = tv.SchemeDescriptor(
        scheme_id="test-badhook/v1",
        claim_grammar={"fw_digest": "digest"},
        dimensions=[{"name": "sw_integrity", "rule": "advisory",
                     "claims": ["fw_digest"]}],
        appraise_fn=_bad_hook)
    try:
        tv.register_scheme(bad)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-scheme-duplicate":
            raise
    ev2 = tv.submit_evidence("test-badhook/v1",
                             {"fw_digest": "ab" * 32}, "prod-a")
    pol2_doc = {"format": "sasanam-appraisal-policy/v1",
                "policy_id": "badhook-policy",
                "scheme_id": "test-badhook/v1", "trust_anchors": {}}
    pol2 = tv.compile_policy(pol2_doc)
    try:
        tv.appraise(ev2, [], pol2, _pins(tv, pol2))
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", "") != "trustvec-evidence-invalid":
            return _record("scheme-registry", "BREAK",
                           "bad hook output: wrong code %r"
                           % (getattr(e, "code", type(e).__name__),))
    else:
        return _record("scheme-registry", "BREAK",
                       "bad hook output accepted silently")
    _record("scheme-registry", "HELD",
            "duplicates refused; custom hook dispatches; bad hook output "
            "fails closed")


# ---------------------------------------------------------------------------
# Depth-1 green checks: the governed-exceptions battery (the composition
# seam) must stay green.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        _record("green-skipped", "HELD", "GOV_SKIP_GREEN=1")
        return
    checks = [
        "evals/w285_exceptions_probes.py",
    ]
    for rel in checks:
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), rel)
        d = tempfile.mkdtemp(prefix="w287-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(m[-1]) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    p_vector_not_boolean()
    p_no_endorsement_insufficient()
    p_endorsement_must_be_independent()
    p_scheme_grammar_fail_closed()
    p_policy_pin_required()
    p_require_affirmed_gate()
    p_scheme_plugin_registry()
    _green_checks()

    nbreak = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    nheld = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    nerr = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("  [%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    print("w287_ear: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
