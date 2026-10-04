"""Break-first battery: first-class policy exceptions (wave-268).

Kyverno PolicyException shape (wave-267 prospectus, STEAL the tuple):
exceptions[] {policyName, ruleNames[], match.any/all, conditions,
expiresAt, compensatingValidations[]} with RBAC-gated authorship and
skip-attached-to-decision semantics (never a silent bypass).

Modes: ``GOV_POLICYEXC_IMPL=stub`` runs the probes against a permissive
stub that loads any wire and grants a skip whenever the policyName
matches -- no authorship check, no expiry, no match/condition/validation
evaluation, no exception identity attached (red phase: attack probes
MUST break). Default (module) runs them against
``gov.policy_exception`` (green phase: attacks MUST be refused with the
exact machine code, skip grants MUST carry exception identities,
controls MUST hold).

Depth-1 green check honoring ``GOV_SKIP_GREEN``; no in-repo git
subprocesses; stdlib only.
"""

import copy
import hashlib
import json
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w268-exception")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

MODE = os.environ.get("GOV_POLICYEXC_IMPL", "module")

try:
    from gov import ed25519
except Exception:
    ed25519 = None

try:
    from gov import decision_codes
except Exception:
    decision_codes = None

try:
    from gov import policy_exception as _pe
    HAVE_MODULE = True
except Exception:  # red phase: module not written yet
    _pe = None
    HAVE_MODULE = False

TAXONOMY_PIN = 1964 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

EXPECTED_CODES = (
    "exception-compensating-validation-failed",
    "exception-expired",
    "exception-granted-with-attribution",
    "exception-malformed",
    "exception-rule-skipped",
    "exception-unauthorized-authorship",
)

EVAL_START = "2026-10-01T12:00:00Z"


def _impl():
    if MODE == "stub":
        return _Stub()
    if not HAVE_MODULE:
        raise RuntimeError("module not present")
    return _pe


# ------------------------------------------------------------------
# Test signing material (deployment-owned keys, test-local only).
# ------------------------------------------------------------------

def _test_keys(keyid="test-key-1"):
    seed = ed25519.generate_seed()
    return {"seed": seed,
            "pub": ed25519.publickey(seed),
            "keyid": keyid}


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _exception_wire(keys, **over):
    body = {
        "kind": "sasanam.policy-exception/v1",
        "id": "exc-1",
        "policyName": "test-policy",
        "ruleNames": ["test.rule"],
        "match": {"any": [
            {"path": "principal.id", "op": "eq", "value": "agent-1"}]},
        "conditions": [],
        "expiresAt": "2027-01-01T00:00:00Z",
        "compensatingValidations": [
            {"name": "target-pinned",
             "check": {"path": "resource.target", "op": "startswith",
                       "value": "backup."}},
        ],
    }
    body.update(over)
    sig = ed25519.sign(keys["seed"], _canon(body))
    wire = dict(body)
    wire["signature"] = {"keyId": keys["keyid"], "sig": sig.hex()}
    return wire


def _ctx(**over):
    ctx = {"principal": {"id": "agent-1", "roles": ["ops"]},
           "action": "tool.call",
           "resource": {"tool": "db.dump", "target": "backup.east",
                        "class": "data"}}
    ctx.update(over)
    return ctx


def _trusted(keys):
    from gov.signing import Ed25519Verifier
    return {keys["keyid"]: Ed25519Verifier(keys["pub"], keys["keyid"])}


# ------------------------------------------------------------------
# Permissive stub (red phase): loads anything, grants a skip whenever
# the policyName matches -- ignoring ruleNames, match, conditions,
# validations, expiry, authorship -- and attaches NO identity.
# ------------------------------------------------------------------

class _FakeExc(object):
    def __init__(self, wire):
        self.wire = wire
        self.id = wire.get("id", "exc-?")
        self.policy_name = wire.get("policyName")
        self.rule_names = list(wire.get("ruleNames", []))


class _FakeDecision(object):
    def __init__(self, kind, exception_ids=(), detail=()):
        self.kind = kind
        self.exception_ids = list(exception_ids)
        self.detail = list(detail)


class _FakeReport(object):
    def __init__(self, exceptions):
        self.exceptions = exceptions
        self.checked = ["stub"]
        self.out_of_scope = ["stub"]
        self.refused = []


class _Stub(object):
    def load_exceptions(self, wires, trusted_authors, eval_start):
        return _FakeReport([_FakeExc(w) for w in wires])

    def apply(self, policy_name, rule_name, context, eval_start,
              exceptions):
        # Maximally permissive: any loaded exception grants a skip,
        # regardless of policy/rule binding, match, conditions,
        # validations, expiry, or authorship. No identity attached.
        if exceptions:
            return _FakeDecision("skip", [], [("stub-grant", None)])
        return _FakeDecision("no-skip")

    def rule_outcome(self, rule_failed, decision):
        if decision.kind == "skip":
            return {"outcome": "skip", "exception_ids": []}
        return {"outcome": "fail" if rule_failed else "pass"}

    def to_skip_record(self, decision, policy_name, rule_name, context,
                       eval_start):
        return {"code": "exception-granted-with-attribution",
                "exception_ids": list(decision.exception_ids),
                "policy": policy_name, "rule": rule_name,
                "digest": "0" * 64}

    def canonical_bytes(self, obj):
        return _canon(obj)


class PolicyExceptionError(Exception):
    code = "exception-malformed"


# ------------------------------------------------------------------
# Probe harness.
# ------------------------------------------------------------------

RESULTS = []


def probe(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


def _run_all():
    impl = _impl()
    out = []
    for name, fn in RESULTS:
        try:
            verdict, note = fn(impl)
        except Exception as exc:  # noqa: BLE001
            verdict, note = "ERROR", "%r" % (exc,)
        out.append((name, verdict, note))
    return out


def _expect(out, mode):
    bad = []
    for name, verdict, note in out:
        if name.startswith("attack_"):
            want = "BREAK" if mode == "stub" else "HELD"
        else:
            want = "HELD"
        if verdict != want:
            bad.append((name, verdict, want, note))
    return bad


# ------------------------------------------------------------------
# Attack probes (must BREAK on stub, HELD on module).
# ------------------------------------------------------------------

@probe("attack_p1_silent_skip_identity")
def _p1(impl):
    """A granted skip must carry the exception identity -- no silent bypass."""
    keys = _test_keys()
    rep = impl.load_exceptions([_exception_wire(keys)], _trusted(keys),
                               EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    rec = impl.to_skip_record(d, "test-policy", "test.rule", _ctx(),
                              EVAL_START)
    if d.kind == "skip" and rec.get("exception_ids") == ["exc-1"]:
        return "HELD", "skip carries identity"
    return "BREAK", "skip without identity: %r" % (rec.get("exception_ids"),)


@probe("attack_p2_expired_exception")
def _p2(impl):
    """An expired exception must NOT grant -- fail closed toward enforcement."""
    keys = _test_keys()
    wire = _exception_wire(keys, expiresAt="2025-01-01T00:00:00Z")
    rep = impl.load_exceptions([wire], _trusted(keys), EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    out = impl.rule_outcome(True, d)
    if d.kind == "no-skip" and out["outcome"] == "fail":
        return "HELD", "expired exception excluded"
    return "BREAK", "expired exception granted skip"


@probe("attack_p3_compensating_validation_fails")
def _p3(impl):
    """Failed compensating validation must refuse the exception."""
    keys = _test_keys()
    rep = impl.load_exceptions([_exception_wire(keys)], _trusted(keys),
                               EVAL_START)
    bad_ctx = _ctx(resource={"tool": "db.dump", "target": "prod.west",
                             "class": "data"})
    d = impl.apply("test-policy", "test.rule", bad_ctx, EVAL_START,
                   rep.exceptions)
    codes = [c for c, _ in d.detail]
    if d.kind == "no-skip" and\
            "exception-compensating-validation-failed" in codes:
        return "HELD", "validation failure refused"
    return "BREAK", "skip granted despite failed validation"


@probe("attack_p4_forged_authorship")
def _p4(impl):
    """An exception signed by an untrusted key must be refused loudly."""
    keys = _test_keys()
    rogue = _test_keys("rogue-key")
    wire = _exception_wire(rogue)
    try:
        impl.load_exceptions([wire], _trusted(keys), EVAL_START)
    except Exception as exc:
        if getattr(exc, "code", "") == "exception-unauthorized-authorship":
            return "HELD", "rogue authorship refused"
        return "ERROR", "wrong code: %r" % getattr(exc, "code", None)
    return "BREAK", "rogue authorship loaded"


@probe("attack_p5_tampered_body")
def _p5(impl):
    """Body tampered after sealing must fail authorship verification."""
    keys = _test_keys()
    wire = _exception_wire(keys)
    wire["ruleNames"] = ["*"]
    try:
        impl.load_exceptions([wire], _trusted(keys), EVAL_START)
    except Exception as exc:
        if getattr(exc, "code", "") == "exception-unauthorized-authorship":
            return "HELD", "tamper refused"
        return "ERROR", "wrong code: %r" % getattr(exc, "code", None)
    return "BREAK", "tampered wire loaded"


@probe("attack_p6_malformed_wire")
def _p6(impl):
    """Missing ruleNames must be malformed, never half-loaded."""
    keys = _test_keys()
    wire = _exception_wire(keys)
    del wire["ruleNames"]
    body = {k: v for k, v in wire.items() if k != "signature"}
    wire["signature"] = {"keyId": keys["keyid"],
                         "sig": ed25519.sign(keys["seed"],
                                             _canon(body)).hex()}
    try:
        impl.load_exceptions([wire], _trusted(keys), EVAL_START)
    except Exception as exc:
        if getattr(exc, "code", "") == "exception-malformed":
            return "HELD", "malformed refused"
        return "ERROR", "wrong code: %r" % getattr(exc, "code", None)
    return "BREAK", "malformed wire loaded"


@probe("attack_p7_bad_expiresAt")
def _p7(impl):
    """Unparseable expiresAt must be malformed, never 'valid forever'."""
    keys = _test_keys()
    try:
        impl.load_exceptions([_exception_wire(keys, expiresAt="soon")],
                             _trusted(keys), EVAL_START)
    except Exception as exc:
        if getattr(exc, "code", "") == "exception-malformed":
            return "HELD", "bad expiresAt refused"
        return "ERROR", "wrong code: %r" % getattr(exc, "code", None)
    return "BREAK", "bad expiresAt loaded"


@probe("attack_p8_match_any_no_match")
def _p8(impl):
    """match.any filters that do not match the context grant nothing."""
    keys = _test_keys()
    wire = _exception_wire(
        keys, match={"any": [
            {"path": "principal.id", "op": "eq", "value": "someone-else"}]})
    rep = impl.load_exceptions([wire], _trusted(keys), EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    if d.kind == "no-skip":
        return "HELD", "non-matching filter grants nothing"
    return "BREAK", "non-matching filter granted skip"


@probe("attack_p9_conditions_fail")
def _p9(impl):
    """match passes but conditions fail -> no skip."""
    keys = _test_keys()
    wire = _exception_wire(
        keys, conditions=[
            {"path": "resource.class", "op": "eq", "value": "credential"}])
    rep = impl.load_exceptions([wire], _trusted(keys), EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    if d.kind == "no-skip":
        return "HELD", "failed conditions grant nothing"
    return "BREAK", "failed conditions granted skip"


@probe("attack_p10_unknown_dsl_op")
def _p10(impl):
    """Unknown subset-DSL op must be malformed at load, never ignored."""
    keys = _test_keys()
    try:
        impl.load_exceptions(
            [_exception_wire(
                keys, conditions=[
                    {"path": "resource.class", "op": "regex",
                     "value": ".*"}])],
            _trusted(keys), EVAL_START)
    except Exception as exc:
        if getattr(exc, "code", "") == "exception-malformed":
            return "HELD", "unknown op refused"
        return "ERROR", "wrong code: %r" % getattr(exc, "code", None)
    return "BREAK", "unknown op loaded"


@probe("attack_p11_eval_start_pinned")
def _p11(impl):
    """Expiry is evaluated against the pinned eval_start, never 'now'."""
    keys = _test_keys()
    # Expired at the pinned eval_start; a wall-clock 'now' would call it
    # valid. The implementation must use the pinned time.
    wire = _exception_wire(keys, expiresAt="2026-10-01T13:00:00Z")
    rep = impl.load_exceptions([wire], _trusted(keys),
                               "2026-10-01T14:00:00Z")
    d = impl.apply("test-policy", "test.rule", _ctx(),
                   "2026-10-01T14:00:00Z", rep.exceptions)
    if d.kind == "no-skip":
        return "HELD", "pinned time used for expiry"
    return "BREAK", "ambient time used for expiry"


@probe("attack_p12_wrong_policy")
def _p12(impl):
    """An exception for another policy must not apply."""
    keys = _test_keys()
    rep = impl.load_exceptions(
        [_exception_wire(keys, policyName="other-policy")],
        _trusted(keys), EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    if d.kind == "no-skip":
        return "HELD", "cross-policy exception ignored"
    return "BREAK", "cross-policy exception applied"


@probe("attack_p13_rule_not_listed")
def _p13(impl):
    """A rule not named in ruleNames must not be excepted."""
    keys = _test_keys()
    rep = impl.load_exceptions(
        [_exception_wire(keys, ruleNames=["test.other"])],
        _trusted(keys), EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    if d.kind == "no-skip":
        return "HELD", "unlisted rule not excepted"
    return "BREAK", "unlisted rule excepted"


# ------------------------------------------------------------------
# Control probes (must HELD on both stub and module).
# ------------------------------------------------------------------

@probe("control_c1_valid_grant_deterministic")
def _c1(impl):
    if MODE == "stub":
        return "HELD", "baseline: identity assertions are module-only"
    keys = _test_keys()
    rep = impl.load_exceptions([_exception_wire(keys)], _trusted(keys),
                               EVAL_START)
    d1 = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                    rep.exceptions)
    d2 = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                    rep.exceptions)
    rec = impl.to_skip_record(d1, "test-policy", "test.rule", _ctx(),
                              EVAL_START)
    if d1.kind == "skip" and d1.exception_ids == d2.exception_ids and\
            rec.get("exception_ids") == d1.exception_ids:
        return "HELD", "grant deterministic, identities attached"
    return "BREAK", "grant unstable: %r" % (d1.exception_ids,)


@probe("control_c2_no_exceptions")
def _c2(impl):
    rep = impl.load_exceptions([], {}, EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    out = impl.rule_outcome(False, d)
    if d.kind == "no-skip" and out["outcome"] == "pass":
        return "HELD", "empty exception set is a no-op"
    return "BREAK", "empty set changed the outcome"


@probe("control_c3_multiple_attach_sorted")
def _c3(impl):
    if MODE == "stub":
        return "HELD", "baseline: identity assertions are module-only"
    keys = _test_keys()
    w1 = _exception_wire(keys, id="exc-b")
    w2 = _exception_wire(keys, id="exc-a")
    rep = impl.load_exceptions([w1, w2], _trusted(keys), EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    if d.kind == "skip" and d.exception_ids == ["exc-a", "exc-b"]:
        return "HELD", "all identities attached, sorted"
    return "BREAK", "attachment wrong: %r" % (d.exception_ids,)


@probe("control_c4_fail_without_exception")
def _c4(impl):
    """Structural composition: any rule fail with no granted exception
    is unsuccessful -- the exception path never manufactures success."""
    rep = impl.load_exceptions([], {}, EVAL_START)
    d = impl.apply("test-policy", "test.rule", _ctx(), EVAL_START,
                   rep.exceptions)
    out = impl.rule_outcome(True, d)
    if out["outcome"] == "fail":
        return "HELD", "fail stays fail"
    return "BREAK", "fail converted: %r" % (out["outcome"],)


@probe("control_c5_behsig_hook_loud_skip")
def _c5(impl):
    """match_pack with canonical exceptions: a granted skip emits NO
    alert and journals exception-rule-skipped WITH the exception ids.
    Stub mode: not applicable (no module hook) -> BASELINE."""
    if MODE == "stub" or not HAVE_MODULE:
        return "HELD", "baseline: hook is module-only"
    from gov import behavioral_sig_packs as bsp
    keys = _test_keys()
    exc = _exception_wire(keys, policyName="test-core",
                          ruleNames=["test.cred_rule"],
                          match={"any": [
                              {"path": "principal.id", "op": "eq",
                               "value": "agent-1"}]},
                          compensatingValidations=[])
    rep = impl.load_exceptions([exc], _trusted(keys), EVAL_START)
    pack_spec = {
        "pack_format": "sasanam.behavioral-sig-pack/v1",
        "pack_id": "test-core",
        "pack_version": "1.0.0",
        "engine_version": "1",
        "macros": [], "lists": [],
        "rules": [{
            "name": "test.cred_rule",
            "desc": "credential class fires",
            "condition": {"op": "eq", "field": "arg.class",
                          "value": "credential"},
            "output": "cred", "priority": "high", "enabled": True,
            "source": "agent_event", "tags": ["maturity_stable"],
            "maturity": "stable", "exceptions": [],
            "capture": {"window_events": 2}, "params": {},
        }],
    }
    env = {"pack": pack_spec,
           "signatures": [{"keyid": keys["keyid"],
                           "sig": ed25519.sign(
                               keys["seed"], _canon(pack_spec)).hex()}]}
    pack_bytes = json.dumps(env, sort_keys=True).encode()
    records = []

    def _j(rec):
        records.append(rec)
        return rec

    pack = bsp.load_pack(pack_bytes,
                         trust_keys={keys["keyid"]: keys["pub"]},
                         journal=_j)
    ev = bsp.enrich_event({
        "ts": 1000.0, "actor_id": "agent-1", "session_id": "s1",
        "tool": "db.dump", "target": "prod",
        "args": {"password": "hunter2"}})
    alerts = bsp.match_pack(pack, [ev], journal=_j,
                            policy_exceptions=rep.exceptions,
                            eval_start=EVAL_START)
    skips = [e for e in records
             if e.get("code") == "exception-rule-skipped"]
    if alerts == [] and skips and skips[0].get("exception_ids") == ["exc-1"]:
        return "HELD", "loud skip with identity, no alert"
    return "BREAK", "alerts=%d skips=%r" % (len(alerts), skips)


@probe("control_c6_pin_check")
def _c6(impl):
    if MODE == "stub" or decision_codes is None:
        return "HELD", "baseline: pin is module-only"
    missing = [c for c in EXPECTED_CODES
               if c not in decision_codes.TAXONOMY]
    if missing:
        return "BREAK", "missing codes: %r" % (missing,)
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        return "BREAK", "pin %d != %d" % (len(decision_codes.TAXONOMY),
                                          TAXONOMY_PIN)
    return "HELD", "taxonomy pin 1299"


# ------------------------------------------------------------------
# Green check (depth-1) + main.
# ------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    results = []
    adj = os.path.join(REPO_ROOT, "evals", "w267_behsig_probes.py")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_BEHSIG_UNDER_TEST"] = "module"
    tmp = "/var/tmp/g268green"
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, adj], capture_output=True, text=True,
            env=env, timeout=600, cwd=REPO_ROOT)
        lines = p.stdout.splitlines()
        # Dual-form (D8): match the canonical "[BREAK]"/"[ERROR]"
        # probe lines AND the legacy "BREAK "/"ERROR " shape, so
        # this check keeps working whether or not the adjacent
        # battery has been summary-form migrated.
        bad_lines = [l for l in lines
                     if l.startswith(("[BREAK]", "BREAK ",
                                      "MISMATCH",
                                      "[ERROR]", "ERROR "))]
        ok = not bad_lines and p.returncode == 0
        note = "rc=%d bad=%d" % (p.returncode, len(bad_lines))
        results.append(("green-check_w267_behsig_probes",
                        "HELD" if ok else "BREAK", note))
    except Exception as exc:  # noqa: BLE001
        results.append(("green-check_w267_behsig_probes", "ERROR",
                        "%r" % (exc,)))
    return results



# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): probes record
# HELD/FAIL/ERROR and the depth-1 green checks record HELD/SKIPPED/
# BREAK/ERROR; canonical emission is BREAK/HELD/ERROR/SKIP, mapped
# red-first (FAIL->BREAK, SKIPPED->SKIP). The green-check pid is renamed
# value-only ("green-check:<adj>" -> "green-check_<adj>") to stay inside
# the pid character class. Probe logic, verdict computation and count
# code are untouched -- only the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}

def main():
    out = _run_all()
    # Determinism: run twice, verdicts must agree.
    out2 = _run_all()
    det = all(a[1] == b[1] for a, b in zip(out, out2))
    green = _green_check()
    print("MODE=%s" % MODE)
    final = [(n, _VERDICT_MAP[v], note) for n, v, note in out]
    final += [(n, _VERDICT_MAP[v], note) for n, v, note in green]
    probe_lines.emit(final)
    brk_c = sum(1 for _, v, _ in final if v == "BREAK")
    held_c = sum(1 for _, v, _ in final if v == "HELD")
    err_c = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk_c, held_c, err_c)
    if not _coh_ok:
        print("coherence-WARNING: %s" % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk_c, held_c, err_c))
    print("RESULT deterministic=%s probes=%d" % (det, len(out)))
    bad = _expect(out, MODE)
    for name, verdict, want, note in bad:
        print("MISMATCH %s got=%s want=%s %s" % (name, verdict, want,
                                                 note))
    failed = bool(bad) or not det or\
        any(v not in ("HELD", "SKIPPED") for _, v, _ in green)
    print("RESULT %s" % ("FAIL" if failed else "OK"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
