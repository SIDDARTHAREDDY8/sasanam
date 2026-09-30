#!/usr/bin/env python3
"""Wave-224 lane B: quarantine-until-decision admission.

ADAPT of the harbor-satellite ADR-0009 rule (re-derived; no upstream
text copied): ORAS copy hooks are NOT the admission boundary. An
artifact is copied into QUARANTINE first and enters the trusted store
ONLY after the final admission decision succeeds. Copying != admitting.

Seams under test:
* gov/quarantine.py -- Quarantine.stage(artifact_bytes, artifact_digest)
  digest-verified at stage time (quarantine-digest-mismatch);
  Quarantine.admit(staged, admission_policy, *, bundle_format,
  signature, inspection, ...) runs gov/admission.py + gov/gate_algebra.py at
  decision time and moves the staged bytes into the trusted store
  ONLY on success (refusal codes propagate by name, never laundered);
  Quarantine.reject(staged, reason) removes with quarantine-rejected
  carrying the reason; Quarantine.admit_to_trust(...) always refuses
  quarantine-bypass-refused -- the bypass path cannot exist silently;
  Quarantine.in_trusted_store(digest) / trusted_payload(digest)
  observe the trusted store.
* Legacy pin: gov/admission.py AdmissionPolicy.admit works without
  the quarantine (base behavior byte-identical).

Attack shapes: digest mismatch at stage; issuer/signature forgery at
decision time; severity-threshold breach; conjunction refusal;
direct-to-trust bypass; envelope override at admit time (payload /
payload_digest swapped after staging); double-admit; foreign handle.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-223 HEAD
28db79fcbf5b8415cc0ba2b20e48d52530cfcc81.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP for the
quarantine probes; the legacy-admission pin is verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g224q
  TMPDIR=/var/tmp/g224q ~/workspace/.gov-venv/bin/python evals/w224_quar_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g224q-u \
      ~/workspace/.gov-venv/bin/python evals/w224_quar_probes.py
"""

import hashlib
import os
import secrets
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w224-quar-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g224q-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import quarantine as qr  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    qr = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

from gov import admission as adm  # noqa: E402 - present on base
from gov import gate_algebra as gal  # noqa: E402 - present on base
from gov import ed25519 as _ed  # noqa: E402 - present on base

_RESULTS = []
_PROBE_FNS = {}

_DIGEST_X = "dd" * 32  # 64-hex stand-in digests

# Code vocabulary (string literals: the battery must run red-first on
# the pristine base where gov/quarantine.py does not exist).
_C_DIGEST_MISMATCH = "quarantine-digest-mismatch"
_C_UNKNOWN_STAGED = "quarantine-unknown-staged"
_C_REJECTED = "quarantine-rejected"
_C_BYPASS_REFUSED = "quarantine-bypass-refused"
_C_OVERRIDE_REFUSED = "quarantine-envelope-override-refused"
_C_NOT_ADMITTED = "quarantine-not-admitted"


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _break(name, detail=""):
    _record(name, "BREAK", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


def _code_of(exc):
    return getattr(exc, "code", type(exc).__name__)


def _expect_refusal(name, code, fn):
    """The attack shape must be refused with exactly this named code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - code is the contract
        got = _code_of(exc)
        if got == code:
            _held(name, "refused with %s" % got)
        else:
            _break(name, "refused with %s, expected %s" % (got, code))
        return
    _break(name, "NOT refused (expected %s)" % code)


def _keypair():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _sign(seed, digest):
    return _ed.sign(seed, adm.signing_bytes(digest))


def _payload_and_digest(payload):
    digest = hashlib.sha256(payload).hexdigest()
    return payload, digest


def _policy_for(digest, seed, bundle_format="evidence-bundle/v1",
                require_inspection=False):
    _seed, pub = _keypair() if seed is None else (seed, _ed.publickey(seed))
    return adm.AdmissionPolicy(digest, pub, bundle_format,
                               require_inspection=require_inspection), seed


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("staged-not-in-trusted-store")
def _p_staged_not_trusted():
    # Copying != admitting: a staged artifact must NOT appear in the
    # trusted store until the admission decision succeeds.
    if not _IMPORT_OK:
        return _gap("staged-not-in-trusted-store")
    payload, digest = _payload_and_digest(b"quarantine-me")
    q = qr.Quarantine()
    staged = q.stage(payload, digest)
    if q.in_trusted_store(digest):
        return _break("staged-not-in-trusted-store",
                      "staged artifact visible in trusted store pre-decision")
    try:
        q.trusted_payload(digest)
    except Exception as exc:
        if _code_of(exc) != _C_NOT_ADMITTED:
            return _break("staged-not-in-trusted-store",
                          "wrong code for unadmitted payload: %s"
                          % _code_of(exc))
    else:
        return _break("staged-not-in-trusted-store",
                      "trusted_payload returned bytes pre-decision")
    if staged.digest != digest:
        return _break("staged-not-in-trusted-store",
                      "staged handle does not bind the staged digest")
    _held("staged-not-in-trusted-store",
          "staged bytes quarantined, trusted store empty")


@_probe("stage-digest-mismatch-refused")
def _p_digest_mismatch():
    # Lying about the digest at stage time must refuse loudly.
    if not _IMPORT_OK:
        return _gap("stage-digest-mismatch-refused")
    q = qr.Quarantine()
    _expect_refusal("stage-digest-mismatch-refused", _C_DIGEST_MISMATCH,
                    lambda: q.stage(b"real-bytes", _DIGEST_X))
    # Non-hex digests are malformed input, not a recomputation
    # mismatch -- the repo convention (gov/admission.py _check_shape:
    # non-hex payload_digest -> admission-malformed).
    _expect_refusal("stage-digest-mismatch-refused", "quarantine-malformed",
                    lambda: q.stage(b"real-bytes", "zz" * 32))
    # Tampered byte-for-byte (one bit) must also refuse.
    _expect_refusal("stage-digest-mismatch-refused", _C_DIGEST_MISMATCH,
                    lambda: q.stage(b"real-bytes!",
                                     hashlib.sha256(b"real-bytes").hexdigest()))


@_probe("successful-admission-moves-to-trust")
def _p_admit_success():
    if not _IMPORT_OK:
        return _gap("successful-admission-moves-to-trust")
    payload, digest = _payload_and_digest(b"admit-me-v1")
    seed, pub = _keypair()
    policy = adm.AdmissionPolicy(digest, pub, "evidence-bundle/v1")
    q = qr.Quarantine()
    staged = q.stage(payload, digest)
    record = q.admit(staged, policy, bundle_format="evidence-bundle/v1",
                     signature=_sign(seed, digest))
    if not (isinstance(record, dict) and record.get("admissible") is True):
        return _break("successful-admission-moves-to-trust",
                      "admit did not return an admissible record: %r"
                      % (record,))
    if not q.in_trusted_store(digest):
        return _break("successful-admission-moves-to-trust",
                      "admitted artifact missing from trusted store")
    if q.trusted_payload(digest) != payload:
        return _break("successful-admission-moves-to-trust",
                      "trusted payload bytes differ from staged bytes")
    if staged.digest in q.quarantined_digests():
        return _break("successful-admission-moves-to-trust",
                      "admitted artifact still listed as staged")
    _held("successful-admission-moves-to-trust",
          "admit moved staged bytes to trust; handle consumed")


@_probe("failed-admission-keeps-out")
def _p_admit_failure():
    # A failed decision must keep the artifact OUT of the trusted store
    # (fail closed) while leaving it staged for triage.
    if not _IMPORT_OK:
        return _gap("failed-admission-keeps-out")
    payload, digest = _payload_and_digest(b"forged-sig-payload")
    seed, pub = _keypair()
    other_seed, _other_pub = _keypair()
    policy = adm.AdmissionPolicy(digest, pub, "evidence-bundle/v1")
    q = qr.Quarantine()
    staged = q.stage(payload, digest)
    _expect_refusal("failed-admission-keeps-out",
                    "admission-issuer-untrusted",
                    lambda: q.admit(staged, policy,
                                    bundle_format="evidence-bundle/v1",
                                    signature=_sign(other_seed, digest)))
    if q.in_trusted_store(digest):
        return _break("failed-admission-keeps-out",
                      "refused artifact entered the trusted store")
    if staged.digest not in q.quarantined_digests():
        return _break("failed-admission-keeps-out",
                      "refused artifact was dropped from quarantine")
    _held("failed-admission-keeps-out",
          "refused with admission-issuer-untrusted; stays staged, out of trust")


@_probe("reject-removes-with-reason")
def _p_reject():
    if not _IMPORT_OK:
        return _gap("reject-removes-with-reason")
    payload, digest = _payload_and_digest(b"reject-me")
    q = qr.Quarantine()
    staged = q.stage(payload, digest)
    try:
        q.reject(staged, "analyst triage: known-bad source")
    except Exception as exc:
        if _code_of(exc) != _C_REJECTED:
            return _break("reject-removes-with-reason",
                          "wrong code: %s" % _code_of(exc))
        if "known-bad source" not in str(exc):
            return _break("reject-removes-with-reason",
                          "refusal does not carry the reason: %s" % exc)
    else:
        return _break("reject-removes-with-reason",
                      "reject did not raise quarantine-rejected")
    if staged.digest in q.quarantined_digests():
        return _break("reject-removes-with-reason",
                      "rejected artifact still staged")
    _expect_refusal("reject-removes-with-reason", _C_UNKNOWN_STAGED,
                    lambda: q.admit(staged, None))
    _held("reject-removes-with-reason",
          "rejected with reason; handle dead afterwards")


@_probe("admit-to-trust-bypass-refused")
def _p_bypass():
    # The bypass path exists only to refuse loudly -- it can never
    # silently admit.
    if not _IMPORT_OK:
        return _gap("admit-to-trust-bypass-refused")
    payload, digest = _payload_and_digest(b"bypass-me")
    seed, _pub = _keypair()
    policy = adm.AdmissionPolicy(digest, _ed.publickey(seed),
                                 "evidence-bundle/v1")
    q = qr.Quarantine()
    envelope = {"format": "evidence-bundle/v1", "payload_digest": digest,
                "signature": _sign(seed, digest), "payload": payload}
    _expect_refusal("admit-to-trust-bypass-refused", _C_BYPASS_REFUSED,
                    lambda: q.admit_to_trust(envelope, policy))
    _expect_refusal("admit-to-trust-bypass-refused", _C_BYPASS_REFUSED,
                    lambda: q.admit_to_trust())
    if q.in_trusted_store(digest):
        return _break("admit-to-trust-bypass-refused",
                      "bypass attempt admitted bytes to trust")
    _held("admit-to-trust-bypass-refused",
          "admit_to_trust refuses loudly; nothing admitted")


@_probe("refusal-codes-propagate-by-name")
def _p_codes_propagate():
    # No code laundering: the exact refusal code from the admission
    # machinery must reach the caller.
    if not _IMPORT_OK:
        return _gap("refusal-codes-propagate-by-name")
    payload, digest = _payload_and_digest(b"code-propagation")
    seed, pub = _keypair()
    other_seed, other_pub = _keypair()
    q = qr.Quarantine()

    def _fresh():
        return q.stage(payload, digest)

    # 1. admission-format-unknown.
    policy = adm.AdmissionPolicy(digest, pub, "evidence-bundle/v1")
    _expect_refusal("refusal-codes-propagate-by-name",
                    "admission-format-unknown",
                    lambda: q.admit(_fresh(), policy, bundle_format="wrong/v9",
                                    signature=_sign(seed, digest)))
    # 2. admission-unverifiable (unsigned).
    _expect_refusal("refusal-codes-propagate-by-name",
                    "admission-unverifiable",
                    lambda: q.admit(_fresh(), policy,
                                    bundle_format="evidence-bundle/v1",
                                    signature=None))
    # 3. admission-conjunction-refused with member attribution.
    conj = gal.PolicyConjunction(
        adm.AdmissionPolicy("00" * 32, pub, "evidence-bundle/v1"),
        adm.AdmissionPolicy("ff" * 32, pub, "evidence-bundle/v1"))
    try:
        q.admit(_fresh(), conj, bundle_format="evidence-bundle/v1",
                signature=_sign(seed, digest))
    except Exception as exc:
        if _code_of(exc) != "admission-conjunction-refused":
            return _break("refusal-codes-propagate-by-name",
                          "conjunction refused with %s" % _code_of(exc))
        members = getattr(exc, "member_results", [])
        if len(members) != 2 or getattr(exc, "refused_count", 0) != 2:
            return _break("refusal-codes-propagate-by-name",
                          "member attribution lost: %r" % (members,))
    else:
        return _break("refusal-codes-propagate-by-name",
                      "conjunction admitted despite both members refusing")
    # 4. admission-severity-exceeded (fail closed on over-threshold).
    sev = gal.SeverityGate(
        adm.AdmissionPolicy(digest, pub, "evidence-bundle/v1"), "high")
    try:
        q.admit(_fresh(), sev, bundle_format="evidence-bundle/v1",
                signature=_sign(seed, digest),
                findings=[{"id": "f1", "severity": "critical"}])
    except Exception as exc:
        if _code_of(exc) != "admission-severity-exceeded":
            return _break("refusal-codes-propagate-by-name",
                          "severity gate refused with %s" % _code_of(exc))
    else:
        return _break("refusal-codes-propagate-by-name",
                      "over-threshold findings admitted")
    # 5. admission-severity-unverifiable (unrated findings fail closed).
    try:
        q.admit(_fresh(), sev, bundle_format="evidence-bundle/v1",
                signature=_sign(seed, digest),
                findings=[{"id": "f2", "severity": "unknown-x"}])
    except Exception as exc:
        if _code_of(exc) != "admission-severity-unverifiable":
            return _break("refusal-codes-propagate-by-name",
                          "unrated findings refused with %s" % _code_of(exc))
    else:
        return _break("refusal-codes-propagate-by-name",
                      "unrated findings admitted")
    _held("refusal-codes-propagate-by-name",
          "all five machinery codes propagated verbatim")


@_probe("legacy-admission-untouched")
def _p_legacy():
    # Legacy pin, verifiable on the pristine base: admitting directly
    # through gov/admission.py (no quarantine) behaves exactly as
    # before -- the quarantine is purely additive.
    payload, digest = _payload_and_digest(b"legacy-path")
    seed, pub = _keypair()
    policy = adm.AdmissionPolicy(digest, pub, "evidence-bundle/v1")
    artifact = {"format": "evidence-bundle/v1", "payload_digest": digest,
                "signature": _sign(seed, digest), "payload": payload}
    record = policy.admit(artifact)
    if not (isinstance(record, dict) and record.get("admissible") is True):
        return _break("legacy-admission-untouched",
                      "direct admit did not return admissible: %r" % (record,))
    try:
        policy.admit(dict(artifact, signature=None))
    except Exception as exc:
        if _code_of(exc) != "admission-unverifiable":
            return _break("legacy-admission-untouched",
                          "wrong legacy code: %s" % _code_of(exc))
    else:
        return _break("legacy-admission-untouched",
                      "legacy unsigned admit was not refused")
    _held("legacy-admission-untouched",
          "direct admission path byte-identical behavior")


@_probe("envelope-override-refused")
def _p_override():
    # The decision must bind to the STAGED bytes: swapping the digest
    # or payload at admit time is an envelope-integrity violation.
    if not _IMPORT_OK:
        return _gap("envelope-override-refused")
    payload, digest = _payload_and_digest(b"override-me")
    seed, pub = _keypair()
    policy = adm.AdmissionPolicy(digest, pub, "evidence-bundle/v1")
    q = qr.Quarantine()
    staged = q.stage(payload, digest)
    _expect_refusal("envelope-override-refused", _C_OVERRIDE_REFUSED,
                    lambda: q.admit(staged, policy,
                                    bundle_format="evidence-bundle/v1",
                                    signature=_sign(seed, digest),
                                    payload_digest=_DIGEST_X))
    _expect_refusal("envelope-override-refused", _C_OVERRIDE_REFUSED,
                    lambda: q.admit(staged, policy,
                                    bundle_format="evidence-bundle/v1",
                                    signature=_sign(seed, digest),
                                    payload=b"swapped-bytes"))
    # A handle from another quarantine instance must not work here.
    q2 = qr.Quarantine()
    foreign = q2.stage(payload, digest)
    _expect_refusal("envelope-override-refused", _C_UNKNOWN_STAGED,
                    lambda: q.admit(foreign, policy,
                                    bundle_format="evidence-bundle/v1",
                                    signature=_sign(seed, digest)))
    if q.in_trusted_store(digest):
        return _break("envelope-override-refused",
                      "override attempt admitted to trust")
    _held("envelope-override-refused",
          "payload/payload_digest overrides refused; foreign handle unknown")


@_probe("double-admit-consumed")
def _p_double_admit():
    # Admission consumes the staged handle: it cannot admit twice.
    if not _IMPORT_OK:
        return _gap("double-admit-consumed")
    payload, digest = _payload_and_digest(b"once-only")
    seed, pub = _keypair()
    policy = adm.AdmissionPolicy(digest, pub, "evidence-bundle/v1")
    q = qr.Quarantine()
    staged = q.stage(payload, digest)
    q.admit(staged, policy, bundle_format="evidence-bundle/v1",
            signature=_sign(seed, digest))
    _expect_refusal("double-admit-consumed", _C_UNKNOWN_STAGED,
                    lambda: q.admit(staged, policy,
                                    bundle_format="evidence-bundle/v1",
                                    signature=_sign(seed, digest)))
    _expect_refusal("double-admit-consumed", _C_UNKNOWN_STAGED,
                    lambda: q.reject(staged, "too late"))
    if not q.in_trusted_store(digest):
        return _break("double-admit-consumed",
                      "first admit did not land in trust")
    _held("double-admit-consumed",
          "second admit/reject on consumed handle refused")


@_probe("policy-contract-refused")
def _p_contract():
    # Success means a VERIFIED admissible record: a policy that
    # returns without one must not land bytes in trust.
    if not _IMPORT_OK:
        return _gap("policy-contract-refused")
    payload, digest = _payload_and_digest(b"contract-check")
    q = qr.Quarantine()

    class _NoRecordPolicy(object):
        def admit(self, envelope, **kwargs):
            return {"admissible": False}

    class _GarbagePolicy(object):
        def admit(self, envelope, **kwargs):
            return "admitted"

    staged = q.stage(payload, digest)
    _expect_refusal("policy-contract-refused",
                    "quarantine-policy-contract-refused",
                    lambda: q.admit(staged, _NoRecordPolicy(),
                                    bundle_format="evidence-bundle/v1"))
    _expect_refusal("policy-contract-refused",
                    "quarantine-policy-contract-refused",
                    lambda: q.admit(staged, _GarbagePolicy(),
                                    bundle_format="evidence-bundle/v1"))
    if q.in_trusted_store(digest):
        return _break("policy-contract-refused",
                      "contract-violating policy landed bytes in trust")
    _held("policy-contract-refused",
          "success verified by record; contract violations refused")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_once():
    _RESULTS.clear()
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001 - never drop a probe
            _record(name, "ERROR", "%s: %s"
                    % (type(exc).__name__, exc))
    return list(_RESULTS)


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green/admission-adjacent", "SKIP", "nested run")]
    return [("green/admission-adjacent", "SKIP",
             "owned by merge; lane runs adjacent suites directly")]


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w224 quarantine probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-40s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-40s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
