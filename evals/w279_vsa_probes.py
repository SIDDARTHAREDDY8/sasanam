"""Wave-279 VSA battery: one signed Verification Summary Attestation per
sealed evidence bundle ("sell evidence, not the engine").

ADAPT of the SLSA VSA shape (slsa-framework/slsa, mixed CSL 1.0 /
Apache-2.0 -- implement the FORMAT from field definitions, never copy
spec prose). The shape is our own: ``sasanam-vsa/1`` from
``gov.provenance_policy`` (the existing issuer ``VSAIssuer`` and the
admission consumer ``ProvenancePolicy.admit_vsa``). This battery pins
the NEW per-bundle wiring in ``gov.bundle_vsa``:

  * ``issue_bundle_vsa`` -- issue a signed VSA naming the bundle
    digest, the verifier identity, the policy/evaluation it passed,
    the verification time, and the bundle's receipts as trust-labeled
    ``input_attestations`` (agent-supplied vs platform-supplied --
    nothing unlabeled).
  * ``verify_bundle_vsa`` -- the verifier: refuses forged/tampered
    VSAs (wrong signature, wrong digest, expired verification) with
    coded fail-closed verdicts (``provenance-vsa-refused`` /
    ``provenance-subject-refused``), never raw raises on hostile
    shapes (F245 discipline).
  * seal-time wiring: ``seal_evidence(vsa_issuer=...)`` (threaded
    through ``submit_evidence`` /
    ``submit_evidence_with_producer_claim``) attaches the VSA to the
    sealed bundle; with no issuer the record is byte-identical to the
    unwired behavior.

Red-first: on base (wave-278, no per-bundle VSA path) the issuance
probes BREAK ("no per-bundle VSA path"); after the lane they HELD.
vsa06 is a defense pin and HELDs on both. Every scenario pins an
independent expected outcome; the grader decides from the observation.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic scenario inputs (fixed
seeds, no random -- GOV_LOG_KEY is provisioned per-run like the unit
tests); fresh unique /var/tmp/g279* TMPDIR (`mkdir -p` first); depth-1 green
checks honoring GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib
only (plus the product itself).
"""

import hashlib
import json
import os
import re
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w279-vsa-ut")

_TMP = tempfile.mkdtemp(prefix="g279-vsa-%d-" % os.getpid(), dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gov.ed25519 as ed  # noqa: E402
import gov.evidence_certs as ec  # noqa: E402
import gov.evidence_bundle_v2 as eb2  # noqa: E402
import gov.kms as kms_mod  # noqa: E402
import gov.provenance_policy as pp  # noqa: E402

try:
    import gov.bundle_vsa as bvsa  # noqa: E402
    _VSA_MODULE = True
except ImportError:
    bvsa = None  # noqa: F821
    _VSA_MODULE = False

TAXONOMY_PIN = 1750  # Wave-279 merge pin; this battery adds no codes (merge: +2 from sibling lanes: evbundle-contract-refused, tool-guardrail-tripwire).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)
GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []

# ---------------------------------------------------------------------------
# Fixtures: sealed bundles through the audited evidence-cert ceremony
# (fixed seeds, independent literals; mirrors tests/test_evbundle.py).
# ---------------------------------------------------------------------------

NOW = 1790860000
POP_DOMAIN = b"evcert-pop-v1"  # spec-pinned, not from the module
ARC = "1.3.6.1.4.1.99999"
APPROVAL = "a" * 32
INTENT = "d" * 64
ISSUER = "https://issuer.example.com"
SEALER_ID = "sasanam-evidence-sealer/w279"
SEALER_SEED = bytes([0x5E]) * 32
VSA_POLICY = "sasanam-evidence-seal/v1"
VSA_TTL = 86400


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


_CA_SEQ = [0]


def _make_ca():
    fake = kms_mod.FakeKmsProvider(["ca-key-1"])
    approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
    _CA_SEQ[0] += 1
    # One audit log per DIRECTORY: the checkpoint sidecar and the
    # subject-key-reuse registry are per-directory product state, so
    # probes must not share a dir (the product's invariant; tests do
    # the same with one tmpdir per test).
    cadir = os.path.join(_TMP, "ca-%d" % _CA_SEQ[0])
    os.makedirs(cadir, exist_ok=True)
    audit_path = os.path.join(cadir, "audit.jsonl")
    return ec.EvidenceCA(
        kms_provider=fake,
        ca_key_id="ca-key-1",
        ca_public_key=fake.test_signing_public_key("ca-key-1"),
        issuers=[ISSUER],
        approval_lookup=approvals.get,
        audit_log_path=audit_path,
        anchor_reachable=lambda: True,
        oid_arc=ARC,
        now=lambda: NOW), fake, audit_path


def _issue_cert(ca, seed_byte=0x01, approval_id=APPROVAL):
    seed, pub = _keypair(seed_byte)
    chal = (POP_DOMAIN + approval_id.encode("utf-8")
            + hashlib.sha256(pub).digest())
    req = {"identity_assertion": {"iss": ISSUER, "sub": "alice",
                                  "exp": NOW + 3600},
           "ephemeral_pub": pub,
           "pop_sig": ed.sign(seed, chal),
           "approval_id": approval_id,
           "intent_digest": INTENT}
    cert, _entry = ca.issue(**req)
    return cert, seed, pub


def _seal_kwargs(cert, seed, ca_pub, body=None):
    body = {"decision": "deny"} if body is None else body
    sig = ed.sign(seed, _canonical(body))
    return dict(artifact_body=body, cert=cert,
                artifact_signature=bytes(sig),
                approval_id=APPROVAL, intent_digest=INTENT,
                ca_public_key=bytes(ca_pub), verify_time=NOW)


ISSUER_SEED = bytes([0x10]) * 32
ISSUER_PUB = ed.publickey(ISSUER_SEED)
CLAIM_SEED = bytes([0x20]) * 32
CLAIM_PUB = ed.publickey(CLAIM_SEED)
SCOPE = "payments/refunds"


def _sealer():
    return pp.VSAIssuer(SEALER_ID, SEALER_SEED)


def _claim_ca():
    """CA configured for the producer-authorization claim path (one
    audit log per directory -- the product invariant)."""
    fake = kms_mod.FakeKmsProvider(["ca-key-1"])
    approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
    _CA_SEQ[0] += 1
    cadir = os.path.join(_TMP, "ca-%d" % _CA_SEQ[0])
    os.makedirs(cadir, exist_ok=True)
    audit_path = os.path.join(cadir, "audit.jsonl")
    ca = ec.EvidenceCA(
        kms_provider=fake,
        ca_key_id="ca-key-1",
        ca_public_key=fake.test_signing_public_key("ca-key-1"),
        issuers=[ISSUER],
        approval_lookup=approvals.get,
        audit_log_path=audit_path,
        anchor_reachable=lambda: True,
        oid_arc=ARC,
        now=lambda: NOW,
        claim_public_key=CLAIM_PUB)
    return ca, fake, audit_path


def _claim_fixture(ca):
    """Producer-authorization claim path (mirrors
    tests/test_producer_authz.py): registry + identity token +
    producer claim, then a cert carrying the claim."""
    seed, pub = _keypair(0x05)
    key_id = hashlib.sha256(pub).hexdigest()[:16]
    registry = eb2.ProducerRegistry(entries={"alice": [SCOPE]})
    token = eb2.mint_identity_token(issuer_signing_key=ISSUER_SEED,
                                    sub="alice", now=lambda: NOW)
    claim = eb2.issue_producer_claim(
        registry=registry, identity_token=token,
        identity_issuer_public_key=ISSUER_PUB,
        requested_scope=SCOPE, subject_key_id=key_id,
        approval_id=APPROVAL, claim_signing_key=CLAIM_SEED,
        now=lambda: NOW)
    chal = (POP_DOMAIN + APPROVAL.encode("utf-8")
            + hashlib.sha256(pub).digest())
    cert, _entry = ca.issue(
        identity_assertion={"iss": ISSUER, "sub": "alice",
                            "exp": NOW + 3600},
        ephemeral_pub=pub, pop_sig=ed.sign(seed, chal),
        approval_id=APPROVAL, intent_digest=INTENT,
        producer_authz_claim=claim)
    return cert, seed, pub, registry, token


def _no_vsa_path():
    """Red-first short-circuit: on base there is no per-bundle VSA
    seam at all."""
    return not _VSA_MODULE


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _pin_check():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _p01_module():
    if _no_vsa_path():
        return "BREAK", ("gov.bundle_vsa absent: no per-bundle VSA "
                         "issuance path")
    for name in ("issue_bundle_vsa", "verify_bundle_vsa",
                 "bundle_input_attestations", "attach_bundle_vsa"):
        if not callable(getattr(bvsa, name, None)):
            return "BREAK", "gov.bundle_vsa missing %s" % name
    return "HELD", "per-bundle VSA seam present"


def _p02_seal_carries_vsa():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    ca, fake, _audit = _make_ca()
    cert, seed, pub = _issue_cert(ca)
    ca_pub = fake.test_signing_public_key("ca-key-1")
    issuer = _sealer()
    sealed = eb2.seal_evidence(vsa_issuer=issuer,
                              vsa_policy_id=VSA_POLICY,
                              vsa_issued_at=NOW,
                              **_seal_kwargs(cert, seed, ca_pub))
    vsa = sealed.get("vsa")
    if not isinstance(vsa, dict):
        return "BREAK", "sealed bundle carries no VSA"
    checked = bvsa.verify_bundle_vsa(
        vsa, verifier_pubkey_hex=issuer.public_key_hex,
        expected_bundle_digest=sealed["artifact"]["artifact_digest"],
        now=NOW)
    if checked.get("policy_id") != VSA_POLICY:
        return "BREAK", "VSA policy_id mismatch"
    if checked.get("verifier", {}).get("id") != SEALER_ID:
        return "BREAK", "VSA verifier id mismatch"
    if checked["subject"]["digest"]["sha256"] !=\
            sealed["artifact"]["artifact_digest"]:
        return "BREAK", "VSA subject digest != bundle digest"
    if not checked.get("input_attestations"):
        return "BREAK", "VSA carries no input_attestations"
    return "HELD", ("sealed bundle carries a signed VSA naming the "
                    "bundle digest, verifier, policy, and receipts")


def _p03_forged_signature():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    issuer = _sealer()
    digest = hashlib.sha256(b"bundle").hexdigest()
    vsa = bvsa.issue_bundle_vsa(
        issuer=issuer, bundle_digest=digest, policy_id=VSA_POLICY,
        verified_level="SLSA_BUILD_LEVEL_1", input_attestations=[],
        issued_at=NOW, ttl_seconds=VSA_TTL)
    bad = dict(vsa)
    sig = dict(vsa["signature"])
    raw = bytearray(bytes.fromhex(sig["sig"]))
    raw[-1] ^= 0x01
    sig["sig"] = bytes(raw).hex()
    bad["signature"] = sig
    try:
        bvsa.verify_bundle_vsa(
            bad, verifier_pubkey_hex=issuer.public_key_hex,
            expected_bundle_digest=digest, now=NOW)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code == "provenance-vsa-refused":
            return "HELD", "forged VSA refused with provenance-vsa-refused"
        return "BREAK", "forged VSA refused with wrong code %r" % (code,)
    return "BREAK", "forged VSA verified (signature not checked)"


def _p04_digest_mismatch():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    issuer = _sealer()
    digest_a = hashlib.sha256(b"bundle-a").hexdigest()
    digest_b = hashlib.sha256(b"bundle-b").hexdigest()
    vsa = bvsa.issue_bundle_vsa(
        issuer=issuer, bundle_digest=digest_a, policy_id=VSA_POLICY,
        verified_level="SLSA_BUILD_LEVEL_1", input_attestations=[],
        issued_at=NOW, ttl_seconds=VSA_TTL)
    try:
        bvsa.verify_bundle_vsa(
            vsa, verifier_pubkey_hex=issuer.public_key_hex,
            expected_bundle_digest=digest_b, now=NOW)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code == "provenance-subject-refused":
            return "HELD", ("digest-mismatched VSA refused with "
                            "provenance-subject-refused")
        return "BREAK", ("digest mismatch refused with wrong code %r"
                         % (code,))
    return "BREAK", "VSA for another bundle's digest verified"


def _p05_expired():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    issuer = _sealer()
    digest = hashlib.sha256(b"bundle").hexdigest()
    vsa = bvsa.issue_bundle_vsa(
        issuer=issuer, bundle_digest=digest, policy_id=VSA_POLICY,
        verified_level="SLSA_BUILD_LEVEL_1", input_attestations=[],
        issued_at=NOW - 7200, ttl_seconds=3600)
    try:
        bvsa.verify_bundle_vsa(
            vsa, verifier_pubkey_hex=issuer.public_key_hex,
            expected_bundle_digest=digest, now=NOW)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code == "provenance-vsa-refused":
            return "HELD", "expired VSA refused with provenance-vsa-refused"
        return "BREAK", "expired VSA refused with wrong code %r" % (code,)
    return "BREAK", "expired VSA verified"


def _p06_no_issuer_no_vsa():
    ca, fake, _audit = _make_ca()
    cert, seed, pub = _issue_cert(ca, seed_byte=0x02)
    ca_pub = fake.test_signing_public_key("ca-key-1")
    sealed = eb2.seal_evidence(**_seal_kwargs(cert, seed, ca_pub))
    if "vsa" in sealed:
        return "BREAK", "seal without issuer grew a vsa key"
    return "HELD", "seal without issuer: no vsa key (flag-off no-op)"


def _p07_hostile_shapes():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    issuer = _sealer()
    digest = hashlib.sha256(b"bundle").hexdigest()
    hostiles = [None, "x", [], b"vsa",
                {"format": "sasanam-statement/9"},
                {"format": pp.VSA_FORMAT},
                {"format": pp.VSA_FORMAT, "signature": {"sig": "zz"}},
                {"format": pp.VSA_FORMAT, "signature": "not-a-dict"},
                {"format": pp.VSA_FORMAT,
                 "signature": {"sig": "00" * 64},
                 "subject": "not-a-dict"}]
    allowed = {"provenance-vsa-refused", "provenance-subject-refused"}
    for h in hostiles:
        try:
            bvsa.verify_bundle_vsa(
                h, verifier_pubkey_hex=issuer.public_key_hex,
                expected_bundle_digest=digest, now=NOW)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            if code not in allowed:
                return ("BREAK",
                        "hostile shape %r escaped with code %r (%s)"
                        % (type(h).__name__, code,
                           type(exc).__name__))
        else:
            return ("BREAK",
                    "hostile shape %r verified" % (type(h).__name__,))
    return "HELD", "9 hostile VSA shapes: all refused machine-coded"


def _p08_trust_labels():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    issuer = _sealer()
    digest = hashlib.sha256(b"bundle").hexdigest()
    unlabeled = [{"kind": "receipt", "digest": "d" * 64}]
    for bad_list in (unlabeled,
                     [{"kind": "receipt", "digest": "d" * 64,
                       "trust": "maybe"}],
                     [{"kind": "receipt", "trust": "platform-supplied"}]):
        try:
            bvsa.issue_bundle_vsa(
                issuer=issuer, bundle_digest=digest, policy_id=VSA_POLICY,
                verified_level="SLSA_BUILD_LEVEL_1",
                input_attestations=bad_list, issued_at=NOW,
                ttl_seconds=VSA_TTL)
        except (ValueError, TypeError):
            continue
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", None)
            if code is None:
                return ("BREAK",
                        "unlabeled input attestation raised raw %s"
                        % type(exc).__name__)
            continue
        return "BREAK", "unlabeled/mis-labeled input attestation issued"
    return "HELD", "input_attestations: trust labels enforced at issue"


def _p09_admit_interop():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    issuer = _sealer()
    digest = hashlib.sha256(b"bundle").hexdigest()
    vsa = bvsa.issue_bundle_vsa(
        issuer=issuer, bundle_digest=digest, policy_id=VSA_POLICY,
        verified_level="SLSA_BUILD_LEVEL_1", input_attestations=[],
        issued_at=NOW, ttl_seconds=VSA_TTL)
    policy = pp.ProvenancePolicy(
        name=VSA_POLICY, allowed_sources=["unrecorded"],
        allowed_builders=["sasanam-evidence-sealer/w279"],
        tag_policy={"mode": "any"}, expected_inputs={},
        require_signed_statement=False, statement_signers={},
        trusted_verifiers={SEALER_ID: issuer.public_key_hex},
        vsa_max_age_seconds=86400, vsa_required_level="SLSA_BUILD_LEVEL_1")
    try:
        ok = policy.admit_vsa(vsa, VSA_POLICY, digest, now=NOW)
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "lane-issued VSA not admitted: %s" % (exc,)
    if ok is not True:
        return "BREAK", "admit_vsa did not return True"
    return "HELD", "lane VSA admits under ProvenancePolicy.admit_vsa"


def _p10_submit_threading():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    ca, fake, audit_path = _make_ca()
    cert, seed, pub = _issue_cert(ca, seed_byte=0x03)
    ca_pub = fake.test_signing_public_key("ca-key-1")
    log = eb2.make_log(
        producer_auth_verifier=eb2.default_producer_auth_verifier,
        now=lambda: NOW)
    issuer = _sealer()
    sub = eb2.submit_evidence(
        audit_log_path=audit_path,
        transparency_log=log, now=lambda: NOW,
        vsa_issuer=issuer, vsa_policy_id=VSA_POLICY, vsa_issued_at=NOW,
        **_seal_kwargs(cert, seed, ca_pub))
    vsa = sub["sealed"].get("vsa")
    if not isinstance(vsa, dict):
        return "BREAK", "submission's sealed bundle carries no VSA"
    bvsa.verify_bundle_vsa(
        vsa, verifier_pubkey_hex=issuer.public_key_hex,
        expected_bundle_digest=sub["sealed"]["artifact"]["artifact_digest"],
        now=NOW)
    return "HELD", "submit_evidence threads the VSA into the sealed bundle"


def _p11_claim_path_threading():
    if _no_vsa_path():
        return "BREAK", "no per-bundle VSA path on base"
    ca, fake, audit_path = _claim_ca()
    cert, seed, pub, registry, token = _claim_fixture(ca)
    ca_pub = fake.test_signing_public_key("ca-key-1")
    log = eb2.make_log(
        producer_auth_verifier=eb2.default_producer_auth_verifier,
        now=lambda: NOW)
    issuer = _sealer()
    sub = eb2.submit_evidence_with_producer_claim(
        audit_log_path=audit_path,
        transparency_log=log, now=lambda: NOW,
        identity_token=token,
        identity_issuer_public_key=ISSUER_PUB,
        producer_registry=registry, requested_scope=SCOPE,
        claim_public_key=CLAIM_PUB,
        vsa_issuer=issuer, vsa_policy_id=VSA_POLICY, vsa_issued_at=NOW,
        **_seal_kwargs(cert, seed, ca_pub))
    vsa = sub["sealed"].get("vsa")
    if not isinstance(vsa, dict):
        return "BREAK", "claim-path submission's sealed bundle has no VSA"
    bvsa.verify_bundle_vsa(
        vsa, verifier_pubkey_hex=issuer.public_key_hex,
        expected_bundle_digest=sub["sealed"]["artifact"]["artifact_digest"],
        now=NOW)
    return "HELD", ("submit_evidence_with_producer_claim threads the "
                    "VSA into the sealed bundle")


_PROBES = [
    ("pin-taxonomy-1495", "HELD", _pin_check),
    ("vsa01-module-seam", "HELD", _p01_module),
    ("vsa02-seal-carries-vsa", "HELD", _p02_seal_carries_vsa),
    ("vsa03-forged-signature", "HELD", _p03_forged_signature),
    ("vsa04-digest-mismatch", "HELD", _p04_digest_mismatch),
    ("vsa05-expired", "HELD", _p05_expired),
    ("vsa06-no-issuer-no-vsa", "HELD", _p06_no_issuer_no_vsa),
    ("vsa07-hostile-shapes", "HELD", _p07_hostile_shapes),
    ("vsa08-trust-labels", "HELD", _p08_trust_labels),
    ("vsa09-admit-interop", "HELD", _p09_admit_interop),
    ("vsa10-submit-threading", "HELD", _p10_submit_threading),
    ("vsa11-claim-path-threading", "HELD", _p11_claim_path_threading),
]


def _green_checks():
    """Depth-1: run the adjacent provenance/bundle batteries with
    GOV_SKIP_GREEN=1 (they record the skip and do not recurse)."""
    if GREEN_SKIP:
        return [("green-checks", "SKIP",
                 "GOV_SKIP_GREEN=1: recorded, not recursing")]
    import subprocess
    out = []
    for name in ("w278_envelope_probes", "w277_conflict_probes"):
        path = os.path.join(REPO, "evals", name + ".py")
        if not os.path.exists(path):
            out.append((name, "SKIP", "battery absent"))
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run([sys.executable, path], env=env,
                               capture_output=True, text=True, timeout=600)
        except Exception as exc:  # noqa: BLE001
            out.append((name, "BREAK", "green check failed: %s" % (exc,)))
            continue
        tail = (p.stdout or "").strip().split("\n")[-1] if p.stdout else ""
        out.append((name, "HELD" if p.returncode == 0 else "BREAK",
                    "%s rc=%d" % (tail[:120], p.returncode)))
    return out


def main():
    print("w279 VSA battery: %d probes (TMPDIR=%s)"
          % (len(_PROBES), _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-34s expected=%-5s got=%-5s %s"
              % (flag, pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in _green_checks():
        print("[%s] %s %s" % ("ok " if verdict in ("HELD", "SKIP") else "FAIL",
                              name, note))
        if verdict not in ("HELD", "SKIP"):
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
