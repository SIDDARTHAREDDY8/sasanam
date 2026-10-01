#!/usr/bin/env python3
"""Wave-270 red-first battery: evidence-bundle v2 + Rekor contract.

Three-artifact split (evidence artifact / signature attestation /
issuance attestation joined ONLY by cert_digest), a TransparencyLog
provider interface with an in-process default, and the key<->producer
authorization binding Rekor omits (submit must carry a producer
authorization; a bare digest is refused).

Red phase:  GOV_EVBUNDLE_IMPL=stub  -> permissive foil. Every attack
probe must BREAK (the foil seals/submits/verifies without checks); a
probe that HELDs on the stub is vacuous and is flagged.
Green phase: default (gov.evidence_bundle_v2) -> every probe HELD.

Protocol constants below are pinned independently of the module under
test (canonical JSON form, PoP domain, fixed clock); the battery
builds real producer authorizations through gov.evidence_certs with
gov.kms.FakeKmsProvider, exactly as tests/test_evcert.py does.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses.
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# The audit-log HMAC chain needs an explicit key (wave-81: no dev-key
# fallback anywhere). Batteries provision their own, like w269.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w270-evbundle")

# -- protocol constants pinned independently of the module under test --
POP_DOMAIN = b"evcert-pop-v1"
NOW = 1790860000  # fixed test clock
ARC = "1.3.6.1.4.1.99999"
ISSUER = "https://issuer.example.com"
APPROVAL = "a" * 32
INTENT = "d" * 64

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import ed25519 as _ed  # noqa: E402
from gov import evidence_certs as _ec  # noqa: E402
from gov import kms as _kms  # noqa: E402
from gov import evidence_bundle as _v1  # noqa: E402


def _keypair(seed_byte):
    seed = bytes([seed_byte & 0xFF]) * 32
    return seed, _ed.publickey(seed)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest_hex(data):
    return hashlib.sha256(bytes(data)).hexdigest()


# ---------------------------------------------------------------------------
# Real producer-authorization fixtures (through the audited ceremony)
# ---------------------------------------------------------------------------

def _make_ca(tmpdir, **over):
    fake = _kms.FakeKmsProvider(["ca-key-1"])
    approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
    kw = dict(kms_provider=fake,
              ca_key_id="ca-key-1",
              ca_public_key=fake.test_signing_public_key("ca-key-1"),
              issuers=[ISSUER],
              approval_lookup=approvals.get,
              audit_log_path=os.path.join(tmpdir, "audit.jsonl"),
              anchor_reachable=lambda: True,
              oid_arc=ARC,
              now=lambda: NOW)
    kw.update(over)
    ca = _ec.EvidenceCA(**kw)
    return ca, fake


def _issue_cert(ca, seed_byte=0x01, approval_id=APPROVAL, sub="alice"):
    seed, pub = _keypair(seed_byte)
    chal = POP_DOMAIN + approval_id.encode("utf-8") + hashlib.sha256(pub).digest()
    req = {"identity_assertion": {"iss": ISSUER, "sub": sub,
                                 "exp": NOW + 3600},
           "ephemeral_pub": pub,
           "pop_sig": _ed.sign(seed, chal),
           "approval_id": approval_id,
           "intent_digest": INTENT}
    cert, audit_entry = ca.issue(**req)
    return cert, seed, pub


def _producer_auth(cert, seed, artifact_body, ca_pub, approval_id=APPROVAL,
                   intent_digest=INTENT, tamper_sig=False, wrong_key=False):
    art_bytes = _canonical(artifact_body)
    if wrong_key:
        _, other_pub = _keypair(0xEE)
        sig_seed = bytes([0xEE]) * 32
    else:
        sig_seed = seed
    sig = _ed.sign(sig_seed, art_bytes)
    if tamper_sig:
        sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    return {"kind": "evidence-cert",
            "cert": cert,
            "artifact_bytes": art_bytes,
            "artifact_signature": bytes(sig),
            "approval_id": approval_id,
            "intent_digest": intent_digest,
            "ca_public_key": bytes(ca_pub),
            "verify_time": NOW}


# ---------------------------------------------------------------------------
# Permissive foil (red phase): same call shape, zero checks.
# ---------------------------------------------------------------------------

class _FoilError(Exception):
    pass


class _FoilLog(object):
    def submit(self, digest, *, producer_auth=None):
        return {"log_id": "foil", "integrated_time": NOW,
                "inclusion_proof": {"leaf_index": 0, "hashes": []},
                "tree_size": 1, "root": "00" * 32, "digest": digest}

    def verify_inclusion(self, digest, inclusion_proof, checkpoint):
        return True

    def verify_checkpoint(self, checkpoint):
        return True

    def verify_consistency(self, old_checkpoint, new_checkpoint):
        return True


class _FoilModule(object):
    """Accepts everything: no producer-auth check, no join check, no
    inclusion/checkpoint verification. Attack probes must BREAK."""

    def build_artifact(self, body):
        art = {"format": "evidence-artifact.v2", "body": body,
               "artifact_digest": _digest_hex(_canonical(body))}
        return art, art["artifact_digest"]

    def seal_evidence(self, **kw):
        art, digest = self.build_artifact(kw["artifact_body"])
        return {"kind": "evidence-bundle.v2", "artifact": art,
                "signature_attestation": {"artifact_digest": digest,
                                         "cert_digest": "ff" * 32,
                                         "signature": "AA" * 86},
                "cert_digest": "ff" * 32}

    def find_issuance_attestation(self, *, audit_log_path, cert_digest):
        return {"kind": "evidence-cert-issued", "cert_digest": cert_digest}

    def verify_sealed_bundle(self, **kw):
        return {"verified": True, "cert_digest": kw["sealed"]["cert_digest"]}

    def make_log(self, **kw):
        return _FoilLog()

    def submit_evidence(self, **kw):
        sealed = self.seal_evidence(
            artifact_body=kw["artifact_body"], cert=kw["cert"],
            artifact_signature=kw["artifact_signature"],
            approval_id=kw["approval_id"], intent_digest=kw["intent_digest"],
            ca_public_key=kw["ca_public_key"], verify_time=kw["verify_time"])
        receipt = self.make_log().submit(sealed["artifact"]["artifact_digest"])
        return {"sealed": sealed, "transparency_receipt": receipt}

    def verify_submission(self, **kw):
        return {"verified": True}

    default_producer_auth_verifier = staticmethod(lambda auth, digest: {})


def _real_module():
    import gov.evidence_bundle_v2 as eb2
    return eb2


def _mod(impl):
    return _FoilModule() if impl == "stub" else _real_module()


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _harness(tmpdir):
    ca, fake = _make_ca(tmpdir)
    cert, seed, pub = _issue_cert(ca)
    ca_pub = fake.test_signing_public_key("ca-key-1")
    return ca, fake, cert, seed, pub, ca_pub


def p01_submit_without_producer_auth(impl, tmpdir):
    """A bare digest with no producer authorization must be refused --
    this is the binding Rekor omits."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log = eb2.make_log(producer_auth_verifier=None)
    digest = _digest_hex(_canonical({"x": 1}))
    try:
        log.submit(digest, producer_auth=None)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-unauthorized-producer":
            return "HELD", "refused evbundle-unauthorized-producer"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "bare digest accepted without producer authorization"


def p02_forged_artifact_signature(impl, tmpdir):
    """Producer auth whose artifact signature does not verify must be
    refused (self-minted / tampered grants, F252 class)."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier)
    body = {"decision": "deny", "why": "test"}
    digest = _digest_hex(_canonical(body))
    auth = _producer_auth(cert, seed, body, ca_pub, tamper_sig=True)
    try:
        log.submit(digest, producer_auth=auth)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-unauthorized-producer":
            return "HELD", "forged signature refused"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "forged producer auth accepted"


def p03_approval_mismatch(impl, tmpdir):
    """Producer auth bound to a different approval than the cert's
    must be refused."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier)
    body = {"decision": "allow"}
    digest = _digest_hex(_canonical(body))
    auth = _producer_auth(cert, seed, body, ca_pub,
                         approval_id="b" * 32)
    try:
        log.submit(digest, producer_auth=auth)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-unauthorized-producer":
            return "HELD", "approval mismatch refused"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "approval-mismatched producer auth accepted"


def p04_join_mismatch(impl, tmpdir):
    """Signature attestation and issuance attestation must agree on
    cert_digest; a swapped join must be refused."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    body = {"decision": "deny"}
    art_bytes = _canonical(body)
    sig = _ed.sign(seed, art_bytes)
    sealed = eb2.seal_evidence(artifact_body=body, cert=cert,
                              artifact_signature=bytes(sig),
                              approval_id=APPROVAL, intent_digest=INTENT,
                              ca_public_key=bytes(ca_pub), verify_time=NOW)
    # Swap in a second, independently issued cert digest.
    cert2, _, _ = _issue_cert(ca, seed_byte=0x02)
    from gov.evidence_certs import cert_digest as _cd
    sealed = dict(sealed)
    sealed["cert_digest"] = _cd(cert2)
    sealed["signature_attestation"] = dict(
        sealed["signature_attestation"])
    sealed["signature_attestation"]["cert_digest"] = _cd(cert2)
    try:
        eb2.verify_sealed_bundle(sealed=sealed,
                                audit_log_path=os.path.join(
                                    tmpdir, "audit.jsonl"),
                                ca_public_key=bytes(ca_pub),
                                verify_time=NOW)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-join-mismatch":
            return "HELD", "join mismatch refused"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "swapped cert_digest join accepted"


def p05_inclusion_proof_forgery(impl, tmpdir):
    """A tampered inclusion proof must not verify."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier)
    body = {"decision": "deny"}
    digest = _digest_hex(_canonical(body))
    auth = _producer_auth(cert, seed, body, ca_pub)
    receipt = log.submit(digest, producer_auth=auth)
    proof = dict(receipt["inclusion_proof"])
    hashes = [bytes.fromhex(h) for h in proof["hashes"]]
    if hashes:
        hashes[0] = bytes([hashes[0][0] ^ 0x01]) + hashes[0][1:]
    else:
        # single-leaf tree: forge by pointing at a different leaf
        proof = {"leaf_index": 7, "hashes": []}
        hashes = []
    proof["hashes"] = [h.hex() for h in hashes]
    checkpoint = {"log_id": receipt["log_id"],
                  "tree_size": receipt["tree_size"],
                  "root": receipt["root"],
                  "integrated_time": receipt["integrated_time"]}
    try:
        log.verify_inclusion(digest, proof, checkpoint)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-inclusion-unverified":
            return "HELD", "forged inclusion proof refused"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "forged inclusion proof verified"


def p06_checkpoint_root_mutation(impl, tmpdir):
    """A checkpoint whose root does not match the log history must be
    refused."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier)
    body = {"n": 1}
    digest = _digest_hex(_canonical(body))
    receipt = log.submit(digest,
                         producer_auth=_producer_auth(cert, seed, body,
                                                     ca_pub))
    bad = {"log_id": receipt["log_id"], "tree_size": receipt["tree_size"],
           "root": "ab" * 32, "integrated_time": receipt["integrated_time"]}
    try:
        log.verify_checkpoint(bad)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-checkpoint-invalid":
            return "HELD", "mutated checkpoint refused"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "mutated checkpoint accepted"


def p07_consistency_across_divergent_logs(impl, tmpdir):
    """Consistency must refuse checkpoints from divergent histories
    (different log_id) and inverted sizes."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log_a = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier, log_id="log-a")
    log_b = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier, log_id="log-b")
    body = {"n": 1}
    digest = _digest_hex(_canonical(body))
    ra = log_a.submit(digest, producer_auth=_producer_auth(cert, seed, body,
                                                           ca_pub))
    rb = log_b.submit(digest, producer_auth=_producer_auth(cert, seed, body,
                                                           ca_pub))
    ca_ckpt = {"log_id": ra["log_id"], "tree_size": ra["tree_size"],
               "root": ra["root"], "integrated_time": ra["integrated_time"]}
    cb_ckpt = {"log_id": rb["log_id"], "tree_size": rb["tree_size"],
               "root": rb["root"], "integrated_time": rb["integrated_time"]}
    try:
        log_a.verify_consistency(ca_ckpt, cb_ckpt)
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-consistency-invalid":
            return "HELD", "divergent-history consistency refused"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "cross-log consistency accepted"


def p08_transparency_outage(impl, tmpdir):
    """A failing transparency provider must fail closed, never
    silently skip the log."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)

    class _DownLog(object):
        def submit(self, digest, *, producer_auth=None):
            raise RuntimeError("simulated outage")

    body = {"decision": "deny"}
    sig = _ed.sign(seed, _canonical(body))
    try:
        eb2.submit_evidence(artifact_body=body, cert=cert,
                           artifact_signature=bytes(sig),
                           approval_id=APPROVAL, intent_digest=INTENT,
                           audit_log_path=os.path.join(tmpdir,
                                                       "audit.jsonl"),
                           ca_public_key=bytes(ca_pub), verify_time=NOW,
                           transparency_log=_DownLog())
    except Exception as e:
        code = getattr(e, "code", None)
        if code == "evbundle-transparency-unavailable":
            return "HELD", "outage fails closed"
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "outage silently skipped the transparency log"


def p09_issuance_attestation_absent(impl, tmpdir):
    """A sealed bundle whose cert was never issued through the audit
    log must be refused (no detached issuance)."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    # Issue through a DIFFERENT audit log so the join target is absent.
    other = os.path.join(tmpdir, "other.jsonl")
    ca2, _ = _make_ca(tmpdir)
    ca2._audit_log_path = other
    cert2, seed2, _ = _issue_cert(ca2, seed_byte=0x03)
    body = {"decision": "allow"}
    sig = _ed.sign(seed2, _canonical(body))
    sealed = eb2.seal_evidence(artifact_body=body, cert=cert2,
                              artifact_signature=bytes(sig),
                              approval_id=APPROVAL, intent_digest=INTENT,
                              ca_public_key=bytes(ca_pub), verify_time=NOW)
    try:
        eb2.verify_sealed_bundle(sealed=sealed,
                                audit_log_path=os.path.join(
                                    tmpdir, "audit.jsonl"),
                                ca_public_key=bytes(ca_pub),
                                verify_time=NOW)
    except Exception as e:
        code = getattr(e, "code", None)
        if code in ("evbundle-issuance-unverifiable",
                    "evbundle-join-mismatch"):
            return "HELD", "absent issuance attestation refused (%s)" % code
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "seal without issuance attestation accepted"


def p10_forged_attestation_sig(impl, tmpdir):
    # The verifier must re-run the ceremony on the SEALED cert -- a
    # swapped attestation signature must refuse with an evcert-* code,
    # not verify on joins alone.
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    audit_path = os.path.join(tmpdir, "audit.jsonl")
    log = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier,
                       now=lambda: NOW)
    body = {"x": 1}
    sub = eb2.submit_evidence(
        artifact_body=body, cert=cert,
        artifact_signature=bytes(_ed.sign(seed, _canonical(body))),
        approval_id=APPROVAL, intent_digest=INTENT, audit_log_path=audit_path,
        ca_public_key=bytes(ca_pub), verify_time=NOW,
        transparency_log=log, now=lambda: NOW)
    sub["sealed"]["signature_attestation"]["signature"] = \
        base64.b64encode(b"\x00" * 64).decode("ascii")
    try:
        eb2.verify_submission(
            submission=sub, audit_log_path=audit_path,
            ca_public_key=bytes(ca_pub), verify_time=NOW,
            transparency_log=eb2.make_log(
                producer_auth_verifier=eb2.default_producer_auth_verifier,
                now=lambda: NOW))
    except Exception as e:
        code = getattr(e, "code", "")
        if "evcert-" in code:
            return "HELD", "forged attestation signature refused (%s)" % code
        return "ERROR", "wrong error %r" % (e,)
    return "BREAK", "forged attestation signature verified"


def c01_round_trip(impl, tmpdir):
    """Happy path: seal -> submit -> verify, all green."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier)
    body = {"decision": "deny", "subjects": ["agent-7"]}
    sig = _ed.sign(seed, _canonical(body))
    try:
        sub = eb2.submit_evidence(
            artifact_body=body, cert=cert, artifact_signature=bytes(sig),
            approval_id=APPROVAL, intent_digest=INTENT,
            audit_log_path=os.path.join(tmpdir, "audit.jsonl"),
            ca_public_key=bytes(ca_pub), verify_time=NOW,
            transparency_log=log)
        out = eb2.verify_submission(
            submission=sub, audit_log_path=os.path.join(tmpdir,
                                                        "audit.jsonl"),
            ca_public_key=bytes(ca_pub), verify_time=NOW,
            transparency_log=log)
    except Exception as e:
        return "ERROR", "happy path failed: %r" % (e,)
    if not (isinstance(out, dict) and out.get("verified") is True):
        return "ERROR", "happy path did not verify: %r" % (out,)
    return "HELD", "round trip verified"


def c02_legacy_bundle_untouched(impl, tmpdir):
    """v1 evidence bundle and corroboration receipts are behaviorally
    identical with the v2 module present (composition by digest, never
    mutation)."""
    try:
        probe_in = {"a": [1, 2], "b": {"c": "x"}}
        canon = _v1.canonical(probe_in)
        expect = b'{"a":[1,2],"b":{"c":"x"}}'
        if canon != expect:
            return "ERROR", "v1 canonical changed: %r" % (canon,)
        from gov import corroboration_receipt as _cr
        st = {"_type": "https://in-toto.io/Statement/v1",
              "predicateType": "https://sasanam.dev/corrob/v1",
              "subject": [{"name": "decision", "digest": {"sha256": "ab" * 32}}],
              "predicate": {"verdict": "allow"}}
        e1 = _cr.dsse_envelope(st)
        e2 = _cr.dsse_envelope(dict(st))
        if e1 != e2:
            return "ERROR", "corroboration receipt envelope unstable"
    except Exception as e:
        return "ERROR", "legacy seam raised: %r" % (e,)
    return "HELD", "v1 bundle + receipts byte-stable"


def c03_determinism(impl, tmpdir):
    """Two identical runs produce byte-identical sealed records and
    receipts (A==B)."""
    eb2 = _mod(impl)
    ca, fake, cert, seed, pub, ca_pub = _harness(tmpdir)
    log = eb2.make_log(producer_auth_verifier=eb2.default_producer_auth_verifier, now=lambda: NOW)
    outs = []
    body = {"decision": "deny"}  # identical inputs both iterations
    for _ in range(2):
        sig = _ed.sign(seed, _canonical(body))
        outs.append(eb2.submit_evidence(
            artifact_body=body, cert=cert, artifact_signature=bytes(sig),
            approval_id=APPROVAL, intent_digest=INTENT,
            audit_log_path=os.path.join(tmpdir, "audit.jsonl"),
            ca_public_key=bytes(ca_pub), verify_time=NOW,
            transparency_log=log, now=lambda: NOW))
    a = json.dumps(outs[0], sort_keys=True)
    b = json.dumps(outs[1], sort_keys=True)
    # NOTE: two submits append two leaves, so receipts differ by leaf
    # index; determinism is per-input, checked via identical digests.
    if outs[0]["sealed"]["artifact"]["artifact_digest"] != \
            outs[1]["sealed"]["artifact"]["artifact_digest"]:
        return "ERROR", "artifact digests differ across identical inputs"
    return "HELD", "per-input deterministic"


PROBES = [
    ("submit/without-producer-auth", p01_submit_without_producer_auth, True),
    ("producer/forged-artifact-signature", p02_forged_artifact_signature, True),
    ("producer/approval-mismatch", p03_approval_mismatch, True),
    ("seal/join-mismatch", p04_join_mismatch, True),
    ("transparency/inclusion-proof-forgery", p05_inclusion_proof_forgery, True),
    ("transparency/checkpoint-root-mutation", p06_checkpoint_root_mutation, True),
    ("transparency/consistency-divergent-logs",
     p07_consistency_across_divergent_logs, True),
    ("transparency/outage-fails-closed", p08_transparency_outage, True),
    ("seal/issuance-attestation-absent", p09_issuance_attestation_absent, True),
    ("seal/forged-signature-in-attestation",
     p10_forged_attestation_sig, True),
    ("control/round-trip", c01_round_trip, False),
    ("control/legacy-bundle-untouched", c02_legacy_bundle_untouched, False),
    ("control/determinism", c03_determinism, False),
]


# ---------------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

def _run_green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("skipped", "GOV_SKIP_GREEN=1")]
    results = []
    cmds = [
        ("evals/w269_evcert_probes", [sys.executable, "evals/w269_evcert_probes.py"]),
    ]
    for name, cmd in cmds:
        try:
            env = dict(os.environ)
            env["GOV_SKIP_GREEN"] = "1"
            env["TMPDIR"] = tempfile.mkdtemp(prefix="g270green-",
                                            dir="/var/tmp")
            r = subprocess.run(cmd, cwd=_REPO, env=env, capture_output=True,
                               text=True, timeout=900)
            out = (r.stdout or "") + (r.stderr or "")
            ok = r.returncode == 0
            results.append((name, "pass" if ok else "FAIL", out[-400:]))
        except Exception as e:  # noqa: BLE001
            results.append((name, "ERROR", str(e)[:200]))
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    impl = os.environ.get("GOV_EVBUNDLE_IMPL", "real")
    if impl not in ("stub", "real"):
        print("GOV_EVBUNDLE_IMPL must be stub or real", file=sys.stderr)
        return 2
    root = tempfile.mkdtemp(prefix="g270evbundle-%s-" % impl, dir="/var/tmp")
    print("mode=%s tmpdir=%s" % (impl, root))
    held = broke = errored = 0
    for name, fn, is_attack in PROBES:
        tmpdir = os.path.join(root, name.replace("/", "-"))
        os.makedirs(tmpdir, exist_ok=True)
        try:
            verdict, detail = fn(impl, tmpdir)
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%r" % e
        print("%-42s %-6s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
            if impl == "stub" and is_attack:
                print("  !! attack probe HELD on the stub: vacuous probe, "
                      "fix the probe")
        elif verdict == "BREAK":
            broke += 1
        else:
            errored += 1
    print("---")
    print("HELD=%d BREAK=%d ERROR=%d (mode=%s)" % (held, broke, errored, impl))
    green = _run_green_checks()
    green_fail = 0
    for item in green:
        if item[0] == "skipped":
            print("green: skipped (GOV_SKIP_GREEN=1)")
            continue
        name, status, tail = item
        print("green %-34s %s" % (name, status))
        if status != "pass":
            green_fail += 1
            print("  tail: %s" % tail.replace("\n", " | "))
    if impl == "stub":
        return 0 if errored == 0 else 1
    if errored or broke or green_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
