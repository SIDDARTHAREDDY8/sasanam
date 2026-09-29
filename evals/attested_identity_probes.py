#!/usr/bin/env python3
"""Red-first break battery for wave-204: attested agent identity.

The gap (pristine tree): agent identity is a config-file claim -- there is
no way to bind an agent's identity to attested facts (TPM quote, cloud
instance-identity document), no containment of the weaker kernel-fact
identity tier, and no attested-bootstrap ceremony. ``gov.attested_identity``
does not exist on the pristine tree.

Pristine expectation: P0 BREAK (the gap); every other probe EXPECTED
(cannot run without the module -- recorded, not faked green).
Fixed expectation: every probe HELD.

Adapted from the wave-204 Lane A spike (verdict ADAPT): the spike proved
the ceremony against synthetic fixtures with real RSA-2048 signatures;
this battery ports its 21 falsifiable criteria to the real module and
adds probes for the real TPM 2.0 marshal, the BOM/PolicyReport evidence
wiring, graceful degradation, and the pinned-issuer authorization rule.

Stdlib only (openssl CLI is fixture-only: RSA key generation and fixture
signing; every VERIFIER under test is stdlib). Deterministic in outcome
(fixture keys and nonces are random; all assertions are on properties,
never on fixed bytes). Sets GOV_DEPLOYMENT_MODE=staging at module level;
verify standalone under ``env -u GOV_DEPLOYMENT_MODE``. Honors
GOV_SKIP_GREEN=1 (green check is depth-1: the adjacent unit suite only,
never nested battery mains).
"""

import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
_HAS_MODULE = importlib.util.find_spec("gov.attested_identity") is not None

RESULTS = []


class _Expected(Exception):
    """Raised when a probe cannot run because the module is absent."""


def check(name, fn):
    try:
        detail = fn()
    except _Expected as e:
        RESULTS.append((name, "EXPECTED", str(e)))
        print("  EXPECTED %s: %s" % (name, e))
        return
    except AssertionError as e:
        RESULTS.append((name, "BROKEN", str(e)))
        print("  BROKEN %s: %s" % (name, e))
        return
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "%s: %s" % (type(e).__name__, e)))
        print("  ERROR %s: %s: %s" % (name, type(e).__name__, e))
        return
    if (isinstance(detail, tuple) and len(detail) == 2
            and detail[0] in ("BREAK",)):
        RESULTS.append((name, detail[0], detail[1]))
        print("  %s %s: %s" % (detail[0], name, detail[1]))
        return
    RESULTS.append((name, "HELD", detail))
    print("  HELD  %s: %s" % (name, detail))


def _expected(name):
    raise _Expected("gov.attested_identity absent (pristine gap)")


# ---------------------------------------------------------------- fixtures
# Fixture-only RSA via openssl CLI (mirrors the spike's fixtures.py: the
# SIGNERS are openssl; every VERIFIER under test is stdlib-only).

def _run_openssl(*args, input_bytes=None):
    return subprocess.run(["openssl", *args], input=input_bytes,
                          capture_output=True, check=True).stdout


class _TestKey:
    def __init__(self, name, workdir):
        self.priv = os.path.join(workdir, name + ".pem")
        pub_pem_path = os.path.join(workdir, name + ".pub.pem")
        _run_openssl("genpkey", "-algorithm", "RSA",
                     "-pkeyopt", "rsa_keygen_bits:2048", "-out", self.priv)
        pub_pem = _run_openssl("pkey", "-in", self.priv, "-pubout")
        with open(pub_pem_path, "wb") as f:
            f.write(pub_pem)
        self.pubkey_der = _run_openssl(
            "pkey", "-pubin", "-inform", "PEM", "-outform", "DER",
            input_bytes=pub_pem)

    def sign(self, message):
        return _run_openssl("dgst", "-sha256", "-sign", self.priv,
                            input_bytes=message)


_FIX = {}


def _fixtures():
    if _FIX:
        return _FIX
    import gov.attested_identity as ai
    from gov.signing import Ed25519Signer
    workdir = tempfile.mkdtemp(prefix="g204d-attest-")
    keys = {n: _TestKey(n, workdir) for n in (
        "ek", "aik", "rogue_aik", "aws_signer", "gcp_signer", "attacker")}
    issuer = Ed25519Signer(os.urandom(32))
    pcr_good = hashlib.sha256(b"measured-boot-state-v1").digest()
    pcr_bad = hashlib.sha256(b"measured-boot-state-v2-rootkit").digest()
    selections = [(ai.TPM_ALG_SHA256, b"\xff\xff")]

    def new_attester(**kw):
        params = dict(
            quote_verifier=ai.QuoteVerifier(
                trusted_ek_pubkeys_der=[keys["ek"].pubkey_der],
                expected_pcr_digest=pcr_good,
                expected_pcr_selections=selections),
            aws_verifier=ai.AwsStyleVerifier(
                signer_pubkey_der=keys["aws_signer"].pubkey_der,
                allowed_account_ids={"123456789012"},
                allowed_regions={"us-east-1"}),
            gcp_verifier=ai.GcpStyleVerifier(
                signer_pubkey_der=keys["gcp_signer"].pubkey_der,
                expected_audience="sasanam-agents",
                allowed_projects={"trusted-proj"},
                allowed_zones={"us-central1-a"}),
        )
        params.update(kw)
        return ai.Attester(issuer, **params)

    endorsement = ai.endorse_aik(keys["aik"].pubkey_der, keys["ek"].sign)

    def good_quote(nonce):
        return ai.make_quote(nonce=nonce, pcr_digest=pcr_good,
                             pcr_selections=selections,
                             signer=keys["aik"].sign)

    _FIX.update(ai=ai, keys=keys, issuer=issuer, pcr_good=pcr_good,
                pcr_bad=pcr_bad, selections=selections,
                new_attester=new_attester, endorsement=endorsement,
                good_quote=good_quote)
    return _FIX


def _refused(fn, label, *err_types):
    import gov.attested_identity as ai
    errs = err_types or (ai.AttestedIdentityError,)
    try:
        fn()
    except errs as e:
        return "refused as required (%s: %s)" % (type(e).__name__, e)
    raise AssertionError("%s was NOT refused" % (label,))


# ---------------------------------------------------------------- probes

def p0_module_present():
    """gov.attested_identity exists with the full public seam."""
    if not _HAS_MODULE:
        return "BREAK", "gov.attested_identity absent (pristine gap)"
    import gov.attested_identity as ai
    seam = ("TIER_ATTESTED", "TIER_KERNEL_FACT", "ACTION_POLICY",
            "TPM_ALG_SHA256", "QuoteError", "IidError", "IdentityError",
            "AttestedIdentityError", "QuoteVerifier", "AwsStyleVerifier",
            "GcpStyleVerifier", "Attester", "Identity",
            "marshal_tpms_attest_quote", "parse_tpms_attest_quote",
            "make_quote", "endorse_aik", "canonical_json",
            "make_aws_style_doc", "make_gcp_style_jwt",
            "credential_body", "credential_signing_bytes",
            "bom_identity_section", "credential_digest_of",
            "degraded_attester")
    missing = [n for n in seam if not hasattr(ai, n)]
    if missing:
        return "BREAK", "missing seam: %r" % (missing,)
    if ai.TIER_ATTESTED != 1 or ai.TIER_KERNEL_FACT != 2:
        return "BREAK", "tier constants wrong"
    return "HELD", "full seam present; tiers 1=attested 2=kernel-fact"


def p1_valid_quote_bootstraps_tier1():
    if not _HAS_MODULE:
        return _expected("P1")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    cid, nonce = a.issue_challenge("agent-1")
    ident = a.bootstrap_with_tpm_quote(
        challenge_id=cid, quote=f["good_quote"](nonce),
        aik_pubkey_der=f["keys"]["aik"].pubkey_der,
        endorsement=f["endorsement"])
    assert ident.tier == ai.TIER_ATTESTED, "not tier 1"
    assert a.verify_credential(ident), "credential does not verify (pinned)"
    a.authorize(ident, "sign_evidence")
    a.authorize(ident, "approve_release")
    return "tier-1 bootstrapped; sign_evidence + approve_release granted"


def p2_tier2_telemetry():
    if not _HAS_MODULE:
        return _expected("P2")
    f = _fixtures()
    a = f["new_attester"]()
    t2 = a.register_kernel_fact_identity(cgroup="/kubepods/agent-7",
                                          uid=1000, hostname="node-3")
    assert t2.tier == f["ai"].TIER_KERNEL_FACT
    assert "NOT ATTESTED" in json.dumps(t2.claims), "warning missing"
    a.authorize(t2, "emit_telemetry")
    return "tier-2 emits telemetry; label carries NOT-ATTESTED warning"


def a1_attacker_signed_quote():
    if not _HAS_MODULE:
        return _expected("A1")
    f = _fixtures()
    a = f["new_attester"]()
    cid, nonce = a.issue_challenge("agent-1")
    q = f["good_quote"](nonce)
    q["signature"] = f["keys"]["attacker"].sign(q["attested"])
    return _refused(
        lambda: a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=f["keys"]["aik"].pubkey_der,
            endorsement=f["endorsement"]),
        "attacker-signed quote")


def a2_tampered_pcr():
    if not _HAS_MODULE:
        return _expected("A2")
    f = _fixtures()
    a = f["new_attester"]()
    cid, nonce = a.issue_challenge("agent-1")
    q = f["good_quote"](nonce)
    tampered = bytearray(q["attested"])
    tampered[-1] ^= 0xFF
    q["attested"] = bytes(tampered)
    return _refused(
        lambda: a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=f["keys"]["aik"].pubkey_der,
            endorsement=f["endorsement"]),
        "tampered PCR digest")


def a3_unendorsed_aik():
    if not _HAS_MODULE:
        return _expected("A3")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    cid, nonce = a.issue_challenge("agent-1")
    q = ai.make_quote(nonce=nonce, pcr_digest=f["pcr_good"],
                      pcr_selections=f["selections"],
                      signer=f["keys"]["rogue_aik"].sign)
    return _refused(
        lambda: a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=f["keys"]["rogue_aik"].pubkey_der,
            endorsement=None),
        "unendorsed AIK")


def a4_forged_endorsement():
    if not _HAS_MODULE:
        return _expected("A4")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    cid, nonce = a.issue_challenge("agent-1")
    q = ai.make_quote(nonce=nonce, pcr_digest=f["pcr_good"],
                      pcr_selections=f["selections"],
                      signer=f["keys"]["rogue_aik"].sign)
    fake_end = ai.endorse_aik(f["keys"]["rogue_aik"].pubkey_der,
                              f["keys"]["attacker"].sign)
    return _refused(
        lambda: a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=f["keys"]["rogue_aik"].pubkey_der,
            endorsement=fake_end),
        "attacker-endorsed AIK")


def b1_stale_nonce():
    if not _HAS_MODULE:
        return _expected("B1")
    f = _fixtures()
    a = f["new_attester"]()
    cid1, nonce1 = a.issue_challenge("agent-1")
    cid2, _nonce2 = a.issue_challenge("agent-1")
    q = f["good_quote"](nonce1)
    return _refused(
        lambda: a.bootstrap_with_tpm_quote(
            challenge_id=cid2, quote=q,
            aik_pubkey_der=f["keys"]["aik"].pubkey_der,
            endorsement=f["endorsement"]),
        "quote replayed against a new challenge")


def b2_evidence_single_use():
    if not _HAS_MODULE:
        return _expected("B2")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    cid1, _ = a.issue_challenge("agent-1")
    bundle = ai.make_aws_style_doc(
        instance_id="i-0abc", account_id="123456789012",
        region="us-east-1", signer=f["keys"]["aws_signer"].sign)
    a.bootstrap_with_aws_iid(challenge_id=cid1, bundle=bundle)
    cid2, _ = a.issue_challenge("agent-1")
    return _refused(
        lambda: a.bootstrap_with_aws_iid(challenge_id=cid2, bundle=bundle),
        "same AWS evidence used for a second bootstrap")


def b3_wrong_boot_state():
    if not _HAS_MODULE:
        return _expected("B3")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    cid, nonce = a.issue_challenge("agent-1")
    q = ai.make_quote(nonce=nonce, pcr_digest=f["pcr_bad"],
                      pcr_selections=f["selections"],
                      signer=f["keys"]["aik"].sign)
    return _refused(
        lambda: a.bootstrap_with_tpm_quote(
            challenge_id=cid, quote=q,
            aik_pubkey_der=f["keys"]["aik"].pubkey_der,
            endorsement=f["endorsement"]),
        "quote from unexpected boot state")


def b4_aws_doc_replays_by_design():
    if not _HAS_MODULE:
        return _expected("B4")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    bundle = ai.make_aws_style_doc(
        instance_id="i-0abc", account_id="123456789012",
        region="us-east-1", signer=f["keys"]["aws_signer"].sign)
    doc1 = a.aws_verifier.verify(bundle)
    doc2 = a.aws_verifier.verify(bundle)
    assert doc1 == doc2
    return ("valid AWS doc re-verifies (host identity, not liveness) -- "
            "contrast B2: the *bootstrap* is single-use, not the doc")


def c1_tier2_sign_refused():
    if not _HAS_MODULE:
        return _expected("C1")
    f = _fixtures()
    a = f["new_attester"]()
    t2 = a.register_kernel_fact_identity(cgroup="/kubepods/agent-7",
                                          uid=1000, hostname="node-3")
    return _refused(lambda: a.authorize(t2, "sign_evidence"),
                    "tier-2 sign_evidence")


def c2_tier2_approve_refused():
    if not _HAS_MODULE:
        return _expected("C2")
    f = _fixtures()
    a = f["new_attester"]()
    t2 = a.register_kernel_fact_identity(cgroup="/kubepods/agent-7",
                                          uid=1000, hostname="node-3")
    return _refused(lambda: a.authorize(t2, "approve_release"),
                    "tier-2 approve_release")


def c3_relabel_attack():
    if not _HAS_MODULE:
        return _expected("C3")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    t2 = a.register_kernel_fact_identity(cgroup="/kubepods/evil",
                                          uid=0, hostname="node-9")
    forged = ai.Identity(tier=ai.TIER_ATTESTED, claims=t2.claims,
                         credential_sig=t2.credential_sig,
                         expires_at=t2.expires_at)
    return _refused(lambda: a.authorize(forged, "sign_evidence"),
                    "relabelled tier-2 credential")


def c4_attacker_minted_credential():
    if not _HAS_MODULE:
        return _expected("C4")
    f = _fixtures()
    ai = f["ai"]
    from gov import ed25519 as _ed
    a = f["new_attester"]()
    # Attacker mints a tier-1-looking credential with their OWN Ed25519 key.
    # authorize() must verify against the attester's PINNED issuer key, and
    # the Identity carries no issuer key at all (the C4 structural fix).
    atk_seed = os.urandom(32)
    body = ai.credential_body(ai.TIER_ATTESTED,
                              {"kind": "tpm_attested",
                               "pcr_digest": "00" * 32},
                              9999999999)
    sig = _ed.sign(atk_seed, ai.credential_signing_bytes(body))
    forged = ai.Identity(tier=ai.TIER_ATTESTED, claims=body["claims"],
                         credential_sig=sig, expires_at=body["expires_at"])
    assert not hasattr(forged, "issuer_pubkey_der"), \
        "identity must not carry a presented issuer key"
    return _refused(lambda: a.authorize(forged, "sign_evidence"),
                    "attacker-minted credential")


def d1_wrong_account():
    if not _HAS_MODULE:
        return _expected("D1")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    bundle = ai.make_aws_style_doc(
        instance_id="i-0abc", account_id="999999999999",
        region="us-east-1", signer=f["keys"]["aws_signer"].sign)
    return _refused(lambda: a.aws_verifier.verify(bundle), "wrong accountId")


def d2_wrong_region():
    if not _HAS_MODULE:
        return _expected("D2")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    bundle = ai.make_aws_style_doc(
        instance_id="i-0abc", account_id="123456789012",
        region="eu-west-1", signer=f["keys"]["aws_signer"].sign)
    return _refused(lambda: a.aws_verifier.verify(bundle), "wrong region")


def d3_forged_aws_doc():
    if not _HAS_MODULE:
        return _expected("D3")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    bundle = ai.make_aws_style_doc(
        instance_id="i-0abc", account_id="123456789012",
        region="us-east-1", signer=f["keys"]["attacker"].sign)
    return _refused(lambda: a.aws_verifier.verify(bundle),
                    "attacker-signed doc")


def d4_gcp_wrong_audience():
    if not _HAS_MODULE:
        return _expected("D4")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    token = ai.make_gcp_style_jwt(
        instance_id="123", project_id="trusted-proj",
        zone="us-central1-a", audience="someone-else",
        signer=f["keys"]["gcp_signer"].sign)
    return _refused(lambda: a.gcp_verifier.verify(token), "wrong aud")


def d5_gcp_expired():
    if not _HAS_MODULE:
        return _expected("D5")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    token = ai.make_gcp_style_jwt(
        instance_id="123", project_id="trusted-proj",
        zone="us-central1-a", audience="sasanam-agents",
        signer=f["keys"]["gcp_signer"].sign, lifetime_s=-300)
    return _refused(lambda: a.gcp_verifier.verify(token), "expired token")


def d6_gcp_wrong_project():
    if not _HAS_MODULE:
        return _expected("D6")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    token = ai.make_gcp_style_jwt(
        instance_id="123", project_id="evil-proj",
        zone="us-central1-a", audience="sasanam-agents",
        signer=f["keys"]["gcp_signer"].sign)
    return _refused(lambda: a.gcp_verifier.verify(token), "wrong project")


def d7_gcp_positive():
    if not _HAS_MODULE:
        return _expected("D7")
    f = _fixtures()
    ai = f["ai"]
    a = f["new_attester"]()
    token = ai.make_gcp_style_jwt(
        instance_id="123", project_id="trusted-proj",
        zone="us-central1-a", audience="sasanam-agents",
        signer=f["keys"]["gcp_signer"].sign)
    payload = a.gcp_verifier.verify(token)
    assert payload["instance_id"] == "123"
    return "valid GCP JWT verifies; claims extracted"


def e1_marshal_strictness():
    if not _HAS_MODULE:
        return _expected("E1")
    f = _fixtures()
    ai = f["ai"]
    good = ai.marshal_tpms_attest_quote(
        qualified_signer=b"AIK", extra_data=b"nonce",
        clock=1, reset_count=1, restart_count=1, safe=True,
        firmware_version=1, pcr_selections=f["selections"],
        pcr_digest=f["pcr_good"])
    for label, bad in (
            ("trailing bytes", good + b"\x00"),
            ("truncated", good[:-5]),
            ("bad magic", b"\x00\x00\x00\x00" + good[4:]),
            ("bad type", good[:4] + b"\x00\x00" + good[6:])):
        try:
            ai.parse_tpms_attest_quote(bad)
        except ai.QuoteError:
            continue
        raise AssertionError("malformed quote accepted: %s" % (label,))
    return "trailing/truncated/bad-magic/bad-type all raise QuoteError"


def e2_marshal_round_trip():
    if not _HAS_MODULE:
        return _expected("E2")
    f = _fixtures()
    ai = f["ai"]
    selections = [(ai.TPM_ALG_SHA256, b"\x03"),
                  (ai.TPM_ALG_SHA1, b"\xff\xff")]
    blob = ai.marshal_tpms_attest_quote(
        qualified_signer=b"AIK-NAME", extra_data=b"n" * 32,
        clock=999, reset_count=3, restart_count=4, safe=False,
        firmware_version=0x0102030405060708,
        pcr_selections=selections, pcr_digest=f["pcr_good"])
    p = ai.parse_tpms_attest_quote(blob)
    assert p["magic"] == 0xFF544347, "magic"
    assert p["type"] == 0x8018, "type"
    assert p["qualified_signer"] == b"AIK-NAME", "signer"
    assert p["extra_data"] == b"n" * 32, "extra_data"
    assert (p["clock"], p["reset_count"], p["restart_count"]) == (999, 3, 4)
    assert p["safe"] is False, "safe"
    assert p["firmware_version"] == 0x0102030405060708, "fw"
    assert p["pcr_selections"] == selections, "selections"
    assert p["pcr_digest"] == f["pcr_good"], "digest"
    return "real TPM 2.0 marshal round-trips all fields byte-exact"


def e3_degraded_attester():
    if not _HAS_MODULE:
        return _expected("E3")
    f = _fixtures()
    ai = f["ai"]
    a = ai.degraded_attester(f["issuer"])
    t2 = a.register_kernel_fact_identity(cgroup="/x", uid=1,
                                          hostname="h")
    a.authorize(t2, "emit_telemetry")
    for meth, kw in (
            ("bootstrap_with_tpm_quote",
             {"challenge_id": "x", "quote": {},
              "aik_pubkey_der": b"", "endorsement": None}),
            ("bootstrap_with_aws_iid",
             {"challenge_id": "x", "bundle": {}}),
            ("bootstrap_with_gcp_jwt",
             {"challenge_id": "x", "token": ""})):
        try:
            getattr(a, meth)(**kw)
        except ai.IdentityError as e:
            assert "no " in str(e) and "verifier" in str(e), str(e)
            continue
        raise AssertionError("%s did not refuse on degraded attester"
                             % (meth,))
    return ("no TPM/cloud path -> tier-1 bootstrap refused loudly; "
            "tier-2 still works")


def e4_expired_credential():
    if not _HAS_MODULE:
        return _expected("E4")
    f = _fixtures()
    a = f["new_attester"](credential_ttl_s=1)
    cid, nonce = a.issue_challenge("agent-1")
    ident = a.bootstrap_with_tpm_quote(
        challenge_id=cid, quote=f["good_quote"](nonce),
        aik_pubkey_der=f["keys"]["aik"].pubkey_der,
        endorsement=f["endorsement"])
    return _refused(
        lambda: a.authorize(ident, "sign_evidence",
                            now=ident.expires_at + 3600),
        "expired credential")


def e5_unknown_action():
    if not _HAS_MODULE:
        return _expected("E5")
    f = _fixtures()
    a = f["new_attester"]()
    t2 = a.register_kernel_fact_identity(cgroup="/x", uid=1,
                                          hostname="h")
    return _refused(lambda: a.authorize(t2, "launch_missiles"),
                    "unknown action")


def e6_bom_wiring():
    if not _HAS_MODULE:
        return _expected("E6")
    f = _fixtures()
    ai = f["ai"]
    from gov import decision_bom as bom
    a = f["new_attester"]()
    cid, nonce = a.issue_challenge("agent-1")
    ident = a.bootstrap_with_tpm_quote(
        challenge_id=cid, quote=f["good_quote"](nonce),
        aik_pubkey_der=f["keys"]["aik"].pubkey_der,
        endorsement=f["endorsement"])
    section = ai.bom_identity_section(ident)
    assert set(section) == {"tier", "credential_digest",
                            "evidence_digest"}, section.keys()
    bundle_bytes = b"policy-bundle-fixture"
    bundle_digest = hashlib.sha256(bundle_bytes).hexdigest()
    b = bom.build_bom(policy_id="p", policy_version="v1",
                      policy_digest=bundle_digest,
                      evidence_head_digest="1" * 64,
                      principal={"agent_id": "a1"},
                      attested_identity=section)
    ok, reason = bom.check_bom_shape(b)
    assert ok, reason
    assert b["inputs"]["attested_identity"]["tier"] == 1
    # tampered tier in the section -> shape fails (mutate post-build so
    # the shape checker is tested independently of the builder, which
    # already refuses tier != 1 loudly at build time)
    b2 = bom.build_bom(policy_id="p", policy_version="v1",
                       policy_digest=bundle_digest,
                       evidence_head_digest="1" * 64,
                       principal={"agent_id": "a1"},
                       attested_identity=section)
    b2["inputs"]["attested_identity"]["tier"] = 99
    ok2, _ = bom.check_bom_shape(b2)
    assert not ok2, "tampered tier accepted by shape check"
    # verify_bom re-derives the credential digest (MATCH leg)
    ok3, r3 = bom.verify_bom(
        b, policy_bundle_bytes=bundle_bytes,
        identity_credential_body=ident.credential_body())
    assert ok3, r3
    assert "attested-identity" in r3, r3
    # swapped credential -> re-derivation fails
    other = ai.Identity(tier=ai.TIER_KERNEL_FACT, claims={},
                        credential_sig=b"\x00" * 64, expires_at=1)
    ok4, _ = bom.verify_bom(
        b, policy_bundle_bytes=bundle_bytes,
        identity_credential_body=other.credential_body())
    assert not ok4, "swapped credential accepted"
    # section present but no credential supplied -> UNVERIFIED, named
    ok5, r5 = bom.verify_bom(b, policy_bundle_bytes=bundle_bytes)
    assert ok5 and "unverified: attested-identity" in r5, r5
    # absence keeps BOMs byte-identical
    b6 = bom.build_bom(policy_id="p", policy_version="v1",
                       policy_digest=bundle_digest,
                       evidence_head_digest="1" * 64,
                       principal={"agent_id": "a1"})
    assert "attested_identity" not in b6["inputs"]
    return ("tier rides inputs.attested_identity; shape + re-derivation + "
            "UNVERIFIED legs all behave; absence byte-identical")


def e7_policy_report_wiring():
    if not _HAS_MODULE:
        return _expected("E7")
    from gov import policy_report as pr
    from gov import mode_ledger as ml
    ledger = ml.ModeLedger(clock=lambda: 1700000000.0)
    ledger.register_rule("r1", mode="warn")
    ledger.observe("r1", mode="warn", matched=True, nominal_effect="queue",
                   request_digest="d" * 64)
    rep1 = pr.build_report(ledger, policy_name="p")
    assert "identityTier" not in rep1["metadata"], "tier leaked by default"
    rep2 = pr.build_report(ledger, policy_name="p", identity_tier=1)
    assert rep2["metadata"]["identityTier"] == "tier-1-attested", \
        rep2["metadata"]
    rep3 = pr.build_report(ledger, policy_name="p", identity_tier=2)
    assert rep3["metadata"]["identityTier"] == "tier-2-kernel-fact"
    try:
        pr.build_report(ledger, policy_name="p", identity_tier=3)
    except pr.PolicyReportError:
        pass
    else:
        raise AssertionError("invalid tier accepted")
    r = pr.project_result(
        next(rec for rec in ledger._chain if rec["rule_id"] == "r1"),
        policy_name="p", identity_tier=2)
    assert r["properties"]["identity_tier"] == 2, r["properties"]
    return "tier label rides report metadata + result properties; " \
        "invalid tier refused; omitted by default"


def e8_bool_tier_refused():
    if not _HAS_MODULE:
        return _expected("E8")
    f = _fixtures()
    ai = f["ai"]
    from gov import decision_bom as bom
    from gov import policy_report as pr
    # True == 1 in Python: tier=True must never mint, bind, or label
    # tier-1 anywhere on the seam.
    for label, fn in (
            ("Identity(tier=True)",
             lambda: ai.Identity(tier=True, claims={},
                                 credential_sig=b"\x00", expires_at=1)),
            ("credential_body(True, ...)",
             lambda: ai.credential_body(True, {}, 1)),
            ("build_bom tier=True",
             lambda: bom.build_bom(
                 policy_id="p", policy_version="v1",
                 policy_digest="0" * 64, evidence_head_digest="1" * 64,
                 principal={"agent_id": "a1"},
                 attested_identity={"tier": True,
                                    "credential_digest": "a" * 64,
                                    "evidence_digest": "b" * 64})),
            ("build_report identity_tier=True",
             lambda: pr.build_report(_e8_ledger(), policy_name="p",
                                     identity_tier=True))):
        try:
            fn()
        except (ai.IdentityError, bom.BomError, pr.PolicyReportError):
            continue
        raise AssertionError("%s accepted bool tier" % (label,))
    return "tier=True refused at identity, credential, BOM, and report"


def _e8_ledger():
    from gov import mode_ledger as ml
    ledger = ml.ModeLedger(clock=lambda: 1700000000.0)
    ledger.register_rule("r1", mode="warn")
    ledger.observe("r1", mode="warn", matched=True,
                   nominal_effect="queue", request_digest="d" * 64)
    return ledger


def _green_check():
    """Depth-1: adjacent unit suite only, never nested battery mains."""
    import subprocess as _sp
    suite = os.path.join(REPO, "tests", "test_attested_identity.py")
    if not os.path.exists(suite):
        print("green check: unit suite not present yet (skip)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="g204d-green-")
    env["TMPDIR"] = tmpd
    p = _sp.run([sys.executable, "-m", "unittest",
                 "tests.test_attested_identity", "-v"],
                cwd=REPO, env=env, capture_output=True, text=True)
    tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
    print("green check (unit suite): %s" % (" | ".join(tail),))
    return p.returncode == 0


def main():
    print("== attested_identity red-team battery ==")
    probes = [p0_module_present, p1_valid_quote_bootstraps_tier1,
              p2_tier2_telemetry,
              a1_attacker_signed_quote, a2_tampered_pcr,
              a3_unendorsed_aik, a4_forged_endorsement,
              b1_stale_nonce, b2_evidence_single_use, b3_wrong_boot_state,
              b4_aws_doc_replays_by_design,
              c1_tier2_sign_refused, c2_tier2_approve_refused,
              c3_relabel_attack, c4_attacker_minted_credential,
              d1_wrong_account, d2_wrong_region, d3_forged_aws_doc,
              d4_gcp_wrong_audience, d5_gcp_expired, d6_gcp_wrong_project,
              d7_gcp_positive,
              e1_marshal_strictness, e2_marshal_round_trip,
              e3_degraded_attester, e4_expired_credential,
              e5_unknown_action, e6_bom_wiring, e7_policy_report_wiring,
              e8_bool_tier_refused]
    for probe in probes:
        check(probe.__name__, probe)
    print()
    held = sum(1 for _, s, _ in RESULTS if s == "HELD")
    gap = [n for n, s, _ in RESULTS if s == "BREAK"]
    broken = [n for n, s, _ in RESULTS if s == "BROKEN"]
    errors = [n for n, s, _ in RESULTS if s == "ERROR"]
    expected = sum(1 for _, s, _ in RESULTS if s == "EXPECTED")
    print("%d/%d HELD (%d EXPECTED)" % (held, len(RESULTS), expected))
    green_ok = True
    failed = gap + broken + errors
    if not _SKIP_GREEN and _HAS_MODULE and not failed:
        green_ok = _green_check()
    rc = 0 if (not failed and green_ok) else 1
    if gap:
        print("GAP (pristine red): %s" % (gap,))
    if broken:
        print("BROKEN: %s" % (broken,))
    if errors:
        print("ERROR: %s" % (errors,))
    if not green_ok:
        print("GREEN CHECK FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
