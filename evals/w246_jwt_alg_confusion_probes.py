"""Wave-246 JWT algorithm-confusion probes (lane 5, red-first).

Attacker shape ADAPTED from WSO2 CVE-2026-5430 (JWT algorithm
confusion, CWE-347): a verifier that takes the token's ``alg`` (or the
record's ``alg``) at face value and dispatches to a weaker primitive
lets an attacker re-label a token -- or mint a fresh one -- under an
algorithm the attacker controls (``alg:none``; HS256 with a public key
as the HMAC secret; unlisted algorithms; attacker-chosen ``kid``).

Probe classes:
  JOSE seams (``gov/agent_cards.py``, ``gov/attested_identity.py``'s
  ``GcpStyleVerifier``, ``gov/capability_manifests.py``,
  ``gov/eat_claims.py``): (a) ``alg:none`` refused, (b) HS256-for-pinned
  confusion refused, (c) non-allowlisted alg refused, (d) attacker
  ``kid`` refused, (e) valid pinned-alg token passes.
  ``alg_registry`` dispatch (the genuine finding this lane closed):
  (f) an HMAC-tier record verified with a PUBLIC key (attacker-known)
  refuses -- the exact RS256->HS256 shape; (g) a pinned HMAC with a
  real shared secret passes; (h) Ed25519 is unaffected.
  Record-module confusion through every affected module: absence,
  checkpoints, denial_capsule, deny_receipts, posture, revocation.

Non-JOSE seams (``gov/delegation_tokens.py``, ``gov/aauth_r3.py``)
carry no ``alg`` negotiation (custom dict envelopes, Ed25519 /
hash-bound) and are out of scope: documented here, not probed.
``gov/jwks_fetch.py`` is a fetch-only utility with no product
consumer (wave-245); not probed.

Stdlib only. Deterministic: fixed RSA fixture (copied from
tests/test_attested_identity.py), fixed seeds/keys, no real network,
no in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_SEAMS = False
try:
    from gov import agent_cards as _ac
    from gov import attested_identity as _ai
    from gov import capability_manifests as _cm
    from gov import eat_claims as _eat
    from gov import alg_registry as _ar
    from gov import absence as _ab
    from gov import checkpoints as _cp
    from gov import denial_capsule as _dcap
    from gov import deny_receipts as _dr
    from gov import posture as _po
    from gov import revocation as _rv
    from gov import ed25519 as _ed
    HAVE_SEAMS = all(hasattr(m, n) for m, n in (
        (_ac, "verify_card"), (_ai, "GcpStyleVerifier"),
        (_cm, "verify_manifest"), (_eat, "verify_eat"),
        (_ar, "default_registry"), (_ab, "verify_negative"),
        (_cp, "verify_checkpoint"), (_dcap, "verify_capsule"),
        (_dr, "verify"), (_po, "verify_signal"),
        (_rv, "RevocationList"), (_ed, "generate_seed")))
except ImportError:
    pass


def _run_probe(name, fn, have, pin=False):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, ("PIN" if pin else "HELD"), note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


# ----------------------------------------------------------------------
# Helpers: base64url and JOSE token minting (test-side only).
# ----------------------------------------------------------------------

import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402


def _b64u(data):
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def _jose_token(header, payload, sig=b""):
    return "%s.%s.%s" % (_b64u(json.dumps(header).encode()),
                         _b64u(json.dumps(payload).encode()),
                         _b64u(sig))


# Fixed 1024-bit RSA fixture (hermetic; copied from
# tests/test_attested_identity.py: generated once with openssl).
_TEST_N_HEX = (
    "00b3a35d6759ba875e28cdabd941c804c3a1d99ab9461c19e2ebca92cc8d"
    "3cdf9860c94c6bd1fffbbb67603119756a9a697552537f9f9eaabc1de199"
    "e1ae9b1f01a48bfb080e67ada449dee737d0339f0aa5d5a6d66e658c317"
    "adaf3839b959f41aa005215604fb43710a399560374cd1dbde1f3dc7672"
    "a39977c5e528d95c5e9d")
_TEST_D_HEX = (
    "0090f088d670b16db36d5cb501707000581068d0cc186368078d943ee9c8"
    "338b7d18ea923c948de4008b2233bb84df64831e643476cec568a0abc371"
    "33847c288100c55511d6ec6cc1261029a4f6a90e4d723be65427af430e50"
    "520668e23187e05b581064233c8e71e25c715761ad5447885906487dffab"
    "bff63b8fc9a2529181")
_TEST_SPKI_DER_HEX = (
    "30819f300d06092a864886f70d010101050003818d0030818902818100b3"
    "a35d6759ba875e28cdabd941c804c3a1d99ab9461c19e2ebca92cc8d3cdf"
    "9860c94c6bd1fffbbb67603119756a9a697552537f9f9eaabc1de199e1ae"
    "9b1f01a48bfb080e67ada449dee737d0339f0aa5d5a6d66e658c317adaf3"
    "839b959f41aa005215604fb43710a399560374cd1dbde1f3dc7672a39977"
    "c5e528d95c5e9d0203010001")
_TEST_DIGESTINFO_SHA256 = bytes.fromhex(
    "3031300d060960864801650304020105000420")


def _rsa_sign(message):
    n = int(_TEST_N_HEX, 16)
    d = int(_TEST_D_HEX, 16)
    digest = hashlib.sha256(bytes(message)).digest()
    t = _TEST_DIGESTINFO_SHA256 + digest
    k = (n.bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


# ----------------------------------------------------------------------
# Probe class 1: JOSE seams.
# ----------------------------------------------------------------------

def _ac_card_fields():
    return {
        "agent_id": "agent-acme-001",
        "name": "acme-agent",
        "version": "2.3.1",
        "capabilities": ["answer"],
        "endpoints": {"jsonrpc": "https://agents.example.com/acme"},
        "keys": [{"kid": "k1", "alg": "EdDSA"}],
    }


_VSEED = b"V" * 32
_VPUB = _ed.publickey(_VSEED)
_JKU = "https://agents.example.com/.well-known/jwks.json"
_NOW = 1_800_000_000.0


def _ac_store():
    return _ac.CardTrustStore(
        keys={"k1": {"pubkey": _VPUB, "alg": "EdDSA", "jku": _JKU,
                     "fetched_at": _NOW - 100}},
        jku_allowlist=[_JKU])


def _ac_tampered_header(card, alg):
    """Re-encode the first signature's protected header with a new alg."""
    import copy
    card = copy.deepcopy(card)
    entry = card["signatures"][0]
    header = json.loads(base64.urlsafe_b64decode(
        entry["protected"] + "===").decode())
    header["alg"] = alg
    entry["protected"] = _b64u(json.dumps(
        header, sort_keys=True, separators=(",", ":")).encode())
    return card


def _probe_agent_cards_alg_none():
    card = _ac.emit_card(_ac_card_fields(), "k1", _VSEED, jku=_JKU,
                         now=_NOW)
    bad = _ac_tampered_header(card, "none")
    try:
        _ac.verify_card(bad, _ac_store(), now=_NOW)
    except _ac.CardVerificationError as exc:
        assert exc.code == "unsupported-alg", exc.code
        return "refused unsupported-alg"
    raise AssertionError("alg:none card accepted")


def _probe_agent_cards_hs256_confusion():
    card = _ac.emit_card(_ac_card_fields(), "k1", _VSEED, jku=_JKU,
                         now=_NOW)
    bad = _ac_tampered_header(card, "HS256")
    try:
        _ac.verify_card(bad, _ac_store(), now=_NOW)
    except _ac.CardVerificationError as exc:
        assert exc.code == "unsupported-alg", exc.code
        return "refused unsupported-alg"
    raise AssertionError("HS256 card accepted")


def _probe_agent_cards_unknown_alg():
    card = _ac.emit_card(_ac_card_fields(), "k1", _VSEED, jku=_JKU,
                         now=_NOW)
    bad = _ac_tampered_header(card, "rot13")
    try:
        _ac.verify_card(bad, _ac_store(), now=_NOW)
    except _ac.CardVerificationError as exc:
        assert exc.code == "unsupported-alg", exc.code
        return "refused unsupported-alg"
    raise AssertionError("rot13 card accepted")


def _probe_agent_cards_attacker_kid():
    card = _ac.emit_card(_ac_card_fields(), "k1", _VSEED, jku=_JKU,
                         now=_NOW)
    import copy
    bad = copy.deepcopy(card)
    entry = bad["signatures"][0]
    header = json.loads(base64.urlsafe_b64decode(
        entry["protected"] + "===").decode())
    header["kid"] = "attacker-key-1"
    entry["protected"] = _b64u(json.dumps(
        header, sort_keys=True, separators=(",", ":")).encode())
    try:
        _ac.verify_card(bad, _ac_store(), now=_NOW)
    except _ac.CardVerificationError as exc:
        assert "kid" in exc.code or "key" in exc.code, exc.code
        return "refused %s" % exc.code
    raise AssertionError("attacker-kid card accepted")


def _probe_agent_cards_valid_ed25519():
    card = _ac.emit_card(_ac_card_fields(), "k1", _VSEED, jku=_JKU,
                         now=_NOW)
    out = _ac.verify_card(card, _ac_store(), now=_NOW)
    assert out["identity"] == "acme-agent", out
    return "valid Ed25519 card passes"


def _gcp_verifier():
    return _ai.GcpStyleVerifier(
        signer_pubkey_der=bytes.fromhex(_TEST_SPKI_DER_HEX),
        expected_audience="aud-test",
        allowed_projects={"proj-1"}, allowed_zones={"zone-1"})


def _probe_gcp_alg_none():
    v = _gcp_verifier()
    tok = _jose_token({"alg": "none"},
                      {"aud": "aud-test", "iat": 1700000000,
                       "exp": 1800000000}, sig=b"x")
    try:
        v.verify(tok, now=1700000000)
    except _ai.IidError as exc:
        assert "alg" in str(exc), str(exc)
        return "refused: %s" % exc
    raise AssertionError("alg:none JWT accepted")


def _probe_gcp_hs256_confusion():
    v = _gcp_verifier()
    tok = _jose_token({"alg": "HS256"},
                      {"aud": "aud-test", "iat": 1700000000,
                       "exp": 1800000000}, sig=b"x" * 32)
    try:
        v.verify(tok, now=1700000000)
    except _ai.IidError as exc:
        assert "RS256" in str(exc), str(exc)
        return "refused: %s" % exc
    raise AssertionError("HS256 JWT accepted against RSA key")


def _probe_gcp_unknown_alg():
    v = _gcp_verifier()
    tok = _jose_token({"alg": "rot13"},
                      {"aud": "aud-test", "iat": 1700000000,
                       "exp": 1800000000}, sig=b"x" * 32)
    try:
        v.verify(tok, now=1700000000)
    except _ai.IidError as exc:
        assert "RS256" in str(exc), str(exc)
        return "refused: %s" % exc
    raise AssertionError("rot13 JWT accepted")


def _probe_gcp_attacker_kid():
    v = _gcp_verifier()
    tok = _jose_token({"alg": "RS256", "kid": "attacker-key"},
                      {"aud": "aud-test", "iat": 1700000000,
                       "exp": 1800000000}, sig=b"x" * 128)
    # kid is ignored entirely: verification is against the pinned key.
    # An attacker kid must not change the outcome (signature still
    # checked against the pinned RSA key, so the bogus sig refuses).
    try:
        v.verify(tok, now=1700000000)
    except _ai.IidError:
        return "refused: kid ignored, pinned-key signature check holds"
    raise AssertionError("attacker-kid JWT with bogus sig accepted")


def _probe_gcp_valid_rs256():
    v = _gcp_verifier()
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"aud": "aud-test", "iat": 1700000000,
               "exp": 1800000000, "project_id": "proj-1",
               "zone": "zone-1"}
    signing = ("%s.%s" % (_b64u(json.dumps(header).encode()),
                          _b64u(json.dumps(payload).encode()))).encode()
    tok = "%s.%s" % (signing.decode(), _b64u(_rsa_sign(signing)))
    out = v.verify(tok, now=1700000000)
    assert out["kind"] == "gcp_jwt" and out["project_id"] == "proj-1", out
    return "valid RS256 JWT passes"


_MKID = "m1"
_MSEED = b"M" * 32
_MPUB = _ed.publickey(_MSEED)


def _cm_manifest():
    return {"skill_id": "s1", "version": "1.0.0",
            "capabilities": [], "code": "x = 1\n"}


def _cm_store():
    return _cm.ManifestStore(keys={_MKID: _MPUB},
                             manifests={"s1": _cm_manifest()})


def _cm_tampered_header(manifest, alg):
    import copy
    manifest = copy.deepcopy(manifest)
    entry = manifest["signatures"][0]
    header = json.loads(base64.urlsafe_b64decode(
        entry["protected"] + "===").decode())
    header["alg"] = alg
    entry["protected"] = _b64u(json.dumps(
        header, sort_keys=True, separators=(",", ":")).encode())
    return manifest


def _probe_manifests_alg_none():
    m = _cm_manifest()
    m["signatures"] = [_cm.sign_manifest(m, _MKID, _MSEED)]
    bad = _cm_tampered_header(m, "none")
    try:
        _cm.verify_manifest(bad, _cm_store())
    except _cm.ManifestVerificationError as exc:
        assert exc.code == "unsupported-alg", exc.code
        return "refused unsupported-alg"
    raise AssertionError("alg:none manifest accepted")


def _probe_manifests_hs256_confusion():
    m = _cm_manifest()
    m["signatures"] = [_cm.sign_manifest(m, _MKID, _MSEED)]
    bad = _cm_tampered_header(m, "HS256")
    try:
        _cm.verify_manifest(bad, _cm_store())
    except _cm.ManifestVerificationError as exc:
        assert exc.code == "unsupported-alg", exc.code
        return "refused unsupported-alg"
    raise AssertionError("HS256 manifest accepted")


def _probe_manifests_jku_refused():
    m = _cm_manifest()
    entry = _cm.sign_manifest(m, _MKID, _MSEED)
    header = json.loads(base64.urlsafe_b64decode(
        entry["protected"] + "===").decode())
    header["jku"] = "https://attacker.example/jwks"
    entry["protected"] = _b64u(json.dumps(
        header, sort_keys=True, separators=(",", ":")).encode())
    m["signatures"] = [entry]
    try:
        _cm.verify_manifest(m, _cm_store())
    except _cm.ManifestVerificationError:
        return "jku refused (no key discovery)"
    raise AssertionError("jku manifest accepted")


def _probe_eat_alg_none():
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    header = {"alg": "none", "typ": "EAT"}
    payload = {"iss": "i", "sub": "s", "eat_nonce": "bm9uY2UtMTIz"}
    tok = _jose_token(header, payload)
    try:
        _eat.verify_eat(tok, issuer_pubkey=pub, expected_issuer="i",
                        expected_nonce=b"nonce-123", expected_submod_nonces={"s": b"x"})
    except _eat.EATVerifyError as exc:
        assert "alg" in str(exc).lower(), str(exc)
        return "refused: %s" % exc
    raise AssertionError("alg:none EAT accepted")


def _probe_eat_hs256_confusion():
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    header = {"alg": "HS256", "typ": "EAT"}
    payload = {"iss": "i", "sub": "s", "eat_nonce": "bm9uY2UtMTIz"}
    tok = _jose_token(header, payload, sig=b"x" * 32)
    try:
        _eat.verify_eat(tok, issuer_pubkey=pub, expected_issuer="i",
                        expected_nonce=b"nonce-123", expected_submod_nonces={"s": b"x"})
    except _eat.EATVerifyError as exc:
        assert "alg" in str(exc).lower(), str(exc)
        return "refused: %s" % exc
    raise AssertionError("HS256 EAT accepted")


def _probe_eat_valid_eddsa():
    seed = bytes(range(32))
    pub = _ed.publickey(seed)

    def _signer(msg):
        return _ed.sign(seed, msg)

    evidence = {
        "tpm": {"ueid": "ek-pubkey-sha256:" + "aa" * 32,
                "oemid": "Infineon", "hwmodel": "TPM2.0-dTPM",
                "hwversion": "7.85", "swname": "sasanam-agent",
                "swversion": "1.0.0",
                "measurements": {"pcr_digest": "bb" * 32},
                "dbgstat": "disabled",
                "nonce": b"tpm-challenge-nonce-0001"},
    }
    tok = _eat.emit_eat(
        evidence=evidence, nonce=b"superior-challenge-0000",
        issuer="sasanam-issuer-1", signer=_signer, now=1700000000,
        expectations={"tpm": {"pcr_digest": "bb" * 32}})
    out = _eat.verify_eat(
        tok, issuer_pubkey=pub, expected_issuer="sasanam-issuer-1",
        expected_nonce=b"superior-challenge-0000",
        expected_submod_nonces={"tpm": b"tpm-challenge-nonce-0001"},
        expectations={"tpm": {"pcr_digest": "bb" * 32}},
        now=1700000100)
    assert out["claims"]["iss"] == "sasanam-issuer-1", out
    return "valid EdDSA EAT passes"


# ----------------------------------------------------------------------
# Probe class 2: alg_registry dispatch (the genuine finding this lane
# closed). Red-first: these REFUSED only after the fix; on the pristine
# base the forged record verified.
# ----------------------------------------------------------------------

_MAC = "hmac-sha256-mac"
_ED = "ed25519-rfc8032"


def _probe_registry_confusion_refused():
    # Attacker knows the victim's PUBLIC key and uses it as the HMAC
    # secret on a fresh HMAC-tier record: the exact RS256->HS256 shape.
    reg = _ar.default_registry()
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    body = b"victim-issuer|revoked|" + b"ab" * 32
    tag = reg.sign(_MAC, body, pub)  # public key as "secret"
    ok = reg.verify(_MAC, body, tag, pub)
    assert ok is False, "confusion: HMAC tier accepted a public key"
    return "refused: symmetric tier needs for_symmetric_key"


def _probe_registry_pinned_hmac_passes():
    reg = _ar.default_registry()
    secret, _ = reg.keygen(_MAC)
    tag = reg.sign(_MAC, b"hello", secret)
    assert reg.verify(_MAC, b"hello", tag, secret,
                      for_symmetric_key=True) is True
    assert reg.verify(_MAC, b"tampered", tag, secret,
                      for_symmetric_key=True) is False
    return "pinned HMAC round-trip passes"


def _probe_registry_ed25519_unaffected():
    reg = _ar.default_registry()
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    sig = reg.sign(_ED, b"hello", seed)
    assert reg.verify(_ED, b"hello", sig, pub) is True
    assert reg.is_symmetric(_ED) is False
    assert reg.is_symmetric(_MAC) is True
    return "Ed25519 tier unaffected"


# ----------------------------------------------------------------------
# Probe class 3: record-module confusion through every affected module.
# ----------------------------------------------------------------------

def _probe_absence_confusion_refused():
    # Full PoC: attacker mints an HMAC-tier absence record using the
    # victim's PUBLIC key as the HMAC secret; verify_negative must
    # refuse it (it verified on the pristine base). We build the
    # record through the issuer then swap the key for the public key
    # and re-seal: the exact confusion shape.
    reg = _ar.default_registry()
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    digest = "ab" * 32
    body = "victim-issuer|never-advertised|" + digest
    neg = {"v": 1, "kind": "absence", "issuer_id": "victim-issuer",
           "claim": "never-advertised", "subject_digest": digest,
           "digest": digest, "alg": _MAC, "revocation_target": None,
           "issued_at": 1700000000.0, "body": body,
           "signature": reg.sign(_MAC, body.encode(), pub).hex()}
    try:
        _ab.verify_negative(neg, pub)
    except _ab.AbsenceUnverifiableError as exc:
        assert "algorithm-confusion" in str(exc), str(exc)
        return "refused algorithm-confusion guard"
    raise AssertionError("forged HMAC absence record VERIFIED")


def _probe_absence_pinned_hmac_passes():
    reg = _ar.default_registry()
    secret, _ = reg.keygen(_MAC)
    issuer = _ab.AbsenceIssuer("i", secret, alg=_MAC)
    neg = issuer.attest_absence("ab" * 32, now=1700000000.0)
    rec = _ab.verify_negative(neg, secret, expect_alg=_MAC)
    assert rec["claim"] == "never-advertised", rec
    return "pinned HMAC absence passes"


def _probe_checkpoint_confusion_refused():
    reg = _ar.default_registry()
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    mmr = _cp.MerkleMountainRange()
    digests = ["ab" * 31 + "%02x" % i for i in range(3)]
    for d in digests:
        mmr.append(d)
    chk = mmr.checkpoint(_MAC, pub, "k-mac")
    try:
        _cp.verify_checkpoint(chk, digests, pub)
    except Exception as exc:  # noqa: BLE001
        assert "algorithm-confusion" in str(exc), str(exc)
        return "refused algorithm-confusion guard"
    raise AssertionError("forged HMAC checkpoint VERIFIED")


def _probe_checkpoint_pinned_hmac_passes():
    reg = _ar.default_registry()
    secret, _ = reg.keygen(_MAC)
    mmr = _cp.MerkleMountainRange()
    digests = ["ab" * 31 + "%02x" % i for i in range(3)]
    for d in digests:
        mmr.append(d)
    chk = mmr.checkpoint(_MAC, secret, "k-mac")
    out = _cp.verify_checkpoint(chk, digests, secret, expect_alg=_MAC)
    assert out["ok"] is True, out
    return "pinned HMAC checkpoint passes"


class _HmacSigner(object):
    def __init__(self, secret, key_id="k"):
        self.alg = _MAC
        self.secret = bytes(secret)
        self.key_id = key_id


def _probe_capsule_confusion_refused():
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    capsule, _ = _dcap.seal_denial(
        refusal_code="deny-receipt-refused",
        authority="governance-authority", action_digest="ab" * 32,
        signer=_HmacSigner(pub), decoy_count=0)
    try:
        _dcap.verify_capsule(capsule, key=pub)
    except _dcap.DenialCapsuleInvalid as exc:
        assert exc.code == "denial-capsule-signature-invalid", exc.code
        return "refused denial-capsule-signature-invalid"
    raise AssertionError("confused capsule VERIFIED")


def _probe_capsule_pinned_hmac_passes():
    reg = _ar.default_registry()
    secret, _ = reg.keygen(_MAC)
    capsule, _ = _dcap.seal_denial(
        refusal_code="deny-receipt-refused",
        authority="governance-authority", action_digest="ab" * 32,
        signer=_HmacSigner(secret), decoy_count=0)
    claim = _dcap.verify_capsule(capsule, key=secret,
                                 expect_alg=_MAC)
    assert claim["ok"] is True, claim
    return "pinned HMAC capsule passes"


def _probe_receipt_confusion_refused():
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    signer = _dr.Signer(_MAC, pub, "k")
    receipt = _dr.emit({"verdict": "DENY", "rule_path": "p",
                        "token_digest": "cd" * 32,
                        "policy_bundle_digest": "ef" * 32,
                        "intent_digest": "01" * 32,
                        "jurisdiction_profile": "default"},
                       signer=signer)
    try:
        _dr.verify(receipt, key=pub)
    except Exception as exc:  # noqa: BLE001
        return "refused: %s" % type(exc).__name__
    raise AssertionError("confused deny receipt VERIFIED")


def _probe_posture_confusion_refused():
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    sig = _po.emit_signal("revocation", "ab" * 32, "permit", pub,
                          issuer_id="i", now=1700000000.0, alg=_MAC)
    try:
        _po.verify_signal(sig, {"i": pub})
    except Exception as exc:  # noqa: BLE001
        return "refused: %s" % type(exc).__name__
    raise AssertionError("confused posture signal VERIFIED")


def _probe_revocation_confusion_refused():
    seed = bytes(range(32))
    pub = _ed.publickey(seed)
    rl = _rv.RevocationList()
    entry = rl.revoke("ab" * 32, issuer_id="i", seed=pub,
                      now=1700000000.0, alg=_MAC)
    fresh = _rv.RevocationList()
    try:
        fresh.import_entries([entry], {"i": pub})
    except Exception as exc:  # noqa: BLE001
        return "refused: %s" % type(exc).__name__
    raise AssertionError("confused revocation entry IMPORTED")


def _probe_revocation_pinned_hmac_passes():
    reg = _ar.default_registry()
    secret, _ = reg.keygen(_MAC)
    rl = _rv.RevocationList()
    rl.revoke("ab" * 32, issuer_id="i", seed=secret,
              now=1700000000.0, alg=_MAC)
    assert rl.verify({"i": secret}, expect_alg=_MAC) is True
    return "pinned HMAC revocation passes"


_PROBES = [
    # JOSE seams: (a)-(e).
    ("jose-agent-cards-alg-none-refused", _probe_agent_cards_alg_none,
     "HAVE_SEAMS", False),
    ("jose-agent-cards-hs256-confusion-refused",
     _probe_agent_cards_hs256_confusion, "HAVE_SEAMS", False),
    ("jose-agent-cards-unknown-alg-refused",
     _probe_agent_cards_unknown_alg, "HAVE_SEAMS", False),
    ("jose-agent-cards-attacker-kid-refused",
     _probe_agent_cards_attacker_kid, "HAVE_SEAMS", False),
    ("jose-agent-cards-valid-ed25519-passes",
     _probe_agent_cards_valid_ed25519, "HAVE_SEAMS", False),
    ("jose-gcp-alg-none-refused", _probe_gcp_alg_none,
     "HAVE_SEAMS", False),
    ("jose-gcp-hs256-confusion-refused", _probe_gcp_hs256_confusion,
     "HAVE_SEAMS", False),
    ("jose-gcp-unknown-alg-refused", _probe_gcp_unknown_alg,
     "HAVE_SEAMS", False),
    ("jose-gcp-attacker-kid-refused", _probe_gcp_attacker_kid,
     "HAVE_SEAMS", False),
    ("jose-gcp-valid-rs256-passes", _probe_gcp_valid_rs256,
     "HAVE_SEAMS", False),
    ("jose-manifests-alg-none-refused", _probe_manifests_alg_none,
     "HAVE_SEAMS", False),
    ("jose-manifests-hs256-confusion-refused",
     _probe_manifests_hs256_confusion, "HAVE_SEAMS", False),
    ("jose-manifests-jku-refused", _probe_manifests_jku_refused,
     "HAVE_SEAMS", False),
    ("jose-eat-alg-none-refused", _probe_eat_alg_none,
     "HAVE_SEAMS", False),
    ("jose-eat-hs256-confusion-refused", _probe_eat_hs256_confusion,
     "HAVE_SEAMS", False),
    ("jose-eat-valid-eddsa-passes", _probe_eat_valid_eddsa,
     "HAVE_SEAMS", False),
    # alg_registry dispatch: (f)-(h).
    ("registry-hmac-with-pubkey-refused",
     _probe_registry_confusion_refused, "HAVE_SEAMS", False),
    ("registry-pinned-hmac-passes",
     _probe_registry_pinned_hmac_passes, "HAVE_SEAMS", False),
    ("registry-ed25519-unaffected",
     _probe_registry_ed25519_unaffected, "HAVE_SEAMS", False),
    # Record modules.
    ("absence-hmac-confusion-refused",
     _probe_absence_confusion_refused, "HAVE_SEAMS", False),
    ("absence-pinned-hmac-passes",
     _probe_absence_pinned_hmac_passes, "HAVE_SEAMS", False),
    ("checkpoint-hmac-confusion-refused",
     _probe_checkpoint_confusion_refused, "HAVE_SEAMS", False),
    ("checkpoint-pinned-hmac-passes",
     _probe_checkpoint_pinned_hmac_passes, "HAVE_SEAMS", False),
    ("capsule-hmac-confusion-refused",
     _probe_capsule_confusion_refused, "HAVE_SEAMS", False),
    ("capsule-pinned-hmac-passes",
     _probe_capsule_pinned_hmac_passes, "HAVE_SEAMS", False),
    ("receipt-hmac-confusion-refused",
     _probe_receipt_confusion_refused, "HAVE_SEAMS", False),
    ("posture-hmac-confusion-refused",
     _probe_posture_confusion_refused, "HAVE_SEAMS", False),
    ("revocation-hmac-confusion-refused",
     _probe_revocation_confusion_refused, "HAVE_SEAMS", False),
    ("revocation-pinned-hmac-passes",
     _probe_revocation_pinned_hmac_passes, "HAVE_SEAMS", False),
]


def main():
    # Depth-1: this battery spawns no nested green-check subprocesses.
    flags = {"HAVE_SEAMS": HAVE_SEAMS}
    results = []
    for name, fn, flag, pin in _PROBES:
        results.append(_run_probe(name, fn, flags[flag], pin=pin))
    held = sum(1 for _, s, _ in results if s in ("HELD", "PIN"))
    total = len(results)
    for name, status, note in results:
        print("%-42s %-6s %s" % (name, status, note.split("\n")[0]))
    print("w246_jwt_alg_confusion: %d/%d HELD-or-PIN" % (held, total))
    return 0 if held == total else 2


if __name__ == "__main__":
    sys.exit(main())
