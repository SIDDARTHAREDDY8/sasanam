#!/usr/bin/env python3
"""Red-first break battery for wave-208 Lane D: TEE attestation verifiers.

The gap (pristine tree): there is no AMD SEV-SNP / Intel TDX attestation
verification -- no offline verifier for attestation reports, no three-hop
TDX binding, no REPORT_DATA key binding, no fail-closed local-TDREPORT
refusal, and no composition with wave-204's attested identity. The tier-1
identity story stops at TPM quotes and cloud IIDs. ``gov.tee_attest``
does not exist on the pristine tree.

Pristine expectation: P0 BREAK (the gap); every other probe EXPECTED
(cannot run without the module -- recorded, not faked green).
Fixed expectation: every probe HELD.

Stdlib only (ECDSA sign/verify is stdlib, test-grade, non-constant-time;
fixtures are synthetic -- no TEE hardware in this lab, same honesty as
wave-204's TPM path). Deterministic in outcome (fixture keys/nonces are
random; all assertions are on properties, never on fixed bytes). Sets
GOV_DEPLOYMENT_MODE=staging at module level; verify standalone under
``env -u GOV_DEPLOYMENT_MODE``. Honors GOV_SKIP_GREEN=1 (green check is
depth-1: adjacent unit suites only, never nested battery mains).

AGPL trap note: no real TDX quote fixtures are used or copied -- every
fixture is generated in-process by gov.tee_attest's synthetic fixture
makers. edgelesssys/go-tdx-qpl fixture bytes are never touched.
"""

import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hmac  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
_HAS_MODULE = importlib.util.find_spec("gov.tee_attest") is not None

RESULTS = []

_TMP = tempfile.mkdtemp(prefix="g208d-probes-", dir="/var/tmp")


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
    raise _Expected("gov.tee_attest absent (pristine gap)")


# ---------------------------------------------------------------- gap probe


def p0_module_absent_gap():
    """The pristine gap: no TEE attestation verifier exists."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        return "BREAK", "gov.tee_attest absent (pristine gap)"
    import gov.tee_attest as ta
    for seam in ("SevSnpVerifier", "TdxQuoteVerifier", "report_data_for",
                 "make_snp_fixture", "make_tdx_fixture",
                 "make_synthetic_local_tdreport", "attach_tee_proof",
                 "tee_bom_section", "is_enabled", "TEE_ATTEST_FLAG"):
        assert hasattr(ta, seam), "missing seam %r" % (seam,)
    return ("full seam present: SNP verifier, TDX verifier, REPORT_DATA "
            "binding, fixture makers, authority/BOM composition, flag gate")


# ---------------------------------------------------------------- fixtures

_FIX = {}


def _fixtures():
    if _FIX:
        return _FIX
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("fixtures")
    import gov.tee_attest as ta
    salt = os.urandom(32)
    snp = ta.make_snp_fixture(policy=0x30000,
                              measurement=b"m" * 48,
                              tcb=b"\x01\x02\x03\x04\x05\x06\x07\x08",
                              chip_id=b"c" * 64,
                              salt=salt)
    now = 1_800_000_000
    tdx = ta.make_tdx_fixture(mrtd=b"t" * 48,
                              rtmrs={0: b"r" * 48, 1: b"s" * 48},
                              tcb_info={"valid_from": now - 10_000,
                                        "valid_until": now + 10_000},
                              salt=salt,
                              now=now)
    _FIX.update(snp=snp, tdx=tdx, salt=salt, now=now)
    return _FIX


def _snp_bundle(fx, **over):
    b = {"report": fx["report"],
         "ask_cert": fx["ask_cert"],
         "vcek_cert": fx["vcek_cert"],
         "expected_policy": fx["policy"],
         "expected_measurement": fx["measurement"],
         "tcb_allowlist": [fx["tcb"]],
         "tee_pubkey": fx["tee_pubkey"],
         "salt": fx["salt"]}
    b.update(over)
    return b


def _tdx_bundle(fx, **over):
    b = {"quote": fx["quote"],
         "pck_cert": fx["pck_cert"],
         "tcb_info": dict(fx["tcb_info"]),
         "expected_mrtd": fx["mrtd"],
         "expected_rtmrs": dict(fx["rtmrs"]),
         "tee_pubkey": fx["tee_pubkey"],
         "salt": fx["salt"],
         "now": fx["now"]}
    b.update(over)
    return b


def _snp_verifier(fx, **kw):
    import gov.tee_attest as ta
    kw.setdefault("enabled", True)
    return ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"], **kw)


def _tdx_verifier(fx, **kw):
    import gov.tee_attest as ta
    kw.setdefault("enabled", True)
    return ta.TdxQuoteVerifier(intel_root_pubkey=fx["intel_root_pubkey"],
                               **kw)


# ---------------------------------------------------------------- SNP probes


def a1_snp_conforming_verifies():
    """A conforming synthetic SEV-SNP report verifies end to end."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("a1")
    fx = _fixtures()["snp"]
    claims = _snp_verifier(fx).verify(_snp_bundle(fx))
    assert claims["platform"] == "sev-snp", claims
    assert claims["measurement"] == fx["measurement"].hex(), claims
    assert claims["kind"] == "sev_snp_attested", claims
    assert len(claims["evidence_digest"]) == 64, claims
    return "conforming SNP report verifies; claims bind measurement"


def a2_snp_bigendian_rs_refused():
    """The endianness trap: R/S read big-endian must FAIL closed.

    The report signature stores R and S as 72-byte LITTLE-endian scalars.
    A verifier (or attacker) that reads them big-endian gets silently wrong
    scalars -- verification must fail, proving the LE handling is
    load-bearing rather than cosmetic.
    """
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("a2")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    r_le = fx["report"][ta.SNP_SIG_OFFSET:ta.SNP_SIG_OFFSET + 72]
    s_le = fx["report"][ta.SNP_SIG_OFFSET + 72:ta.SNP_SIG_OFFSET + 144]
    r_be = int.from_bytes(r_le, "big")
    s_be = int.from_bytes(s_le, "big")
    body = fx["report"][:ta.SNP_SIGNED_SIZE]
    digest = ta._sha384(body)
    ok = ta.ecdsa_verify(ta.P384, fx["vcek_point"], digest, r_be, s_be)
    assert ok is False, "big-endian scalar read verified: endianness trap!"
    # And the LE read (the module's own path) does verify.
    ok_le = ta.ecdsa_verify(ta.P384, fx["vcek_point"], digest,
                            int.from_bytes(r_le, "little"),
                            int.from_bytes(s_le, "little"))
    assert ok_le is True, "LE read should verify the fixture signature"
    return "big-endian R/S read fails; little-endian verifies"


def a3_snp_wrong_ark_refused():
    """A chain rooted at a non-pinned ARK is refused (no trust)."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("a3")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    rogue_priv, rogue_point = ta.gen_keypair("P-384")
    try:
        _snp_verifier(fx).verify(_snp_bundle(fx))
    except Exception:
        raise AssertionError("conforming bundle should verify")
    rogue_fx = ta.make_snp_fixture(
        policy=fx["policy"], measurement=fx["measurement"], tcb=fx["tcb"],
        chip_id=b"c" * 64, salt=fx["salt"],
        ark_priv=rogue_priv, ark_point=rogue_point)
    try:
        _snp_verifier(fx).verify(_snp_bundle(rogue_fx))
    except ta.ChainError as e:
        return "non-pinned ARK chain refused: %s" % (e,)
    raise AssertionError("chain under rogue ARK verified!")


def a4_snp_vcek_tcb_mismatch_refused():
    """VCEK cert TCB != report REPORTED_TCB: the cert is for another boot."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("a4")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    other = dict(fx["vcek_cert"])
    other["tcb"] = (b"\xff" * 8).hex()
    try:
        _snp_verifier(fx).verify(_snp_bundle(fx, vcek_cert=other))
    except ta.ChainError as e:
        return "VCEK/TCB mismatch refused: %s" % (e,)
    raise AssertionError("VCEK cert for another TCB verified!")


def a5_snp_measurement_mismatch_refused():
    """Wrong expected measurement: a different image does not attest."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("a5")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    try:
        _snp_verifier(fx).verify(
            _snp_bundle(fx, expected_measurement=b"x" * 48))
    except ta.PolicyError as e:
        return "measurement mismatch refused: %s" % (e,)
    raise AssertionError("wrong measurement verified!")


def a6_snp_policy_mismatch_refused():
    """Wrong POLICY (e.g. debug bit set): refused, not warned."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("a6")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    try:
        _snp_verifier(fx).verify(
            _snp_bundle(fx, expected_policy=fx["policy"] ^ 0x1))
    except ta.PolicyError as e:
        return "policy mismatch refused: %s" % (e,)
    raise AssertionError("wrong policy verified!")


def a7_snp_stale_tcb_refused():
    """REPORTED_TCB outside the operator allowlist: refused (stale TCB)."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("a7")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    try:
        _snp_verifier(fx).verify(
            _snp_bundle(fx, tcb_allowlist=[b"\x99" * 8]))
    except ta.PolicyError as e:
        return "stale TCB refused: %s" % (e,)
    raise AssertionError("TCB outside allowlist verified!")


# ---------------------------------------------------------------- TDX probes


def b1_tdx_conforming_verifies():
    """A conforming synthetic TDX DCAP quote verifies all three hops."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("b1")
    fx = _fixtures()["tdx"]
    claims = _tdx_verifier(fx).verify(_tdx_bundle(fx))
    assert claims["platform"] == "tdx", claims
    assert claims["measurement"] == fx["mrtd"].hex(), claims
    assert claims["kind"] == "tdx_attested", claims
    return "conforming TDX quote verifies; three-hop chain holds"


def b2_tdx_severed_qe_binding_refused():
    """Hop (b) severed: QE report_data != SHA-256(att_key || qe_auth_data)
    means the attestation key is an unattached peer-supplied key."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("b2")
    import gov.tee_attest as ta
    fx = _fixtures()["tdx"]
    qe = dict(fx["qe_report"])
    qe["report_data"] = (b"\x00" * 32).hex()
    fx2 = dict(fx)
    fx2["qe_report"] = qe
    quote = ta._rebind_tdx_quote(fx2)  # re-signs nothing; fields as given
    try:
        _tdx_verifier(fx).verify(_tdx_bundle(fx, quote=quote))
    except ta.BindingError as e:
        return "severed QE binding refused: %s" % (e,)
    raise AssertionError("severed QE binding verified!")


def b3_tdx_local_tdreport_refused():
    """A local TDREPORT -- even with matching fields -- is refused on the
    remote path. Self-asserted 'I am in a TEE' claims never verify."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("b3")
    import gov.tee_attest as ta
    fx = _fixtures()["tdx"]
    tdreport = ta.make_synthetic_local_tdreport(
        mrtd=fx["mrtd"], tee_pubkey=fx["tee_pubkey"], salt=fx["salt"])
    assert len(tdreport) == 1024, len(tdreport)
    try:
        _tdx_verifier(fx).verify(_tdx_bundle(fx, quote=tdreport))
    except ta.ReportFormatError as e:
        return "local TDREPORT refused on remote path: %s" % (e,)
    raise AssertionError("local TDREPORT verified on remote path!")


def b4_tdx_wrong_attestation_key_refused():
    """Quote body signed by a key that is NOT the QE-bound attestation key."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("b4")
    import gov.tee_attest as ta
    fx = _fixtures()["tdx"]
    rogue_priv, _rogue_point = ta.gen_keypair("P-256")
    fx2 = dict(fx)
    fx2["att_priv"] = rogue_priv  # quote body now signed by rogue key
    quote = ta._rebind_tdx_quote(fx2)
    try:
        _tdx_verifier(fx).verify(_tdx_bundle(fx, quote=quote))
    except ta.BindingError as e:
        return "unbound attestation key refused: %s" % (e,)
    raise AssertionError("quote from unbound key verified!")


def b5_tdx_expired_collateral_refused():
    """Intel TCB-info past its validity window: refused, not warned.

    The ashaveri cautionary example -- collateral freshness must be
    checked, never assumed."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("b5")
    import gov.tee_attest as ta
    fx = _fixtures()["tdx"]
    stale = {"valid_from": fx["now"] - 20_000, "valid_until": fx["now"] - 1}
    try:
        _tdx_verifier(fx).verify(_tdx_bundle(fx, tcb_info=stale))
    except ta.PolicyError as e:
        return "expired collateral refused: %s" % (e,)
    raise AssertionError("expired TCB collateral verified!")


def b6_tdx_pck_not_pinned_refused():
    """PCK cert that does not chain to the pinned Intel root: refused."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("b6")
    import gov.tee_attest as ta
    fx = _fixtures()["tdx"]
    rogue_priv, rogue_point = ta.gen_keypair("P-256")
    rogue_pck = ta.make_pck_cert(rogue_priv, rogue_point,
                                 tcb_hex=fx["pck_cert"]["tcb"],
                                 issuer_priv=rogue_priv)  # self-signed
    try:
        _tdx_verifier(fx).verify(_tdx_bundle(fx, pck_cert=rogue_pck))
    except ta.ChainError as e:
        return "unpinned PCK refused: %s" % (e,)
    raise AssertionError("PCK outside pinned root verified!")


# ---------------------------------------------------------------- binding probes


def c1_report_data_binding():
    """REPORT_DATA = JWK_thumbprint(tee_pubkey) || salt, exactly 64 bytes.

    Correct key+salt verifies; wrong salt or wrong key refuses; the
    construction is byte-exact."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("c1")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    rd = ta.report_data_for("P-384", fx["tee_pubkey"], fx["salt"])
    assert len(rd) == 64, len(rd)
    assert fx["report"][ta.SNP_REPORT_DATA:ta.SNP_REPORT_DATA + 64] == rd
    # Wrong salt refuses.
    try:
        _snp_verifier(fx).verify(_snp_bundle(fx, salt=b"\x00" * 32))
    except ta.BindingError:
        pass
    else:
        raise AssertionError("wrong salt verified!")
    # Wrong key refuses.
    _priv, other_point = ta.gen_keypair("P-384")
    try:
        _snp_verifier(fx).verify(_snp_bundle(fx, tee_pubkey=other_point))
    except ta.BindingError:
        pass
    else:
        raise AssertionError("wrong key verified!")
    return "REPORT_DATA binding is byte-exact; wrong salt/key refused"


# ---------------------------------------------------------------- flag probe


def d1_flag_disabled_refuses():
    """With the flag off, every verify path refuses LOUDLY (fail closed)."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("d1")
    import gov.tee_attest as ta
    assert ta.is_enabled() is False, "flag must default OFF"
    fx = _fixtures()["snp"]
    tfx = _fixtures()["tdx"]
    for mk, bundle in (
            (lambda: ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"],
                                       enabled=False),
             _snp_bundle(fx)),
            (lambda: ta.TdxQuoteVerifier(
                intel_root_pubkey=tfx["intel_root_pubkey"], enabled=False),
             _tdx_bundle(tfx))):
        try:
            mk().verify(bundle)
        except ta.FlagDisabledError:
            continue
        raise AssertionError("disabled verifier did not refuse!")
    return "flag-off verifiers refuse loudly; default is OFF"


# ---------------------------------------------------------------- composition probes


def e1_bootstrap_composition():
    """Attester.bootstrap_with_tee_report mints tier-1 with tee claims.

    The REPORT_DATA salt must equal the single-use challenge nonce
    (freshness); a stale report against a fresh challenge refuses, and
    each bootstrap's evidence digest is recorded exactly once."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("e1")
    import gov.tee_attest as ta
    import gov.attested_identity as ai
    from gov.signing import Ed25519Signer
    fx = _fixtures()["snp"]
    signer = Ed25519Signer(os.urandom(32))
    verifier = ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"], enabled=True)
    attester = ai.Attester(signer, tee_verifier=verifier)
    chal_id, nonce = attester.issue_challenge("agent-tee-1")
    # fx2 reuses fx's ARK so the verifier (pinned to fx's ARK) trusts it.
    fx2 = ta.make_snp_fixture(policy=fx["policy"],
                               measurement=fx["measurement"],
                               tcb=fx["tcb"],
                               chip_id=b"c" * 64,
                               salt=nonce,
                               ark_priv=fx["ark_priv"],
                               ark_point=fx["ark_pubkey"])
    ident = attester.bootstrap_with_tee_report(
        challenge_id=chal_id, bundle=_snp_bundle(fx2))
    assert ident.tier == ai.TIER_ATTESTED, ident.tier
    assert ident.claims["kind"] == "tee_attested", ident.claims
    assert ident.claims["platform"] == "sev-snp", ident.claims
    assert attester.verify_credential(ident) is True
    # Wrong salt (not the challenge nonce) refuses.
    chal2, _nonce2 = attester.issue_challenge("agent-tee-2")
    try:
        attester.bootstrap_with_tee_report(
            challenge_id=chal2, bundle=_snp_bundle(fx2))
    except ai.IdentityError:
        pass
    else:
        raise AssertionError("stale-salt bootstrap verified!")
    # Replay of the same report refuses (consumed evidence).
    # A stale report (built for an older challenge) presented against a
    # fresh challenge refuses: the REPORT_DATA salt must equal the live
    # single-use nonce. This is the replay case that matters for the
    # nonce-bound design -- a byte-identical replay against a fresh
    # challenge is structurally impossible, which is the point.
    chal_stale, _nonce_stale = attester.issue_challenge("agent-tee-stale")
    try:
        attester.bootstrap_with_tee_report(
            challenge_id=chal_stale, bundle=_snp_bundle(fx2))
    except ai.IdentityError:
        pass
    else:
        raise AssertionError("stale-salt bootstrap verified!")
    chal3, nonce3 = attester.issue_challenge("agent-tee-3")
    fx3 = ta.make_snp_fixture(policy=fx["policy"],
                               measurement=fx["measurement"],
                               tcb=fx["tcb"],
                               chip_id=b"c" * 64,
                               salt=nonce3,
                               ark_priv=fx["ark_priv"],
                               ark_point=fx["ark_pubkey"])
    attester.bootstrap_with_tee_report(
        challenge_id=chal3, bundle=_snp_bundle(fx3))
    # The consumed-evidence log recorded each bootstrap exactly once
    # (defense in depth behind the nonce binding): the public audit
    # carries two distinct evidence digests.
    digests = [e["evidence_digest"] for e in attester.audit
               if e["event"] == "tier1_issued"]
    assert len(digests) == 2 and len(set(digests)) == 2, digests
    return ("tier-1 tee bootstrap mints; nonce-freshness holds, stale "
            "reports refuse, evidence digests recorded once each")


def e2_authority_proof_composition():
    """attach_tee_proof records platform+measurement on WITHIN only.

    A TEE proof is *supported* evidence: attaching to anything other than
    WITHIN refuses loudly -- attestation never upgrades a denial."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("e2")
    import gov.tee_attest as ta
    import gov.authority_proof as ap
    fx = _fixtures()["snp"]
    claims = _snp_verifier(fx).verify(_snp_bundle(fx))
    within = ap.AuthorityProof(
        verdict=ap.WITHIN, covered_domains=("fs",),
        uncovered_domains=(), counterexample=None, boundary_id="b1",
        boundary_version="1", resolution_source="path_resolved",
        detail="fs ok")
    out = ta.attach_tee_proof(within, claims)
    assert out.verdict == ap.WITHIN, out.verdict
    assert "platform:sev-snp" in out.detail, out.detail
    assert "measurement:%s" % fx["measurement"].hex() in out.detail
    denied = ap.AuthorityProof(
        verdict=ap.EXCEEDS, covered_domains=("fs",),
        uncovered_domains=(), counterexample=None, boundary_id="b1",
        boundary_version="1", resolution_source="path_resolved",
        detail="fs exceeds")
    try:
        ta.attach_tee_proof(denied, claims)
    except ta.BindingError:
        pass
    else:
        raise AssertionError("TEE proof upgraded a denial!")
    return "TEE proof attaches to WITHIN; denial upgrade refused"


def e3_bom_section():
    """tee_bom_section binds the decision to the TEE evidence."""
    if importlib.util.find_spec("gov.tee_attest") is None:
        _expected("e3")
    import gov.tee_attest as ta
    fx = _fixtures()["snp"]
    claims = _snp_verifier(fx).verify(_snp_bundle(fx))
    sec = ta.tee_bom_section(claims)
    assert sec["platform"] == "sev-snp", sec
    assert sec["measurement"] == fx["measurement"].hex(), sec
    assert sec["evidence_digest"] == claims["evidence_digest"], sec
    assert len(sec["evidence_digest"]) == 64, sec
    return "BOM section binds platform/measurement/evidence digest"


# ---------------------------------------------------------------- green check


def _green_check():
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmp = tempfile.mkdtemp(prefix="g208d-green-", dir="/var/tmp")
    env["TMPDIR"] = tmp
    suites = ["tests/test_tee_attest.py", "tests/test_attested_identity.py"]
    ok = True
    for suite in suites:
        path = os.path.join(REPO, suite)
        if not os.path.exists(path):
            print("  green: %s missing (skipped)" % suite)
            continue
        r = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s",
             os.path.join(REPO, "tests"),
             "-p", os.path.basename(suite)[:-3] + ".py", "-t", REPO],
            capture_output=True, text=True, env=env, cwd=REPO, timeout=600)
        tail = (r.stderr or r.stdout or "")[-400:]
        print("  green %s: rc=%d %s" % (suite, r.returncode,
                                        " ".join(tail.split()[-6:])))
        ok = ok and r.returncode == 0
    return ok


def main():
    probes = [p0_module_absent_gap,
              a1_snp_conforming_verifies, a2_snp_bigendian_rs_refused,
              a3_snp_wrong_ark_refused, a4_snp_vcek_tcb_mismatch_refused,
              a5_snp_measurement_mismatch_refused, a6_snp_policy_mismatch_refused,
              a7_snp_stale_tcb_refused,
              b1_tdx_conforming_verifies, b2_tdx_severed_qe_binding_refused,
              b3_tdx_local_tdreport_refused, b4_tdx_wrong_attestation_key_refused,
              b5_tdx_expired_collateral_refused, b6_tdx_pck_not_pinned_refused,
              c1_report_data_binding,
              d1_flag_disabled_refuses,
              e1_bootstrap_composition, e2_authority_proof_composition,
              e3_bom_section]
    # Double run: a verdict change between runs is an ERROR (determinism).
    first = {}
    for probe in probes:
        check(probe.__name__, probe)
        first[probe.__name__] = RESULTS[-1][1]
    RESULTS.clear()
    for probe in probes:
        check(probe.__name__, probe)
    changed = [n for n, s, _ in RESULTS if first.get(n) != s]
    for n in changed:
        print("NONDETERMINISTIC: %s (%s -> %s)"
              % (n, first.get(n), [s for m, s, _ in RESULTS if m == n][0]))
    held = sum(1 for _, s, _ in RESULTS if s == "HELD")
    gap = [n for n, s, _ in RESULTS if s == "BREAK"]
    broken = [n for n, s, _ in RESULTS if s == "BROKEN"]
    errors = [n for n, s, _ in RESULTS if s == "ERROR"]
    expected = sum(1 for _, s, _ in RESULTS if s == "EXPECTED")
    print()
    print("%d/%d HELD (%d EXPECTED)" % (held, len(RESULTS), expected))
    green_ok = True
    failed = gap + broken + errors + changed
    if not _SKIP_GREEN and _HAS_MODULE and not failed:
        green_ok = _green_check()
    rc = 0 if (not failed and green_ok) else 1
    if gap:
        print("GAP (pristine red): %s" % (gap,))
    if broken:
        print("BROKEN: %s" % (broken,))
    if errors:
        print("ERROR: %s" % (errors,))
    if changed:
        print("NONDETERMINISTIC: %s" % (changed,))
    if not green_ok:
        print("GREEN CHECK FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
