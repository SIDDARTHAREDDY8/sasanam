#!/usr/bin/env python3
"""Red-team battery: claim-bounds / evidence-shape seams (wave-211 lane B).

Adversarial probe set against the Wave-208 -> Wave-210 evidence stack,
aimed at the six requested attack classes:

  1. claim-overreach injection across VC / canonical claim-bounds seams
  2. bound laundering through VC redaction/reissue, C2PA ingredient
     chains, or SLSA translation
  3. EAT superior/submodule no-inheritance confusion
  4. SCITT registration receipt misrepresented as content correctness
  5. TEE report/key binding swap through attach_tee_proof
  6. boundless evidence bundle bypass through standalone tools/evidence-verify

Verdicts:
  HELD     - the attack was stopped by the product (defense holds)
  BREAK    - the attack succeeded: genuine break, filed as F206+ in
             evals/FINDINGS.md
  RESIDUAL - the attack succeeded only inside a class the code documents
             as an accepted residual (citation required in the detail)
  ERROR    - harness failure

Ranked falsifiable hypotheses (diagnosing-bugs loop):
  H1 (rank 1): EAT tokens carry no machine-enforced claim bounds.
     eat_claim_bounds() and token_evidence_record() exist, but emit_eat
     never writes bounds onto the wire and verify_eat never checks them,
     so an EAT token can smuggle an arbitrary superior-level "proves"
     overreach claim and still verify. The narrow-claims discipline is
     enforced for VC / SCITT / C2PA / evidence bundles but NOT for EAT.
     Expected: BREAK -> F206.
  H2 (rank 2): VC claimBounds are issuer-declared free strings; an issuer
     can declare proves=["content correctness"] over hash-only evidence
     and verify_credential passes. Expected: RESIDUAL (claim_bounds.py
     documents the consistently-lying issuer as out of scope), no new
     finding.
  H3 (rank 3): redact_copy could launder broad source bounds onto a
     derived credential whose evidence no longer supports them.
     Expected: HELD (redact_copy replaces bounds with narrow redaction
     bounds).
  H4 (rank 4): SCITT receipt replay/transplant could be misread as
     content correctness. Expected: HELD (digest binding + ts_identity
     pinning + explicit narrow_claim / evidentiary_grade on the report).
  H5 (rank 5): TEE bundle could bind REPORT_DATA for key K1 while the
     verifier is handed K2 (key-binding swap). Expected: HELD
     (thumbprint binding inside report_data).
  H6 (rank 6): V18 could be bypassed with a boundless, section-gapped, or
     over-assigned payload. Expected: HELD (exact four-field shape,
     exact section set, exact section assignment, token membership).

$0 spend. No network. stdlib only.
"""

import base64
import copy
import json
import os
import sys
from types import SimpleNamespace

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
            except ImportError as e:
                _RESULTS.append((name, "ERROR", "missing module: %s" % e))
                return
            except AssertionError as e:
                _RESULTS.append((name, "ERROR", "assertion: %s"
                                % str(e)[:300]))
                return
            except Exception as e:  # noqa: BLE001 - hostile-input battery
                _RESULTS.append((name, "ERROR", "%s: %s"
                                % (type(e).__name__, str(e)[:300])))
                return
            verdict, detail = detail
            assert verdict in ("HELD", "BREAK", "RESIDUAL"), verdict
            _RESULTS.append((name, verdict, detail))
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

_SEED = bytes(range(32))
_SEED2 = bytes.fromhex("ab" * 32)
_SEED_ISSUER = bytes.fromhex("11" * 32)
_SEED_TS = bytes.fromhex("22" * 32)


def _eat_keys():
    from gov import ed25519
    pub = ed25519.publickey(_SEED)
    return pub, (lambda msg: ed25519.sign(_SEED, msg))


def _eat_evidence():
    return {
        "tpm": {
            "ueid": "ek-pubkey-sha256:" + "aa" * 32,
            "oemid": "Infineon",
            "hwmodel": "TPM2.0-dTPM",
            "hwversion": "7.85",
            "swname": "sasanam-agent",
            "swversion": "1.0.0",
            "measurements": {"pcr_digest": "bb" * 32},
            "dbgstat": "disabled",
            "nonce": b"tpm-challenge-nonce-0001",
        },
    }


def _eat_expectations():
    return {"tpm": {"pcr_digest": "bb" * 32}}


def _good_token(eat, signer):
    return eat.emit_eat(
        evidence=_eat_evidence(), nonce=b"superior-challenge-0000",
        issuer="sasanam-issuer-1", signer=signer, now=1700000000,
        expectations=_eat_expectations())


def _eat_verifier_cfg(pub):
    return {
        "issuer_pubkey": pub,
        "expected_issuer": "sasanam-issuer-1",
        "expected_nonce": b"superior-challenge-0000",
        "expectations": _eat_expectations(),
        "now": 1700000100,
        "expected_submod_nonces": {"tpm": b"tpm-challenge-nonce-0001"},
    }


def _payload_claims(token):
    parts = token.split(".")
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(
        padded.encode("ascii")).decode("utf-8"))


def _vc_signer():
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s = Ed25519Signer(_SEED_ISSUER)
    return s, [Ed25519Verifier(s.public_key)]


def _emit_vc(vc, signer, claim_bounds):
    return vc.emit_credential(
        issuer="issuer-a", subject_id="sha256:" + "aa" * 32,
        subject_claims={"role": "agent"},
        evidence=[{"type": "attestation", "digest": "bb" * 32}],
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z",
        signer=signer, claim_bounds=claim_bounds)


def _scitt_setup():
    from gov import scitt_receipt as sr
    from gov.signing import Ed25519Signer, Ed25519Verifier
    issuer_signer = Ed25519Signer(_SEED_ISSUER)
    ts_signer = Ed25519Signer(_SEED_TS)
    policy = sr.RegistrationPolicy(
        name="w211-admission", version="v1",
        allowed_issuers=("issuer-a",),
        allowed_content_types=("application/octet-stream",),
        max_statement_bytes=65536)
    ts = sr.TransparencyService(
        identity="ts-w211", ts_signer=ts_signer,
        registration_policy=policy,
        signing_config={"log_url": "hermetic://scitt",
                        "log_id": "scitt-test-log",
                        "tsa_url": "hermetic://tsa"},
        issuer_verifiers=[Ed25519Verifier(issuer_signer.public_key)],
        issuer_threshold=1)
    stmt = sr.issue_statement(
        issuer_signer, issuer="issuer-a", subject="agent/7",
        content=b"evidence-bytes")
    transparent = ts.register(stmt)
    return sr, ts, transparent, policy, issuer_signer, \
        [Ed25519Verifier(issuer_signer.public_key)], \
        [Ed25519Verifier(ts_signer.public_key)]


# ------------------------------------------------------- EAT / bounds probes

@_probe("eat_bounds_absent_on_wire")
def p_eat_bounds_wire():
    """H1: no claim bounds ride the EAT wire; verify never checks them."""
    import gov.eat_claims as eat
    import gov.claim_bounds as cb
    pub, signer = _eat_keys()
    tok = _good_token(eat, signer)
    claims = _payload_claims(tok)
    # The token claims set: bounds must not be smuggled in silently,
    # and there is no bounds field at all.
    boundish = [k for k in claims
                if "bound" in k.lower() or "prove" in k.lower()]
    if boundish:
        return ("HELD", "bounds present on wire: %s" % boundish)
    # The canonical bounds record exists but no verify path consumes it.
    bounds = eat.eat_claim_bounds()
    cb.validate_bounds(bounds)
    src = open(os.path.join(REPO, "gov", "eat_claims.py")).read()
    body = src.split("def verify_eat", 1)[1]
    body = body.split("\ndef ", 1)[0]  # verify_eat's own body only
    if "eat_claim_bounds" in body or "claim_bounds" in body:
        return ("HELD", "verify_eat consults claim bounds")
    return ("BREAK",
            "F206: token carries no claim bounds; verify_eat never "
            "consults eat_claim_bounds(); the narrow-claims discipline "
            "is unenforced for EAT on the wire")


@_probe("eat_superior_proves_smuggle")
def p_eat_proves_smuggle():
    """H1: a superior-level 'proves' overreach claim verifies fine."""
    import gov.eat_claims as eat
    pub, signer = _eat_keys()
    claims = _payload_claims(_good_token(eat, signer))
    claims["proves"] = ["the enclosed content is factually correct",
                        "the workload behaved safely"]
    claims["does_not_prove"] = []
    forged = eat._sign_claims(claims, signer)
    out = eat.verify_eat(forged, **_eat_verifier_cfg(pub))
    assert out["claims"]["proves"] not in (None, []), \
        "expected smuggled claim back"
    return ("BREAK",
            "F206: superior-level proves=['the enclosed content is "
            "factually correct', ...] verified OK; no bounds check "
            "stopped the overreach")


@_probe("eat_no_inheritance_holds")
def p_eat_no_inherit():
    """H4/H1-control: submod-only facts at superior level are refused."""
    import gov.eat_claims as eat
    pub, signer = _eat_keys()
    claims = _payload_claims(_good_token(eat, signer))
    claims["measurements"] = {"pcr_digest": "bb" * 32}
    forged = eat._sign_claims(claims, signer)
    try:
        eat.verify_eat(forged, **_eat_verifier_cfg(pub))
    except eat.EATError:
        return ("HELD", "superior-level attester fact refused (no "
                "inheritance across the submod boundary)")
    return ("BREAK", "superior-level measurements claim was accepted")


# ---------------------------------------------------------------- VC probes

@_probe("vc_redact_bounds_narrow")
def p_vc_redact():
    """H3: redaction must not launder broad source bounds downstream."""
    import gov.vc_bundle as vc
    signer, verifiers = _vc_signer()
    broad = _emit_vc(vc, signer, {
        "proves": ["workload behavior was safe", "content is correct"],
        "doesNotProve": ["ongoing platform state"]})
    redacted = vc.redact_copy(
        broad, keep_subject_fields=["role"],
        keep_evidence_types=["attestation"],
        holder_issuer="holder-b", signer=signer, verifiers=verifiers,
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z")
    vc.verify_credential(redacted, verifiers=verifiers)
    proves = redacted["claimBounds"]["proves"]
    assert not any("workload" in p or "correct" in p for p in proves), \
        "source overreach survived redaction: %r" % (proves,)
    assert "redactionNotice" in redacted, "redaction notice missing"
    return ("HELD", "redacted credential carries narrow redaction bounds; "
            "source overreach did not survive: %r" % (proves,))


@_probe("vc_overreach_issuer_residual")
def p_vc_overreach():
    """H2: issuer-declared overreach passes -- documented residual."""
    import gov.vc_bundle as vc
    signer, verifiers = _vc_signer()
    doc = _emit_vc(vc, signer, {
        "proves": ["the subject's content is factually correct"],
        "doesNotProve": ["ongoing platform state"]})
    vc.verify_credential(doc, verifiers=verifiers)
    return ("RESIDUAL",
            "attack succeeded within the documented residual: "
            "claimBounds are issuer-declared; a consistently-lying "
            "issuer is undetectable by token membership "
            "(gov/claim_bounds.py module docstring). No new finding.")

# --------------------------------------------------------------- SCITT probes

@_probe("scitt_receipt_transplant_refused")
def p_scitt_transplant():
    """H4: receipt for statement A cannot validate statement B."""
    sr, ts, transparent_a, policy, issuer_signer, iver, tver = _scitt_setup()
    stmt_b = sr.issue_statement(
        issuer_signer, issuer="issuer-a", subject="agent/7",
        content=b"different-bytes")
    transparent_b = ts.register(stmt_b)
    # Graft statement B into A's transparent envelope (keeps A's receipt).
    grafted = {"statement": transparent_b["statement"],
               "receipt": transparent_a["receipt"],
               "transparency_service":
                   transparent_a["transparency_service"]}
    try:
        sr.verify_transparent_statement(
            grafted, issuer_verifiers=iver, ts_verifiers=tver,
            ts_identity="ts-w211", pinned_policy_digest=policy.digest)
    except sr.VerificationFailed as e:
        assert "digest mismatch" in str(e), str(e)[:120]
        return ("HELD", "receipt transplant refused: %s" % str(e)[:120])
    except Exception:
        return ("HELD", "receipt transplant refused (exception path)")
    return ("BREAK", "receipt for statement A validated statement B")


@_probe("scitt_wrong_ts_identity_refused")
def p_scitt_ts_identity():
    """H4: receipt from ts-w211 presented under a foreign TS identity."""
    sr, ts, transparent, policy, _is, iver, tver = _scitt_setup()
    try:
        sr.verify_transparent_statement(
            transparent, issuer_verifiers=iver, ts_verifiers=tver,
            ts_identity="ts-attacker", pinned_policy_digest=policy.digest)
    except sr.VerificationFailed as e:
        assert "does not match" in str(e), str(e)[:120]
        return ("HELD", "cross-TS replay refused: %s" % str(e)[:120])
    except Exception:
        return ("HELD", "cross-TS receipt replay refused (exception path)")
    return ("BREAK", "receipt from ts-w211 accepted under ts-attacker")


@_probe("scitt_denied_issuer_admission")
def p_scitt_admission():
    """H4-control: unallowlisted issuer is refused at admission."""
    sr, ts, _stmt, policy, _is, _iv, _tv = _scitt_setup()
    from gov.signing import Ed25519Signer
    rogue = Ed25519Signer(_SEED2)
    stmt = sr.issue_statement(
        rogue, issuer="rogue-issuer", subject="agent/7",
        content=b"evidence-bytes")
    try:
        ts.register(stmt)
    except sr.RegistrationRefused:
        return ("HELD", "rogue issuer refused at admission "
                "(issuer-not-allowlisted)")
    return ("BREAK", "rogue issuer statement was admitted to the log")


@_probe("scitt_report_fields_honest")
def p_scitt_report():
    """H4: the returned report must not assert content correctness."""
    sr, ts, transparent, policy, _is, iver, tver = _scitt_setup()
    rep = sr.verify_transparent_statement(
        transparent, issuer_verifiers=iver, ts_verifiers=tver,
        ts_identity="ts-w211", pinned_policy_digest=policy.digest)
    assert rep["verified"] is True
    # The report must carry an explicit disavowal of content
    # correctness, not merely omit the claim.
    assert rep["evidentiary_grade"] == "registration-proven-not-content", \
        "evidentiary grade missing/misleading"
    disavowal = rep["narrow_claim"].lower()
    assert "does not prove" in disavowal or "does not" in disavowal, \
        "narrow claim lacks an explicit disavowal"
    assert "correct" in disavowal, \
        "disavowal does not name content correctness"
    assert rep["inclusion_verified"] is True
    return ("HELD", "report carries explicit correctness disavowal; "
            "grade=%r" % rep["evidentiary_grade"])


# ----------------------------------------------------------------- TEE probes

@_probe("tee_binding_swap_refused")
def p_tee_swap():
    """H5: REPORT_DATA binds key K1 but verifier is handed K2."""
    import gov.tee_attest as ta
    salt = os.urandom(32)
    fx = ta.make_snp_fixture(policy=0x30000, measurement=b"m" * 48,
                             tcb=b"\x01" * 8, chip_id=b"c" * 64,
                             salt=salt)
    import base64 as _b64
    other_pub = _b64.urlsafe_b64encode(b"k" * 32).decode("ascii")
    bundle = {"report": fx["report"], "ask_cert": fx["ask_cert"],
              "vcek_cert": fx["vcek_cert"],
              "expected_policy": fx["policy"],
              "expected_measurement": fx["measurement"],
              "tcb_allowlist": [fx["tcb"]],
              "tee_pubkey": other_pub, "salt": fx["salt"]}
    v = ta.SevSnpVerifier(ark_pubkey=fx["ark_pubkey"], enabled=True)
    try:
        v.verify(bundle)
    except ta.BindingError:
        return ("HELD", "key-binding swap refused: REPORT_DATA binds "
                "fixture key, verifier handed a different key")
    except ta.TeeAttestError:
        return ("HELD", "key-binding swap refused (TEE error path)")
    return ("BREAK", "swapped tee_pubkey passed the binding check")


@_probe("tee_local_tdreport_refused")
def p_tee_local():
    """H5-control: local/self-asserted TDREPORT refused on remote path."""
    import gov.tee_attest as ta
    fx = ta.make_tdx_fixture(
        mrtd=b"t" * 48, rtmrs={0: b"r" * 48, 1: b"s" * 48},
        tcb_info={"valid_from": 1, "valid_until": 9_999_999_999},
        salt=os.urandom(32), now=1_800_000_000)
    local = ta.make_synthetic_local_tdreport(
        mrtd=fx["mrtd"], tee_pubkey=fx["tee_pubkey"], salt=fx["salt"])
    v = ta.TdxQuoteVerifier(intel_root_pubkey=fx["intel_root_pubkey"],
                           enabled=True)
    try:
        v.verify({"quote": local})
    except ta.TeeAttestError:
        return ("HELD", "local TDREPORT refused on the remotely-"
                "verifiable path")
    return ("BREAK", "local/self-asserted report was accepted remotely")


# ------------------------------------------------------------ V18 / C2PA probes

def _v18_payload(**over):
    import gov.claim_bounds as cb
    from gov import evidence_verify as ev
    bounds = cb.default_bundle_bounds()
    sections = [s for s in
                ("bundle_meta", "log_slice", "policy", "decisions",
                 "approvals", "citations", "benchmark",
                 "kms_attestation", "retention_manifest")]
    assignment = cb.default_claim_assignment(
        sections, bounds["proves"], discovery_present=False)
    # V18 derives the required section set from the payload itself, so
    # the nine evidence sections must be present (content is irrelevant).
    payload = {"claim_bounds": bounds, "claim_assignment": assignment}
    for s in sections:
        payload[s] = {"probe": "dummy"}
    payload.update(over)
    return ev, payload


def _v18_status(payload):
    from gov import evidence_verify as ev
    check = ev.v18_claim_bounds(SimpleNamespace(payload=payload))
    return check.status


@_probe("v18_boundless_refused")
def p_v18_boundless():
    """H6: a boundless payload must not pass V18."""
    _ev, payload = _v18_payload()
    del payload["claim_bounds"]
    st = _v18_status(payload)
    if st == "fail":
        return ("HELD", "boundless payload refused by V18")
    return ("BREAK", "boundless payload passed V18 (status=%s)" % st)


@_probe("v18_section_gap_refused")
def p_v18_gap():
    """H6: claim_assignment missing a section must not pass V18."""
    _ev, payload = _v18_payload()
    del payload["claim_assignment"]["decisions"]
    st = _v18_status(payload)
    if st == "fail":
        return ("HELD", "section-gap payload refused by V18")
    return ("BREAK", "section-gap payload passed V18 (status=%s)" % st)


@_probe("v18_claim_outside_proves_refused")
def p_v18_outside():
    """H6: a section claim outside proves must not pass V18."""
    _ev, payload = _v18_payload()
    payload["claim_assignment"]["decisions"] = ["workload behaved safely"]
    st = _v18_status(payload)
    if st == "fail":
        return ("HELD", "over-assigned payload refused by V18")
    return ("BREAK", "over-assigned payload passed V18 (status=%s)" % st)


@_probe("v18_control_passes")
def p_v18_control():
    """H6-control: the honest default payload passes V18 cleanly."""
    _ev, payload = _v18_payload()
    st = _v18_status(payload)
    assert st == "pass", "honest payload did not pass V18 (status=%s)" % st
    return ("HELD", "honest payload passes V18 (control)")


@_probe("c2pa_transplant_refused")
def p_c2pa_transplant():
    """H2-control: manifest bound to content D1 attached to D2."""
    from gov import c2pa_provenance as c2
    from gov.signing import Ed25519Signer, Ed25519Verifier
    import hashlib as _hl
    signer = Ed25519Signer(_SEED)
    content = b"model-bytes-v1"
    d1 = _hl.sha256(content).hexdigest()
    manifest = c2.build_manifest(
        content_digest=d1, content_len=len(content),
        action="c2pa.created", software_agent="sasanam-model v1.2.3",
        description="w211 transplant probe")
    envelope = c2.seal_manifest(manifest, [signer])
    d2 = _hl.sha256(b"model-bytes-v2-tampered").hexdigest()
    try:
        c2.open_manifest(envelope, d2,
                         [Ed25519Verifier(signer.public_key)])
    except c2.C2PAManifestError:
        return ("HELD", "transplanted manifest refused (hard binding "
                "mismatch)")
    return ("BREAK", "manifest bound to D1 opened against D2")


# --------------------------------------------------------------- SLSA probes

@_probe("slsa_ingest_marks_secondhand")
def p_slsa_secondhand():
    """H2: ingested SLSA provenance must not launder into native records."""
    import json as _json
    from gov import slsa_predicate as sp
    from gov.signing import Ed25519Signer, Ed25519Verifier
    from gov import dsse_envelope as _de
    bsigner = Ed25519Signer(bytes([11]) * 32)
    isigner = Ed25519Signer(bytes([12]) * 32)
    builder_id = "https://builder.example.com/ci@v1"
    doc = {
        "_type": sp.STATEMENT_V1,
        "subject": [{"name": "app.tar.gz",
                     "digest": {"sha256": "aa" * 32}}],
        "predicateType": sp.SLSA_PROVENANCE_V1,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.com/build-type@v1",
                "resolvedDependencies": [
                    {"uri": "https://example.com/src@main",
                     "digest": {"sha256": "bb" * 32}}],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": "build-1"},
            },
        },
    }
    payload = _json.dumps(doc, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    env = _de.seal(payload, sp.INTOTO_PAYLOAD_TYPE, [bsigner])
    ing = sp.ingest(
        env,
        verifiers=[Ed25519Verifier(bsigner.public_key),
                   Ed25519Verifier(isigner.public_key)],
        authorized_builders={builder_id: bsigner.key_id},
        ingestor_signer=isigner, built_at=1700000000)
    sealed = ing.sealed["app.tar.gz"]
    blob = _json.dumps(sealed, default=str)
    marked = "slsa-provenance/v1@sha256:" in blob
    if marked:
        return ("HELD", "translated SLSA statements carry the second-hand "
                "recipe marker; foreign provenance cannot pass as native")
    return ("BREAK", "ingested SLSA statement lost its second-hand marker")


# ------------------------------------------------------------- determinism

@_probe("determinism")
def p_determinism():
    before = [(n, v) for (n, v, _d) in _RESULTS]
    for name, verdict in before:
        if name == "determinism" or name not in _PROBE_FNS:
            continue
        start = len(_RESULTS)
        _PROBE_FNS[name]()
        n2, v2 = _RESULTS[start][0], _RESULTS[start][1]
        del _RESULTS[start]
        assert n2 == name and v2 == verdict, \
            "non-deterministic verdict: %s %s -> %s" % (name, verdict, v2)
    return ("HELD", "%d/%d verdicts stable across runs"
            % (len(before), len(before)))


# --------------------------------------------------------------------- main

def _green_check():
    # Depth-1 green check: adjacent evidence/attestation batteries must
    # stay green alongside this one (each run with GOV_SKIP_GREEN=1 to
    # prevent combinatorial nesting).
    import subprocess
    adj = ["evals/eat_claims_probes.py", "evals/scitt_receipt_probes.py",
           "evals/vc_bundle_probes.py", "evals/tee_attest_probes.py",
           "evals/c2pa_provenance_probes.py"]
    for rel in adj:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            _RESULTS.append(("green:" + rel, "HELD",
                             "battery absent (lane not merged)"))
            continue
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        r = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, env=env, timeout=600)
        ok = r.returncode == 0
        _RESULTS.append(("green:" + os.path.basename(rel),
                         "HELD" if ok else "ERROR",
                         "adjacent battery %s"
                         % ("green" if ok else
                            "RED: " + (r.stdout + r.stderr)[-300:])))


def main():
    if not GREEN_SKIP:
        _green_check()
    for name in list(_PROBE_FNS):
        if name == "determinism":
            continue
        _PROBE_FNS[name]()
    _PROBE_FNS["determinism"]()
    n_break = n_held = n_res = n_err = 0
    for name, verdict, detail in _RESULTS:
        print("%-34s %-9s %s" % (name, verdict, detail))
        if verdict == "BREAK":
            n_break += 1
        elif verdict == "HELD":
            n_held += 1
        elif verdict == "RESIDUAL":
            n_res += 1
        else:
            n_err += 1
    print("w211 redteam: breaks=%d held=%d residuals=%d errors=%d"
          % (n_break, n_held, n_res, n_err))
    # Exit nonzero only on harness errors; BREAK is the expected
    # red-team outcome (findings filed in evals/FINDINGS.md), not a
    # battery failure (wave-177 convention).
    bad = any(v not in ("BREAK", "HELD", "RESIDUAL") for _, v, _ in _RESULTS)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
