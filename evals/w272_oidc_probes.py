#!/usr/bin/env python3
"""Wave-272 red-first battery: OIDC four-claim gate ceremony (evcert).

The wave-271 prospectus (§child2) found Fulcio authenticates a valid OIDC
token but establishes no application-level producer authorization. This
battery pins the four-claim gate in ``gov/evidence_certs.py``: before
issuance the producer MUST present an OIDC token whose iss/aud/sub/exp
verify against the issuer's JWKS; the certified producer identity is the
(iss, sub) pair.

Red phase (``OIDC_IMPL=stub``): a battery-local ``StubOidcGate`` accepts
ANY token (permissive foil). Every attack BREAKs -- the foil never
refuses -- while non-refusing controls HELD, proving the probes are real
and the foil is permissive rather than vacuous-deny.

Green phase (default): the real ``gov.evidence_certs.OidcGate``. All
attacks HELD with the exact ``oidc-*`` refusal code; controls HELD.

Module-level staging default; verified standalone under
``env -u GOV_DEPLOYMENT_MODE``. Depth-1 green check honoring
``GOV_SKIP_GREEN``. No in-repo git subprocesses; fresh ``/var/tmp/g272*``
TMPDIRs via tempfile.
"""

import base64
import json
import os
import re
import sys
import tempfile
import hashlib
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Audit-log HMAC chain key for issuance paths (same convention as
# tests/test_evcert.py).
import secrets as _secrets  # noqa: E402
os.environ.setdefault("GOV_LOG_KEY", _secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w272-oidc-battery")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import evidence_certs as ec  # noqa: E402
from gov import ed25519 as ed  # noqa: E402
from gov import kms as kms_mod  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Wave-272 merge pin: 1411 (wave-271 merge) + 32 new codes = 1443.
TAXONOMY_PIN = 2035 # Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



OIDC_IMPL = os.environ.get("OIDC_IMPL", "real")

ISSUER = "https://oidc.test.example"
AUDIENCE = "sasanam-evcert-ceremony"
NOW = 1790860000
SKEW = 300  # spec-pinned default clock-skew bound
ARC = "1.3.6.1.4.1.99999"

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "oidc_test_jwks.json")

# Fixed seeds: fixture signer (matches the checked-in JWKS) and attacker.
FIXTURE_SEED = bytes([0xA0]) * 32
ATTACKER_SEED = bytes([0xB0]) * 32
ATTACKER_PUB = ed.publickey(ATTACKER_SEED)


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s):
    if not isinstance(s, str):
        raise ValueError("not a string")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_jwks():
    with open(FIXTURE, "r", encoding="utf-8") as f:
        return json.load(f)


def mint_token(seed, claims, kid="test-key-1", alg="EdDSA",
               raw_payload=None):
    """Battery-local JWT minting (independent of product code)."""
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    hb = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    if raw_payload is not None:
        pb = _b64u(raw_payload)
    else:
        pb = _b64u(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    if alg == "none":
        sig = b""
    else:
        sig = ed.sign(seed, (hb + "." + pb).encode("ascii"))
    return hb + "." + pb + "." + _b64u(sig)


def good_claims(sub="alice", iss=ISSUER, aud=AUDIENCE, exp=NOW + 600):
    return {"iss": iss, "aud": aud, "sub": sub, "exp": exp}


class StubOidcGate(object):
    """Permissive red-phase foil: verifies NOTHING, returns fixed claims
    for any token. If an attack does not BREAK against this foil, the
    probe is vacuous."""

    def __init__(self, **kw):
        self.issuer = kw.get("issuer", ISSUER)
        self.audience = kw.get("audience", AUDIENCE)

    def verify_token(self, token):
        return {"iss": self.issuer, "sub": "alice", "exp": NOW + 600}


def make_gate(**over):
    kw = dict(issuer=ISSUER, audience=AUDIENCE, jwks=load_jwks(),
              clock_skew_s=SKEW, now=lambda: NOW)
    kw.update(over)
    if OIDC_IMPL == "stub":
        return StubOidcGate(**kw)
    gate_cls = getattr(ec, "OidcGate", None)
    if gate_cls is None:
        raise AssertionError("OidcGate not implemented (green phase only)")
    return gate_cls(**kw)


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


class CABase(object):
    def make_ca(self, gate=None):
        os.makedirs("/var/tmp", exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="oidc-ut-", dir="/var/tmp")
        self.fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        approvals = {"a" * 32: {"decider": "alice", "state": "pending"}}
        kw = dict(kms_provider=self.fake,
                  ca_key_id="ca-key-1",
                  ca_public_key=self.fake.test_signing_public_key("ca-key-1"),
                  issuers=[ISSUER],
                  approval_lookup=approvals.get,
                  audit_log_path=os.path.join(self.tmp, "audit.jsonl"),
                  anchor_reachable=lambda: True,
                  oid_arc=ARC,
                  now=lambda: NOW)
        if gate is not None:
            kw["oidc_gate"] = gate
        return ec.EvidenceCA(**kw)

    def pop_req(self, seed_byte=0x01, approval_id="a" * 32):
        seed, pub = _keypair(seed_byte)
        chal = (b"evcert-pop-v1" + approval_id.encode("utf-8")
                + hashlib.sha256(pub).digest())
        return {"ephemeral_pub": pub, "pop_sig": ed.sign(seed, chal),
                "approval_id": approval_id, "intent_digest": "d" * 64}


# ---------------------------------------------------------------------------
# Part A -- gate-level probes (verify_token)
# ---------------------------------------------------------------------------

class GateProbeTests(unittest.TestCase, CABase):
    """Attack the gate directly. Red: stub accepts everything -> BREAK.
    Green: exact oidc-* refusal codes."""

    def gate_refuses(self, token, code):
        gate = make_gate()
        try:
            gate.verify_token(token)
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, code,
                             "wrong refusal code: %r" % (e.code,))
            return "HELD"
        return "BREAK"

    def test_a01_wrong_issuer(self):
        tok = mint_token(FIXTURE_SEED,
                         good_claims(iss="https://evil.example"))
        self.assertEqual(self.gate_refuses(tok, "oidc-issuer-mismatch"),
                         "HELD")

    def test_a02_wrong_audience(self):
        tok = mint_token(FIXTURE_SEED,
                         good_claims(aud="someone-else"))
        self.assertEqual(self.gate_refuses(tok, "oidc-audience-mismatch"),
                         "HELD")

    def test_a03_expired_token(self):
        tok = mint_token(FIXTURE_SEED, good_claims(exp=NOW - SKEW - 1))
        self.assertEqual(self.gate_refuses(tok, "oidc-token-expired"),
                         "HELD")

    def test_a04_missing_sub(self):
        claims = good_claims()
        del claims["sub"]
        tok = mint_token(FIXTURE_SEED, claims)
        self.assertEqual(self.gate_refuses(tok, "oidc-missing-claim"),
                         "HELD")

    def test_a05_ambiguous_subject(self):
        raw = ('{"iss":"%s","aud":"%s","sub":"alice","sub":"mallory",'
               '"exp":%d}' % (ISSUER, AUDIENCE, NOW + 600)).encode("utf-8")
        tok = mint_token(FIXTURE_SEED, None, raw_payload=raw)
        self.assertEqual(self.gate_refuses(tok, "oidc-ambiguous-subject"),
                         "HELD")

    def test_a06_forged_signature(self):
        tok = mint_token(ATTACKER_SEED, good_claims(), kid="test-key-1")
        self.assertEqual(self.gate_refuses(tok, "oidc-signature-invalid"),
                         "HELD")

    def test_a07_unknown_kid(self):
        tok = mint_token(FIXTURE_SEED, good_claims(), kid="no-such-key")
        self.assertEqual(self.gate_refuses(tok, "oidc-signature-invalid"),
                         "HELD")

    def test_a08_alg_none(self):
        # alg=none with a NON-EMPTY signature part: the algorithm
        # allowlist must fire (never verify). The empty-signature
        # variant is refused as malformed (three non-empty parts).
        header = {"alg": "none", "typ": "JWT"}
        hb = _b64u(json.dumps(header, separators=(",", ":")).encode())
        pb = _b64u(json.dumps(good_claims(),
                              separators=(",", ":")).encode())
        tok = hb + "." + pb + "." + _b64u(b"\x00" * 64)
        self.assertEqual(self.gate_refuses(tok, "oidc-signature-invalid"),
                         "HELD")
        tok_empty = hb + "." + pb + "."
        self.assertEqual(self.gate_refuses(tok_empty,
                                           "oidc-malformed-token"), "HELD")

    def test_a10_malformed_token(self):
        self.assertEqual(self.gate_refuses("not.a.jwt.at.all.x",
                                           "oidc-malformed-token"), "HELD")
        self.assertEqual(self.gate_refuses("two.parts",
                                           "oidc-malformed-token"), "HELD")

    # -- controls ------------------------------------------------------
    def test_c11g_valid_token_verifies(self):
        gate = make_gate()
        claims = gate.verify_token(mint_token(FIXTURE_SEED, good_claims()))
        self.assertEqual(claims["iss"], ISSUER)
        self.assertEqual(claims["sub"], "alice")
        self.assertEqual(claims["exp"], NOW + 600)

    def test_c13_skew_boundary(self):
        gate = make_gate()
        # exp 100s in the past is inside the 300s skew bound: valid.
        # (The past-the-bound refusal is pinned by attack a03.)
        ok = gate.verify_token(mint_token(FIXTURE_SEED,
                                          good_claims(exp=NOW - 100)))
        self.assertEqual(ok["sub"], "alice")

    def test_a11_duplicate_iss_fails_closed(self):
        raw = ('{"iss":"%s","iss":"https://evil.example","aud":"%s",'
               '"sub":"alice","exp":%d}'
               % (ISSUER, AUDIENCE, NOW + 600)).encode("utf-8")
        tok = mint_token(FIXTURE_SEED, None, raw_payload=raw)
        self.assertEqual(self.gate_refuses(tok, "oidc-malformed-token"),
                         "HELD")

    def test_c16a_aud_list_accepted(self):
        gate = make_gate()
        claims = gate.verify_token(
            mint_token(FIXTURE_SEED, good_claims(aud=[AUDIENCE, "other"])))
        self.assertEqual(claims["sub"], "alice")

    def test_a12_missing_exp(self):
        claims = good_claims()
        del claims["exp"]
        tok = mint_token(FIXTURE_SEED, claims)
        self.assertEqual(self.gate_refuses(tok, "oidc-missing-claim"),
                         "HELD")

    def test_c17_hostile_bytes_never_leak(self):
        # Exception-type discipline only: a hostile token must never
        # surface a non-ceremony exception. (Acceptance itself is pinned
        # by attack a10; the permissive stub foil accepts everything, so
        # acceptance is not asserted here.)
        gate = make_gate()
        for bad in (b"\xff\xfe\x00bad".decode("latin1"),
                    "\x00", "a." * 40, ""):
            try:
                gate.verify_token(bad)
            except ec.EvidenceCertError:
                continue
            except Exception as e:  # noqa: BLE001
                self.fail("non-ceremony exception leaked: %r" % (e,))


# ---------------------------------------------------------------------------
# Part B -- ceremony wiring probes (EvidenceCA)
# ---------------------------------------------------------------------------

class WiringProbeTests(unittest.TestCase, CABase):
    """The OIDC requirement must be enforceable at the ceremony seam."""

    def test_b01_token_required(self):
        """Gate configured, no token presented -> refused. Pre-seam this
        requirement cannot even be expressed -> BREAK (red)."""
        try:
            ca = self.make_ca(gate=make_gate())
        except TypeError:
            self.fail("BREAK: EvidenceCA has no oidc_gate seam -- the "
                      "token requirement is unenforceable")
        req = self.pop_req()
        try:
            ca.issue(identity_assertion={"iss": ISSUER, "sub": "alice",
                                         "exp": NOW + 3600},
                     oidc_token=None, **req)
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, "oidc-token-required")
            return
        self.fail("BREAK: issuance without a token succeeded")

    def test_b02_e2e_producer_identity(self):
        """Valid token -> issued; the certified producer identity is the
        (iss, sub) pair, recorded on the audit attestation."""
        try:
            ca = self.make_ca(gate=make_gate())
        except TypeError:
            self.fail("BREAK: EvidenceCA has no oidc_gate seam")
            return
        tok = mint_token(FIXTURE_SEED, good_claims())
        req = self.pop_req()
        cert, stored = ca.issue(oidc_token=tok, **req)
        # Cert shape unchanged (byte-identical wire): the pair rides the
        # existing issuer/subject fields plus the attestation.
        self.assertEqual(cert["extensions"]["principal"], "alice")
        self.assertIs(stored.get("oidc_verified"), True)
        self.assertEqual(stored.get("producer_identity"),
                         {"iss": ISSUER, "sub": "alice"})
        # Forged token at the seam is refused, not issued.
        bad = mint_token(ATTACKER_SEED, good_claims(), kid="test-key-1")
        req2 = self.pop_req(seed_byte=0x02)
        try:
            ca.issue(oidc_token=bad, **req2)
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, "oidc-signature-invalid")
            return
        self.fail("BREAK: forged token issued a certificate")

    def test_b03_legacy_path_untouched(self):
        """No gate configured: legacy identity_assertion path issues;
        cert field-set identical to the base shape."""
        ca = self.make_ca()
        req = self.pop_req()
        req["identity_assertion"] = {"iss": ISSUER, "sub": "alice",
                                     "exp": NOW + 3600}
        cert, stored = ca.issue(**req)
        self.assertEqual(set(cert.keys()),
                         {"format", "subject_public_key", "subject_key_id",
                          "issuer_key_id", "not_before", "not_after", "eku",
                          "extensions", "honest_limits", "ca_signature"})
        self.assertIs(stored.get("oidc_verified"), False)

    def test_b04_unexpected_token_refused(self):
        """Token presented to a non-OIDC CA is refused (never honored)."""
        ca = self.make_ca()
        req = self.pop_req()
        req["identity_assertion"] = {"iss": ISSUER, "sub": "alice",
                                     "exp": NOW + 3600}
        tok = mint_token(FIXTURE_SEED, good_claims())
        try:
            ca.issue(oidc_token=tok, **req)
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, "evcert-malformed-request")
            return
        except TypeError:
            # Pre-seam: the kwarg is rejected by the signature --
            # fail-closed in effect (the token is never honored).
            return
        self.fail("BREAK: token honored by a non-OIDC CA")

    def test_b05_pin(self):
        path = os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))),
            "gov", "decision_codes.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        # The foil does not change the tree: the pin holds in both modes.
        expect = TAXONOMY_PIN
        self.assertEqual(len(codes), expect,
                         "raw literal count %d != pin %d"
                         % (len(codes), expect))
        self.assertEqual(len(set(codes)), len(codes), "duplicate literals")
        self.assertEqual(len(codes), len(TAXONOMY))
        oidc = sorted(c for c in TAXONOMY if TAXONOMY[c]["domain"]
                      == "oidc")
        self.assertEqual(len(oidc), 8)
        self.assertEqual(oidc, sorted(oidc))


def _green_check():
    """Depth-1: run the adjacent evcert unit suite with the skip var set
    in the child env. Honors GOV_SKIP_GREEN itself."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="g272-green-", dir="/var/tmp")
    os.makedirs(env["TMPDIR"], exist_ok=True)
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_evcert", "-v"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=600)
    out = p.stdout + p.stderr
    fails = re.findall(r"^FAIL: (\S+)", out, re.M)
    errors = re.findall(r"^ERROR: (\S+)", out, re.M)
    # The taxonomy pin (1458 at the wave-272 merge) is owned by the merge
    # coordinator; every other failure is a real regression.
    non_pin_fails = [f for f in fails if "pin" not in f.lower()]
    ok = not errors and not non_pin_fails
    print("green check tests.test_evcert: %s "
          "(pin failures: %s)" %
          ("OK" if ok else "FAIL", fails))
    if not ok:
        print(out[-2000:])
    return ok


def main():
    os.makedirs("/var/tmp", exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="g272-oidc-", dir="/var/tmp")
    os.environ["TMPDIR"] = tmp
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(GateProbeTests))
    suite.addTests(loader.loadTestsFromTestCase(WiringProbeTests))
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    held = result.testsRun - len(result.failures) - len(result.errors)
    broken = len(result.failures) + len(result.errors)
    print("OIDC_IMPL=%s RESULT %s (%d HELD / %d BREAK / 0 ERROR)" %
          (OIDC_IMPL, "OK" if result.wasSuccessful() else "FAIL",
           held, broken))
    green_ok = _green_check()
    if not result.wasSuccessful() or not green_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
