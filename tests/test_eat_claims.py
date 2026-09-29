"""Unit tests for gov/eat_claims.py (wave-210 lane A).

EAT (RFC 9711)-shaped attestation claims emitted as JSON/JWT with
JOSE/Ed25519. Labeled "EAT-shaped, not wire-interoperable" (no CBOR/COSE).
The no-claim-inheritance rule across submods is code, not prose.
"""

import base64
import copy
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import unittest  # noqa: E402

from gov import eat_claims as eat  # noqa: E402
from gov import ed25519  # noqa: E402

SEED = bytes(range(32))
PUB = ed25519.publickey(SEED)


def _signer(msg):
    return ed25519.sign(SEED, msg)


def _evidence(**over):
    base = {
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
        "tee": {
            "ueid": "tee-chip-id:" + "cc" * 16,
            "oemid": "AMD",
            "hwmodel": "SEV-SNP",
            "hwversion": "1.55",
            "swname": "sasanam-agent",
            "swversion": "1.0.0",
            "measurements": {"mrtd": "dd" * 48},
            "dbgstat": "disabled",
            "nonce": b"tee-challenge-nonce-0002",
        },
    }
    base.update(over)
    return base


def _expectations():
    return {
        "tpm": {"pcr_digest": "bb" * 32},
        "tee": {"mrtd": "dd" * 48},
    }


def _emit(ev=None, **kw):
    args = dict(evidence=_evidence() if ev is None else ev,
                nonce=b"superior-challenge-0000",
                issuer="sasanam-issuer-1", signer=_signer,
                now=1700000000, expectations=_expectations())
    args.update(kw)
    return eat.emit_eat(**args)


def _cfg(**over):
    cfg = dict(issuer_pubkey=PUB, expected_issuer="sasanam-issuer-1",
               expected_nonce=b"superior-challenge-0000",
               expected_submod_nonces={
                   "tpm": b"tpm-challenge-nonce-0001",
                   "tee": b"tee-challenge-nonce-0002"},
               expectations=_expectations(), now=1700000100)
    cfg.update(over)
    return cfg


def _payload(token):
    seg = token.split(".")[1]
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.encode()).decode())


class TestEatClaims(unittest.TestCase):

    def test_round_trip_ok(self):
        tok = _emit()
        out = eat.verify_eat(tok, **_cfg())
        claims = out["claims"]
        self.assertEqual(claims["eat_profile"], eat.EAT_PROFILE_V1)
        self.assertEqual(claims["intuse"], eat.EAT_INTUSE)
        self.assertEqual(set(claims["submods"]), {"tpm", "tee"})
        for sub in claims["submods"].values():
            self.assertEqual(sub["measres"], "pass")
            self.assertEqual(sub["dbgstat"], "disabled")

    def test_header_closed_shape(self):
        tok = _emit()
        seg = tok.split(".")[0]
        seg += "=" * (-len(seg) % 4)
        header = json.loads(base64.urlsafe_b64decode(seg.encode()).decode())
        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["typ"], "application/eat+jwt")
        # Unknown header field -> refused (closed envelope).
        bad_header = dict(header)
        bad_header["crit"] = ["exp"]
        from gov.attested_identity import canonical_json
        parts = tok.split(".")
        si = (eat._b64u(canonical_json(bad_header)) + "." + parts[1])
        bad = si + "." + eat._b64u(_signer(si.encode("ascii")))
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(bad, **_cfg())

    def test_superior_attester_fact_refused(self):
        claims = {
            "iss": "sasanam-issuer-1", "iat": 1700000000,
            "exp": 1700000300, "cti": "x" * 16,
            "eat_nonce": eat._b64u(b"superior-challenge-0000"),
            "eat_profile": eat.EAT_PROFILE_V1, "intuse": eat.EAT_INTUSE,
            "measurements": {"pcr_digest": "bb" * 32},  # leak
            "submods": {},
        }
        tok = eat._sign_claims(claims, _signer)
        with self.assertRaises(eat.EATVerifyError) as cm:
            eat.verify_eat(tok, **_cfg())
        self.assertIn("inherit", str(cm.exception).lower())

    def test_unknown_submod_refused(self):
        ev = _evidence()
        ev["ufo"] = {"ueid": "x", "dbgstat": "disabled",
                     "nonce": b"z", "measurements": {}}
        with self.assertRaises(eat.EATBuildError) as cm:
            _emit(ev=ev)
        self.assertIn("ufo", str(cm.exception))

    def test_missing_submod_field_refused(self):
        ev = _evidence()
        del ev["tpm"]["ueid"]
        with self.assertRaises(eat.EATBuildError):
            _emit(ev=ev)

    def test_tamper_fails(self):
        tok = _emit()
        parts = tok.split(".")
        seg = list(parts[1])
        seg[5] = "A" if seg[5] != "A" else "B"
        bad = parts[0] + "." + "".join(seg) + "." + parts[2]
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(bad, **_cfg())

    def test_nonce_mismatch(self):
        tok = _emit()
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(tok, **_cfg(expected_nonce=b"nope"))

    def test_submod_nonce_wrong(self):
        tok = _emit()
        cfg = _cfg(expected_submod_nonces={
            "tpm": b"wrong", "tee": b"tee-challenge-nonce-0002"})
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(tok, **cfg)

    def test_submod_nonce_missing_cfg(self):
        tok = _emit()
        cfg = _cfg(expected_submod_nonces={"tpm": b"tpm-challenge-nonce-0001"})
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(tok, **cfg)

    def test_dbgstat_enabled_refused(self):
        ev = _evidence()
        ev["tee"]["dbgstat"] = "enabled"
        tok = _emit(ev=ev)
        with self.assertRaises(eat.EATVerifyError) as cm:
            eat.verify_eat(tok, **_cfg())
        self.assertIn("dbgstat", str(cm.exception).lower())

    def test_measurement_mismatch_refused(self):
        tok = _emit()
        cfg = _cfg(expectations={"tpm": {"pcr_digest": "ff" * 32},
                                 "tee": {"mrtd": "dd" * 48}})
        with self.assertRaises(eat.EATVerifyError) as cm:
            eat.verify_eat(tok, **cfg)
        self.assertIn("measurement", str(cm.exception).lower())

    def test_unassessed_refused_by_default(self):
        tok = _emit(expectations={})  # no reference values -> unassessed
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(tok, **_cfg())
        # Explicit opt-in allows it (documented residual).
        out = eat.verify_eat(tok, **_cfg(allow_unassessed=True))
        self.assertEqual(out["claims"]["submods"]["tpm"]["measres"],
                         "unassessed")

    def test_profile_mismatch_refused(self):
        tok = _emit()
        payload = _payload(tok)
        payload["eat_profile"] = "https://evil.example/other"
        retok = eat._sign_claims(payload, _signer)
        with self.assertRaises(eat.EATVerifyError) as cm:
            eat.verify_eat(retok, **_cfg())
        self.assertIn("profile", str(cm.exception).lower())

    def test_unknown_claims_tolerated(self):
        tok = _emit()
        payload = _payload(tok)
        payload["x_future"] = [1, {"two": 2}]
        payload["submods"]["tpm"]["x_note"] = "hi"
        retok = eat._sign_claims(payload, _signer)
        out = eat.verify_eat(retok, **_cfg())
        self.assertEqual(out["claims"]["x_future"][0], 1)

    def test_expired_refused(self):
        tok = _emit()
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(tok, **_cfg(now=1800000000))

    def test_issuer_mismatch_refused(self):
        tok = _emit()
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(tok, **_cfg(expected_issuer="someone-else"))

    def test_bounds_bridge_validates(self):
        import gov.claim_bounds as cb
        bounds = eat.eat_claim_bounds()
        cb.validate_bounds(bounds)  # raises on invalid
        self.assertTrue(bounds["does_not_prove"])
        self.assertFalse(set(bounds["proves"]) &
                         set(bounds["does_not_prove"]))

    # --- F206: claim bounds machine-enforced on the wire (wave-212) ---

    def test_bounds_on_wire_and_pinned(self):
        import gov.claim_bounds as cb
        tok = _emit()
        claims = _payload(tok)
        wire = claims.get("eat_bounds")
        self.assertIsInstance(wire, dict)
        normalized = cb.validate_bounds(wire, where="eat_claim_bounds")
        self.assertEqual(normalized, eat.eat_claim_bounds())
        # The legit token still verifies with bounds on the wire.
        out = eat.verify_eat(tok, **_cfg())
        self.assertEqual(out["claims"]["eat_bounds"], normalized)

    def test_bounds_mandatory_fail_closed(self):
        tok = _emit()
        claims = _payload(tok)
        del claims["eat_bounds"]  # pre-F206 token shape
        retok = eat._sign_claims(claims, _signer)
        with self.assertRaises(eat.EATVerifyError) as cm:
            eat.verify_eat(retok, **_cfg())
        self.assertIn("eat_bounds", str(cm.exception))

    def test_superior_proves_smuggle_refused(self):
        tok = _emit()
        claims = _payload(tok)
        claims["proves"] = ["the enclosed content is factually correct"]
        claims["does_not_prove"] = []
        retok = eat._sign_claims(claims, _signer)
        with self.assertRaises(eat.EATVerifyError) as cm:
            eat.verify_eat(retok, **_cfg())
        self.assertIn("bounds-smuggle", str(cm.exception))

    def test_edited_bounds_refused(self):
        tok = _emit()
        claims = _payload(tok)
        claims["eat_bounds"] = copy.deepcopy(claims["eat_bounds"])
        claims["eat_bounds"]["proves"] = (
            list(claims["eat_bounds"]["proves"]) + ["content is correct"])
        retok = eat._sign_claims(claims, _signer)
        with self.assertRaises(eat.EATVerifyError) as cm:
            eat.verify_eat(retok, **_cfg())
        self.assertIn("canonical", str(cm.exception))

    def test_incoherent_bounds_refused(self):
        tok = _emit()
        claims = _payload(tok)
        claims["eat_bounds"] = copy.deepcopy(claims["eat_bounds"])
        # Schema violation through claim_bounds.py: proves and
        # does_not_prove overlap, does_not_prove non-empty.
        tok0 = claims["eat_bounds"]["proves"][0]
        claims["eat_bounds"]["does_not_prove"] = [tok0]
        retok = eat._sign_claims(claims, _signer)
        with self.assertRaises(eat.EATVerifyError):
            eat.verify_eat(retok, **_cfg())

    def test_determinism_with_fixed_cti(self):
        a = _emit(cti="fixed-cti-0001")
        b = _emit(cti="fixed-cti-0001")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
