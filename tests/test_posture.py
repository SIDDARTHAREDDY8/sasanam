#!/usr/bin/env python3
"""Unit tests for gov/posture.py and the revocation signal hook.

Independent spec-vector literals (no recomputation of the
implementation's own internals): fixed seeds, fixed clocks, fixed
digests. Public seams only.
"""

import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import absence as _ab  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov import posture as po  # noqa: E402
from gov import revocation as rv  # noqa: E402

# Fixed test fixtures: a 32-byte seed, its real public key, two
# canonical digests, one fixed timestamp.
_SEED = bytes(range(32))
_PUB = _ed.publickey(_SEED)
_WRONG_PUB = _ed.publickey(bytes(32 - i for i in range(32)))
_ISSUER = "posture-unit"
_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_NOW = 1700000000.0
_IAT = "2023-11-14T22:13:20Z"


def _emit(**kw):
    kw.setdefault("now", _NOW)
    kw.setdefault("issuer_id", _ISSUER)
    return po.emit_signal("revocation", _DIGEST_A, "permit",
                          _SEED, **kw)


class EmitShapeTests(unittest.TestCase):
    def test_emit_returns_spec_shape(self):
        sig = _emit()
        self.assertEqual(set(sig),
                         {"v", "iss", "jti", "iat", "sub", "events",
                          "scope", "signature"})
        self.assertEqual(sig["v"], 1)
        self.assertEqual(sig["iss"], _ISSUER)
        self.assertEqual(sig["sub"], _DIGEST_A)
        self.assertEqual(sig["scope"], "permit")
        self.assertEqual(sig["iat"], _IAT)
        self.assertEqual(
            sig["events"],
            {"urn:sasanam:posture:v1:revocation": {"digest": _DIGEST_A}})
        self.assertEqual(len(sig["jti"]), 64)
        self.assertEqual(len(sig["signature"]), 128)

    def test_issuer_seed_is_positional_per_spec(self):
        # Spec: emit_signal(event, subject_digest, scope, issuer_seed).
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", _SEED,
                             issuer_id=_ISSUER, now=_NOW)
        po.verify_signal(sig, {_ISSUER: _PUB})

    def test_emit_rejects_unknown_event(self):
        with self.assertRaises(po.SignalUnknownEventError) as ctx:
            po.emit_signal("nonsense", _DIGEST_A, "permit", _SEED,
                           issuer_id=_ISSUER, now=_NOW)
        self.assertEqual(ctx.exception.code, "signal-unknown-event")

    def test_emit_rejects_bad_authoring_inputs(self):
        with self.assertRaises(ValueError):
            po.emit_signal("revocation", "", "permit", _SEED,
                           issuer_id=_ISSUER, now=_NOW)
        with self.assertRaises(ValueError):
            po.emit_signal("revocation", _DIGEST_A, "", _SEED,
                           issuer_id=_ISSUER, now=_NOW)
        with self.assertRaises(ValueError):
            po.emit_signal("revocation", _DIGEST_A, "permit",
                           b"short", issuer_id=_ISSUER, now=_NOW)

    def test_all_four_events_have_urns(self):
        for event, first_kind in (
                ("revocation", None),
                ("permit-refusal", "permit-revoked"),
                ("admission-refusal", "admission-digest-mismatch"),
                ("absence-attribution", "never-advertised")):
            kw = {} if first_kind is None else {"kind": first_kind}
            sig = po.emit_signal(event, _DIGEST_A, "permit", _SEED,
                                 issuer_id=_ISSUER, now=_NOW, **kw)
            urns = list(sig["events"])
            self.assertEqual(len(urns), 1)
            self.assertTrue(urns[0].startswith("urn:sasanam:posture:v1:"),
                            urns)


class KindTests(unittest.TestCase):
    def test_permit_refusal_kinds_discriminated(self):
        a = po.emit_signal("permit-refusal", _DIGEST_A, "permit",
                           _SEED, issuer_id=_ISSUER, now=_NOW,
                           kind="permit-revoked")
        b = po.emit_signal("permit-refusal", _DIGEST_A, "permit",
                           _SEED, issuer_id=_ISSUER, now=_NOW,
                           kind="approval-digest-diverged")
        ka = list(a["events"].values())[0]["kind"]
        kb = list(b["events"].values())[0]["kind"]
        self.assertEqual((ka, kb),
                         ("permit-revoked", "approval-digest-diverged"))

    def test_kind_required_when_event_demands_one(self):
        with self.assertRaises(po.SignalKindRequiredError) as ctx:
            po.emit_signal("permit-refusal", _DIGEST_A, "permit",
                           _SEED, issuer_id=_ISSUER, now=_NOW)
        self.assertEqual(ctx.exception.code, "signal-kind-required")

    def test_unknown_kind_refused(self):
        with self.assertRaises(po.SignalUnknownKindError) as ctx:
            po.emit_signal("admission-refusal", _DIGEST_A, "admission",
                           _SEED, issuer_id=_ISSUER, now=_NOW,
                           kind="launch-the-missiles")
        self.assertEqual(ctx.exception.code, "signal-unknown-kind")

    def test_revocation_takes_no_kind(self):
        with self.assertRaises(po.SignalUnknownKindError):
            _emit(kind="permit-revoked")

    def test_admission_kinds_are_the_admission_codes(self):
        for kind in ("admission-digest-mismatch",
                     "admission-issuer-untrusted",
                     "admission-format-unknown",
                     "admission-unverifiable"):
            sig = po.emit_signal("admission-refusal", _DIGEST_A,
                                 "admission", _SEED, issuer_id=_ISSUER,
                                 now=_NOW, kind=kind)
            self.assertEqual(list(sig["events"].values())[0]["kind"],
                             kind)


class VerifyTests(unittest.TestCase):
    def test_verify_round_trip(self):
        sig = po.emit_signal("permit-refusal", _DIGEST_A, "permit",
                             _SEED, issuer_id=_ISSUER, now=_NOW,
                             kind="permit-revoked")
        rec = po.verify_signal(sig, {_ISSUER: _PUB})
        self.assertEqual(rec["jti"], sig["jti"])
        self.assertEqual(rec["signature"], sig["signature"])

    def test_verify_tampered_sub_fails(self):
        sig = _emit()
        sig["sub"] = _DIGEST_B
        with self.assertRaises(po.SignalUnverifiableError) as ctx:
            po.verify_signal(sig, {_ISSUER: _PUB})
        self.assertEqual(ctx.exception.code, "signal-unverifiable")

    def test_verify_wrong_key_fails(self):
        sig = _emit()
        with self.assertRaises(po.SignalUnverifiableError):
            po.verify_signal(sig, {_ISSUER: _WRONG_PUB})

    def test_verify_unknown_issuer_fails(self):
        sig = _emit()
        with self.assertRaises(po.SignalUnverifiableError):
            po.verify_signal(sig, {"other": _PUB})

    def test_verify_rejects_non_record(self):
        with self.assertRaises(po.SignalUnverifiableError):
            po.verify_signal(["not", "a", "record"], {_ISSUER: _PUB})

    def test_scope_match_and_mismatch(self):
        sig = po.emit_signal("admission-refusal", _DIGEST_A,
                             "admission", _SEED, issuer_id=_ISSUER,
                             now=_NOW,
                             kind="admission-digest-mismatch")
        po.verify_signal(sig, {_ISSUER: _PUB},
                         require_scope="admission")
        with self.assertRaises(po.SignalScopeMismatchError) as ctx:
            po.verify_signal(sig, {_ISSUER: _PUB},
                             require_scope="permit")
        self.assertEqual(ctx.exception.code, "signal-scope-mismatch")


class AuthorityGuardTests(unittest.TestCase):
    def test_spec_named_guard_refuses_signal(self):
        sig = _emit()
        rec = po.verify_signal(sig, {_ISSUER: _PUB})
        with self.assertRaises(po.SignalNotAuthorizationError) as ctx:
            po.signal_carries_no_authority(rec)
        self.assertEqual(ctx.exception.code, "signal-not-authorization")

    def test_alias_behaves_identically(self):
        sig = _emit()
        with self.assertRaises(po.SignalNotAuthorizationError):
            po.require_authorization(sig)

    def test_stripped_fragment_still_refused(self):
        sig = _emit()
        frag = {k: v for k, v in sig.items() if k != "events"}
        with self.assertRaises(po.SignalNotAuthorizationError):
            po.signal_carries_no_authority(frag)

    def test_plain_record_passes_through(self):
        plain = {"permit_id": "p1", "grant": True}
        self.assertIs(po.signal_carries_no_authority(plain), plain)
        self.assertIs(po.signal_carries_no_authority(None), None)

    def test_attestation_statement_passes_through(self):
        # attestation_release statements carry iss/jti/sub/iat but
        # are not posture signals.
        statement = {"format": "sasanam-attestation/v1",
                     "sub": _DIGEST_A, "iss": "attester", "aud": "ops",
                     "status": "affirming", "iat": _IAT,
                     "exp": "2023-11-14T23:13:20Z", "jti": "stmt-1",
                     "agent_scope": "deploy",
                     "session": {"agent_id": "a", "run_id": "r"}}
        self.assertIs(po.signal_carries_no_authority(statement),
                      statement)


class AbsenceCompositionTests(unittest.TestCase):
    def _issuer(self):
        return _ab.AbsenceIssuer("abs-unit", _SEED)

    def test_never_advertised_signal(self):
        sig = po.emit_absence_signal(self._issuer(), _DIGEST_A,
                                     "admission", now=_NOW)
        rec = po.verify_signal(sig, {"abs-unit": _PUB})
        self.assertEqual(list(rec["events"].values())[0]["kind"],
                         "never-advertised")
        self.assertEqual(rec["sub"], _DIGEST_A)

    def test_advertised_but_missing_signal(self):
        issuer = self._issuer()
        issuer.advertise(_DIGEST_B)
        sig = po.emit_absence_signal(issuer, _DIGEST_B, "admission",
                                     now=_NOW)
        rec = po.verify_signal(sig, {"abs-unit": _PUB})
        self.assertEqual(list(rec["events"].values())[0]["kind"],
                         "advertised-but-missing")

    def test_revoked_signal(self):
        issuer = self._issuer()
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_A, issuer_id="rev", seed=_SEED)
        sig = po.emit_absence_signal(issuer, _DIGEST_A, "admission",
                                     revocation=rl, now=_NOW)
        rec = po.verify_signal(sig, {"abs-unit": _PUB})
        self.assertEqual(list(rec["events"].values())[0]["kind"],
                         "revoked")


class AuditTrailTests(unittest.TestCase):
    def test_emit_writes_in_band_audit_entry(self):
        audit = []
        sig = po.emit_absence_signal(_ab.AbsenceIssuer("abs-unit",
                                                       _SEED),
                                     _DIGEST_A, "admission",
                                     audit=audit.append, now=_NOW)
        self.assertEqual(len(audit), 1)
        entry = audit[0]
        self.assertEqual(entry["event"], "posture_signal")
        self.assertEqual(entry["jti"], sig["jti"])
        self.assertEqual(entry["scope"], "admission")
        self.assertEqual(entry["signal_event"], "absence-attribution")
        self.assertEqual(entry["signal_kind"], "never-advertised")
        self.assertEqual(entry["iss"], "abs-unit")

    def test_emit_without_audit_still_works(self):
        sig = _emit()
        po.verify_signal(sig, {_ISSUER: _PUB})  # no error


class RevocationHookTests(unittest.TestCase):
    def test_revoke_emits_configured_signal(self):
        emitted = []
        audit = []
        rl = rv.RevocationList(
            audit=audit.append,
            signal_issuer=("rev-issuer", _SEED, "permit"),
            signal_sink=emitted.append)
        rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=_SEED)
        self.assertEqual(len(emitted), 1)
        rec = po.verify_signal(emitted[0], {"rev-issuer": _PUB},
                               require_scope="permit")
        self.assertEqual(rec["sub"], _DIGEST_A)
        # The signal also rode the list's audit trail.
        posture_entries = [e for e in audit
                           if e.get("event") == "posture_signal"]
        self.assertEqual(len(posture_entries), 1)

    def test_revoke_without_hook_emits_nothing(self):
        emitted = []
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=_SEED)
        self.assertEqual(emitted, [])
        self.assertEqual(rl.check(_DIGEST_A), "revoked")

    def test_hook_with_wrong_key_fails_consumer_verify(self):
        emitted = []
        rl = rv.RevocationList(
            signal_issuer=("rev-issuer", _SEED, "permit"),
            signal_sink=emitted.append)
        rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=_SEED)
        with self.assertRaises(po.SignalUnverifiableError):
            po.verify_signal(emitted[0], {"rev-issuer": _WRONG_PUB})


class DeterminismTests(unittest.TestCase):
    def test_fixed_clock_fixed_seed_is_deterministic(self):
        a = _emit()
        b = _emit()
        self.assertEqual(a["signature"], b["signature"])
        self.assertEqual(a["jti"], b["jti"])


if __name__ == "__main__":
    unittest.main()
