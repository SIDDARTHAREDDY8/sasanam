"""Unit tests for the wave-214 signed agent-card ADAPT.

Covers gov.agent_cards (emit/verify: shape, a2a_version pin, lifetime,
owner binding, trust-store validation) and gov.card_inventory (opt-in,
tighten-only admission). Deterministic; stdlib + repo ed25519 only.
"""

import unittest

from gov import agent_cards as ac
from gov import card_inventory as ci
from gov import ed25519 as ed

NOW = 1_800_000_000.0
VSEED = b"V" * 32
ASEED = b"A" * 32
VPUB = ed.publickey(VSEED)
APUB = ed.publickey(ASEED)
JKU = "https://agents.example.com/.well-known/jwks.json"


def fields(**over):
    f = {
        "agent_id": "agent-acme-001",
        "name": "acme-agent",
        "version": "2.3.1",
        "capabilities": ["answer"],
        "endpoints": {"jsonrpc": "https://agents.example.com/acme"},
        "keys": [{"kid": "k1", "alg": "EdDSA"}],
    }
    f.update(over)
    return f


def store(owner=None):
    kw = {"pubkey": VPUB, "alg": "EdDSA", "jku": JKU,
          "fetched_at": NOW - 100}
    if owner is not None:
        kw["owner"] = owner
    return ac.CardTrustStore(keys={"k1": kw}, jku_allowlist=[JKU])


def signed(**over):
    return ac.emit_card(fields(**over), "k1", VSEED, jku=JKU, now=NOW)


class VersionPinTests(unittest.TestCase):
    def test_only_1_0_accepted(self):
        self.assertEqual(ac.A2A_SPEC_VERSION, "1.0")
        for bad in ("0.2", "0.3", "1.0.0", "1.1", "", None):
            raw = dict(fields())
            raw["a2a_version"] = bad
            raw["issued_at"] = NOW - 1
            raw["expires"] = NOW + 60
            raw["signatures"] = [ac.sign_card(raw, "k1", VSEED)]
            with self.assertRaises(ac.CardVerificationError) as cm:
                ac.verify_card(raw, store(), now=NOW)
            self.assertEqual(cm.exception.code, "card-version")
    def test_roundtrip_verifies(self):
        card = signed()
        out = ac.verify_card(card, store(), now=NOW)
        self.assertEqual(out["identity"], "acme-agent")
        self.assertEqual(out["kids"], ["k1"])

    def test_stamps_version_and_lifetime(self):
        card = signed()
        self.assertEqual(card["a2a_version"], "1.0")
        self.assertEqual(card["issued_at"], NOW)
        self.assertEqual(card["expires"], NOW + 86400)

    def test_deterministic(self):
        import json
        a = json.dumps(signed(), sort_keys=True)
        b = json.dumps(signed(), sort_keys=True)
        self.assertEqual(a, b)

    def test_emit_failfast_bad_shape(self):
        with self.assertRaises(ac.CardVerificationError) as cm:
            ac.emit_card(fields(agent_id=""), "k1", VSEED, now=NOW)
        self.assertEqual(cm.exception.code, "malformed-card")

    def test_emit_caller_supplied_lifetime_preserved(self):
        card = ac.emit_card(fields(), "k1", VSEED, now=NOW,
                            expires_in_s=60)
        self.assertEqual(card["expires"], NOW + 60)


class VersionPinTests(unittest.TestCase):
    def test_only_1_0_accepted(self):
        self.assertEqual(ac.A2A_SPEC_VERSION, "1.0")
        for bad in ("0.2", "0.3", "1.0.0", "1.1", "", None):
            raw = dict(fields())
            raw["a2a_version"] = bad
            raw["issued_at"] = NOW - 1
            raw["expires"] = NOW + 60
            raw["signatures"] = [ac.sign_card(raw, "k1", VSEED)]
            with self.assertRaises(ac.CardVerificationError) as cm:
                ac.verify_card(raw, store(), now=NOW)
            self.assertEqual(cm.exception.code, "card-version")


class LifetimeTests(unittest.TestCase):
    def _raw(self, **over):
        raw = dict(fields())
        raw["a2a_version"] = "1.0"
        raw["issued_at"] = NOW - 60
        raw["expires"] = NOW + 60
        raw.update(over)
        raw["signatures"] = [ac.sign_card(raw, "k1", VSEED)]
        return raw

    def test_expired_refused(self):
        with self.assertRaises(ac.CardVerificationError) as cm:
            ac.verify_card(self._raw(expires=NOW - 1), store(), now=NOW)
        self.assertEqual(cm.exception.code, "expired-card")

    def test_not_yet_valid_refused(self):
        with self.assertRaises(ac.CardVerificationError) as cm:
            ac.verify_card(self._raw(issued_at=NOW + 60, expires=NOW + 120),
                           store(), now=NOW)
        self.assertEqual(cm.exception.code, "not-yet-valid")

    def test_missing_expires_refused(self):
        raw = self._raw()
        del raw["expires"]
        with self.assertRaises(ac.CardVerificationError) as cm:
            ac.verify_card(raw, store(), now=NOW)
        self.assertEqual(cm.exception.code, "malformed-card")


class OwnerBindingTests(unittest.TestCase):
    def test_kid_swap_refused_when_owner_pinned(self):
        st = ac.CardTrustStore(
            keys={"k1": {"pubkey": VPUB, "alg": "EdDSA", "jku": JKU,
                         "fetched_at": NOW - 100, "owner": "agent-acme-001"},
                  "k9": {"pubkey": APUB, "alg": "EdDSA", "jku": JKU,
                         "fetched_at": NOW - 100, "owner": "agent-evil-009"}},
            jku_allowlist=[JKU])
        card = ac.emit_card(fields(keys=[{"kid": "k9", "alg": "EdDSA"}]),
                            "k9", ASEED, jku=JKU, now=NOW)
        with self.assertRaises(ac.CardVerificationError) as cm:
            ac.verify_card(card, st, now=NOW)
        self.assertEqual(cm.exception.code, "identity-mismatch")

    def test_no_owner_no_check(self):
        # Backward compatible: trust records without owner skip binding.
        card = signed()
        out = ac.verify_card(card, store(), now=NOW)
        self.assertEqual(out["kids"], ["k1"])

    def test_owner_match_passes(self):
        card = signed()
        out = ac.verify_card(card, store(owner="agent-acme-001"), now=NOW)
        self.assertEqual(out["kids"], ["k1"])

    def test_register_key_owner_validation(self):
        st = ac.CardTrustStore()
        with self.assertRaises(ValueError):
            st.register_key("k", VPUB, owner="")
        with self.assertRaises(ValueError):
            st.register_key("k", VPUB, owner=123)


class InventoryTests(unittest.TestCase):
    def test_legacy_admits_unsigned(self):
        inv = ci.CardInventory()
        self.assertFalse(inv.keyset_pinned)
        rec = inv.admit_card({"agent_id": "a1", "name": "n1"}, now=NOW)
        self.assertEqual(rec["mode"], "legacy-unsigned")
        self.assertEqual(inv.lookup("a1")["agent_id"], "a1")

    def test_pinned_refuses_unsigned(self):
        inv = ci.CardInventory(store=store())
        with self.assertRaises(ac.CardVerificationError):
            inv.admit_card({"agent_id": "a1", "name": "n1"}, now=NOW)

    def test_pinned_admits_signed(self):
        inv = ci.CardInventory(store=store())
        rec = inv.admit_card(signed(), now=NOW)
        self.assertEqual(rec["mode"], "signed")
        self.assertEqual(rec["kids"], ["k1"])
        self.assertEqual(inv.list_agents(), ["agent-acme-001"])

    def test_pinned_refuses_forged(self):
        inv = ci.CardInventory(store=store(owner="agent-acme-001"))
        forged = ac.emit_card(fields(), "k1", ASEED, jku=JKU, now=NOW)
        with self.assertRaises(ac.CardVerificationError) as cm:
            inv.admit_card(forged, now=NOW)
        self.assertEqual(cm.exception.code, "invalid-signature")

    def test_describe_leaks_no_key_material(self):
        import json
        inv = ci.CardInventory(store=store())
        inv.admit_card(signed(), now=NOW)
        blob = json.dumps(inv.describe())
        self.assertNotIn(VPUB.hex(), blob)
        self.assertIn("k1", blob)


if __name__ == "__main__":
    unittest.main()
