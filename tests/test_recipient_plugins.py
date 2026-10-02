"""Unit tests for gov/recipient_plugins.py (wave-263 lane 1).

Contracts pinned here:
* registry: namespace shape enforcement, conflict refusal
  (exact / prefix-overlap / duplicate name / malformed), routing
  (longest-prefix, legacy fallback for bare labels, unknown-label
  refusal with machine code).
* symmetric plugin: seal/open round-trip through the vault, cross-
  compat with gov.encrypted_envelopes.KeyWrap, legacy byte-compat
  (bare-id seals open identically).
* quorum plugin: Shamir k-of-n -- known-answer split/combine, k
  shares open, k-1 refused, wrong share refused, duplicate-x
  refused at seal, share-label namespace consistency.
* framework: malformed wrap size / inconsistent labels refused at
  seal with machine codes; plugin unwrap errors convert to
  envelope-open-refused at open (never partial plaintext).
* subprocess seam: stub refuses loudly, documents the stanza
  protocol.
* taxonomy pin 1151 (in-lane: 1129 + 7 recipient-plugin-* codes = 1136;
  wave-263 merge: +8 mesh-auth, +7 provenance = 1151).
"""

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes  # noqa: E402
from gov import encrypted_envelopes as ee  # noqa: E402
from gov import recipient_plugins as rp  # noqa: E402


def _km(seed):
    return hashlib.sha256(b"w263-test-%s" % seed.encode()).digest()


def _vault(**kw):
    d = tempfile.mkdtemp(prefix="test-rp-")
    return ee.EnvelopeVault(os.path.join(d, "j.jsonl"), **kw)


class RegistryTest(unittest.TestCase):
    def test_default_registry_namespaces(self):
        reg = rp.default_registry()
        self.assertIn("gov1sym", reg.namespaces())
        self.assertIn("gov1quorum", reg.namespaces())

    def test_namespace_shape_refused(self):
        reg = rp.default_registry()

        class Bad(rp.RecipientPlugin):
            NAME = "bad/v1"
            LABEL_NAMESPACE = "nope"

        with self.assertRaises(rp.RecipientPluginError) as cm:
            reg.register(Bad())
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-namespace-conflict")

    def test_exact_claim_refused(self):
        reg = rp.default_registry()

        class Rogue(rp.SymmetricPlugin):
            NAME = "rogue/v1"
            LABEL_NAMESPACE = "gov1sym"

        with self.assertRaises(rp.RecipientPluginError) as cm:
            reg.register(Rogue())
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-namespace-conflict")

    def test_prefix_overlap_both_directions_refused(self):
        reg = rp.default_registry()

        class Longer(rp.SymmetricPlugin):
            NAME = "longer/v1"
            LABEL_NAMESPACE = "gov1symx"

        with self.assertRaises(rp.RecipientPluginError) as cm:
            reg.register(Longer())
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-namespace-conflict")

        reg2 = rp.PluginRegistry()
        reg2.register(Longer())

        class Shorter(rp.SymmetricPlugin):
            NAME = "shorter/v1"
            LABEL_NAMESPACE = "gov1sym"

        # 'gov1sym' is a prefix of registered 'gov1symx' -> conflict.
        with self.assertRaises(rp.RecipientPluginError) as cm:
            reg2.register(Shorter())
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-namespace-conflict")

    def test_duplicate_name_refused(self):
        reg = rp.default_registry()

        class Dup(rp.SymmetricPlugin):
            NAME = "symmetric-hmac/v1"
            LABEL_NAMESPACE = "gov1other"

        with self.assertRaises(rp.RecipientPluginError) as cm:
            reg.register(Dup())
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-namespace-conflict")

    def test_route_longest_prefix(self):
        reg = rp.PluginRegistry()

        class A(rp.SymmetricPlugin):
            NAME = "a/v1"
            LABEL_NAMESPACE = "gov1aa"

        class B(rp.SymmetricPlugin):
            NAME = "b/v1"
            LABEL_NAMESPACE = "gov1bb"

        reg.register(A())
        reg.register(B())
        self.assertIs(reg.route("gov1aa1x"), reg.get("a/v1"))
        self.assertIs(reg.route("gov1bb1y"), reg.get("b/v1"))

    def test_route_legacy_fallback(self):
        reg = rp.default_registry()
        sym = reg.get("symmetric-hmac/v1")
        self.assertIs(reg.route("alice"), sym)
        self.assertIs(reg.route("r0"), sym)

    def test_route_unknown_label_refused(self):
        reg = rp.default_registry()
        with self.assertRaises(rp.RecipientPluginError) as cm:
            reg.route("gov1nosuch1x")
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-unknown-label")

    def test_route_bare_without_legacy_refused(self):
        reg = rp.PluginRegistry()  # no legacy plugin
        with self.assertRaises(rp.RecipientPluginError) as cm:
            reg.route("alice")
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-unknown-label")

    def test_taxonomy_codes_mapped(self):
        for c in ("recipient-plugin-unknown-label",
                  "recipient-plugin-namespace-conflict",
                  "recipient-plugin-wrap-refused",
                  "recipient-plugin-unwrap-refused",
                  "recipient-plugin-malformed-wrap",
                  "recipient-plugin-label-inconsistent",
                  "recipient-plugin-identity-refused"):
            self.assertEqual(decision_codes.code_for(c)["code"], c)

    def test_taxonomy_pin(self):
        # Wave-263 lane 1: pin -> 1136 (1129 + 7 recipient-plugin-*).
        self.assertEqual(len(decision_codes.TAXONOMY), 1726)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 lane 2: pin 1723 -> 1726 (+3 toolcall-*: sequence-violated, secret-in-args, rule-compile-invalid)


class SymmetricPluginTest(unittest.TestCase):
    def test_roundtrip_plugin_api(self):
        v = _vault()
        env = v.seal_plugin(b"hello", [rp.PluginRecipient(
            "gov1sym1alice", "symmetric-hmac/v1",
            {"key_material": _km("a")})])
        out, meta = v.open_plugin(
            env, {"gov1sym1alice": {"key_material": _km("a")}})
        self.assertEqual(out, b"hello")
        self.assertEqual(meta["recipient_id"], "gov1sym1alice")

    def test_wrong_key_refused(self):
        v = _vault()
        env = v.seal_plugin(b"hello", [rp.PluginRecipient(
            "gov1sym1alice", "symmetric-hmac/v1",
            {"key_material": _km("a")})])
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.open_plugin(env, {"gov1sym1alice":
                                {"key_material": _km("wrong")}})
        self.assertEqual(cm.exception.code, "envelope-open-refused")

    def test_cross_compat_with_keywrap(self):
        # The plugin's default KEM unwraps what KeyWrap wrapped and
        # vice versa: same algorithm, same KDF info strings.
        kem = ee.KeyWrap()
        label = b"gov1sym1alice"
        wrap = kem.wrap(b"\x11" * 32, label, _km("a"))
        plug = rp.SymmetricPlugin()
        got = plug.unwrap([(label.decode(), wrap)],
                          {"gov1sym1alice": {"key_material": _km("a")}})
        self.assertEqual(got, [("gov1sym1alice", b"\x11" * 32)])
        wrap2 = plug.wrap(b"\x22" * 32, label.decode(),
                          {"key_material": _km("a")})[0][1]
        self.assertEqual(kem.unwrap(wrap2, label, _km("a")),
                         b"\x22" * 32)

    def test_legacy_seal_byte_compat(self):
        # A bare-id seal through the plugin-routed core parses exactly
        # like a legacy seal and opens with the legacy open().
        v = _vault()
        env = v.seal(b"data", [ee.Recipient("r0", _km("a"))])
        parsed = ee._parse(env)
        self.assertEqual(len(parsed.recipients), 1)
        self.assertEqual(parsed.recipients[0][0], b"r0")
        out, _meta = v.open(env, _km("a"))
        self.assertEqual(out, b"data")

    def test_short_key_material_refused_at_seal(self):
        v = _vault()
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.seal_plugin(b"hello", [rp.PluginRecipient(
                "gov1sym1alice", "symmetric-hmac/v1",
                {"key_material": b"short"})])
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-identity-refused")

    def test_missing_identity_refused_at_open(self):
        v = _vault()
        env = v.seal_plugin(b"hello", [rp.PluginRecipient(
            "gov1sym1alice", "symmetric-hmac/v1",
            {"key_material": _km("a")})])
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.open_plugin(env, {})
        self.assertEqual(cm.exception.code, "envelope-open-refused")


class QuorumPluginTest(unittest.TestCase):
    def _seal(self, shares, quorum):
        v = _vault()
        env = v.seal_plugin(b"quorum-payload", [rp.PluginRecipient(
            "quorum-group", "quorum-shamir/v1",
            {"shares": shares, "quorum": quorum})])
        parsed = ee._parse(env)
        labels = [rid.decode("utf-8") for rid, _w in parsed.recipients]
        return v, env, labels

    def test_shamir_known_answer(self):
        # Deterministic RNG: split must be invertible by combine.
        counter = [0]

        def fake_rand(n):
            counter[0] += 1
            return bytes((counter[0] + i) % 256 for i in range(n))

        secret = bytes(range(32))
        shares = rp._shamir_split(secret, 2, [1, 2, 3], fake_rand)
        self.assertEqual(len(shares), 3)
        xs = sorted(x for x, _y in shares)
        self.assertEqual(len(set(xs)), 3)
        for combo in (shares[:2], shares[1:], [shares[0], shares[2]]):
            self.assertEqual(rp._shamir_combine(combo), secret)

    def test_k_of_n_roundtrip(self):
        shares = {"s%d" % i: _km("q%d" % i) for i in range(3)}
        v, env, labels = self._seal(shares, 2)
        self.assertEqual(len(labels), 3)
        self.assertEqual(len(set(labels)), 3)
        for l in labels:
            self.assertTrue(l.startswith("gov1quorum1"), l)
        idents = {l: {"shares": {"s0": shares["s0"],
                                 "s1": shares["s1"]}} for l in labels}
        out, _meta = v.open_plugin(env, idents)
        self.assertEqual(out, b"quorum-payload")

    def test_k_minus_1_refused(self):
        shares = {"s%d" % i: _km("q%d" % i) for i in range(3)}
        v, env, labels = self._seal(shares, 2)
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.open_plugin(env, {labels[0]: {"shares":
                                            {"s0": shares["s0"]}}})
        self.assertEqual(cm.exception.code, "envelope-open-refused")

    def test_wrong_share_refused(self):
        shares = {"s%d" % i: _km("q%d" % i) for i in range(3)}
        v, env, labels = self._seal(shares, 3)
        bad = {"s0": shares["s0"], "s1": shares["s1"],
               "s2": _km("wrong")}
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.open_plugin(env, {l: {"shares": bad} for l in labels})
        self.assertEqual(cm.exception.code, "envelope-open-refused")

    def test_3_of_3_opens(self):
        shares = {"s%d" % i: _km("q%d" % i) for i in range(3)}
        v, env, labels = self._seal(shares, 3)
        out, _meta = v.open_plugin(
            env, {l: {"shares": shares} for l in labels})
        self.assertEqual(out, b"quorum-payload")

    def test_bad_quorum_refused_at_seal(self):
        shares = {"s0": _km("q0"), "s1": _km("q1")}
        v = _vault()
        for quorum in (1, 3, 0):
            with self.assertRaises(ee.EnvelopeRefusal) as cm:
                v.seal_plugin(b"x", [rp.PluginRecipient(
                    "quorum-group", "quorum-shamir/v1",
                    {"shares": shares, "quorum": quorum})])
            self.assertEqual(cm.exception.code,
                             "recipient-plugin-identity-refused")

    def test_duplicate_share_id_x_refused(self):
        # Two share ids hashing to the same Shamir x would let one
        # share count twice: refused at seal.
        real = rp._share_x

        def colliding(share_id):
            return 7
        rp._share_x = colliding
        try:
            v = _vault()
            shares = {"s0": _km("q0"), "s1": _km("q1")}
            with self.assertRaises(ee.EnvelopeRefusal) as cm:
                v.seal_plugin(b"x", [rp.PluginRecipient(
                    "quorum-group", "quorum-shamir/v1",
                    {"shares": shares, "quorum": 2})])
            self.assertEqual(cm.exception.code,
                             "recipient-plugin-identity-refused")
        finally:
            rp._share_x = real

    def test_quorum_counts_shares_not_humans_documented(self):
        # Honest residual pin: nothing stops a deployment issuing the
        # same key material under two share ids.
        self.assertIn("not distinct humans",
                      rp.QuorumPlugin.__doc__)


class FrameworkTest(unittest.TestCase):
    def test_malformed_wrap_refused(self):
        reg = rp.default_registry()

        class BadSize(rp.RecipientPlugin):
            NAME = "badsize/v1"
            LABEL_NAMESPACE = "gov1badsize"

            def wrap(self, envelope_key, label, identity):
                return [(label, b"\x00" * 47)]

            def unwrap(self, entries, identity):
                return [(label, b"\x00" * 32) for label, _w in entries]

        reg.register(BadSize())
        v = _vault(plugins=reg)
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.seal_plugin(b"x", [rp.PluginRecipient(
                "gov1badsize1x", "badsize/v1", {})])
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-malformed-wrap")

    def test_inconsistent_labels_refused(self):
        reg = rp.default_registry()

        class Incon(rp.RecipientPlugin):
            NAME = "incon/v1"
            LABEL_NAMESPACE = "gov1incon"

            def wrap(self, envelope_key, label, identity):
                return [(label, b"\x00" * 48),
                        ("gov1sym1hijack", b"\x00" * 48)]

            def unwrap(self, entries, identity):
                return [(label, b"\x00" * 32) for label, _w in entries]

        reg.register(Incon())
        v = _vault(plugins=reg)
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.seal_plugin(b"x", [rp.PluginRecipient(
                "gov1incon1x", "incon/v1", {})])
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-label-inconsistent")

    def test_unwrap_error_never_partial_plaintext(self):
        reg = rp.default_registry()

        class Boom(rp.RecipientPlugin):
            NAME = "boom/v1"
            LABEL_NAMESPACE = "gov1boom"

            def wrap(self, envelope_key, label, identity):
                return [(label, b"\x00" * 48)]

            def unwrap(self, entries, identity):
                raise rp.RecipientPluginError(
                    "recipient-plugin-unwrap-refused", "boom")

        reg.register(Boom())
        d = tempfile.mkdtemp(prefix="test-rp-")
        journal = os.path.join(d, "j.jsonl")
        v = ee.EnvelopeVault(journal, plugins=reg)
        env = v.seal_plugin(b"secret-payload", [rp.PluginRecipient(
            "gov1boom1x", "boom/v1", {})])
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.open_plugin(env, {"gov1boom1x": {}})
        self.assertEqual(cm.exception.code, "envelope-open-refused")
        with open(journal, "rb") as f:
            self.assertNotIn(b"secret-payload", f.read())

    def test_unknown_plugin_name_at_seal(self):
        v = _vault()
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.seal_plugin(b"x", [rp.PluginRecipient(
                "gov1nosuch1x", "nosuch/v1", {})])
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-unknown-label")

    def test_duplicate_labels_refused(self):
        v = _vault()
        recips = [rp.PluginRecipient("gov1sym1a", "symmetric-hmac/v1",
                                     {"key_material": _km("a")}),
                  rp.PluginRecipient("gov1sym1a", "symmetric-hmac/v1",
                                     {"key_material": _km("b")})]
        with self.assertRaises(ee.EnvelopeRefusal) as cm:
            v.seal_plugin(b"x", recips)
        self.assertEqual(cm.exception.code, "envelope-seal-refused")


class SubprocessSeamTest(unittest.TestCase):
    def test_stub_refuses_loudly(self):
        stub = rp.SubprocessPlugin(
            binary="/usr/bin/age-plugin-example",
            label_namespace="gov1example")
        with self.assertRaises(rp.RecipientPluginError) as cm:
            stub.wrap(b"\x00" * 32, "gov1example1x", {})
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-wrap-refused")
        with self.assertRaises(rp.RecipientPluginError) as cm:
            stub.unwrap([], {})
        self.assertEqual(cm.exception.code,
                         "recipient-plugin-unwrap-refused")

    def test_stanza_protocol_documented(self):
        self.assertIn("recipient-v1", rp.SUBPROCESS_PROTOCOL)
        self.assertIn("identity-v1", rp.SUBPROCESS_PROTOCOL)
        self.assertIn("wrap-file-key", rp.SUBPROCESS_PROTOCOL)


if __name__ == "__main__":
    unittest.main()
