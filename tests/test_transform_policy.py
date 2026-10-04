"""Unit tests for gov/transform_registry.py + gov/transform_policy.py.

Deterministic transform-declassification policy (wave-316 lane 4).

TDD red: this file is written BEFORE the modules exist. Every test must
FAIL (ImportError) until gov/transform_registry.py and
gov/transform_policy.py land, then go green one by one.

Key ceremony: tests use tests.keyfixture (scrub_key_env + provision_test_key
with restore), the same pattern as the sink/vsa lanes.
"""

import hashlib
import json
import marshal
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import tests.keyfixture as kf

from gov import transform_registry as tr
from gov import transform_policy as tp
from gov.provenance_labels import TrustLevel as T

NOW = 1790000000  # fixed "now" for token verification (2026-09-...)

ISSUER = "test-approver"


def _fn_identity(fn):
    code = fn.__code__
    return hashlib.sha256(
        marshal.dumps((code.co_code, code.co_consts, code.co_names))
    ).hexdigest()


# -- reference transforms ----------------------------------------------------

def _sanitizer(text):
    # allowlist sanitizer: keeps a safe subset, drops the rest
    return "".join(c for c in text if c.isalnum() or c in " .,;:!?-")


def _classifier(text):
    return "spam" if "spam" in text.lower() else "ham"


def _model_summarizer(text):
    # a model-mediated transform (simulated): never label-lowering
    return "summary: " + text[:20]


def _passthrough(text):
    return text


def _registry():
    return tr.TransformRegistry()


def _sanitizer_reg(**over):
    kw = dict(
        name="safe-text",
        fn=_sanitizer,
        kind="deterministic",
        output_contract={"capacity": "string", "max_bytes": 512,
                         "shape": r"[A-Za-z0-9 .,;:!?'\-]*"},
        lowers_to=T.TOOL,
        description="allowlist text sanitizer",
    )
    kw.update(over)
    return tr.register_fn(**kw)


def _classifier_reg(**over):
    kw = dict(
        name="spam-classifier",
        fn=_classifier,
        kind="deterministic",
        output_contract={"capacity": "enum", "max_bytes": 16,
                         "enum_values": ["spam", "ham"]},
        lowers_to=T.TOOL,
        description="1-bit spam classifier",
    )
    kw.update(over)
    return tr.register_fn(**kw)


def _model_reg(**over):
    kw = dict(
        name="summarizer",
        fn=_model_summarizer,
        kind="model",
        output_contract={"capacity": "string", "max_bytes": 256},
        description="model summarizer (never lowering)",
    )
    kw.update(over)
    return tr.register_fn(**kw)


class RegistryTest(unittest.TestCase):
    def test_register_ok(self):
        reg = _registry()
        r = _sanitizer_reg()
        reg.register(r)
        self.assertIs(reg.get("safe-text"), r)

    def test_duplicate_refused(self):
        reg = _registry()
        reg.register(_sanitizer_reg())
        with self.assertRaises(tr.TransformError) as cm:
            reg.register(_sanitizer_reg())
        self.assertIn("transform-registration-duplicate", str(cm.exception))

    def test_marking_refused(self):
        reg = _registry()
        with self.assertRaises(tr.TransformError) as cm:
            reg.register(_sanitizer_reg(name="spotlight", marking=True))
        self.assertIn("transform-registration-marking-refused",
                      str(cm.exception))

    def test_denylist_contract_refused(self):
        reg = _registry()
        with self.assertRaises(tr.TransformError) as cm:
            reg.register(_sanitizer_reg(
                name="deny-sanitizer",
                output_contract={"capacity": "string", "max_bytes": 512,
                                 "deny": ["<script"]}))
        self.assertIn("transform-registration-denylist-refused",
                      str(cm.exception))

    def test_model_with_lowers_to_refused(self):
        reg = _registry()
        with self.assertRaises(tr.TransformError) as cm:
            reg.register(_model_reg(lowers_to=T.TOOL))
        self.assertIn("transform-registration-model-lowering-refused",
                      str(cm.exception))

    def test_model_without_lowers_to_ok(self):
        reg = _registry()
        reg.register(_model_reg())
        self.assertIsNotNone(reg.get("summarizer"))


class CertifyTest(unittest.TestCase):
    def setUp(self):
        self._restore = kf.scrub_key_env()
        kf.provision_test_key()

    def tearDown(self):
        self._restore()

    def _policy(self, consume_dir=None):
        reg = _registry()
        reg.register(_sanitizer_reg())
        reg.register(_classifier_reg())
        reg.register(_model_reg())
        return tp.TransformPolicy(reg, consume_dir=consume_dir)

    def test_unregistered_data_plane(self):
        p = self._policy()
        r = p.certify("nope", _passthrough, b"x", [T.UNTRUSTED])
        self.assertEqual(r.verdict, "DATA_PLANE")
        self.assertEqual(r.label, T.UNTRUSTED)
        self.assertEqual(r.code, "transform-unregistered")

    def test_identity_mismatch(self):
        p = self._policy()
        out = _sanitizer("hello").encode()
        r = p.certify("safe-text", _passthrough, out, [T.UNTRUSTED])
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-identity-mismatch")

    def test_model_never_lowers(self):
        p = self._policy()
        out = _model_summarizer("hello world").encode()
        r = p.certify("summarizer", _model_summarizer, out,
                      [T.UNTRUSTED, T.TOOL])
        self.assertEqual(r.verdict, "DATA_PLANE")
        self.assertEqual(r.label, T.UNTRUSTED)

    def test_model_token_structural_refusal(self):
        p = self._policy()
        out = _model_summarizer("hello world").encode()
        tok = p.mint_declassify_token(
            transform="summarizer", output_digest=hashlib.sha256(out).hexdigest(),
            capacity="string", input_min_trust=T.UNTRUSTED,
            issuer=ISSUER, ttl_seconds=300, issued_at=NOW)
        r = p.certify("summarizer", _model_summarizer, out, [T.UNTRUSTED],
                      declassify_token=tok, now=NOW + 10)
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-model-lowering-refused")

    def test_contract_violation_refused(self):
        p = self._policy()
        # '<' is outside the allowlist shape
        r = p.certify("safe-text", _sanitizer, b"<script>alert(1)</script>",
                      [T.UNTRUSTED])
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-contract-violated")
        self.assertIsNone(r.sealed)

    def test_string_lowering_requires_token(self):
        p = self._policy()
        out = _sanitizer("hello world").encode()
        r = p.certify("safe-text", _sanitizer, out, [T.UNTRUSTED])
        self.assertEqual(r.verdict, "DATA_PLANE")
        self.assertEqual(r.label, T.UNTRUSTED)  # output usable, not lowered

    def test_string_lowering_with_token(self):
        p = self._policy()
        out = _sanitizer("hello world").encode()
        digest = hashlib.sha256(out).hexdigest()
        tok = p.mint_declassify_token(
            transform="safe-text", output_digest=digest, capacity="string",
            input_min_trust=T.UNTRUSTED, issuer=ISSUER, ttl_seconds=300,
            issued_at=NOW)
        r = p.certify("safe-text", _sanitizer, out, [T.UNTRUSTED],
                      declassify_token=tok, now=NOW + 10)
        self.assertEqual(r.verdict, "LOWERED")
        self.assertEqual(r.label, T.TOOL)
        self.assertTrue(tp.verify_output(r.sealed))
        self.assertEqual(tp.output_digest_of(r.sealed), digest)

    def test_token_replay_refused(self):
        d = tempfile.mkdtemp(prefix="w316-tp-")
        p = self._policy(consume_dir=d)
        out = _sanitizer("hello").encode()
        tok = p.mint_declassify_token(
            transform="safe-text", output_digest=hashlib.sha256(out).hexdigest(),
            capacity="string", input_min_trust=T.UNTRUSTED,
            issuer=ISSUER, ttl_seconds=300, issued_at=NOW)
        r1 = p.certify("safe-text", _sanitizer, out, [T.UNTRUSTED],
                       declassify_token=tok, now=NOW + 10)
        self.assertEqual(r1.verdict, "LOWERED")
        # second policy instance, same ledger dir: cross-instance replay
        p2 = self._policy(consume_dir=d)
        r2 = p2.certify("safe-text", _sanitizer, out, [T.UNTRUSTED],
                        declassify_token=tok, now=NOW + 20)
        self.assertEqual(r2.verdict, "REFUSE")
        self.assertEqual(r2.code, "transform-token-replayed")

    def test_token_binding_mismatch(self):
        p = self._policy()
        out = _sanitizer("hello").encode()
        tok = p.mint_declassify_token(
            transform="safe-text", output_digest=hashlib.sha256(out).hexdigest(),
            capacity="string", input_min_trust=T.UNTRUSTED,
            issuer=ISSUER, ttl_seconds=300, issued_at=NOW)
        other = _sanitizer("different").encode()
        r = p.certify("safe-text", _sanitizer, other, [T.UNTRUSTED],
                      declassify_token=tok, now=NOW + 10)
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-token-invalid")

    def test_enum_lowers_without_token(self):
        p = self._policy()
        out = _classifier("this is spam indeed").encode()
        r = p.certify("spam-classifier", _classifier, out, [T.UNTRUSTED])
        self.assertEqual(r.verdict, "LOWERED")
        self.assertEqual(r.label, T.TOOL)

    def test_enum_undeclared_value_capacity_exceeded(self):
        # "maybe" is not in the closed enum set: the transform emitted on
        # a wider channel than declared (the FIDES budget violation).
        p = self._policy()
        r = p.certify("spam-classifier", _classifier, b"maybe", [T.UNTRUSTED])
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-capacity-exceeded")

    def test_capacity_exceeded(self):
        p = self._policy()
        # enum transform emitting a free string within max_bytes: wider
        # than the declared 1-bit channel
        r = p.certify("spam-classifier", _classifier,
                      b"unknown-class", [T.UNTRUSTED])
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-capacity-exceeded")

    def test_ledger_corrupt_fail_closed(self):
        d = tempfile.mkdtemp(prefix="w316-tp-")
        p = self._policy(consume_dir=d)
        out = _sanitizer("hello").encode()
        tok = p.mint_declassify_token(
            transform="safe-text", output_digest=hashlib.sha256(out).hexdigest(),
            capacity="string", input_min_trust=T.UNTRUSTED,
            issuer=ISSUER, ttl_seconds=300, issued_at=NOW)
        p.certify("safe-text", _sanitizer, out, [T.UNTRUSTED],
                  declassify_token=tok, now=NOW + 10)
        # tamper the ledger file
        import glob
        files = glob.glob(os.path.join(d, "*.jsonl"))
        self.assertTrue(files)
        with open(files[0], "a") as fh:
            fh.write('{"forged": true}\n')
        p2 = self._policy(consume_dir=d)
        tok2 = p.mint_declassify_token(
            transform="safe-text", output_digest=hashlib.sha256(out).hexdigest(),
            capacity="string", input_min_trust=T.UNTRUSTED,
            issuer=ISSUER, ttl_seconds=300, issued_at=NOW)
        r = p2.certify("safe-text", _sanitizer, out, [T.UNTRUSTED],
                       declassify_token=tok2, now=NOW + 30)
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-ledger-corrupt")

    def test_sealed_output_to_segment(self):
        p = self._policy()
        out = _classifier("ham sandwich").encode()
        r = p.certify("spam-classifier", _classifier, out, [T.UNTRUSTED])
        seg = tp.to_segment(r.sealed)
        self.assertEqual(seg.label.trust_level, T.TOOL)
        self.assertEqual(seg.label.origin, "transform")
        # the sink verifies the seal: must pass
        from gov import provenance_labels as pl
        self.assertTrue(pl.verify_label(seg.label, seg.content))

    def test_output_digest_binding(self):
        p = self._policy()
        out = _sanitizer("abc").encode()
        tok = p.mint_declassify_token(
            transform="safe-text", output_digest=hashlib.sha256(out).hexdigest(),
            capacity="string", input_min_trust=T.UNTRUSTED,
            issuer=ISSUER, ttl_seconds=300, issued_at=NOW)
        r = p.certify("safe-text", _sanitizer, out, [T.UNTRUSTED],
                      declassify_token=tok, now=NOW + 10)
        self.assertTrue(tp.verify_output(r.sealed))
        tampered = tp._replace_output(r.sealed, b"xyz")
        self.assertFalse(tp.verify_output(tampered))


class RobustnessTest(unittest.TestCase):
    def setUp(self):
        self._restore = kf.scrub_key_env()
        kf.provision_test_key()

    def tearDown(self):
        self._restore()

    def test_robustness_acceptance(self):
        reg = _registry()
        reg.register(_classifier_reg())
        p = tp.TransformPolicy(reg)
        benign = ["hello friend", "meeting at noon", "project update",
                  "buy cheap spam now"]
        attacker = ["SPAM spam SPAM", "s.p.a.m offer", "SPAM!!! click"]
        rep = p.robustness_check("spam-classifier", _classifier,
                                 benign, attacker)
        self.assertTrue(rep["passed"])
        # the attacker releases no more than the declared channel budget
        self.assertLessEqual(rep["attacker_bits"], rep["budget_bits"] + 1e-9)
        # ... and no more than the benign (passive) set
        self.assertLessEqual(rep["attacker_bits"], rep["benign_bits"] + 1e-9)

    def test_robustness_attacker_exceeds_benign(self):
        reg = _registry()
        reg.register(_classifier_reg())
        p = tp.TransformPolicy(reg)
        # degenerate benign set: the attacker demonstrably learns more
        with self.assertRaises(tp.TransformError):
            p.robustness_check("spam-classifier", _classifier,
                               ["hello friend"],
                               ["SPAM spam SPAM", "s.p.a.m offer"])

    def test_robustness_string_requires_markers(self):
        reg = _registry()
        reg.register(_sanitizer_reg())
        p = tp.TransformPolicy(reg)
        with self.assertRaises(tp.TransformError):
            p.robustness_check("safe-text", _sanitizer,
                               ["hello"], ["<b>hi</b>"])

    def test_robustness_violation_detected(self):
        reg = _registry()
        reg.register(_sanitizer_reg(name="leaky", fn=_passthrough,
                                    output_contract={
                                        "capacity": "string",
                                        "max_bytes": 512,
                                        "shape": r"[\s\S]*"},
                                    lowers_to=T.TOOL))
        p = tp.TransformPolicy(reg)
        with self.assertRaises(tp.TransformError):
            p.robustness_check("leaky", _passthrough,
                               ["hello"], ["<script>steal()</script>"],
                               forbidden_markers=["<script>", "steal()"])


class ReviewFixTest(unittest.TestCase):
    """Regression tests for the wave-316 two-axis review findings."""

    def setUp(self):
        self._restore = kf.scrub_key_env()
        kf.provision_test_key()

    def tearDown(self):
        self._restore()

    def _registration(self, **over):
        kw = dict(name="t", fn=_sanitizer, kind="deterministic",
                  output_contract={"capacity": "string", "max_bytes": 64},
                  description="t")
        kw.update(over)
        r = tr.TransformRegistration(
            name=kw["name"], kind=kw["kind"],
            module=_sanitizer.__module__,
            qualname=_sanitizer.__qualname__,
            code_digest=tr.fn_identity(_sanitizer)[2],
            marking=kw.get("marking", False),
            input_contract=kw.get("input_contract"),
            output_contract=kw["output_contract"],
            lowers_to=kw.get("lowers_to"),
            description=kw["description"])
        return r

    def test_register_enforces_marking(self):
        # M1: hand-built registration cannot bypass register_fn
        reg = _registry()
        with self.assertRaises(tr.TransformError) as cm:
            reg.register(self._registration(marking=True))
        self.assertIn("transform-registration-marking-refused",
                      str(cm.exception))

    def test_register_enforces_model_lowering(self):
        reg = _registry()
        with self.assertRaises(tr.TransformError) as cm:
            reg.register(self._registration(kind="model", lowers_to=T.TOOL))
        self.assertIn("transform-registration-model-lowering-refused",
                      str(cm.exception))

    def test_register_enforces_denylist(self):
        reg = _registry()
        with self.assertRaises(tr.TransformError) as cm:
            reg.register(self._registration(
                output_contract={"capacity": "string", "max_bytes": 64,
                                 "deny": ["<script"]}))
        self.assertIn("transform-registration-denylist-refused",
                      str(cm.exception))

    def test_register_rejects_bad_shape_regex(self):
        # m10: invalid regex fails at registration, not at every certify
        with self.assertRaises(tr.TransformError):
            tr.register_fn("bad-shape", _sanitizer, kind="deterministic",
                           output_contract={"capacity": "string",
                                            "max_bytes": 64,
                                            "shape": r"[unclosed"})

    def test_enum_bool_spelled_members(self):
        # M2: enum members spelling bool/int/float still certify
        def _yn(text):
            return "true" if text else "false"

        reg = _registry()
        reg.register(tr.register_fn(
            "yn", _yn, kind="deterministic",
            output_contract={"capacity": "enum", "max_bytes": 8,
                             "enum_values": ["true", "false"]},
            lowers_to=T.TOOL, description="bool-spelled enum"))
        p = tp.TransformPolicy(reg)
        r = p.certify("yn", _yn, b"true", [T.UNTRUSTED])
        self.assertEqual(r.verdict, "LOWERED")
        self.assertEqual(r.label, T.TOOL)

    def test_declared_string_narrow_output_still_gated(self):
        # M3: the token decision follows the DECLARED capacity
        p = tp.TransformPolicy(_registry_with_sanitizer())
        r = p.certify("safe-text", _sanitizer, b"true", [T.UNTRUSTED])
        self.assertEqual(r.verdict, "DATA_PLANE")
        self.assertEqual(r.label, T.UNTRUSTED)

    def test_certify_bad_input_trusts(self):
        # M4: adversarial input_trusts -> coded REFUSE, not ValueError
        p = tp.TransformPolicy(_registry_with_sanitizer())
        r = p.certify("safe-text", _sanitizer, b"hello", ["not-a-trust"])
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-contract-violated")

    def test_model_max_bytes_enforced(self):
        # m2: model outputs respect max_bytes too
        reg = _registry()
        reg.register(_model_reg())
        p = tp.TransformPolicy(reg)
        r = p.certify("summarizer", _model_summarizer, b"x" * 300,
                      [T.UNTRUSTED])
        self.assertEqual(r.verdict, "REFUSE")
        self.assertEqual(r.code, "transform-contract-violated")

    def test_concurrent_consume_single_spend(self):
        # B1: 20 threads racing one nonce -> exactly one True
        import threading
        d = tempfile.mkdtemp(prefix="w316-tp-")
        store = tp.FileConsumeStore(d)
        nonce = "ab" * 16
        results = []
        lock = threading.Lock()

        def worker():
            try:
                store.consume(nonce, now=NOW)
                ok = True
            except tp.TransformError:
                ok = False
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(results), 1)
        # and the ledger still verifies on reload
        store2 = tp.FileConsumeStore(d)
        self.assertTrue(store2.is_consumed(nonce))


def _registry_with_sanitizer():
    reg = tr.TransformRegistry()
    reg.register(_sanitizer_reg())
    return reg


if __name__ == "__main__":
    unittest.main()
