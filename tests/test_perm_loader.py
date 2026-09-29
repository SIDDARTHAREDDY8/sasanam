"""Unit tests for the PERM model-as-data loader (wave-200).

Covers: strict compile refusals (unknown effect, subjectPriority,
top-level not, unknown matcher (D3), invalid regex, regex column
smuggling, eft-typed request columns, unknown columns, bad
composition, bad policy eft (D1), unsigned/tampered packs), the 9
canonical scenarios, glob wildcard direction pins, regex
mechanics, malformed-request fail-closed, the two-human mint
enforcement, the PERM trust-domain binding on activated packs, and
the Decision BOM perm section.

The canonical model/policy/scenarios below are duplicated from
~/workspace/teams/wave200-capperm/perm_fixtures.py (kept hermetic
per that file's plan); tests mint signed packs dynamically with
test keysets -- no fake production signatures are shipped.

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import decision_bom as db  # noqa: E402
from gov import pack_loader as pload  # noqa: E402
from gov import perm_loader as pl  # noqa: E402
from gov import rule_pack as rp  # noqa: E402
from gov.keyset import (  # noqa: E402
    new_keyset,
    rotate_keyset,
    keyset_signer_for_version,
)
from gov.signing import Ed25519Signer  # noqa: E402

_SEED1 = bytes.fromhex("41" * 32)
_SEED2 = bytes.fromhex("42" * 32)

ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"

PERM_MODEL_YML = """\
perm_model: sasanam-perm/v1
model_version: 1
description: "Wave-200 canonical PERM model: tool-call governance with deny/approval/allow screens."
request_schema:
  agent_id: str
  tool_name: str
  egress_class: str
  velocity_1m: int
  approval_state: str
policy_schema:
  agent_pat: str
  tool_pat: str
  vel_limit: int
  eft: eft
matchers:
  toolMatch: glob
screens:
  -
    name: deny
    description: "Forbid-overrides: a forbidden tool, or velocity above the line limit, denies."
    effect: "!some(where (p_eft == deny))"
    matcher:
      and:
        -
          or:
            -
              eq:
                -
                  pol: agent_pat
                - "*"
            -
              eq:
                -
                  req: agent_id
                -
                  pol: agent_pat
        -
          or:
            -
              call:
                - toolMatch
                -
                  req: tool_name
                -
                  pol: tool_pat
            -
              gt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit
  -
    name: approval
    description: "Classified tool without a granted approval needs a human."
    effect: "some(where (p_eft == allow))"
    matcher:
      and:
        -
          or:
            -
              eq:
                -
                  pol: agent_pat
                - "*"
            -
              eq:
                -
                  req: agent_id
                -
                  pol: agent_pat
        -
          call:
            - toolMatch
            -
              req: tool_name
            -
              pol: tool_pat
        -
          neq:
            -
              req: approval_state
            - granted
        -
          lte:
            -
              req: velocity_1m
            -
              pol: vel_limit
  -
    name: allow
    description: "Ordinary tools, or classified tools with a granted approval."
    effect: "some(where (p_eft == allow))"
    matcher:
      and:
        -
          or:
            -
              eq:
                -
                  pol: agent_pat
                - "*"
            -
              eq:
                -
                  req: agent_id
                -
                  pol: agent_pat
        -
          call:
            - toolMatch
            -
              req: tool_name
            -
              pol: tool_pat
        -
          lte:
            -
              req: velocity_1m
            -
              pol: vel_limit
        -
          or:
            -
              neq:
                -
                  req: egress_class
                - classified
            -
              eq:
                -
                  req: approval_state
                - granted
composition:
  default_verdict: deny
  order:
    -
      screen: deny
      verdict: deny
      invert: true
    -
      screen: approval
      verdict: require_approval
    -
      screen: allow
      verdict: allow
"""

PERM_POLICY_YML = """\
perm_policy: sasanam-perm/v1
description: "Wave-200 canonical PERM policy rows for the 9 spike scenarios."
policies:
  deny:
    -
      agent_pat: "*"
      tool_pat: install_package
      vel_limit: 999999999
      eft: deny
    -
      agent_pat: "*"
      tool_pat: __no_tool__
      vel_limit: 10
      eft: deny
  approval:
    -
      agent_pat: "*"
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: db_write_production
      vel_limit: 999999999
      eft: allow
  allow:
    -
      agent_pat: "*"
      tool_pat: read_file
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: list_dir
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
    -
      agent_pat: "*"
      tool_pat: db_write_production
      vel_limit: 999999999
      eft: allow
"""

# The spike's 9 scenarios, re-expressed against the request schema.
# Each: (name, request, expected_verdict).
PERM_SCENARIOS = [
    ("ordinary tool",
     {"agent_id": "agent-a", "tool_name": "read_file",
      "egress_class": "none", "velocity_1m": 3,
      "approval_state": "none"},
     "allow"),
    ("forbidden tool",
     {"agent_id": "agent-a", "tool_name": "install_package",
      "egress_class": "none", "velocity_1m": 1,
      "approval_state": "none"},
     "deny"),
    ("forbidden tool even with approval granted",
     {"agent_id": "agent-a", "tool_name": "install_package",
      "egress_class": "none", "velocity_1m": 1,
      "approval_state": "granted"},
     "deny"),
    ("classified egress, no approval",
     {"agent_id": "agent-a", "tool_name": "send_email",
      "egress_class": "classified", "velocity_1m": 2,
      "approval_state": "none"},
     "require_approval"),
    ("classified egress, approval granted",
     {"agent_id": "agent-a", "tool_name": "send_email",
      "egress_class": "classified", "velocity_1m": 2,
      "approval_state": "granted"},
     "allow"),
    ("classified egress, approval denied",
     {"agent_id": "agent-a", "tool_name": "send_email",
      "egress_class": "classified", "velocity_1m": 2,
      "approval_state": "denied"},
     "require_approval"),
    ("velocity exceeded on ordinary tool",
     {"agent_id": "agent-a", "tool_name": "read_file",
      "egress_class": "none", "velocity_1m": 50,
      "approval_state": "none"},
     "deny"),
    ("unknown tool (default deny)",
     {"agent_id": "agent-a", "tool_name": "exfiltrate",
      "egress_class": "none", "velocity_1m": 1,
      "approval_state": "none"},
     "deny"),
    ("prod db write, no approval",
     {"agent_id": "agent-a", "tool_name": "db_write_production",
      "egress_class": "classified", "velocity_1m": 1,
      "approval_state": "none"},
     "require_approval"),
]

def _req(**kw):
    base = {"agent_id": "agent-a", "tool_name": "read_file",
            "egress_class": "none", "velocity_1m": 1,
            "approval_state": "none"}
    base.update(kw)
    return base


class CompileStrictnessTest(unittest.TestCase):
    def test_model_compiles(self):
        model = pl.compile_perm_model(PERM_MODEL_YML,
                                      PERM_POLICY_YML)
        self.assertEqual(
            [s["name"] for s in model._model["screens"]],
            ["deny", "approval", "allow"])

    def test_unknown_effect_refused(self):
        bad = PERM_MODEL_YML.replace(
            'effect: "some(where (p_eft == allow))"',
            'effect: "sometimes(maybe)"', 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_subject_priority_refused(self):
        bad = PERM_MODEL_YML.replace(
            'effect: "some(where (p_eft == allow))"',
            'effect: "subjectPriority(p_eft) || deny"', 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_priority_effect_accepted(self):
        ok = PERM_MODEL_YML.replace(
            'effect: "some(where (p_eft == allow))"',
            'effect: "priority(p_eft) || deny"', 1)
        model = pl.compile_perm_model(ok, PERM_POLICY_YML)
        self.assertIsNotNone(model)

    def test_top_level_not_refused(self):
        bad = PERM_MODEL_YML.replace(
            """    matcher:
      and:""",
            """    matcher:
      not:
        and:""", 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_unknown_matcher_refused_d3(self):
        bad = PERM_MODEL_YML.replace("- toolMatch",
                                     "- noSuchFn", 1)
        with self.assertRaises(pl.PermError) as ctx:
            pl.compile_perm_model(bad, PERM_POLICY_YML)
        self.assertIn("unknown matcher function",
                      str(ctx.exception))

    def test_eft_typed_request_column_refused(self):
        bad = PERM_MODEL_YML.replace("  approval_state: str",
                                     "  approval_state: eft", 1)
        with self.assertRaises(pl.PermError) as ctx:
            pl.compile_perm_model(bad, PERM_POLICY_YML)
        self.assertIn("str|int|bool", str(ctx.exception))

    def test_unknown_request_column_refused(self):
        bad = PERM_MODEL_YML.replace("req: approval_state",
                                     "req: no_such_col")
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_unknown_screen_in_composition_refused(self):
        bad = PERM_MODEL_YML.replace("      screen: allow",
                                     "      screen: limbo", 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_invert_must_be_bool(self):
        # invert is a generic composition operator (fire when the
        # effect is False); the loader's check is bool-typed.
        bad = PERM_MODEL_YML.replace("      invert: true",
                                     "      invert: 'yes'", 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_bad_policy_eft_refused_d1(self):
        bad = PERM_POLICY_YML.replace("eft: allow", "eft: maybe",
                                      1)
        with self.assertRaises(pl.PermError) as ctx:
            pl.compile_perm_model(PERM_MODEL_YML, bad)
        self.assertIn("allow|deny", str(ctx.exception))

    def test_policy_missing_screen_refused(self):
        bad = PERM_POLICY_YML.replace("  approval:\n", "", 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(PERM_MODEL_YML, bad)

    def test_unknown_top_level_key_refused(self):
        bad = PERM_MODEL_YML.replace(
            "model_version: 1",
            "model_version: 1\nevil: true", 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_composition_digest_stable(self):
        m1 = pl.compile_perm_model(PERM_MODEL_YML,
                                   PERM_POLICY_YML)
        m2 = pl.compile_perm_model(PERM_MODEL_YML,
                                   PERM_POLICY_YML)
        self.assertEqual(m1.composition_digest,
                         m2.composition_digest)
        self.assertEqual(len(m1.composition_digest), 64)


class ScenarioTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = pl.compile_perm_model(PERM_MODEL_YML,
                                          PERM_POLICY_YML)

    def test_nine_scenarios(self):
        for name, request, want in PERM_SCENARIOS:
            verdict, screen, _detail = self.model.decide(request)
            self.assertEqual(
                verdict, want,
                "scenario %r: got %s via %s, want %s"
                % (name, verdict, screen, want))

    def test_decide_returns_screen_and_detail(self):
        verdict, screen, detail = self.model.decide(_req(
            tool_name="install_package"))
        self.assertEqual((verdict, screen), ("deny", "deny"))
        self.assertIn("matched_rows", detail)


class MatcherDirectionTest(unittest.TestCase):
    """Pin the (value, pattern) call convention for both matchers."""

    def _model_with_policy(self, policy_yml):
        return pl.compile_perm_model(PERM_MODEL_YML, policy_yml)

    def test_glob_wildcard_direction(self):
        pol = """\
perm_policy: sasanam-perm/v1
policies:
  deny: []
  approval: []
  allow:
    -
      agent_pat: "*"
      tool_pat: send_*
      vel_limit: 999999999
      eft: allow
"""
        model = self._model_with_policy(pol)
        verdict, _s, _d = model.decide(_req(tool_name="send_email"))
        self.assertEqual(verdict, "allow")
        # The VALUE must not be treated as the pattern: a value
        # that merely contains wildcard syntax matches nothing.
        verdict, _s, _d = model.decide(_req(tool_name="read_file"))
        self.assertEqual(verdict, "deny")

    def test_glob_exact_still_works(self):
        model = self._model_with_policy(PERM_POLICY_YML)
        verdict, _s, _d = model.decide(
            _req(tool_name="install_package"))
        self.assertEqual(verdict, "deny")

    def test_regex_value_then_literal_pattern(self):
        model_yml = """\
perm_model: sasanam-perm/v1
model_version: 1
request_schema:
  tool_name: str
policy_schema:
  tool_pat: str
  eft: eft
matchers:
  rx: regex
screens:
  -
    name: allow
    effect: "some(where (p_eft == allow))"
    matcher:
      call:
        - rx
        -
          req: tool_name
        - "^db_.*$"
composition:
  default_verdict: deny
  order:
    -
      screen: allow
      verdict: allow
"""
        pol = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: unused-by-matcher
      eft: allow
"""
        model = pl.compile_perm_model(model_yml, pol)
        verdict, _s, _d = model.decide({"tool_name": "db_read"})
        self.assertEqual(verdict, "allow")
        verdict, _s, _d = model.decide({"tool_name": "send_email"})
        self.assertEqual(verdict, "deny")

    def test_invalid_regex_refused_at_load(self):
        model_yml = PERM_MODEL_YML.replace(
            "toolMatch: glob", "toolMatch: glob\n  rx: regex", 1)
        bad_call = """              call:
                - toolMatch
                -
                  req: tool_name
                -
                  pol: tool_pat"""
        good_call = """              call:
                - rx
                -
                  req: tool_name
                - "([bad\""""
        bad = model_yml.replace(bad_call, good_call, 1)
        with self.assertRaises(pl.PermError):
            pl.compile_perm_model(bad, PERM_POLICY_YML)

    def test_regex_column_pattern_refused(self):
        model_yml = PERM_MODEL_YML.replace(
            "toolMatch: glob", "toolMatch: glob\n  rx: regex", 1)
        bad_call = """              call:
                - toolMatch
                -
                  req: tool_name
                -
                  pol: tool_pat"""
        smuggled = """              call:
                - rx
                -
                  req: tool_name
                -
                  pol: tool_pat"""
        bad = model_yml.replace(bad_call, smuggled, 1)
        with self.assertRaises(pl.PermError) as ctx:
            pl.compile_perm_model(bad, PERM_POLICY_YML)
        self.assertIn("model literal", str(ctx.exception))


class MalformedRequestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = pl.compile_perm_model(PERM_MODEL_YML,
                                          PERM_POLICY_YML)

    def test_missing_column_fails_closed(self):
        req = _req()
        del req["tool_name"]
        with self.assertRaises(pl.PermError):
            self.model.decide(req)

    def test_extra_column_fails_closed(self):
        req = _req(extra="x")
        with self.assertRaises(pl.PermError):
            self.model.decide(req)

    def test_wrong_type_fails_closed(self):
        with self.assertRaises(pl.PermError):
            self.model.decide(_req(velocity_1m="fast"))

    def test_bool_for_int_fails_closed(self):
        # bool is an int subclass; the schema rejects it loud.
        with self.assertRaises(pl.PermError):
            self.model.decide(_req(velocity_1m=True))

    def test_non_dict_fails_closed(self):
        for bad in (None, "x", [("tool_name", "read_file")], 42):
            with self.assertRaises(pl.PermError):
                self.model.decide(bad)


class PackRoundTripTest(unittest.TestCase):
    def _two_human_keyset(self):
        ks, _ = new_keyset(_SEED1,
                           purpose=rp.KEYSET_PURPOSE_PERM_PACK)
        ks, _ = rotate_keyset(ks, _SEED2, _SEED1)
        return ks, [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]

    def test_threshold_one_refused_at_mint(self):
        ks, _ = new_keyset(_SEED1,
                           purpose=rp.KEYSET_PURPOSE_PERM_PACK)
        signer = keyset_signer_for_version(ks, 1, _SEED1)
        with self.assertRaises(pl.PermError) as ctx:
            pl.mint_perm_pack(
                ks, [signer], model_bytes=PERM_MODEL_YML,
                policy_bytes=PERM_POLICY_YML, pack_version=1,
                issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
        self.assertIn("threshold >= 2", str(ctx.exception))

    def test_two_human_round_trip(self):
        ks, signers = self._two_human_keyset()
        doc = pl.mint_perm_pack(
            ks, signers, model_bytes=PERM_MODEL_YML,
            policy_bytes=PERM_POLICY_YML, pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
        loader = pl.new_perm_pack_loader(ks)
        active = loader.present(
            doc, {"perm-model.yml": PERM_MODEL_YML.encode(),
                  "perm-policy.yml": PERM_POLICY_YML.encode()},
            now=NOW)
        self.assertEqual(active.threshold, 2)
        self.assertEqual(active.purpose, rp.KEYSET_PURPOSE_PERM_PACK)
        self.assertEqual(active.format_tag, rp.PERM_PACK_FORMAT)
        model = pl.load_perm_from_active_pack(active)
        verdict, screen, _d = model.decide(_req(
            tool_name="install_package"))
        self.assertEqual((verdict, screen), ("deny", "deny"))

    def test_detection_domain_pack_refused(self):
        # A signed DETECTION-rule pack (right shape, wrong trust
        # domain) is never usable as a PERM model pack -- even if
        # someone names its members like PERM members.
        rule_ks, _ = new_keyset(
            _SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        signer = keyset_signer_for_version(rule_ks, 1, _SEED1)
        members = {"perm-model.yml": b"model: x\n",
                   "perm-policy.yml": b"policy: x\n"}
        digests = {
            mid: "sha256:" + hashlib.sha256(data).hexdigest()
            for mid, data in members.items()}
        doc = rp.mint_rule_pack(
            rule_ks, [signer], rules=digests, pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
        loader = pload.PackLoader(rule_ks, "detection")
        active = loader.present(doc, dict(members), now=NOW)
        with self.assertRaises(pl.PermError) as ctx:
            pl.load_perm_from_active_pack(active)
        self.assertIn("trust domain", str(ctx.exception))

    def test_tampered_model_bytes_refused(self):
        ks, signers = self._two_human_keyset()
        doc = pl.mint_perm_pack(
            ks, signers, model_bytes=PERM_MODEL_YML,
            policy_bytes=PERM_POLICY_YML, pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
        loader = pl.new_perm_pack_loader(ks)
        evil = PERM_MODEL_YML.replace(
            'default_verdict: deny', 'default_verdict: allow', 1)
        with self.assertRaises(pload.PackActivationError):
            loader.present(
                doc,
                {"perm-model.yml": evil.encode(),
                 "perm-policy.yml": PERM_POLICY_YML.encode()},
                now=NOW)

    def test_effect_tamper_changes_nothing_silently(self):
        # D2: flipping the deny screen's effect in the SIGNED bytes
        # breaks the digest (refused above); flipping it in
        # unsigned text never reaches the loader. What CAN reach
        # the compiler is a re-signed model -- which then carries a
        # different model digest in the BOM.
        ks, signers = self._two_human_keyset()
        evil = PERM_MODEL_YML.replace(
            'effect: "!some(where (p_eft == deny))"',
            'effect: "some(where (p_eft == allow))"', 1)
        doc = pl.mint_perm_pack(
            ks, signers, model_bytes=evil,
            policy_bytes=PERM_POLICY_YML, pack_version=2,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=2)
        loader = pl.new_perm_pack_loader(ks)
        active = loader.present(
            doc, {"perm-model.yml": evil.encode(),
                  "perm-policy.yml": PERM_POLICY_YML.encode()},
            now=NOW)
        model = pl.load_perm_from_active_pack(active)
        good = pl.compile_perm_model(PERM_MODEL_YML,
                                     PERM_POLICY_YML)
        # The effect lives in the screen definition: the MODEL
        # digest changes. The COMPOSITION (order + verdicts) did
        # not change, so its digest is honestly unchanged.
        self.assertNotEqual(model.model_digest,
                            good.model_digest)
        self.assertEqual(model.composition_digest,
                         good.composition_digest)


class BomSectionTest(unittest.TestCase):
    def test_section_has_four_digests(self):
        model = pl.compile_perm_model(PERM_MODEL_YML,
                                      PERM_POLICY_YML)
        section = model.bom_perm_section()
        self.assertEqual(
            sorted(section),
            ["composition_digest", "function_set_digest",
             "model_digest", "policy_digest"])
        for key, value in section.items():
            self.assertRegex(value, r"^[0-9a-f]{64}$",
                             "bad digest for %s" % key)

    def test_bom_round_trip(self):
        model = pl.compile_perm_model(PERM_MODEL_YML,
                                      PERM_POLICY_YML)
        bom = db.build_bom(
            policy_id="p", policy_version="1",
            policy_digest="ab" * 32, evidence_head_digest="head",
            principal={"agent_id": "a"},
            perm_model=model.bom_perm_section())
        self.assertTrue(db.check_bom_shape(bom)[0])
        ok, reason = db.verify_bom(
            bom, perm_model_bytes=PERM_MODEL_YML.encode(),
            perm_policy_bytes=PERM_POLICY_YML.encode())
        self.assertTrue(ok, reason)
        ok, _reason = db.verify_bom(
            bom, perm_model_bytes=b"swapped")
        self.assertFalse(ok)

    def test_bom_absent_section_byte_identical(self):
        kw = dict(policy_id="p", policy_version="1",
                  policy_digest="ab" * 32,
                  evidence_head_digest="head",
                  principal={"agent_id": "a"})
        import json
        b1 = db.build_bom(**kw)
        self.assertNotIn("perm", json.dumps(b1, sort_keys=True))

    def _bom_with_perm(self):
        model = pl.compile_perm_model(PERM_MODEL_YML,
                                      PERM_POLICY_YML)
        return db.build_bom(
            policy_id="p", policy_version="1",
            policy_digest="ab" * 32, evidence_head_digest="head",
            principal={"agent_id": "a"},
            perm_model=model.bom_perm_section())

    def test_partial_perm_legs_named_unverified(self):
        # A verifier that supplies only an UNRELATED artifact gets an
        # honest "unverified: perm-model,perm-policy" suffix -- never
        # an overbroad "ok".
        import hashlib
        bundle = b"bundle-bytes"
        model = pl.compile_perm_model(PERM_MODEL_YML,
                                      PERM_POLICY_YML)
        bom = db.build_bom(
            policy_id="p", policy_version="1",
            policy_digest=hashlib.sha256(bundle).hexdigest(),
            evidence_head_digest="head",
            principal={"agent_id": "a"},
            perm_model=model.bom_perm_section())
        ok, reason = db.verify_bom(
            bom, policy_bundle_bytes=bundle)
        self.assertTrue(ok, reason)
        self.assertIn("unverified: perm-model,perm-policy", reason)

    def test_model_only_names_policy_unverified(self):
        bom = self._bom_with_perm()
        ok, reason = db.verify_bom(
            bom, perm_model_bytes=PERM_MODEL_YML.encode())
        self.assertTrue(ok, reason)
        self.assertIn("unverified: perm-policy", reason)

    def test_policy_only_names_model_unverified(self):
        bom = self._bom_with_perm()
        ok, reason = db.verify_bom(
            bom, perm_policy_bytes=PERM_POLICY_YML.encode())
        self.assertTrue(ok, reason)
        self.assertIn("unverified: perm-model", reason)

    def test_full_perm_verification_no_unverified(self):
        bom = self._bom_with_perm()
        ok, reason = db.verify_bom(
            bom, perm_model_bytes=PERM_MODEL_YML.encode(),
            perm_policy_bytes=PERM_POLICY_YML.encode())
        self.assertTrue(ok, reason)
        self.assertNotIn("unverified", reason)

    def test_no_artifacts_still_fails_closed(self):
        bom = self._bom_with_perm()
        ok, _reason = db.verify_bom(bom)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
