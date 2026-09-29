"""Unit tests for auditor-side Sigma detection (wave-198).

Covers: the Sigma-subset parser (loud refusals), selection and
aggregation semantics, the signed rule pack (round trip, wrong
purpose, expiry, threshold, revoked keys, tampered bytes), and the
auditor wiring (tampered/unbound/missing rules, unknown correlators,
assumption warnings, report shape, inbox items, export wrapper,
read-only evaluation).

$0 spend, synthetic/local deterministic only. No network.
"""

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import audit_detect as ad  # noqa: E402
from gov import rule_pack as rp  # noqa: E402
from gov import sigma_subset as sig  # noqa: E402
from gov.keyset import (  # noqa: E402
    KEYSET_PURPOSE_AUDIT_ENTRY_SIGNING,
    new_keyset,
    keyset_signer_for_version,
)

_SEED1 = bytes.fromhex("41" * 32)
_SEED2 = bytes.fromhex("42" * 32)
_SEED3 = bytes.fromhex("43" * 32)

RULE_TMPL = """title: Test rule
id: {rid}
status: test
author: unit
logsource:
    category: audit
detection:
    sel:
        type: {etype}
    condition: sel
level: medium
"""


def _parse(tmpl_args=None, extra=""):
    rid = "11111111-2222-3333-4444-555555555555"
    text = RULE_TMPL.format(rid=rid, **(tmpl_args or {"etype": "identity"}))
    if extra:
        text += extra
    return sig.parse_rule_text(text)


class SigmaSubsetParserTest(unittest.TestCase):
    def test_bad_yaml_refuses_loudly(self):
        with self.assertRaises(sig.SigmaSubsetError):
            sig.parse_rule_text("title: t\n\tid: x\n")  # tabs unsupported

    def test_missing_sections_refuse_loudly(self):
        # Parsing is lenient; compilation enforces the required keys.
        doc = sig.parse_rule_text("title: t\nid: i\n")
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(doc)
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(sig.parse_rule_text(
                "title: t\nid: i\nlogsource:\n    category: c\n"))

    def test_bad_condition_refuses(self):
        text = RULE_TMPL.format(
            rid="11111111-2222-3333-4444-555555555555", etype="identity")
        text = text.replace("condition: sel", "condition: sel OR")
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(sig.parse_rule_text(text))

    def test_unknown_macro_refuses(self):
        doc = _parse()
        doc["detection"]["sel"] = {"$macro": "nope"}
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(doc)

    def test_macro_expands_inside_selection(self):
        doc = _parse()
        doc["detection"]["sel"] = {"$macro": "geo_lagos"}
        doc["macros"] = {"geo_lagos": {"geo": "Lagos"}}
        rule = sig.compile_rule(doc)
        self.assertTrue(rule.matches({"type": "x", "geo": "Lagos"}))
        self.assertFalse(rule.matches({"type": "x", "geo": "Abuja"}))

    def test_macro_collision_refuses(self):
        doc = _parse()
        doc["detection"]["sel"] = {"$macro": "m", "geo": "Lagos"}
        doc["macros"] = {"m": {"geo": "Abuja"}}
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(doc)

    def test_bad_timeframe_refuses(self):
        doc = _parse()
        doc["detection"]["timeframe"] = "5 parsecs"
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(doc)

    def test_aggregation_without_by_refuses(self):
        doc = _parse()
        doc["detection"]["condition"] = "sel | count() > 1"
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(doc)

    def test_rule_id_bound_from_document(self):
        rule = sig.compile_rule(_parse())
        self.assertEqual(rule.rule_id, "11111111-2222-3333-4444-555555555555")


class SelectionSemanticsTest(unittest.TestCase):
    def _rule(self, selection, condition="sel"):
        doc = _parse()
        doc["detection"]["sel"] = selection
        doc["detection"]["condition"] = condition
        return sig.compile_rule(doc)

    def test_eq(self):
        r = self._rule({"type": "identity"})
        self.assertTrue(r.matches({"type": "identity"}))
        self.assertFalse(r.matches({"type": "decision"}))

    def test_lt_lte_gt_gte(self):
        # Product spelling: field|op modifier or {"$op": n} dict.
        r = self._rule({"approvals|lt": 3})
        self.assertTrue(r.matches({"approvals": 2}))
        self.assertFalse(r.matches({"approvals": 3}))
        r = self._rule({"approvals": {"$gte": 3}})
        self.assertTrue(r.matches({"approvals": 3}))
        self.assertFalse(r.matches({"approvals": 2}))

    def test_contains_startswith_endswith(self):
        r = self._rule({"tool|contains": "exec"})
        self.assertTrue(r.matches({"tool": "shell_exec"}))
        self.assertFalse(r.matches({"tool": "run"}))
        r = self._rule({"tool": {"$startswith": "sh"}})
        self.assertTrue(r.matches({"tool": "shell"}))
        self.assertFalse(r.matches({"tool": "bash"}))
        r = self._rule({"tool|endswith": "sh"})
        self.assertTrue(r.matches({"tool": "bash"}))
        self.assertFalse(r.matches({"tool": "shell_exec"}))

    def test_unsupported_dict_op_refuses_loudly(self):
        # The product subset has no {near:}/ {wildcard:} dict ops --
        # an unknown op fails loudly at match time, never silently.
        r = self._rule({"lat": {"near": [6.5, 0.5]}})
        with self.assertRaises(sig.RuleError):
            r.matches({"lat": 6.7})

    def test_regex(self):
        r = self._rule({"agent_id": {"$re": r"^agent-\d+$"}})
        self.assertTrue(r.matches({"agent_id": "agent-007"}))
        self.assertFalse(r.matches({"agent_id": "svc-x"}))
        r = self._rule({"agent_id|re": r"^agent-\d+$"})
        self.assertTrue(r.matches({"agent_id": "agent-007"}))

    def test_in_list(self):
        r = self._rule({"type": {"$in": ["a", "b"]}})
        self.assertTrue(r.matches({"type": "b"}))
        self.assertFalse(r.matches({"type": "c"}))
        # Bare lists are OR.
        r = self._rule({"type": ["a", "b"]})
        self.assertTrue(r.matches({"type": "a"}))
        self.assertFalse(r.matches({"type": "c"}))

    def test_one_of_group(self):
        doc = _parse()
        doc["detection"]["sel_a"] = {"type": "identity"}
        doc["detection"]["sel_b"] = {"type": "decision"}
        doc["detection"]["condition"] = "1 of sel_*"
        rule = sig.compile_rule(doc)
        self.assertTrue(rule.matches({"type": "identity"}))
        self.assertTrue(rule.matches({"type": "decision"}))
        self.assertFalse(rule.matches({"type": "key_use"}))

    def test_all_of_group(self):
        doc = _parse()
        doc["detection"]["sel_a"] = {"type": "identity"}
        doc["detection"]["sel_b"] = {"geo": "Lagos"}
        doc["detection"]["condition"] = "all of sel_*"
        rule = sig.compile_rule(doc)
        self.assertTrue(rule.matches({"type": "identity", "geo": "Lagos"}))
        self.assertFalse(rule.matches({"type": "identity", "geo": "Abuja"}))

    def test_empty_group_refuses(self):
        doc = _parse()
        doc["detection"]["condition"] = "1 of zz_*"
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(doc)

    def test_not(self):
        r = self._rule({"type": "identity"}, "not sel")
        self.assertFalse(r.matches({"type": "identity"}))
        self.assertTrue(r.matches({"type": "decision"}))

    def test_and_or(self):
        doc = _parse()
        doc["detection"]["other"] = {"geo": "Lagos"}
        doc["detection"]["condition"] = "sel and other"
        rule = sig.compile_rule(doc)
        self.assertTrue(rule.matches({"type": "identity", "geo": "Lagos"}))
        self.assertFalse(rule.matches({"type": "identity", "geo": "Abuja"}))
        doc["detection"]["condition"] = "sel or other"
        rule = sig.compile_rule(doc)
        self.assertTrue(rule.matches({"type": "x", "geo": "Lagos"}))
        self.assertTrue(rule.matches({"type": "identity", "geo": "x"}))
        self.assertFalse(rule.matches({"type": "x", "geo": "x"}))

    def test_unknown_selection_in_condition_refuses(self):
        doc = _parse()
        doc["detection"]["condition"] = "sel and nope"
        with self.assertRaises(sig.RuleError):
            sig.compile_rule(doc)


class AggregationTest(unittest.TestCase):
    def test_count_by_timeframe(self):
        # Product aggregation spelling: sel | count() by f > n
        # (Sigma-style), timeframe bounds the sliding window.
        text = RULE_TMPL.format(
            rid="22222222-3333-4444-5555-666666666666", etype="decision")
        doc = sig.parse_rule_text(text)
        doc["detection"]["sel"] = {"type": "decision", "verdict": "allow"}
        doc["detection"]["condition"] = "sel | count() by agent_id > 2"
        doc["detection"]["timeframe"] = "5m"
        rule = sig.compile_rule(doc)
        eng = sig.StreamEngine([rule])
        base = "2026-09-20T10:00:00+00:00"
        evs = [{"seq": i, "ts": base, "type": "decision",
                "verdict": "allow", "agent_id": "a"}
               for i in range(4)]
        alerts = eng.feed(evs)
        self.assertEqual(len(alerts), 1)
        # The alert fires at the event where the threshold is first
        # exceeded (> 2), so the observed count is 3.
        self.assertEqual(alerts[0]["detail"]["count"], 3)
        self.assertEqual(alerts[0]["detail"]["group"], {"agent_id": "a"})

    def test_below_threshold_stays_quiet(self):
        text = RULE_TMPL.format(
            rid="33333333-4444-5555-6666-777777777777", etype="decision")
        doc = sig.parse_rule_text(text)
        doc["detection"]["sel"] = {"type": "decision", "verdict": "allow"}
        doc["detection"]["condition"] = "sel | count() by agent_id > 2"
        doc["detection"]["timeframe"] = "5m"
        rule = sig.compile_rule(doc)
        eng = sig.StreamEngine([rule])
        evs = [{"seq": i, "ts": "2026-09-20T10:00:00+00:00",
                "type": "decision", "verdict": "allow", "agent_id": "a"}
               for i in range(2)]
        self.assertEqual(eng.feed(evs), [])

    def test_window_slides(self):
        text = RULE_TMPL.format(
            rid="44444444-5555-6666-7777-888888888888", etype="decision")
        doc = sig.parse_rule_text(text)
        doc["detection"]["sel"] = {"type": "decision"}
        doc["detection"]["condition"] = "sel | count() by agent_id > 1"
        doc["detection"]["timeframe"] = "5m"
        rule = sig.compile_rule(doc)
        eng = sig.StreamEngine([rule])
        evs = [
            {"seq": 1, "ts": "2026-09-20T10:00:00+00:00",
             "type": "decision", "agent_id": "a"},
            {"seq": 2, "ts": "2026-09-20T10:06:00+00:00",
             "type": "decision", "agent_id": "a"},
        ]
        # Both events are >5m apart: no window ever holds 2.
        self.assertEqual(eng.feed(evs), [])


class RulePackTest(unittest.TestCase):
    def setUp(self):
        self.keyset, _ = new_keyset(_SEED1,
                                    purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        self.signers = [keyset_signer_for_version(self.keyset, 1, _SEED1)]
        self.rules = {"rid-1": "sha256:" + "ab" * 32}

    def _mint(self, **kw):
        kw.setdefault("issued_at", "2026-09-01T00:00:00+00:00")
        kw.setdefault("expires_at", "2030-01-01T00:00:00+00:00")
        kw.setdefault("threshold", 1)
        signers = kw.pop("signers", self.signers)
        return rp.mint_rule_pack(self.keyset, signers,
                                 rules=self.rules, pack_version=1, **kw)

    def test_round_trip(self):
        pack = rp.verify_rule_pack(self._mint(), self.keyset,
                                   now="2026-10-01T00:00:00+00:00")
        self.assertEqual(pack.version, 1)
        self.assertEqual(pack.digest_for("rid-1"), "sha256:" + "ab" * 32)

    def test_wrong_purpose_keyset_refused(self):
        other, _ = new_keyset(_SEED1,
                              purpose=KEYSET_PURPOSE_AUDIT_ENTRY_SIGNING)
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack(self._mint(), other,
                                now="2026-10-01T00:00:00+00:00")
        self.assertEqual(ctx.exception.code, "wrong-purpose")

    def test_expired_pack_refused(self):
        doc = self._mint()
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack(doc, self.keyset,
                                now="2031-01-01T00:00:00+00:00")
        self.assertEqual(ctx.exception.code, "pack-expired")

    def test_tampered_signature_refused(self):
        doc = self._mint()
        doc["signatures"][0]["sig"] = "00" * 64
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack(doc, self.keyset,
                                now="2026-10-01T00:00:00+00:00")
        self.assertEqual(ctx.exception.code, "bad-signature")

    def _two_of_two_keyset(self):
        # Deployment ceremony for 2-of-2 (same pattern as the corpus
        # manifest tests): rotate two keys in, then attest with their
        # plain signers -- the keyset model has exactly one active
        # primary, so attestations ride plain Signers verified via the
        # legacy key-id lookup against their pinned versions.
        from gov.keyset import rotate_keyset  # noqa: E402
        from gov.signing import Ed25519Signer  # noqa: E402
        ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        ks, _ = rotate_keyset(ks, _SEED2, _SEED1)
        return ks, [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]

    def test_threshold_two_of_three(self):
        ks, signers = self._two_of_two_keyset()
        doc = rp.mint_rule_pack(ks, signers, rules=self.rules,
                                pack_version=1,
                                issued_at="2026-09-01T00:00:00+00:00",
                                expires_at="2030-01-01T00:00:00+00:00",
                                threshold=2)
        pack = rp.verify_rule_pack(doc, ks, now="2026-10-01T00:00:00+00:00")
        self.assertEqual(len(pack.signing_kids), 2)
        self.assertEqual(len(set(pack.signing_kids)), 2)

    def test_threshold_unmet_refused(self):
        ks, signers = self._two_of_two_keyset()
        doc = rp.mint_rule_pack(ks, signers, rules=self.rules,
                                pack_version=1,
                                issued_at="2026-09-01T00:00:00+00:00",
                                expires_at="2030-01-01T00:00:00+00:00",
                                threshold=2)
        # Break one member's signature: 1 valid < threshold 2.
        doc["signatures"][1]["sig"] = "00" * 64
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack(doc, ks, now="2026-10-01T00:00:00+00:00")
        self.assertEqual(ctx.exception.code, "threshold-unmet")

    def test_revoked_key_not_counted(self):
        ks, signers = self._two_of_two_keyset()
        doc = rp.mint_rule_pack(ks, signers, rules=self.rules,
                                pack_version=1,
                                issued_at="2026-09-01T00:00:00+00:00",
                                expires_at="2030-01-01T00:00:00+00:00",
                                threshold=2)
        # Revoke one member in the verifying keyset: its signature no
        # longer counts, so the threshold is unmet.
        from gov.keyset import Keyset  # noqa: E402
        d2 = ks.to_dict()
        d2["versions"][0]["status"] = "revoked"
        ks2 = Keyset.from_dict(d2)
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack(doc, ks2, now="2026-10-01T00:00:00+00:00")
        self.assertEqual(ctx.exception.code, "threshold-unmet")

    def test_versioned_keyset_signer(self):
        s = keyset_signer_for_version(self.keyset, 1, _SEED1)
        doc = rp.mint_rule_pack(self.keyset, [s], rules=self.rules,
                                pack_version=1,
                                issued_at="2026-09-01T00:00:00+00:00",
                                expires_at="2030-01-01T00:00:00+00:00",
                                threshold=1)
        pack = rp.verify_rule_pack(doc, self.keyset,
                                   now="2026-10-01T00:00:00+00:00")
        self.assertEqual(pack.signing_kids, [s.key_id])
        self.assertTrue(pack.signing_kids[0])

    def test_bad_format_refused(self):
        with self.assertRaises(rp.RulePackError) as ctx:
            rp.verify_rule_pack({"format": "nope"}, self.keyset)
        self.assertEqual(ctx.exception.code, "bad-format")

    def test_rule_format_distinct_from_corpus(self):
        self.assertNotEqual(rp.RULE_PACK_FORMAT, "sasanam-corpus-manifest/v1")
        self.assertNotEqual(rp.KEYSET_PURPOSE_RULE_PACK,
                            KEYSET_PURPOSE_AUDIT_ENTRY_SIGNING)


class AuditDetectTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="audit-detect-")
        for f in os.listdir(os.path.join(TREE, "detection_rules")):
            if f.endswith(".yml"):
                shutil.copy(os.path.join(TREE, "detection_rules", f),
                            self.dir)
        self.keyset, _ = new_keyset(_SEED1,
                                    purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        self.signers = [keyset_signer_for_version(self.keyset, 1, _SEED1)]
        self.pack_doc = self._mint_pack()
        with open(os.path.join(self.dir, ad.RULE_PACK_FILENAME), "w",
                   encoding="utf-8") as f:
            json.dump(self.pack_doc, f, indent=2, sort_keys=True)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _mint_pack(self):
        import hashlib as _h
        rules = {}
        for fname in sorted(os.listdir(self.dir)):
            if not fname.endswith(".yml"):
                continue
            raw = open(os.path.join(self.dir, fname), "rb").read()
            rid = str(sig.parse_rule_text(raw.decode("utf-8"))["id"])
            rules[rid] = "sha256:" + _h.sha256(raw).hexdigest()
        return rp.mint_rule_pack(
            self.keyset, self.signers, rules=rules, pack_version=7,
            issued_at="2026-09-01T00:00:00+00:00",
            expires_at="2030-01-01T00:00:00+00:00", threshold=1)

    def _detect(self, entries, **kw):
        pack_doc = json.load(open(os.path.join(
            self.dir, ad.RULE_PACK_FILENAME), encoding="utf-8"))
        return ad.detect_on_entries(entries, self.dir, pack_doc,
                                    self.keyset, **kw)

    def _events(self):
        return [
            {"seq": 1, "ts": "2026-09-20T10:00:00+00:00",
             "type": "identity", "agent_id": "a1", "geo": "Lagos"},
            {"seq": 2, "ts": "2026-09-20T10:10:00+00:00",
             "type": "identity", "agent_id": "a1", "geo": "London"},
        ]

    def test_load_ok(self):
        pack_doc = json.load(open(os.path.join(
            self.dir, ad.RULE_PACK_FILENAME), encoding="utf-8"))
        pack, rules = ad.load_rule_pack(self.dir, pack_doc, self.keyset)
        self.assertEqual(pack.version, 7)
        self.assertEqual(len(rules), 4)

    def test_tampered_rule_refused(self):
        p = os.path.join(self.dir, "approval_velocity.yml")
        raw = open(p, "rb").read().replace(b"> 25", b"> 2500", 1)
        open(p, "wb").write(raw)
        with self.assertRaises(ad.DetectionError) as ctx:
            self._detect([])
        self.assertEqual(ctx.exception.code, "rule-tampered")

    def test_unbound_rule_refused(self):
        open(os.path.join(self.dir, "zz.yml"), "w").write(
            "title: z\nid: 00000000-0000-0000-0000-000000000000\n"
            "detection:\n    s:\n        type: identity\n"
            "    condition: s\n")
        with self.assertRaises(ad.DetectionError) as ctx:
            self._detect([])
        self.assertEqual(ctx.exception.code, "rule-unbound")

    def test_missing_rule_refused(self):
        os.unlink(os.path.join(self.dir, "approval_velocity.yml"))
        with self.assertRaises(ad.DetectionError) as ctx:
            self._detect([])
        self.assertEqual(ctx.exception.code, "rule-missing")

    def test_duplicate_rule_id_refused(self):
        shutil.copy(os.path.join(self.dir, "approval_velocity.yml"),
                    os.path.join(self.dir, "approval_velocity_copy.yml"))
        with self.assertRaises(ad.DetectionError) as ctx:
            self._detect([])
        self.assertEqual(ctx.exception.code, "bad-rule")

    def test_unsupported_correlation_refused(self):
        p = os.path.join(self.dir, "impossible_travel.yml")
        raw = open(p, "rb").read().replace(b"type: impossible_travel",
                                           b"type: near", 1)
        open(p, "wb").write(raw)
        self.pack_doc = self._mint_pack()
        with open(os.path.join(self.dir, ad.RULE_PACK_FILENAME), "w",
                   encoding="utf-8") as f:
            json.dump(self.pack_doc, f, indent=2, sort_keys=True)
        with self.assertRaises(ad.DetectionError) as ctx:
            self._detect(self._events())
        self.assertEqual(ctx.exception.code, "unsupported-correlation")

    def test_impossible_travel_fires(self):
        rep = self._detect(self._events())
        rids = [a["rule_id"] for a in rep.alerts]
        self.assertTrue(any(r.startswith("7c4a1d02") for r in rids))
        alert = [a for a in rep.alerts if a["rule_id"].startswith("7c4a1d02")]
        self.assertEqual(alert[0]["detail"]["from"], "Lagos")
        self.assertEqual(alert[0]["detail"]["to"], "London")

    def test_impossible_travel_no_alert_when_far_apart_in_time(self):
        evs = [
            {"seq": 1, "ts": "2026-09-20T10:00:00+00:00",
             "type": "identity", "agent_id": "a1", "geo": "Lagos"},
            {"seq": 2, "ts": "2026-09-20T12:00:00+00:00",
             "type": "identity", "agent_id": "a1", "geo": "London"},
        ]
        rep = self._detect(evs)
        self.assertFalse([a for a in rep.alerts
                          if a["rule_id"].startswith("7c4a1d02")])

    def test_assumption_violation_warns(self):
        evs = [
            {"seq": 1, "ts": "2026-09-20T10:00:00+00:00", "type": "key_use",
             "sig_key_id": "k1", "verdict": "allow"},
            {"seq": 2, "ts": "2026-09-20T10:01:00+00:00", "type": "checkpoint",
             "sig_key_id": "k1"},
        ]
        rep = self._detect(evs)
        warns = [x for x in rep.warnings
                 if x.get("code") == "assumption-violated"
                 and (x.get("rule_id") or "").startswith("9e6c3f24")]
        self.assertTrue(warns)
        self.assertIn("ceremony_window_end", warns[0]["detail"])

    def test_correlator_rule_assumptions_evaluated(self):
        # The SPEC-GAP fix: correlator-driven rules must also have
        # their assumptions evaluated -- a stream with no identity
        # events must warn loudly for the travel rule, not pass
        # silently.
        evs = [
            {"seq": 1, "ts": "2026-09-20T10:00:00+00:00",
             "type": "decision", "verdict": "allow", "agent_id": "a1"},
        ]
        rep = self._detect(evs)
        warns = [x for x in rep.warnings
                 if x.get("code") == "assumption-violated"
                 and (x.get("rule_id") or "").startswith("7c4a1d02")]
        self.assertTrue(warns)
        self.assertIn("identity", warns[0]["detail"])

    def test_correlator_geo_assumption_evaluated(self):
        # Identity events with no geo: the correlator is blind --
        # loud warning required.
        evs = [
            {"seq": 1, "ts": "2026-09-20T10:00:00+00:00",
             "type": "identity", "agent_id": "a1"},
            {"seq": 2, "ts": "2026-09-20T10:10:00+00:00",
             "type": "identity", "agent_id": "a1"},
        ]
        rep = self._detect(evs)
        warns = [x for x in rep.warnings
                 if x.get("code") == "assumption-violated"
                 and (x.get("rule_id") or "").startswith("7c4a1d02")]
        self.assertTrue([w for w in warns if "geo" in w["detail"]])
        # And no travel alert fires from the blind correlator.
        self.assertFalse([a for a in rep.alerts
                          if a["rule_id"].startswith("7c4a1d02")])

    def test_report_shape_and_inbox(self):
        rep = self._detect(self._events())
        d = rep.to_dict()
        self.assertEqual(d["report_version"], ad.REPORT_VERSION)
        self.assertEqual(d["pack_version"], 7)
        self.assertEqual(d["stream"]["n_events"], 2)
        self.assertEqual(d["stream"]["n_skipped"], 0)
        self.assertTrue(d["stream"]["ts_min"] <= d["stream"]["ts_max"])
        self.assertEqual(len(d["rules_evaluated"]), 4)
        items = rep.inbox_items()
        self.assertTrue(items)
        self.assertTrue(all("provenance" in i for i in items))
        json.dumps(rep.to_json())

    def test_export_wrapper(self):
        rep = ad.detect_on_export(
            {"entries": self._events()}, self.dir,
            json.load(open(os.path.join(self.dir, ad.RULE_PACK_FILENAME),
                           encoding="utf-8")),
            self.keyset)
        self.assertEqual(rep.n_events, 2)

    def test_entries_not_mutated(self):
        evs = self._events()
        snapshot = copy.deepcopy(evs)
        self._detect(evs)
        self.assertEqual(evs, snapshot)

    def test_bad_ts_skipped_loudly(self):
        evs = self._events() + [{"seq": 9, "ts": "nope", "type": "x"}]
        rep = self._detect(evs)
        self.assertEqual(rep.n_skipped, 1)
        self.assertTrue(any(x.get("code") == "events-skipped"
                            for x in rep.warnings))

    def test_non_dict_entry_skipped(self):
        rep = self._detect(self._events() + ["junk"])
        self.assertEqual(rep.n_skipped, 1)


TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
