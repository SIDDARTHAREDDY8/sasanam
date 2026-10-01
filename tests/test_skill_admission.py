"""Unit tests for gov/skill_admission.py (W248-2).

in-toto-inspired skill admission gate: signed layout + signed per-step
links; hard refusal on command mismatch; structural
authority/signer separation.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_codes as dc
from gov import ed25519
from gov import skill_admission as sa


def _d(*parts):
    return hashlib.sha256(b"|".join(parts)).hexdigest()


_D_SRC = _d(b"src")
_D_TAR = _d(b"tar")
_D_REP = _d(b"rep")

_FETCH_RULES = [("REQUIRE", "skill-src.zip"),
                ("MATCH", "skill.tar.gz", _D_TAR),
                ("DISALLOW",)]
_SCAN_RULES = [("REQUIRE", "skill.tar.gz"),
               ("MATCH", "scan-report.json", _D_REP),
               ("DISALLOW",)]
_FETCH_CMD = ["fetch-skill", "--src", "skill-src.zip"]
_SCAN_CMD = ["scan-skill", "--in", "skill.tar.gz"]


class SkillAdmissionPinTests(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Wave-248 merge: re-pointed to 979 (938 + 41 wave-248 codes: 1 breach-boundary + 9 skill-admission + 2 evidence-envelope + 6 skill-update + 13 identity + 3 combine + 7 artifact), additive only.
        # codes), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1049)  # Wave-256 merge: pin -> 1049.
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.

    def test_module_constants_match_taxonomy(self):
        for const in (
                "SKILL_ADMISSION_LAYOUT_MALFORMED",
                "SKILL_ADMISSION_LAYOUT_SIGNATURE_INVALID",
                "SKILL_ADMISSION_AUTHORITY_IS_STEP_SIGNER",
                "SKILL_ADMISSION_LINK_MISSING",
                "SKILL_ADMISSION_LINK_MALFORMED",
                "SKILL_ADMISSION_LINK_SIGNATURE_INVALID",
                "SKILL_ADMISSION_UNAUTHORIZED_SIGNER",
                "SKILL_ADMISSION_COMMAND_MISMATCH",
                "SKILL_ADMISSION_ARTIFACT_RULE_VIOLATED"):
            code = getattr(sa, const)
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["code"], code)
            self.assertEqual(dc.TAXONOMY[code]["domain"],
                             "skill-admission")


class Fixtures:
    def __init__(self):
        self.authority_seed = ed25519.generate_seed()
        self.authority_pub = ed25519.publickey(
            self.authority_seed).hex()
        self.fetch_seed = ed25519.generate_seed()
        self.fetch_pub = ed25519.publickey(self.fetch_seed).hex()
        self.scan_seed = ed25519.generate_seed()
        self.scan_pub = ed25519.publickey(self.scan_seed).hex()

    def layout(self):
        return sa.make_layout(
            "skill/weather-v1",
            steps=[
                {"name": "fetch", "command": list(_FETCH_CMD),
                 "signer_pub": self.fetch_pub, "rules": _FETCH_RULES},
                {"name": "scan", "command": list(_SCAN_CMD),
                 "signer_pub": self.scan_pub, "rules": _SCAN_RULES},
            ],
            layout_seed=self.authority_seed)

    def links(self):
        return [
            sa.make_link(
                "skill/weather-v1", "fetch", list(_FETCH_CMD),
                materials={"skill-src.zip": _D_SRC},
                products={"skill.tar.gz": _D_TAR},
                signer_seed=self.fetch_seed),
            sa.make_link(
                "skill/weather-v1", "scan", list(_SCAN_CMD),
                materials={"skill.tar.gz": _D_TAR},
                products={"scan-report.json": _D_REP},
                signer_seed=self.scan_seed),
        ]


class MakeLayoutTests(unittest.TestCase):
    def test_deterministic(self):
        f = Fixtures()
        a = sa.make_layout(
            "skill/x", steps=[{"name": "fetch",
                               "command": list(_FETCH_CMD),
                               "signer_pub": f.fetch_pub,
                               "rules": _FETCH_RULES}],
            layout_seed=f.authority_seed)
        # Same seeds and content -> byte-identical signed layout.
        seed_copy = bytes(f.authority_seed)
        b = sa.make_layout(
            "skill/x", steps=[{"name": "fetch",
                               "command": list(_FETCH_CMD),
                               "signer_pub": f.fetch_pub,
                               "rules": [tuple(r) for r in _FETCH_RULES]}],
            layout_seed=seed_copy)
        self.assertEqual(a, b)

    def test_malformed_inputs_raise(self):
        f = Fixtures()
        good_step = {"name": "fetch", "command": list(_FETCH_CMD),
                     "signer_pub": f.fetch_pub, "rules": _FETCH_RULES}
        with self.assertRaises(sa.SkillAdmissionError) as ctx:
            sa.make_layout("", [good_step], f.authority_seed)
        self.assertEqual(ctx.exception.code,
                         sa.SKILL_ADMISSION_LAYOUT_MALFORMED)
        with self.assertRaises(sa.SkillAdmissionError):
            sa.make_layout("skill/x", [], f.authority_seed)
        dup = dict(good_step)
        with self.assertRaises(sa.SkillAdmissionError):
            sa.make_layout("skill/x", [good_step, dup], f.authority_seed)
        bad_rules = dict(good_step, rules=[("BOGUS",)])
        with self.assertRaises(sa.SkillAdmissionError):
            sa.make_layout("skill/x", [bad_rules], f.authority_seed)
        no_disallow = dict(good_step, rules=[("REQUIRE", "skill-src.zip")])
        with self.assertRaises(sa.SkillAdmissionError):
            sa.make_layout("skill/x", [no_disallow], f.authority_seed)
        with self.assertRaises(sa.SkillAdmissionError):
            sa.make_layout("skill/x", [good_step], b"short")


class MakeLinkTests(unittest.TestCase):
    def test_malformed_inputs_raise_link_codes(self):
        f = Fixtures()
        with self.assertRaises(sa.SkillAdmissionError) as ctx:
            sa.make_link("skill/x", "", list(_FETCH_CMD),
                         {"skill-src.zip": _D_SRC},
                         {"skill.tar.gz": _D_TAR}, f.fetch_seed)
        self.assertEqual(ctx.exception.code,
                         sa.SKILL_ADMISSION_LINK_MALFORMED)
        with self.assertRaises(sa.SkillAdmissionError) as ctx2:
            sa.make_link("skill/x", "fetch", list(_FETCH_CMD),
                         {"skill-src.zip": "not-hex"},
                         {"skill.tar.gz": _D_TAR}, f.fetch_seed)
        self.assertEqual(ctx2.exception.code,
                         sa.SKILL_ADMISSION_LINK_MALFORMED)

    def test_link_embeds_signer_pub(self):
        f = Fixtures()
        link = sa.make_link("skill/x", "fetch", list(_FETCH_CMD),
                            {"skill-src.zip": _D_SRC},
                            {"skill.tar.gz": _D_TAR}, f.fetch_seed)
        self.assertEqual(link["link"]["signer_pub"], f.fetch_pub)
        self.assertEqual(len(link["signature"]), 128)


class AdmitTests(unittest.TestCase):
    def test_happy_path(self):
        f = Fixtures()
        verdict = sa.admit(f.layout(), f.links(), f.authority_pub)
        self.assertTrue(verdict["admitted"])
        self.assertIsNone(verdict["code"])
        self.assertEqual(verdict["evidence"]["layout_id"],
                         "skill/weather-v1")
        self.assertEqual(len(verdict["evidence"]["steps"]), 2)

    def test_adversarial_input_never_raises(self):
        # Malformed/adversarial input is a refused verdict, never an
        # exception.
        for bad_layout, bad_links, bad_pub in (
                (None, [], "00" * 32),
                ("nope", [], "00" * 32),
                ({"layout": {}, "signature": "ab" * 64}, [], "00" * 32),
                ({"layout": {"layout_id": "x", "steps": []},
                  "signature": "ab" * 64}, [], "00" * 32),
                ({"layout": {"layout_id": "x", "steps": "nope"},
                  "signature": "ab" * 64}, [], "not-hex")):
            verdict = sa.admit(bad_layout, bad_links, bad_pub)
            self.assertFalse(verdict["admitted"])
            self.assertIn(verdict["code"], dc.TAXONOMY)

    def test_refusal_codes(self):
        f = Fixtures()
        layout = f.layout()
        links = f.links()

        # Forged layout signature.
        forged = dict(layout)
        sig = forged["signature"]
        forged["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        v = sa.admit(forged, links, f.authority_pub)
        self.assertEqual(v["code"],
                         sa.SKILL_ADMISSION_LAYOUT_SIGNATURE_INVALID)

        # Wrong authority key.
        other = ed25519.publickey(ed25519.generate_seed()).hex()
        v = sa.admit(layout, links, other)
        self.assertEqual(v["code"],
                         sa.SKILL_ADMISSION_LAYOUT_SIGNATURE_INVALID)

        # Missing link.
        v = sa.admit(layout, links[:1], f.authority_pub)
        self.assertEqual(v["code"], sa.SKILL_ADMISSION_LINK_MISSING)

        # Link for unknown step.
        rogue = sa.make_link("skill/weather-v1", "backdoor",
                             ["evil"], {}, {"e": _D_SRC}, f.fetch_seed)
        v = sa.admit(layout, links + [rogue], f.authority_pub)
        self.assertEqual(v["code"], sa.SKILL_ADMISSION_LINK_MALFORMED)

        # Cross-layout link replay.
        other_layout_id = sa.make_link(
            "skill/other", "fetch", list(_FETCH_CMD),
            {"skill-src.zip": _D_SRC}, {"skill.tar.gz": _D_TAR},
            f.fetch_seed)
        v = sa.admit(layout, [other_layout_id, links[1]],
                     f.authority_pub)
        self.assertEqual(v["code"], sa.SKILL_ADMISSION_LINK_MALFORMED)

        # Command mismatch is a hard refusal.
        evil_cmd = sa.make_link(
            "skill/weather-v1", "fetch",
            ["fetch-skill", "--src", "skill-src.zip", "--pwn"],
            {"skill-src.zip": _D_SRC}, {"skill.tar.gz": _D_TAR},
            f.fetch_seed)
        v = sa.admit(layout, [evil_cmd, links[1]], f.authority_pub)
        self.assertEqual(v["code"], sa.SKILL_ADMISSION_COMMAND_MISMATCH)

        # Unauthorized signer (valid signature, wrong key).
        rogue_seed = ed25519.generate_seed()
        rogue_link = sa.make_link(
            "skill/weather-v1", "fetch", list(_FETCH_CMD),
            {"skill-src.zip": _D_SRC}, {"skill.tar.gz": _D_TAR},
            rogue_seed)
        v = sa.admit(layout, [rogue_link, links[1]], f.authority_pub)
        self.assertEqual(v["code"], sa.SKILL_ADMISSION_UNAUTHORIZED_SIGNER)

    def test_authority_is_signer_refused(self):
        f = Fixtures()
        layout = sa.make_layout(
            "skill/x",
            steps=[{"name": "fetch", "command": list(_FETCH_CMD),
                    "signer_pub": f.authority_pub, "rules": _FETCH_RULES}],
            layout_seed=f.authority_seed)
        link = sa.make_link("skill/x", "fetch", list(_FETCH_CMD),
                            {"skill-src.zip": _D_SRC},
                            {"skill.tar.gz": _D_TAR}, f.authority_seed)
        v = sa.admit(layout, [link], f.authority_pub)
        self.assertEqual(v["code"],
                         sa.SKILL_ADMISSION_AUTHORITY_IS_STEP_SIGNER)

    def test_artifact_rule_violations(self):
        f = Fixtures()
        layout = f.layout()
        # Empty products: REQUIRE fails (F193 vacuous-proof class).
        empty = sa.make_link("skill/weather-v1", "fetch",
                             list(_FETCH_CMD),
                             {"skill-src.zip": _D_SRC}, {},
                             f.fetch_seed)
        v = sa.admit(layout, [empty], f.authority_pub)
        self.assertEqual(v["code"],
                         sa.SKILL_ADMISSION_ARTIFACT_RULE_VIOLATED)
        # Digest mismatch: MATCH fails.
        tampered = sa.make_link(
            "skill/weather-v1", "fetch", list(_FETCH_CMD),
            {"skill-src.zip": _D_SRC},
            {"skill.tar.gz": _d(b"trojan")}, f.fetch_seed)
        v = sa.admit(layout, [tampered], f.authority_pub)
        self.assertEqual(v["code"],
                         sa.SKILL_ADMISSION_ARTIFACT_RULE_VIOLATED)


if __name__ == "__main__":
    unittest.main()
