"""Unit tests for the wave-206 pack linter (gov/pack_lint) and its
LOG_ONLY -> ENFORCE graduation wiring (gov/pack_loader,
gov/perm_loader, gov/capability_manifests).

Covers: the LintReport API (clean/violations/require_clean), the
detection-domain checks (vacuous rule, dead match ref, uncompilable
pack, never-firing pack), the PERM-domain checks (shadowed row,
contradictory pair, vacuous row, trivially-denies-all, default
allow), the shipped capability rule pack staying clean, the loader
graduation (LOG_ONLY default + marker, ENFORCE refusal with prior
pack preserved, the two-distinct-operator promotion ceremony with
its refusal cases, relint-on-change), the decide() marker
(including unstrippability), and the capability-manifest marker.

$0 spend, synthetic/local deterministic only. No network.
"""

import glob
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import capability_manifests as cm  # noqa: E402
from gov import pack_lint as plint  # noqa: E402
from gov import pack_loader as pload  # noqa: E402
from gov import perm_loader as perm  # noqa: E402
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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _rule_doc(name, namespace, features):
    return """\
rules:
  -
    meta:
      name: "%s"
      namespace: %s
      scopes:
        static: module
      capability_tags: [%s]
      label: "%s"
    features:
%s
""" % (name, namespace, namespace, name, features)


def _ind(block, n=6):
    pad = " " * n
    return "\n".join(pad + ln if ln.strip() else ln
                     for ln in block.splitlines())


GOOD_RULES = {
    "r0.yml": _rule_doc(
        "egress socket", "capability/egress/socket",
        _ind("import: socket")).encode("utf-8"),
    "r1.yml": _rule_doc(
        "secret read", "capability/secrets/read",
        _ind('pattern: "AKIA[0-9A-Z]{16}"')).encode("utf-8"),
}

PERM_MODEL = """\
perm_model: sasanam-perm/v1
model_version: 1
request_schema:
  tool_name: str
  velocity_1m: int
policy_schema:
  tool_pat: str
  vel_limit: int
  eft: eft
matchers:
  toolMatch: glob
screens:
  -
    name: allow
    effect: "some(where (p_eft == allow))"
    matcher:
      and:
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
composition:
  default_verdict: deny
  order:
    -
      screen: allow
      verdict: allow
"""

PERM_POLICY = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: read_file
      vel_limit: 999999999
      eft: allow
    -
      tool_pat: list_dir
      vel_limit: 999999999
      eft: allow
"""


def _has(report, check, rule_sub=""):
    return any(v.check == check and rule_sub in v.rule
               for v in report.violations)


class LintReportTest(unittest.TestCase):
    def test_clean_pack(self):
        report = plint.lint_capability_rule_files(dict(GOOD_RULES))
        self.assertTrue(report.clean)
        self.assertEqual(report.violations, ())
        self.assertIn("safety/vacuous-leaf", report.checks)
        self.assertIn("liveness/pack-never-fires", report.checks)

    def test_require_clean_raises(self):
        bad = {"bad.yml": b"rules:\n  - {name: oops}\n"}
        report = plint.lint_capability_rule_files(bad)
        self.assertFalse(report.clean)
        with self.assertRaises(plint.PackLintError):
            plint.require_clean(report)

    def test_require_clean_passes(self):
        report = plint.lint_capability_rule_files(dict(GOOD_RULES))
        self.assertIsNone(plint.require_clean(report))

    def test_for_check(self):
        bad = {"bad.yml": b"rules:\n  - {name: oops}\n"}
        report = plint.lint_capability_rule_files(bad)
        sub = report.for_check("sanity/uncompilable-pack")
        self.assertEqual(len(sub), 1)
        self.assertEqual(sub[0].check, "sanity/uncompilable-pack")
        self.assertEqual(report.for_check("safety/vacuous-leaf"), ())

    def test_summary_names_rule_and_check(self):
        bad = {"bad.yml": b"rules:\n  - {name: oops}\n"}
        report = plint.lint_capability_rule_files(bad)
        summary = report.summary()
        self.assertIn("sanity/uncompilable-pack", summary)
        self.assertIn("pack", summary)

    def test_valid_perm_pack_clean(self):
        report = plint.lint_perm_pack(PERM_MODEL, PERM_POLICY)
        self.assertTrue(report.clean, report.summary())

    def test_perm_lint_accepts_bytes(self):
        report = plint.lint_perm_pack(PERM_MODEL.encode("utf-8"),
                                      PERM_POLICY.encode("utf-8"))
        self.assertTrue(report.clean, report.summary())


class CapabilityLintTest(unittest.TestCase):
    def test_vacuous_rule(self):
        files = {"v0.yml": _rule_doc(
            "impossible", "capability/egress/impossible",
            _ind("and:\n  - pattern: \"^aaa\"\n  - pattern: \"^bbb\"")
        ).encode("utf-8")}
        report = plint.lint_capability_rule_files(files)
        self.assertTrue(_has(report, "safety/unsatisfiable-rule"))

    def test_dead_match_ref(self):
        files = dict(GOOD_RULES)
        files["r3.yml"] = _rule_doc(
            "dead composite", "capability/egress/dead",
            _ind("and:\n  - match: capability/nonexistent/*\n"
                 "  - import: socket")).encode("utf-8")
        report = plint.lint_capability_rule_files(files)
        self.assertTrue(_has(report, "safety/dead-match-ref"))

    def test_uncompilable_pack(self):
        report = plint.lint_capability_rule_files(
            {"bad.yml": b"rules:\n  - {name: oops}\n"})
        self.assertTrue(_has(report, "sanity/uncompilable-pack"))

    def test_never_fires_pack(self):
        files = {"v0.yml": _rule_doc(
            "impossible", "capability/egress/impossible",
            _ind("and:\n  - pattern: \"^aaa\"\n  - pattern: \"^bbb\"")
        ).encode("utf-8")}
        report = plint.lint_capability_rule_files(files)
        self.assertTrue(_has(report, "liveness/pack-never-fires"))


class PermLintTest(unittest.TestCase):
    def test_shadowed_row(self):
        policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: "*"
      vel_limit: 999999999
      eft: allow
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
"""
        report = plint.lint_perm_pack(PERM_MODEL, policy)
        self.assertTrue(_has(report, "safety/shadowed-row", "row[1]"),
                        report.summary())

    def test_contradictory_pair(self):
        model = PERM_MODEL.replace(
            'effect: "some(where (p_eft == allow))"',
            'effect: "some(where (p_eft == allow)) && '
            '!some(where (p_eft == deny))"')
        policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: deny
"""
        report = plint.lint_perm_pack(model, policy)
        self.assertTrue(_has(report, "safety/contradictory-pair"),
                        report.summary())

    def test_vacuous_row(self):
        # A row whose matcher demands velocity_1m both above and
        # below the same limit can never match: vacuous.
        model = PERM_MODEL.replace(
            """        -
          lte:
            -
              req: velocity_1m
            -
              pol: vel_limit""",
            """        -
          and:
            -
              gt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit
            -
              lt:
                -
                  req: velocity_1m
                -
                  pol: vel_limit""")
        policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: send_email
      vel_limit: 5
      eft: allow
"""
        report = plint.lint_perm_pack(model, policy)
        self.assertTrue(_has(report, "safety/vacuous-row", "row[0]"),
                        report.summary())

    def test_trivially_denies_all(self):
        policy = """\
perm_policy: sasanam-perm/v1
policies:
  allow: []
"""
        report = plint.lint_perm_pack(PERM_MODEL, policy)
        self.assertTrue(
            _has(report, "liveness/trivially-denies-all"),
            report.summary())

    def test_default_allow(self):
        model = PERM_MODEL.replace("default_verdict: deny",
                                   "default_verdict: allow")
        report = plint.lint_perm_pack(model, PERM_POLICY)
        self.assertTrue(_has(report, "sanity/default-allow"),
                        report.summary())


class ShippedFixturesTest(unittest.TestCase):
    def test_shipped_capability_rules_lint_clean(self):
        paths = sorted(glob.glob(os.path.join(
            REPO_ROOT, "capability_rules", "*.yml")))
        self.assertTrue(paths, "no shipped capability rule files found")
        files = {}
        for path in paths:
            with open(path, "rb") as fh:
                files[os.path.basename(path)] = fh.read()
        report = plint.lint_capability_rule_files(files)
        self.assertTrue(report.clean,
                        "shipped rules must lint clean:\n%s"
                        % (report.summary(),))


def _digests(members):
    return {mid: "sha256:" + hashlib.sha256(data).hexdigest()
            for mid, data in members.items()}


def _mint_rule_pack(keyset, signers, members, version=1):
    return rp.mint_rule_pack(
        keyset, signers, rules=_digests(members), pack_version=version,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=1)


def _perm_keyset_pair():
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_PERM_PACK)
    ks, _ = rotate_keyset(ks, _SEED2, _SEED1)
    return ks, [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]


def _mint_perm_pack(keyset, signers, model, policy, version):
    return perm.mint_perm_pack(
        keyset, signers, model_bytes=model.encode("utf-8"),
        policy_bytes=policy.encode("utf-8"), pack_version=version,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=2)


SHADOWED_POLICY = """\
perm_policy: sasanam-perm/v1
policies:
  allow:
    -
      tool_pat: "*"
      vel_limit: 999999999
      eft: allow
    -
      tool_pat: send_email
      vel_limit: 999999999
      eft: allow
"""


class LoaderGraduationTest(unittest.TestCase):
    def setUp(self):
        self.keyset, _ = new_keyset(
            _SEED1, purpose=rp.KEYSET_PURPOSE_PERM_PACK)
        self.keyset, _ = rotate_keyset(self.keyset, _SEED2, _SEED1)
        self.signers = [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]

    def _loader(self, **kw):
        return pload.PackLoader(self.keyset, "perm-test", **kw)

    def _present(self, loader, model, policy, version):
        doc = _mint_perm_pack(self.keyset, self.signers, model,
                              policy, version)
        members = {"perm-model.yml": model.encode("utf-8"),
                   "perm-policy.yml": policy.encode("utf-8")}
        return loader.present(doc, members, now=NOW)

    def test_default_is_log_only(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        self.assertEqual(loader.enforcement_mode, "log_only")

    def test_bad_enforcement_mode_refused(self):
        with self.assertRaises(pload.PackActivationError) as ctx:
            self._loader(
                purpose=rp.KEYSET_PURPOSE_PERM_PACK,
                format_tag=rp.PERM_PACK_FORMAT,
                enforcement_mode="permissive")
        self.assertEqual(ctx.exception.code, "bad-enforcement-mode")

    def test_bool_enforcement_mode_refused(self):
        with self.assertRaises(pload.PackActivationError):
            self._loader(
                purpose=rp.KEYSET_PURPOSE_PERM_PACK,
                format_tag=rp.PERM_PACK_FORMAT,
                enforcement_mode=True)

    def test_log_only_loads_lint_failed_with_marker(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        active = self._present(loader, PERM_MODEL, SHADOWED_POLICY, 1)
        self.assertTrue(active.lint_failed)
        self.assertTrue(active.lint_violations)
        self.assertTrue(any(v.check == "safety/shadowed-row"
                            for v in active.lint_violations))
        self.assertIs(loader.current, active)

    def test_clean_pack_has_no_marker(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        active = self._present(loader, PERM_MODEL, PERM_POLICY, 1)
        self.assertFalse(active.lint_failed)
        self.assertEqual(active.lint_violations, ())

    def test_enforce_refuses_lint_failed(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT,
            enforcement_mode="enforce")
        with self.assertRaises(pload.PackActivationError) as ctx:
            self._present(loader, PERM_MODEL, SHADOWED_POLICY, 1)
        self.assertEqual(ctx.exception.code, "pack-lint-failed")
        self.assertIsNone(loader.current)
        codes = [f["code"] for f in loader.activation_failures]
        self.assertIn("pack-lint-failed", codes)

    def test_enforce_refusal_preserves_prior_pack(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        good = self._present(loader, PERM_MODEL, PERM_POLICY, 1)
        loader.promote_to_enforce(["op-a", "op-b"])
        with self.assertRaises(pload.PackActivationError):
            self._present(loader, PERM_MODEL, SHADOWED_POLICY, 2)
        self.assertIs(loader.current, good)
        self.assertEqual(loader.current.version, 1)

    def test_promote_needs_two_distinct_operators(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        self._present(loader, PERM_MODEL, PERM_POLICY, 1)
        for bad in (["solo"], ["op-a", "op-a"], [], "op-a",
                    ["op-a", ""], ["op-a", True], [True, "op-b"]):
            with self.assertRaises(pload.PackActivationError,
                                   msg="ceremony %r" % (bad,)):
                loader.promote_to_enforce(bad)
        self.assertEqual(loader.enforcement_mode, "log_only")
        loader.promote_to_enforce(["op-a", "op-b"])
        self.assertEqual(loader.enforcement_mode, "enforce")

    def test_promote_without_active_pack_refused(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        with self.assertRaises(pload.PackActivationError) as ctx:
            loader.promote_to_enforce(["op-a", "op-b"])
        self.assertEqual(ctx.exception.code, "no-active-pack")

    def test_promote_with_lint_failed_pack_refused(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        self._present(loader, PERM_MODEL, SHADOWED_POLICY, 1)
        with self.assertRaises(pload.PackActivationError) as ctx:
            loader.promote_to_enforce(["op-a", "op-b"])
        self.assertEqual(ctx.exception.code, "pack-lint-failed")
        self.assertEqual(loader.enforcement_mode, "log_only")

    def test_demote_to_log_only(self):
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        self._present(loader, PERM_MODEL, PERM_POLICY, 1)
        loader.promote_to_enforce(["op-a", "op-b"])
        with self.assertRaises(pload.PackActivationError):
            loader.demote_to_log_only(True)
        loader.demote_to_log_only("op-a")
        self.assertEqual(loader.enforcement_mode, "log_only")
        modes = [m["mode"] for m in loader.mode_changes]
        self.assertEqual(modes, ["enforce", "log_only"])

    def test_changed_pack_is_relinted(self):
        # A pack whose bytes changed after promotion is linted fresh:
        # lint success is never inherited from an older version.
        loader = self._loader(
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
        self._present(loader, PERM_MODEL, PERM_POLICY, 1)
        loader.promote_to_enforce(["op-a", "op-b"])
        with self.assertRaises(pload.PackActivationError) as ctx:
            self._present(loader, PERM_MODEL, SHADOWED_POLICY, 2)
        self.assertEqual(ctx.exception.code, "pack-lint-failed")
        # And a clean v3 still activates under ENFORCE.
        v3 = self._present(loader, PERM_MODEL, PERM_POLICY, 3)
        self.assertFalse(v3.lint_failed)
        self.assertEqual(loader.current.version, 3)


class PermMarkerTest(unittest.TestCase):
    def test_decide_marks_lint_failed_models(self):
        ks, signers = _perm_keyset_pair()
        loader = perm.new_perm_pack_loader(ks)
        doc = _mint_perm_pack(ks, signers, PERM_MODEL, SHADOWED_POLICY,
                              1)
        active = loader.present(
            doc, {"perm-model.yml": PERM_MODEL.encode("utf-8"),
                  "perm-policy.yml": SHADOWED_POLICY.encode("utf-8")},
            now=NOW)
        model = perm.load_perm_from_active_pack(active)
        self.assertTrue(model.lint_failed)
        verdict, screen, detail = model.decide(
            {"tool_name": "send_email", "velocity_1m": 0})
        self.assertTrue(detail.get("pack_lint_failed"))
        self.assertIn("matched_rows", detail)

    def test_marker_unstrippable_by_request(self):
        ks, signers = _perm_keyset_pair()
        loader = perm.new_perm_pack_loader(ks)
        doc = _mint_perm_pack(ks, signers, PERM_MODEL, SHADOWED_POLICY,
                              1)
        active = loader.present(
            doc, {"perm-model.yml": PERM_MODEL.encode("utf-8"),
                  "perm-policy.yml": SHADOWED_POLICY.encode("utf-8")},
            now=NOW)
        model = perm.load_perm_from_active_pack(active)
        with self.assertRaises(perm.PermError):
            model.decide({"tool_name": "send_email", "velocity_1m": 0,
                          "pack_lint_failed": False})

    def test_clean_model_has_no_marker(self):
        model = perm.compile_perm_model(PERM_MODEL, PERM_POLICY)
        self.assertFalse(model.lint_failed)
        _, _, detail = model.decide({"tool_name": "read_file",
                                     "velocity_1m": 0})
        self.assertNotIn("pack_lint_failed", detail)
        self.assertEqual(set(detail), {"matched_rows"})

    def test_nonbool_lint_failed_refused(self):
        model = perm.compile_perm_model(PERM_MODEL, PERM_POLICY)
        with self.assertRaises(perm.PermError):
            perm.compile_perm_model(PERM_MODEL, PERM_POLICY,
                                    lint_failed="yes")


class ManifestMarkerTest(unittest.TestCase):
    def _store(self, lint_failed):
        from gov import capability_rules as cr
        from gov import ed25519 as _ed
        pack = cr.load_pack_files(dict(GOOD_RULES))
        content = b"hello world\n"
        seed = b"\x41" * 32
        manifest = cm.make_manifest("s", content, capabilities={},
                                    kid="k1", seed=seed)
        return cm.ManifestStore(
            keys={"k1": _ed.publickey(seed)},
            manifests={"s": manifest},
            capability_pack=pack,
            capability_pack_lint_failed=lint_failed), content

    def test_lint_failed_pack_marks_results(self):
        store, content = self._store(True)
        self.assertTrue(store.capability_pack_lint_failed)
        ok, detail = cm.verify_skill_manifest("s", content, store)
        self.assertTrue(ok)
        self.assertIn("pack-lint-failed", detail)

    def test_clean_pack_keeps_exact_contract(self):
        store, content = self._store(False)
        ok, detail = cm.verify_skill_manifest("s", content, store)
        self.assertEqual((ok, detail), (True, "clean"))

    def test_nonbool_flag_refused(self):
        with self.assertRaises(ValueError):
            cm.ManifestStore(capability_pack_lint_failed="yes")


if __name__ == "__main__":
    unittest.main()
