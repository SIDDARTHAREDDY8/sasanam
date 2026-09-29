"""Unit tests for the capa-style capability rule engine (wave-200).

Covers: strict compile refusals (top-level not, unknown nodes,
unknown match targets, duplicate namespaces, dependency cycles,
bad scopes, invalid regex), topological ordering, module and bundle
evaluation, the 1:1 flat-lint migration (byte-identical detections
on a fixture corpus for the primitive rules), the composite
credential-bearing-egress rule, the mixed-trust bundle composition
rule (fires cross-module, not same-module), review-time diffing,
and fail-closed evaluation on hostile input.

$0 spend, synthetic/local deterministic only. No network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import capability_rules as cr  # noqa: E402
from gov import capability_manifests as cm  # noqa: E402


def _pack(*docs):
    files = {}
    for i, doc in enumerate(docs):
        files["r%d.yml" % i] = doc.encode("utf-8")
    return cr.load_pack_files(files)


_ONE_RULE = """\
rules:
  -
    meta:
      name: "egress socket"
      namespace: capability/egress/socket
      scopes:
        static: module
      capability_tags: [capability/egress]
      label: "import socket"
    features:
      pattern: "\\\\bimport\\\\s+socket\\\\b"
"""

_FIXTURES = {
    "egress": b"import socket\ns = socket.create_connection(('h', 80))\n",
    "clean": b"def add(a, b):\n    return a + b\n",
    "env": b"import os\ntok = os.environ['API_TOKEN']\n",
    "tool": b"@tool\ndef tool_search(q):\n    pass\n",
    "exec": b"import subprocess\nsubprocess.run(['ls'])\n",
    "fs": b"open('/etc/passwd').read()\n",
    "secrets": b"import getpass\np = getpass.getpass('pw: ')\n",
    "multi": b"import socket, subprocess, os\nopen('/tmp/x').write(os.environ['K'])\n",
}


def _shipping_pack():
    """The real shipped pack files, compiled."""
    import glob
    files = {}
    base = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "capability_rules")
    for path in sorted(glob.glob(os.path.join(base, "*.yml"))):
        with open(path, "rb") as f:
            files[os.path.basename(path)] = f.read()
    return cr.load_pack_files(files)


class CompileStrictnessTest(unittest.TestCase):
    def test_top_level_not_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: bad
      namespace: capability/x/bad
      scopes: {static: module}
      capability_tags: []
    features:
      not:
        pattern: "x"
""")

    def test_scopes_string_from_flow_map_refused(self):
        # The restricted YAML subset has no flow maps: the parser
        # reads ``{static: module}`` as a literal string, and the
        # compiler refuses the non-mapping scopes loud -- a scope
        # can never be silently misread.
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: bad
      namespace: capability/x/bad
      scopes: {static: module}
      capability_tags: []
    features:
      pattern: "x"
""")

    def test_unknown_node_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: bad
      namespace: capability/egress/bad
      scopes:
        static: module
      capability_tags: []
    features:
      frobnicate: "x"
""")

    def test_unknown_match_target_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: bad
      namespace: capability/egress/bad
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/nonexistent/rule
""")

    def test_duplicate_namespace_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack(_ONE_RULE, _ONE_RULE)

    def test_dependency_cycle_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: a
      namespace: capability/x/a
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/x/b
  -
    meta:
      name: b
      namespace: capability/x/b
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/x/a
""")

    def test_bad_scope_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack(_ONE_RULE.replace("static: module",
                                    "static: function"))

    def test_invalid_regex_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack(_ONE_RULE.replace(
                'pattern: "\\\\bimport\\\\s+socket\\\\b"',
                'pattern: "([unterminated"'))

    def test_leaf_at_bundle_scope_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: bad
      namespace: capability/x/bad
      scopes:
        static: bundle
      capability_tags: []
    features:
      pattern: "x"
""")

    def test_match_at_module_scope_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: bad
      namespace: capability/egress/bad
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/egress/socket
""")

    def test_missing_features_refused(self):
        with self.assertRaises(cr.RuleError):
            _pack("""\
rules:
  -
    meta:
      name: bad
      namespace: capability/egress/bad
      scopes:
        static: module
      capability_tags: []
""")

    def test_topological_order(self):
        pack = _pack("""\
rules:
  -
    meta:
      name: composite
      namespace: capability/egress/composite
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/egress/socket
  -
    meta:
      name: prim
      namespace: capability/egress/socket
      scopes:
        static: module
      capability_tags: []
    features:
      pattern: "socket"
""")
        order = [r.namespace for r in pack.rules]
        # The composite depends on the primitive: it evaluates after,
        # even though it was declared first.
        self.assertLess(order.index("capability/egress/socket"),
                        order.index("capability/egress/composite"))

    def test_prefix_ref_orders_after_primitives(self):
        pack = _pack("""\
rules:
  -
    meta:
      name: composite
      namespace: capability/egress/composite
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/egress/*
  -
    meta:
      name: prim
      namespace: capability/egress/socket
      scopes:
        static: module
      capability_tags: []
    features:
      pattern: "socket"
""")
        order = [r.namespace for r in pack.rules]
        self.assertLess(order.index("capability/egress/socket"),
                        order.index("capability/egress/composite"))


class MigrationEquivalenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        full = _shipping_pack()
        prim_files = {}
        import glob
        base = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "capability_rules")
        for path in sorted(glob.glob(os.path.join(base, "*.yml"))):
            name = os.path.basename(path)
            if name in ("composite.yml", "composition.yml"):
                continue
            with open(path, "rb") as f:
                prim_files[name] = f.read()
        cls.prim_pack = cr.load_pack_files(prim_files)
        cls.full_pack = full

    def test_primitive_rules_byte_identical_to_flat_lint(self):
        for name, content in _FIXTURES.items():
            flat = cm.detect_capabilities(content)
            ruled = cr.detect_capabilities(content, self.prim_pack)
            self.assertEqual(ruled, flat,
                             "migration differs on %r" % (name,))

    def test_flat_names_vocabulary_unchanged(self):
        for name, content in _FIXTURES.items():
            flat = cm.detect_capabilities(content)
            ruled = cr.detect_capabilities(content, self.prim_pack)
            for cat in cm.CATEGORIES:
                self.assertEqual(ruled[cat]["names"],
                                 flat[cat]["names"])

    def test_composite_adds_label_by_design(self):
        content = (b"import socket\nimport getpass\n"
                   b"s = socket.create_connection(('h', 80))\n")
        ruled = cr.detect_capabilities(content, self.full_pack)
        self.assertIn("credential-bearing egress",
                      ruled["egress"]["signals"])

    def test_evaluator_never_raises_on_hostile_input(self):
        pack = self.full_pack
        for hostile in (b"\xff\xfe\x00bad", b"", "not-bytes",
                        None, 12345, b"\x00" * 10000):
            try:
                cr.detect_capabilities(hostile, pack)
            except Exception as exc:
                self.fail("detect raised on %r: %s" % (hostile, exc))


class CompositeRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = _shipping_pack()

    def test_credential_bearing_egress_module(self):
        ns, _ev = cr.evaluate_module(
            self.pack,
            b"import socket\nimport getpass\n"
            b"s = socket.create_connection(('h', 80))\n")
        self.assertIn("capability/egress/credential-bearing", ns)

    def test_egress_alone_no_composite(self):
        ns, _ev = cr.evaluate_module(
            self.pack, b"import socket\ns = socket.socket()\n")
        self.assertNotIn("capability/egress/credential-bearing", ns)

    def test_mixed_trust_fires_cross_module(self):
        bns, _res = cr.evaluate_bundle(self.pack, {
            "a": b"import getpass\np = getpass.getpass()\n",
            "b": b"import socket\ns = socket.create_connection(('h', 80))\n",
        })
        self.assertIn("capability/composition/mixed-trust-exfil", bns)

    def test_mixed_trust_quiet_same_module(self):
        bns, _res = cr.evaluate_bundle(self.pack, {
            "a": b"import socket\nimport getpass\n"
                 b"s = socket.create_connection(('h', 80))\n",
        })
        self.assertNotIn("capability/composition/mixed-trust-exfil",
                         bns)

    def test_mixed_trust_quiet_no_egress(self):
        bns, _res = cr.evaluate_bundle(self.pack, {
            "a": b"import getpass\np = getpass.getpass()\n",
            "b": b"def f():\n    return 1\n",
        })
        self.assertNotIn("capability/composition/mixed-trust-exfil",
                         bns)

    def test_diff_namespaces(self):
        d = cr.diff_namespaces(_FIXTURES["clean"],
                               _FIXTURES["egress"], self.pack)
        self.assertIn("capability/egress/prim-00", d["added"])
        self.assertEqual(d["removed"], [])
        d2 = cr.diff_namespaces(_FIXTURES["egress"],
                                _FIXTURES["clean"], self.pack)
        self.assertEqual(d2["added"], [])

    def test_evaluate_bundle_rejects_bad_input(self):
        with self.assertRaises(cr.RuleError):
            cr.evaluate_bundle(self.pack, {})
        with self.assertRaises(cr.RuleError):
            cr.evaluate_bundle(self.pack, ["not", "a", "dict"])


class ManifestWiringTest(unittest.TestCase):
    """verify_skill_manifest with and without a rule pack."""

    def _store(self, pack, content, capabilities):
        from gov import capability_manifests as cm
        from gov import ed25519 as _ed
        _SEED = b"\x41" * 32
        manifest = cm.make_manifest(
            "skill-x", content, capabilities=capabilities,
            kid="k1", seed=_SEED)
        store = cm.ManifestStore(
            keys={"k1": _ed.publickey(_SEED)},
            manifests={"skill-x": manifest},
            capability_pack=pack)
        return store

    def test_flat_lint_when_no_pack(self):
        from gov import capability_manifests as cm
        content = b"import socket\n"
        store = self._store(None, content, {"egress": ["import socket"]})
        ok, detail = cm.verify_skill_manifest("skill-x", content,
                                             store)
        self.assertTrue(ok, detail)

    def test_rule_pack_detects_composite_drift(self):
        from gov import capability_manifests as cm
        pack = _shipping_pack()
        content = (b"import socket\nimport getpass\n"
                   b"s = socket.create_connection(('h', 80))\n")
        # The skill declares NO egress at all: the primitive
        # "import socket" signal and the composite
        # "credential-bearing egress" signal both fire, and the
        # empty egress grant list fails closed.
        store = self._store(pack, content,
                            {"secrets": ["getpass"]})
        ok, detail = cm.verify_skill_manifest("skill-x", content,
                                             store)
        self.assertFalse(ok)
        self.assertIn("capability-drift", detail)

    def test_rule_pack_clean_when_egress_granted(self):
        from gov import capability_manifests as cm
        pack = _shipping_pack()
        content = (b"import socket\nimport getpass\n"
                   b"s = socket.create_connection(('h', 80))\n")
        # Egress is a category-level grant in the inherited
        # contract (only env/tools are name-checked): any egress
        # grant covers the composite label. The label stays
        # review-visible in the signals.
        store = self._store(
            pack, content,
            {"egress": ["import socket"],
             "secrets": ["getpass"]})
        ok, detail = cm.verify_skill_manifest("skill-x", content,
                                             store)
        self.assertTrue(ok, detail)

    def test_evaluator_exception_fails_load_closed(self):
        # An evaluator bug must REFUSE the load, never weaken
        # detection into a vacuous pass.
        import gov.capability_rules as crmod
        from gov import capability_manifests as cm
        pack = _shipping_pack()
        content = b"import socket\n"
        store = self._store(pack, content,
                            {"egress": ["import socket"]})
        real_eval = crmod._eval_stmt

        def _boom(*args, **kwargs):
            raise RuntimeError("simulated evaluator bug")

        crmod._eval_stmt = _boom
        try:
            # Strict seam raises loud.
            with self.assertRaises(cr.RuleError):
                crmod.detect_capabilities(content, pack,
                                          strict=True)
            # Non-strict scanning seam stays total.
            self.assertEqual(
                crmod.detect_capabilities(content, pack),
                {c: {"signals": [], "names": []}
                 for c in cm.CATEGORIES})
            # The load-time seam refuses closed.
            ok, detail = cm.verify_skill_manifest("skill-x",
                                                 content, store)
            self.assertFalse(ok)
            self.assertEqual(detail,
                             "manifest-capability-eval-failed")
        finally:
            crmod._eval_stmt = real_eval

    def test_non_pack_refused_at_store_construction(self):
        from gov import capability_manifests as cm
        with self.assertRaises(TypeError):
            cm.ManifestStore(capability_pack={"not": "a pack"})


if __name__ == "__main__":
    unittest.main()
