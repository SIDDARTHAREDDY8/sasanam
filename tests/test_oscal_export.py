"""Unit tests for gov.evidence.oscal_export (wave-174 lane 3).

Tests verify behavior through the public seams
(generate_oscal_component_definition / component_definition_json /
crosswalk_content_digest), never implementation internals.
"""

import json
import os
import sys
import unittest
import uuid

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov.evidence import (  # noqa: E402
    CONTROL_REGISTRY,
    FRAMEWORKS,
    MECHANISMS,
    component_definition_json,
    crosswalk_content_digest,
    generate_oscal_component_definition,
    oscal_export,
)

T0 = "2026-09-28T12:00:00+00:00"


class TestPackageShape(unittest.TestCase):
    def test_top_level_key(self):
        pkg = generate_oscal_component_definition(generated_at=T0)
        self.assertEqual(set(pkg.keys()), {"component-definition"})

    def test_oscal_version_line(self):
        pkg = generate_oscal_component_definition(generated_at=T0)
        self.assertTrue(
            pkg["component-definition"]["metadata"]["oscal-version"].startswith("1.1."))

    def test_deterministic_uuids(self):
        a = generate_oscal_component_definition(generated_at=T0)
        b = generate_oscal_component_definition(generated_at=T0)
        ca = a["component-definition"]["components"]
        cb = b["component-definition"]["components"]
        self.assertEqual([c["uuid"] for c in ca], [c["uuid"] for c in cb])
        # And equal to the module's own deterministic scheme.
        for comp in ca:
            mid = next(p["value"] for p in comp["props"]
                       if p["name"] == "x-mechanism-id")
            self.assertEqual(comp["uuid"], str(uuid.uuid5(
                oscal_export._PACKAGE_NAMESPACE, "component\x00" + mid)))


class TestCompleteness(unittest.TestCase):
    def test_every_mechanism_is_a_component(self):
        comps = generate_oscal_component_definition(
            generated_at=T0)["component-definition"]["components"]
        ids = {next(p["value"] for p in c["props"]
                    if p["name"] == "x-mechanism-id") for c in comps}
        self.assertEqual(ids, {m["id"] for m in MECHANISMS})

    def test_mapping_count_matches_crosswalk(self):
        comps = generate_oscal_component_definition(
            generated_at=T0)["component-definition"]["components"]
        exported = sum(len(ci["implemented-requirements"])
                       for c in comps
                       for ci in c["control-implementations"])
        expected = sum(len(m["controls"]) for m in MECHANISMS)
        self.assertEqual(exported, expected)


class TestHonesty(unittest.TestCase):
    def _by_triple(self):
        comps = generate_oscal_component_definition(
            generated_at=T0)["component-definition"]["components"]
        out = {}
        for c in comps:
            mid = next(p["value"] for p in c["props"]
                       if p["name"] == "x-mechanism-id")
            for ci in c["control-implementations"]:
                for ir in ci["implemented-requirements"]:
                    out[(mid, ci["source"], ir["control-id"])] = ir
        return out

    def test_iso_rows_unverified_with_caveat(self):
        rows = self._by_triple()
        iso = [ir for k, ir in rows.items() if k[1] == "ISO-IEC-42001-2023"]
        self.assertTrue(iso, "expected ISO mappings in the export")
        for ir in iso:
            props = {p["name"]: p["value"] for p in ir["props"]}
            self.assertEqual(props["mapping-status"], "unverified")
            self.assertIn("licensed", props["x-verification-note"].lower())

    def test_disclaimer_in_remarks(self):
        md = generate_oscal_component_definition(
            generated_at=T0)["component-definition"]["metadata"]
        self.assertIn("not a certification", md["remarks"].lower())


class TestContentBinding(unittest.TestCase):
    def test_digest_stable_and_bound(self):
        self.assertEqual(crosswalk_content_digest(),
                         crosswalk_content_digest())
        md = generate_oscal_component_definition(
            generated_at=T0)["component-definition"]["metadata"]
        embedded = next(p["value"] for p in md["props"]
                        if p["name"] == "x-crosswalk-sha256")
        self.assertEqual(embedded, crosswalk_content_digest())

    def test_json_serialization_is_canonical(self):
        a = component_definition_json(generated_at=T0)
        b = component_definition_json(generated_at=T0)
        self.assertEqual(a, b)
        # Round-trips through JSON without loss.
        self.assertEqual(json.loads(a),
                         generate_oscal_component_definition(generated_at=T0))


class TestRegistryGrounding(unittest.TestCase):
    def test_every_exported_control_in_registry(self):
        comps = generate_oscal_component_definition(
            generated_at=T0)["component-definition"]["components"]
        for c in comps:
            for ci in c["control-implementations"]:
                self.assertIn(ci["source"], FRAMEWORKS)
                for ir in ci["implemented-requirements"]:
                    self.assertIn("%s:%s" % (ci["source"], ir["control-id"]),
                                  CONTROL_REGISTRY)


if __name__ == "__main__":
    unittest.main()
