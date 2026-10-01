"""Unit tests for gov/compliance_emitter.py (wave-254 lane 3).

TDD: these pin the public seams -- validation, the three emitters,
determinism, digest binding, and the honesty boundary (the emitter
runs over evidence; it does not re-verify it).
"""

import json
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import compliance_emitter as ce  # noqa: E402


def _src(**over):
    src = {
        "id": "SAS-COMP-001",
        "title": "Permit lifecycle evidence is tamper-evident",
        "description": "Bound permits are journaled and exportable.",
        "mappings": [
            {"kind": "code", "ref": "permit-journal-misuse",
             "rationale": "refusal path for malformed journal events"},
            {"kind": "mechanism", "ref": "chained-audit-log",
             "rationale": "hash-chained append-only log"},
            {"kind": "posture_track", "ref": "durability",
             "rationale": "durability track covers journal health"},
        ],
    }
    src.update(over)
    return src


class TestValidation(unittest.TestCase):

    def test_valid_source_normalizes(self):
        out = ce.validate_source(_src())
        self.assertEqual(out["id"], "SAS-COMP-001")
        self.assertEqual(len(out["mappings"]), 3)
        # The normalized copy is a deep copy: mutating it must not
        # touch the caller's source.
        src = _src()
        out = ce.validate_source(src)
        out["mappings"][0]["ref"] = "MUTATED"
        self.assertEqual(src["mappings"][0]["ref"],
                         "permit-journal-misuse")

    def test_unlinked_claim_refused(self):
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.validate_source(_src(mappings=[]))
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-unlinked-claim")

    def test_unknown_code_refused(self):
        src = _src(mappings=[{"kind": "code", "ref": "nope",
                              "rationale": "x"}])
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.validate_source(src)
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-unknown-code")

    def test_unknown_mechanism_refused(self):
        src = _src(mappings=[{"kind": "mechanism", "ref": "nope",
                              "rationale": "x"}])
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.validate_source(src)
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-unknown-mechanism")

    def test_unknown_track_refused(self):
        src = _src(mappings=[{"kind": "posture_track", "ref": "nope",
                              "rationale": "x"}])
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.validate_source(src)
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-unknown-track")

    def test_finding_needs_index(self):
        src = _src(mappings=[{"kind": "finding", "ref": "F214",
                              "rationale": "x"}])
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.validate_source(src)
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-unknown-finding")

    def test_finding_status_attached(self):
        src = _src(mappings=[{"kind": "finding", "ref": "F214",
                              "rationale": "x"}])
        out = ce.validate_source(src, findings={"F214": "open"})
        self.assertEqual(out["mappings"][0]["finding_status"], "open")

    def test_malformed_findings_index_refused(self):
        src = _src(mappings=[{"kind": "finding", "ref": "F214",
                              "rationale": "x"}])
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.validate_source(src, findings={"F214": "bogus"})
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-malformed")

    def test_unknown_kind_refused(self):
        src = _src(mappings=[{"kind": "widget", "ref": "x",
                              "rationale": "x"}])
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.validate_source(src)
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-malformed")

    def test_missing_rationale_refused(self):
        src = _src(mappings=[{"kind": "code",
                              "ref": "permit-journal-misuse"}])
        with self.assertRaises(ce.ComplianceEmitterError):
            ce.validate_source(src)


class TestEmitters(unittest.TestCase):

    def test_oscal_shape(self):
        pkg = ce.emit_oscal(_src(),
                            generated_at="2026-10-01T00:00:00Z")
        cd = pkg["component-definition"]
        self.assertEqual(cd["metadata"]["oscal-version"], "1.1.3")
        self.assertIn("decision support", cd["metadata"]["remarks"])
        props = {p["name"]: p["value"]
                 for p in cd["metadata"]["props"]}
        self.assertEqual(props["x-compliance-source-sha256"],
                         ce.source_content_digest(_src()))
        comp = cd["components"][0]
        reqs = comp["control-implementations"][0][
            "implemented-requirements"]
        self.assertEqual(len(reqs), 3)
        kinds = {p["value"] for r in reqs for p in r["props"]
                 if p["name"] == "x-evidence-kind"}
        self.assertEqual(kinds, {"code", "mechanism", "posture_track"})

    def test_oscal_deterministic(self):
        kw = {"generated_at": "2026-10-01T00:00:00Z"}
        self.assertEqual(ce.emit_oscal(_src(), **kw),
                         ce.emit_oscal(_src(), **kw))

    def test_oscal_digest_sensitive(self):
        a = ce.emit_oscal(_src(),
                          generated_at="2026-10-01T00:00:00Z")
        src = _src()
        src["title"] = "Tampered title"
        b = ce.emit_oscal(src, generated_at="2026-10-01T00:00:00Z")
        pa = {p["name"]: p["value"]
              for p in a["component-definition"]["metadata"]["props"]}
        pb = {p["name"]: p["value"]
              for p in b["component-definition"]["metadata"]["props"]}
        self.assertNotEqual(pa["x-compliance-source-sha256"],
                            pb["x-compliance-source-sha256"])

    def test_markdown_traceable(self):
        md = ce.emit_markdown(_src())
        for token in ("SAS-COMP-001", "permit-journal-misuse",
                      "chained-audit-log", "durability"):
            self.assertIn(token, md)
        self.assertIn("decision support", md)

    def test_json_canonical_and_honest(self):
        js = ce.emit_json(_src())
        pkg = json.loads(js)
        self.assertEqual(pkg["source_digest"],
                         ce.source_content_digest(_src()))
        for m in pkg["mappings"]:
            self.assertFalse(m["verified_by_emitter"])
            self.assertIn("did not re-verify", m["emitter_note"])
        # Byte-identical across runs (no wall clock in the artifact).
        self.assertEqual(js, ce.emit_json(_src()))

    def test_emit_dispatcher(self):
        self.assertEqual(ce.emit(_src(), "json"), ce.emit_json(_src()))
        self.assertIsInstance(ce.emit(_src(), "markdown"), str)
        self.assertIsInstance(ce.emit(_src(), "oscal"), dict)
        with self.assertRaises(ce.ComplianceEmitterError) as ctx:
            ce.emit(_src(), "yaml")
        self.assertEqual(ctx.exception.code,
                         "compliance-emitter-unknown-format")

    def test_digest_binds_finding_status(self):
        src = _src(mappings=[{"kind": "finding", "ref": "F214",
                              "rationale": "x"}])
        d_open = ce.source_content_digest(
            src, findings={"F214": "open"})
        d_closed = ce.source_content_digest(
            src, findings={"F214": "closed"})
        self.assertNotEqual(d_open, d_closed)


if __name__ == "__main__":
    unittest.main()
