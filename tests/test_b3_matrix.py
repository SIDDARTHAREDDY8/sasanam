"""Wave-39 B3: standards-matrix consistency gate.

Every adversarial probe ID cited in docs/STANDARDS_MAPPING.md must
(1) exist in evals/scenarios/registry.yaml and
(2) be gate-registered (probe: evals/...), not delegated to the
realistic runner or missing. A stale or typo'd citation fails loudly.
"""
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "docs" / "STANDARDS_MAPPING.md"
REGISTRY = ROOT / "evals" / "scenarios" / "registry.yaml"

ID_RE = re.compile(r"\b(?:redteam|realagent)(?:\.[\w\-]+){2,}\b")


def cited_ids():
    ids = set()
    for m in ID_RE.finditer(MATRIX.read_text(encoding="utf-8")):
        sid = m.group(0)
        if sid.endswith("_"):
            # wildcard shorthand like redteam.b3.dsl_* -- not a citation
            continue
        ids.add(sid)
    return sorted(ids)


class TestB3MatrixConsistency(unittest.TestCase):
    def test_matrix_exists(self):
        self.assertTrue(MATRIX.exists(), "docs/STANDARDS_MAPPING.md missing")

    def test_cited_ids_registered_and_gate_run(self):
        scenarios = yaml.safe_load(
            REGISTRY.read_text(encoding="utf-8"))["scenarios"]
        by_id = {e["id"]: e for e in scenarios}
        stale, delegated = [], []
        for sid in cited_ids():
            entry = by_id.get(sid)
            if entry is None:
                stale.append(sid)
                continue
            probe = (entry.get("probe") or "")
            if not probe.startswith("evals/"):
                delegated.append((sid, probe or "<none>"))
        self.assertFalse(stale, "cited IDs missing from registry: %s"
                         % stale)
        self.assertFalse(delegated,
                         "cited IDs not gate-registered (delegated to "
                         "realistic runner): %s" % delegated)

    def test_green_controls_have_evidence_column(self):
        # Every GREEN row in the controls table must cite at least one
        # full registry ID; a GREEN claim with only wildcards is a hole.
        in_table = False
        for line in MATRIX.read_text(encoding="utf-8").splitlines():
            if line.startswith("| # | Control"):
                in_table = True
                continue
            if in_table and line.startswith("| C-"):
                cells = [c.strip() for c in line.split("|")]
                status, evidence = cells[9], cells[8]
                if status == "GREEN":
                    full = [m for m in ID_RE.finditer(evidence)
                            if not m.group(0).endswith("_")]
                    self.assertTrue(full,
                                    "GREEN row without a full probe ID: %s"
                                    % line[:60])


if __name__ == "__main__":
    unittest.main()
