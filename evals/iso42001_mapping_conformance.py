#!/usr/bin/env python3
"""ISO/IEC 42001 Annex A mapping conformance battery (H21, wave-125 lane).

``docs/iso42001-mapping.json`` is the provisional regulator-shaped
mapping (reallocation stream 3): each Annex A control cites the
product mechanisms (``gov/*.py`` etc.) and tests (``tests/*.py``)
that implement it. Nothing ties the mapping to reality -- a
mechanism renamed or deleted would leave a stale citation, and the
drift would be silent.

This battery asserts, for every mapped control, that:
  1. every ``product_mechanisms`` path (the part before the first
     ": ") exists in the repo tree;
  2. every ``tests`` entry exists as a file in the repo tree.

Conformance result:
- GREEN = all 36 controls resolve; the mapping is conformant.
- RED   = drift found (stale mechanism or test reference), listed
          per control. Mapping drift must be fixed by updating the
          mapping (if the mechanism moved) or the code (if the
          mechanism was dropped unintentionally) -- never by
          deleting the citation silently.

The canonical-suite wrapper ``tests/test_iso42001_mapping.py``
imports ``check_conformance`` from this module, so mapping drift
fails the pre-push gates loudly (H21 acceptance).

$0 spend, synthetic/local. Deterministic (filesystem reads only).

Run:
  mkdir -p /tmp/gov-h21
  TMPDIR=/tmp/gov-h21 ~/workspace/.gov-venv/bin/python evals/iso42001_mapping_conformance.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-h21b ~/workspace/.gov-venv/bin/python evals/iso42001_mapping_conformance.py
"""

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-h21")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = Path(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAPPING_PATH = REPO_ROOT / "docs" / "iso42001-mapping.json"


def check_conformance(mapping_path=None):
    """Check the ISO 42001 mapping against the repo tree.

    Returns (ok: bool, problems: list[str], stats: dict).
    ``problems`` is empty when ok. Pure function over the
    filesystem; importable by the canonical-suite wrapper.
    """
    mp = Path(mapping_path) if mapping_path else MAPPING_PATH
    problems = []
    stats = {"controls": 0, "mechanisms": 0, "tests": 0}
    try:
        mapping = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return False, ["mapping file unreadable: %s (%s)" % (mp, e)], stats
    controls = mapping.get("controls")
    if not isinstance(controls, list) or not controls:
        return False, ["mapping has no controls list"], stats
    for c in controls:
        cid = c.get("id", "?")
        stats["controls"] += 1
        for pm in c.get("product_mechanisms", []):
            stats["mechanisms"] += 1
            # Format is "path: description".
            path = pm.split(":", 1)[0].strip()
            if not path:
                problems.append(
                    "%s: empty mechanism path in %r" % (cid, pm[:60]))
                continue
            if not (REPO_ROOT / path).exists():
                problems.append(
                    "%s: product_mechanism missing: %s" % (cid, path))
        for t in c.get("tests", []):
            stats["tests"] += 1
            if not (REPO_ROOT / t).exists():
                problems.append("%s: test missing: %s" % (cid, t))
    return (len(problems) == 0), problems, stats


def main():
    ok, problems, stats = check_conformance()
    print("H21 ISO-42001-MAPPING conformance: %d controls, %d mechanisms, "
          "%d tests checked" % (stats["controls"], stats["mechanisms"],
                                stats["tests"]))
    if ok:
        print("RESULT: GREEN -- mapping conformant, no drift.")
        return 0
    print("RESULT: RED -- mapping drift (%d problems):" % len(problems))
    for p in problems:
        print("  - %s" % p)
    return 1


if __name__ == "__main__":
    sys.exit(main())
