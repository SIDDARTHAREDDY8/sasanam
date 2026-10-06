#!/usr/bin/env python3
"""Wave-340 lane 3 hygiene probes (R9 docstring + pin).

Base: `9351ab86` (wave-339 merge). Pin 2130 -> 2131 (+1 code).
Footer open F427 / next F430.

P1 (R9): the non-separable hybrid rule is recorded in the
  ``gov/pq_envelope.py`` module docstring: both algorithms sign a value
  committing to the algorithm set, because side-by-side JSON hybrids
  are broken by field deletion. (Wave-339 prospectus carry-forward.)
P2 (pin): TAXONOMY_PIN == 2134 and the registry holds 2127 codes.

Run standalone with green checks on, fresh TMPDIR.

Verdicts: HELD = behavior matches the pin; BREAK = genuine defect;
ERROR = probe/harness problem.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)

_R9_MARKERS = (
    "non-separable",
    "committing to the algorithm set",
    "field deletion",
)


def p1_r9_docstring_rule():
    """R9: non-separable hybrid rule recorded in gov/pq_envelope.py."""
    import gov.pq_envelope as mod
    doc = mod.__doc__ or ""
    missing = [m for m in _R9_MARKERS if m not in doc]
    if missing:
        return "BREAK", "P1", ("R9 rule absent from pq_envelope docstring; "
                                "missing: %s" % ", ".join(missing))
    return "HELD", "P1", "non-separable hybrid rule recorded in docstring"


def p2_pin():
    """TAXONOMY_PIN == 2134 and the registry holds 2127 codes."""
    from gov.decision_codes import TAXONOMY
    if TAXONOMY_PIN != 2134:
        return "BREAK", "P2", "TAXONOMY_PIN = %r, want 2134" % TAXONOMY_PIN
    if len(TAXONOMY) != 2134:
        return "BREAK", "P2", "registry has %d codes, want 2134" % len(TAXONOMY)
    return "HELD", "P2", "pin 2131; registry 2127 codes"


PROBES = [("P1", p1_r9_docstring_rule), ("P2", p2_pin)]


def main():
    breaks = held = errors = 0
    for pid, probe in PROBES:
        try:
            verdict, _pid, detail = probe()
        except Exception as exc:  # noqa: BLE001
            verdict, detail = "ERROR", "probe raised: %r" % exc
        print("[%s] %s: %s" % (verdict, pid, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
