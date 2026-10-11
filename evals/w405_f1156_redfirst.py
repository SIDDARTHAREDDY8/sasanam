#!/usr/bin/env python3
"""Red-first for F1156: F1124 residual -- no-return side-effect callbacks
(wave-405 lane 4 wrapper).

Thin wrapper re-exporting the wave-404 merge-audit red-first
SHAPES/CONTROLS (evals/w404_f1156_redfirst.py). Filed 2026-10-10
23:28 UTC by the wave-404 merge red-first audit (local validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree; on
the closed tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w404_f1156_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
