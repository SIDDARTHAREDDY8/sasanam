#!/usr/bin/env python3
"""Red-first for F1124: side-effect higher-order callbacks (wave-404 lane 2 wrapper).

staging credential assembly through side-effect callbacks on higher-order methods beyond F1090's forEach/every coverage.
Thin wrapper re-exporting the wave-403 attack round 71 red-first
SHAPES/CONTROLS (evals/w403_f1124_redfirst.py). Filed 2026-10-10
18:13 UTC wave-403 (attack round 71, local validation, $0.00 model
spend (0 paid calls)). Prints BREAK on the open tree; on the closed
tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w403_f1124_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
