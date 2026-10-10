#!/usr/bin/env python3
"""Red-first for F1130: manual iterator .next() loop (wave-404 lane 2 wrapper).

driving the iteration protocol manually (`.next()` loop) breaks F1119's for-of-anchored hook.
Thin wrapper re-exporting the wave-403 attack round 71 red-first
SHAPES/CONTROLS (evals/w403_f1130_redfirst.py). Filed 2026-10-10
18:13 UTC wave-403 (attack round 71, local validation, $0.00 model
spend (0 paid calls)). Prints BREAK on the open tree; on the closed
tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w403_f1130_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
