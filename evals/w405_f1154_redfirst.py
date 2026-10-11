#!/usr/bin/env python3
"""Red-first for F1154 (wave-405 lane 2 wrapper).

Thin wrapper re-exporting the wave-404 attack round 72 red-first
SHAPES/CONTROLS (evals/w404_f1154_redfirst.py). Filed 2026-10-10
wave-404 (attack round 72, local validation, $0.00 model spend (0 paid
calls)). Prints BREAK on the open tree; on the closed tree each shape
is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w404_f1154_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
