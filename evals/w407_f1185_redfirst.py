#!/usr/bin/env python3
"""Red-first for F1185: RegExp exec staged reads (sticky/global)
(wave-407 lane 1 wrapper).

Thin wrapper re-exporting the wave-406 attack round 74 red-first
SHAPES/CONTROLS (evals/w406_f1185_redfirst.py). Filed 2026-10-11
01:43 UTC by wave-406 attack round 74 (local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree; on
the closed tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w406_f1185_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
