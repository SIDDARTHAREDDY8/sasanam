#!/usr/bin/env python3
"""Red-first for F1248
(wave-409 lane 3 wrapper).

Thin wrapper re-exporting the wave-408 attack round 76 red-first
SHAPES/CONTROLS (evals/w408_f1248_redfirst.py). Filed 2026-10-11
04:35 UTC by wave-408 attack round 76 (local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree; on
the closed tree each shape is flagged.

Array.filter side-effect accumulation -- Accumulating inside an Array.filter predicate (S+=fromCharCode(c); return false). Disjoint from F1124 (map/every/some twins; F1124 filter requires return true) -- return-false form.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w408_f1248_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
