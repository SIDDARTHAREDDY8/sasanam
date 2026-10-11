#!/usr/bin/env python3
"""Red-first for F1244
(wave-409 lane 3 wrapper).

Thin wrapper re-exporting the wave-408 attack round 76 red-first
SHAPES/CONTROLS (evals/w408_f1244_redfirst.py). Filed 2026-10-11
04:35 UTC by wave-408 attack round 76 (local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree; on
the closed tree each shape is flagged.

Reflect.ownKeys / getOwnPropertyNames staged reads -- Staging chars as indexed object properties and reading back via Reflect.ownKeys(O) or Object.getOwnPropertyNames(O) then map(k=>O[k]).join(''). Distinct from F1220 (filed: Object.keys) -- different methods.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w408_f1244_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
