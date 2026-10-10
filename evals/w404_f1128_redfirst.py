#!/usr/bin/env python3
"""Red-first for F1128: reverse-iteration prepend accumulation (wave-404 lane 2 wrapper).

reverse-order iteration with prepend accumulation breaks the decoder's forward-`+=`-anchored grammars.
Thin wrapper re-exporting the wave-403 attack round 71 red-first
SHAPES/CONTROLS (evals/w403_f1128_redfirst.py). Filed 2026-10-10
18:13 UTC wave-403 (attack round 71, local validation, $0.00 model
spend (0 paid calls)). Prints BREAK on the open tree; on the closed
tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from w403_f1128_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    sys.exit(main())
