#!/usr/bin/env python3
"""Red-first wrapper for F1188 (wave-407 lane 2 closure).

Re-exports the wave-406 attack round 74 SHAPES/CONTROLS for F1188.
On the open tree these print BREAK (MISS); on the closed tree they
print FAIL (HIT, blocked).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from w406_f1188_redfirst import SHAPES, CONTROLS, main  # noqa: E402,F401

if __name__ == "__main__":
    main()
