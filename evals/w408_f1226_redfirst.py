#!/usr/bin/env python3
"""Red-first wrapper for F1226: defineProperty/defineProperties wrappers.

Wave-408 lane 4 closure lane. Delegates to the wave-407 red-first
battery (evals/w407_f1226_redfirst.py), which prints BREAK on the open
tree for every filed shape. After closure, every shape must HIT.
"""
import os
import runpy
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))

if __name__ == "__main__":
    mod = runpy.run_path(
        os.path.join(REPO_ROOT, "evals", "w407_f1226_redfirst.py"),
        run_name="__w407_redfirst__")
    sys.exit(mod["main"]())
