#!/usr/bin/env python3
"""Wave-397 red-first wrapper for F1062 (break-first evidence carried from
the filed wave-396 attack-round-64 red-first; the filed payloads live in
evals/w396_f1062_redfirst.py). Prints BREAK when a payload MISSES (open
tree), HELD when blocked. Run via Python subprocess (wave-392 rule).
"""
import importlib.util
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "w396_f1062_rf",
    os.path.join(REPO_ROOT, "evals", "w396_f1062_redfirst.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

if __name__ == "__main__":
    sys.exit(_mod.main())
