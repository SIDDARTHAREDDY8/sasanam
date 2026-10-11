#!/usr/bin/env python3
"""Red-first for F1208 (wave-408 lane 2 wrapper).

Re-exports the wave-407 attack round 75 red-first shapes for F1208
(rest-destructuring copy spread); prints BREAK on the open tree.
Filed 2026-10-11 03:06 UTC.
"""
import importlib.util
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)


def _load():
    path = os.path.join(REPO_ROOT, "evals", "w407_f1208_redfirst.py")
    spec = importlib.util.spec_from_file_location("w407_f1208_rf", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load()
SHAPES = _mod.SHAPES
CONTROLS = _mod.CONTROLS


def main():
    return _mod.main()


if __name__ == "__main__":
    sys.exit(main())
