#!/usr/bin/env python3
"""Red-first for F1120 (wave-403 lane 1 closure).

Re-exports the wave-402 attack round-70 red-first shapes (verified
correct: they use .replace("{{I}}", ...) so the payloads are genuine,
unlike the w401 {{I}}-format bug). On the open tree find_credential
MISSES each shape (prints BREAK, one scanner call per fresh process);
on the closed tree each is flagged by the wave-403 lane-1 hooks.
Filed 2026-10-10 16:52 UTC wave-402 (attack round 70, local validation,
$0.00 model spend (0 paid calls)).
"""
import importlib.util
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

_spec = importlib.util.spec_from_file_location(
    "w402_f1120_rf", os.path.join(REPO_ROOT, "evals", "w402_f1120_redfirst.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

SHAPES = _mod.SHAPES
CONTROLS = _mod.CONTROLS


def main():
    return _mod.main()


if __name__ == "__main__":
    sys.exit(main())
