"""Red-first for F1180: wave-406 closure re-export of the wave-405
attack-round-73 battery (thin wrapper; the w405 battery carries the
break-first SHAPES/CONTROLS with subprocess capture). Prints BREAK on
the open tree, HELD when closed.
"""
import os
import runpy
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVALS = os.path.join(REPO_ROOT, "evals")
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
sys.path.insert(0, EVALS)

if __name__ == "__main__":
    runpy.run_module("w405_f1180_redfirst", run_name="__main__")
