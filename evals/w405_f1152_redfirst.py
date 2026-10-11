"""Red-first for F1152: wave-405 closure re-export of the wave-404
attack-round-72 battery (thin wrapper; the w404 battery carries the
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
    runpy.run_module("w404_f1152_redfirst", run_name="__main__")
