#!/usr/bin/env python3
"""Wave-410 lane 4 red-first wrapper for F1284.

Re-exports the attack round-77 red-first battery
(evals/w409_f1284_redfirst.py) which was verified BREAK on the open
tree before this lane's fix. The w410 close battery
(evals/w410_f1281f1288close_probes.py) asserts these shapes now
BLOCK/FLAG.
"""
import importlib.util as _ilu
import os as _os

_spec = _ilu.spec_from_file_location(
    "w409_f1284_rf",
    _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                  "w409_f1284_redfirst.py"))
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

SHAPES = _mod.SHAPES
try:
    _CHILD = _mod._CHILD
except AttributeError:
    pass
try:
    _CONTROLS = _mod._CONTROLS
except AttributeError:
    pass

if __name__ == "__main__":
    import subprocess as _sp
    import sys as _sys
    _r = _sp.run([_sys.executable,
                  _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                                "w409_f1284_redfirst.py")],
                 capture_output=True, text=True)
    print(_r.stdout, end="")
    print(_r.stderr, end="", file=_sys.stderr)
    _sys.exit(_r.returncode)
