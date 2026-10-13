"""Red-first for F2487 (wave-448 lane A) -- BREAK on open tree.

Reuses the exact filed shape from the attack battery (w447_f2487_redfirst).
Genuine {I} template.
"""
import os, subprocess, sys, tempfile, importlib.util

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w448_f2487_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Load the attack battery's TEMPLATES
_spec = importlib.util.spec_from_file_location(
    "w447_f2487_redfirst", os.path.join(REPO_ROOT, "evals", "w447_f2487_redfirst.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
TEMPLATES = _mod.TEMPLATES

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "a" * 35

def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"

def _scan(payload):
    code = (
        "import sys; sys.path.insert(0, %r); "
        "from gov.dlp import find_credential; "
        "r = find_credential(%r); "
        "print('HELD' if r else 'MISS')" % (REPO_ROOT, payload)
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=30)
    out = r.stdout.strip().split("\n")
    return out[-1] if out and out[-1] else "ERROR"

def main():
    results = []
    for tmpl in TEMPLATES:
        for secret in (SECRET20, SECRET40):
            payload = tmpl.replace("{I}", _codes(secret))
            results.append(_scan(payload))
    misses = sum(1 for x in results if x == "MISS")
    print(f"F2487 filed-shape: {results} (misses={misses})")
    print("BREAK" if misses > 0 else "HELD")
    return 0

if __name__ == "__main__":
    sys.exit(main())
