"""Close battery for wave-448 lane A (partial): F2450 + F2455-F2467.

Tests the 14 completed findings. F2468-F2495 remain open (not implemented
in this lane due to complexity; documented in REPORT.md).
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w448_close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Pin checks
N_STMTDEC_LOOPS = 193  # 192 + 1 (F2455-F2467 dispatch loop)
VERIFIER_PIN = 2143

PASS = 0
FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name} {detail}")

def scan(payload):
    import base64
    b64 = base64.b64encode(payload.encode()).decode()
    code = (
        "import sys, base64; sys.path.insert(0, %r); "
        "from gov.dlp import find_credential; "
        "payload = base64.b64decode('%s').decode(); "
        "r = find_credential(payload); "
        "print('HELD' if r else 'MISS')" % (REPO_ROOT, b64)
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=30)
    out = r.stdout.strip().split("\n")
    return out[-1] if out and out[-1] else "ERROR:" + r.stderr[:100]

def main():
    global PASS, FAIL
    print("=== Wave-448 Lane A Close Battery (F2450 + F2455-F2467) ===")
    
    # 1. Pin checks
    print("\n-- Pins --")
    import re
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL))
    check("N_STMTDEC_LOOPS pin", len(loops) == N_STMTDEC_LOOPS,
          f"got {len(loops)}, want {N_STMTDEC_LOOPS}")
    
    # 2. Filed shapes HELD (F2450 + F2455-F2467)
    print("\n-- Filed shapes (must HELD) --")
    import importlib.util
    for n in [2450] + list(range(2455, 2468)):
        mod_name = f"w448_f{n}_redfirst"
        spec = importlib.util.spec_from_file_location(
            mod_name, os.path.join(REPO_ROOT, "evals", f"{mod_name}.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for tmpl in mod.TEMPLATES:
            for secret in (mod.SECRET20, mod.SECRET40):
                payload = tmpl.replace("{I}", mod._codes(secret))
                result = scan(payload)
                check(f"F{n} filed-shape HELD", result == "HELD",
                      f"got {result}")
    
    # 3. Honest text controls (must MISS / QUIET)
    print("\n-- Honest-text controls --")
    honest = [
        "The user password is hunter2, please keep it safe.",
        "var x = 5; console.log('hello');",
        "Remember to buy milk tomorrow.",
    ]
    for h in honest:
        result = scan(h)
        check(f"honest-text MISS", result == "MISS", f"got {result} for {h[:30]}")
    
    # 4. Sibling pins (F2468-F2495 must still MISS - not implemented)
    print("\n-- Sibling pins (F2468-F2495 still OPEN -> MISS) --")
    # Just check a couple to verify they're still open
    for n in [2468, 2480, 2495]:
        mod_name = f"w448_f{n}_redfirst"
        spec = importlib.util.spec_from_file_location(
            mod_name, os.path.join(REPO_ROOT, "evals", f"{mod_name}.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tmpl = mod.TEMPLATES[0]
        payload = tmpl.replace("{I}", mod._codes(mod.SECRET20))
        result = scan(payload)
        check(f"F{n} still MISS (open)", result == "MISS", f"got {result}")
    
    print(f"\n=== {PASS} PASS, {FAIL} FAIL ===")
    return 0 if FAIL == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
