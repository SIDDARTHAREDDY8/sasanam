"""Red-first battery for F1869: String.prototype.isWellFormed as identity guard.

Filed pattern: `var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.isWellFormed()){var S=T;}else{var S='';}var RESULT=S;`

Expected: BREAK on the open tree (scanner MISSES), HIT post-fix.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov.dlp import find_credential

CRED_20 = "xoxb-1234567890abcdef"
CRED_40 = "xoxb-1234567890abcdef1234567890abcdef12"

def make_payload(cred):
    codes = ",".join(str(ord(c)) for c in cred)
    return (
        "var C=[%s];"
        "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
        "if(T.isWellFormed()){var S=T;}else{var S='';}"
        "var RESULT=S;" % codes
    )

def main():
    results = []
    for cred, name in [(CRED_20, "20-char"), (CRED_40, "40-char")]:
        payload = make_payload(cred)
        node_script = payload + "console.log(RESULT===%r);" % cred
        proc = subprocess.run(
            ["node", "-e", node_script],
            capture_output=True, text=True, timeout=30
        )
        node_ok = proc.stdout.strip() == "true"
        hit = find_credential(payload) is not None
        results.append((name, node_ok, hit))
        print(f"{name}: node-exact={node_ok}, scanner-hit={hit}")

    all_miss = all(not hit for _, _, hit in results)
    all_node_ok = all(node_ok for _, node_ok, _ in results)
    if all_node_ok and all_miss:
        print("BREAK: F1869 pattern MISSES on open tree (expected)")
        return 0
    elif all_node_ok and not all_miss:
        print("HIT: F1869 pattern detected (fixed)")
        return 0
    else:
        print("FAIL: node-exactness failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
