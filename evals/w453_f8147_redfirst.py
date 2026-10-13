#!/usr/bin/env python3
"""Red-first battery for F8147 - wave-453 merge.

INVERTED vs the usual pattern: F8147 is a FALSE-POSITIVE gap (the seam
routes to approval a shape that should stay QUIET), not a miss. Prints
BREAK while `?trove%3D` (empty URL-encoded equals) FLAGs via the trove
no-equals branch (gap present); prints HELD once it stays QUIET while the
valued encoded form still FLAGs (fixed). Prose-quiet + album fixed-control
included.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w453_f8147_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TEXT = 'https://example.com/page?trove%3D'
VALUED = 'https://example.com/page?trove%3DExampleBrand'
ALBUM_EMPTY = 'https://example.com/page?album%3D'
ALBUM_VALUED = 'https://example.com/page?album%3DExampleBrand'


def _check(t):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.instruction_provenance import instruction_shaped;"
        "r=instruction_shaped(" + repr(t) + ");"
        "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def main():
    v = _check(TEXT)
    vv = _check(VALUED)
    ae = _check(ALBUM_EMPTY)
    av = _check(ALBUM_VALUED)
    pv = _check("The weather is pleasant today with clear skies.")
    print("F8147 filed-shape (trove empty encoded): %s (valued: %s, "
          "album empty: %s, album valued: %s, prose-quiet: %s)"
          % (v, vv, ae, av, pv))
    if v == "FLAG" and vv == "FLAG" and pv == "QUIET":
        print("BREAK")
    elif v == "QUIET" and vv == "FLAG" and ae == "QUIET" \
            and av == "FLAG" and pv == "QUIET":
        print("HELD")
    else:
        print("ERROR")


if __name__ == "__main__":
    main()
