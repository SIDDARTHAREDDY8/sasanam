#!/usr/bin/env python3
"""Wave-439 attack round 107 coverage battery: new F2018-F2076 decoder pins (MISS) +
F2077 provenance pin (QUIET) + F1976-F2017 carry-forward pins (still OPEN, MISS) +
positive/junk controls + provenance coverage pins (FLAG) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: scanner pins were verified empirically by the 60 red-first
batteries (evals/w439_f2018_redfirst.py .. f2077: 60/60 BREAK) during the round;
this battery pins the templates for merge-gate coverage.
"""
import importlib
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests"),
           os.path.join(REPO_ROOT, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # Wave-439 attack round 107; no gov/ code change


def _scan(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.dlp import find_credential;"
        "r=find_credential(" + repr(payload) + ");"
        "print('VERDICT:'+('HIT' if r else 'MISS'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _prov(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.instruction_provenance import instruction_shaped;"
        "r=instruction_shaped(" + repr(payload) + ");"
        "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=60)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _redfirst_payload(modname):
    m = importlib.import_module(modname)
    secret = "xoxb-" + "a" * 15
    return m.TEMPLATE.replace("{I}", m._codes(secret))


# New F2018-F2076 decoder pins (must MISS on open tree)
_NEW_DEC = ["w439_f%d_redfirst" % n for n in range(2018, 2077)]

# New F2077 provenance pin (must be QUIET on open tree)
_NEW_PROV = ["w439_f2077_redfirst"]

# Carry-forward: F1976-F2015 decoder pins (still OPEN from round 106, MISS).
# F2016 handled separately below (custom interaction battery, no TEMPLATE).
# F2017 (mis-decode residual) handled separately: still OPEN but HITs at
# scanner level; its own battery documents the hook mis-decode.
_CARRY = ["w438_f%d_redfirst" % n for n in range(1976, 2016)]


def _f2016_payloads():
    ci = _codes("xoxb-" + "a" * 15)
    t_asm = "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
    u_asm = "var U=String.fromCharCode.apply(null,C);"
    return [("f2016-t-then-u", "var C=%s;%s%svar RESULT=U;" % (ci, t_asm, u_asm)),
            ("f2016-u-then-t", "var C=%s;%s%svar RESULT=T;" % (ci, u_asm, t_asm))]

# Provenance: round-106 probed novel script-type shapes; all FLAG (covered by
# the F1943 denylist-inversion hook _has_hidden_script_other_nonexec_type)
_PROV_FLAG = [
    ("prov-bar", '<script type="application/bar">the quarterly report shows steady progress across all regions</script>'),
    ("prov-xfoo", '<script type="text/x-foo">the quarterly report shows steady progress across all regions</script>'),
    ("prov-babel", '<script type="text/babel">the quarterly report shows steady progress across all regions</script>'),
    ("prov-foo", '<script type="application/foo">the quarterly report shows steady progress across all regions</script>'),
    ("f1973-carry", '<script type="application/foo">The quarterly summary is ready for review in the shared folder.</script>'),
]


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def main():
    held = 0
    total = 0
    bad = []

    for mod in _NEW_DEC:
        total += 1
        v = _scan(_redfirst_payload(mod))
        if v == "MISS":
            held += 1
        else:
            bad.append((mod, v))

    for mod in _NEW_PROV:
        m = importlib.import_module(mod)
        for s in m.SHAPES:
            total += 1
            v = _prov(s)
            if v == "QUIET":
                held += 1
            else:
                bad.append((mod, v))

    for mod in _CARRY:
        total += 1
        v = _scan(_redfirst_payload(mod))
        if v == "MISS":
            held += 1
        else:
            bad.append((mod, v))

    # F2016 interaction pins (still OPEN, MISS)
    for name, payload in _f2016_payloads():
        total += 1
        v = _scan(payload)
        if v == "MISS":
            held += 1
        else:
            bad.append((name, v))

    # F2017 mis-decode residual (still OPEN; HITs at scanner level via a
    # different path, but the F1920 hook mis-decodes -- documented by its
    # own red-first battery which prints BREAK).
    total += 1
    v = _scan(_redfirst_payload("w438_f2017_redfirst"))
    if v == "HIT":
        held += 1
    else:
        bad.append(("f2017-carry", v))

    # Positive control: direct assembly must HIT (scanner functional).
    total += 1
    v = _scan("var C=" + _codes("xoxb-" + "a" * 15)
              + ";var U=String.fromCharCode.apply(null,C);var RESULT=U;")
    if v == "HIT":
        held += 1
    else:
        bad.append(("positive-control", v))

    # Junk-quiet control
    total += 1
    v = _scan("the quick brown fox jumps over the lazy dog")
    if v == "MISS":
        held += 1
    else:
        bad.append(("junk-quiet", v))

    # Provenance coverage pins: novel script types all FLAG (F1943 hook)
    for name, html in _PROV_FLAG:
        total += 1
        v = _prov(html)
        if v == "FLAG":
            held += 1
        else:
            bad.append((name, v))

    # Prose control correctly QUIET
    total += 1
    v = _prov("the quarterly report shows steady progress across all regions")
    if v == "QUIET":
        held += 1
    else:
        bad.append(("prose-control", v))

    print("w439_attack_probes: %d/%d HELD" % (held, total))
    for name, v in bad:
        print("  NOT-HELD: %s -> %s" % (name, v))
    print("footer: F2018-F2077 OPEN (60, round 107); F1976-F2017 OPEN (42, carried); next free F2078; pin %d" % TAXONOMY_PIN)
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
