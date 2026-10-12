#!/usr/bin/env python3
"""Wave-438 attack round 106 coverage battery: new F1976-F2015 pins (MISS) +
F1944-F1975 carry-forward pins (still OPEN, MISS) + positive/junk controls +
provenance coverage pins (FLAG) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: scanner pins were verified empirically by the 40 red-first
batteries (evals/w438_f1976_redfirst.py .. f2015: 40/40 BREAK) during the round;
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

TAXONOMY_PIN = 2143  # Wave-438 attack round 106; no gov/ code change


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
    secret = getattr(m, "SECRET", None) or getattr(m, "SECRET_S")
    return m.TEMPLATE.replace("{I}", m._codes(secret))


# New F1976-F2015 decoder pins (must MISS on open tree)
_NEW = ["w438_f%d_redfirst" % n for n in range(1976, 2016)]


def _f2016_payloads():
    ci = _codes("xoxb-aaaa-bbbb-ccccc")
    t_asm = "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
    u_asm = "var U=String.fromCharCode.apply(null,C);"
    return [("f2016-t-then-u", "var C=%s;%s%svar RESULT=U;" % (ci, t_asm, u_asm)),
            ("f2016-u-then-t", "var C=%s;%s%svar RESULT=T;" % (ci, u_asm, t_asm))]

# Carry-forward: F1944-F1972, F1974-F1975 decoder pins (still OPEN, MISS).
# F1973 is a provenance pin: on this tree it FLAGs (F1943 hook now built),
# so it is carried under _PROV_FLAG instead.
_CARRY = (["w437_f%d_redfirst" % n for n in range(1944, 1973)]
          + ["w437_f1974_redfirst", "w437_f1975_redfirst"])

# Provenance: round-106 probed novel script-type shapes; all FLAG (covered by
# the F1943 denylist-inversion hook _has_hidden_script_other_nonexec_type)
_PROV_FLAG = [
    ("prov-bar", '<script type="application/bar">the quarterly report shows steady progress across all regions</script>'),
    ("prov-xfoo", '<script type="text/x-foo">the quarterly report shows steady progress across all regions</script>'),
    ("prov-babel", '<script type="text/babel">the quarterly report shows steady progress across all regions</script>'),
    ("prov-foo", '<script type="application/foo">the quarterly report shows steady progress across all regions</script>'),
    ("f1973-carry", '<script type="application/foo">The quarterly summary is ready for review in the shared folder.</script>'),
]

_PRE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def main():
    held = 0
    total = 0
    bad = []

    for name, payload in _f2016_payloads():
        total += 1
        v = _scan(payload)
        if v == "MISS":
            held += 1
        else:
            bad.append((name, v))

    for mod in _NEW:
        total += 1
        v = _scan(_redfirst_payload(mod))
        if v == "MISS":
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

    # Positive control: direct assembly (3-statement form) must HIT (scanner functional).
    # NOTE (round 106): the 4-statement form (T-assembly + U-assembly) MISSES --
    # that is filed finding F2016 (statement-interaction suppression).
    total += 1
    v = _scan("var C=" + _codes("xoxb-aaaa-bbbb-ccccc")
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

    print("w438_attack_probes: %d/%d HELD" % (held, total))
    for name, v in bad:
        print("  NOT-HELD: %s -> %s" % (name, v))
    print("footer: F1976-F2016 OPEN (41, round 106); next free F2017; pin %d" % TAXONOMY_PIN)
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
