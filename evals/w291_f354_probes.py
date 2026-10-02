"""Wave-291 lane 3 closure battery: F354 (LOW).

Base: wave-290 push 9c12f9b4b0aec88746786e68e3f84ae7f04d2d16
(verified via git rev-parse HEAD before work).

F354: gov/evidence_admission.py `load_admission_pins` leaks an uncoded
`json.JSONDecodeError` on a malformed pin file. F351 class. Close-when:
(1) a malformed pin file refuses LOUD with a coded decision code --
`admission-policy-invalid` already covers corrupt pin stores, so the JSON
shape refusal reuses it; (2) the f354 probe flips to HELD; (3) the missing
pin file stays fail-closed `FileNotFoundError` (setup-time behavior the
wave-290 red team verified as correct -- NOT changed); (4) adjacent green.

Seams under test: `load_admission_pins` only.

$0 spend, synthetic/local, deterministic (fixed fixtures, temp files under
fresh TMPDIR). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g291-f354 && TMPDIR=/var/tmp/g291-f354 \
    ~/workspace/.gov-venv/bin/python evals/w291_f354_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g291-f354b \
    ~/workspace/.gov-venv/bin/python evals/w291_f354_probes.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*).
TAXONOMY_PIN = 1726

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    n = len(lits)
    if n != TAXONOMY_PIN:
        return _record("taxonomy-pin", "BREAK",
                       "%d raw literals, expected %d" % (n, TAXONOMY_PIN))
    if len(set(lits)) != n:
        return _record("taxonomy-pin", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("taxonomy-pin", "BREAK", "literals not sorted")
    _record("taxonomy-pin", "HELD", "%d/0/sorted" % n)


def _write_pinfile(d, body):
    path = os.path.join(d, "pins.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def p_f354_malformed_pins():
    """Core F354 probe: malformed JSON must refuse LOUD with a coded code."""
    from gov import evidence_admission as adm
    d = tempfile.mkdtemp(prefix="w291-f354-")
    path = _write_pinfile(d, "{not json")
    try:
        adm.load_admission_pins(path)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f354-malformed-pins", "HELD",
                           "malformed pin file refused coded %r" % (code,))
        return _record("f354-malformed-pins", "BREAK",
                       "malformed pin file escapes as %s (code=None)"
                       % type(e).__name__)
    _record("f354-malformed-pins", "BREAK", "malformed pin file loaded")


def p_f354_empty_file():
    """Empty pin file is the same defect shape as malformed JSON."""
    from gov import evidence_admission as adm
    d = tempfile.mkdtemp(prefix="w291-f354e-")
    path = _write_pinfile(d, "")
    try:
        adm.load_admission_pins(path)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f354-empty-file", "HELD",
                           "empty pin file refused coded %r" % (code,))
        return _record("f354-empty-file", "BREAK",
                       "empty pin file escapes as %s (code=None)"
                       % type(e).__name__)
    _record("f354-empty-file", "BREAK", "empty pin file loaded")


def p_f354_non_dict():
    """Positive control: non-dict store already refuses coded."""
    from gov import evidence_admission as adm
    d = tempfile.mkdtemp(prefix="w291-f354n-")
    path = _write_pinfile(d, "[1, 2, 3]")
    try:
        adm.load_admission_pins(path)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "admission-policy-invalid":
            return _record("f354-non-dict", "HELD",
                           "non-dict pin store refused coded")
        return _record("f354-non-dict", "BREAK",
                       "non-dict pin store: %r code=%r" % (e, code))
    _record("f354-non-dict", "BREAK", "non-dict pin store loaded")


def p_f354_valid_dict():
    """Positive control: a well-formed dict store still loads."""
    from gov import evidence_admission as adm
    d = tempfile.mkdtemp(prefix="w291-f354v-")
    path = _write_pinfile(d, json.dumps({"pol-1": "a" * 64}))
    try:
        pins = adm.load_admission_pins(path)
    except Exception as e:  # noqa: BLE001
        return _record("f354-valid-dict", "BREAK",
                       "valid pin store refused: %r" % (e,))
    if pins == {"pol-1": "a" * 64}:
        return _record("f354-valid-dict", "HELD", "valid pin store loads")
    _record("f354-valid-dict", "BREAK", "valid pin store mangled: %r" % (pins,))


def p_f354_missing_file():
    """Adjacent behavior: a missing pin file is setup-time fail-closed.

    Wave-290 red team verified this is the CORRECT behavior; the lane must
    not change it. Expected uncoded FileNotFoundError on base AND fixed.
    """
    from gov import evidence_admission as adm
    d = tempfile.mkdtemp(prefix="w291-f354m-")
    path = os.path.join(d, "no-such-pins.json")
    try:
        adm.load_admission_pins(path)
    except FileNotFoundError:
        return _record("f354-missing-file", "HELD",
                       "missing pin file still fail-closed FileNotFoundError")
    except Exception as e:  # noqa: BLE001
        return _record("f354-missing-file", "BREAK",
                       "missing pin file changed shape: %s %r"
                       % (type(e).__name__, getattr(e, "code", None)))
    _record("f354-missing-file", "BREAK", "missing pin file loaded")


def _green_checks():
    if SKIP_GREEN:
        return
    # Depth-1: post-F354-fix at lane time, w290_redteam expects 5 BREAK
    # (F352, F353, F355 probes + F354's sibling probes); w288_admission
    # unaffected. Wave-291 merge re-pin: F352-F355 ALL closed -> 0 BREAK.
    checks = [
        ("evals/w290_redteam_probes.py", 0),
        ("evals/w288_admission_probes.py", 0),
    ]
    for rel, expected in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w291-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != expected:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)" % (nbreak,
                                                             expected))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % expected)


def main():
    p_taxonomy_pin()
    p_f354_malformed_pins()
    p_f354_empty_file()
    p_f354_non_dict()
    p_f354_valid_dict()
    p_f354_missing_file()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w291_f354: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
