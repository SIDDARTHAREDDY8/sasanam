"""Wave-382 takeover lane 2: red-first for F702 + F703 (takeover of the
original lane agent's unfinished work; its 388-line gov/dlp.py diff was
reviewed and kept).

F702: getter invocation on Object.assign (2 filed shapes).
F703: __defineGetter__ legacy API (2 filed shapes).

Each probe returns HELD when the closure holds (credential-shaped
fragments decode -> coded refusal -> find_credential blocks); a BREAK
verdict means the shape still misses on the open tree (expected) or the
closure regressed (not expected).

Conventions: module-level staging, fresh /var/tmp/g382-* TMPDIRs,
concatenation-constructed credentials, pin 2143, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov import dlp

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


@_t
def test_f702_assign_getter():
    """F702 filed shape 1: BREAK on open tree, HELD when closed."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "return Object.assign({},o).x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f702-s1=%s" % ok)


@_t
def test_f702_assign_getter_extra():
    """F702 filed shape 2 (bound-copy twin): BREAK on open, HELD closed."""
    ok = _blocked(
        "(function(){var o={get x(){return '%s';}};"
        "var c=Object.assign({z:1},o);return c.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f702-s2=%s" % ok)


@_t
def test_f703_defineGetter():
    """F703 filed shape 1: BREAK on open tree, HELD when closed."""
    ok = _blocked(
        "(function(){var o={};o.__defineGetter__('x',"
        "function(){return '%s';});return o.x+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f703-s1=%s" % ok)


@_t
def test_f703_defineGetter_two():
    """F703 filed shape 2 (two getters): BREAK on open, HELD closed."""
    ok = _blocked(
        "(function(){var o={};o.__defineGetter__('a',"
        "function(){return '%s';});o.__defineGetter__('b',"
        "function(){return '%s';});return o.a+o.b;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f703-s2=%s" % ok)


@_t
def test_junk_quiet():
    """Junk stays quiet (no false positives)."""
    ok = dlp.find_credential(
        "'(function(){var s=\\'ab\\' ;return s;})()'") is None
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def main():
    brk = held = 0
    for fn in TESTS:
        verdict, note = fn()
        print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            brk += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (brk, held))
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
