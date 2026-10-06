#!/usr/bin/env python3
"""w346 red-first: F441 double-backslash escapes evade the escape sub-layer.

Wave-346 lane 6 (DLP layer-composition audit) filed F441 (LOW, OPEN):
encoding every credential char as a double-backslash escape --
``\\\\uXXXX`` / ``\\\\xXX`` -- evades find_credential. The escape
decoder has no ``\\\\`` -> ``\\`` production: _ESC_RUN matches the
inner escape starting at the second backslash and decodes inside-out,
leaving stray backslashes, so the decode never converges to the
credential -- while unicode_escape applied twice (a real parser stack)
recovers it. 3/3 shapes + a URL-stacked generalization verified MISS
on the merged tree; controls hold; honest Windows paths unaffected.

Expected on the OPEN tree: prints BREAK (F441 is OPEN).
After a closure (the escape layer handles the escaped-backslash
production, or refuses obfuscation-shaped runs coded): prints HELD.

$0 SPEND BY CONSTRUCTION: canned transforms of a test credential;
no model calls here. Do NOT add ModelDriver/SpendLedger usage here.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO = os.getcwd()
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import base64  # noqa: E402
import codecs  # noqa: E402
import urllib.parse  # noqa: E402

from gov import dlp  # noqa: E402

# Long test credential (base64 = 52 chars, well over the 24-char
# precision guard). Constructed via concatenation -- never a literal.
_LONG = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"


def _unescape_once(p):
    return codecs.decode(p.encode("ascii"), "unicode_escape")


def _rt_double_unescape(payload):
    """A real parser stack (unicode_escape x2) recovers the credential."""
    return _unescape_once(_unescape_once(payload)) == _LONG


def _rt_url_double_unescape(payload):
    return _unescape_once(
        _unescape_once(urllib.parse.unquote(payload))) == _LONG


def _shapes():
    return {
        "bslash-u": (
            "".join("\\\\u%04x" % ord(c) for c in _LONG),
            _rt_double_unescape),
        "bslash-x": (
            "".join("\\\\x%02x" % ord(c) for c in _LONG),
            _rt_double_unescape),
        "bslash-mixed": (
            "".join("\\\\u%04x" % ord(c) for c in _LONG[:19])
            + "".join("\\\\x%02x" % ord(c) for c in _LONG[19:]),
            _rt_double_unescape),
        "url-stacked": (
            "".join("%%%02X" % ord(c)
                    for c in "".join("\\\\u%04x" % ord(x)
                                     for x in _LONG[:12]))
            + "".join("\\\\u%04x" % ord(c) for c in _LONG[12:]),
            _rt_url_double_unescape),
    }


def main():
    assert len(base64.b64encode(_LONG.encode()).decode()) >= 24
    control = dlp.find_credential(_LONG) == "dlp-slack-token"
    print("control (plain credential blocks) -> %s"
          % ("HELD" if control else "BROKEN-CONTROL"))
    # discrimination control: an honest double-backslash path stays quiet
    quiet = dlp.find_credential("C:\\\\Users\\\\admin\\\\docs") is None
    print("control (honest winpath quiet) -> %s"
          % ("HELD" if quiet else "BROKEN-CONTROL"))
    misses = {}
    for name, (payload, rt_fn) in _shapes().items():
        assert _LONG not in payload, "payload %s smuggles plaintext" % name
        rt = rt_fn(payload)
        miss = dlp.find_credential(payload) is None
        misses[name] = miss
        print("%-24s -> %s (roundtrip=%s)"
              % (name, "MISS" if miss else "HIT", rt))
        if not rt:
            print("ROUNDTRIP BROKEN for %s -- not a real attack" % name)
            return 2
    if control and quiet and all(misses.values()):
        print("BREAK")
        return 1
    print("HELD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
