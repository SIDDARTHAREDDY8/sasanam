#!/usr/bin/env python3
"""w342 red-first: F429 backslash-escape-encoded credential evades DLP.

Discovered during the F428 closure (adjacent-obfuscator check): the
decode layer (F2/F8/F428) handles URL-encoding, hex, base64/base64url,
base32, and JSFuck -- but NOT backslash escapes. A credential written
as \\uXXXX / \\UXXXXXXXX / \\xXX sequences misses find_credential and
scan_value while the plain form blocks coded dlp-slack-token.

Expected on the OPEN tree: prints BREAK (F429 is OPEN).
After the F429 closure: must print HELD.

$0 SPEND BY CONSTRUCTION: canned escapes, no model calls.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO = os.getcwd()
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402

PLAIN = "xoxb-abc123def456"


def esc_u(s):
    return "".join("\\u%04x" % ord(c) for c in s)


def esc_U(s):  # noqa: N802 - matches the escape name
    return "".join("\\U%08x" % ord(c) for c in s)


def esc_x(s):
    return "".join("\\x%02x" % ord(c) for c in s)


def main():
    plain_blocked, plain_rule = dlp.scan_value("token=" + PLAIN)[:2]
    print("control plain credential: blocked=%s rule=%s" % (plain_blocked,
                                                            plain_rule))
    broke_any = False
    for name, form in (("unicode \\\\uXXXX", esc_u(PLAIN)),
                       ("unicode \\\\UXXXXXXXX", esc_U(PLAIN)),
                       ("hex \\\\xXX", esc_x(PLAIN)),
                       ("mixed plain+\\\\u", "xoxb-" + esc_u("abc123def456"))):
        rule = dlp.find_credential("token=" + form)
        print("%-22s -> find_credential=%s" % (name, rule))
        broke_any = broke_any or (rule is None)
    broke = broke_any and plain_blocked
    print("F429 backslash-escape decode-layer gap reproduces: %s -> %s"
          % (broke, "BREAK" if broke else "HELD"))


if __name__ == "__main__":
    main()
