#!/usr/bin/env python3
"""Red-first for F437 (LOW, OPEN): JS .reduce() array-assembly evades the
bounded static JS-expression decoder.

F430 closed quoted-'+'/template/fromCharCode/.concat/.repeat; F434 closed
array-literal .join(sep). But .reduce((a,b)=>a+b) over an array of string
fragments evaluates to the credential in any real JS engine (node-verified)
while the decoder -- which handles only join/repeat/concat postfix calls --
fails closed and no other layer matches the sub-threshold fragments.

Prints BREAK on the open tree (verified MISS), HELD once closed.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential  # noqa: E402

# Test credential, concatenation-constructed -- never a literal.
_FRAG1 = "xoxb-" + "abc123"
_FRAG2 = "def456"


def main():
    # node: ["xoxb-abc123","def456"].reduce((a,b)=>a+b) -> the credential
    payload = "['" + _FRAG1 + "','" + _FRAG2 + "'].reduce((a,b)=>a+b)"
    assert (_FRAG1 + _FRAG2) not in payload  # no plaintext credential
    miss = find_credential(payload) is None
    # control: the F434 .join(sep) shape blocks coded
    join_payload = "['" + _FRAG1 + "','" + _FRAG2 + "'].join('')"
    join_hit = find_credential(join_payload) == "dlp-slack-token"
    # control: the plain credential blocks coded
    plain_hit = find_credential(_FRAG1 + _FRAG2) == "dlp-slack-token"
    print("F437 reduce-shape miss (BREAK if True):", miss)
    print("control .join('') blocks:", join_hit)
    print("control plain blocks:", plain_hit)
    if miss and join_hit and plain_hit:
        print("BREAK")
    else:
        print("HELD")


if __name__ == "__main__":
    main()
