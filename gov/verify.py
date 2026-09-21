"""Offline log verifier: ``python -m gov.verify <actions.jsonl>``.

Replays the HMAC chain and checks the newest signed checkpoint, with no
access to the running system. Exit 0 when the log verifies, 1 otherwise.
Reads the key from ``GOV_LOG_KEY`` (falls back to the public dev key with a
warning, same as the logger).
"""

import json
import sys

from .log import _verify


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m gov.verify <actions.jsonl>")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    verdict = _verify(argv[0])
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
