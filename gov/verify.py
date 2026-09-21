"""Offline log verifier: ``python -m gov.verify <actions.jsonl>``.

Replays the HMAC chain and checks the newest signed checkpoint, with no
access to the running system. Exit 0 when the log verifies, 1 otherwise.

Key selection:
  * default: the single active key from ``GOV_LOG_KEY`` (falls back to
    the public dev key with a warning, same as the logger). A log that
    spans a rotation does NOT verify under this path — by design
    (fail-closed): pass ``--keyring``.
  * ``--keyring <path>`` (F19): verify with a persisted keyring file
    (as written by ``KeyRing.save``), so logs spanning key epochs
    verify. ``<path>`` may also be a directory containing
    ``keyring.json``. Genuine tampering still fails closed.
"""

import json
import sys
from pathlib import Path

from .keys import KeyRing
from .log import _verify


def _resolve_keyring(path):
    """Return the keyring file for ``--keyring <path>``.

    Accepts a keyring file directly, or a directory containing
    ``keyring.json``.
    """
    p = Path(path)
    if p.is_dir():
        p = p / "keyring.json"
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    keyring = None
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--keyring" and i + 1 < len(argv):
            keyring = argv[i + 1]
            i += 2
        else:
            rest.append(argv[i])
            i += 1
    if not rest or rest[0] in ("-h", "--help"):
        print("usage: python -m gov.verify [--keyring <path>] "
              "<actions.jsonl>")
        print("")
        print("  --keyring <path>  verify with a persisted keyring file")
        print("                    (or a directory containing keyring.json),")
        print("                    so logs spanning key rotations verify.")
        return 0 if rest and rest[0] in ("-h", "--help") else 2
    log_path = rest[0]
    if keyring is not None:
        kp = _resolve_keyring(keyring)
        try:
            ring = KeyRing.load(str(kp))
        except (OSError, ValueError) as e:
            print(json.dumps({"ok": False, "error": "keyring: %s" % e},
                             indent=2, sort_keys=True))
            return 1
        verdict = ring.verify_log(log_path)
    else:
        verdict = _verify(log_path)
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
