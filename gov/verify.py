"""Offline log verifier: ``python -m gov.verify <actions.jsonl>``.

Replays the HMAC chain and checks the newest signed checkpoint, with no
access to the running system. Exit 0 when the log verifies, 1 otherwise.

Key selection:
  * default: the single active key from ``GOV_LOG_KEY`` — STRICT (R6c):
    unset raises ``NoKeyConfiguredError``; there is no silent dev-key
    fallback (F73). A log that spans a rotation does NOT verify under
    this path — by design (fail-closed): pass ``--keyring``.
  * ``--dev``: explicit opt-in to the PUBLIC development key (in-code
    opt-in at this CLI layer plus ``GOV_DEV_KEYS=1``), with a loud
    warning. For verifying synthetic demo/test logs only; never for
    real audit data.
  * ``--keyring <path>`` (F19): verify with a persisted keyring file
    (as written by ``KeyRing.save``), so logs spanning key epochs
    verify. ``<path>`` may also be a directory containing
    ``keyring.json``. Genuine tampering still fails closed.

Third-party proof commands (P2/A5/K-060) -- no HMAC key needed:
  * ``--sigs``: verify the signed checkpoints' Ed25519 signature sets
    against ``--sig-trust {key_id: pubkey_hex}`` (single-key) or
    ``--roster`` + ``--root-pubkey`` (k-of-n threshold, A5).
    ``--require-signed`` fails closed on any unsigned checkpoint.
  * ``--prove <seq>`` / ``--proof <seq>``: inclusion bundle / end-to-end
    inclusion verification (CT auditor, Crosby & Wallach O(log n)).
  * ``--consistency <old-seq>``: old checkpoint -> newest head.
  * ``--export``: tamper-evident filtered export bundle (K-060), with
    ``--principal/--event/--since/--until/--limit`` filters.
"""

import json
import os
import sys
from pathlib import Path

from .keys import KeyRing, NoKeyConfiguredError
from .log import _verify, enable_dev_keys


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
    dev = False
    # P2/A5/K-060 proof + export commands (third-party: no HMAC key).
    sig_trust = None
    roster_path = None
    root_pubkey = None
    require_signed = False
    prove_seq = None
    proof_seq = None
    consistency_seq = None
    do_sigs = False
    do_export = False
    query = {}
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--keyring" and i + 1 < len(argv):
            keyring = argv[i + 1]
            i += 2
        elif argv[i] == "--dev":
            dev = True
            i += 1
        elif argv[i] == "--sig-trust" and i + 1 < len(argv):
            sig_trust = argv[i + 1]
            i += 2
        elif argv[i] == "--roster" and i + 1 < len(argv):
            roster_path = argv[i + 1]
            i += 2
        elif argv[i] == "--root-pubkey" and i + 1 < len(argv):
            root_pubkey = argv[i + 1]
            i += 2
        elif argv[i] == "--require-signed":
            require_signed = True
            i += 1
        elif argv[i] == "--prove" and i + 1 < len(argv):
            prove_seq = argv[i + 1]
            i += 2
        elif argv[i] == "--proof" and i + 1 < len(argv):
            proof_seq = argv[i + 1]
            i += 2
        elif argv[i] == "--consistency" and i + 1 < len(argv):
            consistency_seq = argv[i + 1]
            i += 2
        elif argv[i] == "--sigs":
            do_sigs = True
            i += 1
        elif argv[i] == "--export":
            do_export = True
            i += 1
        elif argv[i] in ("--principal", "--event", "--since",
                         "--until") and i + 1 < len(argv):
            query[argv[i][2:]] = argv[i + 1]
            i += 2
        elif argv[i] == "--limit" and i + 1 < len(argv):
            query["limit"] = argv[i + 1]
            i += 2
        else:
            rest.append(argv[i])
            i += 1
    if not rest or rest[0] in ("-h", "--help"):
        print("usage: python -m gov.verify [--dev] [--keyring <path>] "
              "<actions.jsonl>")
        print("       python -m gov.verify <actions.jsonl> --sigs "
              "[--sig-trust <json> --roster <json> --root-pubkey <hex> "
              "[--require-signed]]")
        print("       python -m gov.verify <actions.jsonl> --prove <seq> | "
              "--proof <seq> | --consistency <old-seq> [--sig-trust ...]")
        print("       python -m gov.verify <actions.jsonl> --export "
              "[--principal P --event E --since TS --until TS --limit N]")
        print("")
        print("  --dev           verify with the PUBLIC development key "
              "(explicit")
        print("                    opt-in: in-code enablement at this CLI "
              "layer")
        print("                    plus GOV_DEV_KEYS=1, with a loud "
              "warning).")
        print("                    For synthetic demo/test logs only.")
        print("  --keyring <path>  verify with a persisted keyring file")
        print("                    (or a directory containing keyring.json),")
        print("                    so logs spanning key rotations verify.")
        print("  --sigs          third-party (HMAC-keyless) verification of")
        print("                    the signed checkpoints (P2/A5).")
        print("  --sig-trust <json>  {key_id: pubkey_hex} trusted signing "
              "keys")
        print("  --roster <json>     offline-root-signed signer roster "
              "(threshold)")
        print("  --root-pubkey <hex> trusted offline root public key")
        print("  --require-signed    fail if any checkpoint is unsigned")
        print("  --prove <seq>       print an inclusion bundle (CT auditor)")
        print("  --proof <seq>       verify an inclusion proof end-to-end")
        print("  --consistency <seq> verify old checkpoint -> newest head")
        print("  --export            print a tamper-evident export bundle "
              "(K-060)")
        return 0 if rest and rest[0] in ("-h", "--help") else 2
    if dev:
        # R6c: explicit --dev opt-in at the CLI layer (in-code), plus the
        # env factor. Loud warning; default stays strict.
        os.environ.setdefault("GOV_DEV_KEYS", "1")
        enable_dev_keys()
        print("GOVERNANCE KEY WARNING: --dev: verifying with the PUBLIC "
              "development key (zero integrity). Never use for real audit "
              "data.", file=sys.stderr)
    log_path = rest[0]

    def _trust():
        trusted = {}
        if sig_trust is not None:
            with open(sig_trust, encoding="utf-8") as f:
                trusted = json.load(f)
            if not isinstance(trusted, dict):
                raise ValueError("--sig-trust must be a JSON object")
        roster = None
        if roster_path is not None:
            with open(roster_path, encoding="utf-8") as f:
                roster = json.load(f)
        root_pub = None
        if root_pubkey is not None:
            root_pub = bytes.fromhex(root_pubkey)
        return trusted, roster, root_pub

    proof_cmd = (prove_seq is not None or proof_seq is not None
                 or consistency_seq is not None or do_sigs or do_export)
    if proof_cmd:
        from . import log as _logmod
        try:
            trusted, roster, root_pub = _trust()
            if prove_seq is not None:
                prove_n = int(prove_seq)
            if proof_seq is not None:
                proof_n = int(proof_seq)
            if consistency_seq is not None:
                consistency_n = int(consistency_seq)
            if "limit" in query:
                query["limit"] = int(query["limit"])
        except (OSError, ValueError) as e:
            print(json.dumps({"ok": False, "error": "args: %s" % e},
                             indent=2, sort_keys=True))
            return 1
        try:
            if prove_seq is not None:
                out = _logmod.prove_inclusion(log_path, prove_n)
            elif proof_seq is not None:
                b = _logmod.prove_inclusion(log_path, proof_n)
                ok, err = _logmod.verify_inclusion_bundle(
                    b, trusted, roster, root_pub)
                out = {"ok": ok, "error": err, "seq": proof_n,
                       "tree_size": b["tree_size"]}
            elif consistency_seq is not None:
                b = _logmod.prove_consistency(log_path, consistency_n)
                ok, err = _logmod.verify_consistency_bundle(
                    b, trusted, roster, root_pub)
                out = {"ok": ok, "error": err,
                       "old_seq": b["old_seq"], "new_seq": b["new_seq"]}
            elif do_sigs:
                out = _logmod.verify_checkpoint_signatures(
                    log_path, trusted, roster, root_pub,
                    require_signed=require_signed)
            else:  # do_export
                out = _logmod.export_bundle(log_path, roster=roster,
                                            **query)
        except (OSError, ValueError) as e:
            print(json.dumps({"ok": False, "error": str(e)},
                             indent=2, sort_keys=True))
            return 1
        print(json.dumps(out, indent=2, sort_keys=True, default=str))
        if isinstance(out, dict) and "ok" in out:
            return 0 if out["ok"] else 1
        return 0

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
        try:
            verdict = _verify(log_path)
        except NoKeyConfiguredError as e:
            # R6c strict default: no key configured and no --dev opt-in.
            # Fail closed with a clear message, not a traceback.
            print(json.dumps({"ok": False, "error": "key: %s" % e},
                             indent=2, sort_keys=True))
            return 1
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
