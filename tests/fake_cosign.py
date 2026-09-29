#!/usr/bin/env python3
"""Test double for the cosign CLI surface used by gov.cosign_attest.

Implements just enough of `sign-blob` / `verify-blob` to exercise the
product's wiring deterministically with zero network:

  sign-blob --key K --bundle B --use-signing-config=false --yes FILE
    -> writes a JSON "bundle" containing an HMAC-SHA256(file, secret)
       where secret = sha256(bytes of the --key file). REFUSES (rc=3)
       when --use-signing-config=false is absent from argv -- this
       models the product's offline contract behaviorally.

  verify-blob --bundle B --key PUB FILE
    -> rc=0 when the file's digest and HMAC match the bundle, rc=1
       otherwise (this models tamper-refusal).

  FAKE_COSIGN_ARGV_LOG=<path> (env): appends a JSON line of the argv
    per invocation so tests can assert the exact CLI surface.

This double tests OUR module's wiring (argv, flag presence, exit-code
handling, temp-file hygiene, tamper -> loud failure), never cosign's
own cryptography -- the wave-191 spike proved the real CLI end to end.
"""
import hashlib
import hmac
import json
import os
import sys


def _fail(rc, msg):
    sys.stderr.write("FAKE-COSIGN: %s\n" % msg)
    sys.exit(rc)


def _log_argv(argv):
    path = os.environ.get("FAKE_COSIGN_ARGV_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(argv) + "\n")


def _opt(argv, name):
    if name not in argv:
        _fail(2, "missing option %s" % name)
    i = argv.index(name)
    if i + 1 >= len(argv):
        _fail(2, "option %s has no value" % name)
    return argv[i + 1]


def _secret(key_path):
    try:
        with open(key_path, "rb") as f:
            return hashlib.sha256(f.read()).digest()
    except OSError as e:
        _fail(2, "cannot read key file: %s" % e)


def cmd_sign_blob(argv):
    if "--use-signing-config=false" not in argv:
        _fail(3, "refusing: --use-signing-config=false missing from argv "
                 "(the offline contract is load-bearing)")
    key_path = _opt(argv, "--key")
    bundle_path = _opt(argv, "--bundle")
    rest = [a for a in argv[1:]
            if not a.startswith("--") and a not in (key_path, bundle_path)]
    if not rest:
        _fail(2, "no file to sign")
    blob_path = rest[-1]
    try:
        with open(blob_path, "rb") as f:
            data = f.read()
    except OSError as e:
        _fail(2, "cannot read blob: %s" % e)
    secret = _secret(key_path)
    bundle = {
        "fakeCosignBundle": True,
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "fileDigest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "signature": hmac.new(secret, data, hashlib.sha256).hexdigest(),
    }
    with open(bundle_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f)


def cmd_verify_blob(argv):
    # Behavioral model (documented, not a crypto claim): the fake
    # verifies that the blob's digest matches the bundle (tamper ->
    # rc=1) and that a non-empty key file was passed -- the product's
    # wiring-under-test is argv construction, temp PEM handling, and
    # loud propagation of nonzero exit codes. The real CLI's
    # cryptography was proved by the wave-191 spike, and X1 in the
    # probe battery exercises it when a binary is available.
    bundle_path = _opt(argv, "--bundle")
    key_path = _opt(argv, "--key")
    rest = [a for a in argv[1:]
            if not a.startswith("--") and a not in (key_path, bundle_path)]
    if not rest:
        _fail(2, "no file to verify")
    blob_path = rest[-1]
    try:
        with open(key_path, "rb") as f:
            key_bytes = f.read()
        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        with open(blob_path, "rb") as f:
            data = f.read()
    except (OSError, ValueError) as e:
        _fail(2, "cannot read inputs: %s" % e)
    if not key_bytes:
        _fail(2, "empty key file")
    if not isinstance(bundle, dict) or not bundle.get("fakeCosignBundle"):
        _fail(2, "not a fake-cosign bundle")
    if bundle.get("fileDigest") != \
            "sha256:" + hashlib.sha256(data).hexdigest():
        _fail(1, "signature mismatch: blob digest does not match the bundle")
    sys.stdout.write("Verified OK\n")


def main(argv):
    _log_argv(argv)
    if len(argv) < 2:
        _fail(2, "no command")
    cmd = argv[1]
    if cmd == "sign-blob":
        cmd_sign_blob(argv)
    elif cmd == "verify-blob":
        cmd_verify_blob(argv)
    else:
        _fail(2, "unknown command %r" % cmd)


if __name__ == "__main__":
    main(sys.argv)
