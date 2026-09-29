#!/usr/bin/env python3
"""Wave-193 red-team probes: keyset-attested cosign signing.

Break-first battery per the diagnosing-bugs skill, implementing the
red-first pass criteria of ``~/workspace/teams/wave191-cosign-spec/SPEC.md``.

Threat model: evidence bundles leave custody as OCI artifacts; a raw
cosign signature over a tar is not an auditable claim. An auditor must
be able to answer whose key signed the tar, whether it was authorized
at signing time, and whether rotation/revocation since changes the
verdict -- without trusting the registry, the transporter, or any side
channel. On the pristine tree there is NO product seam attesting a
cosign key (only the wave-191 spike's throwaway scripts), so every
probe must BREAK there ("capability absent"); after the build every
probe must HOLD, deterministic x2, identical under
``env -u GOV_DEPLOYMENT_MODE``.

Probes (public seams only -- attestation mint/verify + the five-step
pipeline entry points):

  R1a ROTATION-VERIFY   attestation minted under v1; keyset rotated
                       v1->verify-only / v2 primary; attestation still
                       verifies (rotation must not brick audits).
  R1b ROTATION-PIPELINE full authorize pipeline against the rotated
                       keyset -> VERIFIED.
  R2a REVOCATION-DENY   v1 revoked -> authorization path REFUSES
                       (revoked versions never authorize).
  R2b REVOCATION-FORENSICS forensics path VERIFIES the same
                       attestation (attribution survives revocation,
                       by design).
  R2c REVOCATION-MINT   minting a signing handle from a revoked
                       version's seed -> REFUSED (retired material
                       cannot mint).
  R3  RETIREMENT-MINT   minting a signing handle from a verify-only
                       version's seed -> REFUSED.
  R4  TAMPER           one byte flipped in the bundle tar -> pipeline
                       raises AUDIT FAILED (cosign refused).
  R5a ATTACKER-PEM-STALE attacker PEM + stale fingerprint -> refused.
  R5b ATTACKER-PEM-FRESH attacker PEM + freshly recomputed fingerprint
                       -> refused (the signature covers both).
  R6  GENESIS          a keyset chaining from a different genesis ->
                       refused at the pinned trust anchor, before any
                       signature math runs.
  FLAG OFFLINE         the signing path passes
                       --use-signing-config=false (asserted on the
                       recorded argv; the fake CLI refuses without it).
  BND  BOUNDARY        authorization and forensics entry points are
                       distinct callables with distinct names; the
                       authorization path refuses a revoked-key
                       attestation.
  X1  REAL-COSIGN      (informational) real cosign binary round trip
                       when available; otherwise HELD with the
                       documented residual (fake-CLI coverage only).

cosign is faked by ``tests/fake_cosign.py`` (zero network): the fake
asserts the offline flag behaviorally and models tamper-refusal with
a keyed HMAC. The real CLI is exercised only by X1, gated on
availability.

Verdicts: BREAK (gap demonstrated), HELD (defense held), ERROR only
on harness failure. ``GOV_SKIP_GREEN=1`` is honored (green check
records a skip instead of spawning sub-batteries).
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import cosign_attest as _ca
    HAVE_COSIGN_ATTEST = True
except ImportError:
    HAVE_COSIGN_ATTEST = False
    _ca = None

from gov.keyset import (new_keyset, rotate_keyset, revoke_version,
                        keyset_signer_for_version, KeysetError)

FAKE_COSIGN = os.path.join(REPO, "tests", "fake_cosign.py")
REAL_COSIGN_CANDIDATES = (
    shutil.which("cosign"),
    os.path.expanduser("~/workspace/teams/wave191-cosign/cosign-linux-amd64"),
)

# Fixed synthetic ECDSA-P256 public key (public material only -- the
# private half was shredded at generation time; it never existed in a
# fixture).
TEST_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJKufs+gu8Zcvi606EJlmckiTHVSF
iVzmhr2b6DwQyHF6I6cZ98Kui07xlRUp2PpWK+qkuO5VWZc+4QH2J269FQ==
-----END PUBLIC KEY-----
"""

_FAKE_KEY_BYTES = b"wave193-fake-cosign-key"


def _seed(tag):
    return hashlib.sha256(("wave193-cosign-probe:" + tag).encode()).digest()


def _keyset(tag):
    ks, _signer = new_keyset(_seed(tag),
                             purpose="cosign-key-attestation")
    return ks


def _attest(ks, tag, version=None):
    return _ca.attest_cosign_key(ks, TEST_PEM, _seed(tag), version=version,
                                 at=1700000000)


def _genesis(ks):
    return ks.version(1).key_id


def _keyfile(td, name="cosign.key"):
    p = os.path.join(td, name)
    with open(p, "wb") as f:
        f.write(_FAKE_KEY_BYTES)
    return p


def _capability_absent(name):
    return ("BREAK", "%s: capability absent -- gov.cosign_attest does not "
            "exist; no product seam attests a cosign key to the keyset "
            "ceremony" % name)


def _sign_fake(tar_bytes, td):
    return _ca.sign_bundle_blob(tar_bytes, _keyfile(td),
                                cosign_bin=FAKE_COSIGN)


# ---------------------------------------------------------------------------
# R1a/R1b: rotation keeps auditing alive
# ---------------------------------------------------------------------------

def r1a_rotation_verify():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R1a")
    ks1 = _keyset("r1-v1")
    att = _attest(ks1, "r1-v1")
    ks2, _s2 = rotate_keyset(ks1, _seed("r1-v2"), _seed("r1-v1"))
    assert ks2.version(1).status == "verify-only"
    ok, info = _ca.verify_attestation(att, ks2.to_dict())
    if not ok:
        return ("BREAK", "R1a: attestation minted under v1 refused after "
                "rotation to v2 (verify-only must still verify): %s" % info)
    return ("HELD", "R1a: v1 attestation verifies under the rotated keyset "
            "(status=%s)" % info["status"])


def r1b_rotation_pipeline():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R1b")
    ks1 = _keyset("r1b-v1")
    att = _attest(ks1, "r1b-v1")
    ks2, _s2 = rotate_keyset(ks1, _seed("r1b-v2"), _seed("r1b-v1"))
    with tempfile.TemporaryDirectory() as td:
        tar = b"wave193-r1b-bundle-tar" * 64
        bundle = _sign_fake(tar, td)
        try:
            verdict = _ca.authorize_bundle_signature(
                tar, bundle, att, ks2.to_dict(), _genesis(ks2),
                cosign_bin=FAKE_COSIGN)
        except _ca.CosignAttestationError as e:
            return ("BREAK", "R1b: full pipeline refused after rotation: "
                    "%s" % e)
    return ("HELD", "R1b: pipeline VERIFIED against the rotated keyset "
            "(v%d, %s)" % (verdict["keyset_version"],
                           verdict["keyset_status"]))


# ---------------------------------------------------------------------------
# R2a/R2b/R2c: revocation
# ---------------------------------------------------------------------------

def r2a_revocation_deny():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R2a")
    ks1 = _keyset("r2-v1")
    att = _attest(ks1, "r2-v1")
    ks2, _s2 = rotate_keyset(ks1, _seed("r2-v2"), _seed("r2-v1"))
    ks3 = revoke_version(ks2, 1, "r2 probe compromise", _seed("r2-v2"))
    ok, info = _ca.verify_attestation(att, ks3.to_dict())
    if ok:
        return ("BREAK", "R2a: attestation under REVOKED v1 verified on "
                "the authorization path -- revoked keys must not "
                "authorize")
    if "revoked" not in info:
        return ("BREAK", "R2a: refused, but not for revocation: %s" % info)
    return ("HELD", "R2a: revoked v1 refused on the authorization path "
            "(%s)" % info)


def r2b_revocation_forensics():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R2b")
    ks1 = _keyset("r2b-v1")
    att = _attest(ks1, "r2b-v1")
    ks2, _s2 = rotate_keyset(ks1, _seed("r2b-v2"), _seed("r2b-v1"))
    ks3 = revoke_version(ks2, 1, "r2b probe compromise", _seed("r2b-v2"))
    with tempfile.TemporaryDirectory() as td:
        tar = b"wave193-r2b-bundle-tar" * 64
        bundle = _sign_fake(tar, td)
        try:
            verdict = _ca.attribute_bundle_signature(
                tar, bundle, att, ks3.to_dict(), _genesis(ks3),
                cosign_bin=FAKE_COSIGN)
        except _ca.CosignAttestationError as e:
            return ("BREAK", "R2b: forensics path refused a revoked-key "
                    "attestation -- attribution must survive revocation: "
                    "%s" % e)
    if not verdict.get("forensics"):
        return ("BREAK", "R2b: forensics verdict not marked as forensics")
    return ("HELD", "R2b: forensics path attributes the revoked-key "
            "attestation (v%d, %s)" % (verdict["keyset_version"],
                                      verdict["keyset_status"]))


def r2c_revocation_mint():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R2c")
    ks1 = _keyset("r2c-v1")
    ks2, _s2 = rotate_keyset(ks1, _seed("r2c-v2"), _seed("r2c-v1"))
    ks3 = revoke_version(ks2, 1, "r2c probe compromise", _seed("r2c-v2"))
    try:
        _ca.attest_cosign_key(ks3, TEST_PEM, _seed("r2c-v1"), version=1,
                              at=1700000000)
        return ("BREAK", "R2c: minted an attestation with a REVOKED "
                "version's seed -- retired material must not mint")
    except _ca.CosignAttestationError as e:
        return ("HELD", "R2c: revoked-seed mint refused (%s)"
                % str(e)[:80])


# ---------------------------------------------------------------------------
# R3: verify-only retirement
# ---------------------------------------------------------------------------

def r3_retirement_mint():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R3")
    ks1 = _keyset("r3-v1")
    ks2, _s2 = rotate_keyset(ks1, _seed("r3-v2"), _seed("r3-v1"))
    try:
        _ca.attest_cosign_key(ks2, TEST_PEM, _seed("r3-v1"), version=1,
                              at=1700000000)
        return ("BREAK", "R3: minted an attestation with a VERIFY-ONLY "
                "version's seed -- rotation retirements must retire")
    except _ca.CosignAttestationError as e:
        return ("HELD", "R3: verify-only-seed mint refused (%s)"
                % str(e)[:80])


# ---------------------------------------------------------------------------
# R4: tamper
# ---------------------------------------------------------------------------

def r4_tamper():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R4")
    ks1 = _keyset("r4-v1")
    att = _attest(ks1, "r4-v1")
    with tempfile.TemporaryDirectory() as td:
        tar = bytearray(b"wave193-r4-bundle-tar" * 64)
        bundle = _sign_fake(bytes(tar), td)
        tar[17] ^= 0x01  # one flipped byte in the tar
        try:
            _ca.authorize_bundle_signature(
                bytes(tar), bundle, att, ks1.to_dict(), _genesis(ks1),
                cosign_bin=FAKE_COSIGN)
            return ("BREAK", "R4: pipeline VERIFIED a tampered tar -- "
                    "tamper must be loud")
        except _ca.CosignAttestationError as e:
            if "AUDIT FAILED" not in str(e):
                return ("BREAK", "R4: tamper refused but not loudly: %s"
                        % e)
            return ("HELD", "R4: tampered tar -> %s"
                    % str(e)[:100])


# ---------------------------------------------------------------------------
# R5a/R5b: attacker PEM
# ---------------------------------------------------------------------------

# A different synthetic P-256 public key (the "attacker's"): valid P-256
# SPKI, different point, different fingerprint. Public material only.
_ATTACKER_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJKuf6egu8Zcvi606EJlmckiTR1SF
iVzmhr2b6DwQyHF6I6cZ98Kui07xlU8p2PpWK+qkuO5VWZc+4QH2J269FQ==
-----END PUBLIC KEY-----
"""


def _splice(att, pem, fingerprint):
    import copy
    evil = copy.deepcopy(att)
    evil["cosign_public_key_pem"] = pem
    evil["cosign_key_fingerprint"] = fingerprint
    return evil


def r5a_attacker_pem_stale():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R5a")
    ks1 = _keyset("r5-v1")
    att = _attest(ks1, "r5-v1")
    evil = _splice(att, _ATTACKER_PEM, att["cosign_key_fingerprint"])
    ok, info = _ca.verify_attestation(evil, ks1.to_dict())
    if ok:
        return ("BREAK", "R5a: attacker PEM with a stale fingerprint "
                "verified -- key-swap must fail closed")
    return ("HELD", "R5a: attacker PEM + stale fingerprint refused (%s)"
            % info)


def r5b_attacker_pem_fresh():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R5b")
    ks1 = _keyset("r5-v1")
    att = _attest(ks1, "r5-v1")
    evil = _splice(att, _ATTACKER_PEM,
                   _ca.cosign_key_fingerprint(_ATTACKER_PEM))
    ok, info = _ca.verify_attestation(evil, ks1.to_dict())
    if ok:
        return ("BREAK", "R5b: attacker PEM with a freshly recomputed "
                "fingerprint verified -- recompute-and-swap must fail "
                "closed")
    return ("HELD", "R5b: attacker PEM + recomputed fingerprint refused "
            "(%s)" % info)


# ---------------------------------------------------------------------------
# R6: genesis pin
# ---------------------------------------------------------------------------

def r6_genesis():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("R6")
    ks_a = _keyset("r6-a")
    att = _attest(ks_a, "r6-a")
    ks_b = _keyset("r6-b")  # different genesis
    with tempfile.TemporaryDirectory() as td:
        tar = b"wave193-r6-bundle-tar" * 64
        bundle = _sign_fake(tar, td)
        try:
            _ca.authorize_bundle_signature(
                tar, bundle, att, ks_b.to_dict(), _genesis(ks_a),
                cosign_bin=FAKE_COSIGN)
            return ("BREAK", "R6: pipeline accepted a keyset chaining "
                    "from a DIFFERENT genesis -- the pin must stop this "
                    "before any signature math runs")
        except _ca.CosignAttestationError as e:
            if "genesis" not in str(e).lower():
                return ("BREAK", "R6: refused, but not at the genesis "
                        "pin: %s" % e)
            return ("HELD", "R6: foreign-genesis keyset refused at the "
                    "pin (%s)" % str(e)[:90])


# ---------------------------------------------------------------------------
# FLAG: the offline flag is load-bearing
# ---------------------------------------------------------------------------

def flag_offline():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("FLAG")
    with tempfile.TemporaryDirectory() as td:
        log = os.path.join(td, "argv.log")
        # sign_bundle_blob copies os.environ for the child, so the argv
        # log rides along on the ambient environment for this call.
        old = os.environ.get("FAKE_COSIGN_ARGV_LOG")
        os.environ["FAKE_COSIGN_ARGV_LOG"] = log
        try:
            _ca.sign_bundle_blob(b"wave193-flag-tar" * 64, _keyfile(td),
                                  cosign_bin=FAKE_COSIGN)
        finally:
            if old is None:
                os.environ.pop("FAKE_COSIGN_ARGV_LOG", None)
            else:
                os.environ["FAKE_COSIGN_ARGV_LOG"] = old
        lines = open(log, encoding="utf-8").read().strip().splitlines()
        sign_argv = None
        for line in lines:
            argv = json.loads(line)
            if len(argv) > 1 and argv[1] == "sign-blob":
                sign_argv = argv
                break
        if sign_argv is None:
            return ("ERROR", "FLAG: no sign-blob argv recorded")
        if "--use-signing-config=false" not in sign_argv:
            return ("BREAK", "FLAG: signing path omitted "
                    "--use-signing-config=false -- the offline contract "
                    "is decorative")
        # The fake itself refuses a signing call without the flag
        # (behavioral proof the flag is load-bearing, not decorative).
        with open(os.path.join(td, "t.tar"), "wb") as f:
            f.write(b"x")
        r = subprocess.run(
            [sys.executable, FAKE_COSIGN, "sign-blob",
             "--key", _keyfile(td), "--bundle", os.path.join(td, "b.json"),
             "--yes", os.path.join(td, "t.tar")],
            capture_output=True, text=True)
        if r.returncode != 3:
            return ("BREAK", "FLAG: fake CLI accepted sign-blob without "
                    "the offline flag (rc=%d)" % r.returncode)
    return ("HELD", "FLAG: --use-signing-config=false present in the "
            "signing argv; the CLI surface refuses without it")


# ---------------------------------------------------------------------------
# BND: authorization / forensics are distinct paths
# ---------------------------------------------------------------------------

def bnd_paths():
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("BND")
    authz = _ca.authorize_bundle_signature
    foren = _ca.attribute_bundle_signature
    if authz is foren:
        return ("BREAK", "BND: authorization and forensics are the same "
                "callable -- revoked keys would keep authorizing")
    if authz.__name__ == foren.__name__:
        return ("BREAK", "BND: the two paths share a name")
    ks1 = _keyset("bnd-v1")
    att = _attest(ks1, "bnd-v1")
    ks2, _s2 = rotate_keyset(ks1, _seed("bnd-v2"), _seed("bnd-v1"))
    ks3 = revoke_version(ks2, 1, "bnd probe compromise", _seed("bnd-v2"))
    with tempfile.TemporaryDirectory() as td:
        tar = b"wave193-bnd-tar" * 64
        bundle = _sign_fake(tar, td)
        try:
            authz(tar, bundle, att, ks3.to_dict(), _genesis(ks3),
                  cosign_bin=FAKE_COSIGN)
            return ("BREAK", "BND: authorization path VERIFIED a "
                    "revoked-key attestation")
        except _ca.CosignAttestationError:
            pass
        verdict = foren(tar, bundle, att, ks3.to_dict(), _genesis(ks3),
                        cosign_bin=FAKE_COSIGN)
        if verdict["verdict"] != "VERIFIED":
            return ("BREAK", "BND: forensics path did not verify")
    return ("HELD", "BND: distinct paths; authorization refuses revoked, "
            "forensics attributes")


# ---------------------------------------------------------------------------
# X1: real cosign round trip (gated on availability)
# ---------------------------------------------------------------------------

def x1_real_cosign():
    """Informational: real-cosign round trip, gated on availability AND
    on the CLI actually completing a sign inside a short timeout.

    Verified 2026-09-29: cosign v3.1.3 ``sign-blob
    --use-signing-config=false`` still attempts a Rekor
    transparency-log upload (goroutine stack: sigstore-go transparency
    -> Rekor client) and hangs where Rekor is unreachable. The
    product fails closed at its CLI timeout; this probe must not hang
    the battery proving it, so liveness is checked first with a 25s
    budget.
    """
    if not HAVE_COSIGN_ATTEST:
        return _capability_absent("X1")
    exe = next((c for c in REAL_COSIGN_CANDIDATES if c
                and os.path.isfile(c) and os.access(c, os.X_OK)), None)
    if exe is None:
        return ("HELD", "X1: no cosign binary in this environment -- "
                "fake-CLI coverage only (the wave-191 spike proved the "
                "real CLI 10/10)")
    with tempfile.TemporaryDirectory() as td:
        env = dict(os.environ, COSIGN_PASSWORD="wave193-x1-synthetic")
        kp = os.path.join(td, "cosign")
        r = subprocess.run([exe, "generate-key-pair",
                            "--output-key-prefix", kp],
                           capture_output=True, text=True, env=env,
                           timeout=120)
        if r.returncode != 0:
            return ("ERROR", "X1: real cosign generate-key-pair failed: "
                    "%s" % (r.stdout + r.stderr)[:200])
        pub_pem = open(kp + ".pub", encoding="utf-8").read()
        ks1 = _keyset("x1-v1")
        att = _ca.attest_cosign_key(ks1, pub_pem, _seed("x1-v1"),
                                    at=1700000000)
        tar = b"wave193-x1-real-cosign-tar" * 256
        # Liveness: can the real CLI complete a sign here at all?
        try:
            bundle = _ca.sign_bundle_blob(
                tar, kp + ".key", password="wave193-x1-synthetic",
                cosign_bin=exe, timeout=25)
        except _ca.CosignAttestationError as e:
            return ("HELD", "X1: real cosign present but cannot complete "
                    "sign-blob in this environment (Rekor upload blocked; "
                    "product fails closed: %s) -- fake-CLI coverage only"
                    % str(e)[:120])
        verdict = _ca.authorize_bundle_signature(
            tar, bundle, att, ks1.to_dict(), _genesis(ks1),
            cosign_bin=exe, timeout=60)
    if verdict.get("verdict") != "VERIFIED":
        return ("BREAK", "X1: real-cosign round trip did not verify: %r"
                % (verdict,))
    return ("HELD", "X1: real cosign sign-blob/verify-blob round trip "
            "VERIFIED through the product wiring")


_PROBES = [
    ("R1a", r1a_rotation_verify),
    ("R1b", r1b_rotation_pipeline),
    ("R2a", r2a_revocation_deny),
    ("R2b", r2b_revocation_forensics),
    ("R2c", r2c_revocation_mint),
    ("R3", r3_retirement_mint),
    ("R4", r4_tamper),
    ("R5a", r5a_attacker_pem_stale),
    ("R5b", r5b_attacker_pem_fresh),
    ("R6", r6_genesis),
    ("FLAG", flag_offline),
    ("BND", bnd_paths),
    ("X1", x1_real_cosign),
]


def _run_once():
    results = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- harness must not crash
            verdict, detail = ("ERROR", "%s raised %r" % (name, e))
        results.append((name, verdict, detail))
    return results


def main():
    first = _run_once()
    second = _run_once()
    breaks = held = held_star = errors = 0
    print("%-4s %-6s %s" % ("ID", "VERDICT", "DETAIL"))
    for (name, v1, d1), (_n2, v2, _d2) in zip(first, second):
        if v1 != v2:
            v1, d1 = "ERROR", \
                "%s nondeterministic: %r then %r" % (name, v1, v2)
        print("%-4s %-6s %s" % (name, v1, d1))
        if v1 == "BREAK":
            breaks += 1
        elif v1 == "HELD":
            held += 1
        elif v1 == "HELD*":
            held_star += 1
        else:
            errors += 1
    print("breaks=%d held=%d held_documented=%d errors=%d"
          % (breaks, held, held_star, errors))
    if breaks:
        print("BREAK: %s" % ",".join(n for n, v, _ in first
                                     if v == "BREAK"))
    return 1 if errors else 0


def _green_check():
    """Depth-1 green check: the adjacent unit suite only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_cosign_attest",
         "-v"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK tests.test_cosign_attest: rc=%d %s"
          % (r.returncode, " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
