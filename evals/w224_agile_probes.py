#!/usr/bin/env python3
"""Wave-224 lane C: algorithm-agile posture signals / absence / revocation.

ADAPT of the EMILIA PIP-015 crypto-agility direction (re-derived
prose; nothing copied): the repo's vendored Ed25519 must not be the
only algorithm the posture signals (gov/posture.py), absence records
(gov/absence.py) and revocation entries (gov/revocation.py) can use.

Seams under test:
* gov/alg_registry.py (NEW) — AlgorithmRegistry: register(name, *,
  sign_fn, verify_fn, keygen, domain_separator,
  non_repudiation=True); default_registry() carries
  ``ed25519-rfc8032`` (vendored RFC 8032) and ``hmac-sha256-mac``
  (symmetric MAC tier, non_repudiation=False — a MAC is NOT a
  signature). Registration validates name non-empty, domain
  separator non-empty and unique -> alg-registration-refused.
  sign() with an unregistered alg -> alg-unregistered;
  require_non_repudiation(hmac) -> alg-non-repudiation-refused;
  negotiate(preferred, acceptable) -> highest-preference mutual
  alg, or alg-no-mutual; unknown names -> alg-unregistered.
* gov/posture.py additive — emit_signal(..., alg="ed25519-rfc8032"):
  default emits byte-identical to legacy (no alg field); non-default
  alg records carry "alg" and sign under it; verify_signal(...,
  expect_alg=None): legacy records (no alg) verify as ed25519;
  mismatched expected alg -> alg-mismatch; unknown alg ->
  alg-unregistered.
* gov/absence.py additive — AbsenceIssuer.attest_absence(...,
  alg=...); verify_negative(negative, pubkey, *, expect_alg=None)
  with the same dispatch rules.
* gov/revocation.py additive — RevocationList.revoke(...,
  alg=...); verify() / import_entries(..., expect_alg=None) with
  the same dispatch rules.

Attack shapes: unknown algorithm at sign/verify seams, alg field
tampered post-issuance, MAC record offered where non-repudiation is
required, negotiation with no mutual algorithm, cross-alg replay
(record re-labeled with a different alg), legacy-record confusion.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-223 HEAD
28db79fcbf5b8415cc0ba2b20e48d52530cfcc81.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (alg_registry absent) is expected GAP —
only the legacy pins are verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g224c
  TMPDIR=/var/tmp/g224c ~/workspace/.gov-venv/bin/python evals/w224_agile_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g224c-u \\
      ~/workspace/.gov-venv/bin/python evals/w224_agile_probes.py
"""

import hashlib
import hmac as _hmac
import json
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w224-agile-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g224c-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import alg_registry as ar  # noqa: E402
    _REGISTRY_OK = True
    _REGISTRY_ERR = None
except Exception as exc:  # noqa: BLE001 - import probe records it
    _REGISTRY_OK = False
    _REGISTRY_ERR = exc
    ar = None

try:
    from gov import posture as po  # noqa: E402
    from gov import absence as ab  # noqa: E402
    from gov import revocation as rv  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    _CORE_OK = True
    _CORE_ERR = None
except Exception as exc:  # noqa: BLE001 - import probe records it
    _CORE_OK = False
    _CORE_ERR = exc
    po = ab = rv = _ed = None

_IMPORT_OK = _REGISTRY_OK and _CORE_OK
_IMPORT_ERR = None if _IMPORT_OK else \
    ("alg_registry absent (pristine)" if _CORE_OK else
     "core import failed: %r" % (_CORE_ERR,))

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64

_RESULTS = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records HELD/GAP/BREAK/ERROR on probes and PASS/SKIP/FAIL on its
# depth-1 green checks; the canonical emission vocabulary is
# BREAK/HELD/ERROR/SKIP, mapped red-first (PASS->HELD, GAP/FAIL->BREAK).
# Probe logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _gap(name, detail="absent on base"):
    _record(name, "GAP", detail)


def _break(name, detail):
    _record(name, "BREAK", detail)


def _code_of(exc):
    return getattr(exc, "code", exc.__class__.__name__)


def _expect_refusal(name, code, fn):
    """BREAK unless fn raises an exception carrying ``code``."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == code:
            _held(name, "refused %s" % code)
            return True
        _break(name, "wrong code: %r, expected %r" % (_code_of(exc), code))
        return False
    _break(name, "no refusal raised for %s" % code)
    return False


# ----------------------------------------------------------------------
# Legacy byte-identity pin.
# ----------------------------------------------------------------------

# Captured from the pristine (wave-223) emit path at fixed clock and
# fixed seed — the independent source of truth for "default emit is
# byte-identical to legacy". Filled in from the red run.
_LEGACY_SEED_HEX = \
    "3c773c29f03998737ff2edfb8b58498a7b866fd0f62af5279aefa115dc1493f9"
_LEGACY_SIGNAL_LITERAL = \
    '{"events":{"urn:sasanam:posture:v1:revocation":{"digest":' \
    '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
    '}},"iat":"2023-11-14T22:13:20Z","iss":"posture-issuer","jti":' \
    '"2bd0c7f1d0612d273e52e41de595f93e451f1e5ce82ecc29a1b177245235605f"' \
    ',"scope":"permit","signature":' \
    '"0a1c00af205434e9eca8574a185a85e11b15d664dc848f6b331aad93c5633051' \
    'ef64114813657ea8ad63bb0c552b85409a97b0ea49770723858d09474cb47e0b"' \
    ',"sub":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
    ',"v":1}'


def _legacy_keypair():
    # Deterministic seed so the red-run literal is reproducible.
    seed = hashlib.sha256(b"w224-agile-legacy-pin").digest()
    return seed, _ed.publickey(seed)


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------


@_probe("registry-builtins")
def _p_builtins():
    if not _REGISTRY_OK:
        return _gap("registry-builtins")
    reg = ar.default_registry()
    names = set(reg.names())
    if {"ed25519-rfc8032", "hmac-sha256-mac"} - names:
        return _break("registry-builtins",
                      "missing builtins: %r" % (sorted(names),))
    info = reg.info("hmac-sha256-mac")
    if info.get("non_repudiation") is not False:
        return _break("registry-builtins",
                      "hmac tier not marked non_repudiation=False: %r"
                      % (info,))
    _held("registry-builtins", "both builtins present, hmac tier honest")


@_probe("register-validation")
def _p_register_validation():
    if not _REGISTRY_OK:
        return _gap("register-validation")
    reg = ar.AlgorithmRegistry()
    good = dict(sign_fn=lambda s, m: b"", verify_fn=lambda p, m, s: False,
                keygen=lambda: (b"k", b"k"),
                domain_separator=b"sasanam-test/x:")
    reg.register("test-x", **good)
    # Duplicate name.
    _expect_refusal("register-validation", "alg-registration-refused",
                    lambda: reg.register("test-x", **good))
    # Duplicate domain separator.
    dup = dict(good, domain_separator=b"sasanam-test/x:")
    _expect_refusal("register-validation", "alg-registration-refused",
                    lambda: reg.register("test-y", **dup))
    # Empty domain separator.
    emp = dict(good, domain_separator=b"")
    _expect_refusal("register-validation", "alg-registration-refused",
                    lambda: reg.register("test-z", **emp))
    # Non-callable sign_fn.
    bad = dict(good, sign_fn="not-callable")
    _expect_refusal("register-validation", "alg-registration-refused",
                    lambda: reg.register("test-w", **bad))
    # Signing with an unregistered algorithm.
    _expect_refusal("register-validation", "alg-unregistered",
                    lambda: reg.sign("no-such-alg", b"m", b"k"))


@_probe("ed25519-roundtrip")
def _p_ed_roundtrip():
    if not _REGISTRY_OK:
        return _gap("ed25519-roundtrip")
    reg = ar.default_registry()
    seed = _ed.generate_seed()
    pub = _ed.publickey(seed)
    sig = reg.sign("ed25519-rfc8032", b"hello", seed)
    if not reg.verify("ed25519-rfc8032", b"hello", sig, pub):
        return _break("ed25519-roundtrip", "valid signature failed verify")
    if reg.verify("ed25519-rfc8032", b"hello-tampered", sig, pub):
        return _break("ed25519-roundtrip", "tampered message verified")
    _held("ed25519-roundtrip", "registry ed25519 sign/verify roundtrip")


@_probe("hmac-roundtrip")
def _p_hmac_roundtrip():
    if not _REGISTRY_OK:
        return _gap("hmac-roundtrip")
    reg = ar.default_registry()
    key = secrets.token_bytes(32)
    tag = reg.sign("hmac-sha256-mac", b"hello", key)
    if not reg.verify("hmac-sha256-mac", b"hello", tag, key):
        return _break("hmac-roundtrip", "valid tag failed verify")
    if reg.verify("hmac-sha256-mac", b"hello-tampered", tag, key):
        return _break("hmac-roundtrip", "tampered message verified")
    wrong = secrets.token_bytes(32)
    if reg.verify("hmac-sha256-mac", b"hello", tag, wrong):
        return _break("hmac-roundtrip", "wrong key verified")
    _held("hmac-roundtrip", "hmac sign/verify roundtrip, wrong key fails")


@_probe("non-repudiation-guard")
def _p_non_repudiation():
    if not _REGISTRY_OK:
        return _gap("non-repudiation-guard")
    reg = ar.default_registry()
    # A MAC is NOT a signature: offered as non-repudiation evidence,
    # it fails closed.
    _expect_refusal("non-repudiation-guard",
                    "alg-non-repudiation-refused",
                    lambda: reg.require_non_repudiation(
                        "hmac-sha256-mac"))
    reg.require_non_repudiation("ed25519-rfc8032")  # must not raise
    _held("non-repudiation-guard", "mac tier honestly refused")


@_probe("negotiation")
def _p_negotiation():
    if not _REGISTRY_OK:
        return _gap("negotiation")
    reg = ar.default_registry()
    got = reg.negotiate(["hmac-sha256-mac", "ed25519-rfc8032"],
                        {"ed25519-rfc8032"})
    if got != "ed25519-rfc8032":
        return _break("negotiation", "wrong pick: %r" % (got,))
    got2 = reg.negotiate(["ed25519-rfc8032", "hmac-sha256-mac"],
                         ["hmac-sha256-mac", "ed25519-rfc8032"])
    if got2 != "ed25519-rfc8032":
        return _break("negotiation", "preference order ignored: %r"
                      % (got2,))
    _expect_refusal("negotiation", "alg-no-mutual",
                    lambda: reg.negotiate(["ed25519-rfc8032"], set()))
    # Unknown names are skipped, not refused: they can never be
    # mutual, so this is alg-no-mutual, not alg-unregistered.
    _expect_refusal("negotiation", "alg-no-mutual",
                    lambda: reg.negotiate(["no-such-alg"],
                                          {"ed25519-rfc8032"}))


@_probe("posture-default-byte-identical")
def _p_posture_default():
    # Legacy pin, verifiable on base: the legacy emit shape and, on
    # the red run, the literal capture used for the green comparison.
    if not _CORE_OK:
        return _gap("posture-default-byte-identical",
                    "posture module not importable in this harness")
    seed, pub = _legacy_keypair()
    sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                         issuer_id="posture-issuer", now=1700000000.0)
    if _LEGACY_SIGNAL_LITERAL is None:
        # Red run: capture the literal as the independent source of
        # truth and confirm the legacy shape (no alg field).
        if "alg" in sig:
            return _break("posture-default-byte-identical",
                          "base already carries alg: %r" % (sig,))
        canon = json.dumps(sig, sort_keys=True,
                           separators=(",", ":"))
        print("LEGACY_SIGNAL_LITERAL=%s" % (canon,))
        print("LEGACY_SEED_HEX=%s" % (seed.hex(),))
        _held("posture-default-byte-identical",
              "legacy shape captured (no alg field)")
        return
    # Green run: default emit must reproduce the legacy bytes exactly.
    canon = json.dumps(sig, sort_keys=True,
                       separators=(",", ":"))
    if canon != _LEGACY_SIGNAL_LITERAL:
        return _break("posture-default-byte-identical",
                      "default emit diverged from legacy bytes")
    # And it must verify under the new code as an ed25519 record.
    rec = po.verify_signal(sig, {"posture-issuer": pub})
    if rec["sub"] != _DIGEST_A:
        return _break("posture-default-byte-identical",
                      "legacy record lost sub on verify")
    _held("posture-default-byte-identical",
          "default emit byte-identical to legacy, verifies")


@_probe("posture-hmac-tier")
def _p_posture_hmac():
    if not _IMPORT_OK:
        return _gap("posture-hmac-tier")
    key = secrets.token_bytes(32)
    sig = po.emit_signal("revocation", _DIGEST_A, "permit", key,
                         issuer_id="posture-issuer", now=1700000000.0,
                         alg="hmac-sha256-mac")
    if sig.get("alg") != "hmac-sha256-mac":
        return _break("posture-hmac-tier",
                      "hmac signal carries no alg field: %r" % (sig,))
    rec = po.verify_signal(sig, {"posture-issuer": key})
    if rec["sub"] != _DIGEST_A:
        return _break("posture-hmac-tier",
                      "hmac signal lost sub on verify")
    # Re-labeling the record as ed25519 must not verify: the bytes
    # bound to the hmac domain do not verify under ed25519.
    relabeled = dict(sig, alg="ed25519-rfc8032")
    seed, pub = _legacy_keypair()
    _expect_refusal("posture-hmac-tier", "signal-unverifiable",
                    lambda: po.verify_signal(
                        relabeled, {"posture-issuer": pub}))
    _held("posture-hmac-tier", "hmac signal verifies, re-label fails")


@_probe("posture-expect-alg")
def _p_posture_expect():
    if not _IMPORT_OK:
        return _gap("posture-expect-alg")
    key = secrets.token_bytes(32)
    sig = po.emit_signal("revocation", _DIGEST_A, "permit", key,
                         issuer_id="posture-issuer", now=1700000000.0,
                         alg="hmac-sha256-mac")
    # Consumer pins ed25519: the hmac record fails closed with the
    # alg-mismatch code, not silence.
    _expect_refusal("posture-expect-alg", "alg-mismatch",
                    lambda: po.verify_signal(
                        sig, {"posture-issuer": key},
                        expect_alg="ed25519-rfc8032"))
    # Legacy record (no alg) satisfies an ed25519 pin — backward
    # compatible.
    seed, pub = _legacy_keypair()
    legacy = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                            issuer_id="posture-issuer",
                            now=1700000000.0)
    po.verify_signal(legacy, {"posture-issuer": pub},
                     expect_alg="ed25519-rfc8032")
    _held("posture-expect-alg",
          "expect_alg mismatch refuses; legacy satisfies ed25519 pin")


@_probe("posture-unknown-alg-refused")
def _p_posture_unknown():
    if not _IMPORT_OK:
        return _gap("posture-unknown-alg-refused")
    seed, _pub = _legacy_keypair()
    _expect_refusal("posture-unknown-alg-refused", "alg-unregistered",
                    lambda: po.emit_signal(
                        "revocation", _DIGEST_A, "permit", seed,
                        issuer_id="posture-issuer", now=1700000000.0,
                        alg="rot13"))
    # A record claiming an unknown alg fails closed at verify too.
    sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                         issuer_id="posture-issuer", now=1700000000.0)
    forged = dict(sig, alg="rot13")
    _expect_refusal("posture-unknown-alg-refused", "alg-unregistered",
                    lambda: po.verify_signal(
                        forged, {"posture-issuer": _pub}))


@_probe("absence-hmac-tier")
def _p_absence_hmac():
    if not _IMPORT_OK:
        return _gap("absence-hmac-tier")
    key = secrets.token_bytes(32)
    issuer = ab.AbsenceIssuer("abs-issuer", key, alg="hmac-sha256-mac") \
        if _supports_issuer_alg() else None
    if issuer is None:
        # alg param on the issuer constructor; attest may also take it.
        issuer = ab.AbsenceIssuer("abs-issuer", key)
    neg = issuer.attest_absence(_DIGEST_A, now=1700000000.0,
                                alg="hmac-sha256-mac")
    if neg.get("alg") != "hmac-sha256-mac":
        return _break("absence-hmac-tier",
                      "hmac negative carries no alg: %r" % (neg,))
    rec = ab.verify_negative(neg, key)
    if rec["claim"] != "never-advertised":
        return _break("absence-hmac-tier",
                      "negative lost claim on verify")
    tampered = dict(neg, subject_digest=_DIGEST_B)
    _expect_refusal("absence-hmac-tier", "absence-unverifiable",
                    lambda: ab.verify_negative(tampered, key))
    _expect_refusal("absence-hmac-tier", "alg-mismatch",
                    lambda: ab.verify_negative(
                        neg, key, expect_alg="ed25519-rfc8032"))
    _held("absence-hmac-tier",
          "hmac negative verifies; tamper and mismatch fail closed")


def _supports_issuer_alg():
    try:
        ab.AbsenceIssuer("probe", secrets.token_bytes(32),
                         alg="hmac-sha256-mac")
        return True
    except TypeError:
        return False


@_probe("absence-legacy-verifies")
def _p_absence_legacy():
    # Legacy pin: ed25519 negatives from the base code keep
    # verifying under the new code.
    if not _CORE_OK:
        return _gap("absence-legacy-verifies",
                    "absence module not importable in this harness")
    seed, pub = _legacy_keypair()
    issuer = ab.AbsenceIssuer("abs-issuer", seed)
    neg = issuer.attest_absence(_DIGEST_A, now=1700000000.0)
    if _IMPORT_OK:
        rec = ab.verify_negative(neg, pub,
                                 expect_alg="ed25519-rfc8032")
        if rec["claim"] != "never-advertised":
            return _break("absence-legacy-verifies",
                          "legacy negative lost claim")
        _held("absence-legacy-verifies",
              "legacy negative verifies, satisfies ed25519 pin")
    else:
        # Red run: base behavior check only.
        if "alg" in neg:
            return _break("absence-legacy-verifies",
                          "base already carries alg: %r" % (neg,))
        _held("absence-legacy-verifies", "legacy shape has no alg")


@_probe("revocation-hmac-tier")
def _p_revoke_hmac():
    if not _IMPORT_OK:
        return _gap("revocation-hmac-tier")
    key = secrets.token_bytes(32)
    rl = rv.RevocationList()
    entry = rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=key,
                      now=1700000000.0, alg="hmac-sha256-mac")
    if entry.get("alg") != "hmac-sha256-mac":
        return _break("revocation-hmac-tier",
                      "hmac entry carries no alg: %r" % (entry,))
    rl.verify({"rev-issuer": key})
    if rl.check(_DIGEST_A) != "revoked":
        return _break("revocation-hmac-tier", "check lost revocation")
    fresh = rv.RevocationList()
    fresh.import_entries([entry], {"rev-issuer": key})
    if fresh.check(_DIGEST_A) != "revoked":
        return _break("revocation-hmac-tier",
                      "import lost the hmac entry")
    _expect_refusal("revocation-hmac-tier", "alg-mismatch",
                    lambda: fresh.verify(
                        {"rev-issuer": key},
                        expect_alg="ed25519-rfc8032"))
    _held("revocation-hmac-tier",
          "hmac entry verifies/imports; mismatch fails closed")


@_probe("revocation-legacy-verifies")
def _p_revoke_legacy():
    # Legacy pin: ed25519 entries from the base code keep
    # verifying under the new code.
    if not _CORE_OK:
        return _gap("revocation-legacy-verifies",
                    "revocation module not importable in this harness")
    seed, pub = _legacy_keypair()
    rl = rv.RevocationList()
    entry = rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=seed,
                      now=1700000000.0)
    if _IMPORT_OK:
        rl.verify({"rev-issuer": pub}, expect_alg="ed25519-rfc8032")
        fresh = rv.RevocationList()
        fresh.import_entries([entry], {"rev-issuer": pub})
        if fresh.check(_DIGEST_A) != "revoked":
            return _break("revocation-legacy-verifies",
                          "import lost the legacy entry")
        _held("revocation-legacy-verifies",
              "legacy entry verifies/imports, satisfies ed25519 pin")
    else:
        if "alg" in entry:
            return _break("revocation-legacy-verifies",
                          "base already carries alg: %r" % (entry,))
        _held("revocation-legacy-verifies", "legacy shape has no alg")


@_probe("determinism")
def _p_determinism():
    if not _IMPORT_OK:
        return _gap("determinism")
    key = secrets.token_bytes(32)
    sig1 = po.emit_signal("revocation", _DIGEST_A, "permit", key,
                          issuer_id="posture-issuer", now=1700000000.0,
                          alg="hmac-sha256-mac")
    sig2 = po.emit_signal("revocation", _DIGEST_A, "permit", key,
                          issuer_id="posture-issuer", now=1700000000.0,
                          alg="hmac-sha256-mac")
    if sig1["signature"] != sig2["signature"]:
        return _break("determinism",
                      "hmac emit nondeterministic under fixed clock")
    seed = _ed.generate_seed()
    sig3 = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                          issuer_id="posture-issuer", now=1700000000.0)
    sig4 = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                          issuer_id="posture-issuer", now=1700000000.0)
    if sig3["signature"] != sig4["signature"]:
        return _break("determinism",
                      "ed25519 emit nondeterministic under fixed clock")
    _held("determinism", "both tiers deterministic under fixed clock")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_once():
    _RESULTS.clear()
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001 - never lose a probe
            _record(name, "ERROR", "%r" % (exc,))
    return list(_RESULTS)


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_alg_registry.py",
                 "tests/test_posture.py",
                 "tests/test_absence_revocation.py",
                 "tests/test_permit_leases.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _RESULTS]
    # Green-check pids are renamed value-only ("/" -> "_") so every
    # emitted pid stays inside [A-Za-z0-9_.-] (D7).
    final += [(n.replace("/", "_"), _VERDICT_MAP[s], d)
              for n, s, d in green]
    probe_lines.emit(final)
    brk_c = sum(1 for _, v, _ in final if v == "BREAK")
    held_c = sum(1 for _, v, _ in final if v == "HELD")
    err_c = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk_c, held_c, err_c)
    if not _coh_ok:
        print("coherence-WARNING: %s" % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk_c, held_c, err_c))
    print("w224 agile probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_REGISTRY_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
