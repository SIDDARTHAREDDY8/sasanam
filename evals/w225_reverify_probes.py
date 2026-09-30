#!/usr/bin/env python3
"""Wave-225 lane B: live parent re-verification at use time.

ADAPT of the Mandate JWT -06 direction (re-derived prose; nothing
copied): a credential/capsule/lease chain verified once at issuance is
not enough. At USE time the consumer must re-verify the parent's
signature AND its current non-revoked state AND its liveness. Trust is
re-established per use, never inherited from an earlier check.

Seams under test:
* gov/reverify.py — UseTimeVerifier(revocation_registry=None,
  max_verification_age=300, now=None, audit=None):
  .verify_at_use(envelope, *, expect_alg=None) where the envelope is
  {v, parent_kind, parent, parent_pubkeys, parent_digest,
  parent_expires_at, last_verified_at}; checks signature of the
  parent (kind-dispatched, algorithm-dispatched via
  gov/alg_registry.py) -> ``reverify-parent-signature-invalid``;
  revocation of parent_digest when a registry is attached ->
  ``reverify-revoked``; parent past TTL or last_verified_at older
  than max_verification_age -> ``reverify-stale``; returns a
  UseTimeReceipt {v, record_digest, parent_digest, verified_at,
  outcome} — evidence, never authority.
  reverify_receipt_carries_no_authority(record) ->
  ``reverify-not-authorization`` for receipt-shaped records.
* gov/permit_leases.py additive wiring — PermitLease.redeem(...,
  reverify_at_use=False, use_verifier=None, use_record=None):
  when True and the use-time receipt is missing or invalid ->
  ``reverify-required``; default False leaves the legacy path
  byte-identical.

Attack shapes: tampered parent signature, forged parent key,
revoked parent presented at use, expired parent, stale cached
verification replayed past max_verification_age, unknown parent
kind, malformed envelope, unknown algorithm name, receipt laundered
as authorization, redeem with the opt-in flag but no fresh receipt.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against wave-224 HEAD
186c2b5c5465b9fda67e8b0afa0dc338b0b3212b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP — only
the legacy redeem pins are verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.
NO in-repo git subprocess pins (wave-36 probe fails closed on them).

Run:
  mkdir -p /var/tmp/g225r
  TMPDIR=/var/tmp/g225r ~/workspace/.gov-venv/bin/python evals/w225_reverify_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g225r-u \\
      ~/workspace/.gov-venv/bin/python evals/w225_reverify_probes.py
"""

import os
import secrets
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w225-reverify-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g225r-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import reverify as rvf  # noqa: E402
    _REVERIFY_OK = True
except Exception:  # noqa: BLE001 - import probe records it
    _REVERIFY_OK = False
    rvf = None

try:
    from gov import posture as po  # noqa: E402
    from gov import absence as ab  # noqa: E402
    from gov import revocation as rc  # noqa: E402
    from gov import permit_leases as pl  # noqa: E402
    from gov import alg_registry as algs  # noqa: E402
    _CORE_OK = True
except Exception:  # noqa: BLE001 - import probe records it
    _CORE_OK = False
    po = ab = rc = pl = algs = None

_IMPORT_OK = _REVERIFY_OK and _CORE_OK
_IMPORT_ERR = ("gov.reverify absent (pristine)"
               if not _REVERIFY_OK else "core import failed")

_FIXED_NOW = 1780000000.0
_DIGEST = "a" * 64

_RESULTS = []
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
    except Exception as exc:  # noqa: BLE001 - verdict logic
        if _code_of(exc) == code:
            _held(name, "refused %s" % code)
        else:
            _break(name, "wrong code: got %r want %r (%s)"
                   % (_code_of(exc), code, exc))
    else:
        _break(name, "no refusal for %s" % code)


# ----------------------------------------------------------------------
# Fixtures.
# ----------------------------------------------------------------------

_ALGS = algs.default_registry() if _CORE_OK else None


def _mint_ed():
    seed, pub = _ALGS.keygen("ed25519-rfc8032")
    return seed, pub


def _mint_signal(seed, now=_FIXED_NOW, subject=_DIGEST,
                 scope="scope:alpha"):
    return po.emit_signal("permit-refusal", subject, scope, seed,
                          issuer_id="iss-a", kind="permit-revoked",
                          now=now)


def _mint_absence(seed, now=_FIXED_NOW):
    issuer = ab.AbsenceIssuer("iss-b", seed)
    return issuer, issuer.attest_absence("deadbeef" * 8, now=now)


def _envelope(parent, kind, pubkeys, digest, expires=None,
              last_verified=None):
    return {"v": 1,
            "parent_kind": kind,
            "parent": parent,
            "parent_pubkeys": pubkeys,
            "parent_digest": digest,
            "parent_expires_at": expires,
            "last_verified_at": last_verified}


def _verifier(**kw):
    kw.setdefault("now", lambda: _FIXED_NOW)
    return rvf.UseTimeVerifier(**kw)


def _lease(now=_FIXED_NOW):
    reg = pl.PermitRegistry(now=lambda: now)
    digest = pl.parameter_digest({"a": 1})
    lease = reg.issue("permit-rv", params_digest=digest,
                      grant_scope={"action": {"read"}}, ttl_s=600)
    return reg, lease, digest, lambda: now


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("rv00-import")
def _p_import():
    if not _REVERIFY_OK:
        _gap("rv00-import", _IMPORT_ERR)
    else:
        _held("rv00-import", "gov.reverify imports")


@_probe("rv01-valid-parent-verifies")
def _p_valid():
    if not _IMPORT_OK:
        _gap("rv01-valid-parent-verifies", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"])
    receipt = _verifier().verify_at_use(env)
    want = {"v", "record_digest", "parent_digest", "verified_at",
            "outcome"}
    if set(receipt) != want:
        _break("rv01-valid-parent-verifies",
               "receipt fields %r != %r" % (sorted(receipt), sorted(want)))
    elif receipt["parent_digest"] != sig["jti"] \
            or receipt["outcome"] != "verified":
        _break("rv01-valid-parent-verifies",
               "receipt contents wrong: %r" % (receipt,))
    else:
        _held("rv01-valid-parent-verifies", "receipt %r" % (receipt,))


@_probe("rv02-tampered-parent")
def _p_tampered():
    if not _IMPORT_OK:
        _gap("rv02-tampered-parent", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    sig["sub"] = "f" * 64  # tamper after signing
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"])
    _expect_refusal("rv02-tampered-parent",
                    "reverify-parent-signature-invalid",
                    lambda: _verifier().verify_at_use(env))


@_probe("rv03-forged-parent")
def _p_forged():
    if not _IMPORT_OK:
        _gap("rv03-forged-parent", _IMPORT_ERR)
        return
    seed_a, _pub_a = _mint_ed()
    _seed_b, pub_b = _mint_ed()  # attacker presents the wrong key
    sig = _mint_signal(seed_a)
    env = _envelope(sig, "posture-signal", {"iss-a": pub_b}, sig["jti"])
    _expect_refusal("rv03-forged-parent",
                    "reverify-parent-signature-invalid",
                    lambda: _verifier().verify_at_use(env))


@_probe("rv04-revoked-parent")
def _p_revoked():
    if not _IMPORT_OK:
        _gap("rv04-revoked-parent", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    rlist = rc.RevocationList()
    rlist.revoke(sig["jti"], issuer_id="rev-iss", seed=seed,
                 now=_FIXED_NOW)
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"])
    _expect_refusal("rv04-revoked-parent", "reverify-revoked",
                    lambda: _verifier(
                        revocation_registry=rlist).verify_at_use(env))


@_probe("rv05-no-registry-no-check")
def _p_no_registry():
    if not _IMPORT_OK:
        _gap("rv05-no-registry-no-check", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    # Digest is revoked SOMEWHERE, but this verifier has no registry
    # attached: the check is skipped, not invented (documented).
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"])
    try:
        _verifier().verify_at_use(env)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        _break("rv05-no-registry-no-check",
               "unexpected refusal %r" % (_code_of(exc),))
    else:
        _held("rv05-no-registry-no-check", "no registry, no check")


@_probe("rv06-expired-parent")
def _p_expired():
    if not _IMPORT_OK:
        _gap("rv06-expired-parent", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"],
                    expires=_FIXED_NOW - 1)
    _expect_refusal("rv06-expired-parent", "reverify-stale",
                    lambda: _verifier().verify_at_use(env))


@_probe("rv07-stale-cached-verification")
def _p_stale_cache():
    if not _IMPORT_OK:
        _gap("rv07-stale-cached-verification", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    old = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"],
                    last_verified=_FIXED_NOW - 301)
    _expect_refusal("rv07-stale-cached-verification", "reverify-stale",
                    lambda: _verifier().verify_at_use(old))
    fresh = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"],
                      last_verified=_FIXED_NOW - 299)
    try:
        _verifier().verify_at_use(fresh)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        _break("rv07-stale-cached-verification",
               "fresh cache refused %r" % (_code_of(exc),))
    else:
        _held("rv07-stale-cached-verification",
              "stale refused, fresh accepted")


@_probe("rv08-unknown-parent-kind")
def _p_unknown_kind():
    if not _IMPORT_OK:
        _gap("rv08-unknown-parent-kind", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    env = _envelope(sig, "posture-signal-evil", {"iss-a": pub},
                    sig["jti"])
    _expect_refusal("rv08-unknown-parent-kind",
                    "reverify-unknown-parent-kind",
                    lambda: _verifier().verify_at_use(env))


@_probe("rv09-malformed-envelope")
def _p_malformed():
    if not _IMPORT_OK:
        _gap("rv09-malformed-envelope", _IMPORT_ERR)
        return
    _expect_refusal("rv09-malformed-envelope", "reverify-malformed",
                    lambda: _verifier().verify_at_use(
                        {"v": 1, "parent_kind": "posture-signal"}))


@_probe("rv10-receipt-not-authority")
def _p_not_authority():
    if not _IMPORT_OK:
        _gap("rv10-receipt-not-authority", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"])
    receipt = _verifier().verify_at_use(env)
    _expect_refusal(
        "rv10-receipt-not-authority", "reverify-not-authorization",
        lambda: rvf.reverify_receipt_carries_no_authority(receipt))


@_probe("rv11-absence-parent-kind")
def _p_absence_kind():
    if not _IMPORT_OK:
        _gap("rv11-absence-parent-kind", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    _issuer, neg = _mint_absence(seed)
    env = _envelope(neg, "absence-negative", {"iss-b": pub},
                    "deadbeef" * 8)
    try:
        _verifier().verify_at_use(env)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        _break("rv11-absence-parent-kind",
               "unexpected refusal %r" % (_code_of(exc),))
    else:
        _held("rv11-absence-parent-kind", "absence-negative verifies")


@_probe("rv12-revocation-entry-kind")
def _p_revocation_kind():
    if not _IMPORT_OK:
        _gap("rv12-revocation-entry-kind", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    rlist = rc.RevocationList()
    entry = rlist.revoke("c" * 64, issuer_id="rev-iss", seed=seed,
                         now=_FIXED_NOW)
    env = _envelope(entry, "revocation-entry", {"rev-iss": pub},
                    "c" * 64)
    try:
        _verifier().verify_at_use(env)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        _break("rv12-revocation-entry-kind",
               "unexpected refusal %r" % (_code_of(exc),))
    else:
        _held("rv12-revocation-entry-kind", "revocation-entry verifies")


@_probe("rv13-redeem-reverify-required")
def _p_redeem_required():
    if not _IMPORT_OK:
        _gap("rv13-redeem-reverify-required", _IMPORT_ERR)
        return
    reg, lease, digest, now_fn = _lease()
    # Missing verifier/record under the opt-in flag.
    _expect_refusal("rv13-redeem-reverify-required",
                    "reverify-required",
                    lambda: lease.redeem(digest, now=now_fn,
                                        reverify_at_use=True))
    # Stale record under the opt-in flag.
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    stale = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"],
                      expires=_FIXED_NOW - 1)
    _expect_refusal("rv13-redeem-reverify-required",
                    "reverify-required",
                    lambda: lease.redeem(
                        digest, now=now_fn, reverify_at_use=True,
                        use_verifier=_verifier(), use_record=stale))


@_probe("rv14-redeem-legacy-identical")
def _p_legacy():
    if not _CORE_OK:
        _gap("rv14-redeem-legacy-identical", "core import failed")
        return
    reg, lease, digest, now_fn = _lease()
    grant = lease.redeem(digest, now=now_fn)
    _reg2, lease2, _digest2, now_fn2 = _lease()
    try:
        grant2 = lease2.redeem(digest, now=now_fn2,
                               reverify_at_use=False)
    except TypeError:
        # Pristine: the opt-in wiring does not exist yet; the
        # control half still holds.
        _gap("rv14-redeem-legacy-identical",
             "reverify_at_use wiring absent on base")
        return
    # Legacy grant shape is untouched by the opt-in wiring.
    for g in (grant, grant2):
        if set(g) != {"permit_id", "parameter_digest", "granted_at"}:
            _break("rv14-redeem-legacy-identical",
                   "grant shape changed: %r" % (sorted(g),))
            return
    if grant["parameter_digest"] != grant2["parameter_digest"] \
            or grant["permit_id"] != grant2["permit_id"]:
        _break("rv14-redeem-legacy-identical", "grant contents diverged")
    else:
        _held("rv14-redeem-legacy-identical",
              "default-off path legacy-identical")


@_probe("rv15-alg-dispatch")
def _p_alg():
    if not _IMPORT_OK:
        _gap("rv15-alg-dispatch", _IMPORT_ERR)
        return
    key, _pub = _ALGS.keygen("hmac-sha256-mac")
    sig = po.emit_signal("revocation", "d" * 64, "scope:mac", key,
                         issuer_id="iss-m", now=_FIXED_NOW,
                         alg="hmac-sha256-mac")
    env = _envelope(sig, "posture-signal", {"iss-m": key}, sig["jti"])
    try:
        _verifier().verify_at_use(env)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        _break("rv15-alg-dispatch",
               "mac tier refused %r" % (_code_of(exc),))
        return
    _held("rv15-alg-dispatch", "mac tier dispatched")
    # Pinned expectation that differs must not silently degrade.
    _expect_refusal(
        "rv15-alg-dispatch", "reverify-parent-signature-invalid",
        lambda: _verifier().verify_at_use(
            env, expect_alg="ed25519-rfc8032"))


@_probe("rv16-determinism")
def _p_determinism():
    if not _IMPORT_OK:
        _gap("rv16-determinism", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"])
    r1 = _verifier().verify_at_use(dict(env))
    r2 = _verifier().verify_at_use(dict(env))
    if r1 != r2:
        _break("rv16-determinism", "receipts differ under fixed clock")
    else:
        _held("rv16-determinism", "receipts byte-identical")


@_probe("rv17-unknown-alg")
def _p_unknown_alg():
    if not _IMPORT_OK:
        _gap("rv17-unknown-alg", _IMPORT_ERR)
        return
    seed, pub = _mint_ed()
    sig = _mint_signal(seed)
    sig["alg"] = "pq-hybrid-magic"  # re-label: must fail closed
    env = _envelope(sig, "posture-signal", {"iss-a": pub}, sig["jti"])
    try:
        _verifier().verify_at_use(env)
    except Exception as exc:  # noqa: BLE001 - verdict logic
        if _code_of(exc) in ("reverify-parent-signature-invalid",
                             "reverify-malformed"):
            _held("rv17-unknown-alg",
                  "refused %r, never raw" % (_code_of(exc),))
        else:
            _break("rv17-unknown-alg",
                   "unexpected code %r" % (_code_of(exc),))
    else:
        _break("rv17-unknown-alg", "unknown alg accepted")


# ----------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN).
# ----------------------------------------------------------------------

def _green_checks():
    if GREEN_SKIP:
        _record("green", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    import subprocess  # noqa: E402
    suites = [
        ("adjacent-test_permit_leases",
         ["tests/test_permit_leases.py"]),
        ("adjacent-test_posture", ["tests/test_posture.py"]),
        ("adjacent-test_absence_revocation",
         ["tests/test_absence_revocation.py"]),
    ]
    for name, argv in suites:
        try:
            env = dict(os.environ)
            env["GOV_SKIP_GREEN"] = "1"
            env.setdefault("TMPDIR", "/var/tmp/g225r-green")
            os.makedirs(env["TMPDIR"], exist_ok=True)
            proc = subprocess.run(
                [sys.executable, "-m", "unittest"] + argv,
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=600)
            if proc.returncode == 0:
                _held(name, "green")
            else:
                tail = (proc.stderr or proc.stdout)[-500:]
                _record(name, "ERROR", "exit %d: %s"
                        % (proc.returncode, tail))
        except Exception as exc:  # noqa: BLE001 - verdict logic
            _record(name, "ERROR", "green check failed: %s" % exc)


def main():
    for name, fn in sorted(_PROBE_FNS.items()):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a probe must
            # never take the battery down
            _record(name, "ERROR", "probe crashed: %r" % (exc,))
    _green_checks()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    gap = sum(1 for _, v, _ in _RESULTS if v == "GAP")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("== w225 reverify probes ==")
    for name, verdict, detail in _RESULTS:
        print("%-34s %-6s %s" % (name, verdict, detail))
    print("HELD %d / GAP %d / BREAK %d / ERROR %d" % (held, gap, brk,
                                                      err))
    det = "PASS"
    if _IMPORT_OK:
        try:
            seed, pub = _mint_ed()
            sig = _mint_signal(seed)
            env = _envelope(sig, "posture-signal", {"iss-a": pub},
                            sig["jti"])
            a = _verifier().verify_at_use(dict(env))
            b = _verifier().verify_at_use(dict(env))
            det = "PASS" if a == b else "FAIL"
        except Exception:  # noqa: BLE001 - determinism verdict
            det = "FAIL"
    print("determinism %s" % det)
    sys.exit(1 if (brk or err) else 0)


if __name__ == "__main__":
    main()
