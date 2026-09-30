#!/usr/bin/env python3
"""Wave-227 lane A: registered-key resolution with hybrid mandate check.

ADAPT (re-derived prose; nothing copied) of two directions: a single
validated (key-type, digest-alg) registration unit so alg and key can
never be mismatched downstream, plus a hybrid-signature mandate check
where a declared hybrid key requires BOTH legs to verify — no single-leg
fallback, ever.

Seams under test:
* gov/key_identity.py — KeyRegistry.register(RegisteredKey): key_type
  and digest_alg must both be known schemes or the registration
  refuses ``key-identity-unregistered``; resolve(key_id) refuses
  ``key-identity-unknown`` for unknown ids and ``key-identity-revoked``
  for retired keys or keys whose pubkey_digest is revoked in an
  attached gov/revocation.py registry (nominal resolution without a
  registry); verify_hybrid(key_id, message, sig_a, sig_b, pubkey_a,
  pubkey_b) requires both legs — either bad signature refuses
  ``hybrid-leg-failed``; an unknown/revoked/retired/MAC-tier/nested-hybrid
  leg, or a caller-supplied leg key whose digest does not match the
  registered pubkey_digest, refuses ``hybrid-leg-invalid`` (checked
  BEFORE any signature verification, so a dead leg is never a
  signature oracle).

Attack shapes: smuggle a key record whose digest_alg is unknown;
confuse a MAC-tier key for a signature leg; present a valid signature
under a DIFFERENT key for a leg; verify a hybrid with only one good
leg; resolve a revoked key; resolve a retired key; resolve a key id
that was never registered; nest hybrids to launder a single leg.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-226 HEAD
e3cc497e9e39004d58baca20abcea5cc2d9b938f.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g227a
  TMPDIR=/var/tmp/g227a ~/workspace/.gov-venv/bin/python evals/w227_keys_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g227a-u \\
      ~/workspace/.gov-venv/bin/python evals/w227_keys_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import subprocess
import sys
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import key_identity as _ki
    from gov import alg_registry as _alg
    from gov import revocation as _rev
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

ED = "ed25519-rfc8032"
HMAC = "hmac-sha256-mac"

PROBE_NAMES = [
    "ki-01-valid-unit-resolves",
    "ki-02-mismatched-digest-alg-refused",
    "ki-03-unknown-key-refused",
    "ki-04-unregistered-key-type-refused",
    "ki-05-hybrid-both-legs-verifies",
    "ki-06-hybrid-bad-leg-a-failed",
    "ki-07-hybrid-bad-leg-b-failed",
    "ki-08-hybrid-unknown-leg-invalid",
    "ki-09-hybrid-revoked-leg-invalid",
    "ki-10-revoked-key-refused",
    "ki-11-retired-key-refused",
    "ki-12-no-registry-nominal",
    "ki-13-hybrid-mac-leg-invalid",
    "ki-14-hybrid-wrong-leg-key-invalid",
    "ki-15-hybrid-nested-leg-invalid",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _ed_keypair():
    reg = _alg.default_registry()
    seed, pub = reg.keygen(ED)
    return reg, seed, pub


def _hybrid_setup():
    """Two registered Ed25519 legs + a hybrid key over them. Returns
    (key_registry, alg_registry, seed_a, pub_a, seed_b, pub_b, msg)."""
    areg, seed_a, pub_a = _ed_keypair()
    seed_b, pub_b = areg.keygen(ED)
    kreg = _ki.KeyRegistry()
    kreg.register(_ki.RegisteredKey.build("leg-a", ED, "sha256", pub_a))
    kreg.register(_ki.RegisteredKey.build("leg-b", ED, "sha256", pub_b))
    kreg.register(_ki.RegisteredKey.build(
        "hybrid-1", ED, "sha256", pub_a, hybrid_of=("leg-a", "leg-b")))
    return kreg, areg, seed_a, pub_a, seed_b, pub_b, b"hybrid test message"


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.key_identity absent on this tree")
        return results

    # ki-01: a valid single (key-type, digest-alg) unit resolves, and the
    # registered pubkey_digest recomputes from the presented pubkey.
    try:
        areg, seed, pub = _ed_keypair()
        kreg = _ki.KeyRegistry()
        kreg.register(_ki.RegisteredKey.build("k1", ED, "sha256", pub))
        got = kreg.resolve("k1")
        ok = (got["key_id"] == "k1" and got["key_type"] == ED
              and got["digest_alg"] == "sha256"
              and got["pubkey_digest"] == hashlib.sha256(pub).hexdigest())
        rec("ki-01-valid-unit-resolves", "HELD" if ok else "BREAK",
            "digest recomputed=%r" % (ok,))
    except Exception as exc:  # noqa: BLE001
        rec("ki-01-valid-unit-resolves", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-02: mismatched digest_alg (unknown scheme) refuses
    # key-identity-unregistered at registration.
    try:
        _areg, _seed, pub = _ed_keypair()
        held = _refuses(
            lambda: _ki.RegisteredKey.build("k2", ED, "sha999-nope", pub),
            "key-identity-unregistered")
        rec("ki-02-mismatched-digest-alg-refused", "HELD" if held else "BREAK",
            "unregistered digest_alg refused" if held
            else "mismatched digest_alg did not refuse")
    except Exception as exc:  # noqa: BLE001
        rec("ki-02-mismatched-digest-alg-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-03: resolving a never-registered key_id refuses
    # key-identity-unknown.
    try:
        kreg = _ki.KeyRegistry()
        held = _refuses(lambda: kreg.resolve("ghost-key"),
                        "key-identity-unknown")
        rec("ki-03-unknown-key-refused", "HELD" if held else "BREAK",
            "unknown key_id refused" if held
            else "unknown key_id did not refuse key-identity-unknown")
    except Exception as exc:  # noqa: BLE001
        rec("ki-03-unknown-key-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-04: key_type not in gov/alg_registry.py refuses
    # key-identity-unregistered.
    try:
        _areg, _seed, pub = _ed_keypair()
        held = _refuses(
            lambda: _ki.RegisteredKey.build("k4", "rsa-4096", "sha256", pub),
            "key-identity-unregistered")
        rec("ki-04-unregistered-key-type-refused", "HELD" if held else "BREAK",
            "unregistered key_type refused" if held
            else "unregistered key_type did not refuse")
    except Exception as exc:  # noqa: BLE001
        rec("ki-04-unregistered-key-type-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-05: hybrid with both legs honestly signed verifies.
    try:
        kreg, areg, seed_a, pub_a, seed_b, pub_b, msg = _hybrid_setup()
        sig_a = areg.sign(ED, msg, seed_a)
        sig_b = areg.sign(ED, msg, seed_b)
        ok = kreg.verify_hybrid("hybrid-1", msg, sig_a, sig_b, pub_a, pub_b)
        rec("ki-05-hybrid-both-legs-verifies", "HELD" if ok is True else "BREAK",
            "verify_hybrid returned %r" % (ok,))
    except Exception as exc:  # noqa: BLE001
        rec("ki-05-hybrid-both-legs-verifies", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-06: bad leg-A signature refuses hybrid-leg-failed (never falls
    # back to leg B alone).
    try:
        kreg, areg, seed_a, pub_a, seed_b, pub_b, msg = _hybrid_setup()
        sig_b = areg.sign(ED, msg, seed_b)
        held = _refuses(
            lambda: kreg.verify_hybrid("hybrid-1", msg, b"\x00" * 64,
                                       sig_b, pub_a, pub_b),
            "hybrid-leg-failed")
        rec("ki-06-hybrid-bad-leg-a-failed", "HELD" if held else "BREAK",
            "bad leg A refused hybrid-leg-failed" if held
            else "bad leg A did not refuse hybrid-leg-failed")
    except Exception as exc:  # noqa: BLE001
        rec("ki-06-hybrid-bad-leg-a-failed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-07: bad leg-B signature refuses hybrid-leg-failed.
    try:
        kreg, areg, seed_a, pub_a, seed_b, pub_b, msg = _hybrid_setup()
        sig_a = areg.sign(ED, msg, seed_a)
        held = _refuses(
            lambda: kreg.verify_hybrid("hybrid-1", msg, sig_a,
                                       b"\x00" * 64, pub_a, pub_b),
            "hybrid-leg-failed")
        rec("ki-07-hybrid-bad-leg-b-failed", "HELD" if held else "BREAK",
            "bad leg B refused hybrid-leg-failed" if held
            else "bad leg B did not refuse hybrid-leg-failed")
    except Exception as exc:  # noqa: BLE001
        rec("ki-07-hybrid-bad-leg-b-failed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-08: a hybrid leg that resolves to nothing refuses
    # hybrid-leg-invalid (before any signature is touched).
    try:
        areg, seed, pub = _ed_keypair()
        kreg = _ki.KeyRegistry()
        kreg.register(_ki.RegisteredKey.build("leg-a", ED, "sha256", pub))
        kreg.register(_ki.RegisteredKey.build(
            "hybrid-dead", ED, "sha256", pub,
            hybrid_of=("leg-a", "leg-ghost")))
        held = _refuses(
            lambda: kreg.verify_hybrid("hybrid-dead", b"m", b"s1", b"s2",
                                       pub, pub),
            "hybrid-leg-invalid")
        rec("ki-08-hybrid-unknown-leg-invalid", "HELD" if held else "BREAK",
            "unknown leg refused hybrid-leg-invalid" if held
            else "unknown leg did not refuse hybrid-leg-invalid")
    except Exception as exc:  # noqa: BLE001
        rec("ki-08-hybrid-unknown-leg-invalid", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-09: a hybrid leg revoked in the attached revocation registry
    # refuses hybrid-leg-invalid — the dead leg is checked BEFORE any
    # signature verification (no oracle for forgeries).
    try:
        areg, seed_a, pub_a = _ed_keypair()
        seed_b, pub_b = areg.keygen(ED)
        rev = _rev.RevocationList()
        rev.revoke(hashlib.sha256(pub_b).hexdigest(), issuer_id="ca",
                   seed=os.urandom(32))
        kreg = _ki.KeyRegistry(revocation_registry=rev)
        kreg.register(_ki.RegisteredKey.build("leg-a", ED, "sha256", pub_a))
        kreg.register(_ki.RegisteredKey.build("leg-b", ED, "sha256", pub_b))
        kreg.register(_ki.RegisteredKey.build(
            "hybrid-rev", ED, "sha256", pub_a,
            hybrid_of=("leg-a", "leg-b")))
        msg = b"hybrid revoked leg"
        sig_a = areg.sign(ED, msg, seed_a)
        sig_b = areg.sign(ED, msg, seed_b)
        held = _refuses(
            lambda: kreg.verify_hybrid("hybrid-rev", msg, sig_a, sig_b,
                                       pub_a, pub_b),
            "hybrid-leg-invalid")
        rec("ki-09-hybrid-revoked-leg-invalid", "HELD" if held else "BREAK",
            "revoked leg refused hybrid-leg-invalid" if held
            else "revoked leg did not refuse hybrid-leg-invalid")
    except Exception as exc:  # noqa: BLE001
        rec("ki-09-hybrid-revoked-leg-invalid", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-10: resolving a key whose pubkey_digest is revoked in the
    # attached revocation registry refuses key-identity-revoked.
    try:
        areg, seed, pub = _ed_keypair()
        rev = _rev.RevocationList()
        rev.revoke(hashlib.sha256(pub).hexdigest(), issuer_id="ca",
                   seed=os.urandom(32))
        kreg = _ki.KeyRegistry(revocation_registry=rev)
        kreg.register(_ki.RegisteredKey.build("k10", ED, "sha256", pub))
        held = _refuses(lambda: kreg.resolve("k10"), "key-identity-revoked")
        rec("ki-10-revoked-key-refused", "HELD" if held else "BREAK",
            "revoked key refused key-identity-revoked" if held
            else "revoked key did not refuse key-identity-revoked")
    except Exception as exc:  # noqa: BLE001
        rec("ki-10-revoked-key-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-11: a retired-status key refuses key-identity-revoked even with
    # no registry attached.
    try:
        areg, seed, pub = _ed_keypair()
        kreg = _ki.KeyRegistry()
        kreg.register(_ki.RegisteredKey.build("k11", ED, "sha256", pub,
                                              status="retired"))
        held = _refuses(lambda: kreg.resolve("k11"), "key-identity-revoked")
        rec("ki-11-retired-key-refused", "HELD" if held else "BREAK",
            "retired key refused key-identity-revoked" if held
            else "retired key did not refuse key-identity-revoked")
    except Exception as exc:  # noqa: BLE001
        rec("ki-11-retired-key-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-12: resolution without an attached registry is nominal — a key
    # that WOULD be revoked in a registry still resolves (documented).
    try:
        areg, seed, pub = _ed_keypair()
        kreg = _ki.KeyRegistry()  # no registry attached
        kreg.register(_ki.RegisteredKey.build("k12", ED, "sha256", pub))
        got = kreg.resolve("k12")
        ok = got["key_id"] == "k12"
        rec("ki-12-no-registry-nominal", "HELD" if ok else "BREAK",
            "nominal resolution without registry=%r" % (ok,))
    except Exception as exc:  # noqa: BLE001
        rec("ki-12-no-registry-nominal", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-13: a MAC-tier key cannot be a hybrid leg — a MAC is not a
    # signature; hybrid-leg-invalid (honest tier labeling, per the
    # alg_registry MAC-tier discipline).
    try:
        areg, seed, pub = _ed_keypair()
        mac_key, _ = areg.keygen(HMAC)
        kreg = _ki.KeyRegistry()
        kreg.register(_ki.RegisteredKey.build("leg-a", ED, "sha256", pub))
        kreg.register(_ki.RegisteredKey.build("leg-mac", HMAC, "sha256",
                                              mac_key))
        kreg.register(_ki.RegisteredKey.build(
            "hybrid-mac", ED, "sha256", pub,
            hybrid_of=("leg-a", "leg-mac")))
        held = _refuses(
            lambda: kreg.verify_hybrid("hybrid-mac", b"m", b"s1", b"s2",
                                       pub, mac_key),
            "hybrid-leg-invalid")
        rec("ki-13-hybrid-mac-leg-invalid", "HELD" if held else "BREAK",
            "MAC-tier leg refused hybrid-leg-invalid" if held
            else "MAC-tier leg did not refuse hybrid-leg-invalid")
    except Exception as exc:  # noqa: BLE001
        rec("ki-13-hybrid-mac-leg-invalid", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-14: presenting a valid signature under a DIFFERENT key for a
    # leg refuses hybrid-leg-invalid — the registered pubkey_digest
    # pins which key each leg verifies under.
    try:
        kreg, areg, seed_a, pub_a, seed_b, pub_b, msg = _hybrid_setup()
        _, impostor_pub = areg.keygen(ED)
        sig_a = areg.sign(ED, msg, seed_a)
        sig_b = areg.sign(ED, msg, seed_b)
        held = _refuses(
            lambda: kreg.verify_hybrid("hybrid-1", msg, sig_a, sig_b,
                                       impostor_pub, pub_b),
            "hybrid-leg-invalid")
        rec("ki-14-hybrid-wrong-leg-key-invalid",
            "HELD" if held else "BREAK",
            "impostor leg key refused hybrid-leg-invalid" if held
            else "impostor leg key did not refuse hybrid-leg-invalid")
    except Exception as exc:  # noqa: BLE001
        rec("ki-14-hybrid-wrong-leg-key-invalid", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # ki-15: a hybrid leg that is itself a hybrid refuses
    # hybrid-leg-invalid — legs are leaf keys, so nesting cannot
    # launder a single leg.
    try:
        areg, seed_a, pub_a = _ed_keypair()
        seed_b, pub_b = areg.keygen(ED)
        seed_c, pub_c = areg.keygen(ED)
        kreg = _ki.KeyRegistry()
        for kid, pub in (("a", pub_a), ("b", pub_b), ("c", pub_c)):
            kreg.register(_ki.RegisteredKey.build(kid, ED, "sha256", pub))
        kreg.register(_ki.RegisteredKey.build(
            "inner", ED, "sha256", pub_a, hybrid_of=("a", "b")))
        kreg.register(_ki.RegisteredKey.build(
            "outer", ED, "sha256", pub_a, hybrid_of=("inner", "c")))
        held = _refuses(
            lambda: kreg.verify_hybrid("outer", b"m", b"s1", b"s2",
                                       pub_a, pub_c),
            "hybrid-leg-invalid")
        rec("ki-15-hybrid-nested-leg-invalid", "HELD" if held else "BREAK",
            "nested hybrid leg refused hybrid-leg-invalid" if held
            else "nested hybrid leg did not refuse hybrid-leg-invalid")
    except Exception as exc:  # noqa: BLE001
        rec("ki-15-hybrid-nested-leg-invalid", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_alg_registry.py",
                 "tests/test_kms_signer.py",
                 "tests/test_single_use.py"):
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
    print("w227 key-identity probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
