#!/usr/bin/env python3
"""Wave-183 red-team probes: versioned signing keysets for the audit/evidence
signing path.

Break-first battery per the diagnosing-bugs skill. Threat model: the
audit-entry signing key is a long-lived secret; today's tree has NO
keyset/rotation discipline (one seed -> one key_id via
``gov.log.resolve_audit_signer``; rotating means changing the env var and
hand-managing the verifier's trusted set). Each probe attacks that gap:

  K1 ROTATION      rotate the signing key without invalidating old signatures
  K2 VERSION BIND  the signature binds the key version (tamper/strip -> fail)
  K3 REVOCATION    a compromised key version can be revoked (its sigs fail)
  K4 LINEAGE       every rotation is authorized by the previous primary
  K5 LEGACY        v1 (unversioned) entries keep verifying; HMAC chain and
                   Merkle roots are byte-identical with/without versions
  K6 FAIL-CLOSED   misconfigured keysets refuse loudly, never silently downgrade
  K7 CONFUSION     version/key_id mismatch in the envelope fails closed

On the pristine tree ``gov.keyset`` does not exist: K1-K4/K6-K7 report
BREAK ("capability absent" -- the gap is real and demonstrated), K5
reports HELD (the baseline invariants hold today and must keep holding).

After the fix: K1-K4/K6-K7 must flip to HELD; K5 must stay HELD.

Verdicts: BREAK (gap demonstrated), HELD (defense held), HELD* (held with
a documented residual). ERROR only on harness failure (a verdict changing
between the two deterministic runs, an unexpected exception).

Pattern lineage: tink-crypto/tink-py KeysetHandle (Apache-2.0,
pattern-only -- no Tink code vendored; stdlib only, $0 spend).

Deterministic: all key material derives from SHA256(probe tags); every
probe runs twice and a verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead of
spawning sub-batteries).
"""

import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import keyset as _ks
    HAVE_KEYSET = True
except ImportError:
    HAVE_KEYSET = False
    _ks = None

from gov import log as _log
from gov import ed25519 as _ed
from gov.signing import Ed25519Signer, ed25519_key_id
from keyfixture import provision_test_key

_AUDIT_VARS = ("GOV_AUDIT_SIGNING_KEY", "GOV_AUDIT_SIGNING_KEY_FILE",
               "GOV_AUDIT_KEYSET_FILE")


def _seed(tag):
    """Deterministic 32-byte seed per probe tag."""
    return hashlib.sha256(("wave183-keyset-probe:" + tag).encode()).digest()


def _scrub_audit_env():
    saved = {n: os.environ.get(n) for n in _AUDIT_VARS}
    for n in _AUDIT_VARS:
        os.environ.pop(n, None)

    def restore():
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    return restore


def _capability_absent(name):
    return ("BREAK", "%s: capability absent -- gov.keyset does not exist; "
            "the audit-entry signing path has no versioned-keyset, "
            "rotation, or revocation discipline" % name)


# ---------------------------------------------------------------------------
# K1: rotation without invalidating old signatures
# ---------------------------------------------------------------------------

def k1_rotation():
    """Rotate the entry-signing key: new signatures use v2, v1 signatures
    (now verify-only) still verify."""
    if not HAVE_KEYSET:
        return _capability_absent("K1")
    restore = _scrub_audit_env()
    provision_test_key()
    try:
        with tempfile.TemporaryDirectory() as td:
            ks1, signer1 = _ks.new_keyset(_seed("k1-v1"))
            alog = _log.ActionLog(os.path.join(td, "a.jsonl"),
                                  signer=signer1)
            e1 = alog.append({"event": "before-rotation"})
            assert e1.get("sig_key_version") == 1, \
                "v1 entry must carry sig_key_version=1, got %r" % (
                    e1.get("sig_key_version"),)
            ks2, signer2 = _ks.rotate_keyset(ks1, _seed("k1-v2"),
                                             _seed("k1-v1"))
            assert signer2.key_version == 2
            assert ks2.primary_version == 2
            # Emulate the rotated logger: a fresh log with the v2 signer.
            alog2 = _log.ActionLog(os.path.join(td, "b.jsonl"),
                                   signer=signer2)
            e2 = alog2.append({"event": "after-rotation"})
            assert e2.get("sig_key_version") == 2
            ok_old, r_old = _log.verify_entry_against_keyset(e1, ks2)
            ok_new, r_new = _log.verify_entry_against_keyset(e2, ks2)
            if not ok_old:
                return ("BREAK", "K1: pre-rotation v1 signature rejected "
                        "after rotation: %s" % r_old)
            if not ok_new:
                return ("BREAK", "K1: post-rotation v2 signature rejected: "
                        "%s" % r_new)
            # The old primary must no longer be usable for NEW signatures:
            # a KeysetSigner for a verify-only version must refuse to be
            # minted from the keyset's public directory.
            try:
                _ks.keyset_signer_for_version(ks2, 1, _seed("k1-v1"))
                return ("BREAK", "K1: minted a signing handle for "
                        "verify-only v1 -- rotated-out keys must not sign")
            except _ks.KeysetError:
                pass
            return ("HELD", "K1: rotation clean -- v1 verify-only (old "
                    "sigs verify), v2 primary (new sigs verify), no "
                    "signing handle for verify-only versions")
    finally:
        restore()


# ---------------------------------------------------------------------------
# K2: version binding (tamper/strip -> fail, never silent downgrade)
# ---------------------------------------------------------------------------

def k2_version_binding():
    """The key version is bound into the signed envelope: tampering with
    sig_key_version (or stripping it) must break verification, never
    silently downgrade to the legacy path."""
    if not HAVE_KEYSET:
        return _capability_absent("K2")
    restore = _scrub_audit_env()
    provision_test_key()
    try:
        with tempfile.TemporaryDirectory() as td:
            ks1, signer1 = _ks.new_keyset(_seed("k2-v1"))
            ks2, _s2 = _ks.rotate_keyset(ks1, _seed("k2-v2"),
                                         _seed("k2-v1"))
            alog = _log.ActionLog(os.path.join(td, "a.jsonl"),
                                  signer=_s2)
            e = alog.append({"event": "versioned"})
            ok, _ = _log.verify_entry_against_keyset(e, ks2)
            if not ok:
                return ("BREAK", "K2: honest versioned entry rejected")
            # Tamper: rewrite the version 2 -> 1.
            tampered = dict(e)
            tampered["sig_key_version"] = 1
            ok, reason = _log.verify_entry_against_keyset(tampered, ks2)
            if ok:
                return ("BREAK", "K2: version tampered 2->1 still "
                        "verifies -- version is not cryptographically "
                        "bound")
            # Strip: remove the version entirely (downgrade attempt).
            stripped = dict(e)
            del stripped["sig_key_version"]
            ok, reason = _log.verify_entry_against_keyset(stripped, ks2)
            if ok:
                return ("BREAK", "K2: stripped sig_key_version still "
                        "verifies -- silent downgrade to legacy path")
            return ("HELD", "K2: version tamper (%s) and version strip "
                    "(%s) both fail closed" % (reason, reason))
    finally:
        restore()


# ---------------------------------------------------------------------------
# K3: revocation (compromise story)
# ---------------------------------------------------------------------------

def k3_revocation():
    """A compromised key version can be revoked: its signatures fail,
    other versions keep verifying, and the primary cannot be revoked
    directly (rotate first, then revoke)."""
    if not HAVE_KEYSET:
        return _capability_absent("K3")
    restore = _scrub_audit_env()
    provision_test_key()
    try:
        with tempfile.TemporaryDirectory() as td:
            ks1, s1 = _ks.new_keyset(_seed("k3-v1"))
            ks2, s2 = _ks.rotate_keyset(ks1, _seed("k3-v2"),
                                        _seed("k3-v1"))
            ks3, s3 = _ks.rotate_keyset(ks2, _seed("k3-v3"),
                                        _seed("k3-v2"))
            alog = _log.ActionLog(os.path.join(td, "a.jsonl"), signer=s2)
            e_v2 = alog.append({"event": "signed-by-v2"})
            # Compromise v2: rotate-first ritual, then revoke.
            ks4 = _ks.revoke_version(ks3, 2, "suspected compromise",
                                     _seed("k3-v3"))
            ok, reason = _log.verify_entry_against_keyset(e_v2, ks4)
            if ok:
                return ("BREAK", "K3: signature from revoked v2 still "
                        "verifies -- revocation is not enforced")
            # v1 (verify-only, never compromised) still verifies.
            alog1 = _log.ActionLog(os.path.join(td, "b.jsonl"), signer=s1)
            e_v1 = alog1.append({"event": "signed-by-v1"})
            ok1, r1 = _log.verify_entry_against_keyset(e_v1, ks4)
            # v3 (primary) still verifies.
            alog3 = _log.ActionLog(os.path.join(td, "c.jsonl"), signer=s3)
            e_v3 = alog3.append({"event": "signed-by-v3"})
            ok3, r3 = _log.verify_entry_against_keyset(e_v3, ks4)
            if not (ok1 and ok3):
                return ("BREAK", "K3: revocation broke innocent versions "
                        "(v1: %s; v3: %s)" % (r1, r3))
            # Revoking the primary directly must be refused.
            try:
                _ks.revoke_version(ks4, 3, "oops", _seed("k3-v3"))
                return ("BREAK", "K3: revoking the primary was allowed -- "
                        "would leave no signing key")
            except _ks.KeysetError:
                pass
            return ("HELD", "K3: revoked v2 refused (%s); v1/v3 verify; "
                    "primary revocation refused" % reason)
    finally:
        restore()


# ---------------------------------------------------------------------------
# K4: rotation lineage (authorized by the previous primary)
# ---------------------------------------------------------------------------

def k4_lineage():
    """Every rotation carries a lineage record signed by the previous
    primary; a forged lineage record makes the keyset fail verification."""
    if not HAVE_KEYSET:
        return _capability_absent("K4")
    ks1, _s1 = _ks.new_keyset(_seed("k4-v1"))
    ks2, _s2 = _ks.rotate_keyset(ks1, _seed("k4-v2"), _seed("k4-v1"))
    ok, err = ks2.verify()
    if not ok:
        return ("BREAK", "K4: honest rotated keyset rejected: %s" % err)
    # Forge: swap the lineage record for one signed by the ATTACKER's key.
    evil = _ed.publickey(_seed("k4-evil"))
    doc = ks2.to_dict()
    forged = dict(doc["rotation_lineage"][0])
    forged["to_public_key_hex"] = evil.hex()
    forged["to_key_id"] = ed25519_key_id(evil)
    # Re-sign with the attacker's seed (they cannot forge v1's signature,
    # so this record is self-evidently not v1-authorized).
    stmt = _ks.rotation_statement(1, 2, ks1.version(1).key_id,
                                  forged["to_key_id"],
                                  forged["to_public_key_hex"],
                                  ks1.keyset_hash())
    forged["sig"] = _ed.sign(_seed("k4-evil"),
                             _ks.ROTATION_DOMAIN + stmt).hex()
    doc["rotation_lineage"] = [forged]
    # Also swap the version's pubkey to match the forged record.
    doc["versions"][1]["public_key_hex"] = evil.hex()
    doc["versions"][1]["key_id"] = forged["to_key_id"]
    try:
        evil_ks = _ks.Keyset.from_dict(doc)
    except _ks.KeysetError as e:
        return ("HELD", "K4: forged lineage rejected at parse: %s" % e)
    ok, err = evil_ks.verify()
    if ok:
        return ("BREAK", "K4: keyset with attacker-signed lineage "
                "verified -- rotation authorization is not enforced")
    return ("HELD", "K4: forged lineage rejected (%s); honest lineage "
            "verifies" % err)


# ---------------------------------------------------------------------------
# K5: legacy compatibility (baseline invariant -- HELD before and after)
# ---------------------------------------------------------------------------

def k5_legacy():
    """Unversioned (v1-body) entries keep verifying; adding the version
    envelope must not change HMAC chains or Merkle roots (the leaf
    deliberately excludes the sig envelope so re-signing never changes
    tree roots)."""
    restore = _scrub_audit_env()
    provision_test_key()
    try:
        with tempfile.TemporaryDirectory() as td:
            seed = _seed("k5-same")
            events = [{"event": "e%d" % i, "n": i} for i in range(5)]
            legacy = _log.ActionLog(os.path.join(td, "legacy.jsonl"),
                                    signer=Ed25519Signer(seed))
            le = [legacy.append(dict(ev)) for ev in events]
            assert all("sig_key_version" not in e for e in le)
            # HMAC chain intact on the pristine path.
            for e in le:
                if not isinstance(e.get("ed_sig"), str):
                    return ("BREAK", "K5: legacy entry lost its signature")
            if not HAVE_KEYSET:
                return ("HELD", "K5: baseline -- legacy v1 entries sign "
                        "and carry no version (keyset layer absent)")
            # Versioned log over IDENTICAL events and the SAME seed.
            _, vsigner = _ks.new_keyset(seed)
            assert vsigner.key_version == 1
            versioned = _log.ActionLog(os.path.join(td, "ver.jsonl"),
                                       signer=vsigner)
            ve = [versioned.append(dict(ev)) for ev in events]
            # The version envelope must not change the HMAC chain or the
            # Merkle leaf: for the SAME entry, the canonical forms are
            # identical with the envelope present or stripped. (Compared
            # on one entry, not across two live logs: entries carry
            # wall-clock timestamps, so a live A/B would flake on a
            # second boundary.)
            for e in ve:
                assert "sig_key_version" in e
                stripped = {k: v for k, v in e.items()
                            if k not in ("ed_sig", "sig_key_id",
                                         "sig_key_version")}
                if _log._canonical(e) != _log._canonical(stripped):
                    return ("BREAK", "K5: HMAC canonical changed when the "
                            "version envelope was added")
                if _log._leaf_input(e) != _log._leaf_input(stripped):
                    return ("BREAK", "K5: Merkle leaf changed when the "
                            "version envelope was added")
            # Legacy entries verify against the keyset (legacy path).
            ks, _ = _ks.new_keyset(seed)
            for e in le:
                ok, reason = _log.verify_entry_against_keyset(e, ks)
                if not ok:
                    return ("BREAK", "K5: legacy entry rejected by "
                            "keyset verifier: %s" % reason)
            return ("HELD", "K5: sig envelope (incl. version) excluded from "
                    "HMAC/Merkle canonical forms; legacy entries verify "
                    "against the keyset")
    finally:
        restore()


# ---------------------------------------------------------------------------
# K6: fail-closed configuration
# ---------------------------------------------------------------------------

def k6_fail_closed_config():
    """Keyset misconfiguration refuses loudly: a seed that does not
    match the keyset's primary, revoking the primary, and rotating from
    a revoked version are all loud errors -- never silent downgrades."""
    if not HAVE_KEYSET:
        return _capability_absent("K6")
    restore = _scrub_audit_env()
    provision_test_key()
    try:
        with tempfile.TemporaryDirectory() as td:
            ks1, _s1 = _ks.new_keyset(_seed("k6-v1"))
            ks2, _s2 = _ks.rotate_keyset(ks1, _seed("k6-v2"),
                                         _seed("k6-v1"))
            kspath = os.path.join(td, "keyset.json")
            with open(kspath, "w", encoding="utf-8") as f:
                json.dump(ks2.to_dict(), f)
            # Wrong seed for the primary: must be LOUD.
            os.environ["GOV_AUDIT_KEYSET_FILE"] = kspath
            os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("k6-wrong").hex()
            try:
                _log.open_audit_log(os.path.join(td, "x.jsonl"))
                return ("BREAK", "K6: keyset/seed mismatch opened a log "
                        "without complaint -- silent key confusion")
            except _ks.KeysetError:
                pass  # the only acceptable outcome: a loud refusal
            # Right seed: opens fine and signs with v2.
            os.environ["GOV_AUDIT_SIGNING_KEY"] = _seed("k6-v2").hex()
            alog = _log.open_audit_log(os.path.join(td, "y.jsonl"))
            e = alog.append({"event": "ok"})
            if e.get("sig_key_version") != 2:
                return ("BREAK", "K6: keyset-resolved signer did not sign "
                        "as v2")
            # Rotating FROM a revoked version must be refused.
            ks3 = _ks.revoke_version(ks2, 1, "compromised",
                                     _seed("k6-v2"))
            try:
                _ks.rotate_keyset(ks3, _seed("k6-v3"), _seed("k6-v1"))
                return ("BREAK", "K6: rotation authorized by a revoked "
                        "key was allowed")
            except _ks.KeysetError:
                pass
            return ("HELD", "K6: seed/primary mismatch loud; rotation "
                    "from revoked refused")
    finally:
        restore()


# ---------------------------------------------------------------------------
# K7: version/key_id confusion
# ---------------------------------------------------------------------------

def k7_confusion():
    """An envelope whose version and key_id disagree (version=2 naming
    v1's key_id, or an unknown version) fails closed."""
    if not HAVE_KEYSET:
        return _capability_absent("K7")
    restore = _scrub_audit_env()
    provision_test_key()
    try:
        with tempfile.TemporaryDirectory() as td:
            ks1, s1 = _ks.new_keyset(_seed("k7-v1"))
            ks2, s2 = _ks.rotate_keyset(ks1, _seed("k7-v2"),
                                        _seed("k7-v1"))
            alog = _log.ActionLog(os.path.join(td, "a.jsonl"), signer=s2)
            e = alog.append({"event": "x"})
            # version=2 but v1's key_id.
            confused = dict(e)
            confused["sig_key_id"] = ks1.version(1).key_id
            ok, _ = _log.verify_entry_against_keyset(confused, ks2)
            if ok:
                return ("BREAK", "K7: version/key_id mismatch verified")
            # Unknown version.
            unknown = dict(e)
            unknown["sig_key_version"] = 99
            ok, _ = _log.verify_entry_against_keyset(unknown, ks2)
            if ok:
                return ("BREAK", "K7: unknown version 99 verified")
            # Non-integer version.
            weird = dict(e)
            weird["sig_key_version"] = "2"
            ok, _ = _log.verify_entry_against_keyset(weird, ks2)
            if ok:
                return ("BREAK", "K7: non-integer version verified")
            return ("HELD", "K7: version/key_id mismatch, unknown "
                    "version, and non-integer version all fail closed")
    finally:
        restore()


_PROBES = [
    ("K1", k1_rotation),
    ("K2", k2_version_binding),
    ("K3", k3_revocation),
    ("K4", k4_lineage),
    ("K5", k5_legacy),
    ("K6", k6_fail_closed_config),
    ("K7", k7_confusion),
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
    """Depth-1 green check: adjacent unit suites only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip."""
    import subprocess
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for suite in ("tests.test_keyset", "tests.test_audit_entry_signing"):
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite, "-v"],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
        tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
        print("GREEN CHECK %s: rc=%d %s" % (suite, r.returncode,
                                            " | ".join(tail)))
        if r.returncode != 0:
            return False
    return True


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
