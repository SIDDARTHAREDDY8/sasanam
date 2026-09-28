"""Break-first battery: ThresholdSigner x keyset composition + checkpoint
STH key-version binding (wave-186).

Red-first probes for the two composition residuals left by the wave-183
keyset lane:

  1. ThresholdSigner x keyset: threshold checkpoint signatures must
     carry key-version bindings (``ThresholdSigner.sign_all``) and
     ``verify_threshold`` must cross-check them against each member
     key's keyset -- revoked versions contribute nothing, confusion
     fails closed, verify-only keeps counting.
  2. Checkpoint STH signatures bind key versions: ``write_checkpoint``
     (single-key shape) binds the signer's keyset version into the STH
     body alongside ``ts``; a checkpoint signed under a revoked version
     fails verification when the verifier holds the keyset.

Probe verdicts: BREAK = the attack/property-gap succeeds on the tree
under test; HELD = the tree refuses it. Run on the pristine tree first
(expect BREAKs), then on the fixed tree (expect HELDs).

$0 spend, stdlib only, deterministic (fixed seeds, no wall-clock
dependence beyond checkpoint ``ts``, which is never asserted on).
"""

import copy
import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import signing as _signing
from gov import keyset as _keyset
from gov import log as _logmod

# Wave-81: no dev-key fallback -- provision an explicit test HMAC key
# through the production env path so ActionLog can append.
from tests.keyfixture import provision_test_key  # noqa: E402
provision_test_key(epoch="dev")


def _seed(tag):
    return hashlib.sha256(("wave186|" + tag).encode("utf-8")).digest()


def _mk_keysets(n):
    """n independent (keyset, v1_seed) pairs."""
    out = []
    for i in range(n):
        s1 = _seed("ks%d|v1" % i)
        ks, signer = _keyset.new_keyset(s1)
        out.append([ks, s1, signer])
    return out


def _rotate(ks_entry, i):
    """Rotate keyset i to v2; returns (new_entry, v2_signer)."""
    ks, s1, _s = ks_entry
    s2 = _seed("ks%d|v2" % i)
    ks2, signer2 = _keyset.rotate_keyset(ks, s2, s1)
    return [ks2, s2, signer2]


def _revoke(ks, v2_seed):
    return _keyset.revoke_version(ks, 1, "key compromise", v2_seed)


def _threshold_parts(keysets_entries, k, root_tag="root"):
    """(tsigner, roster, root_pub) from keyset entries' v1 signers."""
    signers = [e[2] for e in keysets_entries]
    root = _signing.Ed25519Signer(_seed(root_tag))
    roster = _signing.make_roster(signers, k, root)
    ts = _signing.ThresholdSigner(signers, k)
    return ts, roster, root.public_key


def _tmpdir():
    return tempfile.mkdtemp(prefix="w186probe_")


# --------------------------------------------------------------------------
# Probes. Each returns (verdict, detail); verdict in {"BREAK", "HELD"}.
# --------------------------------------------------------------------------

def probe_t1_threshold_revoked_refused():
    """2-of-3 threshold checkpoint; two member versions later revoked.

    The revoked members' signatures must not count -> 1/2 -> refused.
    """
    entries = _mk_keysets(3)
    ts, roster, root_pub = _threshold_parts(entries, 2)
    body = b"wave186 t1 checkpoint body"
    sigs = ts.sign_all(body)
    # Revoke v1 in keysets 0 and 1 (rotate first: v2 becomes primary).
    ks = []
    for i in range(3):
        e = _rotate(entries[i], i)
        if i < 2:
            s2 = _seed("ks%d|v2" % i)
            e[0] = _revoke(e[0], s2)
        ks.append(e[0])
    keysets = {}
    for i in range(3):
        v1kid = entries[i][2].key_id
        keysets[v1kid] = ks[i]
    try:
        ok, err = _signing.verify_threshold(body, sigs, roster, root_pub,
                                            keysets=keysets)
    except TypeError:
        return ("BREAK",
                "verify_threshold has no keyset seam: a revoked member "
                "version's signature counts")
    if not ok and "1/2" in (err or ""):
        return ("HELD",
                "revoked versions refused: %s" % (err,))
    return ("BREAK",
            "revoked versions still counted: ok=%r err=%r" % (ok, err))


def probe_t2_threshold_stripped_still_refused():
    """Strip key_version from T1's entries: revocation resolves from the
    key id alone, so stripping must not smuggle the revoked versions
    past."""
    entries = _mk_keysets(3)
    ts, roster, root_pub = _threshold_parts(entries, 2, root_tag="root2")
    body = b"wave186 t2 checkpoint body"
    sigs = ts.sign_all(body)
    stripped = []
    for e in sigs:
        e2 = dict(e)
        e2.pop("key_version", None)
        stripped.append(e2)
    ks = []
    for i in range(3):
        e = _rotate(entries[i], i)
        if i < 2:
            s2 = _seed("ks%d|v2" % i)
            e[0] = _revoke(e[0], s2)
        ks.append(e[0])
    keysets = {}
    for i in range(3):
        keysets[entries[i][2].key_id] = ks[i]
    try:
        ok, err = _signing.verify_threshold(body, stripped, roster,
                                            root_pub, keysets=keysets)
    except TypeError:
        return ("BREAK",
                "verify_threshold has no keyset seam (stripped entries)")
    # Refused either way: stripped entries fail cryptographically
    # (their signatures bind the version), and revocation resolves
    # from the key id alone. Either refusal path is a HELD.
    if not ok:
        return ("HELD",
                "stripped entries refused: %s" % (err,))
    return ("BREAK",
            "stripped revoked versions counted: ok=%r err=%r" % (ok, err))


def probe_t3_singlekey_revoked_refused():
    """Single-key checkpoint signed under v1; v1 later revoked. A
    keyset-aware verifier must refuse the checkpoint."""
    ks, signer = _keyset.new_keyset(_seed("t3|v1"))
    s1 = _seed("t3|v1")
    d = _tmpdir()
    log = _logmod.ActionLog(os.path.join(d, "audit.jsonl"), signer=signer)
    log.append({"event": "t3"})
    cp = log.write_checkpoint()
    if cp.get("key_version") != 1:
        return ("BREAK",
                "checkpoint carries no key_version: the STH does not "
                "bind the signing key's version")
    ks2, signer2 = _keyset.rotate_keyset(ks, _seed("t3|v2"), s1)
    ks3 = _keyset.revoke_version(ks2, 1, "key compromise", _seed("t3|v2"))
    v1 = ks3.version(1)
    trusted = {v1.key_id: v1.public_key}
    try:
        ok, err = _logmod._verify_one_checkpoint_sig(
            cp, trusted, keysets={v1.key_id: ks3})
    except TypeError:
        return ("BREAK",
                "_verify_one_checkpoint_sig has no keyset seam: a "
                "checkpoint signed under a revoked version verifies")
    if not ok and "revoked" in (err or ""):
        return ("HELD", "revoked version refused: %s" % (err,))
    return ("BREAK",
            "revoked version accepted: ok=%r err=%r" % (ok, err))


def probe_t4_singlekey_version_tamper():
    """Rewrite key_version in a keyset-signed checkpoint: the STH body
    binds the version, so the signature must fail."""
    ks, signer = _keyset.new_keyset(_seed("t4|v1"))
    d = _tmpdir()
    log = _logmod.ActionLog(os.path.join(d, "audit.jsonl"), signer=signer)
    log.append({"event": "t4"})
    cp = log.write_checkpoint()
    if cp.get("key_version") != 1:
        return ("BREAK",
                "checkpoint carries no key_version: version unattested")
    tampered = dict(cp)
    tampered["key_version"] = 2
    v1 = ks.version(1)
    trusted = {v1.key_id: v1.public_key}
    ok, err = _logmod._verify_one_checkpoint_sig(tampered, trusted)
    if not ok:
        return ("HELD",
                "rewritten key_version breaks the signature: %s" % (err,))
    return ("BREAK",
            "rewritten key_version still verifies: version claim "
            "unattested")


def probe_t5_threshold_versions_distinguishable():
    """3 fresh keysets rotated to v2; 2-of-3 threshold checkpoint via
    ActionLog: every sig entry must carry key_version=2 and verify."""
    entries = _mk_keysets(3)
    rot = [_rotate(entries[i], i) for i in range(3)]
    signers = [e[2] for e in rot]
    root = _signing.Ed25519Signer(_seed("t5root"))
    roster = _signing.make_roster(signers, 2, root)
    ts = _signing.ThresholdSigner(signers, 2)
    d = _tmpdir()
    log = _logmod.ActionLog(os.path.join(d, "audit.jsonl"), signer=ts,
                            roster=roster)
    log.append({"event": "t5"})
    cp = log.write_checkpoint()
    versions = [e.get("key_version") for e in cp["sigs"]]
    if any(v != 2 for v in versions):
        return ("BREAK",
                "threshold sig entries lack key_version=2: %r" % (versions,))
    keysets = {}
    for i in range(3):
        keysets[signers[i].key_id] = rot[i][0]
    try:
        ok, err = _signing.verify_threshold(
            _logmod._sig_body_for_checkpoint(cp), cp["sigs"], roster,
            root.public_key, keysets=keysets)
    except TypeError:
        return ("BREAK", "verify_threshold has no keyset seam")
    if ok:
        return ("HELD",
                "v2 threshold checkpoint verifies, versions "
                "distinguishable: %r" % (versions,))
    return ("BREAK", "honest v2 checkpoint refused: %r" % (err,))


def probe_t6_verify_only_still_verifies():
    """Baseline: checkpoint signed by v1 while active; v1 rotated to
    verify-only (not revoked). Must keep verifying with the keyset."""
    ks, signer = _keyset.new_keyset(_seed("t6|v1"))
    s1 = _seed("t6|v1")
    d = _tmpdir()
    log = _logmod.ActionLog(os.path.join(d, "audit.jsonl"), signer=signer)
    log.append({"event": "t6"})
    cp = log.write_checkpoint()
    ks2, _s2 = _keyset.rotate_keyset(ks, _seed("t6|v2"), s1)
    v1 = ks2.version(1)
    trusted = {v1.key_id: v1.public_key}
    try:
        ok, err = _logmod._verify_one_checkpoint_sig(
            cp, trusted, keysets={v1.key_id: ks2})
    except TypeError:
        # Pristine: no keyset seam; the signature itself verifies.
        ok2, err2 = _logmod._verify_one_checkpoint_sig(cp, trusted)
        if ok2:
            return ("HELD",
                    "baseline: verify-only-era checkpoint verifies "
                    "(no keyset seam on this tree)")
        return ("BREAK", "baseline broken: %r" % (err2,))
    if ok:
        return ("HELD",
                "verify-only version still verifies: rotation does not "
                "invalidate signed checkpoints")
    return ("BREAK", "verify-only version refused: %r" % (err,))


def probe_t7_threshold_confusion_fails_closed():
    """k=3 n=3; one entry's key_version rewritten to a version the
    keyset does not bind to that key id -> must not count -> 2/3."""
    entries = _mk_keysets(3)
    ts, roster, root_pub = _threshold_parts(entries, 3, root_tag="root7")
    body = b"wave186 t7 checkpoint body"
    sigs = ts.sign_all(body)
    confused = [dict(e) for e in sigs]
    confused[0]["key_version"] = 999
    keysets = {}
    for i in range(3):
        keysets[entries[i][2].key_id] = entries[i][0]
    try:
        ok, err = _signing.verify_threshold(body, confused, roster,
                                            root_pub, keysets=keysets)
    except TypeError:
        return ("BREAK",
                "verify_threshold has no keyset seam: confused "
                "version claims count")
    if not ok and "2/3" in (err or ""):
        return ("HELD",
                "confused version claim contributes nothing: %s" % (err,))
    return ("BREAK",
            "confused version counted: ok=%r err=%r" % (ok, err))


PROBES = [
    ("T1", "threshold revoked versions refused",
     probe_t1_threshold_revoked_refused),
    ("T2", "threshold stripped entries still refused",
     probe_t2_threshold_stripped_still_refused),
    ("T3", "single-key revoked version refused",
     probe_t3_singlekey_revoked_refused),
    ("T4", "single-key version tamper breaks signature",
     probe_t4_singlekey_version_tamper),
    ("T5", "threshold rotated versions distinguishable+verify",
     probe_t5_threshold_versions_distinguishable),
    ("T6", "verify-only version still verifies (baseline)",
     probe_t6_verify_only_still_verifies),
    ("T7", "threshold version/key_id confusion fails closed",
     probe_t7_threshold_confusion_fails_closed),
]


def main():
    breaks = held = errors = 0
    for pid, name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery must not die
            verdict, detail = "ERROR", "%r" % (e,)
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
        print("%s %s: %s -- %s" % (verdict, pid, name, detail))
    print("RESULT: %d BREAK / %d HELD / %d errors" % (breaks, held,
                                                     errors))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
