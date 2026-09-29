#!/usr/bin/env python3
"""Break-first probes for wave-194: the TUF follow-on #2 steal --
signed corpus manifest + per-skill manifest threshold.

Background: the wave-193 python-tuf spike (teams/wave193-tuf/SPIKE.md)
found two gaps in the load path:

  (a) mix-and-match GAP -- no signed {artifact_id -> digest} corpus
      binding exists anywhere; pins are independent per artifact.
  (b) threshold PARTIAL -- the production pin tier needs 2 distinct
      humans, but gov/capability_manifests.verify_manifest accepts
      ONE valid signature, with no per-skill threshold knob.

RED-PHASE (--red-phase): run against the PRISTINE tree. Demonstrates
the gaps: (R1) no corpus manifest seam exists in gov/ (import fails);
(R2) verify_manifest accepts a single-signature manifest with no
threshold parameter (the production-tier 2-of-2 requirement cannot
even be expressed); (R3) load_skill_content has no corpus parameter
(inspect its signature). Exit 0 = gap shown.

GREEN-PHASE (default): the closure battery on the fixed tree.

  T1  honest_load          manifest+pin agree -> load succeeds
  T2  mix_and_match        pin digest != manifest digest -> REFUSED
  T3  unbound              artifact id not in manifest -> REFUSED
  T4  forged_manifest      tampered doc -> bad_signature REFUSED
  T5  expired_manifest     expires_at in the past -> REFUSED
  T6  rollback             older version re-presented -> corpus_stale
  T7  rotation_stable      v1-signed manifest verifies under rotated
                           keyset (v1 verify-only) -> loads
  T8  revoked_member       v1 revoked -> its sig stops counting ->
                           threshold_unmet REFUSED
  T9  manifest_threshold   capability manifest: default 1 ok;
                           threshold=2 needs 2 DISTINCT kids;
                           same kid twice counts once
  T10 wrong_purpose        audit-purpose keyset cannot mint/verify a
                           corpus manifest
  T11 legacy_no_corpus     no corpus -> pinset-only behavior unchanged
  T12 doc_without_tracker  corpus_doc but corpus=None -> REFUSED
  T13 corpus_threshold_two 2-of-2 corpus via rotation-pinned human keys;
      1-of-2 refused

Usage:
  python3 evals/tuf_corpus_probes.py --red-phase   # gap demo (pristine)
  python3 evals/tuf_corpus_probes.py               # closure battery

Deterministic: expiries anchored far from now; main() runs the battery
twice and requires identical statuses.

Conventions: module-level GOV_DEPLOYMENT_MODE=staging; verify standalone
under `env -u GOV_DEPLOYMENT_MODE`; GOV_SKIP_GREEN honored; green check is
depth-1 (tests/test_corpus_manifest + tests/test_capability_manifests,
child env GOV_SKIP_GREEN=1); the battery never touches the shared tree --
TREE is the tree it lives in.
"""

import copy
import hashlib
import inspect
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TREE = REPO_ROOT  # this battery lives in the tree it tests
sys.path.insert(0, TREE)

_SEED1 = bytes.fromhex("11" * 32)
_SEED2 = bytes.fromhex("22" * 32)
_SEED3 = bytes.fromhex("33" * 32)
_TS = "2026-09-29T00:00:00+00:00"
_ISSUED = "2026-09-01T00:00:00+00:00"
_FUTURE = "2030-01-01T00:00:00+00:00"
_PAST = "2020-01-01T00:00:00+00:00"
_OLD_ISSUED = "2019-01-01T00:00:00+00:00"


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Red-phase: pristine-tree gap demonstration.
# ---------------------------------------------------------------------------

def _red_no_corpus_module():
    """R1: no corpus manifest seam exists on the pristine tree."""
    try:
        import gov.corpus_manifest  # noqa: F401
    except ImportError:
        return "PASS", "gov.corpus_manifest absent: no corpus binding"
    return "FAIL", "corpus manifest module unexpectedly present"


def _red_single_sig_accepted():
    """R2: verify_manifest has no threshold knob; one signature always
    suffices -- the production 2-of-2 requirement cannot be expressed."""
    from gov import capability_manifests as cm
    from gov import ed25519 as ed
    kid = "red-kid"
    pub = ed.publickey(_SEED1)
    store = cm.ManifestStore(keys={kid: pub}, manifests={})
    content = b"red skill bytes"
    manifest = cm.make_manifest("skill:red", content, capabilities={},
                                kid=kid, seed=_SEED1)
    try:
        info = cm.verify_manifest(manifest, store)
    except Exception as e:  # noqa: BLE001
        return "FAIL", "single-sig manifest refused: %s" % e
    if info["kids"] != [kid]:
        return "FAIL", "unexpected kids: %r" % (info["kids"],)
    try:
        cm.verify_manifest(manifest, store, threshold=2)
        return "FAIL", "threshold kwarg exists on pristine tree?"
    except TypeError:
        pass  # expected: no threshold knob
    return "PASS", ("single signature accepted, no threshold parameter "
                    "to require two")


def _red_load_has_no_corpus():
    """R3: load_skill_content has no corpus parameter on pristine."""
    from gov import load_gate as lg
    params = inspect.signature(lg.load_skill_content).parameters
    if "corpus" in params or "corpus_doc" in params:
        return "FAIL", "corpus params unexpectedly present"
    return "PASS", "load_skill_content pins-only (no corpus seam)"


RED_PROBES = [

    ("R1_no_corpus_module", _red_no_corpus_module),
    ("R2_single_sig_accepted", _red_single_sig_accepted),
    ("R3_load_has_no_corpus", _red_load_has_no_corpus),
]


# ---------------------------------------------------------------------------
# Green-phase: closure battery fixtures.
# ---------------------------------------------------------------------------

def _world(threshold=1, nsigners=1, tier="dev"):
    """Build keyset + signers + pinset world. Returns dict of parts."""
    from gov import corpus_manifest as cm
    from gov.keyset import new_keyset, keyset_signer_for_version
    from gov import load_gate as lg
    from gov.delegation_tokens import DelegationTrust
    from gov.signing import Ed25519Signer
    seeds = [_SEED1, _SEED2, _SEED3][:nsigners]
    keyset, _ = new_keyset(seeds[0],
                           purpose=cm.KEYSET_PURPOSE_CORPUS_MANIFEST)
    signers = [keyset_signer_for_version(keyset, 1, s) for s in seeds]
    h1, h2 = Ed25519Signer(_SEED1), Ed25519Signer(_SEED2)
    trust = DelegationTrust(
        human_keys={h1.key_id: h1.public_key, h2.key_id: h2.public_key},
        authority_keys={h1.key_id: h1.public_key},
        user_issuer_keys={h2.key_id: h2.public_key})
    pinset = lg.ArtifactPinset(trust)
    return {"cm": cm, "lg": lg, "keyset": keyset, "signers": signers,
            "pinset": pinset, "h1": h1, "threshold": threshold}


def _pin(w, artifact_id, digest, tier="dev"):
    lg = w["lg"]
    # v2 pin protocol (wave-194 lane A): the canonical body commits to
    # (tier|artifact_id|digest|ts|version|not_after), so probes pin at
    # version 1 with the default 90-day expiry bound resolved from ts.
    version = 1
    not_after = lg._resolve_pin_not_after(_TS, None)
    body = lg._canonical_pin_body(tier, artifact_id, digest, _TS,
                                  version=version, not_after=not_after)
    return w["pinset"].pin(artifact_id, digest, w["h1"].key_id,
                           w["h1"].sign(body).hex(), ts=_TS, tier=tier,
                           version=version, not_after=not_after)


def _mint(w, artifacts, version=1, expires_at=_FUTURE,
          issued_at=_ISSUED):
    return w["cm"].mint_corpus_manifest(
        w["keyset"], w["signers"], artifacts=artifacts,
        corpus_version=version, issued_at=issued_at,
        expires_at=expires_at, threshold=w["threshold"])


def _tracker(w):
    return w["lg"].CorpusManifestTracker(w["keyset"])


def _load(w, tracker, doc, skill_name, store):
    return w["lg"].load_skill_content(
        w["pinset"], store, skill_name, corpus=tracker, corpus_doc=doc)


def _t1_honest_load():
    w = _world()
    content = b"skill alpha bytes v1"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    doc = _mint(w, {"skill:alpha": digest}, version=1)
    tracker = _tracker(w)
    marked = _load(w, tracker, doc, "alpha", {"alpha": content})
    ack = marked._ack_context
    assert ack["digest"] == digest, ack
    assert ack["artifact_id"] == "skill:alpha", ack
    return "PASS", "honest manifest+pin loads; digest named in ack"


def _t2_mix_and_match():
    w = _world()
    content = b"skill alpha bytes v2 (rotated)"
    digest_v2 = _digest(content)
    digest_v1 = _digest(b"skill alpha bytes v1")
    _pin(w, "skill:alpha", digest_v2)          # pin moved to v2
    doc = _mint(w, {"skill:alpha": digest_v1}, version=2)  # manifest stale
    tracker = _tracker(w)
    try:
        _load(w, tracker, doc, "alpha", {"alpha": content})
    except w["lg"].ArtifactRefused as e:
        assert "corpus_manifest_mismatch" in str(e), str(e)
        return "PASS", "pin/manifest version skew refused"
    return "FAIL", "mix-and-match accepted"


def _t3_unbound():
    w = _world()
    content = b"skill beta bytes"
    digest = _digest(content)
    _pin(w, "skill:beta", digest)
    doc = _mint(w, {"skill:alpha": "sha256:" + "cc" * 32}, version=1)
    tracker = _tracker(w)
    try:
        _load(w, tracker, doc, "beta", {"beta": content})
    except w["lg"].ArtifactRefused as e:
        assert "corpus_manifest_unbound" in str(e), str(e)
        return "PASS", "artifact missing from manifest refused"
    return "FAIL", "unbound artifact accepted"


def _t4_forged_manifest():
    w = _world()
    content = b"skill alpha bytes v1"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    doc = _mint(w, {"skill:alpha": digest}, version=1)
    import copy
    forged = copy.deepcopy(doc)
    forged["artifacts"]["skill:alpha"] = _digest(b"attacker bytes")
    tracker = _tracker(w)
    try:
        _load(w, tracker, forged, "alpha", {"alpha": content})
    except w["lg"].ArtifactRefused as e:
        assert "corpus_manifest_bad_signature" in str(e), str(e)
        return "PASS", "tampered manifest refused"
    return "FAIL", "forged manifest accepted"


def _t5_expired_manifest():
    w = _world()
    content = b"skill alpha bytes v1"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    doc = _mint(w, {"skill:alpha": digest}, version=1,
                expires_at=_PAST, issued_at=_OLD_ISSUED)
    tracker = _tracker(w)
    try:
        _load(w, tracker, doc, "alpha", {"alpha": content})
    except w["lg"].ArtifactRefused as e:
        assert "corpus_manifest_corpus_expired" in str(e), str(e)
        return "PASS", "expired manifest refused"
    return "FAIL", "expired manifest accepted"


def _t6_rollback():
    w = _world()
    content = b"skill alpha bytes"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    tracker = _tracker(w)
    doc2 = _mint(w, {"skill:alpha": digest}, version=2)
    tracker.present(doc2)
    doc1 = _mint(w, {"skill:alpha": digest}, version=1)
    try:
        w["lg"].load_skill_content(
            w["pinset"], {"alpha": content}, "alpha",
            corpus=tracker, corpus_doc=doc1)
    except w["lg"].ArtifactRefused as e:
        assert "corpus_manifest_stale" in str(e), str(e)
        return "PASS", "older corpus version re-presented -> refused"
    return "FAIL", "corpus rollback accepted"


def _t7_rotation_stable():
    from gov.keyset import rotate_keyset, keyset_signer_for_version
    w = _world()
    content = b"skill alpha bytes v1"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    doc = _mint(w, {"skill:alpha": digest}, version=1)
    # Rotate: v2 active, v1 drops to verify-only.
    ks2, _sg2 = rotate_keyset(w["keyset"], _SEED2, _SEED1)
    tracker2 = w["lg"].CorpusManifestTracker(ks2)
    marked = w["lg"].load_skill_content(
        w["pinset"], {"alpha": content}, "alpha",
        corpus=tracker2, corpus_doc=doc)
    assert marked._ack_context["digest"] == digest
    # And the old version can no longer mint (active-only minting).
    try:
        keyset_signer_for_version(ks2, 1, _SEED1)
        return "FAIL", "verify-only version minted a signer"
    except Exception:  # noqa: BLE001 -- KeysetError expected
        pass
    return "PASS", "verify-only v1 still verifies; cannot mint"


def _t8_revoked_member():
    from gov.keyset import rotate_keyset, revoke_version
    w = _world()
    content = b"skill alpha bytes v1"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    doc = _mint(w, {"skill:alpha": digest}, version=1)
    ks2, _ = rotate_keyset(w["keyset"], _SEED2, _SEED1)
    ks_rev = revoke_version(ks2, 1, "compromised", _SEED2)
    tracker = w["lg"].CorpusManifestTracker(ks_rev)
    try:
        w["lg"].load_skill_content(
            w["pinset"], {"alpha": content}, "alpha",
            corpus=tracker, corpus_doc=doc)
    except w["lg"].ArtifactRefused as e:
        # Revoked member's signature stops counting: zero valid
        # members -> bad-signature.
        assert "corpus_manifest_bad_signature" in str(e), str(e)
        return "PASS", "revoked member sig stops counting -> refused"
    return "FAIL", "revoked member signature accepted"


def _cap_world():
    from gov import capability_manifests as cm
    from gov import ed25519 as ed
    k1, k2 = "cap-kid-1", "cap-kid-2"
    store = cm.ManifestStore(
        keys={k1: ed.publickey(_SEED1), k2: ed.publickey(_SEED2)},
        manifests={})
    return cm, store, k1, k2


def _t9_manifest_threshold():
    cm, store, k1, k2 = _cap_world()
    content = b"cap skill bytes"
    one = cm.make_manifest("skill:cap", content, capabilities={},
                           kid=k1, seed=_SEED1)
    # Default threshold=1: legacy contract preserved.
    info = cm.verify_manifest(one, store)
    assert info["kids"] == [k1], info
    # threshold=2 with one signature: refused.
    try:
        cm.verify_manifest(one, store, threshold=2)
        return "FAIL", "threshold=2 accepted a single signature"
    except cm.ManifestVerificationError as e:
        assert e.code == "threshold-unmet", e.code
    # Two DISTINCT kids: accepted.
    two = cm.make_manifest("skill:cap", content, capabilities={},
                           kid=k1, seed=_SEED1)
    two["signatures"].append(cm.sign_manifest(two, k2, _SEED2))
    info2 = cm.verify_manifest(two, store, threshold=2)
    assert sorted(info2["kids"]) == [k1, k2], info2
    # Same kid twice: counts once -> still unmet at threshold=2.
    dup = cm.make_manifest("skill:cap", content, capabilities={},
                           kid=k1, seed=_SEED1)
    dup["signatures"].append(cm.sign_manifest(dup, k1, _SEED1))
    try:
        cm.verify_manifest(dup, store, threshold=2)
        return "FAIL", "same kid twice counted as two"
    except cm.ManifestVerificationError as e:
        assert e.code == "threshold-unmet", e.code
    # The (ok, detail) seam carries the code.
    store2 = cm.ManifestStore(
        keys={k1: store.pubkey_for(k1), k2: store.pubkey_for(k2)},
        manifests={"skill:cap": one})
    ok, detail = cm.verify_skill_manifest("skill:cap", content, store2,
                                          threshold=2)
    assert (ok, detail) == (False, "manifest-threshold-unmet"), detail
    return "PASS", "threshold=2 needs 2 distinct kids; default 1 kept"


def _t10_wrong_purpose():
    from gov.keyset import new_keyset, keyset_signer_for_version
    w = _world()
    audit_ks, _ = new_keyset(_SEED3)  # default audit purpose
    audit_sg = keyset_signer_for_version(audit_ks, 1, _SEED3)
    try:
        w["cm"].mint_corpus_manifest(
            audit_ks, [audit_sg], artifacts={}, corpus_version=1,
            issued_at=_ISSUED, expires_at=_FUTURE, threshold=1)
        return "FAIL", "audit keyset minted a corpus manifest"
    except w["cm"].CorpusManifestError as e:
        assert e.code == "wrong-purpose", e.code
    # And an audit keyset cannot verify a corpus manifest either.
    doc = _mint(w, {}, version=1)
    try:
        w["cm"].verify_corpus_manifest(doc, audit_ks)
        return "FAIL", "audit keyset verified a corpus manifest"
    except w["cm"].CorpusManifestError as e:
        assert e.code == "wrong-purpose", e.code
    return "PASS", "purpose binding enforced at mint and verify"


def _t11_legacy_no_corpus():
    w = _world()
    content = b"legacy skill bytes"
    digest = _digest(content)
    _pin(w, "skill:legacy", digest)
    marked = w["lg"].load_skill_content(w["pinset"], {"legacy": content},
                                        "legacy")
    assert marked._ack_context["digest"] == digest
    return "PASS", "no corpus -> pinset-only behavior unchanged"


def _t12_doc_without_tracker():
    w = _world()
    content = b"skill alpha bytes v1"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    doc = _mint(w, {"skill:alpha": digest}, version=1)
    try:
        w["lg"].load_skill_content(
            w["pinset"], {"alpha": content}, "alpha", corpus_doc=doc)
    except w["lg"].ArtifactRefused as e:
        assert "corpus_manifest_unpresented" in str(e), str(e)
        return "PASS", "corpus doc without tracker refused"
    return "FAIL", "corpus doc without tracker accepted"


def _t13_corpus_threshold_two():
    """Corpus 2-of-2: deployment rotates two human keys in as keyset
    versions and mints with their plain signers."""
    from gov.keyset import rotate_keyset, new_keyset, Ed25519Signer
    w = _world()
    ks1, _ = new_keyset(_SEED1, purpose=w["cm"].KEYSET_PURPOSE_CORPUS_MANIFEST)
    ks2, _ = rotate_keyset(ks1, _SEED2, _SEED1)
    ks3, _ = rotate_keyset(ks2, _SEED3, _SEED2)
    signers = [Ed25519Signer(_SEED2), Ed25519Signer(_SEED3)]
    content = b"skill alpha bytes v1"
    digest = _digest(content)
    _pin(w, "skill:alpha", digest)
    doc = w["cm"].mint_corpus_manifest(
        ks3, signers, artifacts={"skill:alpha": digest},
        corpus_version=1, issued_at=_ISSUED, expires_at=_FUTURE,
        threshold=2)
    tracker = w["lg"].CorpusManifestTracker(ks3)
    try:
        marked = w["lg"].load_skill_content(
            w["pinset"], {"alpha": content}, "alpha",
            corpus=tracker, corpus_doc=doc)
    except w["lg"].ArtifactRefused as e:
        return "FAIL", "2-of-2 corpus refused: %s" % e
    assert marked._ack_context["digest"] == digest
    # One member's sig corrupted -> load refused (threshold unmet).
    bad = copy.deepcopy(doc)
    bad["signatures"][1]["sig"] = "00" * 64
    tracker2 = w["lg"].CorpusManifestTracker(ks3)
    try:
        w["lg"].load_skill_content(
            w["pinset"], {"alpha": content}, "alpha",
            corpus=tracker2, corpus_doc=bad)
    except w["lg"].ArtifactRefused as e:
        assert "corpus_manifest_threshold_unmet" in str(e), str(e)
        return "PASS", "corpus 2-of-2 honest load OK; 1-of-2 refused"
    return "FAIL", "corrupted 1-of-2 corpus accepted"


PROBES = [
    ("T1_honest_load", _t1_honest_load),
    ("T2_mix_and_match", _t2_mix_and_match),
    ("T3_unbound", _t3_unbound),
    ("T4_forged_manifest", _t4_forged_manifest),
    ("T5_expired_manifest", _t5_expired_manifest),
    ("T6_rollback", _t6_rollback),
    ("T7_rotation_stable", _t7_rotation_stable),
    ("T8_revoked_member", _t8_revoked_member),
    ("T9_manifest_threshold", _t9_manifest_threshold),
    ("T10_wrong_purpose", _t10_wrong_purpose),
    ("T11_legacy_no_corpus", _t11_legacy_no_corpus),
    ("T12_doc_without_tracker", _t12_doc_without_tracker),
    ("T13_corpus_threshold_two", _t13_corpus_threshold_two),
]


# ---------------------------------------------------------------------------
# Runner.
# ---------------------------------------------------------------------------

def _run_once(probes):
    results = []
    for name, fn in probes:
        try:
            status, detail = fn()
        except AssertionError as e:
            status, detail = "FAIL", "assertion: %s" % (e,)
        except Exception as e:  # noqa: BLE001 - probes must not crash
            status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
        results.append((name, status, detail))
    return results

    return "FAIL", "corrupted 1-of-2 corpus accepted"
def _green_check():
    """Depth-1: adjacent unit modules only, child env GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="tuf-corpus-green-")
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_corpus_manifest",
             "tests.test_capability_manifests"],
            capture_output=True, text=True, timeout=600, cwd=TREE,
            env=env)
        tail = (p.stdout + p.stderr)[-1500:]
        print("green check (test_corpus_manifest + "
              "test_capability_manifests):\n%s" % tail)
        return p.returncode == 0
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    red_phase = "--red-phase" in argv
    probes = RED_PROBES if red_phase else PROBES
    first = _run_once(probes)
    second = _run_once(probes)
    det_ok = ([(n, s) for n, s, _ in first]
              == [(n, s) for n, s, _ in second])
    width = max(len(n) for n, _, _ in first)
    print("== tuf_corpus probes (%s) =="
          % ("RED-PHASE: gap demonstration" if red_phase else
             "GREEN-PHASE: closure battery"))
    for name, status, detail in first:
        print("%-*s %s  %s" % (width, name, status, detail))
    print("determinism x2: %s" % ("IDENTICAL" if det_ok else "DIVERGED"))
    if red_phase:
        if all(s == "PASS" for _, s, _ in first) and det_ok:
            print("GAP SHOWN: %d/%d gaps demonstrated, statuses "
                  "identical x2" % (len(first), len(first)))
            return 0
        print("RED-PHASE INCONCLUSIVE")
        return 1
    if not _green_check():
        print("GREEN CHECK FAILED")
        return 1
    bad = [(n, d) for n, s, d in first if s != "PASS"]
    if bad or not det_ok:
        print("%d probe(s) failing" % len(bad))
        for n, d in bad:
            print("  FAIL %s: %s" % (n, d))
        return 1
    print("ALL %d PROBES PASS" % len(first))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
