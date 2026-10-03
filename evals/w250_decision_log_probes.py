"""Wave-250 RFC 6962 decision-log probes (red-first).

W250-2: build ``gov/decision_log.py`` -- an RFC 6962 Merkle-tree
decision log for the policy combiner (transparency-dev/merkle ADAPT;
Apache-2.0, pattern adaptation only, stdlib Python reimplementation).

The wave-248 combiner (gov/policy_combine.py) left two documented
residuals:

  1. same-revision equivocation: two decisions from one pinned policy
     revision with different effects combine without complaint;
  2. no request binding: the combiner does not verify all decisions
     were made for the same request.

The decision log closes both: every combined decision is appended as
a leaf (canonical bytes of effect + policy revisions + request
digest); the log refuses to mix request digests without explicit
epoch separation (structural request binding); and
``detect_equivocation()`` produces inclusion-proven evidence when
two logged decisions share (request digest, policy revision) but
differ in effect. The log detects, it does not prevent.

RFC 6962 pins (upstream transparency-dev/merkle, Apache-2.0):
  * hash vectors from rfc6962/rfc6962_test.go (empty root, empty
    leaf, leaf(b"L123456"), node(b"N123", b"N456"));
  * inclusion happy-path vectors from testdata/inclusion/{1..4};
  * consistency happy-path vectors from testdata/consistency/{1..4}.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import base64
import hashlib
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_LOG = False
try:
    from gov import decision_log as _dl
    HAVE_LOG = all(
        hasattr(_dl, n) for n in (
            "hash_leaf", "hash_node", "empty_root", "MerkleTree",
            "DecisionLog", "DecisionLogError",
            "detect_equivocation"))
except ImportError:
    _dl = None

HAVE_COMBINE = False
try:
    from gov import policy_combine as _pc
    HAVE_COMBINE = hasattr(_pc, "combine")
except ImportError:
    _pc = None

HAVE_PD = False
try:
    from gov.policy import PolicyDecision as _PD
    HAVE_PD = True
except ImportError:
    _PD = None

HAVE_ALL = HAVE_LOG and HAVE_COMBINE and HAVE_PD

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _run_probe(name, fn, have):
    if not have:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return name, "BREAK", "GAP: capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _b64(s):
    return base64.b64decode(s)


# ------------------------------------------------- upstream hash pins
# From transparency-dev/merkle rfc6962/rfc6962_test.go (Apache-2.0).
# echo -n | sha256sum ; echo -n 00 | xxd -r -p | sha256sum ;
# echo -n 004C313233343536 | xxd -r -p | sha256sum ;
# echo -n 014E3132334E343536 | xxd -r -p | sha256sum
_VEC_EMPTY_ROOT = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
_VEC_EMPTY_LEAF = (
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
_VEC_LEAF_L123456 = (
    "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56")
_VEC_NODE_N123_N456 = (
    "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb")


# ------------------------------------------------- upstream proof pins
# Inclusion happy-path vectors, testdata/inclusion/{1..4}/happy-path.json
# (leafIdx, treeSize, root, leafHash, proof[]), base64.
_VEC_INCLUSION = [
    (0, 8,
     "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
     "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
     ["lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
      "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
      "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="]),
    (5, 8,
     "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
     "QnGia+DYqE8L1UyMMC58s6O10fpngKQLzOKHNHfatlg=",
     ["vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
      "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
      "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc="]),
    (2, 3,
     "rra8/idLcKFPsGel5VeCZNsPqbUa9eC6FZFY8yngbnc=",
     "ApjRIpBtz8EIkstTpzmS/FufST6kybrbJ7eRtBJ6f+c=",
     ["+sVCA+fMaWzw38tCySodnbr3CtnmIfS9jZhmLwDjwSU="]),
    (1, 5,
     "Tju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=",
     "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
     ["bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
      "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
      "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms="]),
]

# Consistency happy-path vectors, testdata/consistency/{1..4}/
# happy-path.json (size1, size2, root1, root2, proof[]), base64.
_VEC_CONSISTENCY = [
    (1, 8,
     "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
     "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
     ["lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
      "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
      "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="]),
    (6, 8,
     "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=",
     "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
     ["DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=",
      "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
      "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc="]),
    (2, 5,
     "+sVCA+fMaWzw38tCySodnbr3CtnmIfS9jZhmLwDjwSU=",
     "Tju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=",
     ["Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
      "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms="]),
    (6, 7,
     "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=",
     "3bib5AOAnjJXUNPSY814kpwpQreUKjS3fhIslZSnTIw=",
     ["DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=",
      "sIaT7C5yFZcTBkHoIR5+7cy0wmQTlj7ubB4u0W/7Gl8=",
      "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc="]),
]


# ------------------------------------------------- decision factories

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64


def _dec(effect, policy_id, rev_id, digest=_DIGEST_A):
    return _PD(effect, "test reason %s %s" % (effect, policy_id),
               policy_id=policy_id, policy_rev_id=rev_id,
               policy_digest=digest)


def _combined(effect, policy_id="pol-1", rev_id="rev-7"):
    return _pc.combine([_dec(effect, policy_id, rev_id)])


_REQ_A = hashlib.sha256(b"request-A").digest()
_REQ_B = hashlib.sha256(b"request-B").digest()


# ------------------------------------------------- probes


def _probe_rfc6962_hash_vectors():
    assert _dl.hash_leaf(b"") .hex() == _VEC_EMPTY_LEAF, "empty leaf"
    assert _dl.hash_leaf(b"L123456").hex() == _VEC_LEAF_L123456, \
        "leaf L123456"
    assert _dl.hash_node(_b64("TjEyMw=="), _b64("TjQ1Ng==")).hex() == \
        _VEC_NODE_N123_N456, "node N123/N456"
    assert _dl.empty_root().hex() == _VEC_EMPTY_ROOT, "empty root"
    # Domain separation: leaf vs node must differ on same input.
    assert _dl.hash_leaf(b"N123N456") != _dl.hash_node(
        _b64("TjEyMw=="), _b64("TjQ1Ng=="))
    return "4 upstream RFC 6962 hash vectors match"


def _probe_inclusion_upstream_vectors():
    for idx, size, root, leaf_hash, proof in _VEC_INCLUSION:
        ok = _dl.MerkleTree.verify_inclusion(
            idx, _b64(leaf_hash), size,
            [_b64(p) for p in proof], _b64(root))
        assert ok is True, "inclusion (%d,%d) rejected" % (idx, size)
        # A wrong leaf must not verify.
        bad = _dl.MerkleTree.verify_inclusion(
            idx, _dl.hash_leaf(b"wrong"), size,
            [_b64(p) for p in proof], _b64(root))
        assert bad is False, "inclusion (%d,%d) accepted wrong leaf" % (
            idx, size)
    return "4 upstream inclusion vectors verify; wrong leaves refuse"


def _probe_consistency_upstream_vectors():
    for s1, s2, r1, r2, proof in _VEC_CONSISTENCY:
        ok = _dl.MerkleTree.verify_consistency(
            s1, s2, [_b64(p) for p in proof], _b64(r1), _b64(r2))
        assert ok is True, "consistency (%d->%d) rejected" % (s1, s2)
        bad = _dl.MerkleTree.verify_consistency(
            s1, s2, [_b64(p) for p in proof], _b64(r2), _b64(r1))
        assert bad is False, "consistency (%d->%d) accepted swapped" % (
            s1, s2)
    return "4 upstream consistency vectors verify; swapped roots refuse"


def _probe_tree_append_inclusion_roundtrip():
    t = _dl.MerkleTree()
    idxs = [t.append(b"leaf-%d" % i) for i in range(9)]
    assert idxs == list(range(9)), idxs
    root = t.root()
    for i in range(9):
        proof = t.inclusion_proof(i)
        assert _dl.MerkleTree.verify_inclusion(
            i, _dl.hash_leaf(b"leaf-%d" % i), 9, proof, root) is True, i
    # Deterministic: a second tree over the same leaves, same root.
    t2 = _dl.MerkleTree()
    for i in range(9):
        t2.append(b"leaf-%d" % i)
    assert t2.root() == root, "root not deterministic"
    return "9-leaf roundtrip: all inclusion proofs verify, root stable"


def _probe_log_request_binding():
    log = _dl.DecisionLog()
    log.append(_combined("allow"), _REQ_A)
    log.append(_combined("deny", policy_id="pol-2"), _REQ_A)
    try:
        log.append(_combined("allow", policy_id="pol-3"), _REQ_B)
    except _dl.DecisionLogError as exc:
        assert exc.code == "decision-log-request-mismatch", exc.code
    else:
        raise AssertionError("mixed request digests appended silently")
    assert log.tree_size() == 2, "refused append must not grow the log"
    return "mixed request digests refuse with decision-log-request-mismatch"


def _probe_log_epoch_separation():
    log = _dl.DecisionLog()
    log.append(_combined("allow"), _REQ_A)
    log.new_epoch(_REQ_B)
    log.append(_combined("deny", policy_id="pol-9"), _REQ_B)
    assert log.tree_size() == 2
    epochs = log.epochs()
    assert len(epochs) == 2, epochs
    assert epochs[0]["request_digest"] == _REQ_A.hex()
    assert epochs[1]["request_digest"] == _REQ_B.hex()
    # Old-epoch leaf still inclusion-provable against the current root.
    assert log.verify_leaf(0) is True
    return "explicit epoch separation works; old leaves stay provable"


def _probe_equivocation_detected():
    log = _dl.DecisionLog()
    log.append(_combined("allow", policy_id="pol-1", rev_id="rev-7"),
               _REQ_A)
    log.append(_combined("deny", policy_id="pol-1", rev_id="rev-7"),
               _REQ_A)
    found = _dl.detect_equivocation(log)
    assert len(found) == 1, found
    ev = found[0]
    assert ev.code == "decision-log-equivocation", ev.code
    assert {ev.effect_a, ev.effect_b} == {"allow", "deny"}, ev
    # Both halves of the equivocation proof verify against the root.
    assert ev.verify(log) is True, "equivocation proof does not verify"
    return "same (request, revision) + different effects -> proven"


def _probe_equivocation_no_false_positive():
    log = _dl.DecisionLog()
    log.append(_combined("allow", policy_id="pol-1", rev_id="rev-7"),
               _REQ_A)
    log.append(_combined("allow", policy_id="pol-1", rev_id="rev-7"),
               _REQ_A)
    assert _dl.detect_equivocation(log) == [], "false equivocation"
    # Different revisions deciding differently is not equivocation.
    log2 = _dl.DecisionLog()
    log2.append(_combined("allow", policy_id="pol-1", rev_id="rev-7"),
                _REQ_A)
    log2.append(_combined("deny", policy_id="pol-1", rev_id="rev-8"),
                _REQ_A)
    assert _dl.detect_equivocation(log2) == [], "rev change flagged"
    return "identical repeats and revision changes are not equivocation"


def _probe_failclosed_tampered_proof():
    log = _dl.DecisionLog()
    log.append(_combined("allow"), _REQ_A)
    log.append(_combined("deny", policy_id="pol-2"), _REQ_A)
    proof = log.inclusion_proof(0)
    bad = [bytes(b) for b in proof]
    assert bad, "empty proof for 2-leaf tree"
    flipped = bytearray(bad[0])
    flipped[0] ^= 0xFF
    bad[0] = bytes(flipped)
    try:
        log.verify_proof(0, bad)
    except _dl.DecisionLogError as exc:
        assert exc.code == "decision-log-proof-invalid", exc.code
    else:
        raise AssertionError("tampered proof verified")
    return "tampered inclusion proof refuses with proof-invalid"


def _probe_failclosed_malformed_leaf():
    log = _dl.DecisionLog()
    for bad in ("not-a-decision", {"effect": "allow"}, None, 42):
        try:
            log.append(bad, _REQ_A)
        except _dl.DecisionLogError as exc:
            assert exc.code == "decision-log-malformed", exc.code
        else:
            raise AssertionError("malformed leaf accepted: %r" % (bad,))
    try:
        log.append(_combined("allow"), "not-bytes")
    except _dl.DecisionLogError as exc:
        assert exc.code == "decision-log-malformed", exc.code
    else:
        raise AssertionError("non-bytes request digest accepted")
    assert log.tree_size() == 0
    return "malformed leaves and digests refuse; log unchanged"


def _probe_sth_sign_verify():
    log = _dl.DecisionLog()
    log.append(_combined("allow"), _REQ_A)
    sth = log.issue_sth()
    assert sth["signature"] is None, "unsigned STH must carry no signature"
    from gov import ed25519 as _e
    seed = _e.generate_seed()
    pub = _e.publickey(seed)
    signed = log.sign_sth(sth, seed)
    assert signed["signature"] is not None
    assert log.verify_sth(signed, pub) is True
    tampered = dict(signed)
    tampered["tree_size"] = signed["tree_size"] + 1
    assert log.verify_sth(tampered, pub) is False, \
        "tampered STH verified"
    return "STH issues unsigned, signs with deployment key, verifies"


def _probe_taxonomy_codes_present():
    from gov import decision_codes as dc
    for code in ("decision-log-malformed",
                 "decision-log-request-mismatch",
                 "decision-log-proof-invalid",
                 "decision-log-equivocation"):
        assert code in dc.TAXONOMY, "missing taxonomy code %r" % (code,)
        assert dc.TAXONOMY[code]["domain"] == "decision-log", code
    return "4 decision-log codes in taxonomy under decision-log"


_PROBES = {
    "rfc6962-hash-vectors": (_probe_rfc6962_hash_vectors, HAVE_LOG),
    "inclusion-upstream-vectors": (_probe_inclusion_upstream_vectors,
                                   HAVE_LOG),
    "consistency-upstream-vectors": (_probe_consistency_upstream_vectors,
                                     HAVE_LOG),
    "tree-append-inclusion-roundtrip":
        (_probe_tree_append_inclusion_roundtrip, HAVE_LOG),
    "log-request-binding": (_probe_log_request_binding, HAVE_ALL),
    "log-epoch-separation": (_probe_log_epoch_separation, HAVE_ALL),
    "equivocation-detected": (_probe_equivocation_detected, HAVE_ALL),
    "equivocation-no-false-positive":
        (_probe_equivocation_no_false_positive, HAVE_ALL),
    "failclosed-tampered-proof": (_probe_failclosed_tampered_proof,
                                  HAVE_ALL),
    "failclosed-malformed-leaf": (_probe_failclosed_malformed_leaf,
                                  HAVE_ALL),
    "sth-sign-verify": (_probe_sth_sign_verify, HAVE_ALL),
    "taxonomy-codes-present": (_probe_taxonomy_codes_present, HAVE_LOG),
}

PROBE_NAMES = list(_PROBES)


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1.
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    for mod in ("tests.test_decision_log", "tests.test_decision_codes",
                "tests.test_policy_combine"):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            cwd=root, env=env, capture_output=True, text=True, timeout=300)
        notes.append("unit %s rc=%d" % (mod, proc.returncode))
        if proc.returncode != 0:
            notes.append("unit tail: %s" % (proc.stderr[-500:],))
    return notes


def main():
    print("wave-250 decision_log probes (log present: %s)" % (HAVE_LOG,))
    results = []
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        results.append((name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    held = sum(1 for _n, s, _d in results if s == "HELD")
    brk = sum(1 for _n, s, _d in results if s == "BREAK")
    err = sum(1 for _n, s, _d in results if s == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
