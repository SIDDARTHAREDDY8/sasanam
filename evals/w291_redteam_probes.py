"""Wave-291 independent red-team battery (Lane 4): attack the wave-290 merge.

Base: wave-290 merge commit 9c12f9b4b0aec88746786e68e3f84ae7f04d2d16
(verified via git rev-parse HEAD after clone; ls-remote agrees).
gov/ is byte-identical (attack only, no product code).

Attack surface (all wave-290 additions and residual seams):
  (a) gov/evidence_provenance.py -- rebuild_recipe (sasanam-rebuild/1):
      recipe substitution under a valid signature, transform-vocab
      gaps (is concat+slice+prefix expressive enough to launder a
      digest? bounded transforms -- any bound a 64KB budget misses?),
      verify_rebuild with attacker-controlled material bytes,
      rebuild_required demand paths, anchor_bundle_gated ordering
      (refusal-before-sequencing), a rebuild_recipe carrying a stale
      anchor digest.
  (b) gov/runtime_posture.py -- producer_id binding: producer
      substitution post-signing (signature forgery or a real path?),
      pre-binding record refusal, any legacy-verification path that
      skips the producer check.
  (c) gov/evidence_admission.py -- admit_at_risk error-only API: can a
      caller manufacture a GENUINE AdmissionError (obtained through an
      actual admit() call on attacker-controlled inputs) and then use it
      for an unrelated floor-failed decision? The in-process
      _REFUSE_REGISTRY: cross-decision confusion, registry eviction
      (bounded 1024 -- can the real refusal be flooded out?).
  (d) gov/ceremony_binding.py -- F352-F355 expected-open re-pins via the
      w290 battery; ceremony_leaf shape coverage beyond the keyless
      payload (wrong-typed keys, extra keys).
  (e) Cross-module: a floor-failed admission -> rebuild_required demand
      -> verify_posture chain; a rebuild_recipe carrying a stale anchor
      digest (anchored envelope re-presented against a mutated bundle).

Re-pins at the public seams:
  F311-F351 (CLOSED) -- 0 BREAK expected (w289_redteam +
      w290_rebuild + w290_f348_f349 subprocesses).
  F352-F355 (OPEN at base) -- 6 BREAK expected-open via
      evals/w290_redteam_probes.py (f352-ceremony-sink,
      f353-ceremony-leaf, f353-anchor-binding, f354-pinfile,
      f355a-ceremony-sig, f355b-posture-sig).

New findings filed from F356 with severity labels and falsifiable
close-when criteria.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g291-redteam && TMPDIR=/var/tmp/g291-redteam \\
    ~/workspace/.gov-venv/bin/python evals/w291_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g291-redteam2 \\
    ~/workspace/.gov-venv/bin/python evals/w291_redteam_probes.py
"""

import hashlib
import inspect
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*).
TAXONOMY_PIN = 1826  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    silent pass."""
    try:
        fn()
    except Exception:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected exception: %s"
                % traceback.format_exc(limit=3).replace("\n", " | "))
        return
    if not any(p == pid or p.startswith(pid + "-")
               for p, _, _ in _results):
        _record(pid, "ERROR", "probe recorded nothing")


def _literals():
    # Wave-260 lesson: assert on source literals in decision_codes.py,
    # not len(TAXONOMY) (dict dedup hides duplicate inserts).
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1826/1826/0 sorted")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MATS = {"material/a": b"A" * 32, "material/b": b"B" * 48}
_NO_RECIPE = object()


def _provenance_parts(rebuild_required=(), recipe=None):
    from gov import evidence_provenance as ep
    from gov import ed25519
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    bid = "build.example.com/ci"
    policy = ep.BuilderPolicy("auditor-pin-1", {bid: pub},
                              rebuild_required=rebuild_required)
    return ep, seed, "key-1", bid, policy


def _recipe(order=("material/a", "material/b")):
    return {
        "recipe_format": "sasanam-rebuild/1",
        "inputs": ["material/a", "material/b"],
        "steps": [
            {"op": "concat", "order": list(order)},
            {"op": "sha256"},
        ],
    }


def _claim_sealed(ep, seed, keyid, bid, recipe=None, issued=1700000000):
    recipe = _recipe() if recipe is None else recipe
    if recipe is _NO_RECIPE:
        recipe = None
    order = recipe["steps"][0]["order"] if recipe else ()
    artifact = (hashlib.sha256(b"".join(_MATS[u] for u in order)).hexdigest()
                if recipe else "ab" * 32)
    materials = [{"uri": u, "digest": hashlib.sha256(b).hexdigest(),
                  "completeness": "verified"}
                 for u, b in _MATS.items()]
    claim = ep.make_provenance_claim(bid, keyid, artifact, materials,
                                     issued_at=issued,
                                     rebuild_recipe=recipe)
    return ep.seal_provenance(claim, seed), artifact


def _posture_parts(producer_id="operator", slot_source="log-op"):
    from gov import runtime_posture as rp
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": slot_source}
    rec = rp.issue_posture(
        operator_seed=seed, operator_keyid="op1",
        eat_nonce=secrets.token_bytes(16),
        submods={"sbx": {"digest": "ab" * 32}},
        software_id="agent/1.0", config_digest="cd" * 32,
        endorsements={c: dict(slot) for c in
                      ("software_id", "config_digest", "submods")},
        producer_id=producer_id)
    return rec, seed, pub


def _policy(adm, policy_id="p1", level="strict"):
    return adm.compile_policy({
        "format": "admission-policy/1",
        "policy_id": policy_id,
        "scopes": [{"scope": "provenance", "level": level}],
    })


def _ev():
    return {"kind": "provenance", "artifact_digest": "ab" * 32}


def _outcomes(adm, fails=()):
    return {c: (c not in fails) for c in adm.CHECKS}


def _risk_store(adm, policy_id, grant=True):
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register(adm.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                 "admission", "medium", "accept at operator risk",
                 ["admission-policy"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["ops"])
    if grant:
        now = time.time()
        store.grant(adm.ACCEPT_RISK_CHECK_ID, ("policy", policy_id),
                    "accepting at risk for this test run, operator review",
                    "ops", now + 3600, now)
    return store


def _refuse_err(adm, fails):
    """Manufacture a GENUINE AdmissionError through a real admit() call."""
    pol = _policy(adm)
    try:
        adm.admit(_ev(), pol, _outcomes(adm, fails=fails))
    except adm.AdmissionError as e:
        return e
    raise AssertionError("admit() did not refuse for fails=%r" % (fails,))


def _expect_code(pid, want, note, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == want:
            _record(pid, "HELD", note + " (coded %s)" % (want,))
        else:
            _record(pid, "BREAK",
                    "wrong/uncoded refusal: want %s, got %r (%r)"
                    % (want, code, e))
        return
    _record(pid, "BREAK", note + ": no refusal raised")


# ---------------------------------------------------------------------------
# (a) rebuild_recipe (sasanam-rebuild/1)
# ---------------------------------------------------------------------------

def p_rb_substitution_under_signature():
    """Recipe substitution under a valid signature must fail closed.

    The attacker takes a sealed envelope and swaps the recipe for a
    different one (or mutates a step) without the builder key. The
    signature covers the whole claim, so this must refuse coded
    provenance-signature-invalid -- it is a forgery, not a recipe bug.
    """
    ep, seed, keyid, bid, policy = _provenance_parts()
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    import copy
    tampered = copy.deepcopy(env)
    tampered["provenance"]["rebuild_recipe"]["steps"] = [
        {"op": "concat", "order": ["material/a"]},
        {"op": "sha256"},
    ]
    _expect_code("rb-substitution-under-signature",
                 "provenance-signature-invalid",
                 "recipe swapped under a valid signature refuses",
                 ep.verify_provenance, tampered, policy)


def p_rb_labeled_recipe_cannot_lie():
    """A builder-signed recipe that lies about the artifact digest is
    caught by re-derivation: the claimed digest and the recipe-derived
    digest must BOTH match, and the verifier's own materials decide.

    This probe signs a claim whose recipe honestly derives D1 but whose
    claimed artifact digest is D2 != D1 (a lying builder label). The
    verifier re-derives D1 from its materials and must refuse coded
    provenance-rebuild-mismatch.
    """
    ep, seed, keyid, bid, policy = _provenance_parts()
    recipe = _recipe()
    materials = [{"uri": u, "digest": hashlib.sha256(b).hexdigest(),
                  "completeness": "verified"}
                 for u, b in _MATS.items()]
    lying_digest = "00" * 32
    claim = ep.make_provenance_claim(bid, keyid, lying_digest, materials,
                                     issued_at=1700000000,
                                     rebuild_recipe=recipe)
    env = ep.seal_provenance(claim, seed)
    _expect_code("rb-labeled-recipe-cannot-lie",
                 "provenance-rebuild-mismatch",
                 "lying artifact label caught by re-derivation",
                 ep.verify_provenance, env, policy,
                 require_rebuild=True, material_bytes=dict(_MATS))


def p_rb_material_substitution_fails_closed():
    """Attacker-controlled material bytes cannot fake a rebuild: without
    the true preimage, the derived digest cannot equal the claimed one.
    """
    ep, seed, keyid, bid, policy = _provenance_parts()
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    hostile = {"material/a": b"ATTACKER" * 8, "material/b": b"B" * 48}
    _expect_code("rb-material-substitution-fails-closed",
                 "provenance-rebuild-mismatch",
                 "hostile material bytes fail re-derivation",
                 ep.verify_provenance, env, policy,
                 require_rebuild=True, material_bytes=hostile)


def p_rb_verify_rebuild_no_recipe():
    """verify_rebuild on a claim without a recipe refuses coded
    provenance-rebuild-missing (the demand path is strict, not a
    silent skip)."""
    ep, seed, keyid, bid, policy = _provenance_parts()
    env, _artifact = _claim_sealed(ep, seed, keyid, bid,
                                   recipe=_NO_RECIPE)
    _expect_code("rb-verify-rebuild-no-recipe",
                 "provenance-rebuild-missing",
                 "rebuild demand on recipeless claim refuses",
                 ep.verify_rebuild, env, policy,
                 material_bytes=dict(_MATS))


def p_rb_verify_rebuild_nondict_materials():
    """verify_rebuild with non-dict material bytes refuses coded
    provenance-rebuild-invalid, never an uncoded TypeError."""
    ep, seed, keyid, bid, policy = _provenance_parts()
    env, _artifact = _claim_sealed(ep, seed, keyid, bid)
    _expect_code("rb-verify-rebuild-nondict-materials",
                 "provenance-rebuild-invalid",
                 "non-dict material bytes refuse coded",
                 ep.verify_rebuild, env, policy, material_bytes=None)


def p_rb_execute_unvalidated_keyerror():
    """execute_rebuild is a public seam (no underscore) whose docstring
    claims execution 'trusts nothing and still bounds every operation'.
    On a malformed recipe it indexes recipe["inputs"] directly: a bare
    KeyError (code=None) escapes. F351/F344/F342 class: every public
    seam must refuse coded.
    """
    from gov import evidence_provenance as ep
    for bad in ({}, {"inputs": []}, {"inputs": ["u"], "steps": "x"}):
        try:
            ep.execute_rebuild(bad, {})
        except KeyError:
            _record("rb-execute-unvalidated-keyerror", "BREAK",
                    "execute_rebuild(%r) escapes as KeyError (code=None)"
                    % (bad,))
            return
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) is None:
                _record("rb-execute-unvalidated-keyerror", "BREAK",
                        "execute_rebuild(%r) escapes uncoded: %r"
                        % (bad, e))
                return
    _record("rb-execute-unvalidated-keyerror", "HELD",
            "malformed recipes refuse coded from execute_rebuild")


def p_rb_execute_unvalidated_unknown_op():
    """Sibling of the KeyError probe: an unvalidated recipe whose step
    carries an unknown op silently passes the bytes through unchanged
    (no branch matches, no refusal). The registration gate would have
    refused it coded provenance-rebuild-transform-unknown; the direct
    execution seam does not.
    """
    from gov import evidence_provenance as ep
    recipe = {"recipe_format": "sasanam-rebuild/1",
              "inputs": ["u"],
              "steps": [{"op": "weaponize"}, {"op": "sha256"}]}
    try:
        out = ep.execute_rebuild(recipe, {"u": b"data"})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "provenance-rebuild-transform-unknown":
            _record("rb-execute-unvalidated-unknown-op", "HELD",
                    "unknown op refused coded in direct execution")
        else:
            _record("rb-execute-unvalidated-unknown-op", "BREAK",
                    "unknown op escapes uncoded: %r" % (e,))
        return
    # No refusal: the unknown op was a silent no-op before the hash.
    _record("rb-execute-unvalidated-unknown-op", "BREAK",
            "unknown op silently passes through; output=%r" % (out,))


def p_rb_transform_vocab_expressive():
    """Can concat+slice+prefix+hex launder an arbitrary digest? The
    terminal sha256 is mandatory, so the verifier always hashes the
    pipeline output and compares it to the claimed digest. A recipe that
    discards every input and hashes a 4KB attacker prefix still yields
    a deterministic digest the builder must have committed to in the
    signed claim -- the label cannot lie (see
    rb-labeled-recipe-cannot-lie). Positive control: such a recipe
    registers and verifies honestly.
    """
    ep, seed, keyid, bid, policy = _provenance_parts()
    recipe = {"recipe_format": "sasanam-rebuild/1",
              "inputs": ["material/a"],
              "steps": [{"op": "prefix", "bytes": "ff" * 16},
                        {"op": "sha256"}]}
    artifact = hashlib.sha256(bytes.fromhex("ff" * 16)).hexdigest()
    materials = [{"uri": u, "digest": hashlib.sha256(b).hexdigest(),
                  "completeness": "verified"}
                 for u, b in _MATS.items()]
    claim = ep.make_provenance_claim(bid, keyid, artifact, materials,
                                     issued_at=1700000000,
                                     rebuild_recipe=recipe)
    env = ep.seal_provenance(claim, seed)
    try:
        out = ep.verify_provenance(env, policy, require_rebuild=True,
                                   material_bytes={"material/a": b"A" * 32})
    except Exception as e:  # noqa: BLE001
        _record("rb-transform-vocab-expressive", "BREAK",
                "prefix-discard recipe refused: %r" % (e,))
        return
    if out is True:
        _record("rb-transform-vocab-expressive", "HELD",
                "expressive vocab stays inside the signature envelope; "
                "the label cannot lie about the digest")
    else:
        _record("rb-transform-vocab-expressive", "BREAK",
                "artifact digest mismatch after honest rebuild")


def _log_size(log):
    # TransparencyLog exposes no public entry count; the gate-ordering
    # assertion needs one. Prefer a public accessor when present.
    if hasattr(log, "entries"):
        return len(log.entries())
    return log._size  # test-only introspection of the in-memory log


def p_rb_anchor_gate_refusal_before_sequencing():
    """anchor_bundle_gated: the provenance gate fires AFTER digest
    validation and BEFORE the entry is sequenced. A refused bundle must
    leave NO log entry (refusal-before-sequencing)."""
    from gov import evidence_anchor as ea
    from gov import ed25519
    ep, seed, keyid, bid, policy = _provenance_parts()
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    root = tempfile.mkdtemp(prefix="w291-rb-gate-")
    log = ea.TransparencyLog(root, origin="unit-log.example",
                             signer_keyid="op-1",
                             signer_seed=ed25519.generate_seed())
    before = _log_size(log)
    tampered = dict(_MATS)
    tampered["material/a"] = b"X" * 32
    _expect_code("rb-anchor-gate-refusal-before-sequencing",
                 "provenance-rebuild-mismatch",
                 "gated anchor refuses on re-derivation mismatch",
                 ep.anchor_bundle_gated, log, artifact, env, policy,
                 require_rebuild=True, material_bytes=tampered)
    if _log_size(log) != before:
        _record("rb-anchor-gate-log", "BREAK",
                "refused bundle left a log entry")
    else:
        _record("rb-anchor-gate-log", "HELD",
                "refused bundle left no log entry")


def p_rb_anchor_stale_materials():
    """Stale-verifier scenario: the bundle was anchored honestly, but a
    later verifier re-derives against STALE material bytes. The gate
    must refuse; the stale bytes cannot mint a new anchor for the
    already-sequenced digest.
    """
    from gov import evidence_anchor as ea
    from gov import ed25519
    ep, seed, keyid, bid, policy = _provenance_parts()
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    root = tempfile.mkdtemp(prefix="w291-rb-stale-")
    log = ea.TransparencyLog(root, origin="unit-log.example",
                             signer_keyid="op-1",
                             signer_seed=ed25519.generate_seed())
    receipt = ep.anchor_bundle_gated(log, artifact, env, policy,
                                     require_rebuild=True,
                                     material_bytes=dict(_MATS))
    if receipt.get("bundle_digest") != artifact:
        _record("rb-anchor-stale-materials", "BREAK",
                "honest gated anchor failed")
        return
    n = _log_size(log)
    stale = {"material/a": b"STALE" * 7, "material/b": b"B" * 48}
    _expect_code("rb-anchor-stale-materials",
                 "provenance-rebuild-mismatch",
                 "stale materials cannot re-anchor the bundle",
                 ep.anchor_bundle_gated, log, artifact, env, policy,
                 require_rebuild=True, material_bytes=stale)
    if _log_size(log) != n:
        _record("rb-anchor-stale-log", "BREAK",
                "stale-materials refusal left a log entry")
    else:
        _record("rb-anchor-stale-log", "HELD",
                "log unchanged after stale-materials refusal")


# ---------------------------------------------------------------------------
# (b) runtime_posture producer_id binding
# ---------------------------------------------------------------------------

def p_pp_producer_substitution_is_forgery():
    """Swap producer_id post-signing without the operator key. The
    signature covers the payload, so this must refuse coded
    posture-signature-invalid -- substitution IS a forgery, no bypass.
    """
    import copy
    from gov import runtime_posture as rp
    rec, seed, pub = _posture_parts(producer_id="operator")
    forged = copy.deepcopy(rec)
    forged["payload"]["producer_id"] = "mallory"
    _expect_code("pp-producer-substitution-is-forgery",
                 "posture-signature-invalid",
                 "producer_id swapped post-signing refuses",
                 rp.verify_posture, forged, pub)


def _resign_posture(rp, seed, rec):
    return rp._ed25519.sign(
        bytes(seed),
        rp._sig_structure(rec["protected"], rec["payload"])).hex()


def p_pp_resigned_by_other_key():
    """Re-sign a producer_id-swapped payload with a DIFFERENT operator
    key, then verify against the original key: pubkey mismatch, still
    posture-signature-invalid. There is no key-confusion seam.
    """
    import copy
    from gov import runtime_posture as rp
    from gov import ed25519
    rec, seed, pub = _posture_parts(producer_id="operator")
    other_seed = secrets.token_bytes(32)
    other_pub = ed25519.publickey(other_seed).hex()
    forged = copy.deepcopy(rec)
    forged["payload"]["producer_id"] = "mallory"
    forged["signature"] = _resign_posture(rp, other_seed, forged)
    _expect_code("pp-resigned-by-other-key",
                 "posture-signature-invalid",
                 "re-signed-by-other-key refuses against original key",
                 rp.verify_posture, forged, pub)
    # Sanity: it verifies against the attacker's own key (the record is
    # well-formed, just not from our operator).
    try:
        out = rp.verify_posture(forged, other_pub)
    except Exception as e:  # noqa: BLE001
        _record("pp-resigned-sanity", "BREAK",
                "attacker-signed record refused by attacker key: %r" % (e,))
        return
    if out.get("producer_id") == "mallory":
        _record("pp-resigned-sanity", "HELD",
                "attacker key verifies attacker record (as expected); "
                "trust comes from the pinned key, not the signature")
    else:
        _record("pp-resigned-sanity", "BREAK", "sanity shape wrong")


def p_pp_legacy_record_no_producer():
    """A legacy record without producer_id is refused LOUD
    posture-invalid-shape at verify -- there is no legacy path that
    skips the producer requirement."""
    import copy
    from gov import runtime_posture as rp
    rec, seed, pub = _posture_parts(producer_id="operator")
    legacy = copy.deepcopy(rec)
    del legacy["payload"]["producer_id"]
    # Re-sign so the only defect is the missing producer_id.
    legacy["signature"] = _resign_posture(rp, seed, legacy)
    _expect_code("pp-legacy-record-no-producer",
                 "posture-invalid-shape",
                 "legacy producerless record refuses coded",
                 rp.verify_posture, legacy, pub)


def p_pp_self_endorse_at_verify():
    """Self-sourced endorsement slots refuse at VERIFY time even when
    the record is otherwise well-formed and correctly signed (the
    F350 verify-time independence re-check)."""
    import copy
    from gov import runtime_posture as rp
    rec, seed, pub = _posture_parts(producer_id="operator",
                                    slot_source="log-op")
    # Issuance refuses self-sourced slots, so mutate post-issuance and
    # re-sign: the verify-time independence re-check must still fire.
    rec2 = copy.deepcopy(rec)
    for slot in rec2["payload"]["endorsements"].values():
        slot["source_id"] = "operator"
    rec2["signature"] = _resign_posture(rp, seed, rec2)
    _expect_code("pp-self-endorse-at-verify",
                 "posture-endorsement-not-independent",
                 "self-sourced slot refuses at verify time",
                 rp.verify_posture, rec2, pub)


def p_pp_wrong_length_sig():
    """A well-formed-hex but wrong-length signature reaches ed25519,
    which never raises on malformed inputs: it must refuse coded
    posture-signature-invalid (NOT an uncoded escape)."""
    import copy
    from gov import runtime_posture as rp
    rec, seed, pub = _posture_parts()
    rec2 = copy.deepcopy(rec)
    rec2["signature"] = "ab" * 32  # 32 bytes, valid hex
    _expect_code("pp-wrong-length-sig",
                 "posture-signature-invalid",
                 "wrong-length hex signature refuses coded",
                 rp.verify_posture, rec2, pub)


# ---------------------------------------------------------------------------
# (c) evidence_admission: admit_at_risk error-only API + _REFUSE_REGISTRY
# ---------------------------------------------------------------------------

def p_aa_genuine_error_wrong_scope():
    """Manufacture a GENUINE AdmissionError through a real admit() call
    on attacker-controlled inputs (strict refusal, non-floor check
    fails), then try to use it against an UNRELATED policy scope: the
    exception store grants only ("policy","p2") while the genuine
    refusal is for p1. The registry copy is authoritative, so the scope
    gate must refuse coded admission-exception-refused.
    """
    from gov import evidence_admission as adm
    err = _refuse_err(adm, fails=("provenance-present",))
    if err.code != "admission-refused":
        _record("aa-genuine-error-wrong-scope", "BREAK",
                "fixture: expected admission-refused, got %r" % (err.code,))
        return
    store = _risk_store(adm, "p2")
    _expect_code("aa-genuine-error-wrong-scope",
                 "admission-exception-refused",
                 "genuine p1 refusal unusable under a p2 exception",
                 adm.admit_at_risk, err, store)


def p_aa_genuine_error_honest_use():
    """Positive control: the same genuine error with a live exception
    for its own policy admits at risk (designed behavior, no
    regression)."""
    from gov import evidence_admission as adm
    err = _refuse_err(adm, fails=("provenance-present",))
    store = _risk_store(adm, "p1")
    try:
        rec = adm.admit_at_risk(err, store)
    except Exception as e:  # noqa: BLE001
        _record("aa-genuine-error-honest-use", "BREAK",
                "honest at-risk use refused: %r" % (e,))
        return
    if (rec.get("verdict") == "ADMIT-AT-RISK"
            and rec.get("floor_failed") == []
            and rec.get("refused_decision_digest")):
        _record("aa-genuine-error-honest-use", "HELD",
                "genuine non-floor refusal admits at risk under a live "
                "exception for its own policy")
    else:
        _record("aa-genuine-error-honest-use", "BREAK",
                "at-risk record malformed: %r" % (rec,))


def p_aa_genuine_error_mutated_policy_id():
    """Cross-decision confusion attempt: take the genuine p1 refusal
    and mutate its attached decision's policy_id to "p2" (the error
    object is attacker-held memory). The digest still resolves to the
    registry's pristine p1 copy, so a p2-scoped exception must refuse.
    """
    import copy
    from gov import evidence_admission as adm
    err = _refuse_err(adm, fails=("provenance-present",))
    # AdmissionError is not deepcopy-able (its __init__ takes code);
    # construct a sibling error object carrying the mutated decision.
    mutated = adm.AdmissionError(err.message, code=err.code)
    mutated.decision = copy.deepcopy(err.decision)
    mutated.decision["policy_id"] = "p2"
    store = _risk_store(adm, "p2")
    _expect_code("aa-genuine-error-mutated-policy-id",
                 "admission-exception-refused",
                 "mutated policy_id does not confuse the registry copy",
                 adm.admit_at_risk, mutated, store)


def p_aa_genuine_error_for_floor_failed():
    """A genuine FLOOR-FAILED refusal (manufactured through a real
    admit() with a floor check failing) can never be accepted at risk,
    even with a live exception -- the registry's floor_failed is
    authoritative."""
    from gov import evidence_admission as adm
    err = _refuse_err(adm, fails=("signature-valid",))
    if err.code != "admission-integrity-floor-violated":
        _record("aa-genuine-error-for-floor-failed", "BREAK",
                "fixture: expected floor violation, got %r" % (err.code,))
        return
    store = _risk_store(adm, "p1")
    _expect_code("aa-genuine-error-for-floor-failed",
                 "admission-exception-refused",
                 "genuine floor-failed refusal never admitted at risk",
                 adm.admit_at_risk, err, store)


def p_aa_registry_flood_eviction():
    """Eviction attack: the in-process _REFUSE_REGISTRY is bounded at
    1024 entries (FIFO). Flood it with 1025 fresh genuine refusals so
    the FIRST real refusal evicts, then try admit_at_risk on that first
    error. Eviction must fail CLOSED (admission-exception-refused),
    never fall through to an unregistered acceptance.
    """
    from gov import evidence_admission as adm
    saved = dict(adm._REFUSE_REGISTRY)
    try:
        # The decision digest binds (verdict, policy_id, scope, level,
        # check_results, warnings, floor_failed): varying the policy_id
        # across genuine admit() calls yields distinct digests.
        first_pol = _policy(adm, policy_id="flood-0")
        try:
            adm.admit(_ev(), first_pol,
                      _outcomes(adm, fails=("provenance-present",)))
        except adm.AdmissionError as e:
            first = e
        else:
            _record("aa-registry-flood-eviction", "BREAK",
                    "fixture did not refuse")
            return
        for i in range(1, 1025):
            pol = _policy(adm, policy_id="flood-%d" % i)
            try:
                adm.admit(_ev(), pol,
                          _outcomes(adm, fails=("provenance-present",)))
            except adm.AdmissionError:
                pass
        if len(adm._REFUSE_REGISTRY) != 1024:
            _record("aa-registry-flood-eviction", "ERROR",
                    "registry not at bound: %d" % len(adm._REFUSE_REGISTRY))
            return
        if first.decision["decision_digest"] in adm._REFUSE_REGISTRY:
            _record("aa-registry-flood-eviction", "BREAK",
                    "first refusal NOT evicted after 1025 inserts "
                    "(bound not enforced?)")
            return
        store = _risk_store(adm, "flood-0")
        _expect_code("aa-registry-flood-eviction",
                     "admission-exception-refused",
                     "evicted refusal fails closed",
                     adm.admit_at_risk, first, store)
    finally:
        adm._REFUSE_REGISTRY.clear()
        adm._REFUSE_REGISTRY.update(saved)


def p_aa_unregistered_error_refused():
    """An AdmissionError raised by admit() but never registered (e.g.
    CHECK_FAILED from a missing outcome -- those go through _fail, not
    _refuse_decision) refuses coded admission-exception-refused."""
    from gov import evidence_admission as adm
    pol = _policy(adm)
    outcomes = _outcomes(adm)
    del outcomes["digest-binds"]
    try:
        adm.admit(_ev(), pol, outcomes)
    except adm.AdmissionError as e:
        err = e
    else:
        _record("aa-unregistered-error-refused", "BREAK",
                "missing outcome did not raise")
        return
    if err.code != "admission-check-failed":
        _record("aa-unregistered-error-refused", "BREAK",
                "fixture: expected check-failed, got %r" % (err.code,))
        return
    store = _risk_store(adm, "p1")
    _expect_code("aa-unregistered-error-refused",
                 "admission-exception-refused",
                 "unregistered (non-decision) error refuses at risk",
                 adm.admit_at_risk, err, store)


# ---------------------------------------------------------------------------
# (d) ceremony_binding: shape coverage beyond the keyless payload
# ---------------------------------------------------------------------------

def p_cb_leaf_wrong_typed_keys():
    """ceremony_leaf on a payload whose keys exist but are wrong-typed
    (content_digest as int). _require_record_shape only checks the
    envelope dicts, so the leaf pipeline may mint a leaf for garbage.
    The verify seam refuses such records coded -- the question is
    whether the minting seam anchors garbage.
    """
    from gov import ceremony_binding as cb
    rec = {"ceremony_format": "sasanam-challenge-binding/1",
           "protected": {}, "payload": {"content_digest": 12345,
                                        "challenge_nonce": "ab" * 16,
                                        "challenge_purpose": "appraise"},
           "signature": "00"}
    try:
        leaf = cb.ceremony_leaf(rec)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            _record("cb-leaf-wrong-typed-keys", "HELD",
                    "wrong-typed payload refuses coded %r" % (code,))
        else:
            _record("cb-leaf-wrong-typed-keys", "BREAK",
                    "wrong-typed payload escapes uncoded: %r" % (e,))
        return
    # A leaf minted for garbage: the verify seam must still refuse the
    # record coded, so the garbage leaf is unusable as a ceremony.
    try:
        cb.verify_binding(rec, "ab" * 64)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is not None:
            _record("cb-leaf-wrong-typed-keys", "HELD",
                    "leaf mints for wrong-typed payload (garbage-in), "
                    "but the verify seam refuses coded %r: the garbage "
                    "leaf can never be consumed as a binding"
                    % (getattr(e, "code", None),))
        else:
            _record("cb-leaf-wrong-typed-keys", "BREAK",
                    "verify seam also leaks uncoded on garbage: %r" % (e,))
        return
    _record("cb-leaf-wrong-typed-keys", "BREAK",
            "garbage record VERIFIED: leaf=%r" % (leaf,))


def p_cb_leaf_extra_keys_ignored():
    """Extra payload keys are silently dropped by ceremony_leaf (only
    the three known keys feed the digest). Probe documents the
    behavior: no confusion is possible because the canonical digest is
    injective over the three bound keys, and verify_binding refuses
    the record coded on its own shape/nonce checks.
    """
    from gov import ceremony_binding as cb
    rec, _seed, _pub = _ceremony_parts_for_shape()
    import copy
    clean = copy.deepcopy(rec)
    with_extra = copy.deepcopy(rec)
    with_extra["payload"]["smuggled"] = "attacker-data"
    try:
        leaf_clean = cb.ceremony_leaf(clean)
        leaf_extra = cb.ceremony_leaf(with_extra)
    except Exception as e:  # noqa: BLE001
        _record("cb-leaf-extra-keys-ignored", "BREAK",
                "fixture raised: %r" % (e,))
        return
    if leaf_clean == leaf_extra:
        _record("cb-leaf-extra-keys-ignored", "HELD",
                "extra payload keys are ignored by the leaf digest; the "
                "signed envelope (which binds the full payload) still "
                "distinguishes the records at verify")
    else:
        _record("cb-leaf-extra-keys-ignored", "BREAK",
                "extra keys change the leaf: %r vs %r"
                % (leaf_clean, leaf_extra))


def _ceremony_parts_for_shape():
    from gov import ceremony_binding as cb
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub_hex = ed25519.publickey(seed).hex()
    rec = cb.issue_binding(
        operator_seed=seed, operator_keyid="op1",
        challenge_nonce=secrets.token_bytes(16),
        challenge_purpose="appraise",
        content_digest=secrets.token_bytes(32).hex())
    return rec, seed, pub_hex


# ---------------------------------------------------------------------------
# (e) Cross-module chains
# ---------------------------------------------------------------------------

def p_xm_floor_fail_rebuild_demand():
    """Chain: a floor-failed admission must not become a rebuild demand
    bypass. The floor-failed envelope refuses at admission, refuses at
    risk, and verify_provenance(require_rebuild=True) still independently
    re-derives (rebuild verification is not admission-gated, and
    admission failure is not rebuild-gated -- the two gates compose).
    """
    from gov import evidence_admission as adm
    ep, seed, keyid, bid, policy = _provenance_parts()
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    # 1. Floor-failed admission refuses.
    adm_pol = _policy(adm)
    try:
        adm.admit({"kind": "provenance", "artifact_digest": artifact},
                  adm_pol, _outcomes(adm, fails=("signature-valid",)))
    except adm.AdmissionError as e:
        if e.code != "admission-integrity-floor-violated":
            _record("xm-floor-fail-rebuild-demand", "BREAK",
                    "floor did not fire: %r" % (e.code,))
            return
        floor_err = e
    else:
        _record("xm-floor-fail-rebuild-demand", "BREAK",
                "floor failure admitted")
        return
    # 2. No at-risk escape.
    store = _risk_store(adm, "p1")
    try:
        adm.admit_at_risk(floor_err, store)
    except adm.AdmissionError as e2:
        if e2.code != "admission-exception-refused":
            _record("xm-floor-fail-rebuild-demand", "BREAK",
                    "wrong code: %r" % (e2.code,))
            return
    else:
        _record("xm-floor-fail-rebuild-demand", "BREAK",
                "floor-failed envelope admitted at risk")
        return
    # 3. The rebuild demand still verifies independently (the envelope
    #    itself is honestly built; admission and rebuild are separate
    #    gates that compose rather than bypass each other).
    try:
        out = ep.verify_provenance(env, policy, require_rebuild=True,
                                   material_bytes=dict(_MATS))
    except Exception as e:  # noqa: BLE001
        _record("xm-floor-fail-rebuild-demand", "BREAK",
                "honest rebuild demand refused: %r" % (e,))
        return
    if out is True:
        _record("xm-floor-fail-rebuild-demand", "HELD",
                "floor-failed admission refuses at both gates; the "
                "rebuild demand verifies independently -- no chain "
                "bypass")
    else:
        _record("xm-floor-fail-rebuild-demand", "BREAK",
                "rebuild demand returned wrong digest")


def p_xm_verify_posture_after_admit():
    """A posture record appraised from an admitted envelope binds the
    operator-named producer; a floor-failed envelope never reaches the
    posture seam in this chain (admission refuses first). Documents that
    verify_posture's producer check is independent of admission.
    """
    from gov import evidence_admission as adm
    from gov import runtime_posture as rp
    rec, seed, pub = _posture_parts(producer_id="operator")
    try:
        out = rp.verify_posture(rec, pub)
    except Exception as e:  # noqa: BLE001
        _record("xm-verify-posture-after-admit", "BREAK",
                "honest posture refused: %r" % (e,))
        return
    if out.get("producer_id") != "operator":
        _record("xm-verify-posture-after-admit", "BREAK",
                "producer_id lost in verify")
        return
    # The floor-failed envelope cannot even get here in a correct
    # pipeline: admission refuses before any posture is minted.
    adm_pol = _policy(adm)
    try:
        adm.admit(_ev(), adm_pol, _outcomes(adm, fails=("digest-binds",)))
    except adm.AdmissionError as e:
        if e.code == "admission-integrity-floor-violated":
            _record("xm-verify-posture-after-admit", "HELD",
                    "posture verify binds producer_id independently; "
                    "floor-failed evidence refuses at admission before "
                    "any posture seam")
            return
    _record("xm-verify-posture-after-admit", "BREAK",
            "floor failure did not refuse at admission")


# ---------------------------------------------------------------------------
# Re-pins (subprocess; depth-1 green)
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w291-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=900,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("repin-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("repin-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("repin-" + label, "BREAK",
                "%s: %d BREAK, expected %d"
                % (rel, nbreak, expected_breaks))


def p_repins():
    # F352-F355 OPEN at base: 6 probe-level BREAKs expected.
    # Wave-291 merge re-pin: F352-F355 ALL closed -> 0 BREAK.
    _run_battery("evals/w290_redteam_probes.py", 0, "w290")
    # F311-F351 CLOSED: 0 BREAK expected.
    _run_battery("evals/w289_redteam_probes.py", 0, "w289")
    _run_battery("evals/w290_rebuild_probes.py", 0, "w290-rebuild")
    _run_battery("evals/w290_f348_f349_probes.py", 0, "w290-f348f349")


def _green_checks():
    if SKIP_GREEN:
        return
    for rel in ("evals/w287_tsa_probes.py",
                "evals/w285_tessera_probes.py"):
        _run_battery(rel, 0, "green-" + os.path.basename(rel)[:-3])


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    # (a) rebuild_recipe
    _safe("rb-substitution-under-signature",
          p_rb_substitution_under_signature)
    _safe("rb-labeled-recipe-cannot-lie", p_rb_labeled_recipe_cannot_lie)
    _safe("rb-material-substitution-fails-closed",
          p_rb_material_substitution_fails_closed)
    _safe("rb-verify-rebuild-no-recipe", p_rb_verify_rebuild_no_recipe)
    _safe("rb-verify-rebuild-nondict-materials",
          p_rb_verify_rebuild_nondict_materials)
    _safe("rb-execute-unvalidated-keyerror",
          p_rb_execute_unvalidated_keyerror)
    _safe("rb-execute-unvalidated-unknown-op",
          p_rb_execute_unvalidated_unknown_op)
    _safe("rb-transform-vocab-expressive", p_rb_transform_vocab_expressive)
    _safe("rb-anchor-gate-refusal-before-sequencing",
          p_rb_anchor_gate_refusal_before_sequencing)
    _safe("rb-anchor-stale-materials", p_rb_anchor_stale_materials)
    # (b) producer_id
    _safe("pp-producer-substitution-is-forgery",
          p_pp_producer_substitution_is_forgery)
    _safe("pp-resigned-by-other-key", p_pp_resigned_by_other_key)
    _safe("pp-legacy-record-no-producer", p_pp_legacy_record_no_producer)
    _safe("pp-self-endorse-at-verify", p_pp_self_endorse_at_verify)
    _safe("pp-wrong-length-sig", p_pp_wrong_length_sig)
    # (c) admission
    _safe("aa-genuine-error-wrong-scope", p_aa_genuine_error_wrong_scope)
    _safe("aa-genuine-error-honest-use", p_aa_genuine_error_honest_use)
    _safe("aa-genuine-error-mutated-policy-id",
          p_aa_genuine_error_mutated_policy_id)
    _safe("aa-genuine-error-for-floor-failed",
          p_aa_genuine_error_for_floor_failed)
    _safe("aa-registry-flood-eviction", p_aa_registry_flood_eviction)
    _safe("aa-unregistered-error-refused", p_aa_unregistered_error_refused)
    # (d) ceremony shape
    _safe("cb-leaf-wrong-typed-keys", p_cb_leaf_wrong_typed_keys)
    _safe("cb-leaf-extra-keys-ignored", p_cb_leaf_extra_keys_ignored)
    # (e) cross-module
    _safe("xm-floor-fail-rebuild-demand", p_xm_floor_fail_rebuild_demand)
    _safe("xm-verify-posture-after-admit", p_xm_verify_posture_after_admit)
    _safe("repin-w290", p_repins)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w291_redteam: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
