"""Wave-290 independent red-team battery: attack the wave-289 merge.

Base: wave-289 push eb08e95ae9eb6862d689f9eede5489d0177a5ceb
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (all wave-289 additions and residual seams):
  (a) gov/ceremony_binding.py -- challenge envelope (nonce>=64b +
      purpose) bound into the signed artifact, ceremony_leaf anchor
      composition, cross-ceremony replay/anchor-substitution, the
      63-bit boundary, TSA freshness by reference.
  (b) gov/evidence_admission.py -- trust ladder, integrity floor
      non-overridability (F348/F349 OPEN), per-check overrides,
      admit_at_risk floor gate, pin_admission_policy HMAC, pin-store
      loading.
  (c) gov/runtime_posture.py -- endorsement slots at verify time
      (F350 OPEN), producer_id binding, eat_nonce discipline, tsa_token
      freshness, as_appraisal_evidence seam (F351b/c OPEN).
  (d) gov/trust_vector.py -- trusted_producers rename fallout
      (F343 closed), old-field coded refusal, _canonical funnel
      coverage (F344 closed), cross-module self-endorsement via the
      appraisal seam.
  (e) gov/evidence_provenance.py -- _emit sink isolation semantics
      (F345 closed): swallowed where, recorded where, does a failing
      sink change the verification outcome?

Re-pins at the public seams:
  F311-F345 (CLOSED) -- 0 BREAK expected.
  F346-F351 (OPEN at base) -- 9 BREAK expected-open (6 findings; F351
  has 4 sub-probes).

New findings filed (all LOW, OPEN): F352-F355.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g290-redteam && TMPDIR=/var/tmp/g290-redteam \\
    ~/workspace/.gov-venv/bin/python evals/w290_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g290-redteam2 \\
    ~/workspace/.gov-venv/bin/python evals/w290_redteam_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*).
TAXONOMY_PIN = 1995 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
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
    _record("pin-taxonomy", "HELD", "1995/1995/0 sorted")


# ---------------------------------------------------------------------------
# Re-pins (subprocess, depth-1, GOV_SKIP_GREEN=1, fresh TMPDIRs).
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # (battery, expected_breaks, label)
    # Merge composition (wave-290): F311-F351 ALL CLOSED on the composed
    # tree, so w289_redteam runs 0 BREAK here (was 9 at base: 6 findings,
    # F351 with 4 sub-probes).
    ("evals/w289_redteam_probes.py", 0, "f311-351"),
    # Wave-289 closure lanes: 0 BREAK on the composed tree.
    ("evals/w288_f343_probes.py", 0, "f343-closed"),
    ("evals/w289_f344_f345_probes.py", 0, "f344-345-closed"),
    ("evals/w289_ceremony_probes.py", 0, "ceremony-green"),
    ("evals/w288_admission_probes.py", 0, "admission-green"),
    ("evals/w288_eat_probes.py", 0, "eat-green"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w290-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=1200,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("repin-" + label, "ERROR", "subprocess failed: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # Wave-286 lesson: take the LAST "N BREAK" match (the footer),
        # not per-probe notes.
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak == expected_breaks:
            _record("repin-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("repin-" + label, "BREAK",
                    "%s: %d BREAK, expected %d"
                    % (rel, nbreak, expected_breaks))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _ceremony_parts(nonce=None, purpose="appraise"):
    from gov import ceremony_binding as cb
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    rec = cb.issue_binding(
        operator_seed=seed, operator_keyid="op1",
        challenge_nonce=nonce or secrets.token_bytes(16),
        challenge_purpose=purpose,
        content_digest=secrets.token_bytes(32).hex())
    return rec, seed, pub


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


def _admission_policy(**kw):
    from gov import evidence_admission as adm
    doc = {"format": "admission-policy/1", "policy_id": "p1",
           "scopes": [{"scope": "provenance", "level": "strict"}]}
    doc.update(kw)
    return adm.compile_policy(doc)


# ---------------------------------------------------------------------------
# F352 (LOW): audit-sink failures propagate uncoded out of
# ceremony_binding. Same defect class as F345/F346/F347 (filed against
# evidence_provenance, runtime_posture, evidence_receipt). _emit_event
# calls the installed sink without isolation: a raising sink escapes
# issue_binding as the sink's own exception type (code=None).
# ---------------------------------------------------------------------------

def p_f352_ceremony_sink_uncoded():
    from gov import ceremony_binding as cb

    def boom(event):
        raise RuntimeError("sink exploded")

    cb.set_emit(boom)
    try:
        seed = secrets.token_bytes(32)
        try:
            cb.issue_binding(
                operator_seed=seed, operator_keyid="op1",
                challenge_nonce=secrets.token_bytes(16),
                challenge_purpose="appraise",
                content_digest="ab" * 32)
        except RuntimeError:
            return _record("f352-ceremony-sink", "BREAK",
                           "raising sink escapes issue_binding as "
                           "RuntimeError (code=None)")
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", None)
            if code is not None:
                return _record("f352-ceremony-sink", "HELD",
                               "sink failure isolated, coded %r" % (code,))
            return _record("f352-ceremony-sink", "BREAK",
                           "sink failure escapes uncoded: %r" % (e,))
        return _record("f352-ceremony-sink", "HELD",
                       "no exception from a raising sink")
    finally:
        cb.set_emit(None)


def p_f352_sink_ok():
    """Positive control: a healthy sink sees the binding-issued event."""
    from gov import ceremony_binding as cb
    seen = []
    cb.set_emit(seen.append)
    try:
        rec, seed, pub = _ceremony_parts()
    finally:
        cb.set_emit(None)
    if seen and seen[0].get("event") == "binding-issued" \
            and seen[0].get("purpose") == "appraise":
        return _record("f352-sink-ok", "HELD",
                       "healthy sink receives binding-issued event")
    _record("f352-sink-ok", "BREAK", "sink saw nothing or payload wrong")


# ---------------------------------------------------------------------------
# F353 (LOW): ceremony_leaf (public seam) raises uncoded KeyError on a
# shape-valid but keyless payload. _require_record_shape passes (format
# matches, protected/payload are dicts, signature non-empty), then
# payload["content_digest"] raises KeyError with code=None.
# anchor_binding hits the same path (it calls ceremony_leaf first).
# F351/F342/F344 class: all-refusals-coded contract.
# ---------------------------------------------------------------------------

def p_f353_ceremony_leaf_keyerror():
    from gov import ceremony_binding as cb
    rec = {"ceremony_format": "sasanam-challenge-binding/1",
           "protected": {}, "payload": {}, "signature": "00"}
    try:
        cb.ceremony_leaf(rec)
    except KeyError:
        return _record("f353-ceremony-leaf", "BREAK",
                       "keyless payload escapes ceremony_leaf as "
                       "KeyError (code=None)")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f353-ceremony-leaf", "HELD",
                           "keyless payload refused coded %r" % (code,))
        return _record("f353-ceremony-leaf", "BREAK",
                       "keyless payload escapes uncoded: %r" % (e,))
    _record("f353-ceremony-leaf", "BREAK",
            "keyless payload produced a leaf (unexpected)")


def p_f353_anchor_binding_keyerror():
    from gov import ceremony_binding as cb
    from gov import evidence_anchor as ea
    d = tempfile.mkdtemp(prefix="w290-f353-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w290f353", signer_keyid="op1",
                             signer_seed=seed)
    rec = {"ceremony_format": "sasanam-challenge-binding/1",
           "protected": {}, "payload": {}, "signature": "00"}
    try:
        cb.anchor_binding(log, rec)
    except KeyError:
        return _record("f353-anchor-binding", "BREAK",
                       "keyless payload escapes anchor_binding as "
                       "KeyError (code=None)")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f353-anchor-binding", "HELD",
                           "keyless payload refused coded %r" % (code,))
        return _record("f353-anchor-binding", "BREAK",
                       "keyless payload escapes uncoded: %r" % (e,))
    _record("f353-anchor-binding", "BREAK",
            "keyless payload anchored (unexpected)")


def p_f353_leaf_ok():
    """Positive control: a well-formed record yields a stable leaf."""
    from gov import ceremony_binding as cb
    rec, seed, pub = _ceremony_parts()
    leaf1 = cb.ceremony_leaf(rec)
    leaf2 = cb.ceremony_leaf(rec)
    if leaf1 == leaf2 and len(leaf1) == 64:
        return _record("f353-leaf-ok", "HELD",
                       "well-formed record leafs deterministically")
    _record("f353-leaf-ok", "BREAK", "leaf unstable")


# ---------------------------------------------------------------------------
# F354 (LOW): load_admission_pins raises uncoded JSONDecodeError on a
# malformed pin file. The corrupt-store path refuses coded
# admission-policy-invalid, but the parse failure escapes raw
# (JSONDecodeError subclasses ValueError, code=None). F351 class.
# ---------------------------------------------------------------------------

def p_f354_pinfile_malformed():
    from gov import evidence_admission as adm
    d = tempfile.mkdtemp(prefix="w290-f354-")
    path = os.path.join(d, "pins.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    try:
        adm.load_admission_pins(path)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f354-pinfile", "HELD",
                           "malformed pin file refused coded %r" % (code,))
        return _record("f354-pinfile", "BREAK",
                       "malformed pin file escapes as %s (code=None)"
                       % type(e).__name__)
    _record("f354-pinfile", "BREAK", "malformed pin file loaded silently")


def p_f354_pinfile_ok():
    """Positive control: corrupt (non-dict) store refuses coded."""
    from gov import evidence_admission as adm
    d = tempfile.mkdtemp(prefix="w290-f354b-")
    path = os.path.join(d, "pins.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("[1, 2, 3]")
    try:
        adm.load_admission_pins(path)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "admission-policy-invalid":
            return _record("f354-pinfile-ok", "HELD",
                           "non-dict pin store refused coded")
        return _record("f354-pinfile-ok", "BREAK",
                       "non-dict pin store: %r code=%r" % (e, code))
    _record("f354-pinfile-ok", "BREAK", "non-dict pin store loaded")


# ---------------------------------------------------------------------------
# F355 (LOW): non-hex signature strings escape uncoded (ValueError,
# code=None) from the verify paths of ceremony_binding.verify_binding
# and runtime_posture.verify_posture. _require_record_shape only checks
# the signature is a non-empty str; bytes.fromhex then raises raw.
# F351/F342/F344 class. A forged but well-formed hex signature still
# refuses CODED (positive control).
# ---------------------------------------------------------------------------

def p_f355a_ceremony_nonhex_sig():
    from gov import ceremony_binding as cb
    rec = {"ceremony_format": "sasanam-challenge-binding/1",
           "protected": {"a": 1},
           "payload": {"challenge_nonce": "ab" * 16,
                       "challenge_purpose": "x",
                       "content_digest": "cd" * 32},
           "signature": "not-hex!!"}
    try:
        cb.verify_binding(rec, "ef" * 32)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f355a-ceremony-sig", "HELD",
                           "non-hex signature refused coded %r" % (code,))
        return _record("f355a-ceremony-sig", "BREAK",
                       "non-hex signature escapes as %s (code=None)"
                       % type(e).__name__)
    _record("f355a-ceremony-sig", "BREAK",
            "non-hex signature verified (unexpected)")


def p_f355b_posture_nonhex_sig():
    from gov import runtime_posture as rp
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": "s"}
    rec = {"posture_format": "sasanam-runtime-posture/1",
           "protected": {"a": 1},
           "payload": {"eat_nonce": "ab" * 16,
                       "submods": {"s": {"digest": "cd" * 32}},
                       "software_id": "x", "config_digest": "cd" * 32,
                       "endorsements": {c: dict(slot) for c in
                                        ("software_id", "config_digest",
                                         "submods")}},
           "signature": "not-hex!!"}
    try:
        rp.verify_posture(rec, "ef" * 32)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is not None:
            return _record("f355b-posture-sig", "HELD",
                           "non-hex signature refused coded %r" % (code,))
        return _record("f355b-posture-sig", "BREAK",
                       "non-hex signature escapes as %s (code=None)"
                       % type(e).__name__)
    _record("f355b-posture-sig", "BREAK",
            "non-hex signature verified (unexpected)")


def p_f355_forged_ok():
    """Positive control: a forged (well-formed hex) signature refuses
    CODED on both verify paths."""
    from gov import ceremony_binding as cb
    from gov import runtime_posture as rp
    rec, seed, pub = _ceremony_parts()
    rec["signature"] = "00" * 64
    try:
        cb.verify_binding(rec, pub)
        _record("f355-forged-ok", "BREAK", "forged ceremony verified")
        return
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "challenge-signature-invalid":
            _record("f355-forged-ok", "BREAK",
                    "forged ceremony refused with wrong code %r"
                    % (getattr(e, "code", None),))
            return
    prec, pseed, ppub = _posture_parts()
    prec["signature"] = "00" * 64
    try:
        rp.verify_posture(prec, ppub)
        _record("f355-forged-ok", "BREAK", "forged posture verified")
        return
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "posture-signature-invalid":
            _record("f355-forged-ok", "BREAK",
                    "forged posture refused with wrong code %r"
                    % (getattr(e, "code", None),))
            return
    _record("f355-forged-ok", "HELD",
            "forged signatures refuse coded on both paths")


# ---------------------------------------------------------------------------
# Cross-cutting pressure probes (expected HELD; would become findings if
# they ever BREAK).
# ---------------------------------------------------------------------------

def p_trustvec_old_field_refused():
    """F343 rename fallout: the old trust_anchors field refuses LOUD."""
    from gov import trust_vector as tv
    # The "runtime-posture/v1" scheme registers at runtime_posture
    # import time; ensure it is registered before compile_policy.
    import gov.runtime_posture  # noqa: F401
    doc = {"format": "appraisal-policy/1", "policy_id": "p1",
           "scheme_id": "runtime-posture/v1",
           "trust_anchors": {"mallory": "keyid-1"}}
    try:
        tv.compile_policy(doc)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "trustvec-policy-invalid":
            return _record("x-old-field", "HELD",
                           "trust_anchors refused coded "
                           "trustvec-policy-invalid")
        return _record("x-old-field", "BREAK",
                       "trust_anchors refused with wrong code %r"
                       % (getattr(e, "code", None),))
    _record("x-old-field", "BREAK", "trust_anchors accepted silently")


def p_trustvec_funnel_coverage():
    """F344 funnel: frozenset / custom object / set all refuse coded;
    tuples stay JSON-serializable (deterministic)."""
    from gov import trust_vector as tv
    bad = [frozenset({1, 2}), {"a", "b"}, object()]
    for i, v in enumerate(bad):
        try:
            tv._digest_value(v)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) != "trustvec-evidence-invalid":
                return _record("x-funnel", "BREAK",
                               "value %d refused with wrong code %r"
                               % (i, getattr(e, "code", None)))
            continue
        return _record("x-funnel", "BREAK",
                       "non-JSON value %d digested silently" % (i,))
    d1 = tv._digest_value((1, 2))
    d2 = tv._digest_value([1, 2])
    if d1 != d2:
        return _record("x-funnel", "BREAK", "tuple/list digest mismatch")
    _record("x-funnel", "HELD",
            "non-JSON refused coded; tuple==list deterministic")


def p_provenance_sink_isolation():
    """F345-fix semantics: a raising sink must not change the
    verification outcome, and verification works identically with no
    sink, a healthy sink, and a broken sink. The failure is swallowed
    inside _emit (recorded in the docstring trade-off, not the event
    stream) -- the check here is that the outcome never changes."""
    from gov import evidence_provenance as ep
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    pol = ep.BuilderPolicy("w290pol", {"b1": pub})
    digest = "ab" * 32
    claim = ep.make_provenance_claim(
        "b1", "k1", digest,
        [{"uri": "u", "digest": digest, "completeness": "verified"}])
    envelope = ep.seal_provenance(claim, seed)

    def boom(event):
        raise RuntimeError("sink exploded")

    outs = {}
    for label, sink in (("none", None), ("ok", lambda e: None),
                        ("boom", boom)):
        ep.set_emit(sink)
        try:
            try:
                r = ep.verify_provenance(envelope, pol)
                outs[label] = ("ok", r)
            except Exception as e:  # noqa: BLE001
                outs[label] = ("raise", type(e).__name__,
                               getattr(e, "code", None))
        finally:
            ep.set_emit(None)
    if outs["none"] == outs["ok"] == outs["boom"] == ("ok", True):
        return _record("x-sink-isolation", "HELD",
                       "sink state does not change the outcome: True "
                       "under none/healthy/broken sinks")
    _record("x-sink-isolation", "BREAK",
            "sink changes verification outcome: %r" % (outs,))


def _f350_handcrafted_record():
    """Hand-craft a self-endorsed posture record signed by the operator
    key -- the F350 attack shape (minting it requires the operator
    seed; issue_posture itself refuses self-sourced slots)."""
    from gov import runtime_posture as rp
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed).hex()
    slot = {"log_id": "L", "log_index": 0, "expected_digest": "ef" * 32,
            "source_id": "mallory"}
    protected = {"alg": "EdDSA", "kid": "op1",
                 "posture_format": rp.POSTURE_FORMAT}
    payload = {"v": 1, "eat_nonce": secrets.token_bytes(16).hex(),
               "submods": {"sbx": {"digest": "ab" * 32}},
               "software_id": "agent/1.0", "config_digest": "cd" * 32,
               "endorsements": {c: dict(slot) for c in
                                ("software_id", "config_digest",
                                 "submods")}}
    sig = ed25519.sign(bytes(seed),
                       rp._sig_structure(protected, payload)).hex()
    record = {"posture_format": rp.POSTURE_FORMAT, "protected": protected,
              "payload": payload, "signature": sig}
    return record, pub


def p_self_endorse_cross_module():
    """Cross-module: does F350's self-endorsed posture become an
    appraisal bypass through the trust_vector seam? endorse() refuses
    source_id == evidence.producer_id, so the answer turns on the
    producer_id the DEPLOYMENT passes to submit_evidence -- the record
    does not bind its producer (F350's core). Minting the record at
    all requires the operator key, so this is F350's consequence, not
    a new defect: no escalation beyond operator-key compromise."""
    from gov import runtime_posture as rp
    from gov import trust_vector as tv
    record, pub = _f350_handcrafted_record()
    # F350 re-verified first: the hand-crafted record verifies.
    try:
        rp.verify_posture(record, pub)
    except Exception as e:  # noqa: BLE001
        return _record("x-cross-endorse", "HELD",
                       "hand-crafted self-endorsed record refused: %r"
                       % (getattr(e, "code", type(e).__name__),))
    claim_digest, scheme_id, slots = rp.as_appraisal_evidence(
        record, "mallory")
    claims = {"posture_digest": claim_digest,
              "software_id": "agent/1.0",
              "config_digest": "cd" * 32,
              "submods_digest": "ab" * 32}
    # Honest deployment names the true producer: independence holds.
    ev = tv.submit_evidence(scheme_id, claims, "mallory")
    try:
        tv.endorse(ev, "software_id", "agent/1.0", "mallory")
        return _record("x-cross-endorse", "BREAK",
                       "self-endorsement accepted at endorse() with "
                       "matching producer")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "trustvec-endorsement-not-independent":
            return _record("x-cross-endorse", "BREAK",
                           "wrong refusal code %r"
                           % (getattr(e, "code", None),))
    # The residual F350 consequence: with a deployment-misnamed
    # producer the appraisal cannot recover the true producer from
    # the record -- but minting required the operator key either way.
    _record("x-cross-endorse", "HELD",
            "F350 verifies; appraisal independence holds when the "
            "deployment names the true producer (endorse refuses); "
            "the record binds no producer, so a misnamed producer "
            "is deployment error under operator-key compromise "
            "-- F350's consequence, not a new defect")


def p_ceremony_replay_refused():
    """Ceremony discipline: a binding minted for challenge X refuses
    verification under challenge Y (coded), and under purpose Z."""
    from gov import ceremony_binding as cb
    nonce_x = secrets.token_bytes(16)
    rec, seed, pub = _ceremony_parts(nonce=nonce_x, purpose="appraise")
    try:
        cb.verify_binding(rec, pub, expected_nonce=secrets.token_bytes(16),
                          expected_purpose="appraise")
        return _record("x-replay", "BREAK", "cross-challenge replay verified")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "challenge-nonce-mismatch":
            return _record("x-replay", "BREAK",
                           "wrong code %r" % (getattr(e, "code", None),))
    try:
        cb.verify_binding(rec, pub, expected_nonce=nonce_x,
                          expected_purpose="deploy")
        return _record("x-replay", "BREAK", "purpose confusion verified")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "challenge-purpose-mismatch":
            return _record("x-replay", "BREAK",
                           "wrong code %r" % (getattr(e, "code", None),))
    _record("x-replay", "HELD",
            "cross-challenge replay and purpose confusion refuse coded")


def p_ceremony_63bit_refused():
    """63-bit nonce refuses at issuance; 64-bit issues."""
    from gov import ceremony_binding as cb
    seed = secrets.token_bytes(32)
    try:
        cb.issue_binding(operator_seed=seed, operator_keyid="op1",
                         challenge_nonce=secrets.token_bytes(7),
                         challenge_purpose="appraise",
                         content_digest="ab" * 32)
        return _record("x-63bit", "BREAK", "63-bit nonce minted")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "challenge-nonce-invalid":
            return _record("x-63bit", "BREAK",
                           "wrong code %r" % (getattr(e, "code", None),))
    rec, _, _ = _ceremony_parts(nonce=secrets.token_bytes(8))
    if rec["payload"]["challenge_nonce"]:
        return _record("x-63bit", "HELD",
                       "63-bit refused coded; 64-bit issues")
    _record("x-63bit", "BREAK", "64-bit issue malformed")


# ---------------------------------------------------------------------------
# Green checks (depth-1; skipped when GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w287_tsa_probes.py",
        "evals/w287_ear_probes.py",
        "evals/w285_tessera_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w290-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    _safe("pin", p_taxonomy_pin)
    _safe("repins", _run_repins)
    _safe("f352", p_f352_ceremony_sink_uncoded)
    _safe("f352-ok", p_f352_sink_ok)
    _safe("f353", p_f353_ceremony_leaf_keyerror)
    _safe("f353b", p_f353_anchor_binding_keyerror)
    _safe("f353-ok", p_f353_leaf_ok)
    _safe("f354", p_f354_pinfile_malformed)
    _safe("f354-ok", p_f354_pinfile_ok)
    _safe("f355a", p_f355a_ceremony_nonhex_sig)
    _safe("f355b", p_f355b_posture_nonhex_sig)
    _safe("f355-ok", p_f355_forged_ok)
    _safe("x-old-field", p_trustvec_old_field_refused)
    _safe("x-funnel", p_trustvec_funnel_coverage)
    _safe("x-sink", p_provenance_sink_isolation)
    _safe("x-cross", p_self_endorse_cross_module)
    _safe("x-replay", p_ceremony_replay_refused)
    _safe("x-63bit", p_ceremony_63bit_refused)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w290_redteam: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
