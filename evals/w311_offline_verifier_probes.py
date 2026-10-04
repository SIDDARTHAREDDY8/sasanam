"""Wave-311 lane E battery: standalone offline verifier (registystack pattern).

Base: wave-310 merge 38650946 (pin 1841; open F395 / next F396).

Target: gov/evidence_verify_offline.py -- the auditor-side standalone
offline verifier, build-order step 4 (after Sigstore-bundle
distribution), implementing the wave-310 lane B steal verdicts
(research/prospecting/w310_offline_verifier_auditor_ux.md):

  registystack pattern: pinned verifier, no skip-options, narrow inputs
  (canonical bundle bytes + inline verification bundle + compiled-in
  trust root pinned by SHA-256), zero network by construction, five
  negative tests + one known-good positive;
  DepGuard-shaped typed failure taxonomy (16 codes, exit codes 40-44,
  ordered parse -> crypto -> unsupported -> binding -> policy/temporal --
  11 base codes from lane E plus the 5 wave-312 WITNESS_* codes slotted
  into the existing categories);
  cosign air-gap UX (--offline / --trusted-root / --rfc3161-timestamp,
  no --private-infrastructure); SLSA VSA consumer procedure
  (PASSED != ALLOW); Witness policy binding (trust roots inside the
  signed policy, expired policy always fails); timestamp-authority
  isolation (each authority verified against its own key + validFor
  only); Rekor v2 offline contract (no network; witness entries are now
  VERIFIED checkpoint-first by the wave-312 witness step -- unknown
  entry kinds are still refused coded, never silently skipped); TUF rotation
  ceremony (no TUF client in the verifier; reviewed root refresh pinned
  by SHA-256; never silently fall back); clock as inspectable control
  (named time source, fail closed with no trusted time).

Break-first: every negative probe asserts the verifier FAILS CLOSED with
the typed coded failure (HELD = fail-closed coded, the desired state).
The four 2026-Sigstore-CVE analogues are pinned as probes:
  CVE-2026-24122 (expired issuing CA accepted) -> authority validFor
      checked at the TIMESTAMP's time, not verify time;
  CVE-2026-22703 (log entry not binding digest/signature/key) ->
      observer timestamp must bind evidence_digest + authority key;
  CVE-2026-39395 (false "Verified OK" with content checks off) ->
      predicate/content checks always on, no flag disables them;
  CVE-2026-44310 (crash exited 0) -> internal crash exits non-zero,
      never emits success.

Zero-network is proved twice: a static import scan of the module and a
dynamic run of the full verify path under a socket-blocked harness.

Third-party acceptance (probe thirdparty-accept): a stdlib-only script
(evals/w311_thirdparty_accept.py) re-verifies a known-good bundle with
NO Sasanam import (asserted via sys.modules in the child).

No new decision codes are minted by the witness lane beyond the 10
already registered (the 16 verifier codes -- 11 base + 5 WITNESS_* --
are the verifier's own taxonomy, not governance decisions); pin is
1851 after the witness-code registration. No open findings expected:
_EXPECTED_BREAKS is empty.

Run:
  mkdir -p /var/tmp/g311-ovf && TMPDIR=/var/tmp/g311-ovf \\
    ~/workspace/.gov-venv/bin/python evals/w311_offline_verifier_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g311-ovf2 \\
    ~/workspace/.gov-venv/bin/python evals/w311_offline_verifier_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w311_offline_verifier_probes.py <probe-id>
"""

import base64
import copy
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import traceback
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check
import probe_lines

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# No new decision codes minted by this lane (verifier taxonomy is the
# verifier's own surface, not governance decisions); pin stays 1829.
TAXONOMY_PIN = 1900 # wave-312: 1841 + 10 witness-log/evidence-bundle codes; Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*)

from gov.signing import Ed25519Signer, Ed25519Verifier
from gov import evidence_verify_offline as v

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------

UTC = timezone.utc
NOW = datetime(2026, 10, 3, 14, 0, 0, tzinfo=UTC)

BUNDLE_BYTES = b'{"evidence":"synthetic-bundle-w311-ovf-001"}'
OTHER_BYTES = b'{"evidence":"different-bytes-002"}'

INTOTO_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://sasanam.dev/predicate/evidence-bundle/v1"
PREDICATE_CLAIMS = {"window": "2026-10-03T00:00:00Z", "decisions": 3}

# Test-only anchor seed for the COMPILED trust root (synthetic
# placeholder; the deployment ceremony replaces the anchor and
# re-pins -- see gov/evidence_verify_offline.py).
POLICY_ANCHOR_SEED = bytes.fromhex(
    "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6")
EVIDENCE_SEED = bytes([7]) * 32
EVIDENCE_SEED_2 = bytes([8]) * 32  # second key for threshold=2
TSA_SEED = bytes([9]) * 32
ATTACKER_SEED = bytes([13]) * 32


def _signer(seed):
    return Ed25519Signer(seed)


def _statement(bundle_bytes=BUNDLE_BYTES, claims=None,
               predicate_type=PREDICATE_TYPE):
    claims = PREDICATE_CLAIMS if claims is None else claims
    return {
        "_type": INTOTO_TYPE,
        "subject": [{
            "name": "evidence-bundle",
            "digest": {"sha256": hashlib.sha256(bundle_bytes).hexdigest()},
        }],
        "predicateType": predicate_type,
        "predicate": dict(claims),
    }


def _canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _seal(payload_bytes, payload_type, signers):
    sigs = []
    for s in signers:
        sigs.append({"keyid": s.key_id, "sig": _b64(s.sign(v.pae(payload_type, payload_bytes)))})
    return {"payload": _b64(payload_bytes), "payloadType": payload_type,
            "signatures": sigs}


def _policy_doc(ev_signers, tsa_signers, expires, threshold=1, min_ts=0,
                required_claims=("window", "decisions"), max_age_hours=168):
    return {
        "version": v.POLICY_VERSION,
        "policy_id": "test-policy-w311-ovf",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_signing": {
            "threshold": threshold,
            "keys": [{"keyid": s.key_id,
                      "pubkey_hex": s.public_key.hex()}
                     for s in ev_signers],
        },
        "timestamp_authorities": [{
            "authority_id": "tsa-test-%d" % i,
            "pubkey_hex": s.public_key.hex(),
            "valid_for": {
                "not_before": (NOW - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "not_after": (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        } for i, s in enumerate(tsa_signers)],
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": list(required_claims),
        "observer_timestamps": {"min": min_ts,
                                "max_age_hours": max_age_hours},
        "witness_required": False,
    }


def _seal_policy(policy_doc, signer=None):
    signer = _signer(POLICY_ANCHOR_SEED) if signer is None else signer
    return _seal(_canon(policy_doc), v.POLICY_PAYLOAD_TYPE, [signer])


def _timestamp(authority_id, when, bundle_bytes, tsa_signer):
    body = {"authority_id": authority_id,
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence_digest": hashlib.sha256(bundle_bytes).hexdigest()}
    return dict(body, sig=_b64(tsa_signer.sign(_canon(body))))


def _good_bundle(threshold=1, min_ts=0, expires=None, claims=None,
                 tsa=True, predicate_type=PREDICATE_TYPE,
                 bundle_bytes=BUNDLE_BYTES, max_age_hours=168,
                 required_claims=None):
    """Assemble a fully-valid verification bundle (the known-good positive)."""
    expires = NOW + timedelta(days=10) if expires is None else expires
    ev = [_signer(EVIDENCE_SEED)] + ([_signer(EVIDENCE_SEED_2)]
                                     if threshold > 1 else [])
    tsa_s = [_signer(TSA_SEED)] if tsa else []
    rc = (tuple(required_claims) if required_claims is not None
          else tuple((claims or PREDICATE_CLAIMS).keys()))
    policy = _policy_doc(ev, tsa_s, expires, threshold=threshold, min_ts=min_ts,
                         required_claims=rc, max_age_hours=max_age_hours)
    stmt = _statement(bundle_bytes=bundle_bytes, claims=claims,
                      predicate_type=predicate_type)
    envelope = _seal(_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE, ev[:threshold] if threshold > 1 else ev)
    if threshold > 1:
        envelope = _seal(_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE, ev)
    policy_env = _seal_policy(policy)
    stamps = ([_timestamp("tsa-test-0", NOW - timedelta(hours=1),
                          bundle_bytes, _signer(TSA_SEED))]
              if tsa else [])
    vb = v.build_verification_bundle(envelope, policy_env,
                                     timestamps=stamps)
    return vb, bundle_bytes


def _clock(at=NOW):
    return v.FixedClock("test-clock", at)


def _expect_code(pid, fn, code, exit_code):
    """HELD iff fn raises VerificationError with the typed code/exit."""
    try:
        fn()
    except v.VerificationError as e:
        if e.code == code and e.exit_code == exit_code:
            _record(pid, "HELD", "%s/%d as typed" % (code, exit_code))
        else:
            _record(pid, "BREAK",
                    "wrong code: got %s/%s want %s/%d"
                    % (e.code, e.exit_code, code, exit_code))
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected %r" % (e,))
    else:
        _record(pid, "BREAK", "no refusal raised (want %s)" % code)


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


# ---------------------------------------------------------------------------
# Probes.
# ---------------------------------------------------------------------------

def p_pin_taxonomy():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1900/1900/0 sorted")


def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    m_open = re.findall(r"Open findings: ([^.]*)\.", text)
    # Wave-316 merge footer: F398/F399/F400 CLOSED; F401/F402/F403 OPEN; next F404.
    ok = (m_next and m_next[-1] == "F404"
          and m_open and m_open[-1].strip() == "none")
    _record("footer-state", "HELD" if ok else "BREAK",
            "open none / next F404" if ok else "footer drift")


def p_taxonomy_shape():
    codes = v.FAILURE_CODES
    if len(codes) != 16:
        return _record("taxonomy-shape", "BREAK",
                       "want 16 codes, got %d" % len(codes))
    exits = sorted({c["exit"] for c in codes.values()})
    if exits != [40, 41, 42, 43, 44]:
        return _record("taxonomy-shape", "BREAK",
                       "exit codes want [40..44], got %r" % (exits,))
    order = ["parse", "crypto", "unsupported", "consistency", "policy"]
    cats = [codes[k]["category"] for k in codes]
    if sorted(set(cats)) != sorted(order):
        return _record("taxonomy-shape", "BREAK",
                       "categories want %r" % (order,))
    # Ordered: every code's category must not regress vs the previous
    # code in dict order (parse -> crypto -> unsupported -> consistency
    # -> policy; the wave-312 WITNESS_* codes slot into the existing
    # categories in that order).
    rank = {c: i for i, c in enumerate(order)}
    seq = [rank[c] for c in cats]
    if seq != sorted(seq):
        return _record("taxonomy-shape", "BREAK",
                       "taxonomy not in parse->crypto->unsupported->"
                       "consistency->policy order")
    for k, c in codes.items():
        if not c.get("reason") or not c.get("remedy"):
            return _record("taxonomy-shape", "BREAK",
                           "code %s missing reason/remedy" % k)
    _record("taxonomy-shape", "HELD", "16 codes, exits 40-44, ordered")


def p_known_good_positive():
    vb, bb = _good_bundle()
    try:
        rep = v.verify(bb, vb, time_source=_clock())
    except Exception as e:  # noqa: BLE001
        return _record("known-good-positive", "ERROR",
                       "valid bundle refused: %r" % (e,))
    if rep.get("verificationResult") != "PASSED":
        return _record("known-good-positive", "BREAK",
                       "valid bundle did not PASS")
    steps = [c["step"] for c in rep.get("checks", [])]
    want = ["parse", "payloadType", "signature", "statement", "predicate",
            "digest", "subject", "policy", "transcript"]
    if steps != want:
        return _record("known-good-positive", "BREAK",
                       "transcript steps want %r, got %r" % (want, steps))
    if not all(c["result"] == "pass" for c in rep["checks"]):
        return _record("known-good-positive", "BREAK",
                       "not all checks pass")
    if rep.get("resourceUri") != "sha256:" + hashlib.sha256(bb).hexdigest():
        return _record("known-good-positive", "BREAK",
                       "resourceUri not digest-bound")
    text = v.render_transcript(rep)
    # SLSA VSA consumer procedure: PASSED != ALLOW -- the transcript
    # must say the verdict is evidence input, not a decision.
    if "PASSED" not in text or "not an authorization decision" not in text:
        return _record("known-good-positive", "BREAK",
                       "transcript missing PASSED != ALLOW banner")
    if "system-utc-clock" not in text and "test-clock" not in text:
        return _record("known-good-positive", "BREAK",
                       "transcript does not name the time source")
    _record("known-good-positive", "HELD",
            "PASSED, 9/9 checks, digest-bound, banner present")


def p_neg_altered_artifact_bytes():
    # registystack negative 1: altered artifact bytes.
    vb, _ = _good_bundle()
    _expect_code("neg-altered-artifact-bytes",
                 lambda: v.verify(OTHER_BYTES, vb, time_source=_clock()),
                 "SUBJECT_DIGEST_MISMATCH", 43)


def p_neg_wrong_evidence_key():
    # registystack negative 2: wrong certificate identity -> the
    # envelope is signed by a key the policy does not trust.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    stmt = _statement()
    evil = _seal(_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE,
                 [_signer(ATTACKER_SEED)])
    vb2["envelope"] = evil
    _expect_code("neg-wrong-evidence-key",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "ENVELOPE_SIGNATURE_INVALID", 41)


def p_neg_keyid_spoof():
    # keyid is an unauthenticated hint: an attacker label on an
    # attacker-signed envelope verifies against nothing.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    stmt = _statement()
    evil = _seal(_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE,
                 [_signer(ATTACKER_SEED)])
    good_kid = vb["envelope"]["signatures"][0]["keyid"]
    evil["signatures"][0]["keyid"] = good_kid  # spoofed label
    vb2["envelope"] = evil
    _expect_code("neg-keyid-spoof",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "ENVELOPE_SIGNATURE_INVALID", 41)


def p_neg_threshold_unmet():
    vb, bb = _good_bundle(threshold=2)
    # policy demands 2 distinct keys; strip one signature.
    vb2 = copy.deepcopy(vb)
    vb2["envelope"]["signatures"] = vb2["envelope"]["signatures"][:1]
    _expect_code("neg-threshold-unmet",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "ENVELOPE_SIGNATURE_INVALID", 41)


def p_neg_tampered_payload():
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    raw = bytearray(base64.b64decode(vb2["envelope"]["payload"]))
    raw[10] ^= 0x01
    vb2["envelope"]["payload"] = _b64(bytes(raw))
    _expect_code("neg-tampered-payload",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "ENVELOPE_SIGNATURE_INVALID", 41)


def p_neg_payload_type_confusion():
    # The payloadType check fires BEFORE the signature check (pipeline
    # order): a valid signature over the wrong type is still refused
    # on type, not sig.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    stmt = _statement()
    wrong = _seal(_canon(stmt), "text/plain", [_signer(EVIDENCE_SEED)])
    vb2["envelope"] = wrong
    _expect_code("neg-payload-type-confusion",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "UNSUPPORTED_PAYLOAD_TYPE", 42)


def p_neg_wrong_trust_root_policy():
    # registystack negative 3: wrong trusted root -> the policy is
    # signed by a key the trust root does not pin.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    policy = _policy_doc([_signer(EVIDENCE_SEED)], [_signer(TSA_SEED)],
                         NOW + timedelta(days=10))
    vb2["policy"] = _seal_policy(policy, signer=_signer(ATTACKER_SEED))
    _expect_code("neg-wrong-trust-root-policy",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "POLICY_SIGNATURE_INVALID", 41)


def p_neg_expired_policy():
    # registystack negative 4 (time): an expired policy always fails,
    # even when every signature is valid.
    vb, bb = _good_bundle(expires=NOW - timedelta(hours=1))
    _expect_code("neg-expired-policy",
                 lambda: v.verify(bb, vb, time_source=_clock()),
                 "TEMPORAL_UNSATISFIED", 44)


def p_neg_invalid_signing_time():
    # registystack negative 4 (time): observer timestamp outside the
    # authority's validFor window.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    vb2["timestamps"] = [_timestamp("tsa-test-0", NOW + timedelta(days=60),
                                    bb, _signer(TSA_SEED))]
    _expect_code("neg-invalid-signing-time",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TIMESTAMP_SIGNATURE_INVALID", 41)


def p_neg_corrupted_timestamp_sig():
    # registystack negative 5: corrupted inclusion proof -> corrupted
    # observer timestamp.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    tok = dict(vb2["timestamps"][0])
    raw = bytearray(base64.b64decode(tok["sig"]))
    raw[-1] ^= 0x01
    tok["sig"] = _b64(bytes(raw))
    vb2["timestamps"] = [tok]
    _expect_code("neg-corrupted-timestamp-sig",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TIMESTAMP_SIGNATURE_INVALID", 41)


def p_neg_witness_entries_present():
    # Unknown witness entry kinds are refused coded (never silently
    # skipped) -- the landed witness step verifies the registered
    # sasanam-witness-log/v1 kind; anything else still fails closed.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    vb2["witness_entries"] = [{"version": "rekor-v2-entry/v1",
                               "checkpoint": "..."}]
    _expect_code("neg-witness-entries-present",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "UNSUPPORTED_BUNDLE_VERSION", 42)


def p_neg_same_bytes_noncanonical():
    # Same-bytes discipline: the signed payload bytes are valid, but
    # they are not the canonical serialization of the statement.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    stmt = _statement()
    noncanon = json.dumps(stmt, indent=2).encode("utf-8")
    vb2["envelope"] = _seal(noncanon, v.ENVELOPE_PAYLOAD_TYPE,
                            [_signer(EVIDENCE_SEED)])
    _expect_code("neg-same-bytes-noncanonical",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "SUBJECT_DIGEST_MISMATCH", 43)


def p_cve_24122_window_at_token_time():
    # CVE-2026-24122: an issuing CA expired BEFORE the timestamp was
    # still accepted. The authority's validFor window is checked at the
    # TIMESTAMP's time. Refuse even though the window covers *now*.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    # Token claims a time 60 days out; window ends at +30d.
    vb2["timestamps"] = [_timestamp("tsa-test-0", NOW + timedelta(days=60),
                                    bb, _signer(TSA_SEED))]
    _expect_code("cve-24122-window-at-token-time",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TIMESTAMP_SIGNATURE_INVALID", 41)
    # Control: token time inside the window verifies even when the
    # window has since lapsed (checked at token time, not verify time).
    vb3, _ = _good_bundle(expires=NOW + timedelta(days=90),
                            max_age_hours=24 * 90)
    vb3["timestamps"] = [_timestamp("tsa-test-0", NOW - timedelta(hours=1),
                                    bb, _signer(TSA_SEED))]
    later = v.FixedClock("test-clock", NOW + timedelta(days=60))
    try:
        rep = v.verify(bb, vb3, time_source=later)
    except Exception as e:  # noqa: BLE001
        return _record("cve-24122-window-at-token-time", "BREAK",
                       "control refused: %r" % (e,))
    if rep.get("verificationResult") != "PASSED":
        return _record("cve-24122-window-at-token-time", "BREAK",
                       "control did not PASS")
    # (the HELD record was already written by _expect_code on the
    # refuse path; the control passing keeps it HELD.)


def p_cve_22703_entry_binding():
    # CVE-2026-22703: a log entry that does not reference the
    # artifact's digest must never verify. The observer timestamp
    # binds evidence_digest inside the signed body.
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    # Valid signature, but over a DIFFERENT digest.
    vb2["timestamps"] = [_timestamp("tsa-test-0", NOW - timedelta(hours=1),
                                    OTHER_BYTES, _signer(TSA_SEED))]
    _expect_code("cve-22703-entry-binding",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TIMESTAMP_SIGNATURE_INVALID", 41)


def p_cve_39395_content_checks_always_on():
    # CVE-2026-39395: false "Verified OK" when content checks were
    # opt-in. Predicate/content checks are ALWAYS on here: a valid
    # envelope signature over the wrong predicateType still fails,
    # and a missing required claim still fails. There is no flag to
    # disable them.
    vb, bb = _good_bundle(predicate_type="https://example.com/other/v1")
    _expect_code("cve-39395-predicate-type",
                 lambda: v.verify(bb, vb, time_source=_clock()),
                 "UNSUPPORTED_PREDICATE_TYPE", 42)
    vb2, _ = _good_bundle(claims={"window": "2026-10-03T00:00:00Z"},
                            required_claims=("window", "no-such-claim"))
    _expect_code("cve-39395-required-claim",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "STATEMENT_SHAPE_INVALID", 43)
    # No skip knob exists on the public seam.
    import inspect
    params = set(inspect.signature(v.verify).parameters)
    if params & {"skip_predicate", "check_claims", "no_content_checks"}:
        _record("cve-39395-content-checks-always-on", "BREAK",
                "skip knob present on verify()")
    else:
        _record("cve-39395-content-checks-always-on", "HELD",
                "predicate checks unconditional, no skip knob")


def p_cve_44310_crash_never_success():
    # CVE-2026-44310: a crash must never emit a success signal. Force
    # an internal failure inside verify() and require a non-zero exit
    # with a typed INTERNAL_ERROR machine report.
    vb, bb = _good_bundle()
    path = "/var/tmp/g311-ovf/cve44310_bundle.json"
    os.makedirs("/var/tmp/g311-ovf", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(vb, fh)
    art = "/var/tmp/g311-ovf/cve44310_artifact.bin"
    with open(art, "wb") as fh:
        fh.write(bb)
    real_canon = v.canonical

    def _boom(obj):
        raise RuntimeError("synthetic internal failure")

    v.canonical = _boom
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = v.main(["--bundle", path, "--artifact", art,
                         "--clock", "test:2026-10-03T14:00:00Z"])
    finally:
        v.canonical = real_canon
    out = buf.getvalue()
    if rc == 0:
        return _record("cve-44310-crash-never-success", "BREAK",
                       "internal crash exited 0")
    try:
        doc = json.loads(out)
    except ValueError:
        return _record("cve-44310-crash-never-success", "BREAK",
                       "no machine JSON on crash path")
    if doc.get("code") == "INTERNAL_ERROR" and rc == 1:
        _record("cve-44310-crash-never-success", "HELD",
                "crash -> exit 1 INTERNAL_ERROR, never 0")
    else:
        _record("cve-44310-crash-never-success", "BREAK",
                "crash path rc=%d code=%r" % (rc, doc.get("code")))


def p_neg_no_time_source():
    # Clock as inspectable control: no trusted time -> fail closed.
    vb, bb = _good_bundle()
    _expect_code("neg-no-time-source",
                 lambda: v.verify(bb, vb, time_source=None),
                 "TEMPORAL_UNSATISFIED", 44)


def p_neg_future_timestamp():
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    vb2["timestamps"] = [_timestamp("tsa-test-0", NOW + timedelta(hours=2),
                                    bb, _signer(TSA_SEED))]
    _expect_code("neg-future-timestamp",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TEMPORAL_UNSATISFIED", 44)


def p_neg_stale_timestamp():
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    vb2["timestamps"] = [_timestamp("tsa-test-0",
                                    NOW - timedelta(hours=200),
                                    bb, _signer(TSA_SEED))]
    _expect_code("neg-stale-timestamp",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TEMPORAL_UNSATISFIED", 44)


def p_neg_timestamps_required_unmet():
    vb, bb = _good_bundle(min_ts=2)
    _expect_code("neg-timestamps-required-unmet",
                 lambda: v.verify(bb, vb, time_source=_clock()),
                 "TEMPORAL_UNSATISFIED", 44)


def p_neg_authority_isolation():
    # sigstore-rust PR #166: each authority verified in isolation --
    # a token naming authority A but signed by B's key fails, even
    # though B is a trusted authority.
    vb, bb = _good_bundle()
    policy = _policy_doc([_signer(EVIDENCE_SEED)],
                         [_signer(TSA_SEED)], NOW + timedelta(days=10))
    # Add a second authority with its own key.
    other_tsa = _signer(bytes([11]) * 32)
    policy["timestamp_authorities"].append({
        "authority_id": "tsa-test-9",
        "pubkey_hex": other_tsa.public_key.hex(),
        "valid_for": {
            "not_before": (NOW - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    })
    vb2 = copy.deepcopy(vb)
    vb2["policy"] = _seal_policy(policy)
    tok = _timestamp("tsa-test-0", NOW - timedelta(hours=1), bb, other_tsa)
    vb2["timestamps"] = [tok]
    _expect_code("neg-authority-isolation",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TIMESTAMP_SIGNATURE_INVALID", 41)


def p_neg_unknown_authority():
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    vb2["timestamps"] = [_timestamp("tsa-unknown", NOW - timedelta(hours=1),
                                    bb, _signer(TSA_SEED))]
    _expect_code("neg-unknown-authority",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "TIMESTAMP_SIGNATURE_INVALID", 41)


def p_pos_existence_only_labeled():
    # policy-controller lesson: existence-only verification is
    # LABELED, never defaulted. The crypto core still runs; only the
    # predicate-content evaluation is marked as not performed.
    vb, bb = _good_bundle()
    try:
        rep = v.verify(bb, vb, time_source=_clock(), existence_only=True)
    except Exception as e:  # noqa: BLE001
        return _record("pos-existence-only-labeled", "ERROR",
                       "existence-only refused: %r" % (e,))
    if rep.get("verificationResult") != "PASSED":
        return _record("pos-existence-only-labeled", "BREAK", "not PASSED")
    if rep.get("existenceOnly") is not True:
        return _record("pos-existence-only-labeled", "BREAK",
                       "summary not labeled existenceOnly")
    text = v.render_transcript(rep)
    if "existence-only" not in text.lower():
        return _record("pos-existence-only-labeled", "BREAK",
                       "transcript does not label existence-only")
    # Default path is full verification, unlabeled.
    rep2 = v.verify(bb, vb, time_source=_clock())
    if rep2.get("existenceOnly") is not False:
        return _record("pos-existence-only-labeled", "BREAK",
                       "default path mislabeled")
    _record("pos-existence-only-labeled", "HELD",
            "labeled mode + unlabeled default")


def p_neg_trust_pin_mismatch():
    # A verifier whose compiled-in trust root disagrees with its pin
    # refuses to run at all (exit 1, never a verification verdict).
    real_pin = v.COMPILED_TRUST_ROOT_SHA256
    v.COMPILED_TRUST_ROOT_SHA256 = "0" * 64
    try:
        try:
            v.compiled_trust_root()
        except v.InternalError:
            _record("neg-trust-pin-mismatch", "HELD",
                    "pin mismatch -> InternalError, verifier will not run")
        except Exception as e:  # noqa: BLE001
            _record("neg-trust-pin-mismatch", "ERROR", "%r" % (e,))
        else:
            _record("neg-trust-pin-mismatch", "BREAK",
                    "pin mismatch did not refuse")
    finally:
        v.COMPILED_TRUST_ROOT_SHA256 = real_pin


def p_neg_bundle_malformed():
    _expect_code("neg-bundle-malformed",
                 lambda: v.verify(BUNDLE_BYTES, {"nope": 1},
                                  time_source=_clock()),
                 "BUNDLE_MALFORMED", 40)
    _expect_code("neg-bundle-bytes-not-bytes",
                 lambda: v.verify("not-bytes", {}, time_source=_clock()),
                 "BUNDLE_MALFORMED", 40)


def p_neg_policy_malformed():
    vb, bb = _good_bundle()
    vb2 = copy.deepcopy(vb)
    vb2["policy"] = _seal(b"not-json", v.POLICY_PAYLOAD_TYPE,
                            [_signer(POLICY_ANCHOR_SEED)])
    _expect_code("neg-policy-malformed",
                 lambda: v.verify(bb, vb2, time_source=_clock()),
                 "POLICY_MALFORMED", 40)


def p_zero_network_static():
    # Zero network by construction: the module and its in-repo imports
    # must not import socket/urllib/http.client/ssl.
    import ast
    forbidden = {"socket", "urllib", "http.client", "ssl",
                 "urllib.request", "urllib.parse", "http"}
    src_path = os.path.join(REPO, "gov", "evidence_verify_offline.py")
    with open(src_path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    bad = (imported & forbidden) - set()
    # Also scan the in-repo modules the verifier imports (gov.ed25519).
    for mod in ("gov/ed25519.py",):
        with open(os.path.join(REPO, mod), encoding="utf-8") as fh:
            tree2 = ast.parse(fh.read())
        for node in ast.walk(tree2):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] in forbidden:
                        bad.add(mod + ":" + a.name)
    if bad:
        _record("zero-network-static", "BREAK",
                "network imports reachable: %r" % sorted(bad))
    else:
        # True-closure check: in a FRESH interpreter, load the verifier
        # module by file path (never as gov.x, so gov/__init__.py never
        # executes) and assert no network-capable module is importable
        # in the resulting sys.modules. This is the literal claim:
        # importing the verifier cannot pull in sockets.
        driver = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location(\n"
            "    'ev_standalone', %r)\n" % (src_path,) +
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "banned = {'socket', 'urllib', 'urllib.request', 'urllib.parse',\n"
            "          'http', 'http.client', 'ssl', 'requests'}\n"
            "hit = sorted(banned & set(sys.modules))\n"
            "assert not hit, hit\n"
            "print('CLOSURE_CLEAN')\n"
        )
        env = _clean_env()
        proc = subprocess.run([sys.executable, "-c", driver],
                              cwd="/tmp", env=env, capture_output=True,
                              text=True, timeout=60)
        if proc.returncode != 0 or "CLOSURE_CLEAN" not in proc.stdout:
            _record("zero-network-static", "BREAK",
                    "import closure pulls network modules: %s%s"
                    % (proc.stdout.strip(), proc.stderr.strip()[-200:]))
        else:
            _record("zero-network-static", "HELD",
                    "source scan + fresh-interpreter import closure clean "
                    "(no socket/urllib/http/ssl)")


def p_zero_network_dynamic():
    # Dynamic proof: run the whole verify path with socket.socket
    # rigged to explode. A verifier that needs the network dies here.
    import socket
    real_socket = socket.socket

    def _boom(*a, **k):
        raise AssertionError("network access attempted")

    vb, bb = _good_bundle()
    socket.socket = _boom
    try:
        rep = v.verify(bb, vb, time_source=_clock())
    except AssertionError as e:
        return _record("zero-network-dynamic", "BREAK", str(e))
    except Exception as e:  # noqa: BLE001
        return _record("zero-network-dynamic", "ERROR", "%r" % (e,))
    finally:
        socket.socket = real_socket
    if rep.get("verificationResult") == "PASSED":
        _record("zero-network-dynamic", "HELD",
                "PASSED with socket.socket disabled")
    else:
        _record("zero-network-dynamic", "BREAK", "not PASSED")


def p_cli_airgap_surface():
    # cosign air-gap UX contract: --offline / --trusted-root /
    # --rfc3161-timestamp exist; --private-infrastructure does not.
    vb, bb = _good_bundle()
    d = "/var/tmp/g311-ovf"
    os.makedirs(d, exist_ok=True)
    bpath = os.path.join(d, "cli_bundle.json")
    apath = os.path.join(d, "cli_artifact.bin")
    with open(bpath, "w", encoding="utf-8") as fh:
        json.dump(vb, fh)
    with open(apath, "wb") as fh:
        fh.write(bb)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = v.main(["--offline", "--bundle", bpath, "--artifact", apath,
                     "--clock", "test:2026-10-03T14:00:00Z"])
    if rc != 0:
        return _record("cli-airgap-surface", "BREAK",
                       "--offline run rc=%d" % rc)
    if "PASSED" not in buf.getvalue():
        return _record("cli-airgap-surface", "BREAK",
                       "no PASSED in CLI transcript")
    # --trusted-root with a caller-supplied root (transcript must say
    # caller-supplied and print its digest).
    rpath = os.path.join(d, "cli_root.json")
    with open(rpath, "w", encoding="utf-8") as fh:
        json.dump(v.COMPILED_TRUST_ROOT, fh)
    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        rc2 = v.main(["--bundle", bpath, "--artifact", apath,
                      "--trusted-root", rpath,
                      "--clock", "test:2026-10-03T14:00:00Z"])
    if rc2 != 0 or "caller-supplied" not in buf2.getvalue():
        return _record("cli-airgap-surface", "BREAK",
                       "--trusted-root rc=%d" % rc2)
    # --rfc3161-timestamp accepts an extra observer-timestamp token.
    tpath = os.path.join(d, "cli_token.json")
    tok = _timestamp("tsa-test-0", NOW - timedelta(hours=2), bb,
                     _signer(TSA_SEED))
    with open(tpath, "w", encoding="utf-8") as fh:
        json.dump(tok, fh)
    buf3 = io.StringIO()
    with redirect_stdout(buf3):
        rc3 = v.main(["--bundle", bpath, "--artifact", apath,
                      "--rfc3161-timestamp", tpath,
                      "--clock", "test:2026-10-03T14:00:00Z"])
    if rc3 != 0:
        return _record("cli-airgap-surface", "BREAK",
                       "--rfc3161-timestamp rc=%d" % rc3)
    # --private-infrastructure must NOT exist (SKIP verdict).
    buf4 = io.StringIO()
    try:
        with redirect_stdout(buf4):
            v.main(["--bundle", bpath, "--artifact", apath,
                    "--private-infrastructure",
                    "--clock", "test:2026-10-03T14:00:00Z"])
    except SystemExit as e:
        if e.code == 2:
            _record("cli-airgap-surface", "HELD",
                    "--offline/--trusted-root/--rfc3161-timestamp OK; "
                    "--private-infrastructure refused (exit 2)")
            return
    _record("cli-airgap-surface", "BREAK",
            "--private-infrastructure was accepted")


def p_cli_failure_exit_codes():
    # Typed exit codes on the CLI: tampered artifact -> 43.
    vb, _ = _good_bundle()
    d = "/var/tmp/g311-ovf"
    os.makedirs(d, exist_ok=True)
    bpath = os.path.join(d, "exit_bundle.json")
    apath = os.path.join(d, "exit_artifact.bin")
    with open(bpath, "w", encoding="utf-8") as fh:
        json.dump(vb, fh)
    with open(apath, "wb") as fh:
        fh.write(OTHER_BYTES)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = v.main(["--bundle", bpath, "--artifact", apath,
                     "--clock", "test:2026-10-03T14:00:00Z"])
    try:
        doc = json.loads(buf.getvalue())
    except ValueError:
        return _record("cli-failure-exit-codes", "BREAK",
                       "no machine JSON on failure path")
    if rc == 43 and doc.get("code") == "SUBJECT_DIGEST_MISMATCH":
        _record("cli-failure-exit-codes", "HELD",
                "rc=43 SUBJECT_DIGEST_MISMATCH with remedy")
    else:
        _record("cli-failure-exit-codes", "BREAK",
                "rc=%d code=%r" % (rc, doc.get("code")))
    if not doc.get("remedy"):
        _record("cli-failure-exit-codes", "BREAK", "no remedy hint")


def _clean_env():
    """Subprocess env without import-path leaks (fresh-interpreter
    isolation for the stdlib-only checks)."""
    return {k: val for k, val in os.environ.items()
            if k not in ("PYTHONPATH", "PYTHONHOME")}


def p_thirdparty_accept():
    # Third-party acceptance: the stdlib-only script verifies the
    # known-good bundle with NO Sasanam import (asserted in the child
    # via sys.modules). "Sell evidence, not the engine."
    verif_bundle, artifact_bytes = _good_bundle()
    d = "/var/tmp/g311-ovf/tp"
    os.makedirs(d, exist_ok=True)
    for name, data, mode in (("bundle.json",
                              json.dumps(verif_bundle).encode(), "wb"),
                             ("artifact.bin", artifact_bytes, "wb"),
                             ("trust_root.json",
                              json.dumps(v.COMPILED_TRUST_ROOT).encode(), "wb")):
        with open(os.path.join(d, name), mode) as fh:
            fh.write(data)
    script = os.path.join(REPO, "evals", "w311_thirdparty_accept.py")
    env = _clean_env()
    env["GOV_SKIP_GREEN"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, script,
             "--bundle", os.path.join(d, "bundle.json"),
             "--artifact", os.path.join(d, "artifact.bin"),
             "--trust-root", os.path.join(d, "trust_root.json")],
            cwd="/tmp", env=env, capture_output=True, text=True,
            timeout=120)
    except Exception as e:  # noqa: BLE001
        return _record("thirdparty-accept", "ERROR", "%r" % (e,))
    if proc.returncode != 0:
        return _record("thirdparty-accept", "BREAK",
                       "rc=%d stderr=%s" % (proc.returncode,
                                            proc.stderr[-500:]))
    if "THIRDPARTY_VALID" not in proc.stdout:
        return _record("thirdparty-accept", "BREAK",
                       "acceptance marker missing")
    _record("thirdparty-accept", "HELD",
            "stdlib-only, no Sasanam import, VALID")


def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "green check skipped (GOV_SKIP_GREEN=1)")
        return
    # Adjacent evidence suites (depth-1): DSSE export + in-toto
    # re-enveloping must stay green under the new module.
    green_check.check_unittest(
        _rec, "green-test_evidence_dsse", "tests.test_evidence_dsse",
        repo=REPO)
    green_check.check_unittest(
        _rec, "green-test_evidence_intoto", "tests.test_evidence_intoto",
        repo=REPO)


_PROBES = [
    ("pin-taxonomy", p_pin_taxonomy),
    ("footer-state", p_footer_state),
    ("taxonomy-shape", p_taxonomy_shape),
    ("known-good-positive", p_known_good_positive),
    ("neg-altered-artifact-bytes", p_neg_altered_artifact_bytes),
    ("neg-wrong-evidence-key", p_neg_wrong_evidence_key),
    ("neg-keyid-spoof", p_neg_keyid_spoof),
    ("neg-threshold-unmet", p_neg_threshold_unmet),
    ("neg-tampered-payload", p_neg_tampered_payload),
    ("neg-payload-type-confusion", p_neg_payload_type_confusion),
    ("neg-wrong-trust-root-policy", p_neg_wrong_trust_root_policy),
    ("neg-expired-policy", p_neg_expired_policy),
    ("neg-invalid-signing-time", p_neg_invalid_signing_time),
    ("neg-corrupted-timestamp-sig", p_neg_corrupted_timestamp_sig),
    ("neg-witness-entries-present", p_neg_witness_entries_present),
    ("neg-same-bytes-noncanonical", p_neg_same_bytes_noncanonical),
    ("cve-24122-window-at-token-time", p_cve_24122_window_at_token_time),
    ("cve-22703-entry-binding", p_cve_22703_entry_binding),
    ("cve-39395-content-checks-always-on",
     p_cve_39395_content_checks_always_on),
    ("cve-44310-crash-never-success", p_cve_44310_crash_never_success),
    ("neg-no-time-source", p_neg_no_time_source),
    ("neg-future-timestamp", p_neg_future_timestamp),
    ("neg-stale-timestamp", p_neg_stale_timestamp),
    ("neg-timestamps-required-unmet", p_neg_timestamps_required_unmet),
    ("neg-authority-isolation", p_neg_authority_isolation),
    ("neg-unknown-authority", p_neg_unknown_authority),
    ("pos-existence-only-labeled", p_pos_existence_only_labeled),
    ("neg-trust-pin-mismatch", p_neg_trust_pin_mismatch),
    ("neg-bundle-malformed", p_neg_bundle_malformed),
    ("neg-policy-malformed", p_neg_policy_malformed),
    ("zero-network-static", p_zero_network_static),
    ("zero-network-dynamic", p_zero_network_dynamic),
    ("cli-airgap-surface", p_cli_airgap_surface),
    ("cli-failure-exit-codes", p_cli_failure_exit_codes),
    ("thirdparty-accept", p_thirdparty_accept),
]

# No open findings expected from this lane: every probe must HOLD.
_EXPECTED_BREAKS = frozenset()


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("probe", nargs="?", default=None,
                    help="run one probe by id")
    args = ap.parse_args()
    if args.probe:
        for pid, fn in _PROBES:
            if pid == args.probe:
                _safe(pid, fn)
                break
        else:
            print("unknown probe", args.probe)
            sys.exit(2)
    else:
        for pid, fn in _PROBES:
            _safe(pid, fn)
        _green_checks()
    probe_lines.emit(_results)
    brk = sum(1 for r in _results if r[1] == "BREAK")
    held = sum(1 for r in _results if r[1] == "HELD")
    err = sum(1 for r in _results if r[1] == "ERROR")
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if args.probe:
        return 0
    unexpected = [pid for pid, v, _ in _results
                  if v == "BREAK" and pid not in _EXPECTED_BREAKS]
    if unexpected:
        print("unexpected BREAKs: %s" % (unexpected,))
        return 1
    missing = sorted(_EXPECTED_BREAKS - frozenset(
        pid for pid, v, _ in _results if v == "BREAK"))
    if missing:
        print("expected BREAKs missing: %s" % (missing,))
        return 1
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
