"""Wave-318 lane 2 red-first battery: evidence-bundle schema v2 (AU-3 + CC8.1).

Targets:
  - gov/evidence_schema_v2.py (new): AU-3 record extraction, CC8.1
    decision-maker versioning, v2 section builders/validators.
  - gov/evidence_bundle.py: additive v2 sections behind schema_version="2.0".
  - gov/evidence_verify_offline.py: conditional v2 validation + typed
    EXTENSION_SCHEMA_INVALID code; schema-1.0 bundles verify unchanged.

Run:
  ~/workspace/.gov-venv/bin/python evals/w318_evidence_schema_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w318_evidence_schema_probes.py <probe-id>

All probes must HOLD on the closed tree (red-first: this battery is the
red before green).
"""

import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import traceback
from datetime import datetime, timedelta, timezone

# Wave-95 lesson: module-level staging default.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check
import probe_lines

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# This lane mints no governance decision codes (the verifier taxonomy is
# the verifier's own surface); the decision-code pin moved 1900 -> 1906 at
# the wave-318 merge via lane 3's six trust-root-* codes.
TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)

# The verifier gains one typed code (EXTENSION_SCHEMA_INVALID): 16 -> 17.
# Wave-318 lane 3 adds six trust-root-* chain codes: 17 -> 23.
# Wave-318 merge: verifier taxonomy 16 -> 23.
VERIFIER_TAXONOMY_PIN = 33  # Wave-319 lane 3: 23 -> 33 (+10 witness-consistency/gossip)

from gov.signing import Ed25519Signer
from gov import evidence_verify_offline as v
from gov import evidence_schema_v2 as sv2

_results = []

INTOTO_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://sasanam.dev/predicate/evidence-bundle/v1"

UTC = timezone.utc
NOW = datetime(2026, 10, 4, 4, 0, 0, tzinfo=UTC)

POLICY_ANCHOR_SEED = bytes.fromhex(
    "02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940ed521de3fa3b6")
EVIDENCE_SEED = bytes([7]) * 32
TSA_SEED = bytes([9]) * 32

PROMPT_DIGEST = "ab" * 32
PROMPT_DIGEST_2 = "cd" * 32


def _signer(seed):
    return Ed25519Signer(seed)


def _canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _seal(payload_bytes, payload_type, signers):
    sigs = [{"keyid": s.key_id,
             "sig": _b64(s.sign(v.pae(payload_type, payload_bytes)))}
            for s in signers]
    return {"payload": _b64(payload_bytes), "payloadType": payload_type,
            "signatures": sigs}


def _good_au3():
    return [
        {"seq": 1, "hash": "00" * 32,
         "au3": {"who": "agent:alpha", "what": "tool_call",
                 "when": "2026-10-04T03:00:00Z", "where": "executor:local",
                 "result": "allow"},
         "complete": True},
        {"seq": 2, "hash": "11" * 32,
         "au3": {"who": None, "what": "approval_granted",
                 "when": "2026-10-04T03:01:00Z", "where": None,
                 "result": "approved"},
         "complete": False},
    ]


def _good_dm(prompt_digest=PROMPT_DIGEST):
    return {
        "model": {"name": "synthetic-model", "version": "2026.10.1"},
        "system_prompt": {"digest_sha256": prompt_digest,
                          "version": "sp-2026-10-01"},
        "config": {"snapshot_digest_sha256": "ef" * 32,
                   "version": "cfg-2026-10-01"},
        "change_log": [
            {"changed_at": "2026-10-01T00:00:00Z", "component": "model",
             "from_version": None, "to_version": "2026.10.1",
             "to_digest": None, "note": "genesis"},
            {"changed_at": "2026-10-01T00:00:00Z",
             "component": "system_prompt",
             "from_version": None, "to_version": "sp-2026-10-01",
             "to_digest": prompt_digest, "note": "genesis"},
            {"changed_at": "2026-10-01T00:00:00Z", "component": "config",
             "from_version": None, "to_version": "cfg-2026-10-01",
             "to_digest": "ef" * 32, "note": "genesis"},
        ],
    }


def _v2_claims(au3=None, dm=None, schema_version=sv2.EVIDENCE_SCHEMA_V2):
    claims = {"window": "2026-10-04T00:00:00Z", "decisions": 2}
    if schema_version is not None:
        claims["evidence_schema_version"] = schema_version
    if au3 is not None:
        claims["au3_records"] = au3
    if dm is not None:
        claims["decision_maker_versions"] = dm
    return claims


def _statement(bundle_bytes, claims, predicate_type=PREDICATE_TYPE):
    return {
        "_type": INTOTO_TYPE,
        "subject": [{
            "name": "evidence-bundle",
            "digest": {"sha256": hashlib.sha256(bundle_bytes).hexdigest()},
        }],
        "predicateType": predicate_type,
        "predicate": dict(claims),
    }


def _policy_doc(ev_signers, tsa_signers, expires, required_claims):
    return {
        "version": v.POLICY_VERSION,
        "policy_id": "test-policy-w318-sv2",
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_signing": {
            "threshold": 1,
            "keys": [{"keyid": s.key_id, "pubkey_hex": s.public_key.hex()}
                     for s in ev_signers],
        },
        "timestamp_authorities": [{
            "authority_id": "tsa-test-%d" % i,
            "pubkey_hex": s.public_key.hex(),
            "valid_for": {
                "not_before": (NOW - timedelta(days=30)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "not_after": (NOW + timedelta(days=30)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
            },
        } for i, s in enumerate(tsa_signers)],
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": list(required_claims),
        "observer_timestamps": {"min": 0, "max_age_hours": 168},
        "witness_required": False,
    }


def _timestamp(authority_id, when, bundle_bytes, tsa_signer):
    body = {"authority_id": authority_id,
            "time": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence_digest": hashlib.sha256(bundle_bytes).hexdigest()}
    return dict(body, sig=_b64(tsa_signer.sign(_canon(body))))


def _bundle_bytes(tag=b"w318"):
    return b'{"evidence":"synthetic-bundle-w318-sv2-%s"}' % tag


def _verify_bundle(claims, required_claims=None, bundle_bytes=None,
                   seal_signers=None):
    """Assemble and verify a full verification bundle; returns the report
    or raises the verifier's VerificationError."""
    bb = _bundle_bytes() if bundle_bytes is None else bundle_bytes
    ev = [_signer(EVIDENCE_SEED)]
    tsa = [_signer(TSA_SEED)]
    rc = (list(required_claims) if required_claims is not None
          else list(claims.keys()))
    policy = _policy_doc(ev, tsa, NOW + timedelta(days=10), rc)
    stmt = _statement(bb, claims)
    envelope = _seal(_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE,
                     seal_signers or ev)
    vb = {
        "version": v.BUNDLE_VERSION,
        "envelope": envelope,
        "policy": _seal(_canon(policy), v.POLICY_PAYLOAD_TYPE,
                        [_signer(POLICY_ANCHOR_SEED)]),
        "witness_entries": [],
        "timestamps": [_timestamp("tsa-test-0", NOW - timedelta(hours=1),
                                  bb, _signer(TSA_SEED))],
    }
    return v.verify(bb, vb, time_source=v.FixedClock("test-clock", NOW))


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _expect_code(pid, fn, want_code):
    """fn must raise VerificationError carrying want_code; else BREAK."""
    try:
        fn()
    except v.VerificationError as e:
        if e.code == want_code:
            _record(pid, "HELD", "refused coded %s" % want_code)
        else:
            _record(pid, "BREAK",
                    "wrong code %r, want %r (%s)" % (e.code, want_code, e))
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected exception: %r" % (e,))
    else:
        _record(pid, "BREAK", "no refusal: %s not raised" % want_code)


# ---------------------------------------------------------------------------
# Probes.
# ---------------------------------------------------------------------------

def p_pin_taxonomy():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "2135/2135/0 sorted")




def p_footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    m_open = re.findall(r"Open findings: ([^.]*)\.", text)
    ok = (m_next and m_next[-1] == "F506"
          and m_open and m_open[-1].strip() == "F506, F507, F508, F509, F510, F511")
    _record("footer-state", "HELD" if ok else "BREAK",
            "open F412 / next F413" if ok else "footer drift")


def p_verifier_taxonomy_shape():
    codes = v.FAILURE_CODES
    if len(codes) != VERIFIER_TAXONOMY_PIN:
        return _record("verifier-taxonomy-shape", "BREAK",
                       "want %d codes, got %d"
                       % (VERIFIER_TAXONOMY_PIN, len(codes)))
    if "EXTENSION_SCHEMA_INVALID" not in codes:
        return _record("verifier-taxonomy-shape", "BREAK",
                       "EXTENSION_SCHEMA_INVALID missing")
    c = codes["EXTENSION_SCHEMA_INVALID"]
    if c["exit"] != 43 or c["category"] != "consistency":
        return _record("verifier-taxonomy-shape", "BREAK",
                       "EXTENSION_SCHEMA_INVALID wants exit 43 / "
                       "consistency, got %r" % (c,))
    if not c.get("reason") or not c.get("remedy"):
        return _record("verifier-taxonomy-shape", "BREAK",
                       "EXTENSION_SCHEMA_INVALID missing reason/remedy")
    order = ["parse", "crypto", "unsupported", "consistency", "policy"]
    rank = {cname: i for i, cname in enumerate(order)}
    seq = [rank[codes[k]["category"]] for k in codes]
    if seq != sorted(seq):
        return _record("verifier-taxonomy-shape", "BREAK",
                       "taxonomy order regressed")
    _record("verifier-taxonomy-shape", "HELD",
            "33 codes, EXTENSION_SCHEMA_INVALID exit 43/consistency")


def p_pos_v2_verifies():
    claims = _v2_claims(au3=_good_au3(), dm=_good_dm())
    try:
        rep = _verify_bundle(claims)
    except Exception as e:  # noqa: BLE001
        return _record("pos-v2-verifies", "ERROR",
                       "valid v2 bundle refused: %r" % (e,))
    if rep.get("verificationResult") != "PASSED":
        return _record("pos-v2-verifies", "BREAK", "did not PASS")
    _record("pos-v2-verifies", "HELD",
            "schema-2.0 bundle PASSED with au3 + decision_maker_versions "
            "claims")


def p_pos_v1_still_verifies():
    # Old bundle: no evidence_schema_version claim at all. Must verify
    # exactly as before the lane (backward compat).
    claims = {"window": "2026-10-04T00:00:00Z", "decisions": 2}
    try:
        rep = _verify_bundle(claims)
    except Exception as e:  # noqa: BLE001
        return _record("pos-v1-still-verifies", "ERROR",
                       "schema-1.0 bundle refused: %r" % (e,))
    if rep.get("verificationResult") != "PASSED":
        return _record("pos-v1-still-verifies", "BREAK", "did not PASS")
    _record("pos-v1-still-verifies", "HELD",
            "schema-1.0 bundle PASSED (backward compat)")


def p_neg_tampered_model_version():
    # Post-seal flip of decision_maker_versions.model.version: the
    # envelope signature must cover the extension claims.
    claims = _v2_claims(au3=_good_au3(), dm=_good_dm())
    bb = _bundle_bytes()
    ev = [_signer(EVIDENCE_SEED)]
    policy = _policy_doc(ev, [_signer(TSA_SEED)], NOW + timedelta(days=10),
                         list(claims.keys()))
    stmt = _statement(bb, claims)
    vb = {
        "version": v.BUNDLE_VERSION,
        "envelope": _seal(_canon(stmt), v.ENVELOPE_PAYLOAD_TYPE, ev),
        "policy": _seal(_canon(policy), v.POLICY_PAYLOAD_TYPE,
                        [_signer(POLICY_ANCHOR_SEED)]),
        "witness_entries": [],
        "timestamps": [_timestamp("tsa-test-0", NOW - timedelta(hours=1),
                                  bb, _signer(TSA_SEED))],
    }
    tampered = json.loads(base64.b64decode(vb["envelope"]["payload"]))
    tampered["predicate"]["decision_maker_versions"]["model"]["version"] = \
        "EVIL.9.9"
    vb["envelope"]["payload"] = _b64(_canon(tampered))
    _expect_code(
        "neg-tampered-model-version",
        lambda: v.verify(bb, vb, time_source=v.FixedClock("test-clock", NOW)),
        "ENVELOPE_SIGNATURE_INVALID")


def p_neg_missing_decision_maker_versions():
    # Claims schema 2.0 but the decision_maker_versions claim is absent
    # (policy does not require it, so the v2 gate itself must fire).
    claims = _v2_claims(au3=_good_au3(), dm=None)
    rc = ["window", "decisions", "evidence_schema_version", "au3_records"]
    _expect_code(
        "neg-missing-decision-maker-versions",
        lambda: _verify_bundle(claims, required_claims=rc),
        "EXTENSION_SCHEMA_INVALID")


def p_neg_missing_au3():
    claims = _v2_claims(au3=None, dm=_good_dm())
    rc = ["window", "decisions", "evidence_schema_version",
          "decision_maker_versions"]
    _expect_code(
        "neg-missing-au3",
        lambda: _verify_bundle(claims, required_claims=rc),
        "EXTENSION_SCHEMA_INVALID")


def p_neg_malformed_au3():
    claims = _v2_claims(au3={"not": "a-list"}, dm=_good_dm())
    _expect_code(
        "neg-malformed-au3",
        lambda: _verify_bundle(claims),
        "EXTENSION_SCHEMA_INVALID")


def p_neg_prompt_change_no_changelog():
    # The system-prompt digest changed but no change-log entry lands on
    # the new digest: the CC8.1 change-log gap must be detected.
    dm = _good_dm(prompt_digest=PROMPT_DIGEST_2)  # digest changed...
    dm["change_log"] = [e for e in dm["change_log"]
                        if e["component"] != "system_prompt"]
    dm["change_log"].append(
        {"changed_at": "2026-10-01T00:00:00Z", "component": "system_prompt",
         "from_version": None, "to_version": "sp-2026-10-01",
         "to_digest": PROMPT_DIGEST, "note": "genesis (stale)"})
    claims = _v2_claims(au3=_good_au3(), dm=dm)
    _expect_code(
        "neg-prompt-change-no-changelog",
        lambda: _verify_bundle(claims),
        "EXTENSION_SCHEMA_INVALID")


def p_pos_honest_nulls():
    # An AU-3 record with null fields is honest (complete: false), not
    # synthesized; the bundle still verifies.
    au3 = _good_au3()
    try:
        rep = _verify_bundle(_v2_claims(au3=au3, dm=_good_dm()))
    except Exception as e:  # noqa: BLE001
        return _record("pos-honest-nulls", "ERROR",
                       "honest-null v2 bundle refused: %r" % (e,))
    if rep.get("verificationResult") != "PASSED":
        return _record("pos-honest-nulls", "BREAK", "did not PASS")
    if au3[1]["complete"] is not False:
        return _record("pos-honest-nulls", "BREAK",
                       "null-field record not marked incomplete")
    _record("pos-honest-nulls", "HELD",
            "null AU-3 fields stay null, marked incomplete, PASSED")


def p_pos_builder_v2_sections():
    # The evidence-bundle builder emits the v2 sections additively behind
    # schema_version="2.0"; the sections sit inside the bundle identity.
    try:
        from tests.keyfixture import scrub_key_env, provision_test_key
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle
    except Exception as e:  # noqa: BLE001
        return _record("pos-builder-v2-sections", "ERROR",
                       "import failed: %r" % (e,))
    restore = scrub_key_env()
    try:
        provision_test_key()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            log = ActionLog(log_path)
            log.append({"event": "tool_call", "tool": "x",
                        "decision": "allow", "principal": "agent:alpha"})
            log.append({"event": "approval_granted",
                        "decision": "approved"})
            dm = {"model": {"name": "synthetic-model",
                            "version": "2026.10.1"},
                  "system_prompt": {"digest_sha256": PROMPT_DIGEST,
                                    "version": "sp-2026-10-01"},
                  "config": {"snapshot_digest_sha256": "ef" * 32,
                             "version": "cfg-2026-10-01"}}
            changelog = [
                {"changed_at": "2026-10-01T00:00:00Z", "component": "model",
                 "from_version": None, "to_version": "2026.10.1",
                 "to_digest": None, "note": "genesis"},
                {"changed_at": "2026-10-01T00:00:00Z",
                 "component": "system_prompt",
                 "from_version": None, "to_version": "sp-2026-10-01",
                 "to_digest": PROMPT_DIGEST, "note": "genesis"},
                {"changed_at": "2026-10-01T00:00:00Z", "component": "config",
                 "from_version": None, "to_version": "cfg-2026-10-01",
                 "to_digest": "ef" * 32, "note": "genesis"},
            ]
            payload = EvidenceBundle(
                log_path, schema_version="2.0", decision_maker=dm,
                decision_maker_change_log=changelog).build()
            meta = payload["bundle_meta"]
            if meta.get("evidence_schema_version") != sv2.EVIDENCE_SCHEMA_V2:
                return _record("pos-builder-v2-sections", "BREAK",
                               "bundle_meta does not claim schema 2.0")
            au3 = payload.get("au3_records")
            dmv = payload.get("decision_maker_versions")
            if not isinstance(au3, list) or len(au3) != 2:
                return _record("pos-builder-v2-sections", "BREAK",
                               "au3_records want 2 records, got %r" % (au3,))
            if not isinstance(dmv, dict):
                return _record("pos-builder-v2-sections", "BREAK",
                               "decision_maker_versions section missing")
            rec0 = au3[0]["au3"]
            if rec0["who"] != "agent:alpha" or rec0["what"] != "tool_call" \
                    or rec0["result"] != "allow":
                return _record("pos-builder-v2-sections", "BREAK",
                               "AU-3 extraction wrong: %r" % (rec0,))
            if au3[1]["complete"] is not False:
                return _record("pos-builder-v2-sections", "BREAK",
                               "second record should be incomplete")
            if dmv["model"]["version"] != "2026.10.1":
                return _record("pos-builder-v2-sections", "BREAK",
                               "decision-maker model version wrong")
    finally:
        restore()
    _record("pos-builder-v2-sections", "HELD",
            "builder emits au3_records + decision_maker_versions at 2.0")


def p_pos_builder_v1_unchanged():
    # schema_version="1.0" (default) output must not gain v2 sections.
    try:
        from tests.keyfixture import scrub_key_env, provision_test_key
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle
    except Exception as e:  # noqa: BLE001
        return _record("pos-builder-v1-unchanged", "ERROR",
                       "import failed: %r" % (e,))
    restore = scrub_key_env()
    try:
        provision_test_key()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            log = ActionLog(log_path)
            log.append({"event": "tool_call", "tool": "x",
                        "decision": "allow"})
            payload = EvidenceBundle(log_path).build()
            if "au3_records" in payload or \
                    "decision_maker_versions" in payload:
                return _record("pos-builder-v1-unchanged", "BREAK",
                               "v1 payload gained v2 sections")
            if payload["bundle_meta"].get("evidence_schema_version") \
                    != "evidence-schema/1.0":
                return _record("pos-builder-v1-unchanged", "BREAK",
                               "v1 schema version changed")
    finally:
        restore()
    _record("pos-builder-v1-unchanged", "HELD",
            "schema-1.0 builder output unchanged (no v2 sections)")


def p_neg_builder_v2_without_decision_maker():
    # Schema 2.0 exists to carry CC8.1 versioning: without
    # decision-maker context the build refuses fail-fast instead of
    # issuing a bundle the verifier could never accept.
    try:
        from tests.keyfixture import scrub_key_env, provision_test_key
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle, EvidenceBundleError
    except Exception as e:  # noqa: BLE001
        return _record("neg-builder-v2-without-decision-maker", "ERROR",
                       "import failed: %r" % (e,))
    restore = scrub_key_env()
    try:
        provision_test_key()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            log = ActionLog(log_path)
            log.append({"event": "tool_call", "tool": "x",
                        "decision": "allow"})
            try:
                EvidenceBundle(log_path, schema_version="2.0").build()
            except EvidenceBundleError:
                _record("neg-builder-v2-without-decision-maker", "HELD",
                        "2.0 without decision_maker refused at build")
            else:
                _record("neg-builder-v2-without-decision-maker", "BREAK",
                        "2.0 bundle issued without decision-maker context")
    finally:
        restore()


def p_pos_builder_to_verifier_roundtrip():
    # End-to-end naming contract: a builder-emitted v2 bundle's sections
    # map 1:1 onto the predicate claims the verifier's v2 gate checks.
    try:
        from tests.keyfixture import scrub_key_env, provision_test_key
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle
    except Exception as e:  # noqa: BLE001
        return _record("pos-builder-to-verifier-roundtrip", "ERROR",
                       "import failed: %r" % (e,))
    restore = scrub_key_env()
    try:
        provision_test_key()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            log = ActionLog(log_path)
            log.append({"event": "tool_call", "tool": "x",
                        "decision": "allow", "principal": "agent:alpha"})
            log.append({"event": "approval_granted",
                        "decision": "approved"})
            dm = {"model": {"name": "synthetic-model",
                            "version": "2026.10.1"},
                  "system_prompt": {"digest_sha256": PROMPT_DIGEST,
                                    "version": "sp-2026-10-01"},
                  "config": {"snapshot_digest_sha256": "ef" * 32,
                             "version": "cfg-2026-10-01"}}
            changelog = [
                {"changed_at": "2026-10-01T00:00:00Z", "component": "model",
                 "from_version": None, "to_version": "2026.10.1",
                 "to_digest": None, "note": "genesis"},
                {"changed_at": "2026-10-01T00:00:00Z",
                 "component": "system_prompt",
                 "from_version": None, "to_version": "sp-2026-10-01",
                 "to_digest": PROMPT_DIGEST, "note": "genesis"},
                {"changed_at": "2026-10-01T00:00:00Z", "component": "config",
                 "from_version": None, "to_version": "cfg-2026-10-01",
                 "to_digest": "ef" * 32, "note": "genesis"},
            ]
            payload = EvidenceBundle(
                log_path, schema_version="2.0", decision_maker=dm,
                decision_maker_change_log=changelog).build()
            claims = {
                "window": "2026-10-04T00:00:00Z",
                "decisions": len(payload["au3_records"]),
                "evidence_schema_version": sv2.EVIDENCE_SCHEMA_V2,
                "au3_records": payload["au3_records"],
                "decision_maker_versions":
                    payload["decision_maker_versions"],
            }
            try:
                rep = _verify_bundle(claims)
            except Exception as e:  # noqa: BLE001
                return _record("pos-builder-to-verifier-roundtrip",
                               "ERROR",
                               "builder-emitted sections refused: %r" % (e,))
            if rep.get("verificationResult") != "PASSED":
                return _record("pos-builder-to-verifier-roundtrip",
                               "BREAK", "round trip did not PASS")
    finally:
        restore()
    _record("pos-builder-to-verifier-roundtrip", "HELD",
            "builder 2.0 sections verify through the v2 gate (naming "
            "contract holds)")


def p_pos_v2_sections_inside_identity():
    # The v2 sections must sit inside the deterministic bundle identity:
    # removing them changes the bundle_id, and the id recomputes.
    try:
        from tests.keyfixture import scrub_key_env, provision_test_key
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle, canonical \
            as _canon_payload
    except Exception as e:  # noqa: BLE001
        return _record("pos-v2-sections-inside-identity", "ERROR",
                       "import failed: %r" % (e,))
    restore = scrub_key_env()
    try:
        provision_test_key()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            log = ActionLog(log_path)
            log.append({"event": "tool_call", "tool": "x",
                        "decision": "allow"})
            dm = {"model": {"name": "m", "version": "v1"},
                  "system_prompt": {"digest_sha256": PROMPT_DIGEST,
                                    "version": "sp-1"},
                  "config": {"snapshot_digest_sha256": "ef" * 32,
                             "version": "cfg-1"}}
            changelog = [
                {"changed_at": "2026-10-01T00:00:00Z", "component": "model",
                 "from_version": None, "to_version": "v1",
                 "to_digest": None, "note": "genesis"},
                {"changed_at": "2026-10-01T00:00:00Z",
                 "component": "system_prompt",
                 "from_version": None, "to_version": "sp-1",
                 "to_digest": PROMPT_DIGEST, "note": "genesis"},
                {"changed_at": "2026-10-01T00:00:00Z", "component": "config",
                 "from_version": None, "to_version": "cfg-1",
                 "to_digest": "ef" * 32, "note": "genesis"},
            ]
            payload = EvidenceBundle(
                log_path, schema_version="2.0", decision_maker=dm,
                decision_maker_change_log=changelog).build()
            import hashlib as _hl
            body = dict(payload)
            body["bundle_meta"] = dict(body["bundle_meta"])
            body["bundle_meta"]["bundle_id"] = None
            recomputed = "EVB-" + _hl.sha256(
                _canon_payload(body)).hexdigest()[:16]
            if recomputed != payload["bundle_meta"]["bundle_id"]:
                return _record("pos-v2-sections-inside-identity", "BREAK",
                               "bundle_id does not recompute")
            stripped = dict(body)
            del stripped["au3_records"]
            del stripped["decision_maker_versions"]
            stripped_id = "EVB-" + _hl.sha256(
                _canon_payload(stripped)).hexdigest()[:16]
            if stripped_id == payload["bundle_meta"]["bundle_id"]:
                return _record("pos-v2-sections-inside-identity", "BREAK",
                               "v2 sections outside the bundle identity")
    finally:
        restore()
    _record("pos-v2-sections-inside-identity", "HELD",
            "v2 sections inside bundle_id identity (seal covers them)")


def p_pos_builder_v1_exact_sections():
    # Schema 1.0 output must be the exact legacy section set with the
    # legacy proves list: no v2 leakage anywhere.
    try:
        from tests.keyfixture import scrub_key_env, provision_test_key
        from gov.log import ActionLog
        from gov.evidence_bundle import EvidenceBundle
    except Exception as e:  # noqa: BLE001
        return _record("pos-builder-v1-exact-sections", "ERROR",
                       "import failed: %r" % (e,))
    restore = scrub_key_env()
    try:
        provision_test_key()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            log = ActionLog(log_path)
            log.append({"event": "tool_call", "tool": "x",
                        "decision": "allow"})
            payload = EvidenceBundle(log_path).build()
            want = {"bundle_meta", "log_slice", "policy", "decisions",
                    "approvals", "citations", "benchmark",
                    "kms_attestation", "retention_manifest", "discovery",
                    "sections_meta", "claim_bounds", "claim_assignment"}
            if set(payload) != want:
                return _record("pos-builder-v1-exact-sections", "BREAK",
                               "v1 section set drifted: %r"
                               % (set(payload) ^ want,))
            proves = payload["claim_bounds"]["proves"]
            if "au3-record-integrity" in proves \
                    or "decision-maker-version-integrity" in proves:
                return _record("pos-builder-v1-exact-sections", "BREAK",
                               "v2 proves tokens leaked into v1 bounds")
    finally:
        restore()
    _record("pos-builder-v1-exact-sections", "HELD",
            "v1 output: exact legacy sections, legacy proves list")


def _green_checks():
    def _rec(pid, verdict, note):
        _record(pid, verdict, note)
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "green check skipped (GOV_SKIP_GREEN=1)")
        return
    # Adjacent suites that touch the bundle builder / offline verifier
    # must stay green (depth-1: children run with GOV_SKIP_GREEN=1).
    green_check.check_unittest(
        _rec, "green-test_evidence_schema_v2", "tests.test_evidence_schema_v2",
        repo=REPO)
    green_check.check_unittest(
        _rec, "green-test_evidence_bundle", "tests.test_evidence_bundle",
        repo=REPO)


_PROBES = [
    ("pin-taxonomy", p_pin_taxonomy),
    ("footer-state", p_footer_state),
    ("verifier-taxonomy-shape", p_verifier_taxonomy_shape),
    ("pos-v2-verifies", p_pos_v2_verifies),
    ("pos-v1-still-verifies", p_pos_v1_still_verifies),
    ("neg-tampered-model-version", p_neg_tampered_model_version),
    ("neg-missing-decision-maker-versions",
     p_neg_missing_decision_maker_versions),
    ("neg-missing-au3", p_neg_missing_au3),
    ("neg-malformed-au3", p_neg_malformed_au3),
    ("neg-prompt-change-no-changelog", p_neg_prompt_change_no_changelog),
    ("pos-honest-nulls", p_pos_honest_nulls),
    ("pos-builder-v2-sections", p_pos_builder_v2_sections),
    ("pos-builder-v1-unchanged", p_pos_builder_v1_unchanged),
    ("neg-builder-v2-without-decision-maker",
     p_neg_builder_v2_without_decision_maker),
    ("pos-builder-to-verifier-roundtrip",
     p_pos_builder_to_verifier_roundtrip),
    ("pos-v2-sections-inside-identity", p_pos_v2_sections_inside_identity),
    ("pos-builder-v1-exact-sections", p_pos_builder_v1_exact_sections),
]

# No open findings expected: every probe must HOLD on the closed tree.
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
