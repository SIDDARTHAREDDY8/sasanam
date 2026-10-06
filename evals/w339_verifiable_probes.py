#!/usr/bin/env python3
"""Wave-339 lane 1 red-first battery: R22 verifiable-only bundle payloads
+ R23 ADAPT (#6363 bench-verify contract, #5948 order-independence).

R22 (Bernstein #6371 STEAL): builders must never emit a bundle containing
a payload the verifier cannot verify, and failure reasons stay out of
artifacts.
  P1a-P1e: ``attach_keyed_bundle`` (gov/oci_referrer.py) must refuse --
  coded ``oci-bundle-not-verifiable`` -- bundles that the keyed-bundle
  verifier (gov/sigstore_bundle.py::open_keyed_bundle) structurally
  refuses: tlogEntries (unverifiable log claims), messageSignature
  alongside the envelope, wrong payloadType, multiple signatures, and a
  missing dsseEnvelope. On the base tree the builder checks only JSON
  shape + mediaType, so all five attach (BREAK).
  P1f: control -- a properly sealed keyed bundle still attaches, and the
  attached bytes pass ``verify_keyed_bundle`` (HELD).
  P2a/P2b: degraded seals must not carry raw exception text in the
  signed manifest: ``unavailable_reason`` is drawn from a bounded
  degradation vocabulary (gov/log.py::inclusion_unavailable_reason).
  On the base tree the raw ``str(exc)`` is sealed (BREAK).

R23 (Bernstein ADAPT menu):
  P3a (#6363 bench-verify contract -> offline-verifier track): every
  ``verify()`` report covers each pipeline stage exactly once -- the
  mandatory stages appear once in ``checks``; every conditional stage
  appears once in ``checks`` XOR ``notVerified`` (never both, never
  neither); ``notVerified`` reasons are non-empty. Probed over a config
  matrix (default, existence_only).
  P4a/P4b (#5948 precedence order-independence): ``_verify_threshold``
  yields identical verified-key sets under both signature-entry insertion
  orders; ``verify_referrer_binding`` selects identically under referrer
  entry permutations.

P9: taxonomy pin 2135/2135/0 sorted-unique on raw literals (the new
``oci-bundle-not-verifiable`` code), footer open none / next F430.

Standalone: fresh TMPDIR per run, green checks enabled, depth-1 (the
green check runs adjacent unit tests with GOV_SKIP_GREEN=1 in the child
env). $0 spend: no network, no paid API calls.
"""

import base64
import hashlib
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_OPEN = ("F476", "F477")  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)

FOOTER_NEXT = "F496"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496



_EXPECTED_BREAKS = set()

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as exc:
        _record(pid, "BREAK", str(exc)[:300])
    except Exception as exc:  # noqa: BLE001
        _record(pid, "ERROR", "%s: %s" % (type(exc).__name__, exc))


def _held(pid, note):
    _record(pid, "HELD", note)


def _tmpd(prefix):
    d = tempfile.mkdtemp(prefix=prefix, dir="/var/tmp")
    return d


# ---------------------------------------------------------------------------
# Shared fixtures.
# ---------------------------------------------------------------------------

_SEED = bytes(range(32))


def _signer():
    from gov.signing import Ed25519Signer
    return Ed25519Signer(_SEED)


_PUB = None


def _pub():
    global _PUB
    if _PUB is None:
        _PUB = _signer().public_key
    return _PUB


BASE = "https://registry.example"
REPO_NAME = "sasanam/evidence"


class _MockRegistry(object):
    """In-memory OCI registry for the caller-supplied transport protocol."""

    def __init__(self):
        self.blobs = {}
        self.manifests = {}

    def __call__(self, request):
        import urllib.parse
        method = request["method"]
        url = request["url"]
        body = request.get("body") or b""
        parts = urllib.parse.urlparse(url)
        path = parts.path
        query = urllib.parse.parse_qs(parts.query)
        prefix = "/v2/" + REPO_NAME + "/"
        assert path.startswith(prefix), path
        rest = path[len(prefix):]
        if method == "POST" and rest == "blobs/uploads/":
            return (202, {"location": prefix + "blobs/uploads/s1"}, b"")
        if method == "PUT" and rest.startswith("blobs/uploads/"):
            dgst = query.get("digest", [None])[0]
            assert dgst and dgst.startswith("sha256:")
            self.blobs[dgst] = bytes(body)
            return (201, {}, b"")
        if method == "PUT" and rest.startswith("manifests/"):
            dgst = rest[len("manifests/"):]
            assert dgst.startswith("sha256:")
            self.manifests[dgst] = bytes(body)
            return (201, {}, b"")
        raise AssertionError("unexpected request %s %s" % (method, path))


def _subject_digest():
    return "sha256:" + hashlib.sha256(b"evidence-bytes").hexdigest()


def _sealed_bundle_bytes():
    from gov import sigstore_bundle as SB
    stmt = {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "a", "digest": {"sha256": "00" * 32}}],
            "predicateType": "https://sasanam.dev/evidence-predicate/v1",
            "predicate": {}}
    bundle = SB.seal_keyed_bundle(json.dumps(stmt).encode(), _signer())
    return json.dumps(bundle).encode()


def _mutate(bundle_bytes, fn):
    obj = json.loads(bundle_bytes.decode())
    fn(obj)
    return json.dumps(obj).encode()


def _expect_attach_refusal(pid, bundle_bytes, why):
    from gov import oci_referrer as OR
    try:
        OR.attach_keyed_bundle(_MockRegistry(), BASE, REPO_NAME,
                               _subject_digest(), bundle_bytes)
    except OR.OCIReferrerRefusal as exc:
        assert exc.code == "oci-bundle-not-verifiable", \
            "wrong code: %r (%s)" % (exc.code, why)
        _held(pid, "refused coded oci-bundle-not-verifiable (%s)" % why)
        return
    raise AssertionError("attached a bundle the verifier cannot verify "
                         "(%s)" % why)


# ---------------------------------------------------------------------------
# P1: builder-side verifiability (R22a).
# ---------------------------------------------------------------------------

@_probe("P1a-tlog-entries")
def _p1a():
    good = _sealed_bundle_bytes()
    bad = _mutate(good, lambda o: o.update(
        {"tlogEntries": [{"logIndex": "1", "integratedTime": "1"}]}))
    _expect_attach_refusal("P1a-tlog-entries", bad,
                           "tlogEntries are unverifiable log claims")


@_probe("P1b-message-signature")
def _p1b():
    good = _sealed_bundle_bytes()
    bad = _mutate(good, lambda o: o.update(
        {"messageSignature": {"signature": "00" * 64}}))
    _expect_attach_refusal("P1b-message-signature", bad,
                           "messageSignature alongside the envelope")


@_probe("P1c-wrong-payload-type")
def _p1c():
    good = _sealed_bundle_bytes()
    def _wrong(o):
        o["dsseEnvelope"]["payloadType"] = "application/x-wrong"
    _expect_attach_refusal("P1c-wrong-payload-type", _mutate(good, _wrong),
                           "payloadType not the keyed evidence type")


@_probe("P1d-two-signatures")
def _p1d():
    good = _sealed_bundle_bytes()
    def _two(o):
        sig = dict(o["dsseEnvelope"]["signatures"][0])
        o["dsseEnvelope"]["signatures"].append(sig)
    _expect_attach_refusal("P1d-two-signatures", _mutate(good, _two),
                           "two signatures (proto MUST is one)")


@_probe("P1e-no-envelope")
def _p1e():
    good = _sealed_bundle_bytes()
    bad = _mutate(good, lambda o: o.pop("dsseEnvelope"))
    _expect_attach_refusal("P1e-no-envelope", bad, "missing dsseEnvelope")


@_probe("P1f-control-roundtrip")
def _p1f():
    from gov import oci_referrer as OR
    from gov import sigstore_bundle as SB
    good = _sealed_bundle_bytes()
    reg = _MockRegistry()
    out = OR.attach_keyed_bundle(reg, BASE, REPO_NAME, _subject_digest(),
                                 good)
    blob = reg.blobs[out["bundle_digest"]]
    assert SB.verify_keyed_bundle(json.loads(blob.decode()), _pub()) \
        is True, "attached bundle does not verify consumer-side"
    _held("P1f-control-roundtrip",
          "well-formed bundle attaches; consumer verify_keyed_bundle True")


# ---------------------------------------------------------------------------
# P2: failure reasons redacted from artifacts (R22b).
# ---------------------------------------------------------------------------

_VOCAB = {"no-covering-checkpoint", "checkpoint-root-mismatch",
          "log-integrity-failure", "proof-unavailable"}


def _degraded_manifest_reasons(manifest):
    reasons = []
    for b in manifest.get("inclusion_bundles", []):
        if b.get("bundle") is None:
            reasons.append(b.get("unavailable_reason"))
    return reasons


def _check_vocab(pid, reasons, where):
    import gov.log as _log
    assert reasons, "expected degraded entries, got none (%s)" % where
    for r in reasons:
        assert isinstance(r, str) and r in _VOCAB, \
            "reason %r not in bounded vocabulary (%s)" % (r, where)
        assert "seq" not in r and "ValueError" not in r, \
            "raw failure detail leaked: %r" % (r,)
    # The raising module owns the vocabulary: every _inclusion_material
    # failure shape maps to a code, never raw text.
    cases = [
        (ValueError("no signed checkpoint covers seq 3"),
         "no-covering-checkpoint"),
        (ValueError("checkpoint@7 merkle_root does not match the log; "
                    "refusing to prove"),
         "checkpoint-root-mismatch"),
        (ValueError("log seq not dense at position 0"),
         "log-integrity-failure"),
        (ValueError("seq 99 out of range"), "proof-unavailable"),
        (ValueError("some future message"), "proof-unavailable"),
    ]
    for exc, want in cases:
        got = _log.inclusion_unavailable_reason(exc)
        assert got == want, \
            "inclusion_unavailable_reason(%r) = %r, want %r" \
            % (str(exc), got, want)
        assert got in _VOCAB
    # Consumer-side downgrade: the verifier names only what it can verify.
    assert _log.name_inclusion_reason(None) is None
    assert _log.name_inclusion_reason("no-covering-checkpoint") == \
        "no-covering-checkpoint"
    assert _log.name_inclusion_reason("no signed checkpoint covers seq 1") \
        == "proof-unavailable"
    # The standalone verifier vendors the vocabulary (it runs without the
    # engine); the two sets must stay equal.
    import gov.evidence_verify as _ev
    assert _ev._INCLUSION_UNAVAILABLE_REASONS == \
        _log.INCLUSION_UNAVAILABLE_REASONS, \
        "vendored vocabulary drifted from gov/log.py"
    _held(pid, "%d degraded reason(s) in bounded vocabulary (%s)"
          % (len(reasons), where))


def _hmac_log(path):
    from gov.log import ActionLog
    log = ActionLog(path)  # no signer: HMAC-only, no signed checkpoints
    log.append({"event": "tool_call", "tool": "read_file",
                "decision": "allow"})
    log.append({"event": "tool_call", "tool": "send_email",
                "decision": "deny"})
    return log


def _hmac_incident_log(path):
    from gov.log import ActionLog
    log = ActionLog(path)  # no signer: HMAC-only, no signed checkpoints
    log.append({"event": "tool_call", "agent_id": "agent-1",
                "run_id": "run-9", "tool": "read_file",
                "decision": "allow", "policy_id": "p-default"})
    log.append({"event": "detector_trip", "agent_id": "monitor",
                "run_id": "run-9", "decision": "escalated",
                "policy_id": "detection-breaker",
                "reason": "velocity breaker tripped"})
    log.append({"event": "lineage_quarantine", "agent_id": "agent-7",
                "run_id": "run-9", "decision": "quarantined",
                "policy_id": "infection-monitor",
                "reason": "quarantined origin lineage"})
    return log


@_probe("P2a-bundle-reason-vocabulary")
def _p2a():
    from tests.keyfixture import provision_test_key, scrub_key_env
    from gov.evidence_bundle import EvidenceBundle
    from gov.signing import Ed25519Signer
    import secrets
    restore = scrub_key_env()
    provision_test_key()
    d = _tmpd("w339p2a-")
    try:
        log_path = os.path.join(d, "audit.log")
        _hmac_log(log_path)
        eb = EvidenceBundle(log_path)
        payload = eb.build()
        manifest = eb.seal(payload,
                           signer=Ed25519Signer(secrets.token_bytes(32)))
        _check_vocab("P2a-bundle-reason-vocabulary",
                     _degraded_manifest_reasons(manifest),
                     "evidence_bundle seal")
    finally:
        restore()


@_probe("P2b-exports-reason-vocabulary")
def _p2b():
    from tests.keyfixture import provision_test_key, scrub_key_env
    from gov.evidence_exports import IncidentReport
    from gov.signing import Ed25519Signer
    import secrets
    restore = scrub_key_env()
    provision_test_key()
    d = _tmpd("w339p2b-")
    try:
        log_path = os.path.join(d, "audit.log")
        _hmac_incident_log(log_path)
        gen = IncidentReport(log_path)
        report = gen.build()
        manifest = gen.seal(report,
                            signer=Ed25519Signer(secrets.token_bytes(32)))
        _check_vocab("P2b-exports-reason-vocabulary",
                     _degraded_manifest_reasons(manifest),
                     "evidence_exports seal")
    finally:
        restore()


# ---------------------------------------------------------------------------
# P3: bench-verify contract on the offline verifier report (#6363).
# ---------------------------------------------------------------------------

_MANDATORY_STAGES = {"parse", "payloadType", "signature", "statement",
                      "predicate", "digest", "subject", "policy", "transcript"}
# Stages the pipeline may skip depending on the run configuration. Each
# appears AT MOST once per report: in ``checks`` when evaluated, in
# ``notVerified`` when bypassed -- never both. A skippable stage may
# also be absent (not applicable to the configuration); absence is
# pinned per configuration in the expected-skipped sets below, so a
# stage silently disappearing from both lists goes red.
_SKIPPABLE_STAGES = {"trust-chain", "trust-chain-expiry", "witness",
                     "witness-consistency", "predicate-content",
                     "schema-2.0-extension"}


def _good_vb():
    import base64 as _b64
    from datetime import datetime, timedelta, timezone
    from gov import ed25519
    from gov import evidence_verify_offline as v
    NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
    EV_SEED = "11" * 32
    TSA_SEED = "22" * 32
    ANCHOR_SEED = ("02eb4cee77eb9c934286078d60f8960f6a038a6c9b04906d940"
                   "ed521de3fa3b6")
    BUNDLE_BYTES = b'{"evidence":"w339-bench-verify"}\n'
    PREDICATE_TYPE = "https://sasanam.dev/evidence-predicate/v1"

    def _signer(seed_hex):
        seed = bytes.fromhex(seed_hex)
        pub = ed25519.publickey(seed)
        keyid = hashlib.sha256(pub).hexdigest()[:16]

        class _S(object):
            def keyid(self):
                return keyid

            def pubkey_hex(self):
                return pub.hex()

            def sign(self, msg):
                return ed25519.sign(seed, msg)
        return _S()

    def _seal(payload, ptype, signers):
        msg = v.pae(ptype, payload)
        return {
            "payload": _b64.b64encode(payload).decode("ascii"),
            "payloadType": ptype,
            "signatures": [
                {"keyid": s.keyid(),
                 "sig": _b64.b64encode(s.sign(msg)).decode("ascii")}
                for s in signers],
        }

    ev, tsa, anchor = (_signer(EV_SEED), _signer(TSA_SEED),
                       _signer(ANCHOR_SEED))
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin",
                     "digest": {"sha256": hashlib.sha256(BUNDLE_BYTES)
                                .hexdigest()}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {"window": "2026-10-03T00:00:00Z"},
    }
    payload = v.canonical(stmt)
    policy = {
        "version": "sasanam-verification-policy/v1",
        "policy_id": "w339-bench-verify",
        "expires": (NOW + timedelta(days=10))
                   .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "required_predicate_type": PREDICATE_TYPE,
        "required_predicate_claims": ["window"],
        "evidence_signing": {
            "threshold": 1,
            "keys": [{"keyid": ev.keyid(), "pubkey_hex": ev.pubkey_hex()}],
        },
        "observer_timestamps": {"min": 0, "max_age_hours": 168},
        "timestamp_authorities": [
            {"authority_id": tsa.keyid(), "pubkey_hex": tsa.pubkey_hex(),
             "valid_for": {
                 "not_before": (NOW - timedelta(days=30))
                              .strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "not_after": (NOW + timedelta(days=30))
                              .strftime("%Y-%m-%dT%H:%M:%SZ")}}],
    }
    vb = {
        "version": v.BUNDLE_VERSION,
        "envelope": _seal(payload, v.ENVELOPE_PAYLOAD_TYPE, [ev]),
        "policy": _seal(v.canonical(policy), v.POLICY_PAYLOAD_TYPE,
                        [anchor]),
        "timestamps": [],
    }
    return v, vb, BUNDLE_BYTES, NOW


def _check_stage_contract(pid, report, config_name, expect_skipped):
    # #6363 bench-verify contract, adapted: one result per stage. The
    # report is the benchmark's verdict sheet -- a duplicated stage
    # could hide a failure, a missing stage could hide a blind spot.
    checks = report["checks"]
    steps = [c["step"] for c in checks]
    assert len(steps) == len(set(steps)), \
        "duplicate stage results in checks (%s): %s" % (config_name, steps)
    for s in _MANDATORY_STAGES:
        assert steps.count(s) == 1, \
            "mandatory stage %r not exactly once in checks (%s)" \
            % (s, config_name)
    skipped = {e["stage"]: e["reason"]
               for e in report.get("notVerified") or []}
    assert len(skipped) == len(report.get("notVerified") or []), \
        "duplicate notVerified stage (%s)" % config_name
    for stage, reason in skipped.items():
        assert isinstance(reason, str) and reason.strip(), \
            "empty bypass reason for %r (%s)" % (stage, config_name)
    for s in _SKIPPABLE_STAGES:
        in_checks = s in steps
        in_skipped = s in skipped
        assert not (in_checks and in_skipped), \
            "skippable stage %r in BOTH checks and notVerified (%s)" \
            % (s, config_name)
    assert set(skipped) == set(expect_skipped), \
        "skipped-stage set mismatch (%s): got %s, want %s" \
        % (config_name, sorted(skipped), sorted(expect_skipped))


@_probe("P3a-bench-verify-contract")
def _p3a():
    v, vb, bb, now = _good_vb()
    rep = v.verify(bb, vb, time_source=v.FixedClock("t", now))
    assert rep["verificationResult"] == "PASSED"
    _check_stage_contract("P3a", rep, "default",
                          {"trust-chain", "trust-chain-expiry", "witness",
                           "witness-consistency", "schema-2.0-extension"})
    rep2 = v.verify(bb, vb, time_source=v.FixedClock("t", now),
                    existence_only=True)
    assert rep2["verificationResult"] == "PASSED"
    assert rep2["existenceOnly"] is True
    _check_stage_contract("P3a", rep2, "existence_only",
                          {"trust-chain", "trust-chain-expiry", "witness",
                           "witness-consistency", "predicate-content"})
    _held("P3a-bench-verify-contract",
          "default + existence_only reports: mandatory stages exactly once "
          "in checks, skippable stages at most once, no duplicates, "
          "bypass reasons non-empty")


# ---------------------------------------------------------------------------
# P4: order-independence (#5948).
# ---------------------------------------------------------------------------

@_probe("P4a-threshold-insertion-order")
def _p4a():
    from gov import ed25519
    from gov import evidence_verify_offline as v
    seeds = [bytes([i + 1]) * 32 for i in range(3)]
    pubs = {("k%d" % i): ed25519.publickey(s) for i, s in enumerate(seeds)}
    raw = b'{"order":"test"}'
    pae_bytes = v.pae(v.ENVELOPE_PAYLOAD_TYPE, raw)
    sigs = [("k%d" % i, ed25519.sign(seeds[i], pae_bytes)) for i in range(3)]
    # NOTE: _verify_threshold PAEs internally; pass the RAW payload, not
    # the PAE bytes (double-PAE fails every signature).
    first = v._verify_threshold(raw, v.ENVELOPE_PAYLOAD_TYPE, list(sigs),
                                pubs, 2, "ENVELOPE_SIGNATURE_INVALID")
    for perm in itertools.permutations(sigs):
        got = v._verify_threshold(raw, v.ENVELOPE_PAYLOAD_TYPE, list(perm),
                                  pubs, 2, "ENVELOPE_SIGNATURE_INVALID")
        assert set(got) == set(first), \
            "insertion order changed verified KEY SET: %r vs %r" \
            % (got, first)
    assert set(first) == {"k0", "k1", "k2"}, first
    _held("P4a-threshold-insertion-order",
          "6 permutations -> identical verified-key set %r (list order "
          "follows input order by construction)" % (sorted(first),))


@_probe("P4b-referrer-selection-order")
def _p4b():
    from gov import oci_referrer as OR
    subj = _subject_digest()
    other = "sha256:" + "ab" * 32
    entries = [
        {"digest": "sha256:" + "%02x" % i * 32,
         "artifactType": OR.BUNDLE_ARTIFACT_TYPE,
         "subject": {"digest": subj}}
        for i in range(3)
    ] + [
        {"digest": other, "artifactType": "application/x-other",
         "subject": {"digest": subj}},
    ]
    first = OR.verify_referrer_binding({"referrers": list(entries)}, subj)
    first_digests = [e["digest"] for e in first]
    for perm in itertools.permutations(entries):
        got = OR.verify_referrer_binding({"referrers": list(perm)}, subj)
        assert sorted(e["digest"] for e in got) == sorted(first_digests), \
            "entry order changed selection"
    assert len(first) == 3, first_digests
    _held("P4b-referrer-selection-order",
          "24 permutations -> identical 3-descriptor selection")


# ---------------------------------------------------------------------------
# P9: pin + footer.
# ---------------------------------------------------------------------------

@_probe("P9-pin-taxonomy")
def _p9():
    from gov import decision_codes as DC
    assert len(DC.TAXONOMY) == TAXONOMY_PIN, \
        "want %d, got %d" % (TAXONOMY_PIN, len(DC.TAXONOMY))
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    literals = re.findall(r'"code": \'([A-Za-z0-9][A-Za-z0-9\-_.]*)\'', src)
    assert len(literals) == len(set(literals)) == TAXONOMY_PIN, \
        "taxonomy not sorted-unique on raw literals"
    assert literals == sorted(literals), "taxonomy not sorted"
    assert "oci-bundle-not-verifiable" in DC.TAXONOMY
    text = open(os.path.join(REPO, "evals", "FINDINGS.md")).read()
    assert "Next free finding: **F496**" in text, "footer next free"  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481)
    assert "Open findings: F482, F483, F484, F485, F486, F487, F488." in text, "footer open findings"
    assert FOOTER_OPEN == ("F476", "F477") and FOOTER_NEXT == "F478"  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)
    _held("P9-pin-taxonomy",
          "2135/2135/0 sorted-unique; oci-bundle-not-verifiable "
          "registered; footer open none / next F430")


def _run_child_output(args, timeout):
    d = _tmpd("w339-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: adjacent unit tests as children with
    GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by recording
    a skip, never spawning."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    for mod in ("tests.test_oci_referrer",
                "tests.test_evidence_verify_offline",
                "tests.test_evidence_bundle"):
        try:
            rc, out = _run_child_output(
                [sys.executable, "-m", "unittest", mod, "-v"], timeout=900)
        except Exception as exc:  # noqa: BLE001
            _record("green-check", "ERROR", "%s: %s" % (mod, exc))
            return
        bad = re.findall(r"^(FAIL|ERROR):", out, re.M)
        if rc != 0 or bad or "OK" not in out:
            _record("green-check", "BREAK",
                    "%s non-green rc=%d: %s" % (mod, rc, out[-400:]))
            return
    _record("green-check", "HELD",
            "test_oci_referrer + test_evidence_verify_offline + "
            "test_evidence_bundle green")


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w339_verifiable battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
