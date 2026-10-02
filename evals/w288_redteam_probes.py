"""Wave-288 independent red-team battery: attack the wave-287 merge.

Base: wave-287 push add3e92aa02e68daf6a2288c302a27fd3dfa4690
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (from the wave-287 merge report):
  (a) gov/timestamp_authority.py -- RFC 3161-subset TSA: genTime
      validation at the claimed time, nonce request binding,
      FirstObservedLedger backdate detection, countersign-over-
      signature messageImprint, single-seed TSA (documented), TSA
      key compromise = total time forgery (documented boundary).
  (b) gov/evidence_provenance.py -- BuildKit-pattern provenance:
      builder.id allowlist, completeness marking, unsigned-envelope
      refusal at the anchor gate, claim-about-another-artifact
      binding, GUAC HasSLSA structural edges.
  (c) gov/trust_vector.py -- veraison-pattern EAR appraisal:
      endorsement independence, scheme plugin registry, worst-wins
      vector, require_affirmed (contraindicated never upgradable),
      live-exception at-risk acceptance.
  (d) F334-F342 closure surfaces (OPEN at base: expected-open;
      F338 and F339 are MEDIUM).

Re-pins at the public seams:
  F311 (CLOSED) -- w283_f311_probes.py: 0 BREAK expected.
  F312-F315 (CLOSED) -- w283_redteam_probes.py: 0 BREAK expected;
      w284_f312_315_probes.py: 0 BREAK expected.
  F316-F324 (CLOSED) -- w284_redteam_probes.py: 0 BREAK expected.
  F325-F330 (CLOSED) -- w286_*_probes.py: 0 BREAK expected.
  F331-F333 (CLOSED) -- w287_f33*_probes.py: 0 BREAK expected.
  F334-F342 (OPEN) -- w287_redteam_probes.py: 10 BREAK expected-open.

New findings filed (all LOW, OPEN): F343-F345.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g288-redteam && TMPDIR=/var/tmp/g288-redteam \
    ~/workspace/.gov-venv/bin/python evals/w288_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g288-redteam2 \
    ~/workspace/.gov-venv/bin/python evals/w288_redteam_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance
# +10 trustvec-*).
TAXONOMY_PIN = 1730

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


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
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


# ---------------------------------------------------------------------------
# Re-pins: run the earlier batteries as subprocesses (depth-1, no nesting)
# and check their verdict counts against the expected post-wave-287 state.
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # (battery, expected_breaks, label)
    ("evals/w283_f311_probes.py", 0, "f311-closed"),
    ("evals/w283_redteam_probes.py", 0, "f312-315-closed"),
    ("evals/w284_f312_315_probes.py", 0, "f312-315-closed-b"),
    ("evals/w284_redteam_probes.py", 0, "f316-324-closed"),
    ("evals/w286_f325_probes.py", 0, "f325-closed"),
    ("evals/w286_f326_probes.py", 0, "f326-closed"),
    ("evals/w286_f327_f328_probes.py", 0, "f327-328-closed"),
    ("evals/w286_f329_f330_probes.py", 0, "f329-330-closed"),
    ("evals/w287_f331_probes.py", 0, "f331-closed"),
    ("evals/w287_f332_probes.py", 0, "f332-closed"),
    ("evals/w287_f333_probes.py", 0, "f333-closed"),
    # Wave-288 merge: F334-F342 all CLOSED (lanes 1-4) -> 0 BREAK expected.
    ("evals/w287_redteam_probes.py", 0, "f334-342-closed"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w288-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=900,
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
# F343 (LOW): RULE_OPERATOR_TRUST affirms on a producer_id string match.
# compile_policy requires trust_anchors to map producer id -> key id,
# implying key-pinned trust, but no signature exists anywhere in the
# evidence model and _grade_dimension checks only
# ``evidence.producer_id in policy.trust_anchors``. The pinned key ids
# are decoration: rotating a key changes nothing, and a claimant needs
# no key at all to be "affirmed". The module's honest-limitations
# block does not disclose that operator-trust is name-only.
# ---------------------------------------------------------------------------

def _f343_scheme():
    from gov import trust_vector as tv
    scheme_id = "w288.operator-trust"
    if scheme_id not in tv.registered_schemes():
        tv.register_scheme(tv.SchemeDescriptor(
            scheme_id, {"fw": "str"},
            [{"name": "firmware", "rule": "operator-trust",
              "claims": ["fw"]}]))
    return scheme_id


def p_f343_operator_trust_name_only():
    from gov import trust_vector as tv
    scheme_id = _f343_scheme()
    # F343 closed wave-289 lane 1: the key-implying trust_anchors field
    # refuses LOUD (coded trustvec-policy-invalid) at compile time; the
    # contract is now the honest trusted_producers name-allowlist.
    try:
        tv.compile_policy(
            {"format": tv.POLICY_FORMAT, "policy_id": "w288p1",
             "scheme_id": scheme_id,
             "trust_anchors": {"prodA": "keyid-AAAAAAAAAAAAAAAA"}})
    except tv.TrustVectorError as e:
        if e.code == tv.POLICY_INVALID:
            return _record("f343-operator-trust-name-only", "HELD",
                           "old trust_anchors field refuses LOUD coded "
                           "%s; trusted_producers name-allowlist is the "
                           "documented contract" % (e.code,))
        return _record("f343-operator-trust-name-only", "BREAK",
                       "old field refuses but with unexpected code %s"
                       % (e.code,))
    pol = tv.compile_policy(
        {"format": tv.POLICY_FORMAT, "policy_id": "w288p1",
         "scheme_id": scheme_id,
         "trusted_producers": {"prodA": "release-authority"}})
    # No signatures exist in this module: the producer is a bare
    # string and affirmation is a name-allowlist match (documented
    # in the module's honest-limitations block).
    ev = tv.submit_evidence(scheme_id, {"fw": "1.0"}, "prodA")
    d = tempfile.mkdtemp(prefix="w288-f343-")
    pinpath = os.path.join(d, "pins.json")
    tv.pin_appraisal_policy("w288p1", pol.digest, pinpath)
    pins = tv.load_appraisal_pins(pinpath)
    ear = tv.appraise(ev, [], pol, pins)
    if (ear["overall"] == "affirmed"
            and ear["vector"].get("firmware") == "affirmed"):
        return _record("f343-operator-trust-name-only", "BREAK",
                       "operator-trust affirmed on a producer_id string "
                       "match; the pinned key ids in trust_anchors are "
                       "never consulted (no signature exists in the "
                       "evidence model) -- key rotation is theater")
    _record("f343-operator-trust-name-only", "HELD",
            "trusted_producers name-allowlist affirms; the old "
            "key-implying trust_anchors field refuses LOUD at compile")


# ---------------------------------------------------------------------------
# F344 (LOW): non-JSON-serializable claim values inside list/dict claims
# escape submit_evidence (and _digest_value in endorse/_grade_dimension)
# as an uncoded TypeError. The scheme grammar allows "list"/"dict"
# with arbitrary contents, but _canonical has no default=str, so a set
# nested in a claim raises TypeError with no machine code.
# F327/F331/F342 class: the all-refusals-coded contract.
# ---------------------------------------------------------------------------

def p_f344_nonjson_claim_uncoded():
    from gov import trust_vector as tv
    scheme_id = "w288.nonjson"
    if scheme_id not in tv.registered_schemes():
        tv.register_scheme(tv.SchemeDescriptor(
            scheme_id, {"items": "list"}, []))
    try:
        tv.submit_evidence(scheme_id, {"items": [{"s": {1, 2}}]}, "prodB")
    except TypeError as e:
        if getattr(e, "code", None) is None:
            return _record("f344-nonjson-claim", "BREAK",
                           "raw TypeError escapes submit_evidence for "
                           "non-JSON-serializable claim values -- "
                           "expected coded trustvec-evidence-invalid")
        return _record("f344-nonjson-claim", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f344-nonjson-claim", "HELD",
                       "coded refusal: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f344-nonjson-claim", "BREAK",
            "non-JSON claim silently accepted")


# ---------------------------------------------------------------------------
# F345 (LOW): evidence_provenance._emit does not isolate audit-sink
# failures. A raising sink escapes verify_provenance (and
# record_provenance_in_graph) as the sink's own uncoded exception
# type. timestamp_authority documents the swallow trade-off and
# governed_exceptions records instead of failing loud; this module
# propagates, turning a VERIFIED claim into an uncoded error.
# ---------------------------------------------------------------------------

def p_f345_sink_exception_uncoded():
    from gov import evidence_provenance as ep
    from gov import ed25519
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    pol = ep.BuilderPolicy("w288pol", {"b1": pub})
    digest = "ab" * 32
    claim = ep.make_provenance_claim(
        "b1", "k1", digest,
        [{"uri": "u", "digest": digest, "completeness": "verified"}])
    envelope = ep.seal_provenance(claim, seed)

    def bad_sink(evt):
        raise RuntimeError("sink is down")

    ep.set_emit(bad_sink)
    try:
        ep.verify_provenance(envelope, pol)
    except RuntimeError as e:
        if getattr(e, "code", None) is None:
            return _record("f345-sink-uncoded", "BREAK",
                           "broken audit sink raises uncoded RuntimeError "
                           "out of verify_provenance -- _emit does not "
                           "isolate sink failures")
        return _record("f345-sink-uncoded", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f345-sink-uncoded", "HELD",
                       "coded refusal: %s"
                       % getattr(e, "code", type(e).__name__))
    else:
        _record("f345-sink-uncoded", "HELD",
                "sink failure isolated from verification")
    finally:
        ep.set_emit(None)


# ---------------------------------------------------------------------------
# Depth-1 green checks: the wave-287 lane batteries must stay all-HELD.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w287_tsa_probes.py",
        "evals/w287_provenance_probes.py",
        "evals/w287_ear_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w288-green-")
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
    p_taxonomy_pin()
    _run_repins()
    p_f343_operator_trust_name_only()
    p_f344_nonjson_claim_uncoded()
    p_f345_sink_exception_uncoded()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w288_redteam: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
