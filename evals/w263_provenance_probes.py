"""Break-first probes for admission-time provenance policy (wave-263 lane 3).

slsa-verifier D3 ADAPT: a provenance-policy CONSUMER for our evidence
bundles and gate artifacts — (source, builder, tag) policy evaluated
against a provenance statement at ADMISSION time; verify_and_emit()
(the --print-provenance idea) outputs the VERIFIED statement for
downstream policy; VSA as the delegated-verification statement for
gate re-runs.

Red-first: on the pristine base these probes GAP (no provenance-policy
consumer exists — see RED_RUN.log). Post-fix they must all HELD, in
BOTH deployment modes (staging default below; prod via
`env -u GOV_DEPLOYMENT_MODE`).

Probe shapes (task): provenance with swapped builder id, VSA scope
mismatch (P vs Q), expired VSA, unpinned-verifier VSA, empty-source
policy admitting nothing, missing required provenance fields,
statement-signature tampering, and the taxonomy pin.

Stdlib only. No network, no in-repo git subprocesses. Green check is
depth-1 and honors GOV_SKIP_GREEN=1.
"""

import copy
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

TAXONOMY_PIN = 2021 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 1: pin 2020 -> 2021 (+1 witness-alert-state-lost)



sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import gov.decision_codes as dc
import gov.provenance_policy as pp

BUILDER_A = ("https://github.com/SIDDARTHAREDDY8/sasanam/"
             ".github/workflows/build.yml@v1")
BUILDER_B = "https://evil.example.net/.github/workflows/build.yml@v1"
SOURCE = "git@github.com:SIDDARTHAREDDY8/sasanam"
SOURCE_HEX = "a" * 64  # stand-in source digest (commit sha256 hex)
SIGNER_SEED = b"w263-provenance-signer-a-0000000"  # 32 bytes
EVIL_SEED = b"w263-provenance-signer-b-0000000"     # 32 bytes
VERIFIER_ID = "gate-registry"
VERIFIER_SEED = b"w263-provenance-verifier-0000000"  # 32 bytes


def _signer_pubkeys():
    return {pp.key_id_hex(pp.ed25519_publickey(SIGNER_SEED)):
            pp.ed25519_publickey(SIGNER_SEED).hex()}


def _policy(name="gate-artifact-admission", **kw):
    base = {
        "name": name,
        "version": 1,
        "sources": {"allowed": [SOURCE, "sha256:" + SOURCE_HEX]},
        "builders": {"allowed": [BUILDER_A]},
        "tags": {"mode": "versioned-tag", "semver": ">=0.9.0,<1.0.0",
                 "required": True},
        "require_signed_statement": True,
        "statement_signers": _signer_pubkeys(),
        "trusted_verifiers": {
            VERIFIER_ID: pp.ed25519_publickey(VERIFIER_SEED).hex()},
        "vsa_max_age_seconds": 86400,
        "vsa_required_level": "SLSA_BUILD_LEVEL_3",
    }
    base.update(kw)
    return pp.ProvenancePolicy.from_dict(base)


def _statement(builder=BUILDER_A, tag="v0.9.1", source=SOURCE,
               digest="b" * 64, seed=SIGNER_SEED, drop=(),
               subject_digest="c" * 64):
    st = {
        "format": "sasanam-provenance-statement/1",
        "subject": {"name": "gate-artifact-bundle.zip",
                    "digest": {"sha256": subject_digest}},
        "predicate": {
            "source": {"uri": source,
                       "digest": {"sha256": SOURCE_HEX}},
            "builder": {"id": builder},
            "tag": tag,
            "inputs": {"policy_digest": "sha256:" + "d" * 64},
        },
    }
    for path in drop:
        node = st
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    pp.sign_statement(st, seed)
    return st


def _expect(probe, fn, want_code):
    try:
        fn()
    except pp.ProvenancePolicyError as e:
        if e.code == want_code:
            return True, "HELD (%s)" % want_code
        return False, "GAP: code %s, wanted %s" % (e.code, want_code)
    return False, "GAP: no refusal (wanted %s)" % want_code


def p_swapped_builder():
    """A validly-signed statement from the WRONG builder must refuse.

    The signature is genuine (the PINNED signer asserts a foreign
    builder id) — the policy checks provenance CLAIMS, it does not
    make them true. A wholly unpinned signer never even reaches claim
    evaluation.
    """
    pol = _policy()
    st = _statement(builder=BUILDER_B, seed=SIGNER_SEED)
    ok, why = _expect("swapped-builder",
                      lambda: pol.admit(st,
                                        expected_subject_digest="c" * 64),
                      "provenance-builder-refused")
    if not ok:
        return False, why
    evil = _statement(builder=BUILDER_B, seed=EVIL_SEED)
    ok, why = _expect("unpinned-signer",
                      lambda: pol.admit(evil,
                                        expected_subject_digest="c" * 64),
                      "provenance-statement-unverified")
    if not ok:
        return False, why
    return True, ("HELD (foreign-builder claim refused; unpinned "
                  "signer refused at signature layer)")


def p_vsa_scope_mismatch():
    """A VSA issued for policy P must never admit under policy Q."""
    iss = pp.VSAIssuer(VERIFIER_ID, VERIFIER_SEED)
    vsa = iss.issue(subject_digest="c" * 64,
                    policy_id="gate-artifact-admission",
                    verified_level="SLSA_BUILD_LEVEL_3",
                    issued_at=1000.0, ttl_seconds=3600)
    pol_q = _policy(name="other-policy")
    return _expect("vsa-scope",
                   lambda: pol_q.admit_vsa(vsa, "other-policy",
                                           "c" * 64, now=1100.0),
                   "provenance-vsa-refused")


def p_expired_vsa():
    """A VSA past its TTL must be refused even from a pinned verifier."""
    iss = pp.VSAIssuer(VERIFIER_ID, VERIFIER_SEED)
    vsa = iss.issue(subject_digest="c" * 64,
                    policy_id="gate-artifact-admission",
                    verified_level="SLSA_BUILD_LEVEL_3",
                    issued_at=1000.0, ttl_seconds=100)
    pol = _policy()
    return _expect("vsa-expired",
                   lambda: pol.admit_vsa(vsa, "gate-artifact-admission",
                                        "c" * 64, now=2000.0),
                   "provenance-vsa-refused")


def p_unpinned_verifier_vsa():
    """A VSA signed by a valid-but-unpinned key must be refused."""
    evil_iss = pp.VSAIssuer("rogue-verifier", EVIL_SEED)
    vsa = evil_iss.issue(subject_digest="c" * 64,
                         policy_id="gate-artifact-admission",
                         verified_level="SLSA_BUILD_LEVEL_3",
                         issued_at=1000.0, ttl_seconds=3600)
    pol = _policy()
    return _expect("vsa-unpinned",
                   lambda: pol.admit_vsa(vsa, "gate-artifact-admission",
                                        "c" * 64, now=1100.0),
                   "provenance-vsa-refused")


def p_empty_source_policy():
    """A policy with no allowed sources admits NOTHING (never vacuous)."""
    # construction itself refuses: the policy cannot exist
    try:
        pp.ProvenancePolicy.from_dict({
            "name": "vacuous", "version": 1,
            "sources": {"allowed": []},
            "builders": {"allowed": [BUILDER_A]},
        })
        return False, "GAP: empty-source policy constructed"
    except pp.ProvenancePolicyError as e:
        if e.code != "provenance-policy-vacuous":
            return False, "GAP: wrong code %s" % e.code
    # a missing sources section is the same shape of gap
    try:
        pp.ProvenancePolicy.from_dict({
            "name": "vacuous2", "version": 1,
            "builders": {"allowed": [BUILDER_A]},
        })
        return False, "GAP: sourceless policy constructed"
    except pp.ProvenancePolicyError as e:
        if e.code != "provenance-policy-vacuous":
            return False, "GAP: wrong code %s" % e.code
    return True, "HELD (vacuous policy refused at construction)"


def p_missing_provenance_fields():
    """Statements missing fields the policy requires must refuse."""
    pol = _policy()
    st = _statement(drop=(("predicate", "source"),))
    ok, why = _expect("missing-source",
                      lambda: pol.admit(st), "provenance-source-refused")
    if not ok:
        return False, why
    st = _statement(drop=(("predicate", "builder"),))
    ok, why = _expect("missing-builder",
                      lambda: pol.admit(st), "provenance-builder-refused")
    if not ok:
        return False, why
    st = _statement(tag=None)
    ok, why = _expect("missing-tag",
                      lambda: pol.admit(st), "provenance-tag-refused")
    if not ok:
        return False, why
    st = _statement(drop=(("subject",),))
    ok, why = _expect("missing-subject",
                      lambda: pol.admit(st), "provenance-subject-refused")
    if not ok:
        return False, why
    return True, "HELD (missing source/builder/tag/subject all refuse)"


def p_statement_tamper():
    """A statement with a tampered post-signing field must not verify."""
    pol = _policy()
    st = _statement()
    st["predicate"]["tag"] = "v9.9.9"  # tamper after signing
    ok, why = _expect("tampered",
                      lambda: pol.admit(st), "provenance-statement-unverified")
    if not ok:
        return False, why
    # verify_and_emit must also refuse, and must NOT emit bytes
    try:
        pp.verify_and_emit(st, _signer_pubkeys())
        return False, "GAP: verify_and_emit emitted a tampered statement"
    except pp.ProvenancePolicyError as e:
        if e.code != "provenance-statement-unverified":
            return False, "GAP: wrong code %s" % e.code
    # the genuine statement verifies AND emits stable canonical bytes
    good = _statement()
    blob1 = pp.verify_and_emit(good, _signer_pubkeys())
    blob2 = pp.verify_and_emit(good, _signer_pubkeys())
    if blob1 != blob2 or json.loads(blob1)["predicate"]["tag"] != "v0.9.1":
        return False, "GAP: emitted statement unstable or mangled"
    return True, "HELD (tamper refused; genuine emits stable bytes)"


def p_verify_emit_piping():
    """The --print-provenance shape: verified bytes pipe into policy."""
    pol = _policy()
    st = _statement()
    blob = pp.verify_and_emit(st, _signer_pubkeys())
    # downstream: the policy engine consumes the EMITTED BYTES, not the
    # caller's dict — admit() must accept them identically
    pol.admit(json.loads(blob), expected_subject_digest="c" * 64)
    return True, "HELD (verified bytes -> policy admit)"


def p_vsa_happy_path():
    """A pinned, in-scope, fresh, level-sufficient VSA admits."""
    iss = pp.VSAIssuer(VERIFIER_ID, VERIFIER_SEED)
    vsa = iss.issue(subject_digest="c" * 64,
                    policy_id="gate-artifact-admission",
                    verified_level="SLSA_BUILD_LEVEL_3",
                    issued_at=1000.0, ttl_seconds=3600)
    pol = _policy()
    if not pol.admit_vsa(vsa, "gate-artifact-admission",
                         "c" * 64, now=1100.0):
        return False, "GAP: valid VSA did not admit"
    # but NOT for a different subject digest
    ok, why = _expect(
        "vsa-subject",
        lambda: pol.admit_vsa(vsa, "gate-artifact-admission",
                              "d" * 64, now=1100.0),
        "provenance-subject-refused")
    if not ok:
        return False, why
    # and NOT when the verified level is below the policy's bar
    low = iss.issue(subject_digest="c" * 64,
                    policy_id="gate-artifact-admission",
                    verified_level="SLSA_BUILD_LEVEL_1",
                    issued_at=1000.0, ttl_seconds=3600)
    ok, why = _expect(
        "vsa-level",
        lambda: pol.admit_vsa(low, "gate-artifact-admission",
                              "c" * 64, now=1100.0),
        "provenance-vsa-refused")
    if not ok:
        return False, why
    return True, "HELD (valid VSA admits; wrong subject/level refuse)"


def p_tag_constraints():
    """Versioned-tag policy: semver range enforced, unparseable refused."""
    pol = _policy()
    st = _statement(tag="v2.0.0")  # outside >=0.9.0,<1.0.0
    ok, why = _expect("tag-range",
                      lambda: pol.admit(st), "provenance-tag-refused")
    if not ok:
        return False, why
    st = _statement(tag="not-a-version")
    ok, why = _expect("tag-unparseable",
                      lambda: pol.admit(st), "provenance-tag-refused")
    if not ok:
        return False, why
    st = _statement(tag="v0.9.5")  # inside the range
    pol.admit(st, expected_subject_digest="c" * 64)
    return True, "HELD (range enforced; in-range admits)"


def p_taxonomy_pin():
    n = len(dc.TAXONOMY)
    if n != TAXONOMY_PIN:
        return False, "GAP: taxonomy pin %d, want %d" % (n, TAXONOMY_PIN)
    for c in pp.CODES:
        if c not in dc.TAXONOMY:
            return False, "GAP: new code %s missing from taxonomy" % c
    return True, "HELD (pin %d, %d new codes present)" % (
        TAXONOMY_PIN, len(pp.CODES))


PROBES = [
    ("swapped-builder", p_swapped_builder),
    ("vsa-scope-mismatch", p_vsa_scope_mismatch),
    ("expired-vsa", p_expired_vsa),
    ("unpinned-verifier-vsa", p_unpinned_verifier_vsa),
    ("empty-source-policy", p_empty_source_policy),
    ("missing-provenance-fields", p_missing_provenance_fields),
    ("statement-tamper", p_statement_tamper),
    ("verify-emit-piping", p_verify_emit_piping),
    ("vsa-happy-path", p_vsa_happy_path),
    ("tag-constraints", p_tag_constraints),
    ("taxonomy-pin", p_taxonomy_pin),
]


def green_check():
    """Depth-1 green check: run the lane's unit tests; honors
    GOV_SKIP_GREEN=1 (parent batteries pass it down; a standalone run
    with the var set records a skip and returns without spawning)."""
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "SKIPPED (GOV_SKIP_GREEN=1)"
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_provenance_policy", "-v"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SystemExit("GREEN CHECK FAILED:\n%s\n%s"
                         % (r.stdout[-3000:], r.stderr[-3000:]))
    # unittest -v writes progress to stderr
    return "OK (%d tests)" % r.stderr.count(" ... ok")


def main():
    mode = os.environ.get("GOV_DEPLOYMENT_MODE", "staging")
    held, gap = 0, 0
    print("w263 provenance-policy probes — mode=%s" % mode)
    for name, fn in PROBES:
        try:
            ok, why = fn()
        except Exception as e:  # noqa: BLE001 — a probe error is a GAP
            ok, why = False, "GAP: probe raised %r" % e
        held, gap = held + ok, gap + (not ok)
        print("[%s] %-24s %s" % ("HELD" if ok else "GAP", name, why))
    print("green check: %s" % green_check())
    print("result: %d HELD / %d GAP" % (held, gap))
    return 0 if gap == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
