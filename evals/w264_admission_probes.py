"""Break-first battery for gov/admission_policy.py (wave-264 lane 2).

Target (base 7fa1114729d3374e71eb0b88e43698c4b919f142, taxonomy pin
1151 -> 1162): signature-verification policy as data, adapted as
PATTERN ONLY from sigstore/policy-controller (no code copied;
Apache-2.0). A ClusterImagePolicy-shaped declarative policy names
artifacts (glob patterns, digest pins) and lists authorities -- key
(static Ed25519 public key), keyless (issuer + subject), attestation
(required predicate), transparency (log-membership claim) -- evaluated
at admission, with resolve-before-admit (the verified digest is the
executed digest) and a policy-tester-shaped offline quality gate.

Method (diagnosing-bugs skill): every probe first runs against an
ALWAYS-PASS STUB with the same surface (from_dict / admit /
confirm_use / test_policy). An attack probe is only real if it BREAKs
against the stub (the attack succeeds when nothing is checked) and
HELDs against the real module (the seam refuses it, machine-coded).
Controls expect HELD in both phases. A probe whose stub verdict does
not match its declared expectation is an ERROR (harness bug), not a
product result.

Verdicts: HELD (attack refused / gap is a documented residual), BREAK
(genuine defect), ERROR (harness bug -- fix the harness).

Probes (public seams only):
 1. toctou-tag-moved: tag resolves D1 at admit, D2 at confirm_use.
    Stub lets use proceed (BREAK); real refuses
    admission-policy-digest-changed (HELD).
 2. unsigned-under-key-authority: key-only policy, no signatures.
    Stub admits (BREAK); real refuses admission-policy-unsigned.
 3. wrong-signer: signature by a foreign key. Stub admits (BREAK);
    real refuses admission-policy-signature-refused.
 4. signature-replayed-across-digest: valid signature over D1
    presented for D2 (digest binding). Stub admits (BREAK); real
    refuses admission-policy-signature-refused.
 5. keyless-identity-mismatch: wrong subject under keyless-only
    policy. Stub admits (BREAK); real refuses
    admission-policy-identity-refused.
 6. malformed-policy: from_dict on a non-dict / bad version / bad
    entry shape. Stub accepts (BREAK); real raises
    admission-policy-malformed at load.
 7. empty-authorities: entry with zero authorities. Stub accepts
    (BREAK); real raises admission-policy-vacuous at load (never a
    vacuous allow).
 8. unknown-authority-type: {"type": "weird"}. Stub accepts (BREAK);
    real raises admission-policy-authority-unknown at load.
 9. not-covered-default-deny: artifact matches no entry. Stub admits
    (BREAK); real refuses admission-policy-not-covered.
10. attestation-missing: attestation-only policy, no attestations.
    Stub admits (BREAK); real refuses
    admission-policy-attestation-refused.
11. transparency-missing: transparency-only policy, no log claim.
    Stub admits (BREAK); real refuses
    admission-policy-transparency-refused.
12. unresolvable-tag: tag with no resolver configured. Stub admits
    (BREAK); real refuses admission-policy-unresolvable (fail
    closed, never admit-what-you-cannot-resolve).
13. tester-catches-bad-policy: quality_gate over a corpus where a
    known-unsigned artifact is expect_deny under a key-only policy,
    but the candidate policy is tag-only (no authorities pinned to
    the artifact's real signer...). Concretely: the corpus's bad
    case is admitted by the candidate policy under test. The stub
    tester blesses everything (BREAK -- the gate is vacuous); the
    real gate refuses to bless (HELD).
14. tester-agrees-with-live: the same (artifact, evidence,
    resolver) through test_policy and through admit yields the
    identical verdict -- the tester IS the live path, so
    disagreement is impossible by construction. Trivially HELD
    against the stub too (agreement is necessary, not sufficient;
    pinned so a future refactor cannot silently fork the paths).
15. valid-key-admission (control): well-formed key-signed artifact
    is admitted and the decision is bound to the verify-time
    digest. HELD in both phases.
16. keyless-valid-admission (control): matching (issuer, subject)
    admitted under keyless-only policy. HELD in both phases.

Stdlib only. Deterministic (staging + `env -u GOV_DEPLOYMENT_MODE`).
No in-repo git subprocesses (wave-36 supply-chain probe: fail
closed). Green checks are depth-1 and honor GOV_SKIP_GREEN=1.
"""

import hashlib
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov import decision_codes
from gov import ed25519 as _ed

TAXONOMY_PIN = 2121 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)



_PROBES = []


def probe(name, stub_expect="BREAK"):
    def deco(fn):
        _PROBES.append((name, stub_expect, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


# ---------------------------------------------------------------------------
# Always-pass stub: the same surface, zero checks. Every attack probe must
# BREAK against this; otherwise the probe is vacuous.
# ---------------------------------------------------------------------------

class _StubPolicy(object):
    pass


class _stub_module(object):
    @staticmethod
    def from_dict(d):
        return _StubPolicy()

    @staticmethod
    def admit(policy, artifact, evidence, resolver=None, now=None):
        return {"verdict": "admitted", "artifact_name": "stub",
                "digest": "0" * 64, "matched_entry": "stub",
                "satisfied_authority": {"type": "stub"}}

    @staticmethod
    def confirm_use(decision, artifact, resolver=None):
        return {"verdict": "confirmed", "digest": decision["digest"]}

    @staticmethod
    def test_policy(policy, cases):
        return {"results": [], "mismatches": [], "blessed": True}

    @staticmethod
    def quality_gate(policy_dict, corpus):
        return {"blessed": True, "reason": "stub"}


_STUB = _stub_module()


# ---------------------------------------------------------------------------
# Fixtures (deterministic; no I/O).
# ---------------------------------------------------------------------------

def _seed(tag):
    return hashlib.sha256(b"w264-admission-fixture:" + tag).digest()


_SEED_A = _seed(b"key-A")
_SEED_B = _seed(b"key-B")
assert len(_SEED_A) == 32 and len(_SEED_B) == 32
_PUB_A = _ed.publickey(_SEED_A).hex()
_PUB_B = _ed.publickey(_SEED_B).hex()

_D1 = hashlib.sha256(b"w264-artifact-bytes-v1").hexdigest()
_D2 = hashlib.sha256(b"w264-artifact-bytes-v2").hexdigest()

_SIGN_DOMAIN = b"admission-policy-sign/v1\x00"
_ATTEST_DOMAIN = b"admission-policy-attest/v1\x00"


def _sign(seed, digest_hex):
    return _ed.sign(seed, _SIGN_DOMAIN + digest_hex.encode("ascii")).hex()


def _att_sign(seed, predicate, digest_hex):
    return _ed.sign(seed, _ATTEST_DOMAIN + predicate.encode("utf-8")
                    + b"\x00" + digest_hex.encode("ascii")).hex()


def _key_policy():
    return {
        "version": 1,
        "entries": [{
            "name": "tool-binaries",
            "patterns": ["tool-bin/*"],
            "digests": [],
            "authorities": [{
                "type": "key",
                "key_id": "release-2026",
                "public_key": _PUB_A,
            }],
        }],
    }


def _keyless_policy():
    return {
        "version": 1,
        "entries": [{
            "name": "agent-bundles",
            "patterns": ["bundle/*"],
            "digests": [],
            "authorities": [{
                "type": "keyless",
                "issuer": "https://dex.example.com",
                "subject": "spiffe://td/ns/prod/sa/builder",
            }],
        }],
    }


def _attestation_policy():
    return {
        "version": 1,
        "entries": [{
            "name": "scanned",
            "patterns": ["tool-bin/*"],
            "digests": [],
            "authorities": [{
                "type": "attestation",
                "predicate": "vuln-scan",
                "public_key": _PUB_A,
            }],
        }],
    }


def _transparency_policy():
    return {
        "version": 1,
        "entries": [{
            "name": "logged",
            "patterns": ["tool-bin/*"],
            "digests": [],
            "authorities": [{
                "type": "transparency",
                "log_id": "rekor-local",
                "public_key": _PUB_A,
            }],
        }],
    }


def _resolver_for(mapping):
    def resolve(ref):
        return mapping[ref["tag"]]
    return resolve


def _code_of(fn, *args, **kwargs):
    """Run fn; return ('raised', code) or ('ok', value)."""
    try:
        return ("ok", fn(*args, **kwargs))
    except Exception as e:  # noqa: BLE001 -- battery harness
        return ("raised", getattr(e, "code", "NO-CODE:%s"
                                 % type(e).__name__))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

@probe("admission-policy/toctou-tag-moved")
def p_toctou(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    ev = {"signatures": [{"key_id": "release-2026",
                          "signature": _sign(_SEED_A, _D1),
                          "digest": "sha256:" + _D1}]}
    # verify-time: tag v1 -> D1
    st, dec = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v1": _D1}))
    if st != "ok":
        return _break("admit refused the honest case: %r" % (dec,))
    # use-time: the tag MOVED to D2 (attacker repointed the registry)
    st2, res2 = _code_of(target.confirm_use, dec, art,
                         resolver=_resolver_for({"v1": _D2}))
    if st2 == "ok":
        return _break("use proceeded on moved tag: %r" % (res2,))
    if res2 == "admission-policy-digest-changed":
        return _held("moved tag refused at use: %s" % res2)
    return _break("wrong refusal: %r" % (res2,))


@probe("admission-policy/unsigned-under-key-authority")
def p_unsigned(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    st, res = _code_of(target.admit, pol, art, {"signatures": []},
                       resolver=_resolver_for({"v1": _D1}))
    if st == "ok":
        return _break("unsigned artifact admitted: %r" % (res,))
    if res == "admission-policy-unsigned":
        return _held("unsigned refused machine-coded")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/wrong-signer")
def p_wrong_signer(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    ev = {"signatures": [{"key_id": "release-2026",
                          "signature": _sign(_SEED_B, _D1),
                          "digest": "sha256:" + _D1}]}
    st, res = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v1": _D1}))
    if st == "ok":
        return _break("foreign-key signature admitted: %r" % (res,))
    if res == "admission-policy-signature-refused":
        return _held("wrong signer refused machine-coded")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/signature-replayed-across-digest")
def p_replay(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    # valid signature, but over D1 while the artifact now resolves to D2
    ev = {"signatures": [{"key_id": "release-2026",
                          "signature": _sign(_SEED_A, _D1),
                          "digest": "sha256:" + _D1}]}
    st, res = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v1": _D2}))
    if st == "ok":
        return _break("cross-digest signature replay admitted")
    if res == "admission-policy-signature-refused":
        return _held("replay refused: signature binds the digest")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/keyless-identity-mismatch")
def p_keyless_mismatch(target):
    pol = target.from_dict(_keyless_policy())
    art = {"name": "bundle/agent-x", "tag": "v3"}
    ev = {"identity": {"issuer": "https://dex.example.com",
                       "subject": "spiffe://td/ns/prod/sa/EVIL"}}
    st, res = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v3": _D1}))
    if st == "ok":
        return _break("mismatched identity admitted: %r" % (res,))
    if res == "admission-policy-identity-refused":
        return _held("identity mismatch refused machine-coded")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/malformed-policy")
def p_malformed(target):
    for bad in (["not", "a", "dict"],
                {"version": 99, "entries": []},
                {"version": 1, "entries": [{"name": "x"}]}):
        st, res = _code_of(target.from_dict, bad)
        if st == "ok":
            return _break("malformed policy accepted: %r" % (bad,))
        if res != "admission-policy-malformed":
            return _break("wrong refusal %r for %r" % (res, bad))
    return _held("malformed policies refused at load")


@probe("admission-policy/empty-authorities")
def p_vacuous(target):
    bad = {"version": 1, "entries": [{
        "name": "nothing", "patterns": ["x/*"], "digests": [],
        "authorities": []}]}
    st, res = _code_of(target.from_dict, bad)
    if st == "ok":
        return _break("zero-authority policy constructed")
    if res == "admission-policy-vacuous":
        return _held("vacuous policy refused at load")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/unknown-authority-type")
def p_unknown_auth(target):
    bad = {"version": 1, "entries": [{
        "name": "weird", "patterns": ["x/*"], "digests": [],
        "authorities": [{"type": "fulcio-weird"}]}]}
    st, res = _code_of(target.from_dict, bad)
    if st == "ok":
        return _break("unknown authority type accepted")
    if res == "admission-policy-authority-unknown":
        return _held("unknown authority refused at load")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/not-covered-default-deny")
def p_not_covered(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "other/random-thing", "tag": "v1"}
    ev = {"signatures": [{"key_id": "release-2026",
                          "signature": _sign(_SEED_A, _D1),
                          "digest": "sha256:" + _D1}]}
    st, res = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v1": _D1}))
    if st == "ok":
        return _break("uncovered artifact admitted: %r" % (res,))
    if res == "admission-policy-not-covered":
        return _held("default deny for uncovered artifacts")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/attestation-missing")
def p_attestation(target):
    pol = target.from_dict(_attestation_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    st, res = _code_of(target.admit, pol, art, {"attestations": []},
                       resolver=_resolver_for({"v1": _D1}))
    if st == "ok":
        return _break("unattested artifact admitted: %r" % (res,))
    if res == "admission-policy-attestation-refused":
        return _held("missing attestation refused machine-coded")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/transparency-missing")
def p_transparency(target):
    pol = target.from_dict(_transparency_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    st, res = _code_of(target.admit, pol, art, {"transparency": []},
                       resolver=_resolver_for({"v1": _D1}))
    if st == "ok":
        return _break("unlogged artifact admitted: %r" % (res,))
    if res == "admission-policy-transparency-refused":
        return _held("missing transparency claim refused")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/unresolvable-tag")
def p_unresolvable(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    ev = {"signatures": [{"key_id": "release-2026",
                          "signature": _sign(_SEED_A, _D1),
                          "digest": "sha256:" + _D1}]}
    st, res = _code_of(target.admit, pol, art, ev, resolver=None)
    if st == "ok":
        return _break("unresolvable tag admitted: %r" % (res,))
    if res == "admission-policy-unresolvable":
        return _held("tag without resolver refused fail-closed")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/tester-catches-bad-policy")
def p_tester(target):
    # Corpus: an unsigned artifact that MUST be refused under the
    # candidate policy. The candidate policy under test only covers
    # "other/*" -- the bad artifact is uncovered, so the real gate
    # reports a mismatch-free run... instead make the candidate
    # policy ADMIT the bad case: a keyless policy whose pinned
    # identity matches the attacker's claim. The gate must refuse to
    # bless it.
    candidate = {
        "version": 1,
        "entries": [{
            "name": "attacker-friendly",
            "patterns": ["tool-bin/*"],
            "digests": [],
            "authorities": [{
                "type": "keyless",
                "issuer": "https://dex.example.com",
                "subject": "spiffe://td/ns/prod/sa/EVIL",
            }],
        }],
    }
    corpus = [{
        "name": "evil-identity-admitted",
        "artifact": {"name": "tool-bin/evil", "tag": "v9"},
        "evidence": {"identity": {
            "issuer": "https://dex.example.com",
            "subject": "spiffe://td/ns/prod/sa/EVIL"}},
        "resolver": _resolver_for({"v9": _D2}),
        "expect": "refuse",
    }]
    rep = target.quality_gate(candidate, corpus)
    if rep.get("blessed"):
        return _break("gate blessed a policy admitting the bad case")
    if rep.get("mismatches") or rep.get("reason"):
        return _held("gate refused to bless: %s"
                     % (rep.get("reason")
                        or rep["mismatches"][0].get("name")))
    return _break("gate unblessed but unexplained: %r" % (rep,))


@probe("admission-policy/tester-agrees-with-live", stub_expect="HELD")
def p_agreement(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    ev = {"signatures": [{"key_id": "release-2026",
                          "signature": _sign(_SEED_A, _D1),
                          "digest": "sha256:" + _D1}]}
    resolver = _resolver_for({"v1": _D1})
    case = {"name": "agree", "artifact": art, "evidence": ev,
            "resolver": resolver, "expect": "admit"}
    rep = target.test_policy(pol, [case])
    st, live = _code_of(target.admit, pol, art, ev, resolver=resolver)
    tester_says = "admit" if not rep["mismatches"] else "refuse"
    live_says = "admit" if st == "ok" else "refuse"
    if tester_says == live_says == "admit" and rep["blessed"]:
        return _held("tester and live admission agree (admit)")
    return _break("tester/live disagreement: %s vs %s"
                  % (tester_says, live_says))


@probe("admission-policy/valid-key-admission", stub_expect="HELD")
def p_valid(target):
    pol = target.from_dict(_key_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    ev = {"signatures": [{"key_id": "release-2026",
                          "signature": _sign(_SEED_A, _D1),
                          "digest": "sha256:" + _D1}]}
    st, dec = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v1": _D1}))
    if st != "ok":
        return _break("honest admission refused: %r" % (dec,))
    if target is not _STUB and dec.get("digest") != _D1:
        return _break("decision not bound to verify-time digest")
    st2, conf = _code_of(target.confirm_use, dec, art,
                         resolver=_resolver_for({"v1": _D1}))
    if st2 != "ok":
        return _break("honest confirm_use refused: %r" % (conf,))
    return _held("valid admission bound to digest, use confirmed")


@probe("admission-policy/keyless-valid-admission", stub_expect="HELD")
def p_keyless_valid(target):
    pol = target.from_dict(_keyless_policy())
    art = {"name": "bundle/agent-x", "tag": "v3"}
    ev = {"identity": {"issuer": "https://dex.example.com",
                       "subject": "spiffe://td/ns/prod/sa/builder"}}
    st, dec = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v3": _D1}))
    if st != "ok":
        return _break("honest keyless admission refused: %r" % (dec,))
    return _held("keyless identity admitted on exact match")


def _conjunction_policy():
    return {
        "version": 1,
        "entries": [{
            "name": "belt-and-suspenders",
            "patterns": ["tool-bin/*"],
            "digests": [],
            "mode": "all",
            "authorities": [
                {"type": "key",
                 "key_id": "release-2026",
                 "public_key": _PUB_A},
                {"type": "attestation",
                 "predicate": "vuln-scan",
                 "public_key": _PUB_A},
            ],
        }],
    }


def _full_evidence():
    return {
        "signatures": [{"key_id": "release-2026",
                        "signature": _sign(_SEED_A, _D1),
                        "digest": "sha256:" + _D1}],
        "attestations": [{
            "predicate": "vuln-scan",
            "signature": _att_sign(_SEED_A, "vuln-scan", _D1),
            "digest": "sha256:" + _D1}],
    }


@probe("admission-policy/conjunction-all-satisfied", stub_expect="HELD")
def p_conjunction_ok(target):
    pol = target.from_dict(_conjunction_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    st, dec = _code_of(target.admit, pol, art, _full_evidence(),
                       resolver=_resolver_for({"v1": _D1}))
    if st != "ok":
        return _break("conjunction refused though all hold: %r"
                      % (dec,))
    if target is not _STUB:
        sat = dec.get("satisfied_authority", {})
        if not sat.get("conjunction") or\
                dec.get("entry_mode") != "all":
            return _break("decision hides the conjunction: %r"
                          % (dec,))
    return _held("mode=all admits when every authority holds")


@probe("admission-policy/conjunction-partial-refused")
def p_conjunction_partial(target):
    pol = target.from_dict(_conjunction_policy())
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    # key signature valid, but the attestation is missing: the
    # conjunction must NOT admit on the key alone.
    ev = {"signatures": [{"key_id": "release-2026",
                         "signature": _sign(_SEED_A, _D1),
                         "digest": "sha256:" + _D1}],
          "attestations": []}
    st, res = _code_of(target.admit, pol, art, ev,
                       resolver=_resolver_for({"v1": _D1}))
    if st == "ok":
        return _break("mode=all admitted on a single authority")
    if res == "admission-policy-attestation-refused":
        return _held("partial conjunction refused machine-coded")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/bad-mode-refused-at-load")
def p_bad_mode(target):
    bad = {"version": 1, "entries": [{
        "name": "x", "patterns": ["x/*"], "digests": [],
        "mode": "sometimes",
        "authorities": [{"type": "key", "key_id": "k",
                         "public_key": _PUB_A}]}]}
    st, res = _code_of(target.from_dict, bad)
    if st == "ok":
        return _break("unknown entry mode accepted")
    if res == "admission-policy-malformed":
        return _held("unknown mode refused at load")
    return _break("wrong refusal: %r" % (res,))


@probe("admission-policy/empty-corpus-never-blesses")
def p_empty_corpus(target):
    rep = target.quality_gate(_key_policy(), [])
    if rep.get("blessed"):
        return _break("gate blessed on an empty corpus")
    if rep.get("reason") == "empty-corpus":
        return _held("empty corpus refuses to bless the policy")
    return _break("unblessed but unexplained: %r" % (rep,))


@probe("admission-policy/refusal-names-all-failures")
def p_refusal_summary(target):
    # any-mode entry with two authorities, neither satisfied: the
    # refusal must name every failed authority, not just the last.
    pol = target.from_dict({
        "version": 1,
        "entries": [{
            "name": "two-locks",
            "patterns": ["tool-bin/*"],
            "digests": [],
            "authorities": [
                {"type": "key", "key_id": "k",
                 "public_key": _PUB_A},
                {"type": "keyless",
                 "issuer": "https://dex.example.com",
                 "subject": "spiffe://td/ns/prod/sa/builder"},
            ],
        }],
    })
    art = {"name": "tool-bin/my-tool", "tag": "v1"}
    try:
        target.admit(pol, art, {"signatures": []},
                     resolver=_resolver_for({"v1": _D1}))
    except Exception as e:  # noqa: BLE001 -- battery harness
        detail = getattr(e, "detail", "")
        code = getattr(e, "code", "")
        if code != "admission-policy-identity-refused":
            return _break("wrong refusal code: %r" % (code,))
        if "admission-policy-unsigned" in detail and\
                "admission-policy-identity-refused" in detail:
            return _held("refusal names every failed authority")
        return _break("refusal hides failures: %r" % (detail,))
    return _break("unsatisfied authorities admitted")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_suite(target, label, expect_stub_phase):
    held = breaks = errors = 0
    for name, stub_expect, fn in _PROBES:
        try:
            verdict, detail = fn(target)
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:120]))
        want = stub_expect if expect_stub_phase else "HELD"
        ok = (verdict == want)
        if not ok:
            verdict = "ERROR"
            detail = "want %s: %s" % (want, detail)
            errors += 1
        elif verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        else:
            errors += 1
        print("%-5s %-52s %s" % (verdict, label + "/" + name, detail))
    return held, breaks, errors


def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["w221_admission_probes.py", "evidence_bundle_tamper.py",
                "rekor_anchor_probes.py", "w261_svid2_probes.py"]
    notes = []
    for battery in adjacent:
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent -- skipped"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="w264-green-")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600)
        except Exception as e:  # noqa: BLE001
            notes.append((battery, "ERROR: %s" % e))
            continue
        tail = (proc.stdout or "").strip().splitlines()[-1:]
        notes.append((battery, "exit=%d %s"
                      % (proc.returncode,
                         tail[0][:100] if tail else "")))
    return notes


def main():
    # Phase 1: the probes must be real attacks -- BREAK vs the stub.
    # (No pin check here: the stub phase validates the probes, not
    # the taxonomy.)
    h1, b1, e1 = _run_suite(_STUB, "stub", True)
    print("-" * 79)
    print("STUB phase: HELD %d / BREAK %d / ERROR %d" % (h1, b1, e1))
    if e1:
        print("probe harness bug: fix the probes before trusting phase 2")
        return 2
    # Phase 2: the real module must hold every attack.
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d"
              % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    try:
        import gov.admission_policy as real
    except ImportError:
        print("red phase: gov.admission_policy absent; stub phase only")
        return 3
    h2, b2, e2 = _run_suite(real, "real", False)
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("REAL phase: HELD %d / BREAK %d / ERROR %d over %d probes"
          % (h2, b2, e2, len(_PROBES)))
    return 1 if (b2 or e2) else 0


if __name__ == "__main__":
    sys.exit(main())
