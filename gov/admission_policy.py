"""Signature-verification policy as data for artifact admission
(wave-264 feature lane 2).

Adapts the sigstore/policy-controller MECHANISM as pattern only (no
code copied; Apache-2.0): a ClusterImagePolicy-shaped declarative
policy names artifacts (glob patterns, digest pins) and lists
AUTHORITIES -- ``key`` (static Ed25519 public key), ``keyless``
(issuer + subject identity), ``attestation`` (required predicate),
``transparency`` (log-membership claim) -- evaluated at admission
time, with resolve-before-admit so the verified digest is the
executed digest, and a policy-tester-shaped offline quality gate.

What this module provides, stdlib-only:

* :class:`AdmissionPolicy`: policy-as-data, validated LOUDLY at load
  (``from_dict``). Authoring errors refuse at construction, never at
  admission time: malformed shape (``admission-policy-malformed``),
  zero entries or zero authorities (``admission-policy-vacuous`` --
  never a vacuous allow), unknown authority types
  (``admission-policy-authority-unknown``).
* :func:`admit`: gates one artifact BEFORE it enters the pipeline.
  The artifact reference (``{"name", "tag"}`` or ``{"name",
  "digest"}``) is RESOLVED to a digest at verify time through a
  deployment-provided resolver; the returned decision is BOUND to
  that digest. Refusals, all machine-coded:

  - artifact matches no policy entry: ``admission-policy-not-covered``
    (default deny -- policy precedes discovery);
  - tag cannot be resolved: ``admission-policy-unresolvable`` (never
    admit what you cannot resolve);
  - entry demands a key authority but no signature is presented:
    ``admission-policy-unsigned``;
  - signature present but none verifies under a pinned key for THIS
    digest: ``admission-policy-signature-refused`` (signatures bind
    the digest -- a valid signature for D1 never admits D2);
  - keyless (issuer, subject) mismatch:
    ``admission-policy-identity-refused``;
  - required attestation predicate missing or unverifiable:
    ``admission-policy-attestation-refused``;
  - required transparency-log membership claim missing or
    unverifiable: ``admission-policy-transparency-refused``.

  An artifact is admitted iff it matches at least one policy entry
  AND satisfies that entry's authorities per its ``mode``: ``"any"``
  (default) needs ONE satisfied authority; ``"all"`` needs EVERY
  authority (the upstream conjunction shape -- key AND attestation
  AND transparency on one entry). Upstream ANDs sub-conditions
  within one named authority and ORs across authorities; we expose
  the same two combinators at the entry level instead of nesting
  them inside authorities. The combinator is explicit in the
  policy, never inferred.

* :func:`confirm_use`: the execution seam. Re-resolves the artifact
  reference NOW and compares against the decision's bound digest
  (constant-time). A moved tag refuses
  ``admission-policy-digest-changed`` -- what was verified is what
  runs. Call this immediately before executing the artifact.
* :func:`test_policy` / :func:`quality_gate`: the policy-tester
  analog. Evaluate a candidate policy against an offline corpus of
  (artifact, evidence, expect) cases BEFORE deploying it; the gate
  blesses the policy only when every case matches. The tester runs
  the EXACT live ``admit`` path, so tester/live disagreement is
  impossible by construction (pinned by battery probe).
* :func:`to_evidence`: the decision as a canonical evidence record
  (digest-linked) for attachment to evidence bundles / decision
  packets.

Composition (never duplication):

* Digest-binding signatures follow the ``gov/admission.py``
  discipline (domain-separated signing bytes cover the digest);
  this module's seam is the multi-authority POLICY around that
  primitive, which ``gov/admission.py``'s single pinned triple does
  not express.
* Composes with ``gov/gate_algebra.py`` ``ImmutableTag``: that
  registry refuses re-admission of a changed digest across calls;
  this module's ``confirm_use`` refuses use of a changed digest
  within one decision's lifetime. Different halves of the TOCTOU.
* Keyless identity pairs with ``gov/svid_issuer.py``
  ``SvidVerifier`` at the deployment seam (see residual below).

Fail-closed: every refusal is machine-coded; nothing proceeds on a
partial verification. Pins, keys, and the tag->digest resolver are
deployment-owned.

Honest boundaries (stated, not absorbed):

* Keyless checks the CLAIMED (issuer, subject) against policy; the
  binding of that claim to a cryptographic principal is
  deployment-owned -- an unverified identity claim is only as
  trustworthy as its producer. Deployments needing cryptographic
  keyless identity verify the SVID first
  (``gov/svid_issuer.SvidVerifier``) and pass the verified pair in,
  or require a ``key`` authority alongside (``mode: "all"`` on the
  entry makes that conjunction explicit).
* Transparency verifies a SIGNED INCLUSION CLAIM, not a live log
  round-trip -- the same honest stance as the repo's Rekor notes
  (a log proves digest existence, not authorization).
* A signature proves the pinned key authorized THIS DIGEST, not
  that the artifact bytes are benign (as in ``gov/admission.py``).
* The resolver is deployment-owned trusted code: a lying resolver
  defeats resolve-before-admit, exactly as a reset
  ``ImmutableTag`` registry re-arms mutation.
* Admission is not a sandbox: an admitted artifact is trusted to
  ENTER the pipeline, not to execute.
* Authority combinators (entry ``mode``: ``"any"`` / ``"all"``) are
  OUR documented choice, kept at the entry level rather than nested
  inside authorities as upstream does; the upstream mechanism being
  adapted is the declarative per-artifact authority list, not its
  exact all/any edge semantics.

Stdlib only. Deterministic: injectable clock (``now`` args are
accepted and ignored -- admission is timeless; the parameter exists
so the seam matches the repo's verifier shape), no I/O, no
network, no in-repo git subprocesses.
"""

import fnmatch
import hashlib
import hmac
import json
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519 as _ed25519  # noqa: E402

__all__ = [
    "CODES",
    "POLICY_VERSION",
    "AdmissionPolicyError",
    "AdmissionPolicy",
    "from_dict",
    "signing_bytes",
    "attestation_bytes",
    "transparency_bytes",
    "admit",
    "confirm_use",
    "test_policy",
    "quality_gate",
    "to_evidence",
]

# New decision codes introduced by this module (see
# gov/decision_codes.py). Sorted; the taxonomy merge asserts raw
# literal uniqueness.
CODES = (
    "admission-policy-attestation-refused",
    "admission-policy-authority-unknown",
    "admission-policy-digest-changed",
    "admission-policy-identity-refused",
    "admission-policy-malformed",
    "admission-policy-not-covered",
    "admission-policy-signature-refused",
    "admission-policy-transparency-refused",
    "admission-policy-unresolvable",
    "admission-policy-unsigned",
    "admission-policy-vacuous",
)

MALFORMED = "admission-policy-malformed"
VACUOUS = "admission-policy-vacuous"
AUTHORITY_UNKNOWN = "admission-policy-authority-unknown"
NOT_COVERED = "admission-policy-not-covered"
UNRESOLVABLE = "admission-policy-unresolvable"
UNSIGNED = "admission-policy-unsigned"
SIGNATURE_REFUSED = "admission-policy-signature-refused"
IDENTITY_REFUSED = "admission-policy-identity-refused"
ATTESTATION_REFUSED = "admission-policy-attestation-refused"
TRANSPARENCY_REFUSED = "admission-policy-transparency-refused"
DIGEST_CHANGED = "admission-policy-digest-changed"

POLICY_VERSION = 1

#: Domain separation. Signatures cover the digest so a signature can
#: never be replayed as authorizing a different digest; attestation
#: and transparency claims bind (predicate|log, digest) likewise.
_SIGN_DOMAIN = b"admission-policy-sign/v1\x00"
_ATTEST_DOMAIN = b"admission-policy-attest/v1\x00"
_TRANSPARENCY_DOMAIN = b"admission-policy-transparency/v1\x00"

_HEX = frozenset("0123456789abcdef")

_AUTHORITY_TYPES = frozenset(
    ["key", "keyless", "attestation", "transparency"])


class AdmissionPolicyError(Exception):
    """Loud admission-policy failure. ``code`` is a closed vocabulary
    member of :data:`CODES`."""

    def __init__(self, code, detail=""):
        super(AdmissionPolicyError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _is_hex64(value):
    return isinstance(value, str) and len(value) == 64 \
        and all(c in _HEX for c in value)


def _norm_digest(value):
    """Normalize ``sha256:<hex>`` or bare ``<hex>`` to bare hex64."""
    if not isinstance(value, str):
        return None
    if value.startswith("sha256:"):
        value = value[len("sha256:"):]
    if _is_hex64(value):
        return value
    return None


def signing_bytes(digest_hex):
    """Bytes a key authority signs: domain || digest."""
    return _SIGN_DOMAIN + digest_hex.encode("ascii")


def attestation_bytes(predicate, digest_hex):
    """Bytes an attestation authority signs: domain || predicate ||
    NUL || digest."""
    return _ATTEST_DOMAIN + predicate.encode("utf-8") + b"\x00" \
        + digest_hex.encode("ascii")


def transparency_bytes(log_id, digest_hex):
    """Bytes a transparency authority signs: domain || log_id ||
    NUL || digest."""
    return _TRANSPARENCY_DOMAIN + log_id.encode("utf-8") + b"\x00" \
        + digest_hex.encode("ascii")


def _refuse(code, detail=""):
    raise AdmissionPolicyError(code, detail)


def _need_str(mapping, key, what):
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        _refuse(MALFORMED, "%s: %r must be a non-empty string"
                % (what, key))
    return value


def _validate_authority(auth, where):
    if not isinstance(auth, dict):
        _refuse(MALFORMED, "%s: authority must be a dict" % where)
    atype = auth.get("type")
    if atype not in _AUTHORITY_TYPES:
        _refuse(AUTHORITY_UNKNOWN,
                "%s: unknown authority type %r" % (where, atype))
    if atype == "key":
        _need_str(auth, "key_id", where)
        pub = auth.get("public_key")
        if not _is_hex64(pub):
            _refuse(MALFORMED,
                    "%s: key authority needs 64-hex public_key" % where)
    elif atype == "keyless":
        _need_str(auth, "issuer", where)
        _need_str(auth, "subject", where)
    elif atype == "attestation":
        _need_str(auth, "predicate", where)
        pub = auth.get("public_key")
        if not _is_hex64(pub):
            _refuse(MALFORMED, "%s: attestation authority needs "
                    "64-hex public_key" % where)
    elif atype == "transparency":
        _need_str(auth, "log_id", where)
        pub = auth.get("public_key")
        if not _is_hex64(pub):
            _refuse(MALFORMED, "%s: transparency authority needs "
                    "64-hex public_key" % where)
    return {"type": atype,
            "key_id": auth.get("key_id"),
            "public_key": auth.get("public_key"),
            "issuer": auth.get("issuer"),
            "subject": auth.get("subject"),
            "predicate": auth.get("predicate"),
            "log_id": auth.get("log_id")}


def _validate_entry(entry, idx):
    where = "entries[%d]" % idx
    if not isinstance(entry, dict):
        _refuse(MALFORMED, "%s: entry must be a dict" % where)
    name = _need_str(entry, "name", where)
    patterns = entry.get("patterns", [])
    digests = entry.get("digests", [])
    if not isinstance(patterns, list) or not all(
            isinstance(p, str) and p for p in patterns):
        _refuse(MALFORMED, "%s: patterns must be a list of "
                "non-empty strings" % where)
    norm_digests = []
    for d in digests if isinstance(digests, list) else []:
        n = _norm_digest(d)
        if n is None:
            _refuse(MALFORMED, "%s: bad digest pin %r" % (where, d))
        norm_digests.append(n)
    if not isinstance(digests, list):
        _refuse(MALFORMED, "%s: digests must be a list" % where)
    if not patterns and not norm_digests:
        _refuse(MALFORMED, "%s: entry matches nothing "
                "(no patterns, no digests)" % where)
    authorities = entry.get("authorities")
    if not isinstance(authorities, list) or not authorities:
        _refuse(VACUOUS, "%s: entry %r has no authorities -- "
                "a policy that admits nothing cannot be built"
                % (where, name))
    mode = entry.get("mode", "any")
    if mode not in ("any", "all"):
        _refuse(MALFORMED, "%s: mode must be 'any' or 'all', got %r"
                % (where, mode))
    return {"name": name,
            "mode": mode,
            "patterns": list(patterns),
            "digests": norm_digests,
            "authorities": [_validate_authority(
                a, "%s.authorities[%d]" % (where, i))
                for i, a in enumerate(authorities)]}


class AdmissionPolicy(object):
    """A loaded, validated admission policy. Build with
    :meth:`from_dict`; authoring errors raise at load."""

    def __init__(self, entries):
        self._entries = entries

    @classmethod
    def from_dict(cls, doc):
        if not isinstance(doc, dict):
            _refuse(MALFORMED, "policy must be a dict, got %s"
                    % type(doc).__name__)
        if doc.get("version") != POLICY_VERSION:
            _refuse(MALFORMED, "policy version must be %d, got %r"
                    % (POLICY_VERSION, doc.get("version")))
        entries = doc.get("entries")
        if not isinstance(entries, list) or not entries:
            _refuse(VACUOUS, "policy has no entries -- a policy "
                    "that admits nothing cannot be built")
        return cls([_validate_entry(e, i)
                    for i, e in enumerate(entries)])

    @property
    def entries(self):
        return [dict(e, authorities=[dict(a) for a in
                                     e["authorities"]])
                for e in self._entries]

    @property
    def entry_names(self):
        return [e["name"] for e in self._entries]


def from_dict(doc):
    """Load and validate a policy document. Module-level alias for
    :meth:`AdmissionPolicy.from_dict`."""
    return AdmissionPolicy.from_dict(doc)


def _resolve_digest(artifact, resolver):
    """Resolve the artifact reference to a digest hex64, fail-closed."""
    if not isinstance(artifact, dict):
        _refuse(MALFORMED, "artifact must be a dict")
    name = artifact.get("name")
    if not isinstance(name, str) or not name:
        _refuse(MALFORMED, "artifact needs a non-empty name")
    if "digest" in artifact:
        digest = _norm_digest(artifact["digest"])
        if digest is None:
            _refuse(MALFORMED, "artifact digest malformed: %r"
                    % (artifact["digest"],))
        return name, digest
    if "tag" in artifact:
        if not callable(resolver):
            _refuse(UNRESOLVABLE, "artifact %r names tag %r but no "
                    "resolver is configured" % (name, artifact["tag"]))
        try:
            resolved = resolver(artifact)
        except AdmissionPolicyError:
            raise
        except Exception as e:  # noqa: BLE001 -- fail closed
            _refuse(UNRESOLVABLE, "resolver failed for tag %r: %s: %s"
                    % (artifact["tag"], type(e).__name__, str(e)[:80]))
        digest = _norm_digest(resolved)
        if digest is None:
            _refuse(UNRESOLVABLE, "resolver returned a malformed "
                    "digest for tag %r: %r"
                    % (artifact["tag"], resolved))
        return name, digest
    _refuse(MALFORMED, "artifact needs 'digest' or 'tag'")


def _entry_matches(entry, name, digest):
    if digest in entry["digests"]:
        return True
    return any(fnmatch.fnmatchcase(name, pat)
               for pat in entry["patterns"])


def _verify_sig(public_key_hex, msg, sig_hex):
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    return _ed25519.verify(bytes.fromhex(public_key_hex), msg,
                           sig) is True


def _authority_satisfied(auth, evidence, digest):
    """Return (True, None, None) or (False, code, detail)."""
    atype = auth["type"]
    if atype == "key":
        sigs = evidence.get("signatures", [])
        if not isinstance(sigs, list) or not sigs:
            return (False, UNSIGNED, "no signatures presented")
        msg = signing_bytes(digest)
        for sig in sigs:
            if not isinstance(sig, dict):
                continue
            if _norm_digest(sig.get("digest")) != digest:
                continue  # signature binds another digest: not ours
            if isinstance(sig.get("signature"), str) and \
                    _verify_sig(auth["public_key"], msg,
                                sig["signature"]):
                return (True, None, None)
        return (False, SIGNATURE_REFUSED, "no signature verifies "
                "under a pinned key for this digest")
    if atype == "keyless":
        ident = evidence.get("identity", {})
        if not isinstance(ident, dict):
            ident = {}
        if ident.get("issuer") == auth["issuer"] and \
                ident.get("subject") == auth["subject"]:
            return (True, None, None)
        return (False, IDENTITY_REFUSED,
                "identity (%r, %r) does not match pinned (%r, %r)"
                % (ident.get("issuer"), ident.get("subject"),
                   auth["issuer"], auth["subject"]))
    if atype == "attestation":
        atts = evidence.get("attestations", [])
        if not isinstance(atts, list):
            atts = []
        msg = attestation_bytes(auth["predicate"], digest)
        for att in atts:
            if not isinstance(att, dict):
                continue
            if att.get("predicate") != auth["predicate"]:
                continue
            if _norm_digest(att.get("digest")) != digest:
                continue
            if isinstance(att.get("signature"), str) and \
                    _verify_sig(auth["public_key"], msg,
                                att["signature"]):
                return (True, None, None)
        return (False, ATTESTATION_REFUSED,
                "no verifiable %r attestation for this digest"
                % auth["predicate"])
    if atype == "transparency":
        claims = evidence.get("transparency", [])
        if not isinstance(claims, list):
            claims = []
        msg = transparency_bytes(auth["log_id"], digest)
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            if claim.get("log_id") != auth["log_id"]:
                continue
            if _norm_digest(claim.get("digest")) != digest:
                continue
            if isinstance(claim.get("signature"), str) and \
                    _verify_sig(auth["public_key"], msg,
                                claim["signature"]):
                return (True, None, None)
        return (False, TRANSPARENCY_REFUSED,
                "no verifiable log-membership claim for %r"
                % auth["log_id"])
    return (False, AUTHORITY_UNKNOWN, "unreachable")


def _decision(name, digest, entry, auth, conjunction=False):
    """Build the admission decision dict, bound to the digest."""
    return {"verdict": "admitted",
            "artifact_name": name,
            "digest": digest,
            "matched_entry": entry["name"],
            "entry_mode": entry.get("mode", "any"),
            "satisfied_authority": {
                "type": auth["type"],
                "key_id": auth.get("key_id"),
                "issuer": auth.get("issuer"),
                "subject": auth.get("subject"),
                "predicate": auth.get("predicate"),
                "log_id": auth.get("log_id"),
                "conjunction": conjunction},
            "policy_version": POLICY_VERSION}


def admit(policy, artifact, evidence, resolver=None, now=None):
    """Admit one artifact under the policy. Returns the decision
    dict bound to the verify-time digest; refusals raise
    :class:`AdmissionPolicyError` with a closed-vocabulary code.

    Entry ``mode``: ``"any"`` (default) admits when ANY authority
    of the entry is satisfied; ``"all"`` admits only when EVERY
    authority is satisfied (the upstream conjunction shape: key
    AND attestation AND transparency on one entry)."""
    if not isinstance(policy, AdmissionPolicy):
        _refuse(MALFORMED, "policy must be an AdmissionPolicy")
    if not isinstance(evidence, dict):
        _refuse(MALFORMED, "evidence must be a dict")
    name, digest = _resolve_digest(artifact, resolver)
    matched = [e for e in policy.entries
               if _entry_matches(e, name, digest)]
    if not matched:
        _refuse(NOT_COVERED, "artifact %r matches no policy entry; "
                "default deny" % name)
    failures = []  # every (code, detail) tried, in policy order
    for entry in matched:
        mode = entry.get("mode", "any")
        entry_failures = []
        for auth in entry["authorities"]:
            ok, code, detail = _authority_satisfied(auth, evidence,
                                                   digest)
            if ok:
                if mode == "any":
                    return _decision(name, digest, entry, auth)
            else:
                entry_failures.append((code, detail))
                failures.append((code, detail))
        if mode == "all" and not entry_failures:
            first = entry["authorities"][0]
            return _decision(name, digest, entry, first,
                             conjunction=True)
    if not failures:
        _refuse(SIGNATURE_REFUSED,
                "no authority tried (artifact %r)" % name)
    summary = "; ".join("%s: %s" % f for f in failures)
    last_code = failures[-1][0]
    _refuse(last_code, "%s (artifact %r)" % (summary, name))


def confirm_use(decision, artifact, resolver=None):
    """Execution-seam check: re-resolve the artifact reference NOW
    and require it to equal the decision's bound digest. A moved tag
    refuses ``admission-policy-digest-changed``."""
    if not isinstance(decision, dict):
        _refuse(MALFORMED, "decision must be a dict")
    bound = _norm_digest(decision.get("digest"))
    if bound is None:
        _refuse(MALFORMED, "decision carries no bound digest")
    name, current = _resolve_digest(artifact, resolver)
    if name != decision.get("artifact_name"):
        _refuse(DIGEST_CHANGED, "decision is for %r, use is for %r"
                % (decision.get("artifact_name"), name))
    if not hmac.compare_digest(bound, current):
        _refuse(DIGEST_CHANGED, "tag moved between verify and use: "
                "verified %s, now %s" % (bound, current))
    return {"verdict": "confirmed",
            "artifact_name": name,
            "digest": current,
            "matched_entry": decision.get("matched_entry")}


def test_policy(policy, cases):
    """Offline policy-tester: run the EXACT live :func:`admit` path
    over a corpus of cases. Each case: {"artifact", "evidence",
    "resolver", "expect": "admit"|"refuse"}. Returns {"results",
    "mismatches", "blessed"}; blessed iff every case matches."""
    if isinstance(policy, dict):
        policy = AdmissionPolicy.from_dict(policy)
    if not isinstance(policy, AdmissionPolicy):
        _refuse(MALFORMED, "policy must be a dict or AdmissionPolicy")
    results = []
    mismatches = []
    for i, case in enumerate(cases):
        cname = case.get("name", "case-%d" % i)
        expect = case.get("expect")
        try:
            decision = admit(policy, case.get("artifact"),
                             case.get("evidence", {}),
                             resolver=case.get("resolver"))
            got, code = "admit", None
        except AdmissionPolicyError as e:
            got, code, decision = "refuse", e.code, None
        match = (got == expect)
        results.append({"name": cname, "expect": expect, "got": got,
                        "code": code,
                        "digest": decision["digest"]
                        if decision else None,
                        "match": match})
        if not match:
            mismatches.append({"name": cname, "expect": expect,
                               "got": got, "code": code})
    return {"results": results, "mismatches": mismatches,
            "blessed": not mismatches}


def quality_gate(policy_dict, corpus):
    """Policy-tester quality gate: refuse to bless a candidate
    policy that fails its own corpus (or that cannot be loaded).
    An empty corpus can never bless -- the gate is not vacuous.
    Returns a report dict with a boolean "blessed"."""
    try:
        policy = AdmissionPolicy.from_dict(policy_dict)
    except AdmissionPolicyError as e:
        return {"blessed": False, "reason": e.code,
                "detail": e.detail, "mismatches": []}
    if not corpus:
        return {"blessed": False, "reason": "empty-corpus",
                "detail": "quality gate needs at least one test "
                          "case; an untested policy cannot bless",
                "mismatches": []}
    report = test_policy(policy, corpus)
    report["reason"] = (None if report["blessed"]
                        else "corpus-mismatch")
    return report


def to_evidence(decision):
    """The decision as a canonical, digest-linked evidence record
    for attachment to evidence bundles / decision packets."""
    if not isinstance(decision, dict) or \
            decision.get("verdict") != "admitted":
        _refuse(MALFORMED, "to_evidence needs an admitted decision")
    record = {"kind": "admission-policy-decision",
              "policy_version": POLICY_VERSION,
              "artifact_name": decision["artifact_name"],
              "digest": decision["digest"],
              "matched_entry": decision["matched_entry"],
              "satisfied_authority": decision["satisfied_authority"]}
    canonical = json.dumps(record, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    record["record_digest"] = hashlib.sha256(canonical).hexdigest()
    return record
