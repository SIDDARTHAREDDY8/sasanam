"""Step-scoped quorum policies over independently-signed agreeing link
records (wave-217 lane A).

PATTERN LINEAGE: in-toto (https://github.com/in-toto/in-toto,
Apache-2.0). Exactly two IDEAS are adapted here:

1. **Step-scoped quorum**: a policy is ``{step_name, authorized_keyids[],
   threshold}`` and admission requires a THRESHOLD of link records
   that **AGREE on the asserted statement digest** -- not merely
   threshold signatures anywhere. A quorum of signatures that disagree
   on the fact being asserted is not a quorum at all.
2. **expected-command is diagnostic only**: the command a functionary
   claims to have run is carried in the link record and compared for
   the auditor, but it is NEVER an enforcement input. Rationale, in
   our own words: a compromised functionary can sign a link record
   asserting ANY command it likes, so command equality can prove
   nothing about what actually ran -- it tells the auditor what the
   functionary CLAIMS, nothing more. Matching commands must never
   admit; mismatching commands must never deny.

No in-toto source is vendored and no in-toto spec prose is copied
(the spec is under the Community Specification License); the grammar,
semantics, and code lineage here are ours.

Post-F208 key discipline: verifiers come ONLY from the caller-pinned
keyset (``keyid -> gov.signing.Verifier``). Link records carry NO
public keys and no key hints that select verification material -- the
record's ``signer_keyid`` is an identity label cryptographically bound
INSIDE the signed body (domain-separated). An unknown, unauthorized,
or unpinned keyid fails closed before any signature is trusted, and a
keyid label that lies fails on the signature path by construction.

What this module is and is not:
- It verifies that the LINK RECORDS account for the CLAIMED fact, not
  that the step really ran. Record reality is the caller's
  responsibility (same caller-owned-reality doctrine as
  ``gov.artifact_rules`` and ``gov.bom_queries``).
- A link record is a claim signed by a functionary; the module binds
  and counts claims. It does not observe builds.
- The quorum policy is opt-in: callers that pass no policy keep
  byte-identical legacy behavior (see the promote() wiring in
  ``gov.sign_deploy_namespaces``).

Stdlib only. $0 spend. Synthetic/local testing.
"""

import json

__all__ = [
    "QuorumPolicyError",
    "QuorumStep",
    "load_quorum_step",
    "canonical_link_body",
    "make_link_record",
    "verify_quorum",
]

#: Domain separation for the link-record signed body. The ``\\x00``
#: separates the domain tag from the canonical JSON so no record field
#: can be confused with the tag.
_LINK_BODY_DOMAIN = b"quorum-link/v1\x00"

#: The exact key set a link record carries. Unknown keys are refused
#: at the record boundary (records are our format; there is no
#: forward-compatible extension point to smuggle fields through).
_RECORD_KEYS = frozenset({
    "step_name",
    "statement_digest",
    "expected_command",
    "signer_keyid",
    "signature",
})


class QuorumPolicyError(ValueError):
    """Raised loudly on any quorum-policy violation. A silent False
    on a quorum check is an invitation to skip it."""


def _check_keyid(keyid, where):
    if not isinstance(keyid, str) or not keyid:
        raise QuorumPolicyError(
            "%s: keyid must be a non-empty str" % where)
    return keyid


def _check_digest(digest, where):
    if not isinstance(digest, str):
        raise QuorumPolicyError(
            "%s: statement_digest must be str, got %s"
            % (where, type(digest).__name__))
    if len(digest) != 64 or any(c not in "0123456789abcdef"
                                for c in digest):
        raise QuorumPolicyError(
            "%s: not a sha256 hex digest: %r" % (where, digest))
    return digest


class QuorumStep:
    """A step-scoped quorum policy: which functionaries may attest to
    a step, and how many AGREEING attestations are required.

    Instances are created only via :func:`load_quorum_step` (strict
    validation at policy-load time, fail-closed). Attributes are
    read-only tuples/scalars.
    """

    __slots__ = ("_step_name", "_authorized_keyids", "_threshold")

    def __init__(self, step_name, authorized_keyids, threshold):
        self._step_name = step_name
        self._authorized_keyids = tuple(authorized_keyids)
        self._threshold = threshold

    @property
    def step_name(self):
        return self._step_name

    @property
    def authorized_keyids(self):
        return self._authorized_keyids

    @property
    def threshold(self):
        return self._threshold

    def __repr__(self):
        return ("QuorumStep(step_name=%r, authorized_keyids=%r, "
                "threshold=%r)" % (self._step_name,
                                   self._authorized_keyids,
                                   self._threshold))


def load_quorum_step(spec):
    """Validate a quorum policy at policy-load time, fail-closed.

    ``spec`` is plain data::

        {"step_name": str,
         "authorized_keyids": [str, ...],
         "threshold": int}

    Refused: non-dict specs, unknown keys, empty step names, empty or
    duplicate or non-string keyids, and thresholds outside
    ``1 <= threshold <= len(authorized_keyids)`` (a threshold of 0
    would be a vacuous pass; a threshold above the roster can never be
    met and would be a silent deny-by-misconfiguration).
    """
    if not isinstance(spec, dict):
        raise QuorumPolicyError(
            "quorum step spec must be a dict, got %s"
            % type(spec).__name__)
    unknown = set(spec) - {"step_name", "authorized_keyids", "threshold"}
    if unknown:
        raise QuorumPolicyError(
            "quorum step spec has unknown keys: %s" % sorted(unknown))
    step_name = spec.get("step_name")
    if not isinstance(step_name, str) or not step_name:
        raise QuorumPolicyError(
            "quorum step spec: step_name must be a non-empty str")
    keyids = spec.get("authorized_keyids")
    if not isinstance(keyids, (list, tuple)) or not keyids:
        raise QuorumPolicyError(
            "quorum step spec: authorized_keyids must be a non-empty "
            "list")
    for kid in keyids:
        _check_keyid(kid, "authorized_keyids")
    if len(set(keyids)) != len(keyids):
        raise QuorumPolicyError(
            "quorum step spec: authorized_keyids has duplicates")
    threshold = spec.get("threshold")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or not 1 <= threshold <= len(keyids)):
        raise QuorumPolicyError(
            "quorum step spec: threshold must satisfy 1 <= k <= %d "
            "(authorized roster size)" % len(keyids))
    return QuorumStep(step_name, keyids, threshold)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def canonical_link_body(step_name, statement_digest, expected_command,
                        signer_keyid):
    """The exact bytes a link record's signature covers.

    Binds ``(step_name, statement_digest, expected_command,
    signer_keyid)`` under the ``quorum-link/v1`` domain. The keyid is
    part of the signed body, so a record that names a keyid its
    signature was not made for fails on the signature path -- a keyid
    label lie cannot survive verification.

    ``expected_command`` rides inside the signed body (it is bound to
    the claim, so it cannot be stripped and re-labeled) but the
    verifier treats it as DIAGNOSTIC ONLY: see
    :func:`verify_quorum`.
    """
    if not isinstance(step_name, str) or not step_name:
        raise QuorumPolicyError(
            "canonical_link_body: step_name must be a non-empty str")
    _check_digest(statement_digest, "canonical_link_body")
    if not isinstance(expected_command, str):
        raise QuorumPolicyError(
            "canonical_link_body: expected_command must be a str")
    _check_keyid(signer_keyid, "canonical_link_body")
    record = {
        "step_name": step_name,
        "statement_digest": statement_digest,
        "expected_command": expected_command,
        "signer_keyid": signer_keyid,
    }
    return _LINK_BODY_DOMAIN + _canonical(record)


def make_link_record(step_name, statement_digest, signer,
                     expected_command=""):
    """Functionary-side helper: build a signed link record.

    ``signer`` is a ``gov.signing.Signer`` (key custody is the
    functionary's job). Returns the plain-data record dict ready to
    hand to :func:`verify_quorum`::

        {"step_name", "statement_digest", "expected_command",
         "signer_keyid", "signature"}

    The signature is the signer's 64-byte signature over
    :func:`canonical_link_body`, hex-encoded. ``expected_command`` is
    the functionary's claim about what it ran -- recorded for the
    auditor, never an enforcement input.
    """
    if not (hasattr(signer, "key_id") and hasattr(signer, "sign")):
        raise QuorumPolicyError(
            "make_link_record: signer must expose key_id + sign")
    _check_keyid(signer.key_id, "make_link_record")
    if not isinstance(expected_command, str):
        raise QuorumPolicyError(
            "make_link_record: expected_command must be a str")
    _check_digest(statement_digest, "make_link_record")
    if not isinstance(step_name, str) or not step_name:
        raise QuorumPolicyError(
            "make_link_record: step_name must be a non-empty str")
    body = canonical_link_body(step_name, statement_digest,
                               expected_command, signer.key_id)
    sig = signer.sign(body)
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        raise QuorumPolicyError(
            "make_link_record: signer returned a malformed signature")
    return {
        "step_name": step_name,
        "statement_digest": statement_digest,
        "expected_command": expected_command,
        "signer_keyid": signer.key_id,
        "signature": bytes(sig).hex(),
    }


def _check_record_shape(record, index):
    where = "link_records[%d]" % index
    if not isinstance(record, dict):
        raise QuorumPolicyError(
            "%s: link record must be a dict" % where)
    unknown = set(record) - _RECORD_KEYS
    if unknown:
        raise QuorumPolicyError(
            "%s: unknown record keys: %s" % (where, sorted(unknown)))
    missing = _RECORD_KEYS - set(record)
    if missing:
        raise QuorumPolicyError(
            "%s: missing record keys: %s" % (where, sorted(missing)))
    if not isinstance(record["step_name"], str) or not record["step_name"]:
        raise QuorumPolicyError(
            "%s: step_name must be a non-empty str" % where)
    _check_digest(record["statement_digest"], where)
    if not isinstance(record["expected_command"], str):
        raise QuorumPolicyError(
            "%s: expected_command must be a str" % where)
    _check_keyid(record["signer_keyid"], where)
    sig = record["signature"]
    if not isinstance(sig, str) or len(sig) != 128:
        raise QuorumPolicyError(
            "%s: signature must be a 128-char hex str" % where)
    try:
        sig_bytes = bytes.fromhex(sig)
    except ValueError:
        raise QuorumPolicyError(
            "%s: signature is not hex" % where)
    return sig_bytes


def verify_quorum(step, link_records, keyset):
    """Verify a step quorum: a THRESHOLD of AGREEING link records.

    ``step``: a :class:`QuorumStep` (policy-load validated).
    ``link_records``: a list of plain-data link records (see
    :func:`make_link_record`). ``keyset``: dict mapping keyid ->
    ``gov.signing.Verifier`` -- the deployment-pinned keyset. Records
    never supply verification material (post-F208 discipline).

    Fail-closed (``QuorumPolicyError``) on: a record for a different
    step (cross-step replay); a signer not authorized for the step;
    an authorized signer with no pinned verifier (unpinned keyid);
    a bad signature; a functionary that validly signed TWO different
    digests for the same step (**equivocation** -- double-voting on
    facts is refused, not split across groups); no digest group
    reaching threshold (**quorum-not-met**); or TWO digest groups
    reaching threshold (**quorum-ambiguous** -- the deployment must
    not pick a fact silently).

    Agreement semantics: valid records are grouped by statement
    digest; exactly one group must reach ``step.threshold`` distinct
    signers. Duplicate records from one signer count once (a single
    vote per functionary).

    ``expected_command`` is compared across the winning group's
    records and reported as ``command_agreement`` (bool) plus the
    distinct claimed commands -- DIAGNOSTIC ONLY. A mismatch never
    denies; a match never admits. See the module docstring for the
    rationale.

    Returns the evidence report::

        {"step_name", "statement_digest", "signer_keyids" (sorted),
         "threshold", "distinct_signers", "command_agreement" (bool),
         "expected_commands" (sorted)}

    Deterministic: the same inputs always produce the identical
    report.
    """
    if not isinstance(step, QuorumStep):
        raise QuorumPolicyError(
            "step must be a gov.quorum_policy.QuorumStep")
    if not isinstance(link_records, (list, tuple)):
        raise QuorumPolicyError("link_records must be a list of records")
    if not isinstance(keyset, dict) or not keyset:
        raise QuorumPolicyError("keyset must be a non-empty dict")
    # Per-signer votes: keyid -> (statement_digest, expected_command).
    votes = {}
    for index, record in enumerate(link_records):
        sig_bytes = _check_record_shape(record, index)
        where = "link_records[%d]" % index
        if record["step_name"] != step.step_name:
            raise QuorumPolicyError(
                "%s: step mismatch %r (policy step %r) -- cross-step "
                "replay refused" % (where, record["step_name"],
                                   step.step_name))
        keyid = record["signer_keyid"]
        if keyid not in step.authorized_keyids:
            raise QuorumPolicyError(
                "%s: signer %r is not authorized for step %r" % (
                    where, keyid, step.step_name))
        verifier = keyset.get(keyid)
        if verifier is None:
            raise QuorumPolicyError(
                "%s: authorized signer %r has no pinned verifier -- "
                "unpinned keyid refused" % (where, keyid))
        if not (hasattr(verifier, "key_id")
                and hasattr(verifier, "verify")):
            raise QuorumPolicyError(
                "%s: keyset verifier for %r must expose key_id + verify"
                % (where, keyid))
        if verifier.key_id != keyid:
            raise QuorumPolicyError(
                "%s: keyset verifier key_id %r does not match record "
                "signer %r -- keyset label mismatch refused"
                % (where, verifier.key_id, keyid))
        body = canonical_link_body(record["step_name"],
                                   record["statement_digest"],
                                   record["expected_command"], keyid)
        if not verifier.verify(body, sig_bytes):
            raise QuorumPolicyError(
                "%s: bad signature from %r" % (where, keyid))
        digest = record["statement_digest"]
        prior = votes.get(keyid)
        if prior is None:
            votes[keyid] = (digest, record["expected_command"])
        elif prior[0] != digest:
            raise QuorumPolicyError(
                "functionary %r equivocated: valid signatures for two "
                "different digests in step %r -- double-voting refused"
                % (keyid, step.step_name))
        # else: exact duplicate record -- one vote per functionary.
    # Group distinct signers by asserted digest.
    groups = {}
    for keyid, (digest, _command) in votes.items():
        groups.setdefault(digest, set()).add(keyid)
    winners = [d for d, voters in groups.items()
               if len(voters) >= step.threshold]
    if not winners:
        raise QuorumPolicyError(
            "quorum-not-met: no agreeing digest group reaches "
            "threshold %d for step %r (best group: %d distinct "
            "signers)" % (step.threshold, step.step_name,
                          max((len(v) for v in groups.values()),
                              default=0)))
    if len(winners) > 1:
        raise QuorumPolicyError(
            "quorum-ambiguous: %d digest groups reach threshold %d "
            "for step %r -- refusing to pick a fact silently" % (
                len(winners), step.threshold, step.step_name))
    digest = winners[0]
    voters = sorted(groups[digest])
    commands = sorted({votes[k][1] for k in voters})
    return {
        "step_name": step.step_name,
        "statement_digest": digest,
        "signer_keyids": voters,
        "threshold": step.threshold,
        "distinct_signers": len(voters),
        "command_agreement": len(commands) == 1,
        "expected_commands": commands,
    }
