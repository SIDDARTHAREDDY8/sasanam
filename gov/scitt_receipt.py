"""SCITT-shaped receipts for Sasanam anchors (RFC 9943 architecture, adapted).

Wave-208 lane B. ADAPT of the IETF SCITT architecture (wave-207
prospecting §2): the evidence bundle is the **Signed Statement**
(issuer identity + subject bound in a DSSE/PAE envelope -- NOT COSE;
stdlib only); the **Transparency Service** (TS) keeps an append-only
verifiable record (here: the wave-207 hermetic Rekor v2 tile log)
and issues **Receipts** (TS-signed inclusion proofs); the TS checks a
**registration policy** before recording (admission enforcement --
the wave-205 Harbor lesson); the offline verifier is the **Auditor**
role.

Honest wire-format boundary (do not close without a stdlib COSE
lane): SCITT's wire uses COSE_Sign1 (RFC 9943) and COSE receipts
(RFC 9942). This module uses DSSE/PAE envelopes everywhere. The
*architecture* is SCITT's -- statement/receipt separation,
registration policy, Auditor -- not the COSE wire format.

Honest single-issuer boundary: SCITT is single-issuer; our witness
quorum stays ours and is out of this module's scope.

Narrow-claims discipline (from the prospectus, kept verbatim in the
receipt): a receipt proves REGISTRATION -- authenticity, visibility,
and completeness of history -- explicitly NOT that the statement
content is correct, safe, or wise.

Layering:
1. A receipt is a DIGEST-EXISTENCE / REGISTRATION PROOF ONLY.
   ``evidentiary_grade="registration-proven-not-content"`` and
   ``authority_proof=False`` travel in the receipt body.
2. The TS never verifies content truth -- only issuer signature,
   statement shape, and registration policy.
3. Receipt verification is client-computed and offline: the Auditor
   recomputes the leaf from the statement envelope and the root
   from the receipt's own inclusion proof (the Rekor v2 client
   story). No network, no log needed. Freshness against the CURRENT
   log root requires the live log -- an honest residual, not a
   hidden gap (see ``verify_transparent_statement``).

$0 spend, stdlib only, deterministic (injectable clock).
"""

import hashlib
import json

from . import dsse_envelope as _de
from .rekor_v2_anchor import HermeticRekorV2
from .rekor_v2_anchor import V2ConfigError as _V2ConfigError
# Intra-package use of the v2 tile-log's RFC 6962 math (same trust
# boundary, one codebase): the leaf rule and proof verification must
# be byte-identical to the log's or offline audit lies.
from .rekor_v2_anchor import _leaf as _v2_leaf
from .rekor_v2_anchor import _verify_proof as _v2_verify_proof
from .signing import Signer, Verifier

__all__ = [
    "STATEMENT_PAYLOAD_TYPE",
    "RECEIPT_PAYLOAD_TYPE",
    "EVIDENTIARY_GRADE",
    "NARROW_CLAIM",
    "RegistrationError",
    "RegistrationRefused",
    "ReceiptError",
    "VerificationFailed",
    "issue_statement",
    "RegistrationPolicy",
    "TransparencyService",
    "verify_transparent_statement",
    "audit_subject",
]

#: Payload type of a Signed Statement envelope. The issuer and subject
#: ride inside the signed statement body (SCITT carries them as CWT
#: claims in the COSE protected header; the DSSE payloadType binding
#: is this module's honest substitute -- stated, not hidden).
STATEMENT_PAYLOAD_TYPE = "application/vnd.sasanam.signed-statement"

#: Payload type of a TS Receipt envelope.
RECEIPT_PAYLOAD_TYPE = "application/vnd.sasanam.ts-receipt"

#: The receipt proves registration, never content truth.
EVIDENTIARY_GRADE = "registration-proven-not-content"

#: Kept near-verbatim from the prospecting discipline.
NARROW_CLAIM = (
    "This receipt proves REGISTRATION: the statement was recorded by "
    "the named transparency service under the named registration "
    "policy, and its inclusion in the append-only log is verifiable "
    "from the receipt alone. It does NOT prove the statement content "
    "is correct, safe, or wise."
)

_ENVELOPE_FIELDS = frozenset({"payload", "payloadType", "signatures"})
_TRANSPARENT_FIELDS = frozenset({"statement", "receipt",
                                 "transparency_service"})


# ---------------------------------------------------------------------------
# error taxonomy
# ---------------------------------------------------------------------------

class RegistrationError(ValueError):
    """Bad registration-policy or transparency-service configuration."""


class RegistrationRefused(Exception):
    """The TS refused to record a statement (registration policy).

    Carries a machine-readable ``code``: ``issuer-not-allowlisted``,
    ``subject-denied``, ``subject-not-allowlisted``,
    ``content-type-not-allowlisted``, ``statement-too-large``,
    ``bad-statement-signature``, ``malformed-statement``.
    """

    def __init__(self, code, detail):
        super().__init__("[%s] %s" % (code, detail))
        self.code = code
        self.detail = detail


class ReceiptError(ValueError):
    """A receipt/statement/transparent-statement is malformed."""


class VerificationFailed(Exception):
    """Offline (Auditor) verification of a transparent statement failed."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _deepcopy(obj):
    """Deterministic deep copy of an envelope dict (JSON round-trip:
    the envelope shape is JSON, so this cannot smuggle non-JSON
    state)."""
    return json.loads(_canonical(obj))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _utcnow():
    import datetime
    return datetime.datetime.now(
        datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _as_str_tuple(value, where):
    """Coerce an allowlist parameter to a sorted tuple of str.

    Bare strings are refused loudly -- tuple("alice") would silently
    become a per-character list and reject the intended identity with
    a confusing code.
    """
    if isinstance(value, str):
        raise RegistrationError(
            "%s must be a list/tuple of str, not a bare str" % where)
    if value is None:
        return None
    try:
        items = tuple(value)
    except TypeError:
        raise RegistrationError(
            "%s must be a list/tuple of str" % where)
    if not all(isinstance(i, str) and i for i in items):
        raise RegistrationError(
            "%s must be a list/tuple of str" % where)
    return sorted(items)


def _check_identity(value, where, exc=ReceiptError):
    if not isinstance(value, str) or not value:
        raise exc("%s must be a non-empty str" % where)
    if len(value) > 256:
        raise exc("%s too long (max 256 chars)" % where)
    return value


def _strict_envelope(envelope, where):
    """Strict DSSE envelope shape check (fail-closed, no signature)."""
    if not isinstance(envelope, dict):
        raise ReceiptError("%s: envelope must be a dict" % where)
    extra = set(envelope) - _ENVELOPE_FIELDS
    if extra:
        raise ReceiptError("%s: unknown envelope field(s) refused: %s"
                           % (where, sorted(extra)))
    missing = _ENVELOPE_FIELDS - set(envelope)
    if missing:
        raise ReceiptError("%s: envelope missing field(s): %s"
                           % (where, sorted(missing)))
    return envelope


def _open(payload_type, envelope, verifiers, threshold, where):
    """Verify a DSSE envelope; wrap every failure as VerificationFailed."""
    try:
        payload, got_type, sigs = _de.parse_envelope(envelope)
        if got_type != payload_type:
            raise _de.EnvelopeError(
                "payloadType mismatch: envelope carries %r, expected %r"
                % (got_type, payload_type))
        opened = _de.open_envelope(
            envelope, payload, payload_type, verifiers,
            threshold=threshold,
            allowed_payload_types=frozenset({payload_type}))
    except _de.EnvelopeError as exc:
        raise VerificationFailed("%s: %s" % (where, exc))
    return opened, payload


# ---------------------------------------------------------------------------
# Signed Statement issuance (the Issuer side)
# ---------------------------------------------------------------------------

def issue_statement(issuer_signer, *, issuer, subject, content,
                    content_type="application/octet-stream", claims=None,
                    clock=None):
    """Seal a Signed Statement: issuer + subject bound over content.

    The statement body commits to ``sha256(content)`` -- the content
    itself never crosses into the transparency log (digest-existence
    layering, same as the anchor path). ``claims`` is an optional
    JSON-serializable mapping of additional issuer assertions.
    """
    if not isinstance(issuer_signer, Signer):
        raise ReceiptError("issuer_signer must be a gov.signing.Signer")
    _check_identity(issuer, "issuer")
    _check_identity(subject, "subject")
    if not isinstance(content, (bytes, bytearray)):
        raise ReceiptError("content must be bytes")
    _check_identity(content_type, "content_type")
    if claims is not None and not isinstance(claims, dict):
        raise ReceiptError("claims must be a mapping or None")
    body = {
        "issuer": issuer,
        "subject": subject,
        "content_sha256": hashlib.sha256(bytes(content)).hexdigest(),
        "content_type": content_type,
        "claims": dict(claims) if claims else {},
        "issued_at": (clock() if clock else _utcnow()),
    }
    return _de.seal(_canonical(body), STATEMENT_PAYLOAD_TYPE,
                    [issuer_signer])


# ---------------------------------------------------------------------------
# Registration policy (admission enforcement -- the Harbor lesson)
# ---------------------------------------------------------------------------

class RegistrationPolicy:
    """Named, versioned admission policy the TS checks before recording.

    The policy digest is pinned by the Auditor and travels inside
    every receipt: the policy is part of the evidence (wave-207
    prospecting §2). ``allowed_issuers`` is required; everything else
    is a further restriction.
    """

    def __init__(self, *, name, version, allowed_issuers,
                 allowed_subjects=None, denied_subjects=(),
                 allowed_content_types=None, max_statement_bytes=65536):
        _check_identity(name, "policy name", RegistrationError)
        _check_identity(version, "policy version", RegistrationError)
        allowed_issuers = _as_str_tuple(allowed_issuers, "allowed_issuers")
        if not allowed_issuers:
            raise RegistrationError(
                "allowed_issuers must be a non-empty list/tuple of str")
        if isinstance(max_statement_bytes, bool) \
                or not isinstance(max_statement_bytes, int) \
                or max_statement_bytes < 1:
            raise RegistrationError(
                "max_statement_bytes must be a positive int")
        self._rules = {
            "name": name,
            "version": version,
            "allowed_issuers": allowed_issuers,
            "allowed_subjects": _as_str_tuple(allowed_subjects,
                                              "allowed_subjects"),
            "denied_subjects": _as_str_tuple(denied_subjects or (),
                                             "denied_subjects"),
            "allowed_content_types": _as_str_tuple(allowed_content_types,
                                                   "allowed_content_types"),
            "max_statement_bytes": max_statement_bytes,
        }
        self._digest = hashlib.sha256(
            _canonical(self._rules)).hexdigest()

    @property
    def name(self):
        return self._rules["name"]

    @property
    def version(self):
        return self._rules["version"]

    @property
    def digest(self):
        """sha256 over the canonical rules -- pinned by the Auditor."""
        return self._digest

    def as_dict(self):
        # Deep copy: the rule lists are shared live state. A shallow
        # dict would let a caller mutate the policy while receipts
        # still pin the old digest.
        import copy as _copy
        return _copy.deepcopy(self._rules)

    def check(self, statement_body, statement_bytes):
        """Enforce the policy; raise RegistrationRefused (loud) on any
        violation. Never returns a partial pass."""
        if len(statement_bytes) > self._rules["max_statement_bytes"]:
            raise RegistrationRefused(
                "statement-too-large",
                "%d bytes exceeds policy max %d"
                % (len(statement_bytes),
                   self._rules["max_statement_bytes"]))
        issuer = statement_body.get("issuer")
        if issuer not in self._rules["allowed_issuers"]:
            raise RegistrationRefused(
                "issuer-not-allowlisted",
                "issuer %r not in policy allowlist" % (issuer,))
        subject = statement_body.get("subject")
        if subject in self._rules["denied_subjects"]:
            raise RegistrationRefused(
                "subject-denied",
                "subject %r is denied by policy" % (subject,))
        allowed = self._rules["allowed_subjects"]
        if allowed is not None and subject not in allowed:
            raise RegistrationRefused(
                "subject-not-allowlisted",
                "subject %r not in policy allowlist" % (subject,))
        ctype = statement_body.get("content_type")
        act = self._rules["allowed_content_types"]
        if act is not None and ctype not in act:
            raise RegistrationRefused(
                "content-type-not-allowlisted",
                "content type %r not allowlisted" % (ctype,))


# ---------------------------------------------------------------------------
# Transparency Service (the TS side)
# ---------------------------------------------------------------------------

class TransparencyService:
    """The SCITT Transparency Service, hermetic.

    Holds the append-only log (wave-207 HermeticRekorV2 tile log),
    verifies issuer signatures, enforces the registration policy, and
    issues TS-signed receipts. ``identity`` is the pinned TS name the
    Auditor checks against.
    """

    def __init__(self, *, identity, ts_signer, registration_policy,
                 signing_config, issuer_verifiers, issuer_threshold=1,
                 clock=None):
        _check_identity(identity, "ts identity", RegistrationError)
        if not isinstance(ts_signer, Signer):
            raise RegistrationError(
                "ts_signer must be a gov.signing.Signer")
        if not isinstance(registration_policy, RegistrationPolicy):
            raise RegistrationError(
                "registration_policy must be a RegistrationPolicy")
        issuer_verifiers = list(issuer_verifiers)
        if not issuer_verifiers or not all(
                isinstance(v, Verifier) for v in issuer_verifiers):
            raise RegistrationError(
                "issuer_verifiers must be a non-empty list of Verifier")
        if isinstance(issuer_threshold, bool) \
                or not isinstance(issuer_threshold, int) \
                or issuer_threshold < 1:
            raise RegistrationError(
                "issuer_threshold must be a positive int")
        if issuer_threshold > len(issuer_verifiers):
            raise RegistrationError(
                "issuer_threshold %d exceeds issuer_verifiers count %d "
                "(impossible quorum -- fix the configuration)"
                % (issuer_threshold, len(issuer_verifiers)))
        self._identity = identity
        self._ts_signer = ts_signer
        self._ts_key_id = ts_signer.key_id
        self._policy = registration_policy
        self._issuer_verifiers = issuer_verifiers
        self._issuer_threshold = issuer_threshold
        # The append-only verifiable record. Self-hosted hermetic v2;
        # the live-transport seam (if ever needed) is
        # HermeticRekorV2._submit_to_log, not this module.
        try:
            self._log = HermeticRekorV2(signing_config=signing_config)
        except _V2ConfigError as exc:
            raise RegistrationError("bad signing_config: %s" % (exc,))
        if clock is not None and not callable(clock):
            raise RegistrationError("clock must be callable")
        self._clock = clock or _utcnow
        # Non-shredding index: subject -> [(statement_envelope,
        # receipt_envelope)]. Conflicting statements for one subject
        # coexist; the Auditor flags them (never silently dropped).
        self._by_subject = {}
        self._by_statement = {}

    @property
    def identity(self):
        return self._identity

    @property
    def ts_key_id(self):
        return self._ts_key_id

    @property
    def policy(self):
        return self._policy

    def _parse_statement_body(self, statement_envelope):
        _strict_envelope(statement_envelope, "statement")
        try:
            payload, got_type, _ = _de.parse_envelope(statement_envelope)
        except _de.EnvelopeError as exc:
            raise RegistrationRefused("malformed-statement", str(exc))
        if got_type != STATEMENT_PAYLOAD_TYPE:
            raise RegistrationRefused(
                "malformed-statement",
                "statement payloadType %r refused (expected %r)"
                % (got_type, STATEMENT_PAYLOAD_TYPE))
        try:
            body = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RegistrationRefused("malformed-statement",
                                      "statement body is not JSON: %s"
                                      % (exc,))
        if not isinstance(body, dict):
            raise RegistrationRefused("malformed-statement",
                                      "statement body must be a JSON object")
        for field in ("issuer", "subject", "content_sha256",
                      "content_type", "issued_at"):
            if field not in body:
                raise RegistrationRefused(
                    "malformed-statement",
                    "statement body missing required field %r" % field)
        # Issuer signature verified BEFORE policy/admission: the TS
        # never records a statement it cannot attribute.
        try:
            _de.open_envelope(statement_envelope, payload,
                              STATEMENT_PAYLOAD_TYPE,
                              self._issuer_verifiers,
                              threshold=self._issuer_threshold,
                              allowed_payload_types=frozenset(
                                  {STATEMENT_PAYLOAD_TYPE}))
        except _de.EnvelopeError as exc:
            raise RegistrationRefused("bad-statement-signature",
                                      str(exc))
        return body

    def register(self, statement_envelope):
        """Record a statement and issue a receipt. Loud refusal
        (RegistrationRefused) on ANY failure -- no receipt, no log
        entry, no partial state.

        Re-registering the exact same statement bytes is idempotent:
        the ORIGINAL transparent statement (with its original
        receipt) is returned -- no duplicate leaf, no second receipt.
        """
        body = self._parse_statement_body(statement_envelope)
        statement_bytes = _canonical(statement_envelope)
        statement_digest = hashlib.sha256(statement_bytes).hexdigest()
        if statement_digest in self._by_statement:
            return self._by_statement[statement_digest]
        # Registration policy: admission enforcement, before the log.
        self._policy.check(body, statement_bytes)
        # Append to the verifiable record (idempotent on re-submit:
        # same bytes return the existing index -- no duplicate leaf).
        v2_receipt = self._log.submit_dsse(statement_envelope)
        inclusion = v2_receipt["inclusion"]
        receipt_body = {
            "statement_sha256": hashlib.sha256(
                statement_bytes).hexdigest(),
            "statement_payload_type": STATEMENT_PAYLOAD_TYPE,
            "issuer": body["issuer"],
            "subject": body["subject"],
            "content_sha256": body["content_sha256"],
            "transparency_service": self._identity,
            "ts_key_id": self._ts_key_id,
            # --- the transparency proof (client-verifiable tiles) ---
            "log": {
                "log_id": v2_receipt["log_id"],
                "log_index": inclusion["log_index"],
                "tree_size": inclusion["tree_size"],
                "root_hash": inclusion["root_hash"],
            },
            "anchor_receipt": v2_receipt,
            # --- the registration policy is part of the evidence ---
            "registration_policy": {
                "name": self._policy.name,
                "version": self._policy.version,
                "digest": self._policy.digest,
            },
            # --- the narrow claims, in the receipt itself ---
            "evidentiary_grade": EVIDENTIARY_GRADE,
            "authority_proof": False,
            "narrow_claim": NARROW_CLAIM,
            "issued_at": self._clock(),
        }
        receipt_envelope = _de.seal(_canonical(receipt_body),
                                    RECEIPT_PAYLOAD_TYPE,
                                    [self._ts_signer])
        # The caller keeps ownership of the envelope dict it passed
        # in: the index stores a deep copy, so post-register mutation
        # by the caller can only break its own copy (fail-closed), not
        # corrupt the non-shredding record.
        stored_statement = _deepcopy(statement_envelope)
        transparent = {
            "statement": stored_statement,
            "receipt": receipt_envelope,
            "transparency_service": self._identity,
        }
        self._by_subject.setdefault(body["subject"], []).append(
            (stored_statement, receipt_envelope))
        self._by_statement[receipt_body["statement_sha256"]] = \
            transparent
        return transparent

    def statements_for(self, subject):
        """Every statement envelope ever registered for ``subject`` --
        the non-shredding property: nothing is dropped or replaced."""
        # Deep copies: the index is the record; callers may not reach
        # in and mutate it.
        return [_deepcopy(s)
                for s, _ in self._by_subject.get(subject, [])]

    def receipt_for(self, statement_envelope):
        """The receipt envelope issued for a registered statement."""
        digest = hashlib.sha256(
            _canonical(statement_envelope)).hexdigest()
        try:
            return _deepcopy(self._by_statement[digest]["receipt"])
        except KeyError:
            raise ReceiptError("no receipt on record for this statement")


# ---------------------------------------------------------------------------
# Auditor: offline verification of a transparent statement
# ---------------------------------------------------------------------------

def _parse_json_body(payload, where):
    try:
        body = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise VerificationFailed("%s: body is not JSON: %s"
                                 % (where, exc))
    if not isinstance(body, dict):
        raise VerificationFailed("%s: body must be a JSON object"
                                 % where)
    return body


def _verify_inclusion_offline(statement_envelope, receipt_body):
    """Client-computed inclusion check, offline.

    Recomputes the leaf from the statement envelope's PAE (signed)
    bytes and the root from the receipt's own inclusion proof, and
    requires them to agree. This is the Rekor v2 client verification
    story (no online proof API) applied to the SCITT receipt.

    Honest residual: this checks the proof against the receipt's OWN
    claimed root (self-consistency). Freshness against the CURRENT
    log root requires the live log (``HermeticRekorV2.verify_inclusion``
    enforces the stale-proof guard there).
    """
    _strict_envelope(statement_envelope, "statement")
    try:
        payload, payload_type, _ = _de.parse_envelope(statement_envelope)
    except _de.EnvelopeError as exc:
        raise VerificationFailed("statement envelope: %s" % exc)
    leaf_input = _de.pae(payload_type, payload)
    anchor = receipt_body.get("anchor_receipt")
    if not isinstance(anchor, dict):
        raise VerificationFailed("receipt has no anchor_receipt")
    inclusion = anchor.get("inclusion")
    if not isinstance(inclusion, dict):
        raise VerificationFailed("receipt anchor has no inclusion proof")
    try:
        proof = [bytes.fromhex(h) for h in inclusion["hashes"]]
        claimed_root = bytes.fromhex(inclusion["root_hash"])
        tree_size = int(inclusion["tree_size"])
        leaf_index = int(inclusion["log_index"])
    except (KeyError, ValueError, TypeError) as exc:
        raise VerificationFailed("malformed inclusion proof: %s" % exc)
    try:
        recomputed = _v2_verify_proof(_v2_leaf(leaf_input), leaf_index,
                                      proof, tree_size)
    except ValueError as exc:
        raise VerificationFailed("inclusion proof rejected: %s" % exc)
    if recomputed != claimed_root:
        raise VerificationFailed(
            "inclusion proof does not recompute to the receipt's root")


def verify_transparent_statement(transparent, *, issuer_verifiers,
                                 ts_verifiers, ts_identity,
                                 pinned_policy_digest, issuer_threshold=1,
                                 ts_threshold=1):
    """The Auditor role: verify a transparent statement OFFLINE.

    Needs only pinned public material -- issuer verifiers, TS
    verifiers, the TS identity, and the registration-policy digest.
    No engine, no log, no network. Raises :class:`VerificationFailed`
    on ANY violation; returns a report dict on success.
    """
    if not isinstance(transparent, dict):
        raise VerificationFailed("transparent statement must be a dict")
    extra = set(transparent) - _TRANSPARENT_FIELDS
    if extra:
        raise VerificationFailed("unknown field(s) refused: %s"
                                 % sorted(extra))
    missing = _TRANSPARENT_FIELDS - set(transparent)
    if missing:
        raise VerificationFailed("missing field(s): %s"
                                 % sorted(missing))
    if transparent["transparency_service"] != ts_identity:
        raise VerificationFailed(
            "transparency_service %r does not match pinned identity %r"
            % (transparent["transparency_service"], ts_identity))
    statement_envelope = _strict_envelope(transparent["statement"],
                                         "statement")
    receipt_envelope = _strict_envelope(transparent["receipt"],
                                       "receipt")
    # 1. Issuer signature over the statement (authentication first).
    _, stmt_payload = _open(STATEMENT_PAYLOAD_TYPE, statement_envelope,
                            issuer_verifiers, issuer_threshold,
                            "statement")
    stmt_body = _parse_json_body(stmt_payload, "statement")
    for field in ("issuer", "subject", "content_sha256"):
        if field not in stmt_body:
            raise VerificationFailed(
                "statement body missing required field %r" % field)
    # 2. TS signature over the receipt.
    _, rcpt_payload = _open(RECEIPT_PAYLOAD_TYPE, receipt_envelope,
                            ts_verifiers, ts_threshold, "receipt")
    rcpt_body = _parse_json_body(rcpt_payload, "receipt")
    # 3. The receipt binds THIS statement's exact bytes.
    statement_digest = hashlib.sha256(
        _canonical(statement_envelope)).hexdigest()
    if rcpt_body.get("statement_sha256") != statement_digest:
        raise VerificationFailed(
            "receipt does not bind this statement (digest mismatch)")
    # 4. Issuer/subject claims agree between statement and receipt.
    for field in ("issuer", "subject"):
        if rcpt_body.get(field) != stmt_body[field]:
            raise VerificationFailed(
                "receipt %s %r disagrees with statement %r"
                % (field, rcpt_body.get(field), stmt_body[field]))
    # 5. The receipt's TS identity matches the pinned one.
    if rcpt_body.get("transparency_service") != ts_identity:
        raise VerificationFailed(
            "receipt transparency_service does not match pinned identity")
    # 6. The registration policy is the pinned one (policy is evidence).
    policy = rcpt_body.get("registration_policy")
    if not isinstance(policy, dict) \
            or policy.get("digest") != pinned_policy_digest:
        raise VerificationFailed(
            "receipt registration policy digest does not match the "
            "pinned policy")
    # 7. Client-computed inclusion, offline.
    _verify_inclusion_offline(statement_envelope, rcpt_body)
    return {
        "verified": True,
        "issuer": stmt_body["issuer"],
        "subject": stmt_body["subject"],
        "content_sha256": stmt_body["content_sha256"],
        "transparency_service": ts_identity,
        "policy_digest": policy["digest"],
        "inclusion_verified": True,
        "evidentiary_grade": rcpt_body.get("evidentiary_grade"),
        "narrow_claim": rcpt_body.get("narrow_claim"),
    }


def audit_subject(ts, subject, *, issuer_verifiers, ts_verifiers,
                  ts_identity, pinned_policy_digest, issuer_threshold=1,
                  ts_threshold=1):
    """Audit every statement ever registered for ``subject``.

    Verifies each transparent statement offline and reports whether
    distinct contents were registered for one subject
    (``equivocation_detected``). Both conflicting statements stay
    present -- the TS does not shred -- so the conflict is evidence,
    not an error.
    """
    if not isinstance(ts, TransparencyService):
        raise ReceiptError("ts must be a TransparencyService")
    _check_identity(subject, "subject")
    statements = ts.statements_for(subject)
    verified = 0
    contents = set()
    failures = []
    for stmt in statements:
        try:
            report = verify_transparent_statement(
                {"statement": stmt,
                 "receipt": ts.receipt_for(stmt),
                 "transparency_service": ts_identity},
                issuer_verifiers=issuer_verifiers,
                ts_verifiers=ts_verifiers, ts_identity=ts_identity,
                pinned_policy_digest=pinned_policy_digest,
                issuer_threshold=issuer_threshold,
                ts_threshold=ts_threshold)
        except VerificationFailed as exc:
            failures.append(str(exc))
            continue
        verified += 1
        contents.add(report["content_sha256"])
    return {
        "subject": subject,
        "statement_count": len(statements),
        "verified": verified,
        "verification_failures": failures,
        "distinct_contents": len(contents),
        "equivocation_detected": len(contents) > 1,
    }
