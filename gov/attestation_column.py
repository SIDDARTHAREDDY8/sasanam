"""Attested-vs-asserted field column (wave-238).

Adapted from the aqta-ai ACTION-v1 section 8 attested-vs-asserted field
table: a prose rewrite of the mechanism with attribution (the aqta-ai
attestation-spec is CC-BY-4.0 for the spec text / Apache-2.0 for code;
no verbatim text or code is reused here).

Every field of an audit-log record is labeled with exactly one of four
attestation classes:

* ``issuer-attested``             -- the issuer cryptographically attests
  the value: outcome, policy_applied, timestamp, effect_digest.
* ``issuer-assigned``             -- the issuer assigned the identifier
  and can vouch for its binding: org_id, session_id, action_id.
* ``caller-declared-issuer-observed`` -- the caller declared the value;
  the issuer only observed it on the wire: tool, args_hash.
* ``caller-asserted-recorded-only``   -- the caller asserted the value;
  the issuer records it but vouches for nothing: agent.

The conformance rule: a caller-asserted (or caller-declared) field must
NEVER be presented as issuer-verified. Presenting the caller-asserted
``agent`` field as verified identity refuses
``attestation-class-inflation`` -- AQTA CONFORMANCE makes that
presentation non-conformant. Only issuer-attested and issuer-assigned
fields may be presented as verified.

The outcome rule: the issuer-attested ``outcome`` field attests the
DECISION, never the effect. Presenting ALLOWED as proof that the effect
executed refuses ``attestation-outcome-misread``; proof of execution
requires issuer-attested effect evidence (``effect_digest``).

A field with no attestation class cannot be emitted: ``emit`` refuses
``attestation-class-unlabeled`` instead of inventing a label.

The four machine refusals, all vocabulary-bound to
``gov/decision_codes.py``:

- ``attestation-class-inflation`` -- a non-issuer-vouched field was
  presented as issuer-verified.
- ``attestation-class-unlabeled`` -- a record field has no attestation
  class; refused at emit.
- ``attestation-outcome-misread`` -- the decision outcome was presented
  as proof of execution.
- ``attestation-record-malformed`` -- the record is the wrong shape.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads.

What this does NOT do (honest boundaries):
- It does not authenticate the agent. The ``agent`` field is
  caller-asserted by design; this column's job is to stop anyone from
  treating it as verified.
- It does not prove execution. An ``effect_digest`` is still the
  issuer's claim about the effect; the column only stops the weaker
  claim (ALLOWED means allowed, not done) from masquerading as it.
- The attestation class is the issuer's own classification. A
  mislabeling issuer can lie about the class; this column makes the
  labels explicit and checkable, it does not make the issuer honest.
"""

ISSUER_ATTESTED = "issuer-attested"
ISSUER_ASSIGNED = "issuer-assigned"
CALLER_DECLARED = "caller-declared-issuer-observed"
CALLER_ASSERTED = "caller-asserted-recorded-only"

ATTESTATION_CLASSES = frozenset((
    ISSUER_ATTESTED,
    ISSUER_ASSIGNED,
    CALLER_DECLARED,
    CALLER_ASSERTED,
))

# The closed vocabulary: every emittable audit-record field and the
# class the issuer vouches for it at. Only issuer-attested and
# issuer-assigned fields may be presented as verified.
FIELD_CLASS = {
    "outcome": ISSUER_ATTESTED,
    "policy_applied": ISSUER_ATTESTED,
    "timestamp": ISSUER_ATTESTED,
    "effect_digest": ISSUER_ATTESTED,
    "org_id": ISSUER_ASSIGNED,
    "session_id": ISSUER_ASSIGNED,
    "action_id": ISSUER_ASSIGNED,
    "tool": CALLER_DECLARED,
    "args_hash": CALLER_DECLARED,
    "agent": CALLER_ASSERTED,
}

# Fields that may be presented as issuer-verified.
_VERIFIABLE = frozenset((ISSUER_ATTESTED, ISSUER_ASSIGNED))

CLASS_INFLATION = "attestation-class-inflation"
CLASS_UNLABELED = "attestation-class-unlabeled"
OUTCOME_MISREAD = "attestation-outcome-misread"
RECORD_MALFORMED = "attestation-record-malformed"


class AttestationColumnError(Exception):
    """An attestation-column refusal carrying a machine taxonomy code.

    ``code`` is one of the module-level constants; ``detail`` is a
    human sentence. Refusals name the field and its attestation class;
    they never say "tampered" -- class inflation is a conformance
    violation, not evidence of compromise.
    """

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s: %s" % (code, detail) if detail else code)


def label_record(record):
    """Label every field of a record with its attestation class.

    Returns a list of ``{"field", "class"}`` dicts in record order.
    A non-dict record, or a non-string field name or value, refuses
    ``attestation-record-malformed``. A field outside the closed
    ``FIELD_CLASS`` vocabulary refuses ``attestation-class-unlabeled``.
    """
    if not isinstance(record, dict):
        raise AttestationColumnError(
            RECORD_MALFORMED, "audit record must be a dict")
    labels = []
    for field, value in record.items():
        if not isinstance(field, str) or not isinstance(value, str):
            raise AttestationColumnError(
                RECORD_MALFORMED,
                "field names and values must be strings, got %r" % (field,))
        cls = FIELD_CLASS.get(field)
        if cls is None:
            raise AttestationColumnError(
                CLASS_UNLABELED,
                "field %r has no attestation class and cannot be emitted"
                % (field,))
        labels.append({"field": field, "class": cls})
    return labels


def emit(record):
    """Emit a record with its attestation column attached.

    Every field is labeled; an unlabeled field refuses
    ``attestation-class-unlabeled`` (fail closed at emit rather than
    shipping an unlabeled field). Returns
    ``{"record": <record dict>, "fields": {field: {"class": ...}}}``.
    """
    labels = label_record(record)
    fields = {entry["field"]: {"class": entry["class"]} for entry in labels}
    return {"record": dict(record), "fields": fields}


def present_as_verified(record, field):
    """Read a field's value as issuer-verified.

    Only issuer-attested and issuer-assigned fields may be read this
    way. Presenting a caller-declared or caller-asserted field (e.g.
    ``agent``) as verified refuses ``attestation-class-inflation`` --
    the non-conformance this column exists to stop.
    """
    if not isinstance(record, dict) or not isinstance(field, str):
        raise AttestationColumnError(
            RECORD_MALFORMED, "record must be a dict and field a string")
    if field not in record:
        raise AttestationColumnError(
            RECORD_MALFORMED, "field %r is not present in the record" % (field,))
    cls = FIELD_CLASS.get(field)
    if cls is None:
        raise AttestationColumnError(
            CLASS_UNLABELED,
            "field %r has no attestation class and cannot be verified"
            % (field,))
    if cls not in _VERIFIABLE:
        raise AttestationColumnError(
            CLASS_INFLATION,
            "field %r is %s: it must never be presented as "
            "issuer-verified" % (field, cls))
    return {"field": field, "value": record[field], "class": cls}


def present_as_decision(record):
    """Read the issuer-attested outcome as the decision it is.

    This is the conformant reading: ALLOWED means the gate allowed the
    action. It says nothing about whether the effect executed.
    """
    if not isinstance(record, dict):
        raise AttestationColumnError(
            RECORD_MALFORMED, "audit record must be a dict")
    outcome = record.get("outcome")
    if not isinstance(outcome, str):
        raise AttestationColumnError(
            RECORD_MALFORMED, "record carries no issuer-attested outcome")
    return {"decision": outcome, "class": ISSUER_ATTESTED}


def present_as_proof_of_execution(record):
    """Read the record as proof the effect executed.

    The decision outcome is NOT such proof: ALLOWED attests the
    decision only, so a record whose only attestation is the outcome
    refuses ``attestation-outcome-misread``. Proof of execution
    requires issuer-attested effect evidence: a non-empty
    ``effect_digest`` field.
    """
    if not isinstance(record, dict):
        raise AttestationColumnError(
            RECORD_MALFORMED, "audit record must be a dict")
    evidence = record.get("effect_digest")
    if not isinstance(evidence, str) or not evidence:
        raise AttestationColumnError(
            OUTCOME_MISREAD,
            "outcome %r attests the decision only, not that the effect "
            "executed; proof of execution needs issuer-attested "
            "effect_digest" % (record.get("outcome"),))
    return {"effect_digest": evidence, "class": ISSUER_ATTESTED}
