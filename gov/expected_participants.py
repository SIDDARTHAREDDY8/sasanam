"""Expected-participants audit (W241-5, audit-first, NO crypto construction).

Per Reddy draft-aggregate-signatures §11 verbatim: an aggregate
signature proves which hops *signed*, not that every *expected* hop
was included -- without a destination policy naming the workload,
omission is not detectable. This module implements the declared-policy
half: an ``ExpectedParticipantsPolicy`` names, per workload/scope, the
participant ids expected to sign each delegation chain; chain
verification then checks both directions:

  - every declared expected participant must have a signed hop, else
    ``expected-participant-missing`` (the omission §11 names);
  - every signed hop must be a declared expected participant, else
    ``unexpected-participant-signed``.

A workload with no declared policy refuses
``expected-participants-undeclared`` (fail-closed: without a policy
naming the workload, omission cannot be audited, so the chain is not
verifiable).

Only exactly ``True`` counts as a signed hop -- truthy non-True values
refuse. This module authenticates nothing: it audits declared
expectations against claimed signatures. Whether the signatures are
genuine is deployment-owned (key/signature verification upstream).

NO aggregate crypto construction here: the aggregate mechanism is
still an individual draft (IESG "I-D Exists"), the reference repo
still does not exist, and ML-DSA has no aggregate-capable algorithm.
This is the declared-policy audit the draft says must come first.

Stdlib only. Deterministic. Fail-closed on malformed input.
"""

EXPECTED_PARTICIPANT_MISSING = "expected-participant-missing"
UNEXPECTED_PARTICIPANT_SIGNED = "unexpected-participant-signed"
EXPECTED_PARTICIPANTS_UNDECLARED = "expected-participants-undeclared"
EXPECTED_PARTICIPANTS_MALFORMED = "expected-participants-malformed"


class ExpectedParticipantsError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(ExpectedParticipantsError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise ExpectedParticipantsError(code, detail)


class ExpectedParticipantsPolicy(object):
    """Declared expected-participants policy.

    ``declarations`` maps a workload/scope name to the iterable of
    participant ids expected to sign each delegation chain for that
    workload. Duplicate participant ids within one workload are
    refused; an empty expected set is refused (a policy that expects
    nothing audits nothing).
    """

    def __init__(self, declarations):
        if not isinstance(declarations, dict) or not declarations:
            _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                    "declarations must be a non-empty dict")
        self._declarations = {}
        for workload, participants in declarations.items():
            if not isinstance(workload, str) or not workload:
                _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                        "workload names must be non-empty strings")
            if isinstance(participants, str) or not hasattr(
                    participants, "__iter__"):
                _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                        "participants for %r must be iterable"
                        % (workload,))
            ordered = []
            for participant in participants:
                if not isinstance(participant, str) or not participant:
                    _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                            "participant ids must be non-empty strings")
                if participant in ordered:
                    _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                            "duplicate participant %r for workload %r"
                            % (participant, workload))
                ordered.append(participant)
            if not ordered:
                _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                        "workload %r declares no expected participants"
                        % (workload,))
            self._declarations[workload] = tuple(ordered)

    def expected_for(self, workload):
        try:
            return self._declarations[workload]
        except KeyError:
            _refuse(EXPECTED_PARTICIPANTS_UNDECLARED,
                    "no declared expected participants for workload %r"
                    % (workload,))


def _signed_participants(chain):
    """Participant ids whose hop carries exactly True signature_present.
    Malformed hops refuse fail-closed."""
    if not hasattr(chain, "__iter__"):
        _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                "chain must be an iterable of hop dicts")
    signed = []
    for index, hop in enumerate(chain):
        if not isinstance(hop, dict):
            _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                    "hop %d is not a dict" % (index,))
        participant = hop.get("participant_id")
        if not isinstance(participant, str) or not participant:
            _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                    "hop %d has no participant_id" % (index,))
        if hop.get("signature_present") is True:
            if participant not in signed:
                signed.append(participant)
    return signed


def verify_delegation_chain(chain, policy, workload):
    """Audit a delegation chain against the declared policy.

    Refuses ``expected-participants-undeclared`` when the workload has
    no declared policy; ``expected-participant-missing`` naming the
    omitted participants when a declared expected participant has no
    signed hop; ``unexpected-participant-signed`` naming the extra
    signed participants when a signed hop was not declared expected.
    Returns a verdict dict on success.
    """
    if not isinstance(policy, ExpectedParticipantsPolicy):
        _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                "policy must be an ExpectedParticipantsPolicy")
    if not isinstance(workload, str) or not workload:
        _refuse(EXPECTED_PARTICIPANTS_MALFORMED,
                "workload must be a non-empty string")
    expected = policy.expected_for(workload)
    signed = _signed_participants(chain)
    missing = [p for p in expected if p not in signed]
    if missing:
        _refuse(EXPECTED_PARTICIPANT_MISSING,
                "expected participant(s) missing from signed chain for "
                "workload %r: %s" % (workload, ", ".join(missing)))
    unexpected = [p for p in signed if p not in expected]
    if unexpected:
        _refuse(UNEXPECTED_PARTICIPANT_SIGNED,
                "signed participant(s) not declared expected for "
                "workload %r: %s" % (workload, ", ".join(unexpected)))
    return {"ok": True,
            "workload": workload,
            "verified_participants": expected}
