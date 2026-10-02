"""Trust-vector evidence appraisal (wave-287 lane 8, veraison STEAL).

PATTERN LINEAGE: veraison/veraison (+ veraison/services, Apache-2.0 --
the ``veraison/veraison`` meta-repo is archived and points at
``veraison/services`` as the real implementation; this lane follows the
services-side mechanism, not the archived repo). This is a clean-room
stdlib-only reimplementation of the *mechanisms*; no upstream code,
schemas, or prose are vendored.

Mechanisms stolen:
* the four-part pipeline -- evidence extraction, producer
  allowlists, endorsements (golden values), appraisal policy -- as
  four separate stores: the thing measured, the values it is compared
  against, and the policy that decides are never the same object;
* the endorsement slot: every evidence claim carries a separately
  sourced endorsement slot that the verifier checks WITHOUT trusting
  the producer (wave-286 design rule -- the endorsement gap was
  confirmed twice independently, Veraison's endorsement store and
  Open Enclave's endorsements buffer);
* the scheme plugin interface: each scheme declares its claim grammar
  and endorsement expectations via :class:`SchemeDescriptor` and
  dispatches appraisal per scheme (veraison's
  ``ISchemeImplementation`` + ``SchemeDescriptor``, minus the Go
  plugin machinery);
* the EAR trust vector: per-dimension grades
  ``affirmed`` / ``contraindicated`` / ``insufficient`` plus an
  overall appraisal -- a failing dimension is surfaced, never folded
  into a bare boolean (veraison's EAR: Entity Attestation Results).

Traps NOT followed (documented, not hidden): CBOR/COSE wire formats,
the multi-service deployment (verification + provisioning), and OPA
as a runtime dependency -- Sasanam's offline evidence honesty
forbids importing that operational weight. Policy-as-data here is a
pinned JSON document, appraised by this module.

Fail-closed rules (all LOUD, coded :class:`TrustVectorError`):
* unknown scheme, or evidence failing the scheme's claim grammar;
* an endorsement sourced from the evidence's own producer
  (``trustvec-endorsement-not-independent``);
* appraisal under an unpinned or drifted policy document;
* no endorsement on an ``endorsed-match`` dimension => at most
  INSUFFICIENT, never affirmed (the honest limitation made
  structural);
* :func:`require_affirmed` refuses CONTRAINDICATED always -- a live
  governed exception can never upgrade a contraindication -- and
  refuses INSUFFICIENT without a live, covering exception.

Composition, not duplication:
* appraisal consumes ``(claim_digest, scheme_id, endorsements)``
  tuples -- the narrow seam through which lane 7's
  ``gov/evidence_provenance.py`` composes. Provenance is one evidence
  input to appraisal, not a dependency of this module.
* operator-issued trust routes through ``gov/governed_exceptions.py``:
  :func:`require_affirmed` accepts an ``ExceptionStore``; a live
  exception with check ``SAS_TRUSTVEC_ACCEPT_RISK`` and scope
  ``("policy", policy_id)`` turns INSUFFICIENT into an
  accepted-at-risk record. The vector is UNCHANGED (SKIPPED-shaped,
  exception digest attached) -- an exception is accepted-risk
  evidence, never an upgrade.

Honest limitations (documented, not hidden): the vector is only as
good as its endorsement sources; appraisal runs over declared claims,
not observed runtime; operator-claimed timestamps; no endorsement ever
means insufficient, never affirmed; operator-trust is a NAME-ALLOWLIST
over declared producer_id values -- the evidence model carries no
signatures anywhere, so there is no key-pinned authentication behind
it (F343: the former `trust_anchors` producer-id -> key-id contract
was renamed to `trusted_producers` producer-id -> authority label and
the key ids removed precisely because they were never consulted).
Submission is itself the privileged act in this model.

All refusals are LOUD: coded :class:`TrustVectorError`, never silent.
"""

import hashlib
import hmac
import json
import os
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EAR_FORMAT = "sasanam-ear/v1"

POLICY_FORMAT = "sasanam-appraisal-policy/v1"

#: Closed grade vocabulary (veraison's trust-vector shape, our words).
AFFIRMED = "affirmed"
CONTRAINDICATED = "contraindicated"
INSUFFICIENT = "insufficient"
GRADES = (AFFIRMED, CONTRAINDICATED, INSUFFICIENT)

#: Grade ordering: worst wins for the overall appraisal.
_GRADE_RANK = {AFFIRMED: 2, INSUFFICIENT: 1, CONTRAINDICATED: 0}

#: Closed dimension-rule vocabulary.
RULE_ENDORSED_MATCH = "endorsed-match"
RULE_OPERATOR_TRUST = "operator-trust"
RULE_ADVISORY = "advisory"
DIMENSION_RULES = (RULE_ENDORSED_MATCH, RULE_OPERATOR_TRUST, RULE_ADVISORY)

#: Closed claim-type vocabulary for scheme grammars.
CLAIM_TYPES = ("str", "int", "bool", "digest", "list", "dict")

#: Check id used with gov/governed_exceptions.py for accept-at-risk.
ACCEPT_RISK_CHECK_ID = "SAS_TRUSTVEC_ACCEPT_RISK"

# Machine codes (registered in gov/decision_codes.py, domain 'trustvec').
SCHEME_UNKNOWN = "trustvec-scheme-unknown"
SCHEME_DUPLICATE = "trustvec-scheme-duplicate"
EVIDENCE_INVALID = "trustvec-evidence-invalid"
ENDORSEMENT_NOT_INDEPENDENT = "trustvec-endorsement-not-independent"
POLICY_INVALID = "trustvec-policy-invalid"
POLICY_UNPINNED = "trustvec-policy-unpinned"
POLICY_DRIFT = "trustvec-policy-drift"
APPRAISAL_CONTRAINDICATED = "trustvec-appraisal-contraindicated"
APPRAISAL_INSUFFICIENT = "trustvec-appraisal-insufficient"
NO_COVERING_EXCEPTION = "trustvec-no-covering-exception"


class TrustVectorError(ValueError):
    """Loud trust-vector failure. ``code`` is the machine-readable
    failure mode."""

    def __init__(self, message, code):
        super(TrustVectorError, self).__init__(
            "%s: %s" % (code, message))
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Canonical digests
# ---------------------------------------------------------------------------

def _canonical(obj):
    """Canonical JSON bytes for digest binding. The digest model only
    binds JSON-serializable claim values; anything else refuses LOUD
    with ``trustvec-evidence-invalid`` (F344) rather than escaping as
    an uncoded ``TypeError`` from ``json.dumps``."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise TrustVectorError(
            "claim/endorsement value is not JSON-serializable: %s" % (exc,),
            code=EVIDENCE_INVALID)


def _digest(obj):
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


def _digest_value(value):
    """Digest binding for a single claim/endorsement value."""
    return _digest({"v": value})


# ---------------------------------------------------------------------------
# Scheme plugin registry
# ---------------------------------------------------------------------------

class SchemeDescriptor(object):
    """Per-scheme plugin descriptor (veraison's SchemeDescriptor shape).

    ``claim_grammar`` maps claim name -> one of CLAIM_TYPES.
    ``dimensions`` is a list of {"name", "rule", "claims"}; the rule is
    one of DIMENSION_RULES and every named claim must exist in the
    grammar. ``appraise_fn`` is an optional per-scheme hook with
    signature ``(evidence, endorsements, policy, grade_fn) -> dict``
    returning {dimension_name: grade}; its output is validated
    fail-closed.
    """

    def __init__(self, scheme_id, claim_grammar, dimensions,
                 appraise_fn=None):
        if not isinstance(scheme_id, str) or not scheme_id:
            raise TrustVectorError(
                "scheme_id must be a non-empty string",
                code=EVIDENCE_INVALID)
        if (not isinstance(claim_grammar, dict) or not claim_grammar
                or not all(isinstance(k, str) for k in claim_grammar)
                or not all(v in CLAIM_TYPES
                           for v in claim_grammar.values())):
            raise TrustVectorError(
                "claim_grammar must map claim names to one of %s"
                % (sorted(CLAIM_TYPES),),
                code=EVIDENCE_INVALID)
        if not isinstance(dimensions, list):
            raise TrustVectorError(
                "dimensions must be a list", code=EVIDENCE_INVALID)
        seen = set()
        for dim in dimensions:
            if (not isinstance(dim, dict)
                    or not isinstance(dim.get("name"), str)
                    or not dim["name"]):
                raise TrustVectorError(
                    "dimension needs a non-empty name",
                    code=EVIDENCE_INVALID)
            if dim["name"] in seen:
                raise TrustVectorError(
                    "duplicate dimension %r" % (dim["name"],),
                    code=EVIDENCE_INVALID)
            seen.add(dim["name"])
            if dim.get("rule") not in DIMENSION_RULES:
                raise TrustVectorError(
                    "dimension %r rule must be one of %s"
                    % (dim["name"], DIMENSION_RULES),
                    code=EVIDENCE_INVALID)
            claims = dim.get("claims")
            if (not isinstance(claims, list) or not claims
                    or not all(c in claim_grammar for c in claims)):
                raise TrustVectorError(
                    "dimension %r claims must be a non-empty list drawn "
                    "from the claim grammar" % (dim["name"],),
                    code=EVIDENCE_INVALID)
        if appraise_fn is not None and not callable(appraise_fn):
            raise TrustVectorError(
                "appraise_fn must be callable or None",
                code=EVIDENCE_INVALID)
        self.scheme_id = scheme_id
        self.claim_grammar = dict(claim_grammar)
        self.dimensions = [dict(d) for d in dimensions]
        self.appraise_fn = appraise_fn


_SCHEMES = {}


def register_scheme(descriptor):
    """Register a scheme plugin. Duplicate scheme ids refuse LOUD."""
    if not isinstance(descriptor, SchemeDescriptor):
        raise TrustVectorError(
            "register_scheme needs a SchemeDescriptor",
            code=EVIDENCE_INVALID)
    if descriptor.scheme_id in _SCHEMES:
        raise TrustVectorError(
            "scheme %r is already registered"
            % (descriptor.scheme_id,),
            code=SCHEME_DUPLICATE)
    _SCHEMES[descriptor.scheme_id] = descriptor
    return descriptor


def get_scheme(scheme_id):
    """Fetch a registered scheme or refuse LOUD."""
    try:
        return _SCHEMES[scheme_id]
    except KeyError:
        raise TrustVectorError(
            "unknown attestation scheme %r" % (scheme_id,),
            code=SCHEME_UNKNOWN)


def registered_schemes():
    return sorted(_SCHEMES)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

_TYPE_CHECKS = {
    "str": lambda v: isinstance(v, str),
    "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "bool": lambda v: isinstance(v, bool),
    "list": lambda v: isinstance(v, list),
    "dict": lambda v: isinstance(v, dict),
}


def _check_digest_shape(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


class Evidence(object):
    """Validated evidence: claims bound to a scheme and a producer."""

    def __init__(self, scheme_id, claims, producer_id, digest):
        self.scheme_id = scheme_id
        self.claims = claims
        self.producer_id = producer_id
        self.digest = digest


def submit_evidence(scheme_id, claims, producer_id):
    """Validate claims against the scheme grammar and bind them to the
    producer. Every grammar failure refuses LOUD."""
    scheme = get_scheme(scheme_id)
    if not isinstance(producer_id, str) or not producer_id:
        raise TrustVectorError(
            "producer_id must be a non-empty string",
            code=EVIDENCE_INVALID)
    if not isinstance(claims, dict):
        raise TrustVectorError(
            "claims must be a mapping", code=EVIDENCE_INVALID)
    missing = [c for c in scheme.claim_grammar if c not in claims]
    if missing:
        raise TrustVectorError(
            "evidence missing required claims %r for scheme %r"
            % (sorted(missing), scheme_id),
            code=EVIDENCE_INVALID)
    extra = [c for c in claims if c not in scheme.claim_grammar]
    if extra:
        raise TrustVectorError(
            "evidence carries undeclared claims %r for scheme %r"
            % (sorted(extra), scheme_id),
            code=EVIDENCE_INVALID)
    for name, want in scheme.claim_grammar.items():
        value = claims[name]
        if want == "digest":
            ok = _check_digest_shape(value)
        else:
            ok = _TYPE_CHECKS[want](value)
        if not ok:
            raise TrustVectorError(
                "claim %r must be %s for scheme %r"
                % (name, want, scheme_id),
                code=EVIDENCE_INVALID)
    digest = _digest({"scheme_id": scheme_id,
                      "claims": claims,
                      "producer_id": producer_id})
    return Evidence(scheme_id, dict(claims), producer_id, digest)


# ---------------------------------------------------------------------------
# Endorsements (golden values, separately sourced)
# ---------------------------------------------------------------------------

class Endorsement(object):
    """A golden value for one claim, bound to evidence and source."""

    def __init__(self, evidence_digest, claim_name, expected_digest,
                 source_id, digest):
        self.evidence_digest = evidence_digest
        self.claim_name = claim_name
        self.expected_digest = expected_digest
        self.source_id = source_id
        self.digest = digest


def endorse(evidence, claim_name, expected_value, source_id):
    """Add an endorsement for one claim. An endorsement sourced from
    the evidence's own producer refuses LOUD -- the slot exists so the
    verifier checks WITHOUT trusting the producer."""
    if not isinstance(evidence, Evidence):
        raise TrustVectorError(
            "endorse needs an Evidence object", code=EVIDENCE_INVALID)
    scheme = get_scheme(evidence.scheme_id)
    if claim_name not in scheme.claim_grammar:
        raise TrustVectorError(
            "claim %r is not in scheme %r grammar"
            % (claim_name, evidence.scheme_id),
            code=EVIDENCE_INVALID)
    if not isinstance(source_id, str) or not source_id:
        raise TrustVectorError(
            "source_id must be a non-empty string",
            code=EVIDENCE_INVALID)
    if source_id == evidence.producer_id:
        raise TrustVectorError(
            "endorsement source %r is the evidence producer: "
            "endorsements must be separately sourced"
            % (source_id,),
            code=ENDORSEMENT_NOT_INDEPENDENT)
    expected_digest = _digest_value(expected_value)
    digest = _digest({"evidence_digest": evidence.digest,
                      "claim_name": claim_name,
                      "expected_digest": expected_digest,
                      "source_id": source_id})
    return Endorsement(evidence.digest, claim_name, expected_digest,
                       source_id, digest)


# ---------------------------------------------------------------------------
# Appraisal policy (policy-as-data, pinned)
# ---------------------------------------------------------------------------

class AppraisalPolicy(object):
    """A compiled, digest-bound appraisal policy document.

    ``trusted_producers`` is a name-allowlist: producer id -> a
    non-empty authority label (e.g. "release-authority"). There is no
    key material in the contract -- see the honest-limitations block
    at module top.
    """

    def __init__(self, policy_id, scheme_id, trusted_producers,
                 digest, doc):
        self.policy_id = policy_id
        self.scheme_id = scheme_id
        self.trusted_producers = trusted_producers
        self.digest = digest
        self.doc = doc


def compile_policy(doc):
    """Validate an appraisal-policy document and bind its digest.
    Every malformed document refuses LOUD."""
    if not isinstance(doc, dict):
        raise TrustVectorError(
            "policy document must be a mapping", code=POLICY_INVALID)
    if doc.get("format") != POLICY_FORMAT:
        raise TrustVectorError(
            "policy format must be %r" % (POLICY_FORMAT,),
            code=POLICY_INVALID)
    policy_id = doc.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        raise TrustVectorError(
            "policy needs a non-empty policy_id", code=POLICY_INVALID)
    scheme_id = doc.get("scheme_id")
    if not isinstance(scheme_id, str) or not scheme_id:
        raise TrustVectorError(
            "policy needs a non-empty scheme_id", code=POLICY_INVALID)
    get_scheme(scheme_id)  # unknown scheme refuses LOUD here
    if "trust_anchors" in doc:
        raise TrustVectorError(
            "trust_anchors was renamed to trusted_producers (F343): "
            "the producer-id -> key-id contract overpromised -- the "
            "evidence model carries no signatures, so the key ids "
            "were never consulted. Use trusted_producers (producer "
            "id -> non-empty authority label) instead.",
            code=POLICY_INVALID)
    producers = doc.get("trusted_producers", {})
    if (not isinstance(producers, dict)
            or not all(isinstance(k, str) and k
                       and isinstance(v, str) and v
                       for k, v in producers.items())):
        raise TrustVectorError(
            "trusted_producers must map producer id -> non-empty "
            "authority label",
            code=POLICY_INVALID)
    digest = _digest(doc)
    return AppraisalPolicy(policy_id, scheme_id, dict(producers), digest,
                           dict(doc))


def pin_appraisal_policy(policy_id, digest, pinpath):
    """Commit a policy digest to a pin file. Refuses to silently
    overwrite an existing pin."""
    if not isinstance(policy_id, str) or not policy_id:
        raise TrustVectorError(
            "policy_id must be a non-empty string", code=POLICY_INVALID)
    if not _check_digest_shape(digest):
        raise TrustVectorError(
            "pin digest must be 64 lowercase hex", code=POLICY_INVALID)
    pins = {}
    if os.path.exists(pinpath):
        with open(pinpath, encoding="utf-8") as fh:
            try:
                pins = json.load(fh)
            except ValueError:
                raise TrustVectorError(
                    "pin file %r is not valid JSON" % (pinpath,),
                    code=POLICY_INVALID)
        if not isinstance(pins, dict):
            raise TrustVectorError(
                "pin file %r must hold an object" % (pinpath,),
                code=POLICY_INVALID)
        if pins.get(policy_id) == digest:
            return pins  # idempotent re-pin of the same digest
        if policy_id in pins:
            raise TrustVectorError(
                "policy %r already pinned: re-pin only after review"
                % (policy_id,),
                code=POLICY_DRIFT)
    pins[policy_id] = digest
    tmp = pinpath + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(pins, fh, sort_keys=True, indent=2)
        fh.write("\n")
    os.replace(tmp, pinpath)
    return pins


def load_appraisal_pins(pinpath):
    """Load a pin file. Missing or malformed files refuse LOUD."""
    if not os.path.exists(pinpath):
        raise TrustVectorError(
            "pin file %r does not exist" % (pinpath,),
            code=POLICY_UNPINNED)
    with open(pinpath, encoding="utf-8") as fh:
        try:
            pins = json.load(fh)
        except ValueError:
            raise TrustVectorError(
                "pin file %r is not valid JSON" % (pinpath,),
                code=POLICY_INVALID)
    if not isinstance(pins, dict):
        raise TrustVectorError(
            "pin file %r must hold an object" % (pinpath,),
            code=POLICY_INVALID)
    return pins


# ---------------------------------------------------------------------------
# Appraisal: evidence + endorsements + policy -> EAR trust vector
# ---------------------------------------------------------------------------

def _grade_dimension(evidence, endorsements, policy, dimension):
    """Grade one dimension under its rule. Worst claim wins."""
    scheme = get_scheme(evidence.scheme_id)
    rule = dimension["rule"]
    by_claim = {}
    for end in endorsements:
        by_claim.setdefault(end.claim_name, []).append(end)

    if rule == RULE_ENDORSED_MATCH:
        worst = AFFIRMED
        for claim in dimension["claims"]:
            ends = [e for e in by_claim.get(claim, [])
                    if e.evidence_digest == evidence.digest]
            if not ends:
                # The honest limitation, made structural: no
                # endorsement is never affirmed.
                grade = INSUFFICIENT
            else:
                actual = _digest_value(evidence.claims[claim])
                if any(not hmac.compare_digest(e.expected_digest, actual)
                       for e in ends):
                    grade = CONTRAINDICATED
                else:
                    grade = AFFIRMED
            if _GRADE_RANK[grade] < _GRADE_RANK[worst]:
                worst = grade
        return worst

    if rule == RULE_OPERATOR_TRUST:
        # F343: name-allowlist over the DECLARED producer_id. There are
        # no signatures in the evidence model, so this is not
        # authentication -- submission is the privileged act.
        if evidence.producer_id in policy.trusted_producers:
            return AFFIRMED
        return INSUFFICIENT

    # RULE_ADVISORY: informational; never contraindicates.
    for claim in dimension["claims"]:
        if claim not in evidence.claims:
            return INSUFFICIENT
    return AFFIRMED


def _grade_all(evidence, endorsements, policy):
    scheme = get_scheme(evidence.scheme_id)
    vector = {}
    for dim in scheme.dimensions:
        vector[dim["name"]] = _grade_dimension(evidence, endorsements,
                                               policy, dim)
    return vector


def _check_endorsement_binding(evidence, endorsements):
    if not isinstance(endorsements, (list, tuple)):
        raise TrustVectorError(
            "endorsements must be a list", code=EVIDENCE_INVALID)
    for end in endorsements:
        if not isinstance(end, Endorsement):
            raise TrustVectorError(
                "endorsements must be Endorsement objects",
                code=EVIDENCE_INVALID)
        if end.evidence_digest != evidence.digest:
            raise TrustVectorError(
                "endorsement for a different evidence object",
                code=EVIDENCE_INVALID)


def appraise(evidence, endorsements, policy, pins):
    """Appraise evidence against endorsements under a pinned policy.

    Returns the EAR-shaped trust vector. Refuses LOUD on unpinned or
    drifted policy, malformed endorsements, or bad custom-hook output.
    """
    if not isinstance(evidence, Evidence):
        raise TrustVectorError(
            "appraise needs an Evidence object", code=EVIDENCE_INVALID)
    if not isinstance(policy, AppraisalPolicy):
        raise TrustVectorError(
            "appraise needs an AppraisalPolicy", code=POLICY_INVALID)
    if evidence.scheme_id != policy.scheme_id:
        raise TrustVectorError(
            "evidence scheme %r does not match policy scheme %r"
            % (evidence.scheme_id, policy.scheme_id),
            code=EVIDENCE_INVALID)
    if not isinstance(pins, dict) or policy.policy_id not in pins:
        raise TrustVectorError(
            "policy %r is not pinned: appraisal decides only under "
            "pinned, reviewable policy" % (policy.policy_id,),
            code=POLICY_UNPINNED)
    if not hmac.compare_digest(str(pins[policy.policy_id]),
                               policy.digest):
        raise TrustVectorError(
            "policy %r digest drifted from its pin: re-review and "
            "re-pin before appraising" % (policy.policy_id,),
            code=POLICY_DRIFT)
    _check_endorsement_binding(evidence, endorsements)
    scheme = get_scheme(evidence.scheme_id)

    def _grade(ev, ends, pol):
        return _grade_all(ev, ends, pol)

    if scheme.appraise_fn is not None:
        vector = scheme.appraise_fn(evidence, endorsements, policy,
                                    _grade)
        if (not isinstance(vector, dict)
                or set(vector) != {d["name"] for d in scheme.dimensions}
                or not all(g in GRADES for g in vector.values())):
            raise TrustVectorError(
                "scheme %r appraise hook returned a malformed vector"
                % (scheme.scheme_id,),
                code=EVIDENCE_INVALID)
    else:
        vector = _grade(evidence, endorsements, policy)

    overall = AFFIRMED
    for grade in vector.values():
        if _GRADE_RANK[grade] < _GRADE_RANK[overall]:
            overall = grade
    ear = {
        "ear_format": EAR_FORMAT,
        "entity_digest": evidence.digest,
        "scheme_id": evidence.scheme_id,
        "policy_id": policy.policy_id,
        "policy_digest": policy.digest,
        "appraised_at": time.time(),
        "vector": dict(vector),
        "overall": overall,
        "evidence_digest": evidence.digest,
        "endorsement_digests": sorted(e.digest for e in endorsements),
    }
    ear["appraisal_digest"] = _digest(
        {"entity_digest": ear["entity_digest"],
         "scheme_id": ear["scheme_id"],
         "policy_id": ear["policy_id"],
         "policy_digest": ear["policy_digest"],
         "vector": ear["vector"],
         "overall": ear["overall"],
         "endorsement_digests": ear["endorsement_digests"]})
    return ear


# ---------------------------------------------------------------------------
# require_affirmed: the fail-closed gate over an EAR
# ---------------------------------------------------------------------------

def _check_ear_shape(ear):
    if not isinstance(ear, dict):
        raise TrustVectorError(
            "EAR must be a mapping", code=EVIDENCE_INVALID)
    for key in ("ear_format", "vector", "overall", "policy_id"):
        if key not in ear:
            raise TrustVectorError(
                "EAR missing %r" % (key,), code=EVIDENCE_INVALID)
    if ear.get("ear_format") != EAR_FORMAT:
        raise TrustVectorError(
            "EAR format must be %r" % (EAR_FORMAT,),
            code=EVIDENCE_INVALID)
    if (not isinstance(ear["vector"], dict)
            or not all(g in GRADES for g in ear["vector"].values())):
        raise TrustVectorError(
            "EAR vector malformed", code=EVIDENCE_INVALID)
    if ear["overall"] not in GRADES:
        raise TrustVectorError(
            "EAR overall grade malformed", code=EVIDENCE_INVALID)


def require_affirmed(ear, exception_store=None, now=None):
    """Fail-closed gate over an appraised EAR.

    * overall affirmed -> {"status": "affirmed", "ear": ear};
    * overall contraindicated -> refuses LOUD ALWAYS. A live governed
      exception can NEVER upgrade a contraindication;
    * overall insufficient -> refuses LOUD with
      ``trustvec-appraisal-insufficient`` unless a live, covering
      exception (check ``SAS_TRUSTVEC_ACCEPT_RISK``, scope
      ``("policy", policy_id)``) exists in ``exception_store``; with
      one, returns {"status": "accepted-at-risk", "ear": ear,
      "exception_digest": ...}. The vector is UNCHANGED: the
      exception is accepted-risk evidence (SKIPPED-shaped), never an
      upgrade. An expired/revoked covering exception refuses LOUD via
      the store -- never a silent fallthrough.
    """
    _check_ear_shape(ear)
    overall = ear["overall"]
    if overall == AFFIRMED:
        return {"status": "affirmed", "ear": ear}
    if overall == CONTRAINDICATED:
        raise TrustVectorError(
            "trust vector is contraindicated: failing dimensions %r; "
            "no exception can upgrade a contraindication"
            % (sorted(d for d, g in ear["vector"].items()
                      if g == CONTRAINDICATED),),
            code=APPRAISAL_CONTRAINDICATED)
    # INSUFFICIENT from here on.
    if exception_store is None:
        raise TrustVectorError(
            "trust vector is insufficient and no exception store was "
            "offered: failing dimensions %r"
            % (sorted(d for d, g in ear["vector"].items()
                      if g != AFFIRMED),),
            code=APPRAISAL_INSUFFICIENT)
    result = exception_store.evaluate(
        ACCEPT_RISK_CHECK_ID,
        ("policy", ear["policy_id"]),
        lambda: False,
        now=now)
    if result.get("status") == "SKIPPED":
        return {"status": "accepted-at-risk", "ear": ear,
                "exception_digest": result["exception_digest"]}
    raise TrustVectorError(
        "trust vector is insufficient and no live exception covers "
        "policy %r" % (ear["policy_id"],),
        code=NO_COVERING_EXCEPTION)
