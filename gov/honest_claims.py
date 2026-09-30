"""Reserved-claim vocabulary: machine-enforced honest-claim discipline.

Wave-233 lane C. Stdlib only.

Re-derived from the NOA honest-claim direction (normative NON-CLAIMS.md
at the repo root, reserved-not-emitted tokens, doc-truth mechanical
CI): Sasanam evidence must never EMIT reserved claim tokens. The
reserved vocabulary is a closed :data:`RESERVED_CLAIM_TOKENS`
frozenset; :func:`assert_no_reserved_claims` scans a rendered artifact
(a receipt, packet, or evidence-bundle payload) and refuses
``honest-claim-reserved-token``, naming the exact token found.

Scan semantics (deliberate, fail-closed):

* Matching is case-insensitive and normalizes ``_`` and space to
  ``-`` (``Tamper_Proof`` -> ``tamper-proof``). Substring matching is
  intentional over-approximation: an evidence artifact that even
  MENTIONS ``tamper-proof`` has made the claim. This is a claim
  discipline, not NLP.
* Only string VALUES are scanned; dict keys are never claims
  (a receipt's own ``non_repudiation`` key must not trip the scan).
* Any subtree nested under a dict key named ``does_not_prove`` is
  EXEMPT: honestly declaring what is NOT proven is not a claim.
  This is what lets claim-bounded bundles (gov/claim_bounds.py)
  name ``non-repudiation`` in their ``does_not_prove`` list.
* ``tamper-evident`` is deliberately NOT reserved: it is an
  integrity claim about digests and chains, which evidence CAN
  prove. Only the overstated tokens are banned.

There is no keyword opt-out and no silent bypass by design: every
call to :func:`assert_no_reserved_claims` either passes or refuses,
and the product wirings import this module unconditionally (a
missing vocabulary breaks the import -- fail closed -- rather
than skipping enforcement).
The evidence-bundle builder (gov/evidence_bundle.py,
``EvidenceBundle.build``) and the denial-receipt emitter
(gov/deny_receipts.py, ``emit``) call it additively on their
rendered output, before signing or sealing.
"""

# The closed vocabulary. ``proof-of-execution`` and
# ``proof-of-human-review`` are normalized variant forms of the
# ``proves-execution`` / ``proves-human-understanding`` families
# (speculative phrasing a claim could hide behind). Additions
# require a NON-CLAIMS.md entry justifying why the token is never
# provable by our evidence.
RESERVED_CLAIM_TOKENS = frozenset([
    "proves-execution",
    "proof-of-execution",
    "proves-human-understanding",
    "proof-of-human-review",
    "non-repudiation",
    "tamper-proof",
    "formally-verified",
])

REFUSAL_CODE = "honest-claim-reserved-token"

# Subtrees under this dict key are honest non-claims, not claims.
_EXEMPT_KEY = "does_not_prove"


class HonestClaimError(Exception):
    """A rendered evidence artifact contains a reserved claim token.

    ``code`` is machine-readable and registered in
    gov/decision_codes.py (domain ``honest_claims``). ``token`` is the
    exact reserved token found (normalized form).
    """
    code = REFUSAL_CODE

    def __init__(self, token, message=""):
        super().__init__(message or
                         "%s: reserved claim token %r must never be "
                         "emitted by Sasanam evidence" % (self.code, token))
        self.token = token


def normalize_claim_text(text):
    """Lowercase and normalize separators to the canonical token form."""
    return text.lower().replace("_", "-").replace(" ", "-")


def find_reserved_claim(artifact):
    """Return the first reserved token found in ``artifact``, else None.

    ``artifact`` may be a str, bytes, dict, list/tuple, or scalar.
    Dict keys are never scanned; ``does_not_prove`` subtrees are
    exempt (see module docstring).
    """
    if isinstance(artifact, bytes):
        try:
            artifact = artifact.decode("utf-8")
        except ValueError:
            return None
    if isinstance(artifact, str):
        text = normalize_claim_text(artifact)
        for token in sorted(RESERVED_CLAIM_TOKENS):
            if token in text:
                return token
        return None
    if isinstance(artifact, dict):
        for key, value in artifact.items():
            if key == _EXEMPT_KEY:
                continue
            hit = find_reserved_claim(value)
            if hit is not None:
                return hit
        return None
    if isinstance(artifact, (list, tuple)):
        for item in artifact:
            hit = find_reserved_claim(item)
            if hit is not None:
                return hit
        return None
    return None


def assert_no_reserved_claims(artifact):
    """Refuse ``honest-claim-reserved-token`` if ``artifact`` emits a
    reserved claim token. Returns None on a clean artifact.

    No opt-out keyword exists: this either passes or refuses.
    """
    hit = find_reserved_claim(artifact)
    if hit is not None:
        raise HonestClaimError(hit)
    return None
