"""C2PA 2.4 conformance *verification* (ADAPT, rules-only).

PROVENANCE (honest, non-vendored):
  - The rules enforced here are adapted from the official C2PA
    conformance rubric v1.0 (2026-08-06), which is CC-BY-4.0
    *rules-only*. The rules are described in this module's own words;
    no rubric text is copied into docstrings, comments, or strings.
  - There is no official 2.4 binary test corpus anywhere. All vectors
    in ``evals/w215_c2pa24_probes.py`` are regenerated LOCALLY by our
    own deterministic generator and marked "locally-regenerated";
    ``public-testfiles`` is 2.2-only and CC-BY-SA share-alike, so
    nothing is vendored from it. c2pa-rs was unavailable in this
    environment (no cargo); our own generator stands in for it.

Scope: this module is a *verifier only*. It never emits manifests.
``gov/c2pa_provenance.py`` keeps emitting its 2.2-shaped vocabulary
(explicitly not conformant); this module judges whether a manifest's
assertion vocabulary meets the 2.4 profile:

  - ``c2pa.actions`` (unversioned) and ``c2pa.ingredient`` (unversioned)
    are DEPRECATED in 2.4. They are refused by default; a deprecated
    label is admitted ONLY when the caller presents a *digest-bound,
    issuer-signed re-pin* for exactly that assertions payload.
  - ``c2pa.actions.v2``, ``c2pa.ingredient.v3`` are the current labels
    (shape-checked, closed vocabularies).
  - ``c2pa.ai-disclosure`` (new in 2.4) is allowed (shape-checked).
  - Any other assertion label is refused -- closed vocabulary.

The verifier takes an ``assertions`` dict (the same subtree shape the
2.2 builder produces), so existing 2.2 emission can be checked
directly -- and is refused by default, which is the deprecation
pressure made real.

Trust-list layering for *signed-C2PA assertion trust records* (who we
trust to sign C2PA-shaped claims): records carry a ``layer`` in
``{"default", "itl", "custom"}`` (adapted from the conformance tool's
default -> itl -> custom layering). Lookup precedence is
custom > itl > default: the first matching layer decides. Records are
Ed25519-signed by a pinned trust-authority; records carry only a
``kid``, never a usable key.

stdlib-only. Fail-closed: the single error vocabulary is
``C2PA24Error`` with a ``.code`` refusal code; malformed inputs verify
False/raise, never pass silently.
"""

import hashlib
import json
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from . import ed25519 as _ed

#: Current 2.4 assertion labels (shape-checked below).
ACCEPTED_LABELS = (
    "c2pa.actions.v2",
    "c2pa.ingredient.v3",
    "c2pa.ai-disclosure",
    "c2pa.hash.data",
    "c2pa.signature",
)

#: Deprecated in 2.4: refused unless an explicit digest-bound re-pin
#: is presented. A pin is NEVER blanket -- it names one assertions
#: payload digest.
DEPRECATED_LABELS = ("c2pa.actions", "c2pa.ingredient")

#: Trust layers, lowest to highest precedence.
TRUST_LAYERS = ("default", "itl", "custom")

#: Domain separation for deprecation-pin signatures.
PIN_SIGN_DOMAIN = b"sasanam-c2pa24-deprecation-pin/v1:"
#: Domain separation for trust-record signatures.
TRUST_SIGN_DOMAIN = b"sasanam-c2pa24-trust-sign/v1:"

#: Closed action vocabulary accepted under ``c2pa.actions.v2``. These
#: are C2PA action identifiers (factual vocabulary terms, not prose)
#: from the subset this verifier supports; unknown action labels are
#: refused.
V2_KNOWN_ACTIONS = (
    "c2pa.created",
    "c2pa.edited",
    "c2pa.repackaged",
    "c2pa.filtered",
    "c2pa.color_adjustments",
    "c2pa.transcoded",
    "c2pa.ai_generated",
)

#: Closed ingredient-role vocabulary for ``c2pa.ingredient.v3`` --
#: the same discipline as the 2.2 builder: every parent says what
#: kind of parent it is.
V3_KNOWN_ROLES = ("prompt", "model", "tool-output", "prior-decision",
                  "policy", "evidence-bundle")


class C2PA24Error(Exception):
    """Single fail-closed vocabulary for 2.4 conformance violations.

    ``code`` is the machine refusal code; human text follows it.
    """

    def __init__(self, code, detail):
        self.code = code
        super().__init__("[%s] %s" % (code, detail))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _is_hex128(value):
    return (isinstance(value, str) and len(value) == 128
            and all(c in "0123456789abcdef" for c in value))


def _shape_error(label, detail):
    raise C2PA24Error("bad-assertion-shape",
                      "%s: %s" % (label, detail))


def _check_v2_actions(label, body):
    if not isinstance(body, dict):
        _shape_error(label, "assertion body must be a dict")
    if body.get("version") != 2:
        _shape_error(label, "version must be exactly 2, got %r"
                     % body.get("version"))
    actions = body.get("actions")
    if not isinstance(actions, list) or not actions:
        _shape_error(label, "actions must be a non-empty list")
    for i, action in enumerate(actions):
        where = "%s.actions[%d]" % (label, i)
        if not isinstance(action, dict):
            _shape_error(label, "%s: must be a dict" % where)
        name = action.get("action")
        if not isinstance(name, str):
            _shape_error(label, "%s.action must be a string" % where)
        if name not in V2_KNOWN_ACTIONS:
            raise C2PA24Error(
                "unknown-action-label",
                "%s: action %r not in the 2.4 closed vocabulary"
                % (where, name))
        agent = action.get("softwareAgent")
        if agent is not None and not isinstance(agent, str):
            _shape_error(label, "%s.softwareAgent must be a string" % where)


def _check_v3_ingredient(label, body):
    if not isinstance(body, dict):
        _shape_error(label, "assertion body must be a dict")
    if body.get("version") != 3:
        _shape_error(label, "version must be exactly 3, got %r"
                     % body.get("version"))
    ings = body.get("ingredients")
    if not isinstance(ings, list):
        _shape_error(label, "ingredients must be a list")
    for i, ing in enumerate(ings):
        where = "%s.ingredients[%d]" % (label, i)
        if not isinstance(ing, dict):
            _shape_error(label, "%s: must be a dict" % where)
        if not _is_hex64(ing.get("ingredient_digest")):
            _shape_error(label, "%s.ingredient_digest must be sha256 hex"
                         % where)
        if ing.get("relationship") not in ("parentOf", "childOf"):
            _shape_error(label, "%s.relationship must be parentOf/childOf"
                         % where)
        if ing.get("role") not in V3_KNOWN_ROLES:
            _shape_error(label, "%s.role not in closed vocabulary" % where)


def _check_ai_disclosure(label, body):
    if not isinstance(body, dict):
        _shape_error(label, "assertion body must be a dict")
    disc = body.get("aiDisclosure")
    if not isinstance(disc, dict):
        _shape_error(label, "aiDisclosure must be a dict")
    if not isinstance(disc.get("label"), str) or not disc["label"]:
        _shape_error(label, "aiDisclosure.label must be a non-empty string")


def _check_hash_data(label, body):
    if not isinstance(body, dict):
        _shape_error(label, "assertion body must be a dict")
    if not _is_hex64(body.get("digest")):
        _shape_error(label, "digest must be sha256 hex")


def _check_signature(label, body):
    if not isinstance(body, dict):
        _shape_error(label, "assertion body must be a dict")
    if not isinstance(body.get("payloadType"), str):
        _shape_error(label, "payloadType must be a string")


_CHECKERS = {
    "c2pa.actions.v2": _check_v2_actions,
    "c2pa.ingredient.v3": _check_v3_ingredient,
    "c2pa.ai-disclosure": _check_ai_disclosure,
    "c2pa.hash.data": _check_hash_data,
    "c2pa.signature": _check_signature,
}


def assertions_digest(assertions):
    """sha256 over the canonical JSON of an assertions dict.

    This is the binding a deprecation re-pin targets: one digest, one
    pin, no blanket admissions.
    """
    if not isinstance(assertions, dict):
        raise C2PA24Error("bad-assertion-shape",
                          "assertions must be a dict")
    return hashlib.sha256(_canonical(assertions)).hexdigest()


def pin_signing_bytes(label, assertions_digest_value, reason):
    """Bytes the pin issuer signs: domain || sha256(canonical(body))."""
    body = {"label": label, "assertions_digest": assertions_digest_value,
            "reason": reason}
    return (PIN_SIGN_DOMAIN
            + hashlib.sha256(_canonical(body)).digest())


def sign_deprecation_pin(issuer_seed, *, label, assertions_digest,
                         reason):
    """Issue a digest-bound deprecation re-pin (operator-side).

    The pin admits ONE deprecated label on ONE assertions payload.
    ``reason`` is required so blanket pins are never silent.
    """
    if label not in DEPRECATED_LABELS:
        raise C2PA24Error("bad-pin",
                          "pin target %r is not a deprecated label" % label)
    if not _is_hex64(assertions_digest):
        raise C2PA24Error("bad-pin",
                          "assertions_digest must be sha256 hex")
    if not isinstance(reason, str) or not reason:
        raise C2PA24Error("bad-pin", "reason must be a non-empty string")
    msg = pin_signing_bytes(label, assertions_digest, reason)
    sig = _ed.sign(issuer_seed, msg)
    return {"label": label, "assertions_digest": assertions_digest,
            "reason": reason,
            "signer": {"kid": _ed.publickey(issuer_seed).hex()[:16]},
            "signature": sig.hex()}


def _verify_pin(pin, expected_digest, issuer_pub):
    where = "deprecation-pin"
    if not isinstance(pin, dict):
        raise C2PA24Error("bad-pin", "%s: must be a dict" % where)
    label = pin.get("label")
    if label not in DEPRECATED_LABELS:
        raise C2PA24Error("bad-pin", "%s: target %r not deprecated"
                          % (where, label))
    if pin.get("assertions_digest") != expected_digest:
        raise C2PA24Error("bad-pin", "%s: pin binds a different payload "
                          "(re-pin is digest-bound, never blanket)" % where)
    signer = pin.get("signer")
    if not isinstance(signer, dict) or set(signer) != {"kid"}:
        raise C2PA24Error("bad-pin",
                          "%s: signer must carry exactly {kid}" % where)
    sig_hex = pin.get("signature")
    if not _is_hex128(sig_hex):
        raise C2PA24Error("bad-pin",
                          "%s: signature must be 128-char hex" % where)
    msg = pin_signing_bytes(label, expected_digest, pin.get("reason", ""))
    try:
        ok = _ed.verify(issuer_pub, msg, bytes.fromhex(sig_hex))
    except Exception:
        ok = False
    if not ok:
        raise C2PA24Error("bad-pin",
                          "%s: issuer signature invalid" % where)
    return label


def verify_24_vocabulary(assertions, *, deprecated_pins=(),
                         deprecated_pin_issuer_pub=None):
    """Verify an assertions dict against the 2.4 profile.

    Returns a dict ``{"deprecated_admitted": [labels...]}`` listing the
    deprecated labels that were admitted via re-pin. Refusals raise
    ``C2PA24Error`` with codes:

      - ``deprecated-assertion-version``: unversioned c2pa.actions /
        c2pa.ingredient present without a valid digest-bound pin;
      - ``unknown-assertion-label``: any label outside the closed
        accepted + deprecated sets;
      - ``bad-assertion-shape`` / ``unknown-action-label``: accepted
        label with a malformed body;
      - ``bad-pin``: pin problems (wrong digest, wrong key, malformed).
    """
    if not isinstance(assertions, dict):
        raise C2PA24Error("bad-assertion-shape",
                          "assertions must be a dict")
    digest = assertions_digest(assertions)
    deprecated_admitted = []
    for label, body in assertions.items():
        if label in ACCEPTED_LABELS:
            _CHECKERS[label](label, body)
        elif label in DEPRECATED_LABELS:
            admitted = False
            for pin in (deprecated_pins or ()):
                if deprecated_pin_issuer_pub is None:
                    raise C2PA24Error(
                        "bad-pin",
                        "pin presented but no issuer key configured")
                got = _verify_pin(pin, digest, deprecated_pin_issuer_pub)
                if got == label:
                    admitted = True
                    break
            if not admitted:
                raise C2PA24Error(
                    "deprecated-assertion-version",
                    "%s is deprecated in the 2.4 profile; present a "
                    "digest-bound, issuer-signed re-pin to admit it" % label)
            deprecated_admitted.append(label)
        else:
            raise C2PA24Error(
                "unknown-assertion-label",
                "assertion label %r is outside the closed 2.4 vocabulary"
                % label)
    return {"deprecated_admitted": sorted(deprecated_admitted)}


# ---------------------------------------------------------------- trust
# lists: default -> itl -> custom layering for signed-C2PA assertion
# trust records. Lookup precedence: custom > itl > default; the first
# matching layer decides. Records are issuer-signed; they carry only a
# kid, never key material.


def trust_signing_bytes(layer, key_id, trust):
    body = {"layer": layer, "key_id": key_id, "trust": trust}
    return (TRUST_SIGN_DOMAIN
            + hashlib.sha256(_canonical(body)).digest())


def sign_trust_record(issuer_seed, *, layer, key_id, trust):
    """Issue one trust record (operator-side)."""
    if layer not in TRUST_LAYERS:
        raise C2PA24Error("bad-trust-record",
                          "layer %r not in %s" % (layer, list(TRUST_LAYERS)))
    if not isinstance(key_id, str) or not key_id:
        raise C2PA24Error("bad-trust-record",
                          "key_id must be a non-empty string")
    if trust not in ("allow", "deny"):
        raise C2PA24Error("bad-trust-record",
                          "trust must be allow/deny, got %r" % trust)
    msg = trust_signing_bytes(layer, key_id, trust)
    sig = _ed.sign(issuer_seed, msg)
    return {"layer": layer, "key_id": key_id, "trust": trust,
            "signer": {"kid": _ed.publickey(issuer_seed).hex()[:16]},
            "signature": sig.hex()}


class TrustStore:
    """Layered trust store: default -> itl -> custom."""

    def __init__(self):
        self._records = []  # (layer, key_id, trust), signed at add time

    def add_record(self, record, *, issuer_pub):
        if not isinstance(record, dict):
            raise C2PA24Error("bad-trust-record", "record must be a dict")
        layer = record.get("layer")
        key_id = record.get("key_id")
        trust = record.get("trust")
        signer = record.get("signer")
        sig_hex = record.get("signature")
        if layer not in TRUST_LAYERS:
            raise C2PA24Error("bad-trust-record",
                              "layer %r unknown" % layer)
        if not isinstance(key_id, str) or not key_id:
            raise C2PA24Error("bad-trust-record", "key_id bad")
        if trust not in ("allow", "deny"):
            raise C2PA24Error("bad-trust-record", "trust bad")
        if not isinstance(signer, dict) or set(signer) != {"kid"}:
            raise C2PA24Error("bad-trust-record",
                              "signer must carry exactly {kid}")
        if not _is_hex128(sig_hex):
            raise C2PA24Error("bad-trust-signature",
                              "trust record signature malformed")
        msg = trust_signing_bytes(layer, key_id, trust)
        try:
            ok = _ed.verify(issuer_pub, msg, bytes.fromhex(sig_hex))
        except Exception:
            ok = False
        if not ok:
            raise C2PA24Error("bad-trust-signature",
                              "trust record not signed by the trust "
                              "authority")
        for r_layer, r_key, _ in self._records:
            if (r_layer, r_key) == (layer, key_id):
                raise C2PA24Error("duplicate-trust-record",
                                  "layer %r already has a record for %r; "
                                  "records are single-valued per layer"
                                  % (layer, key_id))
        self._records.append((layer, key_id, trust))

    def lookup(self, key_id):
        """First matching layer wins: custom > itl > default."""
        for layer in reversed(TRUST_LAYERS):
            for r_layer, r_key, trust in self._records:
                if r_layer == layer and r_key == key_id:
                    return trust
        return None

    def check(self, key_id):
        """Return 'allow'; raise on deny or on no record."""
        trust = self.lookup(key_id)
        if trust == "allow":
            return trust
        if trust == "deny":
            raise C2PA24Error("signer-denied",
                              "key_id %r is denied by the trust list"
                              % key_id)
        raise C2PA24Error("untrusted-signer",
                          "key_id %r has no trust record in any layer"
                          % key_id)
