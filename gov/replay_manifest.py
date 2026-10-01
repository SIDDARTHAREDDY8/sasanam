"""Replay manifest v1: hash-chained, digest-addressed trajectory evidence.

Wave-271 (wave-270 prospectus section 2). **Terminology discipline:**
this module speaks of a *replay manifest*, never of "replay"
unqualified -- the prospectus teardown found "replay" is a spent word
(LangSmith means upload-retry, datasets mean re-execution, none of the
three vendors does deterministic trajectory replay). A replay manifest
is a hash-chained record from which an offline verifier can re-derive
*what was recorded*, without the engine.

Pattern/vocabulary steals (clean-room; no vendor code):
  - LangSmith ``dotted_order`` *shape* -- chain-derived ordering, not
    wall-clock -- and the git-info field list, *inverted* (dirty ->
    refuse-to-seal, never "still scored").
  - Braintrust span-origin discipline -- every link carries a
    content-addressed tool/code pin.
  - Phoenix span kinds + ``annotator_kind`` vocabulary only (Phoenix is
    Elastic License 2.0 -- ideas/vocabulary, NO Phoenix code).

What a manifest proves
----------------------
A *sealed* manifest proves: (1) this exact sequence of recorded
events existed with these digests; (2) the record is tamper-evident
(any edit breaks the chain); (3) every dispatched tool was pinned to a
verifiable code digest at seal time; (4) approval events reference
corroboration-receipt statements by digest (non-repudiation via the
receipt ceremony, verified by a caller-supplied checker); (5)
deliberate non-actions are recorded as negative evidence.

Honest limits (read before citing a manifest as proof)
------------------------------------------------------
  - A manifest proves what was *recorded*, not what *happened*: a
    writer with builder access can record a false but well-formed
    chain. The chain is tamper-evidence on the record, not truth.
  - Identical manifests do NOT imply identical outcomes.
    temperature=0 is not determinism; no bit-identity guarantee is
    offered, built, or implied.
  - Environment capture is advisory (``env`` is a hint, not a pin).
  - Approval-receipt *signatures* are verified only by a
    caller-supplied ``receipt_checker`` (built on
    ``gov.corroboration_receipt``). Without one, approval links are
    structurally pinned but signature-unverified -- reported honestly
    in the verification report (never silent).
  - Presentation bytes are caller-supplied at verification time; a
    digest with no presented bytes is reported unverified, never
    assumed shown.
  - Explicitly NOT built: replay-as-a-service, time-travel resume,
    bit-identity guarantees, OTel export (prospectus lane 8).

Composition
-----------
``as_evidence_artifact()`` wraps the sealed manifest with
``gov.evidence_bundle_v2.build_artifact`` -- the manifest becomes an
evidence artifact digest-addressed for the v2 submission flow.
Composition is by use; this module never mutates the v2 seam. The
import is lazy so ``verify_manifest`` stays importable with stdlib
only (the offline-verifier claim is real, not decorative).

Stdlib only: hashlib, hmac, json, re, time.
"""

import hashlib
import hmac
import json
import re
import time

from gov import decode_trust as _dt

MANIFEST_FORMAT = "sasanam-replay-manifest/v1"
GENESIS_HASH = "00" * 32  # 64 lowercase hex chars, like every link_hash

# Closed action vocabulary. Unknown actions are malformed (fail
# closed), never carried as free text.
ACTION_ENVIRONMENT_SNAPSHOT = "environment_snapshot"
ACTION_TOOL_CALL = "tool_call"
ACTION_PRESENTATION = "presentation"
ACTION_APPROVAL_REQUESTED = "approval_requested"
ACTION_APPROVAL_RECEIVED = "approval_received"
ACTION_GATE_CONSULT = "gate_consult"
# Wave-272: explicit content-equivalence annotations. A replay whose
# tool digest differs from the revision binding is refused unless the
# manifest carries one of these links covering
# (tool_id, bound_digest -> presented_digest) with a non-empty reason.
ACTION_CONTENT_EQUIVALENCE = "content_equivalence"
_ACTIONS = frozenset([
    ACTION_ENVIRONMENT_SNAPSHOT,
    ACTION_TOOL_CALL,
    ACTION_PRESENTATION,
    ACTION_APPROVAL_REQUESTED,
    ACTION_APPROVAL_RECEIVED,
    ACTION_GATE_CONSULT,
    ACTION_CONTENT_EQUIVALENCE,
])

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReplayManifestError(Exception):
    """Coded, fail-closed replay-manifest error. ``code`` is a machine
    code in the ``replay`` decision-code domain; ``detail`` is human
    text."""

    def __init__(self, code, detail):
        super(ReplayManifestError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _require_hex64(value, where):
    if not isinstance(value, str) or not _HEX64.match(value):
        raise ReplayManifestError(
            "replay-malformed",
            "%s must be 64 lowercase hex chars" % where)
    return value


def _link_hash(link_body):
    return _sha256_hex(_canonical(link_body))


# ---------------------------------------------------------------------------
# Code-pin policy: the fail-closed pin block (LangSmith inversion)
# ---------------------------------------------------------------------------

class CodePinPolicy(object):
    """Decides whether a tool/code digest pin is acceptable at seal
    time. The strict default refuses dirty or unverifiable pins --
    the opposite of the trace-vendor posture (``dirty: true`` still
    scored). Deployments back this with the per-tool grant store
    (``supply_chain.link_digest``) and the skill-bundle registry."""

    def verify_pin(self, *, tool_id, link_digest, dirty=False):
        """Return the canonical pin string, or raise
        ``replay-dirty-codebase-seal`` / ``replay-unverifiable-tool-digest``."""
        if dirty:
            raise ReplayManifestError(
                "replay-dirty-codebase-seal",
                "tool %r recorded dirty: refusing to seal (a dirty "
                "codebase is never sealed)" % (tool_id,))
        if not isinstance(link_digest, str) or not _HEX64.match(link_digest):
            raise ReplayManifestError(
                "replay-unverifiable-tool-digest",
                "tool %r has no verifiable digest pin; refusing to seal"
                % (tool_id,))
        return "sha256:" + link_digest


class InMemoryPinRegistry(CodePinPolicy):
    """Test/deployment helper: pins are registered explicitly; a
    claimed digest that does not match the registered one (or an
    unregistered tool) is unverifiable."""

    def __init__(self):
        self._pins = {}

    def register(self, tool_id, link_digest):
        _require_hex64(link_digest, "registered link_digest")
        self._pins[tool_id] = link_digest

    def verify_pin(self, *, tool_id, link_digest, dirty=False):
        if dirty:
            raise ReplayManifestError(
                "replay-dirty-codebase-seal",
                "tool %r recorded dirty: refusing to seal" % (tool_id,))
        expected = self._pins.get(tool_id)
        if expected is None or not hmac.compare_digest(
                str(link_digest or ""), expected):
            raise ReplayManifestError(
                "replay-unverifiable-tool-digest",
                "tool %r pin does not match the registry; refusing to "
                "seal" % (tool_id,))
        return "sha256:" + expected


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class ReplayManifestBuilder(object):
    """Appends hash-chained links for one agent trajectory.

    ``actor`` is the workload identity (SPIFFE-ID-shaped string).
    ``now`` is an explicit clock (defaults to time.time); pass a fixed
    clock for deterministic manifests. ``code_pin_policy`` gates
    ``seal()`` (fail-closed pin block). ``chain_revision`` is the
    deployment's chain-revision label (wave-272): when set, every
    ``tool_call`` link records a ``revision_binding`` block binding its
    pin to the chain revision it executed at."""

    def __init__(self, actor, *, now=None, code_pin_policy=None,
                 chain_revision=None):
        if not isinstance(actor, str) or not actor:
            raise ReplayManifestError(
                "replay-malformed", "actor must be a non-empty string")
        if chain_revision is not None and \
                (not isinstance(chain_revision, str)
                 or not chain_revision):
            raise ReplayManifestError(
                "replay-malformed",
                "chain_revision must be a non-empty string or None")
        self._actor = actor
        self._now = now or time.time
        self._policy = code_pin_policy or CodePinPolicy()
        self._chain_revision = chain_revision
        self._links = []
        self._sealed = False

    # -- internals ----------------------------------------------------

    def _append(self, action, fields):
        if self._sealed:
            raise ReplayManifestError(
                "replay-malformed",
                "builder already sealed; start a new builder")
        if action not in _ACTIONS:
            raise ReplayManifestError(
                "replay-malformed",
                "unknown action %r (closed vocabulary)" % (action,))
        prev = self._links[-1]["link_hash"] if self._links \
            else GENESIS_HASH
        body = {"format": MANIFEST_FORMAT,
                "seq": len(self._links),
                "prev_hash": prev,
                "ts": int(self._now()),
                "actor": self._actor,
                "action": action}
        body.update(fields)
        body["link_hash"] = _link_hash(body)
        self._links.append(body)
        return body["link_hash"]

    # -- record API ---------------------------------------------------

    def record_environment_snapshot(self, env):
        """Advisory environment capture. ``env`` is a JSON dict; it is
        a hint, never a pin (see honest limits)."""
        if not isinstance(env, dict):
            raise ReplayManifestError(
                "replay-malformed", "env must be a dict")
        try:
            _canonical(env)
        except RecursionError as e:
            # json.dumps raises RecursionError (a RuntimeError, not a
            # ValueError) for deeply-nested structures -- a hostile env
            # must still surface the coded error (F272).
            raise ReplayManifestError(
                "replay-malformed",
                "env is too deeply nested to serialize: %s" % (e,))
        except (TypeError, ValueError) as e:
            raise ReplayManifestError(
                "replay-malformed",
                "env is not JSON-serializable: %s" % (e,))
        return self._append(ACTION_ENVIRONMENT_SNAPSHOT, {"env": env})

    def record_tool_call(self, *, tool_id, input_digest, output_digest,
                         tool_digest_pin, seed, presentation_digest=None,
                         dirty=False):
        """Record a dispatched tool call. Digests are sha256 hex; the
        pin is checked at ``seal()`` (fail-closed). ``seed`` is the
        deterministic seed recorded for this step."""
        if not isinstance(tool_id, str) or not tool_id:
            raise ReplayManifestError(
                "replay-malformed", "tool_id must be a non-empty string")
        _require_hex64(input_digest, "input_digest")
        _require_hex64(output_digest, "output_digest")
        if not isinstance(seed, int):
            raise ReplayManifestError(
                "replay-malformed", "seed must be an int")
        fields = {"tool_id": tool_id,
                  "input_digest": input_digest,
                  "output_digest": output_digest,
                  "tool_digest_pin": tool_digest_pin,
                  "seed": seed,
                  "dirty": bool(dirty)}
        if self._chain_revision is not None:
            # Wave-272 revision binding: the pin is bound to the chain
            # revision it executed at, on the link itself.
            fields["revision_binding"] = {
                "revision": self._chain_revision,
                "content_digest": tool_digest_pin,
            }
        if presentation_digest is not None:
            _require_hex64(presentation_digest, "presentation_digest")
            fields["presentation_digest"] = presentation_digest
        return self._append(ACTION_TOOL_CALL, fields)

    def record_presentation(self, *, presented_bytes, purpose):
        """Evidence-of-what-was-shown: only the digest enters the
        chain (the bytes are evidence-bundle material, joined by
        digest)."""
        if not isinstance(presented_bytes, (bytes, bytearray)):
            raise ReplayManifestError(
                "replay-malformed", "presented_bytes must be bytes")
        if not isinstance(purpose, str) or not purpose:
            raise ReplayManifestError(
                "replay-malformed", "purpose must be a non-empty string")
        return self._append(ACTION_PRESENTATION, {
            "presentation_digest": _sha256_hex(bytes(presented_bytes)),
            "purpose": purpose})

    def record_approval_requested(self, *, approval_id, presented_bytes):
        if not isinstance(approval_id, str) or not approval_id:
            raise ReplayManifestError(
                "replay-malformed", "approval_id must be a non-empty string")
        if not isinstance(presented_bytes, (bytes, bytearray)):
            raise ReplayManifestError(
                "replay-malformed", "presented_bytes must be bytes")
        return self._append(ACTION_APPROVAL_REQUESTED, {
            "approval_id": approval_id,
            "presentation_digest": _sha256_hex(bytes(presented_bytes))})

    def record_approval_received(self, *, approval_id,
                                 approval_receipt_ref, decision_digest):
        """Bind a wave-267 corroboration receipt into the chain:
        ``approval_receipt_ref`` is the receipt statement digest
        (``gov.corroboration_receipt.statement_digest``). Signature
        verification happens through a caller-supplied
        ``receipt_checker`` at ``verify_manifest`` time."""
        if not isinstance(approval_id, str) or not approval_id:
            raise ReplayManifestError(
                "replay-malformed", "approval_id must be a non-empty string")
        _require_hex64(approval_receipt_ref, "approval_receipt_ref")
        _require_hex64(decision_digest, "decision_digest")
        return self._append(ACTION_APPROVAL_RECEIVED, {
            "approval_id": approval_id,
            "approval_receipt_ref": approval_receipt_ref,
            "decision_digest": decision_digest})

    def record_gate_consult(self, *, gate, decision_code, reason,
                            dispatched_tool=None):
        """Negative evidence: a gate was consulted and the decision
        was ``decision_code``. When no tool was dispatched, the link
        carries an explicit negative-evidence block -- deliberate
        non-actions are first-class chain links, not absent data."""
        if not isinstance(gate, str) or not gate:
            raise ReplayManifestError(
                "replay-malformed", "gate must be a non-empty string")
        if not isinstance(decision_code, str) or not decision_code:
            raise ReplayManifestError(
                "replay-malformed",
                "decision_code must be a non-empty string")
        fields = {"gate": gate,
                  "decision_code": decision_code,
                  "reason": str(reason)}
        if dispatched_tool is None:
            fields["negative_evidence"] = {
                "tool_dispatched": False,
                "decision": decision_code,
            }
        else:
            fields["dispatched_tool"] = str(dispatched_tool)
        return self._append(ACTION_GATE_CONSULT, fields)

    def record_content_equivalence(self, *, tool_id, from_digest,
                                   to_digest, reason):
        """Explicit content-equivalence annotation (wave-272): the
        deployment states that ``to_digest`` is an acceptable
        replacement for ``from_digest`` for ``tool_id`` (e.g. a
        versioned tool rollout). ``revision_binding.verify_replay``
        accepts a replay whose pin differs from the revision binding
        ONLY when one of these links covers
        ``(tool_id, from_digest -> to_digest)``. The reason is
        mandatory -- an annotation without a reason is refused at
        record time (fail closed, never carried as free text)."""
        if not isinstance(tool_id, str) or not tool_id:
            raise ReplayManifestError(
                "replay-malformed",
                "tool_id must be a non-empty string")
        _require_hex64(from_digest, "from_digest")
        _require_hex64(to_digest, "to_digest")
        if not isinstance(reason, str) or not reason:
            raise ReplayManifestError(
                "replay-malformed",
                "reason must be a non-empty string (an equivalence "
                "annotation without a reason is refused)")
        return self._append(ACTION_CONTENT_EQUIVALENCE, {
            "tool_id": tool_id,
            "from_digest": from_digest,
            "to_digest": to_digest,
            "reason": reason,
        })

    # -- seal ---------------------------------------------------------

    def seal(self):
        """Fail-closed seal. Refuses: dirty pins
        (``replay-dirty-codebase-seal``), missing/malformed/registry-
        mismatched pins (``replay-unverifiable-tool-digest``), and
        approval links without a receipt reference
        (``replay-missing-approval-receipt``). Returns the sealed
        manifest: ``{"format", "links", "code_pins", "manifest_digest"}``.
        Link bodies are never mutated at seal time (they are immutable
        once appended); the code pins live in a manifest-level
        ``code_pins`` map covered by the seal digest."""
        if self._sealed:
            raise ReplayManifestError(
                "replay-malformed", "builder already sealed")
        code_pins = {}
        for link in self._links:
            action = link["action"]
            if action == ACTION_TOOL_CALL:
                code_pins[str(link["seq"])] = self._policy.verify_pin(
                    tool_id=link["tool_id"],
                    link_digest=link.get("tool_digest_pin"),
                    dirty=link.get("dirty", False))
            elif action == ACTION_APPROVAL_RECEIVED:
                if not link.get("approval_receipt_ref"):
                    raise ReplayManifestError(
                        "replay-missing-approval-receipt",
                        "approval_received link seq %d has no receipt "
                        "reference; refusing to seal" % (link["seq"],))
        sealed = {"format": MANIFEST_FORMAT,
                  "links": list(self._links),
                  "code_pins": code_pins,
                  "manifest_digest": _sha256_hex(_canonical(
                      {"format": MANIFEST_FORMAT,
                       "links": self._links,
                       "code_pins": code_pins}))}
        self._sealed = True
        self._sealed_manifest = sealed
        return sealed

    def as_evidence_artifact(self):
        """Wrap the sealed manifest as a v2 evidence-bundle artifact
        (digest-addressed, ready for the v2 submission flow).
        Composition by use; the v2 seam is never mutated. The
        ``gov.evidence_bundle_v2`` import is lazy so this module stays
        importable with stdlib only."""
        if not self._sealed:
            raise ReplayManifestError(
                "replay-malformed",
                "seal() before wrapping as an evidence artifact")
        from gov.evidence_bundle_v2 import build_artifact
        return build_artifact(self._sealed_manifest)


# ---------------------------------------------------------------------------
# Offline verifier (stdlib only -- no engine, no gov imports)
# ---------------------------------------------------------------------------

def _check_link_shape(link, seq):
    if not isinstance(link, dict):
        raise ReplayManifestError(
            "replay-malformed", "link %d is not a dict" % (seq,))
    for key in ("seq", "prev_hash", "ts", "actor", "action", "link_hash"):
        if key not in link:
            raise ReplayManifestError(
                "replay-malformed",
                "link %d missing field %r" % (seq, key))
    if link["seq"] != seq:
        raise ReplayManifestError(
            "replay-malformed",
            "link seq %r out of order (expected %d)"
            % (link["seq"], seq))
    if link["action"] not in _ACTIONS:
        raise ReplayManifestError(
            "replay-malformed",
            "link %d has unknown action %r" % (seq, link["action"]))
    _require_hex64(link["prev_hash"], "link %d prev_hash" % seq)
    _require_hex64(link["link_hash"], "link %d link_hash" % seq)


# ---------------------------------------------------------------------------
# Decode trust split (wave-274 lane 3; Cedar decode/decode_unchecked).
#
# - decode_untrusted_manifest: hostile manifest -> full shape and
#   self-consistency validation (link shapes, seq order, prev_hash
#   chain, link_hash recomputation, tool pins, dirty flags,
#   receipt references, presentations, manifest digest). Coded
#   ReplayManifestError, never trusted output.
# - seal_manifest_trust: the trust event. Runs the cryptographic
#   receipt checks and the presentation byte checks (the inputs that
#   need external verification) and seals a TrustEvidence bound to
#   the manifest_digest under the "replay-manifest" scope.
# - decode_trusted_manifest: the trusted path. Requires the
#   evidence, re-checks the digest binding itself
#   (decodetrust-no-evidence / decodetrust-binding-mismatch), then
#   extracts the link list fast. Never reachable from unverified
#   input.
# ---------------------------------------------------------------------------

MANIFEST_TRUST_SCOPE = "replay-manifest"


def _manifest_seal_bytes(manifest):
    """The exact bytes the manifest_digest covers."""
    return _canonical({"format": MANIFEST_FORMAT,
                       "links": manifest["links"],
                       "code_pins": manifest["code_pins"]})


def decode_untrusted_manifest(manifest):
    """Untrusted-decode path for a replay manifest: shape and
    self-consistency checks only. Raises coded ReplayManifestError on
    any defect. Returns the parsed structure; the receipt and
    presentation checks that need external verification are NOT run
    here -- see :func:`seal_manifest_trust`.
    """
    if not isinstance(manifest, dict) \
            or manifest.get("format") != MANIFEST_FORMAT:
        raise ReplayManifestError(
            "replay-malformed",
            "manifest must be a %s record" % MANIFEST_FORMAT)
    links = manifest.get("links")
    if not isinstance(links, list):
        raise ReplayManifestError(
            "replay-malformed", "manifest links must be a list")
    code_pins = manifest.get("code_pins")
    if not isinstance(code_pins, dict):
        raise ReplayManifestError(
            "replay-malformed", "manifest code_pins must be a dict")
    prev = GENESIS_HASH
    approval_links = []
    presentation_digests = set()
    for seq, link in enumerate(links):
        _check_link_shape(link, seq)
        if not hmac.compare_digest(link["prev_hash"], prev):
            raise ReplayManifestError(
                "replay-broken-chain",
                "link %d prev_hash does not match the previous link "
                "hash (chain broken)" % (seq,))
        body = {k: v for k, v in link.items() if k != "link_hash"}
        if not hmac.compare_digest(_link_hash(body), link["link_hash"]):
            raise ReplayManifestError(
                "replay-broken-chain",
                "link %d body does not hash to its link_hash "
                "(tampered)" % (seq,))
        prev = link["link_hash"]
        action = link["action"]
        if action == ACTION_TOOL_CALL:
            if link.get("dirty"):
                raise ReplayManifestError(
                    "replay-dirty-codebase-seal",
                    "link %d records a dirty codebase; a dirty chain "
                    "never verifies" % (seq,))
            pin = link.get("tool_digest_pin")
            if not isinstance(pin, str) or not _HEX64.match(pin):
                raise ReplayManifestError(
                    "replay-unverifiable-tool-digest",
                    "link %d has no verifiable tool digest pin" % (seq,))
            if not code_pins.get(str(seq)):
                raise ReplayManifestError(
                    "replay-unverifiable-tool-digest",
                    "link %d has no seal-time code pin (code_pins); the "
                    "manifest was not sealed fail-closed" % (seq,))
            # Wave-272: the revision_binding block the builder emits
            # is structurally validated like everything else -- a
            # malformed block is refused, never half-honored (an
            # uncoded AttributeError at the registry seam is the
            # failure this prevents).
            binding = link.get("revision_binding")
            if binding is not None:
                if not isinstance(binding, dict) \
                        or not isinstance(
                            binding.get("revision"), str) \
                        or not binding.get("revision") \
                        or not isinstance(
                            binding.get("content_digest"), str) \
                        or not _HEX64.match(
                            binding.get("content_digest")):
                    raise ReplayManifestError(
                        "replay-malformed",
                        "link %d revision_binding must be a dict with "
                        "a non-empty revision string and a 64-char "
                        "hex content_digest" % (seq,))
        elif action == ACTION_APPROVAL_RECEIVED:
            ref = link.get("approval_receipt_ref")
            if not ref:
                raise ReplayManifestError(
                    "replay-missing-approval-receipt",
                    "link %d approval_received without a receipt "
                    "reference" % (seq,))
            approval_links.append((seq, link))
        elif action == ACTION_CONTENT_EQUIVALENCE:
            # Wave-272: explicit equivalence annotations are
            # structurally validated like everything else -- a
            # malformed annotation is refused, never half-honored.
            for field in ("from_digest", "to_digest"):
                value = link.get(field)
                if not isinstance(value, str) or \
                        not _HEX64.match(value):
                    raise ReplayManifestError(
                        "replay-malformed",
                        "link %d content_equivalence %s must be 64 "
                        "lowercase hex chars" % (seq, field))
            if not isinstance(link.get("reason"), str) or \
                    not link.get("reason"):
                raise ReplayManifestError(
                    "replay-malformed",
                    "link %d content_equivalence reason must be a "
                    "non-empty string" % (seq,))
        if "presentation_digest" in link:
            presentation_digests.add(link["presentation_digest"])
    # Manifest-level digest: the seal covers links AND code pins.
    # A non-str manifest_digest must fail with the coded error, never
    # leak TypeError out of hmac.compare_digest (F272).
    digest = manifest.get("manifest_digest", "")
    if not isinstance(digest, str):
        raise ReplayManifestError(
            "replay-malformed",
            "manifest_digest must be a string, not %s"
            % type(digest).__name__)
    recomputed = _sha256_hex(_manifest_seal_bytes(manifest))
    if not hmac.compare_digest(recomputed, digest):
        raise ReplayManifestError(
            "replay-broken-chain",
            "manifest_digest does not cover the link list and code pins "
            "(seal broken)")
    return {"links": links, "code_pins": code_pins,
            "approval_links": approval_links,
            "presentation_digests": presentation_digests,
            "manifest_digest": digest}


def seal_manifest_trust(parsed, *, receipts=None, receipt_checker=None,
                        presentations=None):
    """The trust event for a replay manifest: run the checks that
    need external verification (cryptographic receipt checks,
    presentation byte checks) over a shape-validated ``parsed``
    manifest and seal a TrustEvidence bound to the manifest_digest.

    Returns ``(evidence, report)`` where report carries
    ``receipts_unverified`` / ``presentations_unverified`` exactly as
    the legacy verifier did. Caller-supplied container shape defects
    raise the coded ``replay-malformed`` (F272).
    """
    approval_links = parsed["approval_links"]
    presentation_digests = parsed["presentation_digests"]
    # Caller-supplied containers: a non-dict receipts/presentations map
    # must fail with the coded error, never leak AttributeError (F272).
    for name, mapping in (("receipts", receipts),
                          ("presentations", presentations)):
        if mapping is not None and not isinstance(mapping, dict):
            raise ReplayManifestError(
                "replay-malformed",
                "%s must be a dict mapping digests to statements/bytes, "
                "not %s" % (name, type(mapping).__name__))
    # Approval receipts: cryptographic check is delegated; absence is
    # reported, never silent.
    receipts_unverified = False
    if approval_links:
        if receipt_checker is None:
            receipts_unverified = True
        else:
            for seq, link in approval_links:
                statement = (receipts or {}).get(
                    link["approval_receipt_ref"])
                if statement is None:
                    raise ReplayManifestError(
                        "replay-approval-receipt-invalid",
                        "link %d: no receipt statement supplied for "
                        "ref %s" % (seq,
                                    link["approval_receipt_ref"][:16]))
                receipt_checker(link, statement)
    # Presentations: bytes supplied -> digest re-derived; mismatch is
    # a refusal; absent bytes -> reported, never assumed.
    presentations_unverified = sorted(
        d for d in presentation_digests
        if not (presentations or {}).get(d))
    for digest in presentation_digests:
        raw = (presentations or {}).get(digest)
        if raw is not None and not hmac.compare_digest(
                _sha256_hex(bytes(raw)), digest):
            raise ReplayManifestError(
                "replay-presentation-mismatch",
                "presented bytes do not match presentation_digest %s "
                "(what-was-shown disagrees with the record)"
                % digest[:16])
    kind = "receipt" if (approval_links and not receipts_unverified) \
        else "chain"
    evidence = _dt.seal_evidence(
        scope=MANIFEST_TRUST_SCOPE, digest=parsed["manifest_digest"],
        kind=kind, signer="receipt-checker" if kind == "receipt"
        else "self-consistency")
    return evidence, {"receipts_unverified": receipts_unverified,
                      "presentations_unverified": presentations_unverified}


def decode_trusted_manifest(manifest, evidence):
    """Trusted-decode path for a replay manifest.

    Requires ``evidence`` sealed by :func:`seal_manifest_trust`;
    the digest binding is re-checked against the manifest's own
    seal bytes before a single link is read
    (decodetrust-no-evidence / decodetrust-malformed-evidence /
    decodetrust-binding-mismatch).
    Returns the link list.
    """
    if not isinstance(manifest, dict):
        raise _dt.DecodeTrustError(
            "decodetrust-malformed-evidence",
            "trusted manifest decode requires the manifest dict, got "
            "%s" % type(manifest).__name__)
    if evidence is None:
        # No evidence presented at all: refuse before touching the
        # wire shape (decodetrust-no-evidence, not
        # decodetrust-binding-mismatch).
        raise _dt.DecodeTrustError(
            "decodetrust-no-evidence",
            "trusted manifest decode requires sealed evidence; none "
            "presented")
    try:
        seal_bytes = _manifest_seal_bytes(manifest)
    except (KeyError, TypeError):
        raise _dt.DecodeTrustError(
            "decodetrust-malformed-evidence",
            "trusted manifest decode: manifest lacks the sealed "
            "shape; refusing rather than guessing")
    _dt.require_trust(evidence, seal_bytes, scope=MANIFEST_TRUST_SCOPE)
    return manifest["links"]


def verify_manifest(manifest, *, receipts=None, receipt_checker=None,
                    presentations=None):
    """Verify a sealed replay manifest WITHOUT the engine.

    Decode trust split: the untrusted-decode path
    (:func:`decode_untrusted_manifest`) validates shapes and
    self-consistency; the trust event (:func:`seal_manifest_trust`)
    runs the cryptographic receipt and presentation checks; the
    trusted-decode path (:func:`decode_trusted_manifest`) re-checks
    the evidence binding before reading links. Checks: shape, seq
    order, prev_hash chain, link_hash recomputation (any mismatch is
    ``replay-broken-chain`` -- evidence disagrees with the claim,
    treat as tampering), tool-pin presence and shape
    (``replay-unverifiable-tool-digest``), dirty flags
    (``replay-dirty-codebase-seal``), approval-link receipt references
    (``replay-missing-approval-receipt``), and the manifest digest.

    ``receipts`` maps approval_receipt_ref -> statement dict;
    ``receipt_checker(link, statement)`` performs the cryptographic
    receipt verification (built on ``gov.corroboration_receipt``) and
    raises ``ReplayManifestError("replay-approval-receipt-invalid")``
    on failure. WITHOUT a checker, approval links are structurally
    pinned but signature-unverified -- reported honestly as
    ``receipts_unverified: True`` (never silent).

    ``presentations`` maps presentation_digest -> presented bytes; a
    digest whose bytes mismatch is ``replay-presentation-mismatch``.
    Digests with no presented bytes are reported as
    ``presentations_unverified`` (never assumed shown).

    Returns ``{"verified": True, ...}`` on success; raises coded
    ``ReplayManifestError`` on any failure. The raise-vs-return
    contract is pinned in ``tests/test_replay_manifest.py``.
    """
    parsed = decode_untrusted_manifest(manifest)
    evidence, report = seal_manifest_trust(
        parsed, receipts=receipts, receipt_checker=receipt_checker,
        presentations=presentations)
    links = decode_trusted_manifest(manifest, evidence)
    return {"verified": True,
            "manifest_digest": parsed["manifest_digest"],
            "links": len(links),
            "approval_links": len(parsed["approval_links"]),
            "receipts_unverified": report["receipts_unverified"],
            "presentations_unverified": report["presentations_unverified"]}
