"""in-toto-inspired skill admission gate (W248-2).

Pattern adaptation ONLY -- no in-toto code is vendored and no spec
text is copied (in-toto is Apache-2.0; the lineage here is ours). The
stolen mechanism is in-toto's Layout/Step/Link provenance shape plus
its artifact-rule discipline, hardened in the two ways the wave-247
prospectus mandates:

1. Command-alignment mismatch is a HARD REFUSAL
   (``skill-admission-command-mismatch``). in-toto's
   ``verify_command_alignment`` only warns; a warning is not a gate.
2. Signer/authority separation is STRUCTURAL. A layout whose
   authority key is also a step signer key is refused
   (``skill-admission-authority-is-step-signer``) -- the layout
   authority that authorized a step is always a different principal
   from the one that executed and vouched the step. in-toto's
   record-then-sign-in-one-process default is not inherited.

What this gate is: a registry-side check that the skill which was
authorized is the skill that was built. A skill bundle ships:

- a LAYOUT, signed by the layout authority: named steps, each with
  the exact authorized command, the authorized step-signer public
  key, and artifact rules over that step's materials/products;
- per-step LINK metadata, signed by the step signer: the command
  actually run, the materials consumed, the products produced.

Admission verifies: layout signature -> authority/step-signer
separation -> per-step link presence, shape, link signature, signer
authorization, exact command alignment, artifact rules (via
``gov.artifact_rules``: REQUIRE/MATCH fail closed on absent
materials; the terminal DISALLOW refuses leftovers, so a step that
produced nothing cannot pass a REQUIRE-products rule -- the F193
vacuous-proof class).

Verification order (fail-closed): shape -> layout signature ->
separation -> link presence -> link shape -> link signature ->
signer authorization -> command alignment -> artifact rules.

Honest residuals:
- Signatures prove the authorized keys vouched the records, not that
  the step's command did anything honest. A malicious-but-authorized
  signer is a key-compromise problem, not an admission problem.
- Artifact digests are caller-supplied observations of step
  materials/products; the gate checks the vouch, never the bytes.
- Layout distribution (how the registry learns the authority key) is
  deployment-owned -- the TUF-shaped skill registry (W248-3) is the
  intended transport.

Stdlib only. Deterministic. No env reads, no I/O, no wall clock.
Fail-closed on malformed input.
"""

import hashlib
import json
import re

from gov import artifact_rules
from gov import bundle_scan
from gov import ed25519

# Machine codes (all registered in gov/decision_codes.py TAXONOMY).
SKILL_ADMISSION_LAYOUT_MALFORMED = "skill-admission-layout-malformed"
SKILL_ADMISSION_LAYOUT_SIGNATURE_INVALID = (
    "skill-admission-layout-signature-invalid")
SKILL_ADMISSION_AUTHORITY_IS_STEP_SIGNER = (
    "skill-admission-authority-is-step-signer")
SKILL_ADMISSION_LINK_MISSING = "skill-admission-link-missing"
SKILL_ADMISSION_LINK_MALFORMED = "skill-admission-link-malformed"
SKILL_ADMISSION_LINK_SIGNATURE_INVALID = (
    "skill-admission-link-signature-invalid")
SKILL_ADMISSION_UNAUTHORIZED_SIGNER = "skill-admission-unauthorized-signer"
SKILL_ADMISSION_COMMAND_MISMATCH = "skill-admission-command-mismatch"
SKILL_ADMISSION_ARTIFACT_RULE_VIOLATED = (
    "skill-admission-artifact-rule-violated")

_PUB_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SIG_HEX_RE = re.compile(r"^[0-9a-f]{128}$")
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class SkillAdmissionError(ValueError):
    """Raised with a taxonomy ``code`` naming the refusal."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical_bytes(obj):
    """Deterministic JSON bytes for signing (sorted keys, no spaces)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _check_pub_hex(value, where):
    if not isinstance(value, str) or not _PUB_HEX_RE.match(value):
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "%s: expected 64-char lowercase hex ed25519 public key, "
            "got %r" % (where, value))


def _check_command(value, where, code=SKILL_ADMISSION_LAYOUT_MALFORMED):
    if (not isinstance(value, list) or not value
            or any(not isinstance(a, str) or not a for a in value)):
        raise SkillAdmissionError(
            code,
            "%s: command must be a non-empty list of non-empty "
            "strings, got %r" % (where, value))
    return list(value)


def _check_artifact_map(mapping, where,
                        code=SKILL_ADMISSION_LAYOUT_MALFORMED):
    if not isinstance(mapping, dict):
        raise SkillAdmissionError(
            code,
            "%s: expected {name: sha256-hex} mapping, got %r"
            % (where, mapping))
    for name, digest in mapping.items():
        if not isinstance(name, str) or not name:
            raise SkillAdmissionError(
                code,
                "%s: artifact name must be a non-empty string, got %r"
                % (where, name))
        if not isinstance(digest, str) or not _DIGEST_HEX_RE.match(digest):
            raise SkillAdmissionError(
                code,
                "%s: digest for %r must be 64-char lowercase hex, got %r"
                % (where, name, digest))
    return dict(mapping)


def _check_rules(rules, where):
    # Fail fast at authoring time: rule grammar errors are layout
    # authoring errors, never admission-time surprises.
    if not isinstance(rules, (list, tuple)) or not rules:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "%s: rules must be a non-empty list of artifact-rule "
            "tuples" % (where,))
    try:
        return artifact_rules.load_rules(rules)
    except artifact_rules.ArtifactRuleError as exc:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "%s: invalid artifact rules: %s" % (where, exc))


def _check_step(step, where):
    if not isinstance(step, dict):
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "%s: step must be a dict, got %r" % (where, step))
    name = step.get("name")
    if not isinstance(name, str) or not name:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "%s: step name must be a non-empty string" % (where,))
    _check_pub_hex(step.get("signer_pub"), "%s.signer_pub" % (where,))
    _check_command(step.get("command"), "%s.command" % (where,))
    _check_rules(step.get("rules"), "%s.rules" % (where,))
    return {"name": name,
            "command": _check_command(step["command"], where),
            "signer_pub": step["signer_pub"],
            "rules": [list(r) for r in step["rules"]]}


def make_layout(layout_id, steps, layout_seed):
    """Author and sign a skill layout (layout-authority principal).

    ``steps``: list of ``{"name", "command", "signer_pub", "rules"}``
    dicts. ``layout_seed``: 32-byte ed25519 seed of the layout
    authority. Returns ``{"layout": {...}, "signature": hex}``.
    Raises :class:`SkillAdmissionError` on any authoring problem.
    """
    if not isinstance(layout_id, str) or not layout_id:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "layout_id must be a non-empty string")
    if not isinstance(steps, (list, tuple)) or not steps:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "steps must be a non-empty list")
    if not isinstance(layout_seed, (bytes, bytearray)) \
            or len(layout_seed) != 32:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "layout_seed must be 32 bytes")
    checked = [_check_step(s, "steps[%d]" % (i,))
                    for i, s in enumerate(steps)]
    names = [s["name"] for s in checked]
    if len(set(names)) != len(names):
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "duplicate step names: %s" % (sorted(names),))
    layout = {"layout_id": layout_id, "steps": checked}
    signature = ed25519.sign(bytes(layout_seed),
                             _canonical_bytes(layout)).hex()
    return {"layout": layout, "signature": signature}


def make_link(layout_id, step_name, command, materials, products,
              signer_seed):
    """Create and sign step link metadata (step-signer principal).

    A SEPARATE principal from the layout authority -- see the module
    docstring. Returns ``{"link": {...}, "signature": hex}``.
    Raises :class:`SkillAdmissionError` on any authoring problem.
    """
    if not isinstance(layout_id, str) or not layout_id:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LINK_MALFORMED,
            "layout_id must be a non-empty string")
    if not isinstance(step_name, str) or not step_name:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LINK_MALFORMED,
            "step_name must be a non-empty string")
    if not isinstance(signer_seed, (bytes, bytearray)) \
            or len(signer_seed) != 32:
        raise SkillAdmissionError(
            SKILL_ADMISSION_LINK_MALFORMED,
            "signer_seed must be 32 bytes")
    link = {"layout_id": layout_id,
            "step_name": step_name,
            "command": _check_command(command, "link.command",
                                     SKILL_ADMISSION_LINK_MALFORMED),
            "materials": _check_artifact_map(
                materials, "link.materials",
                SKILL_ADMISSION_LINK_MALFORMED),
            "products": _check_artifact_map(
                products, "link.products",
                SKILL_ADMISSION_LINK_MALFORMED),
            "signer_pub": ed25519.publickey(bytes(signer_seed)).hex()}
    signature = ed25519.sign(bytes(signer_seed),
                             _canonical_bytes(link)).hex()
    return {"link": link, "signature": signature}


def _refuse(code, detail, evidence):
    return {"admitted": False, "code": code, "detail": detail,
            "evidence": evidence}


def _check_signed_envelope(envelope, kind, malformed_code):
    # Returns (inner_dict, signature_bytes) or raises
    # SkillAdmissionError(malformed_code).
    if not isinstance(envelope, dict):
        raise SkillAdmissionError(
            malformed_code, "%s envelope must be a dict" % (kind,))
    inner = envelope.get(kind)
    if not isinstance(inner, dict):
        raise SkillAdmissionError(
            malformed_code,
            "%s envelope must carry a %r dict" % (kind, kind))
    signature = envelope.get("signature")
    if not isinstance(signature, str) \
            or not _SIG_HEX_RE.match(signature):
        raise SkillAdmissionError(
            malformed_code,
            "%s envelope signature must be 128-char lowercase hex"
            % (kind,))
    return inner, bytes.fromhex(signature)


def _scan_artifact_payloads(artifact_bytes, context):
    """Content-scan caller-presented pickle payloads (wave-270).

    ``artifact_bytes``: dict mapping artifact name -> raw payload
    bytes, for artifacts the registry believes are pickle-serialized.
    Non-pickle payloads must NOT be passed -- the scanner fails
    closed on non-pickle bytes.

    Returns ``(scan_evidence, refusal)`` where ``scan_evidence`` is
    the auditable record and ``refusal`` is ``None`` or
    ``{"code", "detail"}`` for a CRITICAL/structural finding.
    Raises :class:`SkillAdmissionError` on a malformed argument.
    """
    if not isinstance(artifact_bytes, dict):
        raise SkillAdmissionError(
            SKILL_ADMISSION_LAYOUT_MALFORMED,
            "artifact_bytes must be a dict of name -> payload bytes")
    scanned = []
    advisories = []
    refusal = None
    for name in sorted(artifact_bytes.keys()):
        payload = artifact_bytes[name]
        if not isinstance(name, str):
            raise SkillAdmissionError(
                SKILL_ADMISSION_LAYOUT_MALFORMED,
                "artifact_bytes keys must be strings")
        verdict = bundle_scan.scan_pickle_stream(
            payload, context="%s:%s" % (context, name))
        scanned.append(name)
        record = {"artifact": name,
                  "verdict": verdict["verdict"],
                  "code": verdict["code"],
                  "severity": verdict["severity"],
                  "findings": verdict["findings"],
                  "evidence_digest": verdict["evidence_digest"],
                  "payload_bytes": verdict["payload_bytes"]}
        if verdict["verdict"] == "refuse":
            advisories.append(record)
            if refusal is None:
                refusal = {
                    "code": verdict["code"],
                    "detail": "artifact %r refused by content scan: %s"
                              % (name, verdict["code"])}
        elif verdict["verdict"] == "advisory":
            advisories.append(record)
    scan_evidence = {
        "scanned": scanned,
        "verdict": ("refuse" if refusal is not None
                    else "advisory" if advisories else "clean"),
        "advisories": advisories,
    }
    return scan_evidence, refusal


def admit(signed_layout, links, authority_pub, artifact_bytes=None):
    """Admit a skill bundle against its signed layout (registry side).

    ``signed_layout``: output of :func:`make_layout`.
    ``links``: list of :func:`make_link` outputs, one per layout step.
    ``authority_pub``: 64-char hex ed25519 public key of the
    registry-known layout authority.
    ``artifact_bytes``: optional dict mapping artifact name -> raw
    payload bytes, for artifacts the registry believes are
    pickle-serialized. Each payload is content-scanned
    (``gov.bundle_scan``, scan-without-load, never unpickled): a
    ``refuse`` verdict refuses ingestion with the scanner's machine
    code and the artifact identity attached; an ``advisory`` verdict
    is recorded in ``evidence["content_scan"]`` -- loud evidence,
    never a silent pass, never a denial. ``None`` (default) preserves
    the legacy behavior byte-identically.

    Returns a verdict dict ``{"admitted", "code", "detail",
    "evidence"}``. ``code`` is None on admission, otherwise a
    registered taxonomy code. Never raises on adversarial input --
    malformed input is a refused verdict, not an exception
    (authoring-time helpers raise instead).
    """
    evidence = {"layout_id": None, "authority_pub": authority_pub,
                "steps": []}
    try:
        _check_pub_hex(authority_pub, "authority_pub")
        if not isinstance(links, (list, tuple)):
            raise SkillAdmissionError(
                SKILL_ADMISSION_LAYOUT_MALFORMED,
                "links must be a list")
        layout, layout_sig = _check_signed_envelope(
            signed_layout, "layout", SKILL_ADMISSION_LAYOUT_MALFORMED)
        layout_id = layout.get("layout_id")
        if not isinstance(layout_id, str) or not layout_id:
            raise SkillAdmissionError(
                SKILL_ADMISSION_LAYOUT_MALFORMED,
                "layout.layout_id must be a non-empty string")
        raw_steps = layout.get("steps")
        if not isinstance(raw_steps, (list, tuple)) or not raw_steps:
            raise SkillAdmissionError(
                SKILL_ADMISSION_LAYOUT_MALFORMED,
                "layout.steps must be a non-empty list")
        steps = [_check_step(s, "layout.steps[%d]" % (i,))
                 for i, s in enumerate(raw_steps)]
        names = [s["name"] for s in steps]
        if len(set(names)) != len(names):
            raise SkillAdmissionError(
                SKILL_ADMISSION_LAYOUT_MALFORMED,
                "duplicate step names: %s" % (sorted(names),))
        evidence["layout_id"] = layout_id

        # 1. Layout signature (bool contract: verify returns True/False,
        #    never raises -- check `is True`).
        if ed25519.verify(bytes.fromhex(authority_pub),
                          _canonical_bytes(
                              {"layout_id": layout_id, "steps": steps}),
                          layout_sig) is not True:
            return _refuse(SKILL_ADMISSION_LAYOUT_SIGNATURE_INVALID,
                           "layout signature does not verify under the "
                           "registry-known authority key",
                           evidence)

        # 2. Structural signer/authority separation.
        for step in steps:
            if step["signer_pub"] == authority_pub:
                return _refuse(
                    SKILL_ADMISSION_AUTHORITY_IS_STEP_SIGNER,
                    "step %r: layout authority key is also the step "
                    "signer key; authorization and execution must be "
                    "separate principals" % (step["name"],),
                    evidence)

        # 3. Index links by step name.
        link_index = {}
        for entry in links:
            inner, _sig = _check_signed_envelope(
                entry, "link", SKILL_ADMISSION_LINK_MALFORMED)
            step_name = inner.get("step_name")
            if not isinstance(step_name, str) or not step_name:
                raise SkillAdmissionError(
                    SKILL_ADMISSION_LINK_MALFORMED,
                    "link.step_name must be a non-empty string")
            if step_name not in names:
                raise SkillAdmissionError(
                    SKILL_ADMISSION_LINK_MALFORMED,
                    "link for unknown step %r (not in layout)"
                    % (step_name,))
            if step_name in link_index:
                raise SkillAdmissionError(
                    SKILL_ADMISSION_LINK_MALFORMED,
                    "duplicate link for step %r" % (step_name,))
            link_index[step_name] = (inner, _sig)

        # 4. Per-step verification, in layout order.
        for step in steps:
            name = step["name"]
            if name not in link_index:
                return _refuse(
                    SKILL_ADMISSION_LINK_MISSING,
                    "step %r: no link metadata presented" % (name,),
                    evidence)
            link, link_sig = link_index[name]
            if link.get("layout_id") != layout_id:
                return _refuse(
                    SKILL_ADMISSION_LINK_MALFORMED,
                    "step %r: link layout_id %r does not match layout "
                    "%r" % (name, link.get("layout_id"), layout_id),
                    evidence)
            _check_pub_hex(link.get("signer_pub"),
                           "link.signer_pub")
            link_command = link.get("command")
            if (not isinstance(link_command, list) or not link_command
                    or any(not isinstance(a, str) for a in
                           link_command)):
                return _refuse(
                    SKILL_ADMISSION_LINK_MALFORMED,
                    "step %r: link command malformed" % (name,),
                    evidence)
            try:
                materials = _check_artifact_map(
                    link.get("materials"), "link.materials")
                products = _check_artifact_map(
                    link.get("products"), "link.products")
            except SkillAdmissionError as exc:
                return _refuse(SKILL_ADMISSION_LINK_MALFORMED,
                               "step %r: %s" % (name, exc.detail),
                               evidence)

            # 4a. Link signature under the link's claimed signer key.
            if ed25519.verify(
                    bytes.fromhex(link["signer_pub"]),
                    _canonical_bytes(
                        {"layout_id": layout_id,
                         "step_name": name,
                         "command": link_command,
                         "materials": materials,
                         "products": products,
                         "signer_pub": link["signer_pub"]}),
                    link_sig) is not True:
                return _refuse(
                    SKILL_ADMISSION_LINK_SIGNATURE_INVALID,
                    "step %r: link signature does not verify under "
                    "the link's claimed signer key" % (name,),
                    evidence)

            # 4b. Signer authorization: the link's signer must be
            # exactly the layout-authorized signer for this step.
            if link["signer_pub"] != step["signer_pub"]:
                return _refuse(
                    SKILL_ADMISSION_UNAUTHORIZED_SIGNER,
                    "step %r: link signer is not the layout-authorized "
                    "signer" % (name,),
                    evidence)

            # 4c. Command alignment: EXACT match. A mismatch is a hard
            # refusal, never a warning.
            if link_command != step["command"]:
                return _refuse(
                    SKILL_ADMISSION_COMMAND_MISMATCH,
                    "step %r: link command %r != authorized command "
                    "%r" % (name, link_command, step["command"]),
                    evidence)

            # 4d. Artifact rules over the link's materials/products.
            try:
                audit = artifact_rules.verify_artifacts(
                    materials, products, step["rules"],
                    context="skill-admission:%s" % (name,))
            except artifact_rules.ArtifactRuleError as exc:
                return _refuse(
                    SKILL_ADMISSION_ARTIFACT_RULE_VIOLATED,
                    "step %r: %s" % (name, exc),
                    evidence)

            evidence["steps"].append(
                {"name": name, "signer_pub": step["signer_pub"],
                 "command": step["command"], "rules_audit": audit})

        evidence["layout_digest"] = hashlib.sha256(
            _canonical_bytes(
                {"layout_id": layout_id, "steps": steps})).hexdigest()

        # 5. Content scan (wave-270, additive): scan-without-load over
        #    caller-presented pickle payloads. A refuse verdict refuses
        #    ingestion with the scanner's machine code and the artifact
        #    identity; advisories are loud evidence, never denials.
        #    artifact_bytes=None preserves legacy behavior
        #    byte-identically (no content_scan key).
        if artifact_bytes is not None:
            scan_evidence, refusal = _scan_artifact_payloads(
                artifact_bytes, "skill-admission:%s" % (layout_id,))
            evidence["content_scan"] = scan_evidence
            if refusal is not None:
                return _refuse(refusal["code"], refusal["detail"],
                               evidence)

        return {"admitted": True, "code": None,
                "detail": "all %d step(s) verified: layout signature, "
                          "authority/signer separation, link signatures, "
                          "signer authorization, command alignment, "
                          "artifact rules" % (len(steps),),
                "evidence": evidence}
    except SkillAdmissionError as exc:
        return _refuse(exc.code, exc.detail, evidence)
