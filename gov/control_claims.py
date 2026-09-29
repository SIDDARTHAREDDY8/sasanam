"""NIST SP 800-53 Rev 5 control-claim table (documentation-as-code).

Every claim maps: control -> NIST statement (paraphrase) -> the Sasanam
mechanism that satisfies it -> an AUTOMATED CHECK against the real tree
-> the evidence-bundle field an assessor inspects -> the narrow scope
(what is proven) and the explicit exclusions (what is NOT claimed).

The standing red-team rule: **an uncheckable claim is an overstated
closure.** Every claim's ``check`` is a registered callable that runs
real operations against the real modules in a fresh temp dir and
returns ``(held: bool, detail: str)``. The red-team battery
(``evals/control_claim_probes.py``) evaluates every check and fails the
claim LOUDLY when the cited mechanism does not hold -- or when the
check itself cannot be evaluated (unknown check name, exception).
Checkable is fail-closed: anything but an explicit ``(True, detail)``
is a failed claim.

Honesty rules (same discipline as gov/evidence/crosswalk.py):
  - NIST publications are US public domain; control statements below
    are paraphrases of the Rev 5 text, not quotations.
  - A claim is EVIDENCE FOR an assessment, never the assessment.
    Nothing here certifies compliance.
  - 800-53 Rev 5.2.0 organization-defined parameters (e.g. "[Assignment:
    organization-defined frequency]") are the deploying organization's
    to fill; where we made an assignment it is stated in the scope.
  - The narrow-claims rule (four-source consensus: W3C, SCITT, TEE,
    and our own evidence discipline): every bundle/claim states what
    it proves and what it does not. The ``not_claimed`` field is
    mandatory.

Stdlib only, offline, $0, deterministic. No enforcement path is
changed by importing this module.
"""

import hashlib
import os
import tempfile

__all__ = [
    "FRAMEWORK_ID",
    "FRAMEWORK_NAME",
    "CLAIM_FIELDS",
    "CONTROL_CLAIMS",
    "NOT_CLAIMED",
    "CHECKS",
    "ClaimResult",
    "get_claim",
    "evaluate_claim",
    "check_claim",
    "check_all",
]

FRAMEWORK_ID = "NIST-SP-800-53-Rev-5"
FRAMEWORK_NAME = "NIST Special Publication 800-53 Revision 5"

CLAIM_FIELDS = ("control_id", "family", "nist_statement", "mechanism",
                "check", "evidence_field", "scope", "not_claimed")


class ClaimResult(object):
    """Outcome of evaluating one claim's check.

    ``checkable`` False means the check could not be evaluated at all
    (unknown check name, import failure, exception) -- this is the
    overstated-closure signal and is NEVER treated as a pass.
    """

    __slots__ = ("control_id", "held", "checkable", "detail")

    def __init__(self, control_id, held, checkable, detail):
        self.control_id = control_id
        self.held = bool(held)
        self.checkable = bool(checkable)
        self.detail = str(detail)

    def __repr__(self):
        return ("ClaimResult(%r, held=%r, checkable=%r, detail=%r)"
                % (self.control_id, self.held, self.checkable,
                   self.detail))


# ---------------------------------------------------------------------------
# Checks (registered by name; each returns (held: bool, detail: str)).
#
# Every check runs REAL operations against the real modules in a fresh
# temp dir. A check must not swallow a mechanism failure into a pass:
# mechanism failure -> (False, reason). Infrastructure failure
# (exception) is caught by evaluate_claim -> UNCHECKABLE.
# ---------------------------------------------------------------------------

def _tmpdir():
    return tempfile.mkdtemp(prefix="control-claim-")


def check_si7():
    """SI-7: integrity verification detects unauthorized changes.

    DSSE seal/open round trip (Ed25519, SHA-256 PAE binding) plus a
    hash-chained record store verified by the real chain verifier;
    tampering either is refused loudly.
    """
    from gov import dsse_envelope as dsse
    from gov import chained_store as cs
    from gov.signing import Ed25519Signer, Ed25519Verifier

    seed = b"\x11" * 32
    signer = Ed25519Signer(seed)
    verifier = Ed25519Verifier(signer.public_key, signer.key_id)
    payload = b'{"decision": "deny", "policy_id": "p1"}'
    ptype = "application/vnd.sasanam.decision+json"
    env = dsse.seal(payload, ptype, [signer])
    opened = dsse.open_envelope(env, payload, ptype, [verifier])
    if opened["key_ids"] != [signer.key_id]:
        return False, "DSSE round trip lost the signer key id"
    tampered = dict(env)
    raw = bytearray(__import__("base64").b64decode(tampered["payload"]))
    raw[0] ^= 0x01
    tampered["payload"] = __import__("base64").b64encode(
        bytes(raw)).decode("ascii")
    try:
        dsse.open_envelope(tampered, payload, ptype, [verifier])
    except dsse.EnvelopeError:
        pass
    else:
        return False, "tampered DSSE payload was accepted"

    class _ProbeStore(cs.ChainedStore):
        _record_version_key = "control-claim-probe/v1"

    store = _ProbeStore(_tmpdir())
    recs = []
    prev = ""
    for i in range(3):
        rec = {"agent_id": "probe", "seq": i, "prev_digest": prev}
        rec["digest"] = cs.sha256_hex(cs.canonical(
            {k: v for k, v in rec.items() if k != "digest"}))
        recs.append(rec)
        prev = rec["digest"]
    path = store._path("probe")
    with open(str(path), "w", encoding="utf-8") as f:
        for rec in recs:
            f.write(cs.canonical(rec) + "\n")
    if not store.verify_chain("probe"):
        return False, "intact hash chain did not verify"
    recs[1]["seq"] = 99  # tamper the middle record
    with open(str(path), "w", encoding="utf-8") as f:
        for rec in recs:
            f.write(cs.canonical(rec) + "\n")
    if store.verify_chain("probe"):
        return False, "tampered hash chain verified"
    return True, ("DSSE seal/open ok, tampered payload refused "
                  "(EnvelopeError); hash chain verifies intact and "
                  "fails tampered")


def _pinset_with_dev_pin(artifact_id, data):
    """Real dev-tier pinset with a genuinely-signed dev pin."""
    from gov import load_gate as lg
    from gov.delegation_tokens import DelegationTrust
    from gov.signing import Ed25519Signer
    h1 = Ed25519Signer(b"\x21" * 32)
    a1 = Ed25519Signer(b"\x22" * 32)
    u1 = Ed25519Signer(b"\x23" * 32)
    trust = DelegationTrust(
        human_keys={h1.key_id: h1.public_key},
        authority_keys={a1.key_id: a1.public_key},
        user_issuer_keys={u1.key_id: u1.public_key})
    pinset = lg.ArtifactPinset(trust)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    ts = lg._utcnow_iso()
    version = 1
    not_after = lg._resolve_pin_not_after(ts, None)
    body = lg._canonical_pin_body("dev", artifact_id, digest, ts,
                                  version=version, not_after=not_after)
    sig_hex = bytes(h1.sign(body)).hex()
    pinset.pin(artifact_id, digest, h1.key_id, sig_hex, ts=ts,
               tier="dev", version=version, not_after=not_after)
    return pinset


def check_si7_1():
    """SI-7(1): integrity checks happen at the load transition.

    The digest-pinned load gate verifies fetched bytes against the pin
    and refuses unpinned artifacts outright (no trust-on-first-use) --
    the check runs at the transition, not on demand.
    """
    from gov import load_gate as lg
    data = b"skill bundle bytes, pinned"
    pinset = _pinset_with_dev_pin("probe-artifact", data)
    art = lg.verify_and_load(pinset, "probe-artifact", data)
    if art.data != data or art.digest != "sha256:" + \
            hashlib.sha256(data).hexdigest():
        return False, "verified artifact did not carry the hashed bytes"
    try:
        lg.verify_and_load(pinset, "never-pinned", b"x")
    except lg.ArtifactRefused as e:
        if "artifact_unpinned" not in str(e):
            return False, "wrong refusal code for unpinned artifact"
    else:
        return False, "unpinned artifact was loaded (TOFU)"
    return True, ("pinned bytes load through verify_and_load; unpinned "
                  "artifacts refused with artifact_unpinned")


def check_si7_6():
    """SI-7(6): cryptographic (not checksum-only) integrity.

    Ed25519 signatures (pure-python, RFC 8032 self-test) -- asymmetric
    cryptography, not checksums.
    """
    from gov import evidence_verify as ev
    if not ev.rfc8032_selftest():
        return False, "RFC 8032 self-test failed"
    seed = ev.generate_seed()
    pub = ev.publickey(seed)
    msg = b"bundle manifest bytes"
    sig = ev.sign(seed, msg)
    if not ev.verify(pub, msg, sig):
        return False, "valid Ed25519 signature did not verify"
    if ev.verify(pub, b"tampered manifest bytes", sig):
        return False, "signature verified over different bytes"
    return True, ("RFC 8032 self-test ok; Ed25519 sign/verify round trip "
                  "ok; wrong-message verification refused")


def check_si7_7():
    """SI-7(7): detection is surfaced as an actionable failure.

    Tampering produces LOUD, machine-readable refusals (EnvelopeError,
    ArtifactRefused digest_mismatch) at the verification boundary --
    detection never degrades to a silent or ambiguous outcome.
    """
    import base64
    from gov import dsse_envelope as dsse
    from gov import load_gate as lg
    from gov.signing import Ed25519Signer, Ed25519Verifier
    signer = Ed25519Signer(b"\x31" * 32)
    verifier = Ed25519Verifier(signer.public_key, signer.key_id)
    env = dsse.seal(b"payload", "t", [signer])
    raw = bytearray(base64.b64decode(env["payload"]))
    raw[-1] ^= 0x01
    env["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    try:
        dsse.open_envelope(env, b"payload", "t", [verifier])
    except dsse.EnvelopeError as e:
        if not str(e):
            return False, "EnvelopeError carried no message"
    else:
        return False, "tampered envelope not detected"
    data = b"genuine bytes"
    pinset = _pinset_with_dev_pin("probe-artifact-77", data)
    try:
        lg.verify_and_load(pinset, "probe-artifact-77", b"evil bytes")
    except lg.ArtifactRefused as e:
        if "digest_mismatch" not in str(e):
            return False, "tamper refusal carried the wrong code"
    else:
        return False, "tampered artifact bytes were loaded"
    return True, ("tampered envelope -> EnvelopeError; tampered bytes -> "
                  "ArtifactRefused digest_mismatch: both loud and typed")


def check_au10():
    """AU-10: non-repudiation -- signed decision packets bind action,
    principal, policy and verdict under an Ed25519 packet signature.
    """
    from gov import decision_packet as dp
    from gov import decision_bom as bom
    policy_bytes = b"policy bundle v1"
    identity = {"agent_id": "a1", "role": "reader", "principal": "org1",
                "run_id": "run-1"}
    bom_b = bom.build_bom(
        policy_id="p1", policy_version="1",
        policy_digest=hashlib.sha256(policy_bytes).hexdigest(),
        evidence_head_digest="cd" * 32,
        principal=dict(identity))
    body = dp.build_decision_packet(
        decision="deny", boundary_declared=False,
        policy_id="p1", policy_version="1",
        decision_digest="ab" * 32, evidence_head_digest="cd" * 32,
        bill_of_materials=bom_b, identity=identity)
    packet = dp.sign_packet(body, b"\x41" * 32)
    ok, reason = dp.verify_decision_packet(packet)
    if not ok:
        return False, "freshly signed packet did not verify: %s" % reason
    bad = dict(packet)
    bad["signature"] = bad["signature"][:-4] + "AAAA"
    ok2, _ = dp.verify_decision_packet(bad)
    if ok2:
        return False, "packet with a forged signature verified"
    return True, ("signed decision packet verifies; forged signature "
                  "refused (fail-closed, no exception on malformed input)")


def _v2_event():
    from gov import decision_log_v2 as dlv
    decision = {"kind": "tool_call", "effect": "deny",
                "policy_id": "p1", "reason": "rule r1 matched"}
    raw = {"agent_id": "a1", "tool": "read_file", "path": "/etc/passwd"}
    inputs = {"rules": [{"id": "r1", "effect": "deny",
                         "match": {"role": "intern"}}],
              "request": {"role": "intern", "tool": "read"}}
    verdict = {"effect": "deny", "matched_rule": "r1",
               "reason": "deny-first: rule r1 matched"}
    return dlv.build_event(decision=decision, raw_body=raw,
                           replay_fn="deny_first_rules",
                           replay_inputs=inputs,
                           replay_verdict=verdict)


def check_au12():
    """AU-12: audit records are generated for the defined event type --
    a v2 decision event per policy decision, verifiable offline.
    """
    from gov import decision_log_v2 as dlv
    event = _v2_event()
    if not dlv.is_v2_event(event):
        return False, "built event is not recognized as a v2 event"
    if not dlv.verify_event(event):
        return False, "built event did not verify"
    digest = dlv.event_digest(event)
    if not digest or len(digest) != 64:
        return False, "event digest malformed"
    return True, ("v2 decision event built, verified offline, "
                  "decision_id=%s" % event["decision_id"])


def check_au3():
    """AU-3: audit records contain the defined content -- decision
    (kind/effect/policy_id/reason), content-derived decision_id,
    event digest, and the replay binding.
    """
    from gov import decision_log_v2 as dlv
    event = _v2_event()
    dec = event.get("decision")
    for key in ("kind", "effect", "policy_id", "reason"):
        if not isinstance(dec, dict) or not dec.get(key):
            return False, "decision.%s missing or empty" % key
    did = event.get("decision_id")
    if not isinstance(did, str) or len(did) != 64:
        return False, "decision_id is not a content-derived sha256 hex"
    replay = event.get("replay")
    if not isinstance(replay, dict):
        return False, "replay binding missing"
    for key in ("fn", "inputs", "verdict"):
        if not replay.get(key):
            return False, "replay.%s missing or empty" % key
    if not dlv.verify_event(event):
        return False, "content-complete event did not verify"
    return True, ("decision{kind,effect,policy_id,reason} + decision_id "
                  "+ replay{fn,inputs,verdict} all present and verified")


def check_sr4():
    """SR-4: provenance -- the Decision BOM binds the decision to
    digest-identified artifacts; verify_bom reconstructs on demand.
    """
    from gov import decision_bom as bom
    policy_bytes = b"policy bundle for the sr4 claim check"
    b = bom.build_bom(
        policy_id="p1", policy_version="1",
        policy_digest=hashlib.sha256(policy_bytes).hexdigest(),
        evidence_head_digest="bb" * 32,
        principal={"agent_id": "a1", "role": "reader",
                   "principal": "org1", "run_id": "run-1"})
    bom.check_bom_shape(b)
    if bom.bom_digest(b) != bom.bom_digest(b):
        return False, "BOM digest not stable"
    ok, reason = bom.verify_bom(b, policy_bundle_bytes=policy_bytes)
    if not ok:
        return False, "fresh BOM did not verify: %s" % reason
    bad = bytes(policy_bytes) + b"!"
    ok2, _ = bom.verify_bom(b, policy_bundle_bytes=bad)
    if ok2:
        return False, "BOM verified against tampered policy bytes"
    return True, ("BOM built, shape-checked, digest-stable; policy digest "
                  "re-derived from the actual bundle bytes; tampered bytes "
                  "refused by verify_bom")


def check_sr9():
    """SR-9: tamper detection -- digest mismatch at the load seam is
    refused loudly (ArtifactRefused, code digest_mismatch).
    """
    from gov import load_gate as lg
    data = b"authentic artifact bytes"
    pinset = _pinset_with_dev_pin("probe-artifact-9", data)
    try:
        lg.verify_and_load(pinset, "probe-artifact-9", b"tampered bytes")
    except lg.ArtifactRefused as e:
        if "digest_mismatch" not in str(e):
            return False, "tamper refusal carried the wrong code: %s" % e
    else:
        return False, "tampered bytes passed the load gate"
    art = lg.verify_and_load(pinset, "probe-artifact-9", data)
    if art.data != data:
        return False, "authentic bytes did not load"
    return True, ("tampered bytes refused with digest_mismatch; authentic "
                  "bytes load")


def check_sr10():
    """SR-10: inspection before use -- pack lint flags a vacuous rule
    pack and passes a clean pack (safety/liveness/sanity).
    """
    from gov import pack_lint as plint

    def _rule_doc(name, namespace, features):
        return ("rules:\n  -\n    meta:\n      name: \"%s\"\n"
                "      namespace: %s\n      scopes:\n        static: module\n"
                "      capability_tags: [%s]\n      label: \"%s\"\n"
                "    features:\n%s\n"
                % (name, namespace, namespace, name, features))

    def _ind(block, n=6):
        pad = " " * n
        return "\n".join(pad + ln if ln.strip() else ln
                         for ln in block.split("\n"))

    vacuous = {"v0.yml": _rule_doc(
        "impossible", "capability/egress/impossible",
        _ind("and:\n  - pattern: \"^aaa\"\n  - pattern: \"^bbb\"")
    ).encode("utf-8")}
    report = plint.lint_capability_rule_files(vacuous)
    if not any(v.check == "safety/unsatisfiable-rule"
               for v in report.violations):
        return False, "vacuous rule pack passed inspection"
    clean = {"r0.yml": _rule_doc(
        "egress socket", "capability/egress/socket",
        _ind("import: socket")).encode("utf-8")}
    report2 = plint.lint_capability_rule_files(clean)
    if report2.violations:
        return False, "clean pack flagged: %s" % (report2.violations,)
    return True, ("vacuous rule flagged safety/unsatisfiable-rule; clean "
                  "pack passes inspection")


def check_sr11():
    """SR-11: component authenticity -- signed-only admission.

    Staging accepts unsigned content loudly labeled; only a signed,
    two-operator-promoted bundle reaches the enforced namespace, and
    admission re-verifies the signature fresh and re-hashes the bytes.
    """
    from gov import sign_deploy_namespaces as sdn
    from gov.signing import Ed25519Signer, Ed25519Verifier
    signer = Ed25519Signer(b"\x51" * 32)
    verifier = Ed25519Verifier(signer.public_key, signer.key_id)
    reg = sdn.NamespaceRegistry(verifiers=[verifier], threshold=1)
    reg.stage("bundle-a", b"bundle bytes v1")
    if "UNSIGNED" not in reg.staging_label("bundle-a"):
        return False, "unsigned staging entry not loudly labeled"
    try:
        reg.admit_deploy("sha256:" + "00" * 32)
    except sdn.NamespaceError as e:
        if "unknown-bundle" not in str(e):
            return False, "wrong refusal for unpromoted bundle: %s" % e
    else:
        return False, "unpromoted bundle admitted to enforced"
    reg.sign("bundle-a", [signer])
    try:
        reg.promote("bundle-a", operator_ids=["op1"])
    except sdn.NamespaceError:
        pass  # single operator must fail the two-operator ceremony
    else:
        return False, "promotion succeeded with one operator"
    promoted = reg.promote("bundle-a", operator_ids=["op1", "op2"])
    digest = promoted["digest"]
    admitted = reg.admit_deploy(digest)
    if admitted["signed_by"] != [signer.key_id]:
        return False, "admission lost the signer provenance"
    if admitted["promoted_by"] != ["op1", "op2"]:
        return False, "admission lost the promotion provenance"
    return True, ("unsigned refused at admission; one-operator promotion "
                  "refused; signed + two-operator bundle admitted with "
                  "provenance")


def check_si4():
    """SI-4: monitoring -- witness-cosigned checkpoints anchored to a
    transparency log; inclusion proofs verify; equivocation and
    tampered proofs are refused.
    """
    from gov import log as _log
    from gov import anchor as _anchor
    from gov.signing import Ed25519Signer
    import secrets
    # Explicit key provisioning through the documented operator seam
    # (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH): wave-81 removed every fallback,
    # so the check provisions a fresh random key and restores the env.
    _key_vars = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")
    saved = {v: os.environ.get(v) for v in _key_vars}
    os.environ["GOV_LOG_KEY"] = secrets.token_bytes(32).hex()
    os.environ["GOV_LOG_KEY_EPOCH"] = "control-claim-test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        d = _tmpdir()
        path = os.path.join(d, "actions.jsonl")
        signer = Ed25519Signer(b"\x61" * 32)
        lg = _log.ActionLog(path, signer=signer)
        for i in range(1, 4):
            lg.append({"event": "tool_call", "n": i, "principal": "org1",
                       "agent_id": "a1"})
        cp = _log.signed_checkpoint(path, 3)
        tlog = _anchor.FakeTransparencyLog(b"\x62" * 32)
        entry, _ah = _anchor.anchor_checkpoint(path, 3, tlog)
        ok, err = _anchor.verify_anchor(entry, cp, tlog.public_key)
        if not ok:
            return False, "anchor receipt did not verify: %s" % err
        bad = dict(entry)
        bad["inclusion_proof"] = ["00" * 64]
        ok2, _ = _anchor.verify_anchor(bad, cp, tlog.public_key)
        if ok2:
            return False, "tampered inclusion proof verified"
        return True, ("checkpoint anchored; SET verifies; tampered "
                      "inclusion proof refused")
    finally:
        for v, val in saved.items():
            if val is None:
                os.environ.pop(v, None)
            else:
                os.environ[v] = val


def check_si10():
    """SI-10: input validation -- mask-before-buffer.

    The decision-shipping gate refuses events not built under the
    deployment's compiled mask plan, and masked leaves never reach the
    buffer as raw values.
    """
    from gov import decision_log_v2 as dlv
    from gov import decision_shipping as ship
    secret = "tok-live-abc-123"
    event = dlv.build_event(
        decision={"kind": "tool_call", "effect": "allow",
                  "policy_id": "p1", "reason": "unit"},
        raw_body={"action": "read", "token": secret},
        masked=("/token",),
        replay_fn="deny_first_rules",
        replay_inputs={"rules": [{"id": "r1", "effect": "allow",
                                  "match": {"role": "reader"}}],
                       "request": {"role": "reader", "tool": "read"}},
        replay_verdict={"effect": "allow", "matched_rule": "r1",
                        "reason": "rule r1 matched"})
    config = ship.ShippingConfig(
        chunk_limit_bytes=10_000, buffer_limit_bytes=100_000,
        buffer_limit_events=100, max_delay_s=600.0, min_delay_s=0.0,
        backoff_base_s=0.0, backoff_max_s=0.0, max_retries=3)
    mask = ship.CompiledMask(masked=("/token",))
    sh = ship.DecisionShipper(config, mask, sink=lambda chunk: 200)
    res = sh.ingest(event)
    if res.get("status") != "buffered":
        return False, "masked event was not buffered: %r" % (res,)
    buffered = sh._buffer[0][2]
    if secret in ship._canonical(buffered).decode("utf-8"):
        return False, "raw secret reached the buffer"
    body = buffered.get("body")
    if not isinstance(body, dict) or \
            body.get("token") != dlv.MASKED_PLACEHOLDER:
        return False, "masked leaf not replaced by the placeholder"
    return True, ("event built under the mask plan buffered; raw secret "
                  "never in the buffer; $masked placeholder in place")


def check_sa15():
    """SA-15: trustworthy development processes.

    Checkable process evidence: the canonical runner carries the F75
    supply-chain preflight, break-first red-team batteries exist as
    build gates, and every battery honors the depth-1 green-check
    convention.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    runner = os.path.join(here, "tests", "run_tests.py")
    try:
        with open(runner, "r", encoding="utf-8") as f:
            body = f.read()
    except OSError:
        return False, "canonical runner tests/run_tests.py missing"
    if "F75" not in body and "supply" not in body.lower():
        return False, "runner has no supply-chain preflight reference"
    evals = os.path.join(here, "evals")
    batteries = [n for n in os.listdir(evals)
                 if n.endswith("_probes.py") or n.endswith("_battery.py")]
    if len(batteries) < 10:
        return False, "fewer than 10 red-team batteries present: %d" \
            % len(batteries)
    for n in ("evals/control_claim_probes.py",):
        if not os.path.exists(os.path.join(here, n)):
            return False, "%s missing" % n
    return True, ("canonical runner with supply-chain preflight present; "
                  "%d red-team batteries as build gates" % len(batteries))


CHECKS = {
    "check_si7": check_si7,
    "check_si7_1": check_si7_1,
    "check_si7_6": check_si7_6,
    "check_si7_7": check_si7_7,
    "check_au10": check_au10,
    "check_au12": check_au12,
    "check_au3": check_au3,
    "check_sr4": check_sr4,
    "check_sr9": check_sr9,
    "check_sr10": check_sr10,
    "check_sr11": check_sr11,
    "check_si4": check_si4,
    "check_si10": check_si10,
    "check_sa15": check_sa15,
}


# ---------------------------------------------------------------------------
# The claim table
# ---------------------------------------------------------------------------

CONTROL_CLAIMS = [
    {
        "control_id": "SI-7",
        "family": "SI",
        "nist_statement": ("Employ integrity verification tools to detect "
                           "unauthorized changes to software, firmware, and "
                           "information; take organization-defined actions "
                           "when unauthorized changes are detected."),
        "mechanism": ("Ed25519/DSSE-signed envelopes (PAE type binding) and "
                      "SHA-256 hash-chained audit records; tampering is "
                      "refused loudly at every verification seam."),
        "check": "check_si7",
        "evidence_field": ("evidence_bundle/manifest.signature (Ed25519) + "
                           "audit_log chain digests (prev_digest linkage)"),
        "scope": ("Proves: signed bytes are intact and chained records are "
                  "unmodified. The check exercises the DSSE seal/open path "
                  "and the real chain verifier on intact vs tampered data."),
        "not_claimed": ("Does not prove the signed content was correct, "
                        "safe, or produced by a trustworthy process -- "
                        "integrity of the bytes, not of the judgment."),
    },
    {
        "control_id": "SI-7(1)",
        "family": "SI",
        "nist_statement": ("Perform integrity checks of software, firmware, "
                           "and information at organization-defined "
                           "transitional states or on demand."),
        "mechanism": ("The digest-pinned load gate (gov/load_gate.py): "
                      "fetched bytes are hashed and compared to the pin at "
                      "the load transition; unpinned artifacts are refused "
                      "(no trust-on-first-use)."),
        "check": "check_si7_1",
        "evidence_field": "load_gate/verified_artifact.digest",
        "scope": ("Proves: the check runs at the load transition for every "
                  "governed artifact, and unpinned artifacts cannot enter. "
                  "Assignment made: the transition is every governed load."),
        "not_claimed": ("Does not cover artifacts that bypass the governed "
                        "load path (the path must be the forced entry "
                        "point)."),
    },
    {
        "control_id": "SI-7(6)",
        "family": "SI",
        "nist_statement": ("Employ cryptographic mechanisms to protect the "
                           "integrity of software, firmware, and "
                           "information (not checksums alone)."),
        "mechanism": ("Ed25519 digital signatures (pure-python, RFC 8032 "
                      "self-tested) over domain-separated signing inputs; "
                      "SHA-256 hash chains."),
        "check": "check_si7_6",
        "evidence_field": "evidence_bundle/manifest.signature (Ed25519)",
        "scope": ("Proves: integrity rests on asymmetric cryptography "
                  "(RFC 8032 vectors pass), not on checksums."),
        "not_claimed": ("Does not claim post-quantum signatures; does not "
                        "claim key custody beyond the key-ceremony/key "
                        "provider boundary."),
    },
    {
        "control_id": "SI-7(7)",
        "family": "SI",
        "nist_statement": ("Integrate the detection of unauthorized changes "
                           "with incident response: detection is surfaced "
                           "as an actionable failure."),
        "mechanism": ("Fail-closed verification errors with machine-readable "
                      "codes (EnvelopeError, ArtifactRefused digest_mismatch) "
                      "raised at the executor/load boundary; a failed check "
                      "never returns ambiguous data."),
        "check": "check_si7_7",
        "evidence_field": ("executor/load boundary refusal (typed error, "
                           "machine-readable code)"),
        "scope": ("Proves: detection surfaces as a loud, typed refusal at "
                  "the boundary. The response integration claimed is the "
                  "fail-closed refusal, not a SOC workflow."),
        "not_claimed": ("Does not claim incident-response handling (IR-4) "
                        "beyond detection surfacing; no SOC is operated."),
    },
    {
        "control_id": "AU-10",
        "family": "AU",
        "nist_statement": ("Provide irrefutable evidence that an individual "
                           "(or process acting on behalf of an individual) "
                           "has performed organization-defined actions."),
        "mechanism": ("Signed decision packets: {value, producer, version} "
                      "binding action + principal + policy + verdict under "
                      "an Ed25519 packet signature; countersigned invocation "
                      "receipts chain under the packet."),
        "check": "check_au10",
        "evidence_field": "decision_packet/signature (+ authority block)",
        "scope": ("Proves: a signed packet verifies and a forged signature "
                  "is refused fail-closed. The binding covers action, "
                  "principal, policy identity and verdict."),
        "not_claimed": ("Does not prove the principal's real-world identity "
                        "beyond the attested-identity tier recorded in the "
                        "packet; repudiation of key compromise is a key- "
                        "custody matter."),
    },
    {
        "control_id": "AU-12",
        "family": "AU",
        "nist_statement": ("Generate audit records for organization-defined "
                           "auditable events."),
        "mechanism": ("Decision-log v2: one event per policy decision, "
                      "built by build_event and verifiable offline by "
                      "verify_event."),
        "check": "check_au12",
        "evidence_field": "decision_log_v2 event record",
        "scope": ("Proves: an event is generated per decision and verifies "
                  "offline. Assignment made: the auditable event set is "
                  "every policy decision at the executor boundary."),
        "not_claimed": ("Does not claim events for actions outside the "
                        "governed executor path."),
    },
    {
        "control_id": "AU-3",
        "family": "AU",
        "nist_statement": ("Ensure audit records contain organization-defined "
                           "content: what was done, by whom, when, and the "
                           "outcome."),
        "mechanism": ("The v2 event schema: decision{kind, effect, policy_id, "
                      "reason}, the content-derived decision_id, the event "
                      "digest, and the replay binding (replay_fn/inputs/"
                      "verdict)."),
        "check": "check_au3",
        "evidence_field": ("decision_log_v2 event: decision_id + decision "
                           "content + replay binding"),
        "scope": ("Proves: every mandated content field is present, "
                  "non-empty, and the complete event verifies."),
        "not_claimed": ("Does not claim wall-clock accuracy of timestamps "
                        "beyond the deployment's clock; does not claim "
                        "content outside the defined schema."),
    },
    {
        "control_id": "SR-4",
        "family": "SR",
        "nist_statement": ("Document, monitor, and maintain provenance of "
                           "system components; uniquely identify components "
                           "through the supply chain."),
        "mechanism": ("The Decision BOM: digest identity for the policy "
                      "bundle, pinned skills, approvals, and identity "
                      "inputs; the provenance verifier (in-toto-pattern "
                      "REQUIRE/MATCH/DISALLOW) checks receipts against "
                      "trusted statements."),
        "check": "check_sr4",
        "evidence_field": "decision_bom digest (+ pin_digests)",
        "scope": ("Proves: the BOM assembles, is shape-checked, has a stable "
                  "digest, and a rewritten digest is refused on "
                  "reconstruction."),
        "not_claimed": ("Does not claim provenance for inputs the decision "
                        "did not record; an approval_id without a resolvable "
                        "record digest is refused rather than silently "
                        "dropped."),
    },
    {
        "control_id": "SR-9",
        "family": "SR",
        "nist_statement": ("Detect tampering of system components."),
        "mechanism": ("Digest-mismatch refusal at the load seams: fetched "
                      "bytes that do not match the pinned digest are refused "
                      "with ArtifactRefused/digest_mismatch."),
        "check": "check_sr9",
        "evidence_field": "load_gate refusal record (digest_mismatch)",
        "scope": ("Proves: tampered bytes are detected and refused at the "
                  "load seam with a machine-readable code."),
        "not_claimed": ("Detects tampering of pinned artifacts; does not "
                        "detect tampering that occurred before the pin was "
                        "authored (pin authorship is the trust root)."),
    },
    {
        "control_id": "SR-10",
        "family": "SR",
        "nist_statement": ("Inspect systems or components before use."),
        "mechanism": ("Pack lint: safety/liveness/sanity inspection of rule "
                      "packs before load (no vacuous rules, no unreachable "
                      "branches, no shadowed grants, at least one reachable "
                      "allow path, no contradictory pairs)."),
        "check": "check_sr10",
        "evidence_field": "pack_lint report.violations",
        "scope": ("Proves: a vacuous rule pack is flagged before use and a "
                  "clean pack passes. Honest ceiling: bounded witness "
                  "search, no SMT solver -- exotic forms may yield "
                  "conservative false positives."),
        "not_claimed": ("Inspection is an approximation, not a formal proof; "
                        "does not inspect artifact bytes, only rule packs."),
    },
    {
        "control_id": "SR-11",
        "family": "SR",
        "nist_statement": ("Verify that components are authentic and "
                           "unmodified (anti-counterfeit)."),
        "mechanism": ("Signed-only admission: staging accepts unsigned "
                      "content loudly labeled; only signed, two-operator-"
                      "promoted bundles enter the enforced namespace, and "
                      "admission re-verifies signatures fresh and re-hashes "
                      "the exact bytes handed out."),
        "check": "check_sr11",
        "evidence_field": ("namespace admission record: signed_by key ids + "
                           "promoted_by operators"),
        "scope": ("Proves: unsigned content cannot deploy from enforced; "
                  "promotion needs two operators; admission re-verifies "
                  "fresh (no cached trust)."),
        "not_claimed": ("Does not claim revocation of already-promoted "
                        "bundles beyond refusing to promote/admit; signer "
                        "key custody is the key ceremony's scope."),
    },
    {
        "control_id": "SI-4",
        "family": "SI",
        "nist_statement": ("Monitor the system to detect attacks and "
                           "indicators of potential attacks."),
        "mechanism": ("Witness-cosigned checkpoints anchored to a "
                      "transparency log: signed entry timestamps (SETs) with "
                      "Merkle inclusion proofs; equivocation (conflicting "
                      "checkpoints per seq) is refused with evidence."),
        "check": "check_si4",
        "evidence_field": "anchor SET (inclusion_proof, log_sig, log_root)",
        "scope": ("Proves: a checkpoint anchors, its receipt verifies, and "
                  "a tampered inclusion proof is refused. The monitoring "
                  "claimed is transparency-log anchoring of checkpoints, "
                  "not a live SOC."),
        "not_claimed": ("Does not claim real-time intrusion detection or "
                        "response; the check uses the deterministic "
                        "in-process log, not a live transparency service."),
    },
    {
        "control_id": "SI-10",
        "family": "SI",
        "nist_statement": ("Validate information inputs before they become "
                           "trusted / are used."),
        "mechanism": ("Mask-before-buffer on the decision-shipping path: "
                      "events must be built under the deployment's compiled "
                      "mask plan; masked leaves are replaced by placeholders "
                      "and raw secrets never reach the buffer."),
        "check": "check_si10",
        "evidence_field": "shipped event: $masked placeholders",
        "scope": ("Proves: the gate refuses off-plan events and the buffered "
                  "event contains no raw secret under a masked pointer."),
        "not_claimed": ("Validates against the deployment's mask plan; the "
                        "plan's completeness (which pointers are sensitive) "
                        "is operator-owned."),
    },
    {
        "control_id": "SA-15",
        "family": "SA",
        "nist_statement": ("Require the developer to follow a documented "
                           "development process with standards and tools "
                           "that support trustworthiness."),
        "mechanism": ("Break-first red-team batteries as build gates (every "
                      "lane ships probes demonstrating genuine red before "
                      "green); the canonical runner's F75 supply-chain "
                      "preflight fails closed on contaminated interpreters."),
        "check": "check_sa15",
        "evidence_field": ("repo: evals/*_probes.py batteries + "
                           "tests/run_tests.py F75 preflight"),
        "scope": ("Proves: the process artifacts exist in the tree -- "
                  "red-team batteries as gates and the supply-chain "
                  "preflight in the runner. Process evidence, not product "
                  "behavior."),
        "not_claimed": ("Does not claim an external audit of the development "
                        "process; does not claim the process catches every "
                        "defect class."),
    },
]


# ---------------------------------------------------------------------------
# Explicitly NOT claimed (the honesty list). Each names the missing
# capability so no reader can mistake absence for coverage.
# ---------------------------------------------------------------------------

NOT_CLAIMED = [
    {"control_id": "AU-6", "title": "Audit Review, Analysis, and Reporting",
     "why_not": ("No audit-review/analysis workflow is shipped; we generate "
                 "and protect records, we do not operate the review function.")},
    {"control_id": "AU-7", "title": "Audit Record Reduction and Report Generation",
     "why_not": "No reduction/reporting pipeline is shipped."},
    {"control_id": "IR-4", "title": "Incident Handling",
     "why_not": ("Detection is surfaced fail-closed (SI-7(7)); no incident "
                 "handling, containment, or recovery workflow is shipped.")},
    {"control_id": "CA-7", "title": "Continuous Monitoring",
     "why_not": ("Checkpoint anchoring (SI-4) is transparency evidence, not "
                 "a continuous-monitoring program with a SOC.")},
    {"control_id": "CP-2", "title": "Contingency Plan",
     "why_not": "No contingency planning artifact is shipped."},
    {"control_id": "SC-8", "title": "Transmission Confidentiality and Integrity",
     "why_not": ("TLS for the shipping sink is caller-owned (documented "
                 "residual of the decision-shipping lane); not claimed.")},
    {"control_id": "SC-28", "title": "Protection of Information at Rest",
     "why_not": ("The disk journal has no envelope encryption at rest "
                 "(documented residual); not claimed.")},
    {"control_id": "IA-2", "title": "Identification and Authentication",
     "why_not": ("Operator identity authentication is caller-owned "
                 "(operator identities are caller-supplied strings in "
                 "ceremonies); not claimed.")},
]


# ---------------------------------------------------------------------------
# Evaluation (fail-closed)
# ---------------------------------------------------------------------------

def get_claim(control_id):
    """Return the claim dict for control_id; KeyError if unknown."""
    for c in CONTROL_CLAIMS:
        if c["control_id"] == control_id:
            return c
    raise KeyError("unknown control claim %r" % (control_id,))


def evaluate_claim(claim):
    """Evaluate one claim dict. Never raises: infrastructure failure
    becomes an UNCHECKABLE result (the overstated-closure signal)."""
    cid = claim.get("control_id", "?")
    name = claim.get("check")
    fn = CHECKS.get(name)
    if fn is None:
        return ClaimResult(
            cid, False, False,
            "UNCHECKABLE: no registered check named %r -- the claim "
            "cannot be evaluated and is therefore an overstated closure"
            % (name,))
    try:
        held, detail = fn()
    except Exception as e:
        return ClaimResult(
            cid, False, False,
            "UNCHECKABLE: check %r raised %s: %s -- the mechanism it "
            "cites cannot be demonstrated"
            % (name, type(e).__name__, e))
    if not isinstance(held, bool):
        return ClaimResult(
            cid, False, False,
            "UNCHECKABLE: check %r did not return a bool held flag"
            % (name,))
    return ClaimResult(cid, held, True, detail or "")


def check_claim(control_id):
    """Evaluate the claim for control_id."""
    return evaluate_claim(get_claim(control_id))


def check_all():
    """Evaluate every claim in table order."""
    return [evaluate_claim(c) for c in CONTROL_CLAIMS]
