"""Constructive decision packets at the policy decision seam (wave-176).

OpenShell prospectus steal #2, adapted not vendored: OpenShell emits a
decision packet per authorization -- machine-checkable, self-describing,
carrying the decision plus its justification (deny + counterexample +
obligations). Ours is a SIGNED, SELF-DESCRIBING record of one policy
decision, emitted by the executor at the final allow/deny/queue routing.

The packet COMPOSES existing bindings instead of duplicating them: it
references digests (policy decision, preview, receipt) rather than
re-binding the underlying values. It EMBEDS the authority-proof outcome
(verdict + coverage domains + counterexample) when a boundary is
configured, and says "no boundary configured" otherwise.

Every field is wrapped as {"value", "producer", "producer_version"} so an
offline auditor can see exactly which component produced each claim --
the packet is verifiable WITHOUT the engine (see verify_decision_packet;
the offline probe copies only this file + ed25519.py).

Stdlib only. Deterministic: no clock (issued_at is injectable), no
randomness (RFC 8032 deterministic nonces), no I/O, no env reads in the
build/verify path. The Ed25519 backend loads dual-mode (gov.ed25519 in
the repo, bare ed25519.py standalone) so verification works with no gov
package on sys.path.

What this does NOT do (honest boundaries):
- It does not grant authority. A within_boundary proof never upgrades a
  policy deny; the packet records the decision, it is not the decision.
- It does not prove the boundary is correct or task-minimal (steal #1's
  residuals apply unchanged).
- It is emitted at the call() decision seam only. Pre-decision
  fail-closed gates (authority-boundary refusal, quarantine, skill-watch
  denial) return before the seam; their audit entries carry the proof
  directly and no packet is emitted for them.
- The packet names the evidence-chain head it was built under; a
  concurrent writer between head-read and append is handled by the
  executor's rebuild-once (see ToolExecutor._emit_decision_packet).
"""

import hashlib
import json
import os
import stat

try:
    from . import ed25519 as _ed
except ImportError:  # standalone/offline: ed25519.py beside this file
    import ed25519 as _ed

DECISION_PACKET_VERSION = 1

DECISIONS = ("allow", "deny", "queue")

# The authority-proof verdicts, mirroring gov/authority_proof.py
# (WITHIN/EXCEEDS/UNSUPPORTED/INCONCLUSIVE). Hardcoded (not imported) so
# this module stays standalone-verifiable; tests/test_decision_packet.py
# asserts parity with gov.authority_proof.
PROOF_VERDICTS = ("within_boundary", "exceeds_boundary",
                  "unsupported", "inconclusive")

NO_BOUNDARY = "no boundary configured"

# producer_version names the value-shape version of that producer's
# contribution as defined by decision_packet v1. All "1" today; the
# per-field split exists so a producer can rev its contribution without
# revving the whole packet schema.
PRODUCER_VERSIONS = {
    "gov/executor.py": "1",
    "gov/authority_proof.py": "1",
    "gov/decision_contract.py": "1",
    "gov/skill_watch.py": "1",
    "gov/memory_actgate.py": "1",
    "gov/audio_carrier.py": "1",
    "gov/invocation_receipts.py": "1",
    "gov/log.py": "1",
    "gov/decision_packet.py": "1",
}

_SIGN_DOMAIN = b"decision-packet-v1:"


class PacketError(Exception):
    """The packet could not be built (loud, fail-closed for builders)."""


class NoPacketKeyError(Exception):
    """No packet-signing key configured (loud, no dev-key fallback)."""


def _canonical(obj):
    """Deterministic canonical JSON bytes (sort_keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def canonical_bytes(packet):
    """Canonical bytes of a packet (what digests and signatures bind)."""
    return _canonical(packet)


def packet_digest(packet):
    """sha256 over the canonical packet EXCLUDING the signature.

    This is the digest the executor's audit entry references
    (entry["packet_digest"]) and the digest linkage checks recompute.
    """
    body = {k: v for k, v in packet.items() if k != "signature"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def signing_input(body):
    """Domain-separated signing input over the unsigned body (which
    INCLUDES the authority block, mirroring gov/invocation_receipts)."""
    return _SIGN_DOMAIN + _canonical(body)


def _b64u_encode(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text):
    import base64
    if not isinstance(text, str):
        raise ValueError("not a string")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _utcnow_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def resolve_packet_key(explicit=None):
    """Resolve the Ed25519 packet-signing key (keyprovider idiom).

    Precedence: explicit hex seed > ``GOV_DECISION_PACKET_KEY`` (hex) >
    ``GOV_DECISION_PACKET_KEY_FILE`` (0600 file, hex). Nothing configured
    raises :class:`NoPacketKeyError`. No dev-key fallback, ever.

    Returns ``{"seed", "key_id", "pubkey_hex"}`` where ``key_id`` is
    ``sha256(pubkey)[:16]`` hex -- the same key-id convention as the
    invocation receipts.
    """
    seed_hex = (explicit or os.environ.get("GOV_DECISION_PACKET_KEY",
                                           "")).strip()
    if seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise NoPacketKeyError("GOV_DECISION_PACKET_KEY is not hex")
        if len(seed) != 32:
            raise NoPacketKeyError(
                "GOV_DECISION_PACKET_KEY must be 32 bytes")
        pub = _ed.publickey(seed)
        return {"seed": seed,
                "key_id": hashlib.sha256(pub).digest()[:16].hex(),
                "pubkey_hex": pub.hex()}
    key_file = os.environ.get("GOV_DECISION_PACKET_KEY_FILE", "").strip()
    if key_file:
        try:
            st = os.stat(key_file)
        except OSError as e:
            raise NoPacketKeyError(
                "refusing GOV_DECISION_PACKET_KEY_FILE %s: %s"
                % (key_file, e))
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise NoPacketKeyError(
                "refusing GOV_DECISION_PACKET_KEY_FILE %s: not 0600"
                % key_file)
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                seed = bytes.fromhex(f.read().strip())
        except (OSError, ValueError) as e:
            raise NoPacketKeyError(
                "cannot read GOV_DECISION_PACKET_KEY_FILE: %s" % (e,))
        if len(seed) != 32:
            raise NoPacketKeyError(
                "packet key file must hold 32 bytes hex")
        pub = _ed.publickey(seed)
        return {"seed": seed,
                "key_id": hashlib.sha256(pub).digest()[:16].hex(),
                "pubkey_hex": pub.hex()}
    raise NoPacketKeyError(
        "no packet-signing key configured (GOV_DECISION_PACKET_KEY / "
        "GOV_DECISION_PACKET_KEY_FILE); decision packets are disabled")


def _wrap(value, producer):
    """Wrap one field value with its producer attribution."""
    return {"value": value,
            "producer": producer,
            "producer_version": PRODUCER_VERSIONS[producer]}


def _check_proof_shape(proof):
    """Validate an embedded authority-proof dict. Returns (ok, reason)."""
    if not isinstance(proof, dict):
        return False, "authority_proof is not a dict"
    verdict = proof.get("verdict")
    if verdict not in PROOF_VERDICTS:
        return False, "authority_proof.verdict %r not a proof verdict" % (
            verdict,)
    for key in ("covered_domains", "uncovered_domains"):
        val = proof.get(key)
        if not isinstance(val, list) or not all(
                isinstance(x, str) for x in val):
            return False, "authority_proof.%s must be a list of str" % key
    ce = proof.get("counterexample")
    if ce is not None:
        if not isinstance(ce, dict):
            return False, "authority_proof.counterexample is not a dict"
        for key in ("domain", "access", "reason"):
            if not isinstance(ce.get(key), str):
                return False, \
                    "authority_proof.counterexample.%s must be str" % key
        # nearest_rule is Optional[str] on the producer side
        # (Counterexample.to_dict emits None when no boundary entry is
        # even close, or when the shape was unmodelable -- e.g. every
        # `unsupported` verdict). Accept str or null; anything else is
        # still malformed. (F195)
        nr = ce.get("nearest_rule")
        if nr is not None and not isinstance(nr, str):
            return False, \
                "authority_proof.counterexample.nearest_rule must be str or null"
    return True, "ok"


def _repair_hint(decision, proof):
    """The constructive element (steal #2): machine-actionable guidance
    for revising the REQUEST. Never revises the policy or the boundary."""
    if not isinstance(proof, dict):
        return None
    verdict = proof.get("verdict")
    ce = proof.get("counterexample") or {}
    if verdict == "exceeds_boundary":
        return ("narrow the request: %s access %r exceeds the boundary; "
                "nearest boundary rule %r (%s)"
                % (ce.get("domain"), ce.get("access"),
                   ce.get("nearest_rule"), ce.get("reason")))
    if verdict in ("unsupported", "inconclusive"):
        return ("the boundary does not cover this action shape (%s); "
                "declare the missing domain or split the action"
                % verdict)
    if decision == "deny":
        return ("the policy denied this action; revise the request, not "
                "the policy")
    return None


def build_decision_packet(*, decision, boundary_declared,
                          authority_proof=None,
                          policy_id=None, policy_version=None,
                          matched_rules=(), policy_flag=None,
                          decision_digest=None,
                          canonical_target=None, preview_digest=None,
                          capability_manifest_digest=None, skill_id=None,
                          actgate_tier="gate_not_attached",
                          actgate_disclosure_digest=None,
                          attachment_carriers=(), memory_carriers=(),
                          evidence_head_digest="GENESIS",
                          identity=None, approval_id=None,
                          decision_seq=None, policy_reason=None,
                          issued_at=None):
    """Build the UNSIGNED decision-packet body (dict, no ``signature``).

    ``decision`` is "allow" | "deny" | "queue" (the executor maps
    require_approval -> queue). ``authority_proof`` is the
    AuthorityProof.to_dict() when a boundary is declared, else None
    (the packet then records "no boundary configured"). Digests are
    referenced, not re-bound: ``decision_digest`` (sha256 over the
    canonical policy decision), ``preview_digest``, and the receipt
    digest (minted post-execution; the packet carries None and names
    the invocation_receipt entry that chains under it).

    Raises :class:`PacketError` (loud) when a declared boundary has no
    proof, or when a proof rides an undeclared boundary -- a packet
    that misstates the boundary posture is refused at construction,
    not patched at verify time.
    """
    if decision not in DECISIONS:
        raise PacketError(
            "decision must be one of %r, got %r" % (DECISIONS, decision))
    if not isinstance(boundary_declared, bool):
        raise PacketError("boundary_declared must be bool")
    if boundary_declared:
        ok, reason = _check_proof_shape(authority_proof)
        if not ok:
            raise PacketError(
                "boundary declared but authority proof invalid: %s"
                % reason)
        proof_value = authority_proof
    else:
        if authority_proof is not None:
            raise PacketError(
                "no boundary declared but an authority proof was supplied "
                "-- refusing to misstate the boundary posture")
        proof_value = NO_BOUNDARY
    if actgate_tier not in ("gate_not_attached", "no_un_elevated_reads",
                            "un_elevated_reads_present"):
        raise PacketError("unknown actgate_tier %r" % (actgate_tier,))
    ident = identity if isinstance(identity, dict) else {}
    body = {
        "decision_packet_version": DECISION_PACKET_VERSION,
        "decision": _wrap(decision, "gov/executor.py"),
        "boundary_declared": _wrap(boundary_declared, "gov/executor.py"),
        "authority_proof": _wrap(proof_value, "gov/authority_proof.py"),
        "policy": _wrap({
            "policy_id": policy_id,
            "policy_version": policy_version,
            "matched_rules": list(matched_rules or []),
            "policy_flag": policy_flag,
            # The decision itself, by digest: the packet composes the
            # policy binding rather than re-binding it. An auditor
            # re-hashes the chained decision entry to confirm.
            "decision_digest": decision_digest,
        }, "gov/decision_contract.py"),
        "canonical_target": _wrap(canonical_target, "gov/executor.py"),
        "preview_digest": _wrap(preview_digest, "gov/executor.py"),
        "capability_manifest": _wrap({
            "digest": capability_manifest_digest,
            "skill_id": skill_id,
        }, "gov/skill_watch.py"),
        "memory_actgate": _wrap({
            "tier": actgate_tier,
            "disclosure_digest": actgate_disclosure_digest,
        }, "gov/memory_actgate.py"),
        "carriers": _wrap({
            "attachment_carriers": list(attachment_carriers or []),
            "memory_carriers": list(memory_carriers or []),
        }, "gov/audio_carrier.py"),
        "evidence": _wrap({
            # The chain head this packet was built under. The packet's
            # own audit entry chains onto it; linkage is verified by
            # matching entry prev_hash (see verify_decision_packet).
            "head_digest": evidence_head_digest,
        }, "gov/log.py"),
        "identity": _wrap({
            "agent_id": ident.get("agent_id"),
            "role": ident.get("role"),
            "principal": ident.get("principal"),
            "run_id": ident.get("run_id"),
        }, "gov/executor.py"),
        "approval_id": _wrap(approval_id, "gov/executor.py"),
        "decision_seq": _wrap(decision_seq, "gov/executor.py"),
        # The constructive refusal (steal #2): what the decision was
        # and, on deny/exceeds, machine-readable guidance for revising
        # the REQUEST. Never revises the policy or the boundary.
        "justification": _wrap({
            "policy_reason": policy_reason,
            "matched_rules": list(matched_rules or []),
            "counterexample": ((authority_proof or {}).get("counterexample")
                               if boundary_declared else None),
            "repair_hint": _repair_hint(decision,
                                        authority_proof
                                        if boundary_declared else None),
        }, "gov/decision_packet.py"),
        # Receipts mint post-execution over the executed action; the
        # packet references the receipt by digest when one exists yet
        # (it never does at decision time -- the packet is emitted
        # first and the invocation_receipt entry chains under it).
        # None here is honest ordering, not a gap.
        "receipt_digest": _wrap(None, "gov/invocation_receipts.py"),
        "issued_at": _wrap(issued_at or _utcnow_iso(),
                           "gov/decision_packet.py"),
    }
    return body


def sign_packet(body, seed):
    """Attach the executor's Ed25519 packet signature. Returns a new dict.

    ``seed`` is the 32-byte packet-signing seed (see resolve_packet_key).
    The authority block (kid/pubkey) is part of the signed body, so the
    signature binds the key identity to the packet.
    """
    if not isinstance(body, dict):
        raise PacketError("body must be a dict")
    if "signature" in body:
        raise PacketError("body is already signed")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise PacketError("seed must be 32 bytes")
    pub = _ed.publickey(bytes(seed))
    authority = {"kid": hashlib.sha256(pub).digest()[:16].hex(),
                 "pubkey": pub.hex()}
    body_with_auth = dict(body)
    body_with_auth["authority"] = authority
    sig = _ed.sign(bytes(seed), signing_input(body_with_auth))
    packet = dict(body_with_auth)
    packet["signature"] = _b64u_encode(sig)
    return packet


def _find_packet_entries(entries, digest):
    """Decision-packet audit entries whose packet_digest matches."""
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "decision_packet":
            continue
        if e.get("packet_digest") == digest:
            out.append(e)
    return out


def verify_decision_packet(packet, entries=None):
    """Offline verification of a signed decision packet (stdlib only).

    Returns ``(True, "ok")`` or ``(False, reason)``. Never raises on
    malformed input (fail-closed for verifiers: malformed is False, never
    an exception). Checks, in order: structure (every section present and
    producer-attributed), packet version, decision value, the
    boundary/proof consistency rule (a declared boundary MUST carry a
    proof; an undeclared boundary MUST NOT), authority well-formedness
    (32-byte pubkey, kid == sha256(pub)[:16]), the Ed25519 signature over
    the domain-separated canonical body, and -- when ``entries`` (audit
    entries) are supplied -- the digest linkage: some decision_packet
    entry references this packet's digest AND its prev_hash equals the
    packet's stated head digest AND that head exists in the chain.

    ``entries=None`` skips the linkage check (reported in the reason);
    pass the chain for the full check.
    """
    try:
        return _verify(packet, entries)
    except Exception as e:  # noqa: BLE001 - verifiers never raise
        return False, "verifier exception (fail-closed): %s: %s" % (
            type(e).__name__, e)


def _verify(packet, entries):
    if not isinstance(packet, dict):
        return False, "packet is not a dict"
    if packet.get("decision_packet_version") != DECISION_PACKET_VERSION:
        return False, "unsupported decision_packet_version %r" % (
            packet.get("decision_packet_version"),)
    required = ("decision", "boundary_declared", "authority_proof",
                "policy", "canonical_target", "preview_digest",
                "capability_manifest", "memory_actgate", "carriers",
                "evidence", "identity", "approval_id", "decision_seq",
                "justification", "receipt_digest", "issued_at")
    for name in required:
        section = packet.get(name)
        if not isinstance(section, dict):
            return False, "missing section %r" % name
        if "value" not in section:
            return False, "section %r has no value" % name
        if not section.get("producer"):
            return False, "section %r names no producer" % name
        if not section.get("producer_version"):
            return False, "section %r names no producer_version" % name
    if packet["decision"]["value"] not in DECISIONS:
        return False, "decision %r not in %r" % (
            packet["decision"]["value"], DECISIONS)
    declared = packet["boundary_declared"]["value"]
    if not isinstance(declared, bool):
        return False, "boundary_declared is not bool"
    proof_value = packet["authority_proof"]["value"]
    if declared:
        ok, reason = _check_proof_shape(proof_value)
        if not ok:
            return False, \
                "boundary declared but no valid authority proof: %s" % reason
    else:
        if proof_value != NO_BOUNDARY:
            return False, \
                "no boundary declared but packet carries a proof"
    auth = packet.get("authority")
    if not isinstance(auth, dict):
        return False, "missing authority block"
    try:
        pub = bytes.fromhex(auth.get("pubkey") or "")
    except (ValueError, TypeError):
        return False, "authority.pubkey not hex"
    if len(pub) != 32:
        return False, "authority.pubkey not 32 bytes"
    if auth.get("kid") != hashlib.sha256(pub).digest()[:16].hex():
        return False, "authority.kid does not match pubkey"
    sig_b64 = packet.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        return False, "missing signature"
    try:
        sig = _b64u_decode(sig_b64)
    except (ValueError, TypeError):
        return False, "signature not base64url"
    body = {k: v for k, v in packet.items() if k != "signature"}
    if not _ed.verify(pub, signing_input(body), sig):
        return False, "Ed25519 packet signature does not verify"
    head = packet["evidence"]["value"].get("head_digest")
    if not isinstance(head, str) or not head:
        return False, "evidence.head_digest missing"
    digest = packet_digest(packet)
    if entries is None:
        return True, "ok (structure+signature; chain linkage not checked)"
    if not isinstance(entries, (list, tuple)):
        return False, "entries is not a list"
    matches = _find_packet_entries(entries, digest)
    if not matches:
        return False, \
            "digest linkage: no decision_packet entry references this packet"
    for m in matches:
        if m.get("prev_hash") != head:
            return False, \
                "digest linkage: entry prev_hash does not match the " \
                "packet's stated head digest (stale or forked head)"
    hashes = {e.get("hash") for e in entries
              if isinstance(e, dict) and e.get("hash")}
    if head != "GENESIS" and head not in hashes:
        return False, \
            "digest linkage: stated head digest not present in the chain"
    return True, "ok"


def evidence_head_digest(log_path):
    """The current evidence-chain head digest for a JSONL audit log.

    Returns the ``hash`` of the last well-formed entry (mirroring
    ActionLog.refresh's F52 rule: unparseable tail lines are skipped,
    never trusted), or "GENESIS" for a missing/empty log with no
    well-formed entries.
    """
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            window = min(size, 1 << 16)
            f.seek(size - window)
            tail = f.read()
    except FileNotFoundError:
        return "GENESIS"
    except OSError as e:
        raise PacketError("cannot read log %s: %s" % (log_path, e))
    lines = [ln for ln in tail.splitlines() if ln.strip()]
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if (isinstance(entry, dict)
                and isinstance(entry.get("seq"), int)
                and isinstance(entry.get("hash"), str)
                and entry["hash"]):
            return entry["hash"]
    if size > 1 << 16:
        # The tail window held no well-formed entry; fall back to a
        # full scan rather than misreporting the head.
        head = None
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if (isinstance(entry, dict)
                            and isinstance(entry.get("seq"), int)
                            and isinstance(entry.get("hash"), str)
                            and entry["hash"]):
                        head = entry["hash"]
        except OSError as e:
            raise PacketError("cannot read log %s: %s" % (log_path, e))
        return head or "GENESIS"
    return "GENESIS"
