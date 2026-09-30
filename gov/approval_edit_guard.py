#!/usr/bin/env python3
"""Approve-with-edits refusal at the adapter boundary (wave-237).

Re-derived from fissible ADR-0040 and the wave-237 prospectus W237-4:
an approval that does not match the proposal it claims to approve is
refused here, at the adapter boundary -- never "close enough" accepted,
never rebound to a different proposal.

* ``propose(action_bytes, proposal_id=None)`` seals a Proposal binding
  the CANONICAL action bytes. Canonicalization is JCS (``json.dumps``
  with sorted keys, no whitespace, ASCII) for action bytes that parse
  as JSON; non-JSON bytes are bound byte-exact (opaque payloads). The
  action digest is domain-separated from every other digest in the
  tree so a digest minted here cannot be confused with a permit
  request digest or a receipt digest.
* ``check_approval(proposal, approval)`` verifies id/action consistency:
  the approval's ``proposal_id`` must equal the proposal's AND the
  digest of the approval's action bytes must equal the proposal's
  ``action_digest``. An approval whose action bytes were edited under
  the same proposal id refuses ``approval-edited``; an approval
  presented in a proposal context it does not belong to (a different
  ``proposal_id`` -- the IDOR-shaped rebinding attempt) refuses
  ``approval-rebinding``. Byte-identical approvals pass; byte-different
  but semantically identical JSON wire shapes pass (JCS binds them).
* ``repropose(edited_action, proposal_id=None)`` re-proposes the
  edited action as a NEW proposal: fresh id, fresh digest, no link to
  the old approval. A subsequent clean approval against the fresh
  proposal consumes normally. This module keeps no registry, so it
  cannot stop a caller from reusing an old id -- the default fresh id
  is derived from the new digest, and callers must not reuse ids.

Honest residuals: the module binds digests of caller-supplied action
bytes; it does not prove a human actually gave the approval, and a
(proposal, approval) pair is only as trustworthy as the channel that
delivered it. Nothing here prevents replay of an old valid pair --
that is deployment-owned (expiry, single-use consumption). The digest
binds what was proposed, in which canonical form; the check proves the
approval matches the proposal, not that the proposal was wise.

Stdlib only. Deterministic: no randomness; the only clock read is
``time.time()`` for ``issued_at`` stamps (never re-verified against
the clock). No network. $0.
"""

import hashlib
import json
import time

_APPROVAL_GUARD_DOMAIN = b"sasanam-approval-edit-guard-v1:"
_PROPOSAL_VERSION = 1
_HEX64 = "0123456789abcdef"

# Refusal codes (module-level, w228 vocabulary idiom 2).
APPROVAL_EDITED = "approval-edited"
APPROVAL_REBINDING = "approval-rebinding"
APPROVAL_MALFORMED = "approval-malformed"


class ApprovalEditGuardError(Exception):
    """Base error: carries no string ``code`` itself (w228 audited)."""


class _ApprovalEdited(ApprovalEditGuardError):
    code = APPROVAL_EDITED


class _ApprovalRebinding(ApprovalEditGuardError):
    code = APPROVAL_REBINDING


class _ApprovalMalformed(ApprovalEditGuardError):
    code = APPROVAL_MALFORMED


# ----------------------------------------------------------------------
# Internals.
# ----------------------------------------------------------------------


def _canonical_dumps(obj):
    """JCS: sorted keys, compact separators, ASCII. Same canonical idiom
    as gov/permit_closure.py, re-derived here so this module stays
    self-contained (stdlib only, no cross-module private coupling)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _canonical_action_bytes(action_bytes):
    """Bind the canonical action bytes.

    Bytes that parse as JSON are canonicalized with JCS so that
    byte-different but semantically identical wire shapes (key order,
    whitespace) still bind. Bytes that do not parse as JSON are bound
    byte-exact (opaque payloads).
    """
    if not isinstance(action_bytes, (bytes, bytearray)):
        raise _ApprovalMalformed(
            "approval-malformed: action_bytes must be bytes")
    raw = bytes(action_bytes)
    if not raw:
        raise _ApprovalMalformed(
            "approval-malformed: action_bytes must be non-empty")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return raw
    return _canonical_dumps(parsed).encode("utf-8")


def _action_digest(action_bytes):
    """Domain-separated digest of the canonical action bytes."""
    h = hashlib.sha256(_APPROVAL_GUARD_DOMAIN)
    h.update(_canonical_action_bytes(action_bytes))
    return h.hexdigest()


def _is_bare_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in _HEX64 for c in value)


def _check_proposal_id(proposal_id, field):
    if not isinstance(proposal_id, str) or not proposal_id:
        raise _ApprovalMalformed(
            "approval-malformed: %s must be a non-empty string" % (field,))


# ----------------------------------------------------------------------
# Proposals.
# ----------------------------------------------------------------------


def propose(action_bytes, proposal_id=None, issued_at=None):
    """Seal a Proposal binding the canonical action bytes.

    ``action_bytes`` are the exact bytes proposed for approval; their
    digest binds the JCS canonical form (byte-exact for opaque
    payloads). ``proposal_id`` defaults to ``"proposal-" + digest[:16]``
    -- deterministic, fresh for every distinct action. Returns the
    proposal record; the record itself is caller-held.
    """
    digest = _action_digest(action_bytes)
    if proposal_id is None:
        proposal_id = "proposal-%s" % digest[:16]
    _check_proposal_id(proposal_id, "proposal_id")
    return {
        "version": _PROPOSAL_VERSION,
        "proposal_id": proposal_id,
        "action_digest": digest,
        "issued_at": issued_at if issued_at is not None else time.time(),
    }


def repropose(edited_action, proposal_id=None, issued_at=None):
    """Re-propose an edited action as a NEW proposal.

    Fresh id (default derived from the new digest), fresh digest, and
    no link whatsoever to any old approval: the returned record carries
    only the four proposal fields. A subsequent clean approval against
    this proposal consumes normally via ``check_approval``.
    """
    return propose(edited_action, proposal_id=proposal_id,
                   issued_at=issued_at)


# ----------------------------------------------------------------------
# The adapter boundary.
# ----------------------------------------------------------------------


def check_approval(proposal, approval):
    """Verify id/action consistency at the adapter boundary.

    ``proposal`` is the record returned by ``propose``/``repropose``
    (at minimum ``proposal_id`` and ``action_digest``) -- the brief's
    "proposal_digest" is realized as ``proposal["action_digest"]``,
    because the rebinding check needs the proposal id too, and a bare
    digest cannot distinguish a rebinding attempt from an edited one.
    ``approval`` carries the ``proposal_id`` it claims and the
    ``action_bytes`` being approved.
    Returns True when the approval matches the proposal exactly.
    Refuses ``approval-edited`` when the action bytes differ from the
    proposal under the same id (never "close enough"); refuses
    ``approval-rebinding`` when the approval is presented in a proposal
    context it does not belong to (different ``proposal_id`` -- the
    IDOR-shaped attempt), even if the bytes would match elsewhere.
    Shape failures refuse ``approval-malformed``.
    """
    if not isinstance(proposal, dict):
        raise _ApprovalMalformed(
            "approval-malformed: proposal must be a dict")
    if not isinstance(approval, dict):
        raise _ApprovalMalformed(
            "approval-malformed: approval must be a dict")
    proposal_id = proposal.get("proposal_id")
    _check_proposal_id(proposal_id, "proposal.proposal_id")
    action_digest = proposal.get("action_digest")
    if not _is_bare_digest(action_digest):
        raise _ApprovalMalformed(
            "approval-malformed: proposal.action_digest must be a "
            "64-char lowercase hex digest")
    approval_proposal_id = approval.get("proposal_id")
    _check_proposal_id(approval_proposal_id, "approval.proposal_id")
    if "action_bytes" not in approval:
        raise _ApprovalMalformed(
            "approval-malformed: approval carries no action_bytes")
    # Order matters: the context check comes first. An approval bound
    # to a different proposal id presented here is a rebinding attempt
    # (IDOR-shaped), even when its bytes happen to be unedited.
    if approval_proposal_id != proposal_id:
        raise _ApprovalRebinding(
            "approval-rebinding: approval claims proposal %r but is "
            "presented for %r; approvals are never rebound across "
            "proposals" % (approval_proposal_id, proposal_id))
    recomputed = _action_digest(approval["action_bytes"])
    if recomputed != action_digest:
        raise _ApprovalEdited(
            "approval-edited: approved action bytes differ from the "
            "proposed action bytes; re-propose the edited action "
            "instead of approving with edits")
    return True
