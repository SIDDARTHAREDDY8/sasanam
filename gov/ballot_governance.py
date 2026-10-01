"""Consortium ballot governance: CCF-style scriptable constitutions over our
audit journal. Wave-261 lane 1.

PATTERN LINEAGE: microsoft/CCF (https://github.com/microsoft/CCF),
**Apache-2.0** (license verified from raw LICENSE bytes 2026-10-01 by
the wave-260 prospecting lane). Exactly four IDEAS are adapted here --
no CCF source is vendored and no CCF code or prose is copied (the
governance protocol is reimplemented in our own grammar):

1. **Scriptable constitution** exporting the three-phase shape
   ``validate`` (pure admission of the proposal, no state) /
   ``resolve`` (ballot + votes -> Adopted / Rejected / Open, read-only
   state) / ``apply`` (state transition, caller-owned, only on
   adoption). The constitution is DATA here (members with roles and
   weights, named ballot types with programmable hooks), not JS.
2. **Programmable ``vote()`` ballots**: each ballot type carries a
   ``vote_fn(member, decision, view) -> bool`` hook, re-executed on
   every vote -- and re-run over ALL recorded votes at every
   ``resolve()`` -- against a READ-ONLY snapshot of the ballot state
   (``types.MappingProxyType``; a hook that tries to mutate it fails
   loudly and the vote is refused, never counted).
3. **Every vote is signed and ledger-recorded**: votes are Ed25519
   member signatures (``gov/ed25519.py``) over a domain-separated
   canonical envelope; accepted votes journal ``ballot-vote-recorded``
   and refused votes journal ``ballot-vote-refused`` (with the machine
   code) on the hash-chained ``gov/durable_journal`` journal. A bad
   signature or a non-member vote is REFUSED with a machine code,
   never counted.
4. **Sample constitutions** ported from CCF's: majority-accept with
   **single-member veto** (any ``False`` -> ``Rejected``), and
   **role-weighted resolve** (operators carry weight; destructive
   ballots need a 2/3 weight supermajority AND no operator veto).

What this module is and is not:
- It is consortium governance among KNOWN key-holders. Sybil
  resistance is the member list, which is deployment-owned (loaded
  from a trusted config, not negotiated here). It does NOT solve
  member-key custody: a compromised member key votes as that member,
  exactly as a compromised keyholder acts in any consortium.
- It records the DECISION, not the action: ``apply()`` invokes the
  ballot type's optional ``on_adopt`` hook and journals
  ``ballot-applied``; the actual state transition (grant issued,
  credential swapped) is the caller's responsibility, executed only
  when ``resolve()`` says ``adopted``.
- A ballot that can never reach quorum does not adopt silently:
  once the electorate is exhausted without adoption,
  ``resolve()`` returns ``rejected`` with the explicit machine code
  ``ballot-quorum-not-reached``. Unknown ballots, double votes, and
  late votes after resolution refuse loudly with machine codes.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json
import secrets
import types as _types

from gov import durable_journal
from gov import ed25519

__all__ = [
    "BallotError",
    "BallotUnknownBallot",
    "BallotUnknownBallotType",
    "BallotMalformedProposal",
    "BallotNotMember",
    "BallotBadSignature",
    "BallotDoubleVote",
    "BallotLateVote",
    "BallotVoteHookFailed",
    "BallotQuorumNotReached",
    "Member",
    "BallotType",
    "Constitution",
    "BallotBox",
    "vote_envelope",
    "majority_with_veto",
    "operator_weighted",
]

#: Domain separation for the vote signed body. The ``\\x00`` separates the
#: domain tag from the canonical JSON so no ballot field can be confused
#: with the tag.
_VOTE_DOMAIN = b"ballot-vote/v1\x00"

#: Bounds: proposals and votes are small governance records, not blobs.
_MAX_PAYLOAD_BYTES = 64 * 1024

#: Ballot statuses (CCF: Accepted / Rejected / Open).
ADOPTED = "adopted"
REJECTED = "rejected"
OPEN = "open"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _payload_digest(payload):
    return hashlib.sha256(_canonical(payload)).hexdigest()


def vote_envelope(ballot_id, member_id, decision, payload_digest):
    """Canonical signed bytes for a vote.

    Binds member identity, ballot, decision, and the proposal payload
    digest so a signature cannot be replayed across ballots, members,
    decisions, or payload edits.
    """
    return _VOTE_DOMAIN + _canonical({
        "ballot_id": ballot_id,
        "member_id": member_id,
        "decision": bool(decision),
        "payload_digest": payload_digest,
    })


# ---------------------------------------------------------------------------
# Errors: one class per machine code (decision_codes inventory idiom 1).
# ---------------------------------------------------------------------------

class BallotError(Exception):
    """Base: every ballot-governance refusal carries a machine ``code``."""


class BallotUnknownBallot(BallotError):
    code = "ballot-unknown-ballot"


class BallotUnknownBallotType(BallotError):
    code = "ballot-unknown-ballot-type"


class BallotMalformedProposal(BallotError):
    code = "ballot-malformed-proposal"


class BallotNotMember(BallotError):
    code = "ballot-not-member"


class BallotBadSignature(BallotError):
    code = "ballot-bad-signature"


class BallotDoubleVote(BallotError):
    code = "ballot-double-vote"


class BallotLateVote(BallotError):
    code = "ballot-late-vote"


class BallotVoteHookFailed(BallotError):
    code = "ballot-vote-hook-failed"


class BallotQuorumNotReached(BallotError):
    code = "ballot-quorum-not-reached"


# ---------------------------------------------------------------------------
# Data model: Member, BallotType, Constitution.
# ---------------------------------------------------------------------------

class Member:
    """A consortium key-holder: id, Ed25519 public key, role, weight."""

    def __init__(self, member_id, pubkey, role="member", weight=1):
        if not isinstance(member_id, str) or not member_id:
            raise ValueError("member_id must be a non-empty string")
        if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
            raise ValueError("pubkey must be 32 raw Ed25519 bytes")
        if not isinstance(role, str) or not role:
            raise ValueError("role must be a non-empty string")
        if not isinstance(weight, int) or weight < 1:
            raise ValueError("weight must be a positive int")
        self.member_id = member_id
        self.pubkey = bytes(pubkey)
        self.role = role
        self.weight = weight

    def to_dict(self):
        return {"member_id": self.member_id,
                "pubkey": self.pubkey.hex(),
                "role": self.role, "weight": self.weight}

    @classmethod
    def from_dict(cls, d):
        return cls(d["member_id"], bytes.fromhex(d["pubkey"]),
                   d.get("role", "member"), d.get("weight", 1))


class BallotType:
    """One programmable ballot kind in a constitution.

    ``vote_fn(member, decision, view) -> bool`` is the CCF ``vote()``
    hook: re-executed on every vote (and re-run over all votes at every
    ``resolve()``) against the READ-ONLY ``view`` snapshot. ``view`` is
    a mapping proxy of ``{"ballot": {...}, "votes": {member_id: bool}}``;
    a hook that raises or mutates fails the vote loudly.

    ``resolve_fn(ballot_snapshot, effective_votes) -> (status, note)``
    is the CCF ``resolve()``: ``status`` in {adopted, rejected, open};
    ``note`` is a machine string (a decision code when terminal).
    ``ballot_snapshot`` and the votes mapping are read-only proxies.

    ``on_adopt(ballot_snapshot)`` is the optional CCF ``apply()`` body,
    run by :meth:`BallotBox.apply` only after adoption; its return
    value is journaled. The caller owns the real state transition.
    """

    def __init__(self, name, vote_fn=None, resolve_fn=None,
                 on_adopt=None, description=""):
        if not isinstance(name, str) or not name:
            raise ValueError("ballot type name must be non-empty")
        self.name = name
        self.vote_fn = vote_fn or (lambda member, decision, view: bool(
            decision))
        self.resolve_fn = resolve_fn or (lambda ballot, votes: (OPEN, ""))
        self.on_adopt = on_adopt
        self.description = description


class Constitution:
    """The consortium's governance data: members + ballot types."""

    def __init__(self, members, ballot_types):
        members = dict(members)
        ballot_types = dict(ballot_types)
        if not members:
            raise ValueError("constitution needs at least one member")
        if not ballot_types:
            raise ValueError("constitution needs at least one ballot type")
        for mid, m in members.items():
            if not isinstance(m, Member) or m.member_id != mid:
                raise ValueError("member key %r mismatches" % (mid,))
        for name, bt in ballot_types.items():
            if not isinstance(bt, BallotType) or bt.name != name:
                raise ValueError("ballot type key %r mismatches" % (name,))
        self.members = members
        self.ballot_types = ballot_types

    def to_dict(self):
        return {
            "members": {mid: m.to_dict()
                        for mid, m in self.members.items()},
            "ballot_types": sorted(self.ballot_types),
        }


# ---------------------------------------------------------------------------
# Sample constitutions (CCF's two shipped samples, reimplemented).
# ---------------------------------------------------------------------------

def _identity_vote(member, decision, view):
    return bool(decision)


def _majority_veto_resolve(ballot, votes):
    """Single-member veto + majority accept (CCF sample 1)."""
    n = ballot["electorate"]
    if any(v is False for v in votes.values()):
        return (REJECTED, "vetoed")
    yes = sum(1 for v in votes.values() if v is True)
    if yes * 2 > n:
        return (ADOPTED, "majority")
    if len(votes) >= n:
        # Electorate exhausted without a majority: explicit, never silent.
        return (REJECTED, "ballot-quorum-not-reached")
    return (OPEN, "")


def majority_with_veto(members):
    """Sample constitution 1: one member one vote; any ``False`` vetoes;
    adoption needs a strict majority of the electorate."""
    members = list(members)
    return Constitution(
        members={m.member_id: m for m in members},
        ballot_types={
            "standard": BallotType(
                name="standard",
                vote_fn=_identity_vote,
                resolve_fn=_majority_veto_resolve,
                description="majority accept with single-member veto",
            ),
        },
    )


def _operator_veto_weighted_resolve(destructive):
    def resolve(ballot, votes):
        members = ballot["members"]
        total = sum(m["weight"] for m in members.values())
        yes_w = sum(members[mid]["weight"] for mid, v in votes.items()
                    if v is True)
        if destructive:
            # Operators carry veto on destructive ballots (CCF sample 2:
            # role-weighted resolve; operators gate sensitive actions).
            if any(v is False and members[mid]["role"] == "operator"
                   for mid, v in votes.items()):
                return (REJECTED, "operator-veto")
            if yes_w * 3 >= total * 2:
                return (ADOPTED, "supermajority")
        else:
            if yes_w * 2 > total:
                return (ADOPTED, "weight-majority")
        if len(votes) >= len(members):
            return (REJECTED, "ballot-quorum-not-reached")
        return (OPEN, "")
    return resolve


def operator_weighted(members):
    """Sample constitution 2: role-weighted thresholds (CCF sample 2).

    ``routine`` ballots adopt on a weight majority; ``destructive``
    ballots need >= 2/3 of total weight AND no operator ``False``
    vote (operator veto). Roles and weights are constitution data.
    """
    members = list(members)
    by_id = {m.member_id: m for m in members}
    return Constitution(
        members=by_id,
        ballot_types={
            "routine": BallotType(
                name="routine",
                vote_fn=_identity_vote,
                resolve_fn=_operator_veto_weighted_resolve(False),
                description="weight-majority adoption",
            ),
            "destructive": BallotType(
                name="destructive",
                vote_fn=_identity_vote,
                resolve_fn=_operator_veto_weighted_resolve(True),
                description="2/3 weight supermajority + operator veto",
            ),
        },
    )


# ---------------------------------------------------------------------------
# The ballot box: propose (validate) / vote / resolve / apply.
# ---------------------------------------------------------------------------

class BallotBox:
    """Runs ballots under a constitution, journaling every governance
    event to a hash-chained ``durable_journal.Journal``."""

    def __init__(self, constitution, journal_path):
        if not isinstance(constitution, Constitution):
            raise ValueError("constitution must be a Constitution")
        self.constitution = constitution
        self.journal = durable_journal.Journal(journal_path)
        self._ballots = {}
        self._replay_journal()

    # -- journal replay ------------------------------------------------
    def _replay_journal(self):
        """Rebuild open-ballot state from the journal (crash recovery).
        Corruption fails closed: Journal raises on load."""
        for rec in self.journal.records:
            body = rec["body"]
            rtype = rec["type"]
            if rtype == "ballot-proposed":
                self._ballots[body["ballot_id"]] = {
                    "ballot_id": body["ballot_id"],
                    "ballot_type": body["ballot_type"],
                    "proposer": body["proposer"],
                    "payload": body["payload"],
                    "payload_digest": body["payload_digest"],
                    "votes": {},
                    "status": OPEN,
                    "resolution": None,
                }
            elif rtype == "ballot-vote-recorded":
                b = self._ballots.get(body["ballot_id"])
                if b is not None and b["status"] == OPEN:
                    b["votes"][body["member_id"]] = {
                        "decision": body["decision"],
                        "effective": body["effective"],
                        "signature_sha256": body["signature_sha256"],
                        "seq": body["seq"],
                    }
            elif rtype == "ballot-resolved":
                b = self._ballots.get(body["ballot_id"])
                if b is not None:
                    b["status"] = body["status"]
                    b["resolution"] = body

    # -- validate (pure admission, CCF validate) ------------------------
    def _validate_proposal(self, ballot_type, payload, proposer):
        if ballot_type not in self.constitution.ballot_types:
            raise BallotUnknownBallotType(
                "unknown ballot type %r" % (ballot_type,))
        if proposer not in self.constitution.members:
            raise BallotNotMember(
                "proposer %r is not a consortium member" % (proposer,))
        if not isinstance(payload, dict):
            raise BallotMalformedProposal("payload must be a dict")
        try:
            raw = _canonical(payload)
        except (TypeError, ValueError):
            raise BallotMalformedProposal(
                "payload is not JSON-canonicalizable")
        if len(raw) > _MAX_PAYLOAD_BYTES:
            raise BallotMalformedProposal("payload exceeds %d bytes" %
                                          _MAX_PAYLOAD_BYTES)
        if "action" not in payload or not isinstance(payload["action"],
                                                      str):
            raise BallotMalformedProposal(
                "payload needs a string 'action' field")

    def propose(self, ballot_type, payload, proposer):
        """Admit a proposal (validate) and open a ballot. Returns the
        ballot id. Every proposal is journaled."""
        self._validate_proposal(ballot_type, payload, proposer)
        ballot_id = "blt-" + secrets.token_hex(8)
        while ballot_id in self._ballots:
            ballot_id = "blt-" + secrets.token_hex(8)
        digest = _payload_digest(payload)
        ballot = {
            "ballot_id": ballot_id,
            "ballot_type": ballot_type,
            "proposer": proposer,
            "payload": dict(payload),
            "payload_digest": digest,
            "votes": {},
            "status": OPEN,
            "resolution": None,
        }
        self.journal.append("ballot-proposed", {
            "ballot_id": ballot_id,
            "ballot_type": ballot_type,
            "proposer": proposer,
            "payload": dict(payload),
            "payload_digest": digest,
            "electorate": len(self.constitution.members),
        })
        self._ballots[ballot_id] = ballot
        return ballot_id

    # -- read-only state view for vote()/resolve() hooks ----------------
    def _view(self, ballot):
        return _types.MappingProxyType({
            "ballot": _types.MappingProxyType({
                "ballot_id": ballot["ballot_id"],
                "ballot_type": ballot["ballot_type"],
                "proposer": ballot["proposer"],
                "payload_digest": ballot["payload_digest"],
                "electorate": len(self.constitution.members),
                "members": _types.MappingProxyType({
                    mid: _types.MappingProxyType({
                        "role": m.role, "weight": m.weight})
                    for mid, m in self.constitution.members.items()}),
            }),
            "votes": _types.MappingProxyType(dict(
                (mid, v["effective"]) for mid, v in
                ballot["votes"].items())),
        })

    def _effective_votes(self, ballot):
        """Re-run every vote() hook over all recorded votes (CCF: each
        submitted vote re-executes all ballots against current state).

        The hook return is bool-coerced exactly as vote() does, so the
        resolve-time tally always agrees with the journaled effective
        values (F237: the shipped resolvers use `is True` / `is False`,
        and an uncoerced truthy/falsy return silently corrupted the
        tally -- veto evasion, lost yes-votes).
        """
        btype = self.constitution.ballot_types[ballot["ballot_type"]]
        view = self._view(ballot)
        effective = {}
        for member_id, vote in ballot["votes"].items():
            member = self.constitution.members[member_id]
            effective[member_id] = bool(btype.vote_fn(member,
                                                      vote["decision"],
                                                      view))
        return effective

    # -- vote ------------------------------------------------------------
    def _refuse_vote(self, ballot_id, member_id, decision, signature,
                     code, detail):
        sig = bytes(signature) if isinstance(signature, (bytes,
                                                         bytearray)) else b""
        self.journal.append("ballot-vote-refused", {
            "ballot_id": ballot_id,
            "member_id": member_id,
            "decision": bool(decision) if isinstance(decision, bool)
            else None,
            "signature_sha256": hashlib.sha256(sig).hexdigest(),
            "code": code,
            "detail": detail,
        })

    def vote(self, ballot_id, member_id, decision, signature):
        """Cast a signed vote. Verifies membership then the Ed25519
        signature; runs the ballot type's vote() hook against read-only
        state; journals the vote. Refusals raise a BallotError with a
        machine code and are journaled as refused -- never counted."""
        ballot = self._ballots.get(ballot_id)
        if ballot is None:
            self._refuse_vote(ballot_id, member_id, decision, signature,
                              "ballot-unknown-ballot",
                              "no such ballot")
            raise BallotUnknownBallot("unknown ballot %r" % (ballot_id,))
        if ballot["status"] != OPEN:
            self._refuse_vote(ballot_id, member_id, decision, signature,
                              "ballot-late-vote",
                              "ballot already %s" % ballot["status"])
            raise BallotLateVote(
                "ballot %r already %s" % (ballot_id, ballot["status"]))
        member = self.constitution.members.get(member_id)
        if member is None:
            self._refuse_vote(ballot_id, member_id, decision, signature,
                              "ballot-not-member",
                              "voter is not a consortium member")
            raise BallotNotMember(
                "voter %r is not a consortium member" % (member_id,))
        if member_id in ballot["votes"]:
            self._refuse_vote(ballot_id, member_id, decision, signature,
                              "ballot-double-vote",
                              "member already voted")
            raise BallotDoubleVote(
                "member %r already voted on %r" % (member_id, ballot_id))
        if not isinstance(decision, bool):
            self._refuse_vote(ballot_id, member_id, decision, signature,
                              "ballot-malformed-proposal",
                              "decision must be boolean")
            raise BallotMalformedProposal("vote decision must be boolean")
        if isinstance(signature, str):
            try:
                signature = bytes.fromhex(signature)
            except ValueError:
                signature = b""
        envelope = vote_envelope(ballot_id, member_id, decision,
                                 ballot["payload_digest"])
        # ed25519.verify never raises: malformed is False, never an
        # exception (fail-closed for verifiers). Check the return --
        # never assume a verify() raises (wave-243 lesson).
        if not isinstance(signature, (bytes, bytearray)) or \
                ed25519.verify(member.pubkey, envelope,
                               bytes(signature)) is not True:
            self._refuse_vote(ballot_id, member_id, decision, signature,
                              "ballot-bad-signature",
                              "signature does not verify")
            raise BallotBadSignature(
                "vote signature from %r does not verify" % (member_id,))
        # Run the programmable vote() hook against read-only state.
        btype = self.constitution.ballot_types[ballot["ballot_type"]]
        try:
            effective = btype.vote_fn(member, decision,
                                      self._view(ballot))
        except Exception as e:
            self._refuse_vote(ballot_id, member_id, decision, signature,
                              "ballot-vote-hook-failed",
                              "vote hook failed: %s" %
                              type(e).__name__)
            raise BallotVoteHookFailed(
                "vote hook failed for %r: %s" % (member_id, e))
        effective = bool(effective)
        seq = len(ballot["votes"])
        ballot["votes"][member_id] = {
            "decision": decision,
            "effective": effective,
            "signature_sha256": hashlib.sha256(
                bytes(signature)).hexdigest(),
            "seq": seq,
        }
        self.journal.append("ballot-vote-recorded", {
            "ballot_id": ballot_id,
            "member_id": member_id,
            "decision": decision,
            "effective": effective,
            "signature_sha256": hashlib.sha256(
                bytes(signature)).hexdigest(),
            "seq": seq,
        })
        return {"ballot_id": ballot_id, "member_id": member_id,
                "decision": decision, "effective": effective}

    def votes(self, ballot_id):
        """Read-only copy of the recorded raw votes for a ballot."""
        ballot = self._ballots.get(ballot_id)
        if ballot is None:
            raise BallotUnknownBallot("unknown ballot %r" % (ballot_id,))
        return {mid: dict(v) for mid, v in ballot["votes"].items()}

    def payload_digest(self, ballot_id):
        ballot = self._ballots.get(ballot_id)
        if ballot is None:
            raise BallotUnknownBallot("unknown ballot %r" % (ballot_id,))
        return ballot["payload_digest"]

    # -- resolve (CCF resolve) -------------------------------------------
    def resolve(self, ballot_id):
        """Run the ballot type's resolve() over re-executed vote hooks.

        Returns ``{"ballot_id", "status", "note"}``. Terminal outcomes
        are journaled once and sticky; resolving an already-resolved
        ballot returns the stored outcome. ``rejected`` with note
        ``ballot-quorum-not-reached`` is the explicit no-silent-adoption
        outcome.
        """
        ballot = self._ballots.get(ballot_id)
        if ballot is None:
            raise BallotUnknownBallot("unknown ballot %r" % (ballot_id,))
        if ballot["status"] != OPEN:
            return dict(ballot["resolution"])
        btype = self.constitution.ballot_types[ballot["ballot_type"]]
        effective = self._effective_votes(ballot)
        eff_view = _types.MappingProxyType(dict(effective))
        snapshot = _types.MappingProxyType({
            "ballot_id": ballot["ballot_id"],
            "ballot_type": ballot["ballot_type"],
            "proposer": ballot["proposer"],
            "payload_digest": ballot["payload_digest"],
            "electorate": len(self.constitution.members),
            "members": _types.MappingProxyType({
                mid: _types.MappingProxyType(
                    {"role": m.role, "weight": m.weight})
                for mid, m in self.constitution.members.items()}),
        })
        try:
            status, note = btype.resolve_fn(snapshot, eff_view)
        except Exception as e:
            raise BallotVoteHookFailed(
                "resolve hook failed for %r: %s" % (ballot_id, e))
        if status not in (ADOPTED, REJECTED, OPEN):
            raise BallotVoteHookFailed(
                "resolve hook returned bad status %r" % (status,))
        outcome = {"ballot_id": ballot_id, "status": status,
                   "note": note or ""}
        if status != OPEN:
            ballot["status"] = status
            ballot["resolution"] = outcome
            self.journal.append("ballot-resolved", dict(outcome, **{
                "yes": sum(1 for v in effective.values() if v is True),
                "no": sum(1 for v in effective.values() if v is False),
                "electorate": len(self.constitution.members),
            }))
        return outcome

    # -- apply (CCF apply; state transition is caller-owned) -------------
    def apply(self, ballot_id):
        """Run the ballot type's on_adopt hook for an ADOPTED ballot and
        journal ``ballot-applied``. Refuses loudly on anything else:
        adoption is the only gate to application."""
        ballot = self._ballots.get(ballot_id)
        if ballot is None:
            raise BallotUnknownBallot("unknown ballot %r" % (ballot_id,))
        if ballot["status"] != ADOPTED:
            note = (ballot["resolution"] or {}).get("note", "")
            raise BallotQuorumNotReached(
                "ballot %r is %s (%s); only adopted ballots apply"
                % (ballot_id, ballot["status"], note or "no outcome"))
        btype = self.constitution.ballot_types[ballot["ballot_type"]]
        result = None
        if btype.on_adopt is not None:
            result = btype.on_adopt(_types.MappingProxyType({
                "ballot_id": ballot["ballot_id"],
                "payload_digest": ballot["payload_digest"],
            }))
        self.journal.append("ballot-applied", {
            "ballot_id": ballot_id,
            "result": result if isinstance(result, (str, int, float,
                                                    bool)) or result is None
            else repr(result)[:256],
        })
        return {"ballot_id": ballot_id, "status": "applied",
                "result": result}
