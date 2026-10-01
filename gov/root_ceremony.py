"""Threshold root ceremony: sigstore/root-signing ceremony discipline over
our CCF-style ballot governance. Wave-262 feature lane 3.

PATTERN LINEAGE: sigstore/root-signing
(https://github.com/sigstore/root-signing), **Apache-2.0** (license
verified from raw LICENSE bytes 2026-10-01 by the wave-261 prospecting
lane). Adapted, never vendored: the multi-party approval ceremony made
operational -- named keyholders, review-before-sign, fork-PR-style
signature collection (each signature references the exact ceremony
digest, no detached approvals), mandatory staged rehearsal, and the
routine (KMS/expiry) vs ceremonial (human/root-key) signing split.
The decision math (threshold of signed votes) is COMPOSED from
``gov/ballot_governance.py`` (wave-261), not duplicated: the execute
phase runs a ``threshold_approval`` ballot whose votes are the
keyholders' execution signatures.

A Ceremony is one root-key event (key generation, rotation, trust-root
pin change, recovery):

    propose -> review -> rehearse -> execute -> complete

- ``propose`` records the change description and the NEW KEY MATERIAL
  FINGERPRINT (sha256 hex of the new public key). NEVER the private
  key: proposals carrying private-key-shaped fields are refused with
  ``ceremony-private-key-material``.
- ``review`` collects Ed25519-signed review attestations from
  ``review_quorum`` keyholders, each attestation binding the keyholder
  id to the EXACT ceremony digest. A mismatched digest reference is
  ``ceremony-digest-mismatch`` (a detached approval); a bad signature
  is ``ceremony-bad-signature``.
- ``rehearse`` records a MANDATORY staged-rehearsal run in a scratch
  namespace proving the new root verifies end-to-end. The rehearsal
  record is digest-verified; any tamper, failed check, production
  namespace, or fingerprint drift is ``ceremony-rehearsal-forged``.
  The ceremony refuses to advance without a passing record
  (``ceremony-rehearsal-missing``).
- ``execute`` collects keyholder execution signatures through the
  composed ballot box: each signature references the exact ceremony
  digest (transitively, via the ballot payload digest). Execution
  without a threshold of yes-signatures is
  ``ceremony-quorum-not-reached``.
- ``complete`` supersedes the old root and journals the supersession.
  Completed ceremony ids are tombstoned: reuse is ``ceremony-replayed``.

Routine-vs-ceremonial split: routine operations (daily signing) use the
KMS/provider path via :func:`routine_sign`. Anything touching the root
key set REQUIRES the ceremony. :func:`is_ceremonial` fails closed:
unknown, empty, or non-string actions are ceremonial; only exact-match
routine ops are routine.

What this module is and is not:
- It is ceremony DISCIPLINE among named keyholders: quorum intent plus
  rehearsal evidence, hash-chained and journaled. It does NOT attest
  key custody: a compromised keyholder key signs as that keyholder,
  exactly as in root-signing, and hardware binding of keyholder keys
  is deployment-owned (YubiKeys, HSMs), not proven here.
- It records and enforces the DECISION, not the root swap: ``complete``
  journals the supersession; the actual key-set transition (updating
  the trust store) is the caller's responsibility, executed only after
  a completed ceremony.
- The rehearsal record proves a rehearsal RAN and PASSED in a scratch
  namespace against this ceremony's digest; it does not attest who ran
  it -- that binding is deployment trust.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json
import secrets

from gov import ballot_governance as bg
from gov import durable_journal
from gov import ed25519

__all__ = [
    "CeremonyError",
    "CeremonyUnknownCeremony",
    "CeremonyMalformedProposal",
    "CeremonyPrivateKeyMaterial",
    "CeremonyNotKeyholder",
    "CeremonyBadSignature",
    "CeremonyDigestMismatch",
    "CeremonyDoubleReview",
    "CeremonyPhaseViolation",
    "CeremonyRehearsalMissing",
    "CeremonyRehearsalForged",
    "CeremonyQuorumNotReached",
    "CeremonyReplayed",
    "CeremonyRoutinePathRefused",
    "CeremonyGovernor",
    "review_envelope",
    "make_rehearsal_record",
    "is_ceremonial",
    "routine_sign",
    "threshold_approval",
    "ROUTINE_ACTIONS",
    "CEREMONIAL_ACTIONS",
    "EVENT_TYPES",
    "PHASES",
]

#: Domain separation for review attestation envelopes.
_REVIEW_DOMAIN = b"root-ceremony-review/v1\x00"

#: Domain separation for the routine (KMS-path) signing envelope.
_ROUTINE_DOMAIN = b"root-ceremony-routine/v1\x00"

#: Ceremony phases, in legal transition order.
PHASES = ("proposed", "reviewed", "rehearsed", "executed", "completed")

#: Root-key event types a ceremony may govern.
EVENT_TYPES = ("key-generation", "rotation", "trust-root-pin-change",
               "recovery")

#: Exact-match routine operations allowed on the KMS path.
ROUTINE_ACTIONS = frozenset({
    "sign-daily",
    "resign-expiry",
    "expiry-resign",
    "attest-artifact",
    "timestamp-token",
    "log-checkpoint",
})

#: Known ceremonial actions (anything touching the root key set).
CEREMONIAL_ACTIONS = frozenset({
    "root-key-generate",
    "root-key-rotate",
    "trust-root-pin-change",
    "root-key-recover",
    "keyholder-add",
    "keyholder-remove",
    "threshold-change",
})

#: Substrings that force an action ceremonial (fail-closed heuristic).
_CEREMONIAL_TOKENS = ("root", "trust-root", "keyholder", "threshold",
                      "master-key")

#: Proposal field names that must never appear (private-key heuristic).
_FORBIDDEN_KEY_TOKENS = ("private_key", "privkey", "privatekey",
                         "private", "secret_key", "secret", "seed",
                         "mnemonic", "passphrase", "password")

#: Rehearsal namespaces must look like scratch/staging, never production.
_SCRATCH_PREFIXES = ("scratch/", "staging/")

_MAX_DESCRIPTION_BYTES = 4096


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


def _is_hex64(s):
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Errors: one class per machine code (decision_codes inventory idiom 1).
# ---------------------------------------------------------------------------

class CeremonyError(Exception):
    """Base: every root-ceremony refusal carries a machine ``code``."""


class CeremonyUnknownCeremony(CeremonyError):
    code = "ceremony-unknown-ceremony"


class CeremonyMalformedProposal(CeremonyError):
    code = "ceremony-malformed-proposal"


class CeremonyPrivateKeyMaterial(CeremonyError):
    code = "ceremony-private-key-material"


class CeremonyNotKeyholder(CeremonyError):
    code = "ceremony-not-keyholder"


class CeremonyBadSignature(CeremonyError):
    code = "ceremony-bad-signature"


class CeremonyDigestMismatch(CeremonyError):
    code = "ceremony-digest-mismatch"


class CeremonyDoubleReview(CeremonyError):
    code = "ceremony-double-review"


class CeremonyPhaseViolation(CeremonyError):
    code = "ceremony-phase-violation"


class CeremonyRehearsalMissing(CeremonyError):
    code = "ceremony-rehearsal-missing"


class CeremonyRehearsalForged(CeremonyError):
    code = "ceremony-rehearsal-forged"


class CeremonyQuorumNotReached(CeremonyError):
    code = "ceremony-quorum-not-reached"


class CeremonyReplayed(CeremonyError):
    code = "ceremony-replayed"


class CeremonyRoutinePathRefused(CeremonyError):
    code = "ceremony-routine-path-refused"


# ---------------------------------------------------------------------------
# Routine-vs-ceremonial classifier (fails closed).
# ---------------------------------------------------------------------------

def is_ceremonial(action):
    """Classify an action as requiring the ceremony (True) or allowed on
    the routine KMS path (False). FAILS CLOSED: unknown, empty, or
    non-string actions are ceremonial. Only exact-match routine ops are
    routine; anything root/keyholder/threshold-shaped is ceremonial."""
    if not isinstance(action, str) or not action:
        return True
    a = action.strip().lower()
    if not a:
        return True
    if a in ROUTINE_ACTIONS:
        return False
    if a in CEREMONIAL_ACTIONS:
        return True
    for tok in _CEREMONIAL_TOKENS:
        if tok in a:
            return True
    return True  # unknown action -> ceremonial (fail closed)


def routine_sign(action, payload, seed):
    """Sign on the routine (KMS/daily) path. Refuses
    ``ceremony-routine-path-refused`` for anything ceremonial -- root-key
    actions REQUIRE the ceremony. Returns the 64-byte Ed25519
    signature."""
    if is_ceremonial(action):
        raise CeremonyRoutinePathRefused(
            "action %r touches the root key set or is unknown; "
            "it requires the ceremony, not the routine path" % (action,))
    if not isinstance(payload, dict):
        raise CeremonyMalformedProposal("routine payload must be a dict")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise CeremonyMalformedProposal(
            "routine seed must be 32 raw bytes")
    try:
        payload_digest = _sha256_hex(_canonical(payload))
    except (TypeError, ValueError):
        raise CeremonyMalformedProposal(
            "routine payload is not JSON-canonicalizable")
    return ed25519.sign(bytes(seed), _ROUTINE_DOMAIN + _canonical({
        "action": action.strip().lower(),
        "payload_digest": payload_digest,
    }))


# ---------------------------------------------------------------------------
# Signed artifacts: review envelopes, rehearsal records.
# ---------------------------------------------------------------------------

def review_envelope(ceremony_id, keyholder_id, ceremony_digest):
    """Canonical signed bytes for a review attestation. Binds the
    keyholder identity to the EXACT ceremony digest -- a signature over
    a different digest is a detached approval and refuses."""
    return _REVIEW_DOMAIN + _canonical({
        "ceremony_id": ceremony_id,
        "keyholder_id": keyholder_id,
        "ceremony_digest": ceremony_digest,
    })


def make_rehearsal_record(ceremony_id, new_key_fingerprint, namespace,
                          checks):
    """Build a digest-verified rehearsal record. The deployment runs the
    staged rehearsal in a scratch namespace, then calls this to seal the
    record: any later tamper of a field breaks ``record_digest``. Every
    check must have passed; the namespace must be scratch/staging."""
    if not isinstance(checks, list) or not checks:
        raise CeremonyMalformedProposal(
            "rehearsal checks must be a non-empty list")
    sealed_checks = []
    for c in checks:
        if not isinstance(c, dict) or "name" not in c:
            raise CeremonyMalformedProposal(
                "rehearsal check needs a name")
        sealed_checks.append({"name": str(c["name"]),
                              "passed": bool(c.get("passed", False))})
    rec = {
        "ceremony_id": ceremony_id,
        "new_root_fingerprint": new_key_fingerprint,
        "namespace": namespace,
        "checks": sealed_checks,
    }
    rec["record_digest"] = _sha256_hex(_canonical(rec))
    return rec


def _verify_rehearsal_record(rec, ceremony_id, expected_fingerprint):
    """Verify a rehearsal record against the ceremony. Returns the
    record on success; raises CeremonyRehearsalForged on ANY defect:
    malformed, digest mismatch, ceremony-id drift, fingerprint drift,
    failed/unpassed checks, or a non-scratch namespace."""
    if not isinstance(rec, dict):
        raise CeremonyRehearsalForged("rehearsal record must be a dict")
    for key in ("ceremony_id", "new_root_fingerprint", "namespace",
                "checks", "record_digest"):
        if key not in rec:
            raise CeremonyRehearsalForged(
                "rehearsal record missing %r" % (key,))
    claimed = rec["record_digest"]
    body = {k: v for k, v in rec.items() if k != "record_digest"}
    if not isinstance(claimed, str) or \
            claimed != _sha256_hex(_canonical(body)):
        raise CeremonyRehearsalForged(
            "rehearsal record digest does not verify")
    if rec["ceremony_id"] != ceremony_id:
        raise CeremonyRehearsalForged(
            "rehearsal record is for another ceremony")
    if rec["new_root_fingerprint"] != expected_fingerprint:
        raise CeremonyRehearsalForged(
            "rehearsal fingerprint does not match the proposal")
    checks = rec["checks"]
    if not isinstance(checks, list) or not checks or not all(
            isinstance(c, dict) and c.get("passed") is True
            for c in checks):
        raise CeremonyRehearsalForged(
            "rehearsal checks did not all pass")
    ns = rec["namespace"]
    if not isinstance(ns, str) or not ns.startswith(
            _SCRATCH_PREFIXES):
        raise CeremonyRehearsalForged(
            "rehearsal ran outside a scratch namespace")
    return rec


# ---------------------------------------------------------------------------
# Threshold constitution for the execute phase (composed, not duplicated).
# ---------------------------------------------------------------------------

def threshold_approval(members, threshold):
    """A ballot_governance Constitution whose resolve adopts on a
    threshold of yes votes. The execute phase's keyholder signatures
    are collected as votes on this ballot: the CCF-style math
    (validate/resolve/apply, signed ledger-recorded votes) comes from
    ballot_governance; only the threshold rule is ceremony-specific."""
    members = list(members)
    if not isinstance(threshold, int) or not 1 <= threshold <= len(
            members):
        raise ValueError("threshold must be 1..%d" % len(members))

    def _resolve(ballot, votes):
        yes = sum(1 for v in votes.values() if v is True)
        if yes >= threshold:
            return (bg.ADOPTED, "threshold-met")
        if len(votes) >= ballot["electorate"]:
            # Electorate exhausted without threshold: explicit, never
            # silent adoption.
            return (bg.REJECTED, "ceremony-quorum-not-reached")
        return (bg.OPEN, "")

    return bg.Constitution(
        members={m.member_id: m for m in members},
        ballot_types={
            "threshold": bg.BallotType(
                name="threshold",
                vote_fn=lambda member, decision, view: bool(decision),
                resolve_fn=_resolve,
                description="threshold of yes votes adopts",
            ),
        },
    )


# ---------------------------------------------------------------------------
# The ceremony governor.
# ---------------------------------------------------------------------------

class CeremonyGovernor:
    """Runs root-key ceremonies for a fixed keyholder set, journaling
    every ceremony event to a hash-chained durable_journal. The execute
    phase's signature collection is delegated to a ballot_governance
    BallotBox sharing the same journal (one evidence stream)."""

    def __init__(self, members, journal_path):
        members = list(members)
        if not members:
            raise ValueError("governor needs at least one keyholder")
        for m in members:
            if not isinstance(m, bg.Member):
                raise ValueError("keyholders must be ballot_governance "
                                 "Members")
        self.keyholders = {m.member_id: m for m in members}
        self.journal = durable_journal.Journal(journal_path)
        self._ceremonies = {}
        self._completed = set()
        self._box = None  # built lazily; shares the journal
        self._replay_journal()

    # -- journal replay ------------------------------------------------
    def _replay_journal(self):
        for rec in self.journal.records:
            body = rec["body"]
            rtype = rec["type"]
            if rtype == "ceremony-proposed":
                self._ceremonies[body["ceremony_id"]] = {
                    "ceremony_id": body["ceremony_id"],
                    "event_type": body["event_type"],
                    "change_description": body["change_description"],
                    "new_key_fingerprint": body[
                        "new_key_fingerprint"],
                    "old_root_fingerprint": body.get(
                        "old_root_fingerprint"),
                    "proposer": body["proposer"],
                    "threshold": body["threshold"],
                    "review_quorum": body["review_quorum"],
                    "ceremony_digest": body["ceremony_digest"],
                    "phase": "proposed",
                    "reviews": [],
                    "rehearsal": None,
                    "execution_ballot": None,
                }
            elif rtype == "ceremony-review-recorded":
                c = self._ceremonies.get(body["ceremony_id"])
                if c is not None and body["keyholder_id"] not in \
                        [r["keyholder_id"] for r in c["reviews"]]:
                    c["reviews"].append({
                        "keyholder_id": body["keyholder_id"],
                        "signature_sha256": body["signature_sha256"],
                    })
            elif rtype == "ceremony-reviewed":
                c = self._ceremonies.get(body["ceremony_id"])
                if c is not None:
                    c["phase"] = "reviewed"
            elif rtype == "ceremony-rehearsal-recorded":
                c = self._ceremonies.get(body["ceremony_id"])
                if c is not None:
                    c["rehearsal"] = body["record"]
            elif rtype == "ceremony-rehearsed":
                c = self._ceremonies.get(body["ceremony_id"])
                if c is not None:
                    c["phase"] = "rehearsed"
            elif rtype == "ceremony-execution-opened":
                c = self._ceremonies.get(body["ceremony_id"])
                if c is not None:
                    c["execution_ballot"] = body["ballot_id"]
            elif rtype == "ceremony-executed":
                c = self._ceremonies.get(body["ceremony_id"])
                if c is not None:
                    c["phase"] = "executed"
            elif rtype == "ceremony-completed":
                c = self._ceremonies.get(body["ceremony_id"])
                if c is not None:
                    c["phase"] = "completed"
                self._completed.add(body["ceremony_id"])

    def _seat_box(self, ceremony):
        """Seat a threshold ballot box for this ceremony's execute
        phase (fresh constitution with this ceremony's threshold)."""
        self._box = bg.BallotBox(
            threshold_approval(list(self.keyholders.values()),
                               ceremony["threshold"]),
            self.journal.path)

    # -- lookup helpers -------------------------------------------------
    def _get(self, ceremony_id):
        c = self._ceremonies.get(ceremony_id)
        if c is None:
            raise CeremonyUnknownCeremony(
                "no ceremony %r" % (ceremony_id,))
        return c

    def _live(self, ceremony_id):
        """A ceremony that exists and is not completed. Completed
        ceremonies are tombstoned: ANY mutation is a replay."""
        c = self._get(ceremony_id)
        if c["phase"] == "completed" or ceremony_id in self._completed:
            raise CeremonyReplayed(
                "ceremony %r is completed; id reuse is refused"
                % (ceremony_id,))
        return c

    @staticmethod
    def _scan_private_key(payload):
        """Heuristic: refuse proposals whose field NAMES look like
        private-key material. Documented heuristic, not a guarantee --
        the ceremony moves fingerprints, never private keys."""
        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    kl = str(k).lower()
                    if any(tok in kl for tok in _FORBIDDEN_KEY_TOKENS):
                        return k
                    hit = walk(v)
                    if hit:
                        return hit
            elif isinstance(obj, (list, tuple)):
                for v in obj:
                    hit = walk(v)
                    if hit:
                        return hit
            return None
        return walk(payload)

    # -- propose ---------------------------------------------------------
    def propose(self, event_type, change_description,
                new_key_fingerprint, proposer, threshold=3,
                review_quorum=2, old_root_fingerprint=None,
                ceremony_id=None, **extra):
        """Open a ceremony (phase: proposed). ``extra`` fields ride in
        the proposal and are private-key scanned like everything else."""
        proposal = {
            "event_type": event_type,
            "change_description": change_description,
            "new_key_fingerprint": new_key_fingerprint,
            "proposer": proposer,
            "threshold": threshold,
            "review_quorum": review_quorum,
            "old_root_fingerprint": old_root_fingerprint,
        }
        proposal.update(extra)
        if ceremony_id is not None:
            if not isinstance(ceremony_id, str) or not ceremony_id:
                raise CeremonyMalformedProposal(
                    "ceremony_id must be a non-empty string")
            if ceremony_id in self._completed:
                raise CeremonyReplayed(
                    "ceremony id %r is already completed" % (ceremony_id,))
            if ceremony_id in self._ceremonies:
                raise CeremonyMalformedProposal(
                    "ceremony id %r is already open" % (ceremony_id,))
        if event_type not in EVENT_TYPES:
            raise CeremonyMalformedProposal(
                "unknown event type %r" % (event_type,))
        if not isinstance(change_description, str) or not \
                change_description.strip() or \
                len(change_description.encode("utf-8")) > \
                _MAX_DESCRIPTION_BYTES:
            raise CeremonyMalformedProposal(
                "change_description must be a non-empty string <= %d "
                "bytes" % _MAX_DESCRIPTION_BYTES)
        if not _is_hex64(new_key_fingerprint):
            raise CeremonyMalformedProposal(
                "new_key_fingerprint must be 64 hex chars")
        if old_root_fingerprint is not None and not _is_hex64(
                old_root_fingerprint):
            raise CeremonyMalformedProposal(
                "old_root_fingerprint must be 64 hex chars or null")
        if proposer not in self.keyholders:
            raise CeremonyNotKeyholder(
                "proposer %r is not a named keyholder" % (proposer,))
        if not isinstance(threshold, int) or not 1 <= threshold <= len(
                self.keyholders):
            raise CeremonyMalformedProposal(
                "threshold must be 1..%d" % len(self.keyholders))
        if not isinstance(review_quorum, int) or not 1 <= \
                review_quorum <= len(self.keyholders):
            raise CeremonyMalformedProposal(
                "review_quorum must be 1..%d" % len(self.keyholders))
        bad = self._scan_private_key(proposal)
        if bad is not None:
            raise CeremonyPrivateKeyMaterial(
                "proposal field %r looks like private-key material; "
                "ceremonies move fingerprints, never private keys"
                % (bad,))
        try:
            _canonical(proposal)
        except (TypeError, ValueError):
            raise CeremonyMalformedProposal(
                "proposal is not JSON-canonicalizable")
        if ceremony_id is None:
            ceremony_id = "crm-" + secrets.token_hex(8)
            while ceremony_id in self._ceremonies or \
                    ceremony_id in self._completed:
                ceremony_id = "crm-" + secrets.token_hex(8)
        digest = _sha256_hex(_canonical({
            "ceremony_id": ceremony_id,
            "event_type": event_type,
            "change_description": change_description,
            "new_key_fingerprint": new_key_fingerprint,
            "old_root_fingerprint": old_root_fingerprint,
            "proposer": proposer,
            "threshold": threshold,
            "review_quorum": review_quorum,
        }))
        self.journal.append("ceremony-proposed", {
            "ceremony_id": ceremony_id,
            "event_type": event_type,
            "change_description": change_description,
            "new_key_fingerprint": new_key_fingerprint,
            "old_root_fingerprint": old_root_fingerprint,
            "proposer": proposer,
            "threshold": threshold,
            "review_quorum": review_quorum,
            "ceremony_digest": digest,
            "extra_keys": sorted(str(k) for k in extra),
        })
        self._ceremonies[ceremony_id] = {
            "ceremony_id": ceremony_id,
            "event_type": event_type,
            "change_description": change_description,
            "new_key_fingerprint": new_key_fingerprint,
            "old_root_fingerprint": old_root_fingerprint,
            "proposer": proposer,
            "threshold": threshold,
            "review_quorum": review_quorum,
            "ceremony_digest": digest,
            "phase": "proposed",
            "reviews": [],
            "rehearsal": None,
            "execution_ballot": None,
        }
        return ceremony_id

    def ceremony_digest(self, ceremony_id):
        return self._get(ceremony_id)["ceremony_digest"]

    def status(self, ceremony_id):
        c = self._get(ceremony_id)
        return {
            "ceremony_id": c["ceremony_id"],
            "event_type": c["event_type"],
            "phase": c["phase"],
            "threshold": c["threshold"],
            "review_quorum": c["review_quorum"],
            "ceremony_digest": c["ceremony_digest"],
            "reviews": [r["keyholder_id"] for r in c["reviews"]],
            "rehearsal": (dict(c["rehearsal"])
                           if c["rehearsal"] else None),
            "execution_ballot": c["execution_ballot"],
        }

    # -- review ----------------------------------------------------------
    def record_review(self, ceremony_id, keyholder_id, attestation):
        """Record one keyholder's signed review attestation. The
        attestation must reference the EXACT ceremony digest; reaching
        ``review_quorum`` advances the phase to reviewed."""
        c = self._live(ceremony_id)
        if c["phase"] not in ("proposed", "reviewed"):
            raise CeremonyPhaseViolation(
                "reviews are recorded in phase proposed/reviewed, not "
                "%s" % c["phase"])
        member = self.keyholders.get(keyholder_id)
        if member is None:
            raise CeremonyNotKeyholder(
                "%r is not a named keyholder" % (keyholder_id,))
        if keyholder_id in [r["keyholder_id"] for r in c["reviews"]]:
            raise CeremonyDoubleReview(
                "%r already reviewed %r" % (keyholder_id, ceremony_id))
        if not isinstance(attestation, dict):
            raise CeremonyMalformedProposal(
                "attestation must be a dict")
        claimed = attestation.get("ceremony_digest")
        expected = c["ceremony_digest"]
        if claimed != expected:
            # A signature over a different digest is a DETACHED
            # approval: refused before any crypto, never counted.
            raise CeremonyDigestMismatch(
                "attestation references digest %r, ceremony %r is %r"
                % (claimed, ceremony_id, expected))
        sig = attestation.get("signature")
        if isinstance(sig, str):
            try:
                sig = bytes.fromhex(sig)
            except ValueError:
                sig = b""
        envelope = review_envelope(ceremony_id, keyholder_id, expected)
        # ed25519.verify never raises: malformed is False, never an
        # exception (fail-closed for verifiers). Check the return --
        # never assume a verify() raises (wave-243 lesson).
        if not isinstance(sig, (bytes, bytearray)) or \
                ed25519.verify(member.pubkey, envelope,
                               bytes(sig)) is not True:
            raise CeremonyBadSignature(
                "review attestation from %r does not verify"
                % (keyholder_id,))
        c["reviews"].append({
            "keyholder_id": keyholder_id,
            "signature_sha256": _sha256_hex(bytes(sig)),
        })
        self.journal.append("ceremony-review-recorded", {
            "ceremony_id": ceremony_id,
            "keyholder_id": keyholder_id,
            "ceremony_digest": expected,
            "signature_sha256": _sha256_hex(bytes(sig)),
        })
        if len(c["reviews"]) >= c["review_quorum"] and \
                c["phase"] == "proposed":
            c["phase"] = "reviewed"
            self.journal.append("ceremony-reviewed", {
                "ceremony_id": ceremony_id,
                "review_count": len(c["reviews"]),
            })
        return {"ceremony_id": ceremony_id,
                "keyholder_id": keyholder_id,
                "phase": c["phase"]}

    # -- rehearse ---------------------------------------------------------
    def record_rehearsal(self, ceremony_id, rehearsal_record):
        """Record the mandatory staged-rehearsal evidence. The record
        must verify (digest, ceremony binding, all checks passed,
        scratch namespace, fingerprint match); verification failure is
        ceremony-rehearsal-forged."""
        c = self._live(ceremony_id)
        if c["phase"] != "reviewed":
            raise CeremonyPhaseViolation(
                "rehearsal is recorded in phase reviewed, not %s"
                % c["phase"])
        verified = _verify_rehearsal_record(
            rehearsal_record, ceremony_id, c["new_key_fingerprint"])
        c["rehearsal"] = dict(verified)
        self.journal.append("ceremony-rehearsal-recorded", {
            "ceremony_id": ceremony_id,
            "record": dict(verified),
        })
        c["phase"] = "rehearsed"
        self.journal.append("ceremony-rehearsed", {
            "ceremony_id": ceremony_id,
            "namespace": verified["namespace"],
            "check_count": len(verified["checks"]),
        })
        return {"ceremony_id": ceremony_id, "phase": "rehearsed"}

    # -- execute -----------------------------------------------------------
    def open_execution(self, ceremony_id):
        """Open the execution ballot (threshold signature collection).
        Requires a passing rehearsal record: the ceremony refuses to
        advance without rehearsal evidence."""
        c = self._live(ceremony_id)
        if c["phase"] in ("proposed", "reviewed"):
            raise CeremonyRehearsalMissing(
                "no passing rehearsal record for %r; rehearse first"
                % (ceremony_id,))
        if c["phase"] != "rehearsed":
            raise CeremonyPhaseViolation(
                "execution opens in phase rehearsed, not %s"
                % c["phase"])
        if c["execution_ballot"] is not None:
            raise CeremonyPhaseViolation(
                "execution ballot already open for %r" % (ceremony_id,))
        self._seat_box(c)
        payload = {
            "action": "ceremony-execute",
            "ceremony_id": ceremony_id,
            "ceremony_digest": c["ceremony_digest"],
            "new_key_fingerprint": c["new_key_fingerprint"],
        }
        ballot_id = self._box.propose("threshold", payload,
                                      c["proposer"])
        c["execution_ballot"] = ballot_id
        self.journal.append("ceremony-execution-opened", {
            "ceremony_id": ceremony_id,
            "ballot_id": ballot_id,
            "ceremony_digest": c["ceremony_digest"],
            "payload_digest": self._box.payload_digest(ballot_id),
        })
        return {"ballot_id": ballot_id,
                "ceremony_id": ceremony_id,
                "ceremony_digest": c["ceremony_digest"],
                "payload_digest": self._box.payload_digest(ballot_id)}

    def execution_ballot(self, ceremony_id):
        c = self._get(ceremony_id)
        ballot_id = c["execution_ballot"]
        if ballot_id is None:
            raise CeremonyPhaseViolation(
                "no execution ballot open for %r" % (ceremony_id,))
        self._seat_box(c)
        return {"ballot_id": ballot_id,
                "ceremony_id": ceremony_id,
                "ceremony_digest": c["ceremony_digest"],
                "payload_digest": self._box.payload_digest(ballot_id)}

    def sign_execution(self, ceremony_id, keyholder_id, decision,
                       signature):
        """Collect one keyholder's execution signature through the
        composed ballot box. Digest-mismatched signatures refuse as
        ballot-bad-signature (the box recomputes the envelope from its
        own payload, which binds the exact ceremony digest)."""
        c = self._live(ceremony_id)
        ballot_id = c["execution_ballot"]
        if ballot_id is None:
            raise CeremonyPhaseViolation(
                "no execution ballot open for %r" % (ceremony_id,))
        self._seat_box(c)
        return self._box.vote(ballot_id, keyholder_id, decision,
                              signature)

    def resolve_execution(self, ceremony_id):
        """Resolve the execution ballot. Adoption advances to executed;
        anything else -- still open, or rejected -- refuses
        ceremony-quorum-not-reached: the ceremony never executes
        without a threshold of signatures."""
        c = self._live(ceremony_id)
        ballot_id = c["execution_ballot"]
        if ballot_id is None or c["phase"] != "rehearsed":
            raise CeremonyPhaseViolation(
                "nothing to resolve for %r in phase %s"
                % (ceremony_id, c["phase"]))
        self._seat_box(c)
        outcome = self._box.resolve(ballot_id)
        if outcome["status"] != bg.ADOPTED:
            raise CeremonyQuorumNotReached(
                "execution ballot %r is %s (%s); ceremony %r refuses "
                "to execute without a threshold of signatures"
                % (ballot_id, outcome["status"],
                   outcome.get("note", ""), ceremony_id))
        c["phase"] = "executed"
        self.journal.append("ceremony-executed", {
            "ceremony_id": ceremony_id,
            "ballot_id": ballot_id,
            "note": outcome.get("note", ""),
        })
        return {"ceremony_id": ceremony_id, "status": "adopted",
                "ballot_id": ballot_id}

    # -- complete ------------------------------------------------------------
    def complete(self, ceremony_id):
        """Supersede the old root and close the ceremony. The
        supersession is journaled; the ceremony id is tombstoned so any
        reuse refuses ceremony-replayed."""
        c = self._live(ceremony_id)
        if c["phase"] != "executed":
            raise CeremonyPhaseViolation(
                "complete runs in phase executed, not %s" % c["phase"])
        supersession = {
            "ceremony_id": ceremony_id,
            "event_type": c["event_type"],
            "old_root_fingerprint": c["old_root_fingerprint"],
            "new_root_fingerprint": c["new_key_fingerprint"],
            "threshold": c["threshold"],
            "review_count": len(c["reviews"]),
        }
        self.journal.append("ceremony-completed", dict(supersession))
        c["phase"] = "completed"
        self._completed.add(ceremony_id)
        return supersession
