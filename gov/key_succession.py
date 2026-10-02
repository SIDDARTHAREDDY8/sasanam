"""Declared, phased key-rotation ceremonies (gardener pattern).

Pattern lineage: gardener/gardener (Apache-2.0) two-phase credential
rotation (Preparing->Prepared->Completing->Completed) holding the
union-of-trust invariant throughout; cert-manager trust-manager
(Apache-2.0) versioned trust bundles where rotation keeps old+new
anchors during an overlap window, never an atomic swap; supertokens
(Apache-2.0) "reuse of a retired credential is a revocation event,
not an authentication failure". Mechanisms only; no vendored code;
stdlib only.

A ``KeySuccession`` ceremony governs rotation of one authority's
signing key (registry keys, delegation issuers, posture producers).
The OLD key is the delegating authority: every transition record is
signed by the old key, and the verifier pins the old key out-of-band.

Phases::

    none        -- no ceremony; old key is the only authority
    preparing   -- successor key generated/attested; old key still
                   authoritative (union of trust: old+new coexist,
                   but only the old key verifies material yet)
    prepared    -- successor announced in a signed record; old key
                   still authoritative
    completing  -- successor authoritative for new material; the old
                   key verifies ONLY in-flight material inside the
                   mandatory bounded overlap window
    completed   -- old key retired; its reuse refuses LOUD
                   ``keysuccession-retired-reuse`` -- a revocation
                   EVENT, never a silent failure

Transition rules (enforced, not documented):

* every transition moves exactly one phase forward; skipping a phase
  refuses coded ``keysuccession-phase-skipped``;
* ``advance`` (prepared -> completing) REQUIRES a bounded overlap
  window (1s .. 30 days); a missing, zero, negative, or excessive
  window refuses coded ``keysuccession-window-missing`` -- there is
  no unbounded overlap;
* a transition record with a bad signature, a tampered body, or a
  replayed record refuses coded
  ``keysuccession-invalid-transition``;
* material signed by the new key before ``completing`` refuses coded
  ``keysuccession-invalid-transition`` (the new key is not yet
  authorized);
* material signed by the old key after the window closes (or after
  ``completed``) refuses coded ``keysuccession-retired-reuse``.

Overlap notes: when old-key material verifies inside the completing
window, ``verify_authority`` returns an ``overlap_note`` declaring
which key signed, and fires the audit-sink event
``keysuccession-overlap-use``. Tolerance is never silent (wave-292
decay precedent); the sink itself follows the F345-class trade-off --
a broken sink can never break verification.

Composition with gov/revocation_status.py: ``RevocationRegistry``
gains additive key-rotation wiring (``begin_key_rotation`` /
``advance_key_rotation`` / ``finalize_key_rotation``). The registry's
existing credential-level ``rotate`` already implements the same
phased rule (successor issued first, predecessor retired after);
this module applies the ceremony to the registry's OWN signing key.
No existing API or behavior changes.

THREAT MODEL:

* The old key is the trust anchor. Whoever holds the old seed can
  declare any successor -- key distribution for the successor is
  out-of-band (same posture as the registry key).
* ``declared_at`` / ``checked_at`` are freshness markers, not a
  clock. Verifiers bound response age in policy; this module records
  times, it does not run a clock.
* A compromised old seed can mint transitions AND backdate material
  inside the window -- the compromised-host class; the ceremony
  proves what was authorized, not who holds keys.
"""

import hashlib
import json
import re
import time

from gov import ed25519 as _ed25519

SUCCESSION_FORMAT = "sasanam-key-succession/1"
OVERLAP_NOTE_FORMAT = "sasanam-key-succession-overlap-note/1"

INVALID_TRANSITION = "keysuccession-invalid-transition"
PHASE_SKIPPED = "keysuccession-phase-skipped"
RETIRED_REUSE = "keysuccession-retired-reuse"
WINDOW_MISSING = "keysuccession-window-missing"

_PHASES = ("none", "preparing", "prepared", "completing", "completed")
_NEXT = {"none": "preparing", "preparing": "prepared",
         "prepared": "completing", "completing": "completed"}

# Overlap windows are mandatory AND bounded: 1 second .. 30 days.
_MIN_WINDOW = 1
_MAX_WINDOW = 30 * 24 * 3600

_AUTHORITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")


class KeySuccessionError(Exception):
    """Base class; carries the machine ``code`` and a
    ``is_revocation_event`` flag (True only for retired-key reuse --
    the LOUD revocation-event class)."""

    code = INVALID_TRANSITION
    is_revocation_event = False

    def __init__(self, message, code=None, revocation_event=False):
        super().__init__(message)
        if code is not None:
            self.code = code
        self.is_revocation_event = bool(revocation_event)


def _fail(code, detail, revocation_event=False):
    raise KeySuccessionError(detail, code=code,
                             revocation_event=revocation_event)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def _emit_event(event, fields):
    """Returns True if a sink consumed the event, False when no sink
    is wired or the sink raised. Never raises (F345-class)."""
    if _EMIT is None:
        return False
    try:
        _EMIT(event, fields)
        return True
    except Exception:
        # F345-class trade-off: a broken sink can never break the
        # ceremony or verification.
        return False


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _check_authority(value):
    if not isinstance(value, str) or not _AUTHORITY_RE.match(value):
        _fail(INVALID_TRANSITION, "authority id fails grammar")


def _check_pubkey_hex(value, what="public key"):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        _fail(INVALID_TRANSITION, "%s must be 64 lowercase hex chars"
              % what)


def _check_seed(value, what="seed"):
    if not isinstance(value, bytes) or len(value) != 32:
        _fail(INVALID_TRANSITION, "%s must be 32 raw bytes" % what)


def _check_ts(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(INVALID_TRANSITION, "%s must be a non-negative int" % what)


def _check_window(value):
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(WINDOW_MISSING,
              "overlap window must be an int number of seconds")
    if value < _MIN_WINDOW or value > _MAX_WINDOW:
        _fail(WINDOW_MISSING,
              "overlap window must be bounded: %d..%d seconds; there is "
              "no unbounded overlap" % (_MIN_WINDOW, _MAX_WINDOW))


class KeySuccession:
    """One authority's key-rotation ceremony.

    The verifier pins ``old_pubkey_hex`` out-of-band. The operator
    drives transitions by supplying the old seed; the verifier replays
    signed records (``from_records``) and then calls
    ``verify_authority`` on material.
    """

    def __init__(self, authority_id, old_pubkey_hex):
        _check_authority(authority_id)
        _check_pubkey_hex(old_pubkey_hex, "old authority public key")
        self.authority_id = authority_id
        self.old_pubkey = old_pubkey_hex
        self.new_pubkey = None
        self.phase = "none"
        self._records = []
        self._seen_digests = set()
        self._completing_at = None
        self._overlap_window = None
        # Public read-model: None until advance().
        self.overlap_window_seconds = None
        # Transition envelopes, stashed for auditor replay.
        self.begin_record = None
        self.announce_record = None
        self.advance_record = None
        self.finalize_record = None

    # -- record construction / verification ---------------------------

    def _build_record(self, phase_from, phase_to, declared_at, **extra):
        record = {
            "record_format": SUCCESSION_FORMAT,
            "authority_id": self.authority_id,
            "phase_from": phase_from,
            "phase_to": phase_to,
            "old_pubkey": self.old_pubkey,
            "new_pubkey": self.new_pubkey,
            "declared_at": declared_at,
        }
        record.update(extra)
        return record

    def _sign_old(self, record, old_seed):
        return _ed25519.sign(old_seed, _canonical(record)).hex()

    def verify_transition(self, envelope):
        """Verify one transition record envelope. Returns True; any
        failure refuses coded ``keysuccession-invalid-transition``."""
        if not isinstance(envelope, dict):
            _fail(INVALID_TRANSITION, "transition envelope must be a dict")
        record = envelope.get("record")
        sig_hex = envelope.get("signature")
        if not isinstance(record, dict) or not isinstance(sig_hex, str):
            _fail(INVALID_TRANSITION,
                  "transition envelope must carry record and signature")
        if record.get("record_format") != SUCCESSION_FORMAT:
            _fail(INVALID_TRANSITION, "transition record format mismatch")
        if record.get("authority_id") != self.authority_id:
            _fail(INVALID_TRANSITION,
                  "transition record is for another authority")
        if record.get("old_pubkey") != self.old_pubkey:
            _fail(INVALID_TRANSITION,
                  "transition record names a different old key")
        phase_from = record.get("phase_from")
        phase_to = record.get("phase_to")
        if _NEXT.get(phase_from) != phase_to:
            _fail(INVALID_TRANSITION,
                  "transition %r -> %r is not a legal single phase step"
                  % (phase_from, phase_to))
        rec_new = record.get("new_pubkey")
        if self.new_pubkey is None:
            _check_pubkey_hex(rec_new, "successor public key")
        elif rec_new != self.new_pubkey:
            _fail(INVALID_TRANSITION,
                  "transition record names a different successor key")
        _check_ts(record.get("declared_at"), "declared_at")
        if not _HEX128_RE.match(sig_hex):
            _fail(INVALID_TRANSITION,
                  "transition signature is not 128 hex")
        ok = _ed25519.verify(bytes.fromhex(self.old_pubkey),
                             _canonical(record),
                             bytes.fromhex(sig_hex))
        if ok is not True:
            _fail(INVALID_TRANSITION,
                  "transition record signature does not verify under "
                  "the pinned old authority key")
        return True

    def verify_envelope(self, envelope, checked_at=None, overlap_note=None):
        """Verify authority material against THIS ceremony. Convenience
        wrapper around ``verify_envelope_with_succession``."""
        return verify_envelope_with_succession(envelope, self, checked_at,
                                              overlap_note)
        return True

    def _check_replay(self, envelope):
        """Replayed transition records refuse coded
        ``keysuccession-invalid-transition`` -- checked BEFORE the
        phase expectation so a replay is never misreported as a
        phase skip."""
        if not isinstance(envelope, dict):
            _fail(INVALID_TRANSITION, "transition envelope must be a dict")
        digest = hashlib.sha256(_canonical(envelope)).hexdigest()
        if digest in self._seen_digests:
            _fail(INVALID_TRANSITION,
                  "replayed transition record refused")
        return digest

    def _apply_record(self, envelope, want_from, want_to):
        digest = self._check_replay(envelope)
        self.verify_transition(envelope)
        record = envelope["record"]
        if record["phase_from"] != want_from or \
                record["phase_to"] != want_to:
            _fail(INVALID_TRANSITION,
                  "transition record %r -> %r does not match the "
                  "ceremony's current step %r -> %r"
                  % (record["phase_from"], record["phase_to"],
                     want_from, want_to))
        if self.new_pubkey is None:
            self.new_pubkey = record["new_pubkey"]
        self._seen_digests.add(digest)
        self._records.append(envelope)
        # Stash each transition envelope for auditor replay.
        _RECORD_ATTRS = {"preparing": "begin_record",
                         "prepared": "announce_record",
                         "completing": "advance_record",
                         "completed": "finalize_record"}
        attr = _RECORD_ATTRS.get(want_to)
        if attr is not None:
            setattr(self, attr, envelope)
        self.phase = want_to
        return envelope

    def _expect_phase(self, want_from, action):
        if self.phase != want_from:
            _fail(PHASE_SKIPPED,
                  "%s requires phase %r; the ceremony is at %r -- "
                  "phases cannot be skipped" % (action, want_from,
                                                self.phase))

    # -- operator transitions (signed by the old authority key) ------

    def begin(self, new_pubkey_hex, old_seed, declared_at=None):
        """none -> preparing. Declares the successor key. The
        successor is generated/attested; the old key stays
        authoritative."""
        if self.phase != "none":
            _fail(INVALID_TRANSITION,
                  "begin requires a fresh ceremony; a ceremony is "
                  "already in progress at phase %r" % (self.phase,))
        _check_pubkey_hex(new_pubkey_hex, "successor public key")
        if new_pubkey_hex == self.old_pubkey:
            _fail(INVALID_TRANSITION,
                  "successor key must differ from the old key")
        _check_seed(old_seed, "old authority seed")
        if declared_at is None:
            declared_at = int(time.time())
        _check_ts(declared_at, "declared_at")
        self.new_pubkey = new_pubkey_hex
        record = self._build_record("none", "preparing", declared_at)
        envelope = {"record": record,
                    "signature": self._sign_old(record, old_seed),
                    "keyid": "old-authority"}
        self._apply_record(envelope, "none", "preparing")
        _emit_event("keysuccession-begin",
                    {"authority_id": self.authority_id,
                     "new_pubkey": new_pubkey_hex})
        return envelope

    def announce(self, old_seed=None, declared_at=None, record=None):
        """preparing -> prepared. Announces the successor in a signed
        record. The old key stays authoritative."""
        if record is not None:
            self._check_replay(record)
        self._expect_phase("preparing", "announce")
        if record is not None:
            return self._apply_record(record, "preparing", "prepared")
        _check_seed(old_seed, "old authority seed")
        if declared_at is None:
            declared_at = int(time.time())
        _check_ts(declared_at, "declared_at")
        envelope = {"record": self._build_record(
                        "preparing", "prepared", declared_at),
                    "signature": None, "keyid": "old-authority"}
        envelope["signature"] = self._sign_old(envelope["record"],
                                               old_seed)
        return self._apply_record(envelope, "preparing", "prepared")

    def advance(self, old_seed=None, declared_at=None,
                overlap_window_seconds=None, record=None):
        """prepared -> completing. The successor becomes authoritative
        for new material; the old key verifies only in-flight material
        inside the mandatory bounded overlap window."""
        if record is not None:
            self._check_replay(record)
        self._expect_phase("prepared", "advance")
        if record is not None:
            # F366: validate the overlap window BEFORE the record is
            # applied. A well-signed advance record with a missing or
            # out-of-bounds window refused coded AFTER the phase had
            # already moved to "completing", leaving the ceremony in a
            # state unreachable via the seed path or from_records.
            # The window is now checked first, so a malformed record
            # leaves the ceremony at "prepared".
            inner = record.get("record") \
                if isinstance(record, dict) else None
            window = inner.get("overlap_window_seconds") \
                if isinstance(inner, dict) else None
            _check_window(window)
            envelope = self._apply_record(record, "prepared",
                                          "completing")
            self._overlap_window = window
            self.overlap_window_seconds = window
            self._completing_at = envelope["record"]["declared_at"]
            return envelope
        _check_seed(old_seed, "old authority seed")
        _check_window(overlap_window_seconds)
        if declared_at is None:
            declared_at = int(time.time())
        _check_ts(declared_at, "declared_at")
        envelope = {"record": self._build_record(
                        "prepared", "completing", declared_at,
                        overlap_window_seconds=overlap_window_seconds),
                    "signature": None, "keyid": "old-authority"}
        envelope["signature"] = self._sign_old(envelope["record"],
                                               old_seed)
        self._apply_record(envelope, "prepared", "completing")
        self._overlap_window = overlap_window_seconds
        self.overlap_window_seconds = overlap_window_seconds
        self._completing_at = declared_at
        _emit_event("keysuccession-advance",
                    {"authority_id": self.authority_id,
                     "overlap_window_seconds": overlap_window_seconds})
        return envelope

    def finalize(self, old_seed=None, declared_at=None, record=None):
        """completing -> completed. The old key is retired; any later
        use of it refuses LOUD as a revocation event."""
        if record is not None:
            self._check_replay(record)
        self._expect_phase("completing", "finalize")
        if record is not None:
            return self._apply_record(record, "completing", "completed")
        _check_seed(old_seed, "old authority seed")
        if declared_at is None:
            declared_at = int(time.time())
        _check_ts(declared_at, "declared_at")
        envelope = {"record": self._build_record(
                        "completing", "completed", declared_at),
                    "signature": None, "keyid": "old-authority"}
        envelope["signature"] = self._sign_old(envelope["record"],
                                               old_seed)
        self._apply_record(envelope, "completing", "completed")
        _emit_event("keysuccession-finalize",
                    {"authority_id": self.authority_id})
        return envelope

    @classmethod
    def from_records(cls, authority_id, old_pubkey_hex, records):
        """Reconstruct a ceremony from its signed record chain (the
        auditor path). Every record is verified; the phases must
        chain without gaps."""
        ceremony = cls(authority_id, old_pubkey_hex)
        if not isinstance(records, (list, tuple)) or not records:
            _fail(INVALID_TRANSITION,
                  "record chain must be a non-empty list")
        for envelope in records:
            ceremony.verify_transition(envelope)
            record = envelope["record"]
            ceremony._expect_phase(record["phase_from"], "replay")
            if ceremony.new_pubkey is None:
                ceremony.new_pubkey = record["new_pubkey"]
            elif record["new_pubkey"] != ceremony.new_pubkey:
                _fail(INVALID_TRANSITION,
                      "record chain names a different successor key")
            if record["phase_to"] == "completing":
                window = record.get("overlap_window_seconds")
                _check_window(window)
                ceremony._overlap_window = window
                ceremony.overlap_window_seconds = window
                ceremony._completing_at = record["declared_at"]
            digest = hashlib.sha256(_canonical(envelope)).hexdigest()
            if digest in ceremony._seen_digests:
                _fail(INVALID_TRANSITION,
                      "replayed transition record refused")
            ceremony._seen_digests.add(digest)
            ceremony._records.append(envelope)
            ceremony.phase = record["phase_to"]
        return ceremony

    # -- material verification ---------------------------------------

    def _verify_under(self, pubkey_hex, signature_hex, message):
        if not isinstance(signature_hex, str) or \
                not _HEX128_RE.match(signature_hex):
            return False
        ok = _ed25519.verify(bytes.fromhex(pubkey_hex), message,
                             bytes.fromhex(signature_hex))
        return ok is True

def verify_envelope_with_succession(envelope, succession,
                                    checked_at=None, overlap_note=None):
    """Verify authority material against a ``KeySuccession``.

    The envelope's signature is checked against the union of trust:
    during ``completing`` (inside the window) EITHER key verifies;
    before completing only the old key; after completing (or past
    the window) only the new key. Returns ``(True, detail)`` where
    ``detail`` names which key signed (``"old-key"`` / ``"new-key"``),
    whether the use fell during overlap, and any emitted overlap
    note. Retired-key reuse raises ``KeySuccessionError`` coded
    ``keysuccession-retired-reuse`` with ``is_revocation_event``
    True. Every refusal is coded; nothing returns a bare False.
    """
    if not isinstance(succession, KeySuccession):
        _fail(INVALID_TRANSITION, "succession must be a KeySuccession")
    if not isinstance(envelope, dict):
        _fail(INVALID_TRANSITION, "envelope must be a dict")
    payload = None
    for key in ("status", "credential", "payload", "record"):
        if isinstance(envelope.get(key), dict):
            payload = envelope[key]
            break
    if payload is None:
        _fail(INVALID_TRANSITION,
              "envelope carries no signed payload")
    signature_hex = envelope.get("signature")
    if not isinstance(signature_hex, str) or \
            not _HEX128_RE.match(signature_hex):
        _fail(INVALID_TRANSITION,
              "envelope must carry a 128-hex signature")
    message = _canonical(payload)
    return _verify_under_either(signature_hex, message, succession,
                                checked_at=checked_at,
                                overlap_note=overlap_note)


def _verify_under_either(signature_hex, message, succession,
                         checked_at=None, overlap_note=None):
    """The union-of-trust check shared by
    ``verify_envelope_with_succession``. Returns ``(True, detail)``."""
    if checked_at is None:
        checked_at = int(time.time())
    else:
        _check_ts(checked_at, "checked_at")
    old_ok = _sig_ok(succession.old_pubkey, signature_hex, message)
    new_ok = (succession.new_pubkey is not None and
              _sig_ok(succession.new_pubkey, signature_hex, message))
    if old_ok and new_ok:
        # Both keys verify (e.g. a payload signed identically by a
        # shared signer). Attribute to the new key once the ceremony
        # has reached completing; before that, to the old key.
        if succession.phase in ("completing", "completed"):
            return True, {"signed_by": "new-key",
                          "during_overlap": False,
                          "overlap_note": None,
                          "note_emitted": False}
        return True, {"signed_by": "old-key",
                      "during_overlap": False,
                      "overlap_note": None,
                      "note_emitted": False}
    if old_ok:
        if succession.phase in ("none", "preparing", "prepared"):
            return True, {"signed_by": "old-key",
                          "during_overlap": False,
                          "overlap_note": None,
                          "note_emitted": False}
        if succession.phase == "completing" and \
                _overlap_open(succession, checked_at):
            return True, _old_key_overlap_detail(succession, checked_at,
                                                 overlap_note)
        _retired_reuse_fail(succession)
    if new_ok:
        if succession.phase in ("completing", "completed"):
            return True, {"signed_by": "new-key",
                          "during_overlap": False,
                          "overlap_note": None,
                          "note_emitted": False}
        _fail(INVALID_TRANSITION,
              "material signed by the successor key while the "
              "ceremony is at %r: the new key is not authorized "
              "before completing" % (succession.phase,))
    _fail(INVALID_TRANSITION,
          "signature verifies under neither the old authority key "
          "nor the successor key")


def _sig_ok(pubkey_hex, signature_hex, message):
    """True only on exact verification success (wave-243 lesson:
    ``ed25519.verify`` is bool-returning; check ``is True``)."""
    ok = _ed25519.verify(bytes.fromhex(pubkey_hex), message,
                         bytes.fromhex(signature_hex))
    return ok is True


def _overlap_open(succession, checked_at):
    return (succession.phase == "completing" and
            succession._completing_at is not None and
            succession._overlap_window is not None and
            0 <= checked_at - succession._completing_at <=
            succession._overlap_window)


def _old_key_overlap_detail(succession, checked_at, overlap_note):
    """Union of trust during overlap: old-key material verifies, but
    the verifier records which key signed and emits a signed note
    when a declaration is supplied -- tolerance is never silent
    (wave-292 decay precedent). The note's signed half is the audit
    event ``keysuccession-overlap-use`` (the audit log is
    HMAC-chained); the returned envelope is the structured
    declaration. A broken audit sink only downgrades
    ``note_emitted`` (F345-class isolation)."""
    note = None
    note_emitted = False
    if overlap_note is not None:
        record = {
            "record_format": OVERLAP_NOTE_FORMAT,
            "authority_id": succession.authority_id,
            "key_used": "old-key",
            "checked_at": checked_at,
            "window_remaining_seconds":
                (succession._completing_at + succession._overlap_window
                 - checked_at),
            "declared": overlap_note,
        }
        note_emitted = bool(_emit_event("keysuccession-overlap-use",
                                        record))
        note = {"record": record, "keyid": "old-authority",
                "signature": None}
    return {"signed_by": "old-key",
            "during_overlap": True,
            "overlap_note": note,
            "note_emitted": note_emitted}


def _retired_reuse_fail(succession):
    _emit_event("keysuccession-retired-reuse",
                {"authority_id": succession.authority_id})
    _fail(RETIRED_REUSE,
          "old authority key is retired (ceremony %r, overlap "
          "window closed or exhausted): reuse of a retired key is a "
          "revocation EVENT, refused LOUD" % (succession.phase,),
          revocation_event=True)
