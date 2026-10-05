"""Witness operations: C2SP add-checkpoint daemon + log-side
block-until-quorum submission client (wave-339 lane 2, R24).

What exists already (do not rebuild): the signed witness-policy
artifact (``gov.witness_policy``), the checkpoint note wire format
(``gov.checkpoint_note``: 0x01 log lines, 0x04 cosignature/v1 lines),
the Merkle log (``gov.witness_log``), and quorum verification
(``gov.witness_consistency.require_cosignatures``). This module is the
missing operational surface the w338 witness prospectus specified:

* :class:`WitnessDaemon` -- one small process per witness. Holds the
  witness key, keeps ``{origin -> (size, cosigned checkpoint)}`` in a
  sqlite store (the OmniWitness pattern, reimplemented from the C2SP
  contract -- patterns described, nothing copied), and implements the
  C2SP ``add-checkpoint`` status table:

    - 404 unknown origin (never heard of this log);
    - 403 no trusted-key checkpoint signature, or a trusted key's
      signature fails (forgery signal);
    - 400 ``old`` size larger than the stored size, or more than 63
      proof lines (the C2SP cap);
    - 409 ``old`` size != stored size; the response body is the stored
      size (the client rebases and retries once);
    - 422 size-zero checkpoint with a non-empty root, an unverifiable
      consistency proof, or same-size-different-root (equivocation);
    - 200 with the cosignature line after ATOMIC persist of the new
      checkpoint (check-and-persist in one sqlite statement; an
      in-process lock serializes concurrent requests).

  Unknown signature lines on the checkpoint are IGNORED
  (MUST-ignore-unknown, the rotation rule); a KNOWN log key's bad
  signature is 403, never ignored.

* :func:`submit_checkpoint` -- the log-side submission client. On each
  checkpoint tick it POSTs to every configured witness (transport is
  caller-supplied; a stdlib-urllib default is provided), rebases once
  on 409, and BLOCKS until ``quorum_k`` valid cosignatures are
  collected (Rekor v2 section 5.3 semantics). Below quorum it refuses
  ``witness-publish-quorum-unmet`` and returns NOTHING: the trusted
  head freezes, no partial checkpoint is published. Per-witness
  timeout defaults to 10s, the total budget to 20s (the CLIENTS.md
  rule); the budget is tracked on ``time.monotonic``.

* :func:`check_policy_update` is NOT reimplemented here -- the
  dual-threshold fix lives in ``gov.witness_policy`` (TUF section 5.3:
  a policy-signer-set change needs threshold(old)+threshold(new)).

HONEST RESIDUALS (never claimed away):

* Witnessing proves CHECKPOINT CONSISTENCY (anti-equivocation), not
  bundle content truth, entry authorization, or wall-clock time.
* A state-lost witness MUST NOT re-baseline from the log's head --
  that would void the anti-equivocation guarantee. Recovery is an
  operator-supplied bootstrap checkpoint, never blind TOFU. The
  ``:memory:`` store is for tests; production deployments persist the
  state file.
* Cosignature timestamps are the witness's claim, not an RFC 3161
  substitute. The client rejects zero and future-dated cosignature
  times.
* ML-DSA-44 cosignatures: C2SP SHOULD, deployed practice Ed25519 --
  this module emits Ed25519 cosignature/v1 (the PQ upgrade path is
  noted, not claimed).
* No witness-network interop is claimed: these witnesses are
  operator-run; their quorum, their keys, our signed policy artifact.
* This module never touches the network itself: ``WitnessDaemon``
  answers ``handle_add_checkpoint`` calls; the optional stdlib HTTP
  harness is deployment-owned; the client's transport is
  caller-supplied (no implicit I/O, no new dependencies).

Stdlib only (sqlite3, urllib, http.server). $0 spend, synthetic/local.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import checkpoint_note as _cn
from . import witness_policy as _wp
from . import witness_consistency as _wc
from .witness_log import verify_consistency

__all__ = [
    "WitnessDaemonError",
    "WitnessSubmitError",
    "WitnessDaemon",
    "submit_checkpoint",
    "urllib_transport",
    "make_http_handler",
    "serve_forever",
    "MAX_PROOF_LINES",
    "DEFAULT_PER_WITNESS_TIMEOUT",
    "DEFAULT_TOTAL_BUDGET",
]

#: C2SP tlog-witness: at most 63 base64 consistency-proof lines.
MAX_PROOF_LINES = 63

#: Default per-witness submission timeout, seconds (the spec's <10s estimate).
DEFAULT_PER_WITNESS_TIMEOUT = 10

#: Default total client-facing budget, seconds (the CLIENTS.md >=20s rule).
DEFAULT_TOTAL_BUDGET = 20

WITNESS_DAEMON_STATE_FAILED = "witness-daemon-state-failed"
WITNESS_PUBLISH_QUORUM_UNMET = "witness-publish-quorum-unmet"
WITNESS_UNREACHABLE = "witness-unreachable"
WITNESS_COSIGNATURE_INVALID = "witness-cosignature-invalid"


class WitnessDaemonError(Exception):
    """A coded witness-daemon failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


class WitnessSubmitError(Exception):
    """A coded submission-client failure. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail) if detail else
                         "[%s]" % (code,))


def _refuse_daemon(code, detail=""):
    raise WitnessDaemonError(code, detail)


def _refuse_submit(code, detail=""):
    raise WitnessSubmitError(code, detail)


# ---------------------------------------------------------------------------
# The daemon.
# ---------------------------------------------------------------------------

_SCHEMA = ("CREATE TABLE IF NOT EXISTS checkpoints ("
           "origin TEXT PRIMARY KEY, "
           "size INTEGER NOT NULL, "
           "note BLOB NOT NULL, "
           "updated_at INTEGER NOT NULL)")


class WitnessDaemon(object):
    """One witness operator process.

    ``known_logs`` maps log origin -> list of log vkey strings (the
    witness's trusted log keys; a checkpoint must carry a signature
    from one of them). ``witness_name``/``signer`` identify the
    witness: ``signer`` exposes ``.public_key`` (32 bytes) and
    ``.sign(bytes)``. ``state_path`` is the sqlite file holding
    ``{origin -> (size, cosigned checkpoint)}``; ``:memory:`` is
    allowed only for tests (a state-lost witness must be
    re-bootstrapped by the operator, never from the log's head).
    """

    def __init__(self, known_logs, witness_name, signer, state_path):
        if not isinstance(known_logs, dict) or not known_logs:
            raise ValueError("known_logs must be a non-empty {origin: [vkey]}")
        parsed = {}
        for origin, vkeys in known_logs.items():
            if not isinstance(origin, str) or not origin:
                raise ValueError("known_logs origin must be a non-empty str")
            if (not isinstance(vkeys, (list, tuple)) or not vkeys
                    or not all(isinstance(v, str) for v in vkeys)):
                raise ValueError(
                    "known_logs[%r] must be a non-empty list of vkey "
                    "strings" % (origin,))
            try:
                parsed_vkeys = [_cn.parse_vkey(v) for v in vkeys]
            except ValueError as exc:
                raise ValueError(
                    "known_logs[%r]: bad vkey: %s" % (origin, exc))
            for v in parsed_vkeys:
                if v["signature_type"] != _cn.SIG_TYPE_ED25519:
                    raise ValueError(
                        "known_logs[%r]: log keys must be 0x01 Ed25519 "
                        "vkeys" % (origin,))
            parsed[origin] = vkeys
        if not isinstance(witness_name, str) or not witness_name:
            raise ValueError("witness_name must be a non-empty str")
        pub = getattr(signer, "public_key", None)
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            raise ValueError("signer.public_key must be 32 bytes")
        if not callable(getattr(signer, "sign", None)):
            raise ValueError("signer must expose sign(bytes)")
        if not isinstance(state_path, str) or not state_path:
            raise ValueError("state_path must be a non-empty str")
        self._known_logs = parsed
        self._witness_name = witness_name
        self._signer = signer
        self._state_path = state_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(state_path, check_same_thread=False,
                                     isolation_level=None)
        try:
            with self._conn:
                self._conn.execute(_SCHEMA)
        except sqlite3.Error as exc:
            _refuse_daemon(WITNESS_DAEMON_STATE_FAILED,
                           "cannot initialize state store: %s" % (exc,))

    # -- state -----------------------------------------------------------

    def _stored(self, origin):
        try:
            row = self._conn.execute(
                "SELECT size, note FROM checkpoints WHERE origin = ?",
                (origin,)).fetchone()
        except sqlite3.Error as exc:
            _refuse_daemon(WITNESS_DAEMON_STATE_FAILED,
                           "state read failed: %s" % (exc,))
        if row is None:
            return None
        return (int(row[0]), bytes(row[1]))

    def stored_note(self, origin):
        """The latest cosigned checkpoint for ``origin`` (bytes), or
        None if this witness never cosigned it."""
        hit = self._stored(origin)
        return hit[1] if hit else None

    def _persist(self, origin, size, note, now):
        """Atomic check-and-persist: the stored size never moves
        backward, even under concurrent writers (one UPSERT statement;
        callers additionally hold the daemon lock)."""
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO checkpoints (origin, size, note, "
                    "updated_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(origin) DO UPDATE SET "
                    "size = excluded.size, note = excluded.note, "
                    "updated_at = excluded.updated_at "
                    "WHERE excluded.size >= checkpoints.size",
                    (origin, size, bytes(note), int(now)))
                row = self._conn.execute(
                    "SELECT size FROM checkpoints WHERE origin = ?",
                    (origin,)).fetchone()
        except sqlite3.Error as exc:
            _refuse_daemon(WITNESS_DAEMON_STATE_FAILED,
                           "state persist failed: %s" % (exc,))
        if row is None or int(row[0]) != size:
            # Another writer won with a larger size -- our persist is
            # correctly ignored (monotonicity), but the caller already
            # verified this request against the pre-write state, so
            # treat a lost race as a state failure rather than
            # cosigning something we did not store.
            _refuse_daemon(WITNESS_DAEMON_STATE_FAILED,
                           "lost the persist race for %r" % (origin,))

    # -- request handling --------------------------------------------------

    @staticmethod
    def _parse_body(body):
        """Split an add-checkpoint body into (old_size, proof_hashes,
        checkpoint_note). Raises WitnessDaemonError on shape errors."""
        if isinstance(body, (bytes, bytearray)):
            try:
                text = bytes(body).decode("utf-8")
            except UnicodeDecodeError:
                _refuse_daemon("witness-note-malformed",
                               "add-checkpoint body is not UTF-8")
        elif isinstance(body, str):
            text = body
        else:
            _refuse_daemon("witness-note-malformed",
                           "add-checkpoint body must be str/bytes")
        if "\x00" in text:
            _refuse_daemon("witness-note-malformed",
                           "add-checkpoint body carries NUL")
        lines = text.split("\n")
        if not lines or not lines[0].startswith("old "):
            _refuse_daemon("witness-note-malformed",
                           "add-checkpoint body must start with 'old <size>'")
        try:
            old_size = int(lines[0][4:])
        except ValueError:
            _refuse_daemon("witness-note-malformed",
                           "old size is not an integer")
        if old_size < 0:
            _refuse_daemon("witness-note-malformed",
                           "old size must be >= 0")
        proof_lines = []
        i = 1
        while i < len(lines) and lines[i] != "":
            proof_lines.append(lines[i])
            i += 1
        note_text = "\n".join(lines[i + 1:])
        if len(proof_lines) > MAX_PROOF_LINES:
            _refuse_daemon("witness-note-malformed",
                           "%d proof lines exceed the C2SP cap of %d"
                           % (len(proof_lines), MAX_PROOF_LINES))
        proof_hashes = []
        for j, ln in enumerate(proof_lines):
            try:
                raw = base64.b64decode(ln, validate=True)
            except (binascii.Error, ValueError):
                _refuse_daemon("witness-note-malformed",
                               "proof line %d is not valid base64" % (j,))
            if len(raw) != 32:
                _refuse_daemon("witness-note-malformed",
                               "proof line %d is not a 32-byte hash" % (j,))
            proof_hashes.append(raw)
        return old_size, proof_hashes, note_text.encode("utf-8")

    def handle_add_checkpoint(self, body, now=None):
        """Handle one C2SP ``add-checkpoint`` request.

        Returns ``(status, response_text)`` with status in
        200/400/403/404/409/422. On 200 the response is the
        cosignature/v1 line (no trailing blank); on 409 it is the
        stored size as decimal text. Local state failures raise
        :class:`WitnessDaemonError` (coded) instead of returning a
        status -- a witness that cannot persist must not cosign.
        ``now`` is the observed unix time (int).
        """
        now_s = int(time.time()) if now is None else int(now)
        try:
            old_size, proof_hashes, note = self._parse_body(body)
        except WitnessDaemonError:
            return (400, "malformed add-checkpoint body")
        try:
            fields = _cn.parse_checkpoint(note)
        except _cn.CheckpointNoteError:
            return (400, "checkpoint note does not parse")
        origin = fields["origin"]
        vkeys = self._known_logs.get(origin)
        if vkeys is None:
            return (404, "unknown origin %r" % (origin,))
        # The checkpoint signature MUST come from a trusted log key;
        # unknown lines are ignored, a known key's bad signature is 403.
        try:
            verified = _cn.verify_checkpoint(note, vkeys)
        except _cn.CheckpointNoteError as exc:
            if exc.code == _cn.CHECKPOINT_KNOWN_SIGNATURE_INVALID:
                return (403, "a trusted log key's signature failed")
            return (403, "no trusted log-key signature on the checkpoint")
        if verified["origin"] != origin:
            return (403, "checkpoint origin mismatch")
        new_size = verified["tree_size"]
        new_root = verified["root_hash"]
        if new_size == 0 and new_root != bytes(32):
            return (422, "size-zero checkpoint with a non-empty root")
        with self._lock:
            stored = self._stored(origin)
            stored_size = stored[0] if stored else 0
            if old_size > stored_size:
                return (400, "old size %d exceeds the stored size %d"
                        % (old_size, stored_size))
            if old_size != stored_size:
                return (409, str(stored_size))
            if stored is not None:
                stored_fields = _cn.parse_checkpoint(stored[1])
                if (new_size == stored_size
                        and new_root != stored_fields["root_hash"]):
                    return (422, "same size, different root: equivocation "
                            "refused")
                if new_size == stored_size:
                    # Idempotent re-submit of the identical checkpoint.
                    return (200, self._cosignature_lines(
                        stored[1], self._witness_name))
                if new_size < stored_size:
                    return (400, "checkpoint size moved backward")
            # Advancing: the consistency proof must recompute from the
            # stored checkpoint to the new one. Bootstrap (old == 0,
            # nothing stored) skips the proof -- the signature check
            # above is the admission rule, exactly like first-seen
            # operator bootstrap.
            if stored is not None:
                old_root = stored_fields["root_hash"]
                try:
                    verify_consistency(
                        stored_size, old_root, new_size, new_root,
                        [h.hex() for h in proof_hashes])
                except Exception:
                    return (422, "consistency proof does not verify")
            cosigned = self._cosign(note, now_s)
            self._persist(origin, new_size, cosigned, now_s)
            return (200, self._cosignature_lines(cosigned,
                                                 self._witness_name))

    # -- cosigning ---------------------------------------------------------

    def _cosign(self, note, now_s):
        """Append this witness's cosignature/v1 line to the note."""
        if not isinstance(now_s, int) or now_s <= 0:
            _refuse_daemon("witness-note-malformed",
                           "cosignature timestamp must be a positive int")
        fields = _cn.parse_checkpoint(note)
        line = _cn.emit_cosignature_line(
            self._witness_name, self._signer, fields["origin"],
            fields["tree_size"], fields["root_hash"], now_s)
        return note + line.encode("utf-8") + b"\n"

    @staticmethod
    def _cosignature_lines(cosigned_note, witness_name):
        """This witness's own cosignature lines of a cosigned note
        (the log's own 0x01 line is never echoed back)."""
        _, sigs = _cn._split_note(cosigned_note)
        lines = []
        for sig in sigs:
            if sig["key_name"] != witness_name:
                continue
            lines.append("%s %s %s" % (
                _cn.EM_DASH, sig["key_name"],
                base64.b64encode(sig["key_id"] + sig["signature"]
                                 ).decode("ascii")))
        return "\n".join(lines) + "\n"

    # -- monitor surface -----------------------------------------------------

    def monitor_note(self, origin_hash):
        """``GET <monitoring prefix>/<origin hash>/checkpoint``: the
        latest cosigned checkpoint for the log whose origin hashes to
        ``origin_hash`` (lowercase hex SHA-256 of the origin), or None.
        The witness MAY delay updates; this implementation serves the
        latest stored note."""
        if (not isinstance(origin_hash, str)
                or len(origin_hash) != 64):
            return None
        want = origin_hash.lower()
        for origin in self._known_logs:
            if hashlib.sha256(origin.encode("utf-8")).hexdigest() == want:
                return self.stored_note(origin)
        return None

# ---------------------------------------------------------------------------
# The log-side submission client.
# ---------------------------------------------------------------------------

def _check_witness_entry(entry, where):
    if not isinstance(entry, dict):
        _refuse_submit("witness-note-malformed",
                       "%s: witness entry must be a mapping" % (where,))
    for field in ("name", "vkey", "endpoint"):
        if (not isinstance(entry.get(field), str)
                or not entry[field].strip()):
            _refuse_submit("witness-note-malformed",
                           "%s: witness %r must be a non-empty str"
                           % (where, field))
    try:
        parsed = _cn.parse_vkey(entry["vkey"])
    except ValueError as exc:
        _refuse_submit("witness-note-malformed",
                       "%s: bad witness vkey: %s" % (where, exc))
    if parsed["signature_type"] != _cn.SIG_TYPE_ED25519_COSIGNATURE_V1:
        _refuse_submit("witness-note-malformed",
                       "%s: witness vkeys must be 0x04 cosignature/v1 "
                       "vkeys" % (where,))
    return {"name": entry["name"], "vkey": entry["vkey"],
            "endpoint": entry["endpoint"]}


def _parse_cosignature_time(line):
    """The u64BE timestamp of a cosignature/v1 response line, or None
    when the line is not a well-formed 76-byte cosignature blob."""
    parts = line.strip().split(" ")
    if len(parts) != 3 or parts[0] != _cn.EM_DASH:
        return None
    try:
        raw = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 76:
        return None
    return int.from_bytes(raw[4:12], "big")


def urllib_transport(prefix_url):
    """The default caller-supplied transport: stdlib urllib POST to
    ``<prefix_url>/add-checkpoint`` with the given timeout. Returns
    ``(status, body_text)``; raises on connection errors (the client
    records them as ``witness-unreachable``). No keep-alive pooling is
    attempted beyond what urllib does per opener; the C2SP keep-alive
    SHOULD is best-effort here and documented as such.
    """
    def transport(entry, body, timeout):
        url = prefix_url.rstrip("/") + "/add-checkpoint"
        req = urllib.request.Request(
            url, data=body.encode("utf-8"), method="POST",
            headers={"Content-Type": "text/plain; charset=utf-8"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return (resp.status,
                        resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read().decode("utf-8", errors="replace")
            except Exception:
                payload = ""
            return (exc.code, payload)
    return transport


def submit_checkpoint(log, *, origin, log_key_name, log_seed, witnesses,
                      quorum_k, policy, per_witness_timeout=None,
                      total_budget=None, now=None, transport, state):
    """Submit the log's current head for witnessing; block until
    ``quorum_k`` valid cosignatures are collected (Rekor v2 section 5.3
    semantics, fail-closed).

    ``log`` is a ``gov.witness_log.WitnessLog``; the checkpoint note is
    minted with the log's key (``log_key_name``/``log_seed``).
    ``witnesses`` is a list of ``{"name", "vkey", "endpoint"}`` (the
    vkey must be a 0x04 cosignature/v1 vkey). ``policy`` is a VERIFIED
    witness-policy dict (``witness_policy.verifier_inputs`` supplies the
    vkeys and quorum); ``quorum_k`` is checked against it.
    ``transport(entry, body_text, timeout) -> (status, body)`` is
    caller-supplied (no implicit I/O). ``state`` is a caller-owned
    ``{witness_name: last_cosigned_size}`` dict, updated in place ONLY
    on success -- below quorum nothing is returned and ``state`` is
    untouched (the freeze). ``now`` is the observed unix time.

    Returns ``{"checkpoint": <full note bytes>,
    "cosigned_by": [names], "witnesses": [{"name", "status", "detail"}]}``.
    Below quorum (or budget exhausted first) raises
    :class:`WitnessSubmitError` coded ``witness-publish-quorum-unmet``;
    a configured witness's bad cosignature raises the coded
    ``witness-cosignature-invalid`` from ``require_cosignatures``
    (hard refusal, never a soft accept).
    """
    per_witness_timeout = (DEFAULT_PER_WITNESS_TIMEOUT
                           if per_witness_timeout is None
                           else per_witness_timeout)
    total_budget = (DEFAULT_TOTAL_BUDGET
                    if total_budget is None else total_budget)
    for label, v in (("per_witness_timeout", per_witness_timeout),
                     ("total_budget", total_budget)):
        if (isinstance(v, bool) or not isinstance(v, (int, float))
                or v < 0):
            _refuse_submit("witness-note-malformed",
                           "%s must be a non-negative number" % (label,))
    if (isinstance(quorum_k, bool) or not isinstance(quorum_k, int)
            or quorum_k < 1):
        _refuse_submit("witness-note-malformed",
                       "quorum_k must be a positive int")
    entries = [_check_witness_entry(e, "witnesses[%d]" % i)
               for i, e in enumerate(witnesses or ())]
    if not entries:
        _refuse_submit(WITNESS_PUBLISH_QUORUM_UNMET,
                       "no witnesses configured; refusing to publish an "
                       "unwitnessed checkpoint")
    if not callable(transport):
        _refuse_submit("witness-note-malformed",
                       "transport must be callable")
    if not isinstance(state, dict):
        _refuse_submit("witness-note-malformed",
                       "state must be a {name: size} dict")
    now_s = int(time.time()) if now is None else int(now)

    # The checkpoint note: minted locally, signed by the log key.
    if not hasattr(log, "root_hash") or not hasattr(log, "tree_size"):
        _refuse_submit("witness-note-malformed",
                       "log must be a gov.witness_log.WitnessLog")
    new_size = int(log.tree_size)
    if new_size < 1:
        _refuse_submit("witness-note-malformed",
                       "cannot submit a checkpoint for an empty log")
    try:
        note = _cn.emit_checkpoint(origin, new_size, log.root_hash(),
                                   log_key_name, log_seed)
    except (ValueError, _cn.CheckpointNoteError) as exc:
        _refuse_submit("witness-note-malformed",
                       "checkpoint emission failed: %s" % (exc,))

    vi = _wp.verifier_inputs(policy, now_s)
    if quorum_k != vi["quorum_k"]:
        _refuse_submit("witness-note-malformed",
                       "quorum_k=%d disagrees with the verified policy's "
                       "quorum_k=%d" % (quorum_k, vi["quorum_k"]))
    deadline = time.monotonic() + total_budget
    collected = {}   # name -> response line(s)
    diagnostics = []  # [{"name", "status", "detail"}]

    for entry in entries:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            diagnostics.append({"name": entry["name"],
                                "status": "budget-exhausted",
                                "detail": "total budget exhausted before "
                                "contacting this witness"})
            continue
        timeout = min(per_witness_timeout, remaining)
        old_size = state.get(entry["name"], 0)
        if (not isinstance(old_size, int) or isinstance(old_size, bool)
                or old_size < 0):
            _refuse_submit("witness-note-malformed",
                           "state[%r] must be a non-negative int"
                           % (entry["name"],))
        status, detail, line, new_old = _submit_to_witness(
            log, note, new_size, entry, old_size, timeout, transport,
            now_s)
        if line is not None:
            collected[entry["name"]] = line
        diagnostics.append({"name": entry["name"], "status": status,
                            "detail": detail})

    if len(collected) < quorum_k:
        _refuse_submit(WITNESS_PUBLISH_QUORUM_UNMET,
                       "collected %d of %d cosignatures; the checkpoint "
                       "is NOT published and the trusted head freezes; "
                       "per-witness: %s"
                       % (len(collected), quorum_k,
                          "; ".join("%s=%s" % (d["name"], d["status"])
                                    for d in diagnostics)))
    # Verify the assembled note: operator signature first, then the
    # quorum of configured-witness cosignatures; unknown lines
    # ignored, a configured witness's bad line a hard refusal.
    full_note = note + b"".join(collected[n].encode("utf-8")
                                for n in sorted(collected))
    _wc.require_cosignatures(full_note,
                             operator_vkeys=vi["operator_vkeys"],
                             witness_vkeys={n: vi["witness_vkeys"][n]
                                            for n in collected},
                             quorum_k=quorum_k)
    # Cosignature timestamps: zero and future-dated times refuse.
    for name in sorted(collected):
        ts = _parse_cosignature_time(collected[name].split("\n")[0])
        if ts is None or ts == 0 or ts > now_s:
            _refuse_submit(WITNESS_COSIGNATURE_INVALID,
                           "witness %r returned an unusable cosignature "
                           "time %r" % (name, ts))
    for name in collected:
        state[name] = new_size
    return {"checkpoint": full_note,
            "cosigned_by": sorted(collected),
            "witnesses": diagnostics}


def _submit_to_witness(log, note, new_size, entry, old_size, timeout,
                       transport, now_s):
    """One witness submission with a single 409-rebase retry.

    Returns ``(status, detail, cosignature_line_or_None,
    effective_old_size)``. ``status`` is one of: ``"ok"``,
    ``"unreachable"``, ``"refused-<http>"``, ``"bad-cosignature"``.
    """
    def build(old):
        lines = ["old %d" % old]
        if 0 < old < new_size:
            proof = log.consistency_proof(old, new_size)
            for h in proof["hashes"]:
                lines.append(base64.b64encode(
                    bytes.fromhex(h)).decode("ascii"))
        lines.append("")
        return "\n".join(lines) + "\n" + note.decode("utf-8")

    def attempt(old):
        try:
            st, resp = transport(entry, build(old), timeout)
        except Exception as exc:  # noqa: BLE001 - any transport failure
            return ("unreachable", "transport failed: %r" % (exc,),
                    None, old)
        if not isinstance(st, int):
            return ("unreachable",
                    "transport returned non-int status %r" % (st,),
                    None, old)
        if st == 200:
            first = (resp or "").split("\n")[0]
            ts = _parse_cosignature_time(first)
            if ts is None:
                return ("bad-cosignature",
                        "200 response is not a cosignature/v1 line",
                        None, old)
            return ("ok", "cosigned", resp, old)
        if st == 409:
            try:
                rebased = int((resp or "").strip())
            except ValueError:
                return ("refused-409",
                        "409 with unparseable size body %r" % (resp,),
                        None, old)
            # One rebase-and-retry, per the C2SP discovery rule.
            try:
                st2, resp2 = transport(entry, build(rebased), timeout)
            except Exception as exc:  # noqa: BLE001
                return ("unreachable",
                        "rebase retry transport failed: %r" % (exc,),
                        None, rebased)
            if st2 == 200:
                first = (resp2 or "").split("\n")[0]
                if _parse_cosignature_time(first) is None:
                    return ("bad-cosignature",
                            "rebase-retry 200 is not a cosignature/v1 "
                            "line", None, rebased)
                return ("ok", "cosigned after 409 rebase to %d" % rebased,
                        resp2, rebased)
            return ("refused-%d" % st2,
                    "rebase retry -> %d: %s" % (st2, (resp2 or "")[:120]),
                    None, rebased)
        return ("refused-%d" % st,
                "%d: %s" % (st, (resp or "")[:120]), None, old)

    return attempt(old_size)


# ---------------------------------------------------------------------------
# The optional stdlib HTTP harness (deployment-owned).
# ---------------------------------------------------------------------------

def make_http_handler(daemon):
    """Build a ``BaseHTTPRequestHandler`` subclass serving one daemon's
    ``POST /add-checkpoint``. Deployment-owned: binding, TLS, and
    auth live outside this module (the C2SP bastion note applies).
    """
    if not isinstance(daemon, WitnessDaemon):
        raise ValueError("daemon must be a WitnessDaemon")

    class _AddCheckpointHandler(BaseHTTPRequestHandler):
        server_version = "SasanamWitness/1.0"

        def log_message(self, *args):  # keep the harness quiet
            pass

        def do_POST(self):
            if self.path.rstrip("/").endswith("/add-checkpoint"):
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                try:
                    status, resp = daemon.handle_add_checkpoint(body)
                except WitnessDaemonError as exc:
                    status, resp = 500, "[%s] %s" % (exc.code,
                                                     exc.detail)
                payload = resp.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_error(404, "unknown path")

        def do_GET(self):
            # GET /<origin-hash>/checkpoint -- the monitor surface.
            parts = self.path.strip("/").split("/")
            if len(parts) == 2 and parts[1] == "checkpoint":
                note = daemon.monitor_note(parts[0])
                if note is None:
                    self.send_error(404, "never cosigned")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(note)))
                self.end_headers()
                self.wfile.write(note)
                return
            self.send_error(404, "unknown path")

    return _AddCheckpointHandler


def serve_forever(daemon, host, port):
    """Serve one daemon on ``(host, port)`` until interrupted. Thin
    wrapper over :func:`make_http_handler`; production deployments
    own TLS, auth, and process supervision."""
    handler = make_http_handler(daemon)
    with HTTPServer((host, port), handler) as httpd:
        httpd.serve_forever()
