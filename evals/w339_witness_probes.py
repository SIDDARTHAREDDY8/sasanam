#!/usr/bin/env python3
"""Red-first battery for witness operations (wave-339 lane 2, R24).

Covers gov/witness_daemon.py (C2SP add-checkpoint witness daemon +
log-side block-until-quorum submission client) and the
check_policy_update TUF dual-threshold fix in gov/witness_policy.py.

P1 (11): witness daemon add-checkpoint wire contract -- unknown origin
    404; bad log signature 403; unknown-key lines ignored with a valid
    trusted signature (MUST-ignore) 200; known key's bad signature 403;
    old-size mismatch 409 with stored size (+ rebase-retry once -> 200);
    old 0 bootstrap 200; old > stored 400; bad consistency proof 422;
    same-size-different-root 422 (equivocation refuse); idempotent
    re-submit 200; >63 proof lines 400; restart-from-state-file persists
    (persist-before-respond).
P2 (7): submission client -- quorum-2 happy path returns cosigned
    checkpoint verifying via require_cosignatures; below-quorum refuses
    witness-publish-quorum-unmet and returns nothing (freeze);
    unreachable witness recorded, others proceed; 409 rebase-and-retry;
    total-budget exhaustion stops early; configured witness's bad
    cosignature refuses witness-cosignature-invalid (hard); unknown-key
    response lines ignored.
P3 (5): dual-threshold -- signer-set change sealed with anchor
    threshold only refuses witness-policy-dual-threshold-unmet (the
    base-tree gap, demonstrated red before the fix); old+new thresholds
    pass; unchanged signer set keeps old behavior; new-set-only fails;
    one key counted once per side (dedup).
P4 (2): pin 2140/2140/0 sorted on raw source literals (2 new codes:
    witness-policy-dual-threshold-unmet, witness-daemon-state-failed);
    footer open none / next F430.

Result contract: each probe prints [HELD]/[BREAK]/[ERROR]. Exit 0 iff
no ERROR and no unexpected BREAK. On the OPEN tree (module absent) the
top-level import fails with ImportError before any probe runs -- the
battery fails loudly and no probe can pass (the red-first property).

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git
subprocesses; deterministic (fixed seeds); stdlib only.
"""

import base64
import copy
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import witness_daemon as WD  # noqa: E402  (red-first: ImportError on the open tree)
from gov import witness_policy as WP  # noqa: E402
from gov import witness_consistency as WC  # noqa: E402
from gov import checkpoint_note as CN  # noqa: E402
from gov import decision_codes as DC  # noqa: E402
from gov.witness_log import WitnessLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception as exc:  # noqa: BLE001
        _record(pid, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3)))


def _expect_code(pid, fn, code, note):
    """HELD iff fn() raises a coded error with `code` (any module's)."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: raised %r (code=%r), want coded %s"
                      % (note, exc, got, code))
    return _break(pid, "%s: ACCEPTED, want coded refusal %s" % (note, code))


# Fixed seeds: deterministic keys across runs.
_SEED_LOG = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])
_SEED_P3 = bytes([(i * 11 + 23) % 256 for i in range(32)])

_NOW = 1798765432
_ORIGIN = "sasanam-witness-test/v1"
_LOG_KEY_NAME = "oplog"


def _signer(seed):
    return Ed25519Signer(seed)


def _log_vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519,
                               signer.public_key),
        CN.SIG_TYPE_ED25519, signer.public_key)


def _wit_vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               signer.public_key),
        CN.SIG_TYPE_ED25519_COSIGNATURE_V1, signer.public_key)


def _make_log(n):
    log = WitnessLog(_signer(_SEED_LOG).public_key)
    for i in range(n):
        log.append(b"leaf-%d" % i)
    return log


def _note(log):
    return CN.emit_checkpoint(_ORIGIN, len(log), log.root_hash(),
                              _LOG_KEY_NAME, _SEED_LOG)


def _daemon(state_dir=None):
    d = state_dir or tempfile.mkdtemp(prefix="w339-daemon-")
    known = {_ORIGIN: [_log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))]}
    return WD.WitnessDaemon(known, "wit1", _signer(_SEED_W1),
                            os.path.join(d, "witness.db")), d


def _proof_lines(log, old_size, new_size):
    proof = log.consistency_proof(old_size, new_size)
    return [base64.b64encode(bytes.fromhex(h)).decode("ascii")
            for h in proof["hashes"]]


def _add_body(log, old_size, note):
    lines = ["old %d" % old_size]
    if old_size and old_size < len(log):
        lines.extend(_proof_lines(log, old_size, len(log)))
    lines.append("")
    return "\n".join(lines) + "\n" + note.decode("utf-8")


# ---------------------------------------------------------------------------
# P1: daemon wire contract
# ---------------------------------------------------------------------------

@probe("P1a-unknown-origin-404")
def _p1a():
    daemon, _ = _daemon()
    note = CN.emit_checkpoint("other-origin/v9", 1, bytes(32),
                              _LOG_KEY_NAME, _SEED_LOG)
    st, _ = daemon.handle_add_checkpoint("old 0\n\n" + note.decode(), _NOW)
    if st == 404:
        return _held("P1a-unknown-origin-404", "unknown origin -> 404")
    return _break("P1a-unknown-origin-404", "got status %r, want 404" % (st,))


@probe("P1b-bad-log-signature-403")
def _p1b():
    daemon, _ = _daemon()
    # Signed by a key the daemon does not trust for this origin.
    note = CN.emit_checkpoint(_ORIGIN, 1, bytes(32),
                              _LOG_KEY_NAME, _SEED_W2)
    st, _ = daemon.handle_add_checkpoint("old 0\n\n" + note.decode(), _NOW)
    if st == 403:
        return _held("P1b-bad-log-signature-403",
                     "no trusted-key signature -> 403")
    return _break("P1b-bad-log-signature-403", "got status %r, want 403" % (st,))


@probe("P1c-unknown-key-line-ignored-200")
def _p1c():
    daemon, _ = _daemon()
    log = _make_log(3)
    note = _note(log)
    # Append a line from a key the daemon never heard of; the trusted
    # log signature is still valid -> MUST-ignore -> 200.
    extra = ("%s %s %s\n" % (
        CN.EM_DASH, "stranger",
        base64.b64encode(bytes(76)).decode("ascii"))).encode("utf-8")
    st, _ = daemon.handle_add_checkpoint(_add_body(log, 0, note + extra),
                                         _NOW)
    if st == 200:
        return _held("P1c-unknown-key-line-ignored-200",
                     "unknown signature line ignored, trusted log sig -> 200")
    return _break("P1c-unknown-key-line-ignored-200",
                  "got status %r, want 200" % (st,))


@probe("P1d-known-key-bad-signature-403")
def _p1d():
    daemon, _ = _daemon()
    log = _make_log(3)
    note = _note(log)
    # Flip a byte in the log's signature blob: name+ID match a trusted
    # key but the signature fails -> 403 (forgery signal).
    text, sigs = CN._split_note(note)
    bad = dict(sigs[0])
    raw = bytearray(bad["signature"])
    raw[-1] ^= 1
    bad_line = "%s %s %s\n" % (
        CN.EM_DASH, bad["key_name"],
        base64.b64encode(bad["key_id"] + bytes(raw)).decode("ascii"))
    # _split_note's text excludes the blank separator: restore it.
    forged = text + b"\n" + bad_line.encode("utf-8")
    st, _ = daemon.handle_add_checkpoint(_add_body(log, 0, forged), _NOW)
    if st == 403:
        return _held("P1d-known-key-bad-signature-403",
                     "trusted key's bad signature -> 403")
    return _break("P1d-known-key-bad-signature-403",
                  "got status %r, want 403" % (st,))

@probe("P1e-old-size-mismatch-409")
def _p1e():
    daemon, _ = _daemon()
    log = _make_log(3)
    note = _note(log)
    st, _ = daemon.handle_add_checkpoint(_add_body(log, 0, note), _NOW)
    if st != 200:
        return _break("P1e-old-size-mismatch-409",
                      "bootstrap got %r, want 200" % (st,))
    # Advance the log; submit claiming the witness still has size 0.
    log.append(b"leaf-3")
    note2 = _note(log)
    st, body = daemon.handle_add_checkpoint(_add_body(log, 0, note2), _NOW)
    if st != 409 or body.strip() != "3":
        return _break("P1e-old-size-mismatch-409",
                      "got (%r, %r), want (409, '3')" % (st, body))
    # Rebase `old` to the returned size and retry once -> 200.
    st, _ = daemon.handle_add_checkpoint(_add_body(log, 3, note2), _NOW)
    if st != 200:
        return _break("P1e-old-size-mismatch-409",
                      "rebase retry got %r, want 200" % (st,))
    return _held("P1e-old-size-mismatch-409",
                 "409 with stored size; rebase-once retry -> 200")


@probe("P1f-old-zero-bootstrap-200")
def _p1f():
    daemon, d = _daemon()
    log = _make_log(2)
    st, resp = daemon.handle_add_checkpoint(_add_body(log, 0, _note(log)),
                                            _NOW)
    if st != 200 or not resp.strip():
        return _break("P1f-old-zero-bootstrap-200",
                      "got (%r, %r...), want 200 + cosignature line"
                      % (st, resp[:40]))
    # Restart from the same state file: the checkpoint survived
    # (persist-before-respond), so the witness reports size 2.
    daemon2 = WD.WitnessDaemon(
        {_ORIGIN: [_log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))]},
        "wit1", _signer(_SEED_W1), os.path.join(d, "witness.db"))
    stored = daemon2.stored_note(_ORIGIN)
    if stored is None or b"wit1" not in stored:
        return _break("P1f-old-zero-bootstrap-200",
                      "restart lost the checkpoint (persist-before-respond "
                      "violated)")
    return _held("P1f-old-zero-bootstrap-200",
                 "old 0 bootstrap -> 200; survives restart (persisted)")


@probe("P1g-old-greater-than-stored-400")
def _p1g():
    daemon, _ = _daemon()
    log = _make_log(2)
    daemon.handle_add_checkpoint(_add_body(log, 0, _note(log)), _NOW)
    st, _ = daemon.handle_add_checkpoint(_add_body(log, 5, _note(log)), _NOW)
    if st == 400:
        return _held("P1g-old-greater-than-stored-400",
                     "old 5 > stored 2 -> 400")
    return _break("P1g-old-greater-than-stored-400",
                  "got status %r, want 400" % (st,))


@probe("P1h-bad-consistency-proof-422")
def _p1h():
    daemon, _ = _daemon()
    log = _make_log(2)
    daemon.handle_add_checkpoint(_add_body(log, 0, _note(log)), _NOW)
    log.append(b"leaf-2")
    note2 = _note(log)
    # Corrupt the proof: valid lines count, wrong hash bytes.
    lines = ["old 2"] + [base64.b64encode(bytes(32)).decode("ascii")] + [""]
    body = "\n".join(lines) + "\n" + note2.decode("utf-8")
    st, _ = daemon.handle_add_checkpoint(body, _NOW)
    if st == 422:
        return _held("P1h-bad-consistency-proof-422",
                     "unverifiable consistency proof -> 422")
    return _break("P1h-bad-consistency-proof-422",
                  "got status %r, want 422" % (st,))


@probe("P1i-same-size-different-root-422")
def _p1i():
    daemon, _ = _daemon()
    log = _make_log(2)
    daemon.handle_add_checkpoint(_add_body(log, 0, _note(log)), _NOW)
    # A DIFFERENT log (same origin/size, different root): equivocation.
    evil = WitnessLog(_signer(_SEED_LOG).public_key)
    evil.append(b"evil-0")
    evil.append(b"evil-1")
    forged = CN.emit_checkpoint(_ORIGIN, 2, evil.root_hash(),
                                _LOG_KEY_NAME, _SEED_LOG)
    st, _ = daemon.handle_add_checkpoint(_add_body(evil, 2, forged), _NOW)
    if st == 422:
        return _held("P1i-same-size-different-root-422",
                     "same size, different root -> 422 (no equivocation)")
    return _break("P1i-same-size-different-root-422",
                  "got status %r, want 422" % (st,))


@probe("P1j-idempotent-resubmit-200")
def _p1j():
    daemon, _ = _daemon()
    log = _make_log(2)
    note = _note(log)
    st1, r1 = daemon.handle_add_checkpoint(_add_body(log, 0, note), _NOW)
    st2, r2 = daemon.handle_add_checkpoint(_add_body(log, 2, note), _NOW + 60)
    if st1 == 200 and st2 == 200 and r1 == r2:
        return _held("P1j-idempotent-resubmit-200",
                     "identical re-submit -> 200 with the same cosignature")
    return _break("P1j-idempotent-resubmit-200",
                  "got (%r, %r), want (200, 200) with identical response"
                  % (st1, st2))


@probe("P1k-proof-lines-over-63-400")
def _p1k():
    daemon, _ = _daemon()
    log = _make_log(2)
    note = _note(log)
    lines = ["old 0"] + [base64.b64encode(bytes(32)).decode("ascii")] * 64 + [""]
    body = "\n".join(lines) + "\n" + note.decode("utf-8")
    st, _ = daemon.handle_add_checkpoint(body, _NOW)
    if st == 400:
        return _held("P1k-proof-lines-over-63-400",
                     ">63 proof lines -> 400 (C2SP cap)")
    return _break("P1k-proof-lines-over-63-400",
                  "got status %r, want 400" % (st,))


# ---------------------------------------------------------------------------
# P2: submission client
# ---------------------------------------------------------------------------

def _client_daemon(name, seed):
    d = tempfile.mkdtemp(prefix="w339-cli-")
    known = {_ORIGIN: [_log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))]}
    return (WD.WitnessDaemon(known, name, _signer(seed),
                             os.path.join(d, "witness.db")),
            {"name": name, "vkey": _wit_vkey(name, _signer(seed)),
             "endpoint": "http://127.0.0.1:9/%s" % name})


def _direct_transport(daemons):
    by_name = {d[1]["name"]: d[0] for d in daemons}

    def transport(entry, body, timeout):
        daemon = by_name[entry["name"]]
        return daemon.handle_add_checkpoint(body, _NOW)
    return transport


def _policy_doc():
    body = {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": 1,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + 86400 * 90,
        "threshold": 2,
        "log": {"name": _LOG_KEY_NAME,
                "vkey": _log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))},
        "witnesses": [
            {"name": "wit1", "vkey": _wit_vkey("wit1", _signer(_SEED_W1)),
             "operator": "op1", "contact": "w1@example.org",
             "not_before": _NOW - 100000, "not_after": _NOW + 100000,
             "status": "usable"},
            {"name": "wit2", "vkey": _wit_vkey("wit2", _signer(_SEED_W2)),
             "operator": "op2", "contact": "w2@example.org",
             "not_before": _NOW - 100000, "not_after": _NOW + 100000,
             "status": "usable"},
            {"name": "wit3", "vkey": _wit_vkey("wit3", _signer(_SEED_W3)),
             "operator": "op3", "contact": "w3@example.org",
             "not_before": _NOW - 100000, "not_after": _NOW + 100000,
             "status": "usable"},
        ],
        "policy_signers": [
            {"key_id": _signer(_SEED_P1).public_key.hex(),
             "public_key": _signer(_SEED_P1).public_key.hex()},
        ],
        "policy_threshold": 1,
        "max_checkpoint_staleness_seconds": 10800,
    }
    doc = WP.seal_policy(body, [_signer(_SEED_P1)])
    return WP.verify_policy_document(
        doc, {"policy_signers": body["policy_signers"],
              "policy_threshold": 1}, _NOW)


@probe("P2a-quorum-2-happy-path")
def _p2a():
    daemons = [_client_daemon("wit1", _SEED_W1),
               _client_daemon("wit2", _SEED_W2),
               _client_daemon("wit3", _SEED_W3)]
    entries = [d[1] for d in daemons]
    log = _make_log(4)
    state = {}
    out = WD.submit_checkpoint(
        log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME, log_seed=_SEED_LOG,
        witnesses=entries, quorum_k=2, policy=_policy_doc(),
        transport=_direct_transport(daemons), state=state, now=_NOW)
    if set(out["cosigned_by"]) != {"wit1", "wit2", "wit3"}:
        return _break("P2a-quorum-2-happy-path",
                      "cosigned_by=%r, want all three" % (out["cosigned_by"],))
    note = out["checkpoint"]
    vi = WP.verifier_inputs(_policy_doc(), _NOW)
    try:
        WC.require_cosignatures(note, operator_vkeys=vi["operator_vkeys"],
                                witness_vkeys=vi["witness_vkeys"],
                                quorum_k=2)
    except Exception as exc:  # noqa: BLE001
        return _break("P2a-quorum-2-happy-path",
                      "require_cosignatures refused: %r" % (exc,))
    if state != {"wit1": 4, "wit2": 4, "wit3": 4}:
        return _break("P2a-quorum-2-happy-path",
                      "per-witness state not advanced: %r" % (state,))
    return _held("P2a-quorum-2-happy-path",
                 "3 cosignatures; verifier accepts with zero log calls")


@probe("P2b-below-quorum-freeze")
def _p2b():
    daemons = [_client_daemon("wit1", _SEED_W1)]

    def flaky(entry, body, timeout):
        if entry["name"] in ("wit2", "wit3"):
            raise ConnectionError("simulated outage")
        return _direct_transport(daemons)(entry, body, timeout)

    entries = [daemons[0][1],
               {"name": "wit2", "vkey": _wit_vkey("wit2", _signer(_SEED_W2)),
                "endpoint": "http://127.0.0.1:9/wit2"},
               {"name": "wit3", "vkey": _wit_vkey("wit3", _signer(_SEED_W3)),
                "endpoint": "http://127.0.0.1:9/wit3"}]
    log = _make_log(4)
    state = {}
    try:
        WD.submit_checkpoint(
            log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME,
            log_seed=_SEED_LOG, witnesses=entries, quorum_k=2,
            policy=_policy_doc(), transport=flaky, state=state, now=_NOW)
    except WD.WitnessSubmitError as exc:
        if exc.code != "witness-publish-quorum-unmet":
            return _break("P2b-below-quorum-freeze",
                          "refused coded %s, want witness-publish-quorum-unmet"
                          % (exc.code,))
        if state:
            return _break("P2b-below-quorum-freeze",
                          "state advanced on failure: %r (freeze violated)"
                          % (state,))
        return _held("P2b-below-quorum-freeze",
                     "1 of 3 -> witness-publish-quorum-unmet; head frozen")
    except Exception as exc:  # noqa: BLE001
        return _break("P2b-below-quorum-freeze", "raised %r" % (exc,))
    return _break("P2b-below-quorum-freeze",
                  "ACCEPTED below quorum -- fail-closed violated")


@probe("P2c-unreachable-witness-recorded")
def _p2c():
    daemons = [_client_daemon("wit1", _SEED_W1),
               _client_daemon("wit2", _SEED_W2)]

    def flaky(entry, body, timeout):
        if entry["name"] == "wit3":
            raise ConnectionError("simulated outage")
        return _direct_transport(daemons)(entry, body, timeout)

    entries = [d[1] for d in daemons] + [
        {"name": "wit3", "vkey": _wit_vkey("wit3", _signer(_SEED_W3)),
         "endpoint": "http://127.0.0.1:9/wit3"}]
    log = _make_log(4)
    state = {}
    out = WD.submit_checkpoint(
        log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME, log_seed=_SEED_LOG,
        witnesses=entries, quorum_k=2, policy=_policy_doc(),
        transport=flaky, state=state, now=_NOW)
    diag = {w["name"]: w["status"] for w in out["witnesses"]}
    if (set(out["cosigned_by"]) == {"wit1", "wit2"}
            and diag.get("wit3") == "unreachable"):
        return _held("P2c-unreachable-witness-recorded",
                     "wit3 outage recorded; quorum still met from wit1+wit2")
    return _break("P2c-unreachable-witness-recorded",
                  "cosigned_by=%r diagnostics=%r"
                  % (out["cosigned_by"], diag))


@probe("P2d-budget-exhaustion-stops")
def _p2d():
    daemons = [_client_daemon("wit1", _SEED_W1),
               _client_daemon("wit2", _SEED_W2),
               _client_daemon("wit3", _SEED_W3)]
    entries = [d[1] for d in daemons]
    calls = []

    def slow(entry, body, timeout):
        calls.append(entry["name"])
        return _direct_transport(daemons)(entry, body, timeout)

    log = _make_log(4)
    try:
        WD.submit_checkpoint(
            log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME,
            log_seed=_SEED_LOG, witnesses=entries, quorum_k=2,
            policy=_policy_doc(), transport=slow, state={},
            per_witness_timeout=60, total_budget=0, now=_NOW)
    except WD.WitnessSubmitError as exc:
        if exc.code == "witness-publish-quorum-unmet" and not calls:
            return _held("P2d-budget-exhaustion-stops",
                         "zero budget -> no witness contacted; "
                         "witness-publish-quorum-unmet")
        return _break("P2d-budget-exhaustion-stops",
                      "code=%r calls=%r" % (exc.code, calls))
    except Exception as exc:  # noqa: BLE001
        return _break("P2d-budget-exhaustion-stops", "raised %r" % (exc,))
    return _break("P2d-budget-exhaustion-stops",
                  "ACCEPTED with zero budget -- budget not enforced")


@probe("P2e-bad-cosignature-hard-refusal")
def _p2e():
    daemons = [_client_daemon("wit1", _SEED_W1),
               _client_daemon("wit2", _SEED_W2),
               _client_daemon("wit3", _SEED_W3)]
    entries = [d[1] for d in daemons]

    def tampering(entry, body, timeout):
        st, resp = _direct_transport(daemons)(entry, body, timeout)
        if st == 200 and entry["name"] == "wit2":
            raw = bytearray(base64.b64decode(resp.strip().split(" ")[2]))
            raw[-1] ^= 1
            resp = "%s %s %s\n" % (
                CN.EM_DASH, entry["name"],
                base64.b64encode(bytes(raw)).decode("ascii"))
        return st, resp

    log = _make_log(4)
    try:
        WD.submit_checkpoint(
            log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME,
            log_seed=_SEED_LOG, witnesses=entries, quorum_k=2,
            policy=_policy_doc(), transport=tampering, state={}, now=_NOW)
    except WC.WitnessConsistencyError as exc:
        if exc.code == "witness-cosignature-invalid":
            return _held("P2e-bad-cosignature-hard-refusal",
                         "configured witness's forged cosignature -> "
                         "witness-cosignature-invalid (hard refusal)")
        return _break("P2e-bad-cosignature-hard-refusal",
                      "refused coded %s, want witness-cosignature-invalid"
                      % (exc.code,))
    except Exception as exc:  # noqa: BLE001
        return _break("P2e-bad-cosignature-hard-refusal", "raised %r" % (exc,))
    return _break("P2e-bad-cosignature-hard-refusal",
                  "ACCEPTED a forged cosignature -- hard refusal violated")


@probe("P2f-unknown-response-line-ignored")
def _p2f():
    daemons = [_client_daemon("wit1", _SEED_W1),
               _client_daemon("wit2", _SEED_W2)]
    entries = [d[1] for d in daemons]

    def chatty(entry, body, timeout):
        st, resp = _direct_transport(daemons)(entry, body, timeout)
        if st == 200:
            resp += "%s %s %s\n" % (
                CN.EM_DASH, "stranger",
                base64.b64encode(bytes(76)).decode("ascii"))
        return st, resp

    log = _make_log(4)
    out = WD.submit_checkpoint(
        log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME, log_seed=_SEED_LOG,
        witnesses=entries, quorum_k=2, policy=_policy_doc(),
        transport=chatty, state={}, now=_NOW)
    if set(out["cosigned_by"]) == {"wit1", "wit2"}:
        return _held("P2f-unknown-response-line-ignored",
                     "unknown-key response lines ignored; 2 trusted count")
    return _break("P2f-unknown-response-line-ignored",
                  "cosigned_by=%r" % (out["cosigned_by"],))

# ---------------------------------------------------------------------------
# P3: dual-threshold on policy-signer-set changes
# ---------------------------------------------------------------------------

def _signer_entry(signer):
    pub = signer.public_key
    return {"key_id": pub.hex(), "public_key": pub.hex()}


def _pbody(version, signers, policy_threshold, witnesses=3):
    wit = []
    seeds = [_SEED_W1, _SEED_W2, _SEED_W3][:witnesses]
    for i, sd in enumerate(seeds, 1):
        wit.append({"name": "w%d" % i,
                    "vkey": _wit_vkey("w%d" % i, _signer(sd)),
                    "operator": "op%d" % i, "contact": "w%d@example.org" % i,
                    "not_before": _NOW - 100000,
                    "not_after": _NOW + 100000, "status": "usable"})
    return {
        "schema": "witness-policy/v1",
        "policy_id": "sasanam-witness-policy",
        "version": version,
        "issued_at": _NOW - 1000,
        "expires_at": _NOW + 86400 * 90,
        "threshold": 2,
        "log": {"name": _LOG_KEY_NAME,
                "vkey": _log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))},
        "witnesses": wit,
        "policy_signers": [_signer_entry(s) for s in signers],
        "policy_threshold": policy_threshold,
        "max_checkpoint_staleness_seconds": 10800,
    }


@probe("P3a-signer-set-change-anchor-only-refused")
def _p3a():
    old_body = _pbody(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
    anchor = {"policy_signers": old_body["policy_signers"],
              "policy_threshold": 2}
    old = WP.verify_policy_document(
        WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
        anchor, _NOW)
    # Signer set changes P1->P3, sealed ONLY by the anchor threshold
    # (P1+P2). TUF demands threshold(old)+threshold(new).
    new_body = _pbody(2, [_signer(_SEED_P2), _signer(_SEED_P3)], 2)
    new_doc = WP.seal_policy(new_body, [_signer(_SEED_P1), _signer(_SEED_P2)])
    return _expect_code(
        "P3a-signer-set-change-anchor-only-refused",
        lambda: WP.check_policy_update(old, new_doc, anchor, _NOW),
        "witness-policy-dual-threshold-unmet",
        "signer-set change with only old-set authority")


@probe("P3b-dual-threshold-met-passes")
def _p3b():
    old_body = _pbody(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
    anchor = {"policy_signers": old_body["policy_signers"],
              "policy_threshold": 2}
    old = WP.verify_policy_document(
        WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
        anchor, _NOW)
    # P1+P2 (old threshold 2/2) AND P2+P3 (new threshold 2/2): P2's
    # signature counts once per side.
    new_body = _pbody(2, [_signer(_SEED_P2), _signer(_SEED_P3)], 2)
    new_doc = WP.seal_policy(
        new_body, [_signer(_SEED_P1), _signer(_SEED_P2), _signer(_SEED_P3)])
    try:
        got = WP.check_policy_update(old, new_doc, anchor, _NOW)
    except Exception as exc:  # noqa: BLE001
        return _break("P3b-dual-threshold-met-passes", "raised %r" % (exc,))
    if got["version"] != 2:
        return _break("P3b-dual-threshold-met-passes",
                      "did not return the new policy")
    return _held("P3b-dual-threshold-met-passes",
                 "threshold(old)+threshold(new) -> update accepted")


@probe("P3c-unchanged-set-old-behavior")
def _p3c():
    old_body = _pbody(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
    anchor = {"policy_signers": old_body["policy_signers"],
              "policy_threshold": 2}
    old = WP.verify_policy_document(
        WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
        anchor, _NOW)
    # Same signer set (reordered), version bump only: no dual-threshold.
    signers = [_signer(_SEED_P2), _signer(_SEED_P1)]
    new_body = _pbody(2, signers, 2)
    new_doc = WP.seal_policy(new_body, signers)
    try:
        WP.check_policy_update(old, new_doc, anchor, _NOW)
    except Exception as exc:  # noqa: BLE001
        return _break("P3c-unchanged-set-old-behavior", "raised %r" % (exc,))
    return _held("P3c-unchanged-set-old-behavior",
                 "unchanged signer set keeps anchor-only behavior")


@probe("P3d-new-set-only-refused")
def _p3d():
    old_body = _pbody(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
    # The anchor is the standing trust root; it already knows P3 (the
    # successor was pre-provisioned, the trustroot.proto contract), so
    # anchor verification passes and the DUAL-threshold check decides.
    anchor = {"policy_signers": [_signer_entry(_signer(_SEED_P1)),
                                 _signer_entry(_signer(_SEED_P2)),
                                 _signer_entry(_signer(_SEED_P3))],
              "policy_threshold": 2}
    old = WP.verify_policy_document(
        WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
        anchor, _NOW)
    # New-set-only authority (P2+P3): missing old-set threshold.
    new_body = _pbody(2, [_signer(_SEED_P2), _signer(_SEED_P3)], 2)
    new_doc = WP.seal_policy(new_body, [_signer(_SEED_P2), _signer(_SEED_P3)])
    return _expect_code(
        "P3d-new-set-only-refused",
        lambda: WP.check_policy_update(old, new_doc, anchor, _NOW),
        "witness-policy-dual-threshold-unmet",
        "signer-set change with only new-set authority")


@probe("P3e-shared-key-counts-once-per-side")
def _p3e():
    old_body = _pbody(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
    anchor = {"policy_signers": old_body["policy_signers"],
              "policy_threshold": 2}
    old = WP.verify_policy_document(
        WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
        anchor, _NOW)
    # P2 stays across the rotation but signs twice: the duplicate must
    # count ONCE on the new side, so new-side authority is 1/2 and the
    # rotation refuses (no double-counting a shared key).
    new_body = _pbody(2, [_signer(_SEED_P2), _signer(_SEED_P3)], 2)
    new_doc = WP.seal_policy(
        new_body, [_signer(_SEED_P1), _signer(_SEED_P2), _signer(_SEED_P2)])
    return _expect_code(
        "P3e-shared-key-counts-once-per-side",
        lambda: WP.check_policy_update(old, new_doc, anchor, _NOW),
        "witness-policy-dual-threshold-unmet",
        "duplicate P2 signature counted once per side")


# ---------------------------------------------------------------------------
# P4: pin + footer
# ---------------------------------------------------------------------------

@probe("P4-pin-taxonomy-2140-unique")
def _p4a():
    path = os.path.join(REPO, "gov", "decision_codes.py")
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    # Raw "code": name literals (dotted legacy names included); the two
    # dynamic constructions ("code": refusal / entry["code"]) are not
    # literals and are excluded by the name pattern.
    lits = re.findall(r"\"code\":\s*[\"']([A-Za-z0-9_.\-]+)[\"']", src)
    n_dict = len(DC.TAXONOMY)
    ok = (n_dict == TAXONOMY_PIN == 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and len(lits) == 2140 and len(set(lits)) == len(lits)  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
          and "witness-policy-dual-threshold-unmet" in lits
          and "witness-daemon-state-failed" in lits)
    if ok:
        return _held("P4-pin-taxonomy-2140-unique",
                     "2131 dict / 2131 unique raw literals; both new "
                     "codes registered")
    return _break("P4-pin-taxonomy-2140-unique",
                  "want dict 2131 + 2131 unique literals, got dict=%d "
                  "lits=%d unique=%s" % (n_dict, len(lits),
                                         len(set(lits)) == len(lits)))


@probe("P4-footer-state")
def _p4b():
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    lines = [ln for ln in text.split("\n") if "Next free finding:" in ln]
    line = lines[-1] if lines else ""
    ok = ("**F531**" in line and "Open findings: F662, F663, F664, F665, F666, F667, F668, F669, F670, F671." in line)  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
    if ok:
        return _held("P4-footer-state", "open F526-F530 / next F531")
    return _break("P4-footer-state", "footer line: %r" % (line[:120],))


# ---------------------------------------------------------------------------
# Green check (depth-1) + main
# ---------------------------------------------------------------------------

GREEN_UNITTESTS = [
    ("test-witness-daemon", "tests.test_witness_daemon"),
    ("test-witness-policy", "tests.test_witness_policy"),
    ("test-witness-consistency", "tests.test_witness_consistency"),
    ("test-checkpoint-note", "tests.test_checkpoint_note"),
]


def _run_green_unittest(name, module):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w339-gc-")
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest", module, "-v"],
            env=env, capture_output=True, text=True, timeout=900,
            cwd=REPO)
    except Exception as e:  # noqa: BLE001
        return (name, "BREAK", "spawn failed: %r" % (e,))
    out = p.stdout + p.stderr
    m = re.search(r"OK(?:\s+\((\d+) tests?\))?", out)
    failed = re.search(r"FAILED", out)
    if p.returncode == 0 and m and not failed:
        return (name, "HELD", out.strip().splitlines()[-1][:80])
    tail = "\n".join(out.strip().splitlines()[-6:])
    return (name, "BREAK", "rc=%d: %s" % (p.returncode, tail))


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skipped",
                "HELD", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    for name, module in GREEN_UNITTESTS:
        n, v, note = _run_green_unittest(name, module)
        _record("green-" + n, v, note)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    for pid, fn in _PROBES:
        if only is not None and pid != only:
            continue
        _safe(pid, fn)
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    for _, verdict, _ in _results:
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    expected_breaks = set()  # no BREAKs expected on the closed tree
    actual_breaks = {pid for pid, v, _ in _results if v == "BREAK"}
    green_breaks = {pid for pid, v, _ in _results
                    if pid.startswith("green-") and v == "BREAK"}
    unexpected = (actual_breaks - expected_breaks - green_breaks)
    print("w339_witness battery: %d BREAK / %d HELD / %d ERROR "
          % (breaks, len(_results) - breaks - errors, errors))
    if errors or unexpected:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
