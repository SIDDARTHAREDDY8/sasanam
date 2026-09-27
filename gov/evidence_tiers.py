"""Policy-driven retention tiers for the hash-chained audit log.

The base log (``gov/log.py``) is append-only: the operator's only
"retention" options were keeping everything forever or breaking the
chain. This module adds *evidence tiers* -- hot / warm / cold -- so a
deployment can declare retention policy and retire aged entries with
cryptographic continuity instead of silent truncation.

Tier layout (all files live next to the hot log):

- ``actions.jsonl`` (hot): the live ``ActionLog``. Unchanged format;
  entries are never rewritten, sequence numbers never reassigned.
- ``warm.jsonl`` (warm): chained *retirement summaries*. Each summary
  covers one contiguous retired hot range and commits to the EXACT set
  of hot entries it replaces (ordered chained digest over their chain
  hashes + a Merkle root for O(log n) inclusion proofs), plus
  per-entry projections carrying a strict field subset.
- ``cold.jsonl`` (cold): chained *checkpoint anchors*. Each anchor
  commits to a contiguous range of warm summaries (their digests, so a
  hot retirement marker can still resolve its summary after the warm
  prefix is reclaimed) and to the warm chain head at the anchor point.

Continuity argument (what an auditor checks with ``verify_tiered``):

1. The hot suffix is MAC-verified entry by entry from the stored
   ``prev_hash`` links. Retirement markers are appended at the tail
   (the log stays append-only) and are PERMANENT audit records:
   truncation removes only non-marker entries, so the markers'
   ranges tile the complete retired history in-file. A seq gap is
   allowed only when a marker covers it AND the later entry's
   ``prev_hash`` equals the marker's ``truncation_hash`` (the
   cryptographic link across the truncated region); otherwise the
   file fails LOUD.
2. Every marker's ``summary_digest`` equals its warm summary's
   recomputed commitment, and the marker's ``truncation_hash`` equals
   the summary's. Without the HMAC key neither can be forged, so a
   fabricated retirement is detectable.
3. Markers' ranges tile history contiguously from seq 1 (each
   marker's ``first_seq`` is the previous marker's ``last_seq`` + 1).
   A later summary embeds the superseded marker's projection, so the
   chain of custody stays audit-visible even though the marker itself
   is never deleted.
4. Every marker resolves to a warm summary (directly, or transitively
   through a cold anchor's digest list after the warm prefix is
   reclaimed); entries above the retired region must be contiguous,
   so unrecorded deletions fail LOUD.
5. Checkpoint sidecar: the newest checkpoint at/after the live
   suffix's first seq must agree with the entry at that seq (F27/F28
   adapted to the truncated file -- never weakened).

Crash-safe ordering (enforced by ``retire_hot`` / ``retire_warm``):

  summary/anchor written + fsync'd  ->  retirement marker appended
  (chained, checkpointed, audited)  ->  summary re-verified  ->
  hot/warm prefix truncated.

A crash between summary and marker leaves an *orphan summary*: the
next ``retire_*`` reuses it (digest match, no double summary).
A crash between marker and truncation leaves the range present: the
next ``retire_*`` completes the truncation (no second marker).
Re-running a completed retirement is a safe no-op. Retirement is
therefore idempotent.

TTL enforcement: ``retire_*`` refuses to retire entries whose
per-event-class TTL has not expired (evaluated against an injectable
``now`` for determinism). Only the largest TTL-expired *prefix* of the
live entries retires -- chain order is never violated. The retirement
marker records ``evaluated_at`` so TTL compliance re-audits with the
policy.

No new HMAC call sites (wave-70): tier chains reuse
``gov.log._compute_mac``; internal commitments are plain SHA-256
(authenticated transitively by the chained summary/anchor entries).

Ceilings (honest, not findings):
- Prefix-only: one long-TTL entry pins the whole prefix behind it.
- Markers accumulate: one small marker per retirement stays in the hot
  file forever (permanent audit records). The hot file grows O(# of
  retirements), not O(# of retired entries).
- Retired entry *content* is gone from the log; the summary commits to
  what was retired, but inclusion proofs need an operator backup copy.
- Warm projections inherit whatever hot entries exposed; the
  secretish-field denylist is defense-in-depth, not a scrubber --
  secrets do not belong in hot entries (F12 precedent).
- Tamper-EVIDENT, not tamper-proof, against key compromise: the
  operator key could rewrite history, exactly as with the base log.
- ``verify_tiered`` needs the policy to re-audit TTL compliance (the
  TTL table is config, not logged); cryptographic continuity verifies
  without it.
"""

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from gov import log as _log
from gov import merkle as _merkle

TIER_WARM = "warm"
TIER_COLD = "cold"

_WARM_GENESIS = "tier:warm:genesis"
_COLD_GENESIS = "tier:cold:genesis"

# Domain for the ordered commitment over a retired entry set.
_DIGEST_DOMAIN = b"evidence-tier/v1\x00"

RETIRE_EVENT = "evidence_retired"
WARM_RETIRE_EVENT = "warm_retired"

# Warm projections may never introduce these: defense-in-depth so a
# policy cannot accidentally carry secrets/PII into the longer-lived
# warm tier. Exact names are refused; the two substrings catch
# compounds (api_secret_key, db_password, ...). Reserved chain fields
# (seq/ts/event/key_epoch/epoch_id/format_version) contain none of
# these substrings and stay projectable.
_FORBIDDEN_EXACT = frozenset({
    "password", "passwd", "secret", "api_key", "apikey",
    "private_key", "privatekey", "credential", "credentials",
    "ssn", "passphrase", "auth_token", "authtoken", "token",
})
_FORBIDDEN_SUBSTR = ("secret", "password")
# Chain bookkeeping already committed to cryptographically; keeping it
# out of projections avoids a confusing duplicate source of truth.
_FORBIDDEN_PROJECTION = frozenset({"hash", "prev_hash"})
# Reserved fields that are always safe to project (no secret content).
_RESERVED_PROJECTABLE = frozenset({
    "seq", "ts", "event", "key_epoch", "epoch_id", "format_version",
})


class TierError(Exception):
    """Fail-closed refusal: TTL not expired, unverifiable log, crash-
    recovery mismatch, or policy violation. Never silent."""


class RetentionPolicy:
    """Deployment-declared retention tiers. Boundaries are config, not
    code constants.

    ``hot_ttl_by_event``: event name -> TTL seconds for hot entries;
      ``"*"`` is the required default. Entries retire only after
      ``ts + ttl <= now``.
    ``warm_fields_by_event``: event name -> [fields] surviving into
      warm projections; ``"*"`` required. Every list is validated to
      exclude secretish and chain-hash fields at construction.
    ``warm_ttl_seconds``: how long warm summaries live before they may
      be checkpoint-anchored to cold.
    """

    def __init__(self, policy_id, hot_ttl_by_event,
                 warm_fields_by_event, warm_ttl_seconds):
        if not isinstance(policy_id, str) or not policy_id:
            raise ValueError("policy_id must be a non-empty string")
        self.policy_id = policy_id
        self.hot_ttl_by_event = _checked_ttls(hot_ttl_by_event, "hot")
        self.warm_fields_by_event = _checked_fields(warm_fields_by_event)
        try:
            warm_ttl_seconds = float(warm_ttl_seconds)
        except (TypeError, ValueError):
            raise ValueError("warm_ttl_seconds must be a number")
        if warm_ttl_seconds <= 0:
            raise ValueError("warm_ttl_seconds must be > 0")
        self.warm_ttl_seconds = warm_ttl_seconds

    def ttl_for(self, event):
        return self.hot_ttl_by_event.get(event,
                                         self.hot_ttl_by_event["*"])

    def warm_fields_for(self, event):
        return self.warm_fields_by_event.get(event,
                                             self.warm_fields_by_event["*"])

    def __repr__(self):
        return "RetentionPolicy(%r)" % (self.policy_id,)


def _checked_ttls(mapping, name):
    if not isinstance(mapping, dict) or "*" not in mapping:
        raise ValueError("%s_ttl_by_event must be a dict with a '*' "
                         "default" % name)
    out = {}
    for k, v in mapping.items():
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise ValueError("TTL for %r must be a number" % (k,))
        if v <= 0:
            raise ValueError("TTL for %r must be > 0" % (k,))
        out[k] = v
    return out


def _checked_fields(mapping):
    if not isinstance(mapping, dict) or "*" not in mapping:
        raise ValueError("warm_fields_by_event must be a dict with a "
                         "'*' default")
    out = {}
    for event, fields in mapping.items():
        if not isinstance(fields, (list, tuple)) or not fields:
            raise ValueError("warm fields for %r must be a non-empty "
                             "list" % (event,))
        clean = []
        for f in fields:
            if not isinstance(f, str) or not f:
                raise ValueError("warm field names must be non-empty "
                                 "strings")
            low = f.lower()
            if f in _FORBIDDEN_PROJECTION:
                raise ValueError(
                    "warm field %r is chain bookkeeping already committed "
                    "to by digests; projections stay content-focused" % f)
            if low in _FORBIDDEN_EXACT or any(
                    s in low for s in _FORBIDDEN_SUBSTR):
                raise ValueError(
                    "warm field %r looks secretish: refusing to carry it "
                    "into the longer-lived warm tier" % f)
            clean.append(f)
        # TTL compliance must stay re-auditable: every projection
        # carries the event class and timestamp the TTL was evaluated
        # against. A policy that drops either cannot be audited later,
        # so it is refused here, fail-fast.
        for required in ("event", "ts"):
            if required not in clean:
                raise ValueError(
                    "warm fields for %r must include %r (TTL re-audit "
                    "needs the event class and timestamp)" % (event,
                                                              required))
        out[event] = clean
    return out


# ------------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------------

def _parse_ts(ts):
    """Parse an entry ``ts`` (ISO-8601, as written by ``_utcnow``) into
    an aware datetime. Raises TierError fail-closed on garbage: an
    entry whose age cannot be determined is never retired."""
    try:
        dt = datetime.fromisoformat(str(ts))
    except (ValueError, TypeError):
        raise TierError("unparsable entry ts %r: refusing to evaluate "
                        "TTL" % (ts,))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _coerce_now(now):
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return _parse_ts(now)


def _hot_path(log_path):
    return Path(log_path)


def _warm_path(log_path):
    return Path(log_path).parent / "warm.jsonl"


def _cold_path(log_path):
    return Path(log_path).parent / "cold.jsonl"


def _read_hot_entries(log_path):
    """Hot entries via the guarded reader (keeps F163/F164 read audit)."""
    return _log.read_entries(str(_hot_path(log_path)))


def _read_tier_entries(tier_path):
    """Raw JSONL read for warm/cold files (no exchange guards: derived
    files, written only by retire_*). Malformed lines fail closed."""
    p = Path(tier_path)
    if not p.exists():
        return []
    out = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8")
                                 .splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            raise TierError("tier file %s line %d is not valid JSON; "
                            "failing closed" % (p.name, lineno))
        if not isinstance(obj, dict):
            raise TierError("tier file %s line %d is not an object; "
                            "failing closed" % (p.name, lineno))
        out.append(obj)
    return out


def _is_hot_marker(entry):
    return (isinstance(entry, dict)
            and entry.get("event") == RETIRE_EVENT
            and entry.get("tier") == "hot")


def _is_warm_marker(entry):
    return (isinstance(entry, dict)
            and entry.get("kind") == WARM_RETIRE_EVENT
            and entry.get("tier") == TIER_WARM)


def _atomic_rewrite(path, lines):
    """Crash-safe file rewrite: write temp + fsync + atomic replace."""
    p = Path(path)
    tmp = p.parent / (p.name + ".tmp-retire")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join(lines))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


# ------------------------------------------------------------------
# Commitments over retired sets
# ------------------------------------------------------------------

def _entry_digest_chain(first_seq, entry_hashes):
    """Ordered chained digest committing to the EXACT retired set:
    range start + every entry hash in order. Any drop, reorder, or
    substitution changes the digest."""
    d = hashlib.sha256(_DIGEST_DOMAIN
                       + b"first_seq=" + str(first_seq).encode("utf-8")).digest()
    for h in entry_hashes:
        d = hashlib.sha256(_DIGEST_DOMAIN + d + b"\x00"
                           + str(h).encode("utf-8")).digest()
    return d.hex()


def _retired_leaf(entry):
    """Merkle leaf for a retired hot entry: canonical content + the
    stored chain hash (mirrors ``_leaf_input``'s rationale)."""
    return _merkle.leaf_hash(
        _log._canonical(entry).encode("utf-8") + b"\x00"
        + str(entry["hash"]).encode("utf-8"))


def prove_inclusion_in_summary(entry, index, entries):
    """O(log n) inclusion proof that ``entry`` (at 0-based ``index``)
    belongs to the retired set ``entries``. The caller holds the
    entries (operator backup); the summary holds the trusted root."""
    leaves = [_retired_leaf(e) for e in entries]
    return _merkle.inclusion_proof(leaves, index)


def verify_inclusion_in_summary(entry, index, proof, summary):
    """Check an inclusion proof against a warm summary's Merkle root.
    Never raises on malformed inputs (fail-closed False)."""
    try:
        leaf = _retired_leaf(entry)
        root = bytes.fromhex(summary["merkle_root"])
        return bool(_merkle.verify_inclusion(
            leaf, index, proof, root, summary["count"]))
    except Exception:
        return False


def _warm_projection(entry, policy):
    """Strict field subset of the hot entry per policy. Never adds
    fields; never carries secretish names (enforced at policy build)."""
    fields = policy.warm_fields_for(entry.get("event"))
    return {f: entry[f] for f in fields if f in entry}


# ------------------------------------------------------------------
# Summary / anchor construction
# ------------------------------------------------------------------

def _summary_commitment(summary):
    """Deterministic commitment over a warm summary's content fields
    (chain envelope excluded so the digest is stable and purely about
    WHAT was retired)."""
    body = {k: v for k, v in summary.items()
            if k not in ("hash", "summary_digest", "seq", "ts",
                         "prev_hash", "tier", "format_version",
                         "key_epoch")}
    return hashlib.sha256(
        _DIGEST_DOMAIN
        + json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, default=str).encode("utf-8")).hexdigest()


def _build_warm_summary(prefix_entries, policy, now):
    """Build the (yet-unchained) warm summary for a retired hot
    prefix. Deterministic given entries + policy + now (``ts`` is set
    at append time and excluded from the commitment)."""
    now = _coerce_now(now)
    first = prefix_entries[0]["seq"]
    summary = {
        "kind": "retirement_summary",
        "policy_id": policy.policy_id,
        "evaluated_at": now.isoformat(),
        "first_seq": first,
        "last_seq": prefix_entries[-1]["seq"],
        "count": len(prefix_entries),
        "entry_digest_chain": _entry_digest_chain(
            first, [e["hash"] for e in prefix_entries]),
        "merkle_root": _merkle.tree_root(
            [_retired_leaf(e) for e in prefix_entries]).hex(),
        "truncation_hash": prefix_entries[-1]["hash"],
        "projections": [_warm_projection(e, policy)
                        for e in prefix_entries],
    }
    summary["summary_digest"] = _summary_commitment(summary)
    return summary


def _build_cold_anchor(prefix_entries, policy, now):
    """Checkpoint anchor committing to a retired warm prefix. Carries
    the covered summaries' digests so hot markers still resolve after
    the warm prefix is reclaimed."""
    now = _coerce_now(now)
    digests = []
    for e in prefix_entries:
        if e.get("kind") == "retirement_summary":
            digests.append(e["summary_digest"])
    anchor = {
        "kind": "cold_anchor",
        "policy_id": policy.policy_id,
        "evaluated_at": now.isoformat(),
        "first_warm_seq": prefix_entries[0]["seq"],
        "last_warm_seq": prefix_entries[-1]["seq"],
        "count": len(prefix_entries),
        "summary_digests": digests,
        "merkle_root": _merkle.tree_root(
            [bytes.fromhex(d) for d in digests]).hex() if digests
        else _merkle.EMPTY_ROOT.hex(),
        "entry_digest_chain": _entry_digest_chain(
            prefix_entries[0]["seq"],
            [e["hash"] for e in prefix_entries]),
        "warm_head_hash": prefix_entries[-1]["hash"],
    }
    anchor["anchor_digest"] = _summary_commitment(anchor)
    return anchor


# ------------------------------------------------------------------
# Tier-file chained append (reuses gov.log's keyed MAC -- wave-70)
# ------------------------------------------------------------------

def _tier_genesis(tier):
    return _WARM_GENESIS if tier == TIER_WARM else _COLD_GENESIS


def _tier_append(tier_path, tier, payload):
    """Append ``payload`` to a tier file as a chained entry. The chain
    is HMAC'd with the deployment key via ``_compute_mac`` (no new
    keyed-MAC site); the ``tier`` field in the canonical form gives
    domain separation from the hot chain and across tiers."""
    key, epoch = _log._active_key()
    p = Path(tier_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _log._append_locked(str(p)):
        tail_seq, prev = 0, _tier_genesis(tier)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                tail = json.loads(line)
                tail_seq, prev = tail["seq"], tail["hash"]
        entry = {"tier": tier, "seq": tail_seq + 1, "ts": _log._utcnow(),
                 "prev_hash": prev,
                 "format_version": _log.FORMAT_VERSION,
                 "key_epoch": epoch}
        entry.update(payload)
        entry["hash"] = _log._compute_mac(key, epoch, prev,
                                         _log._canonical(entry))
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=True, default=str)
                    + "\n")
            f.flush()
            os.fsync(f.fileno())
    return entry


def _append_warm_summary(warm_path, summary):
    return _tier_append(warm_path, TIER_WARM, summary)


def _append_cold_anchor(cold_path, anchor):
    return _tier_append(cold_path, TIER_COLD, anchor)


# ------------------------------------------------------------------
# Retirement selection
# ------------------------------------------------------------------

def _retired_until(entries, is_marker, last_key):
    """Highest seq covered by any retirement marker (0 when never
    retired). Entries at or below this are retired history (or
    superseded markers); only entries above it are live."""
    last = 0
    for e in entries:
        if is_marker(e):
            last = max(last, e.get(last_key, 0))
    return last


def _eligible_prefix_for_retire(log_path, policy, now=None):
    """Largest TTL-expired prefix of the live hot entries. Markers are
    always eligible (superseded metadata retires with the next range).
    Raises TierError if an entry's age cannot be determined
    (fail-closed: keep evidence)."""
    now = _coerce_now(now)
    entries = _read_hot_entries(log_path)
    retired = _retired_until(entries, _is_hot_marker, "last_seq")
    cands = sorted((e for e in entries if e.get("seq", 0) > retired),
                   key=lambda e: e["seq"])
    prefix = []
    for e in cands:
        if _is_hot_marker(e):
            prefix.append(e)
            continue
        ttl = policy.ttl_for(e.get("event"))
        if _parse_ts(e.get("ts")) + timedelta(seconds=ttl) <= now:
            prefix.append(e)
        else:
            break
    return prefix


def _eligible_warm_prefix(log_path, policy, now=None):
    """Largest warm-TTL-expired prefix of the live warm summaries."""
    now = _coerce_now(now)
    entries = _read_tier_entries(_warm_path(log_path))
    retired = _retired_until(entries, _is_warm_marker, "last_warm_seq")
    cands = sorted((e for e in entries if e.get("seq", 0) > retired),
                   key=lambda e: e["seq"])
    prefix = []
    for e in cands:
        if _is_warm_marker(e):
            prefix.append(e)
            continue
        if e.get("kind") != "retirement_summary":
            break  # unknown entry shape: stop, do not retire past it
        if _parse_ts(e.get("ts")) + timedelta(
                seconds=policy.warm_ttl_seconds) <= now:
            prefix.append(e)
        else:
            break
    return prefix


# ------------------------------------------------------------------
# Marker append + truncation
# ------------------------------------------------------------------

def _append_retirement_marker(log_path, policy, prefix_entries,
                              warm_entry, now):
    """Append the audited ``evidence_retired`` event to the hot log via
    the normal ActionLog path (chained, MAC'd, checkpointed). The act
    of retiring is itself audited."""
    now = _coerce_now(now)
    marker = {
        "event": RETIRE_EVENT,
        "tier": "hot",
        "tier_policy": policy.policy_id,
        "first_seq": prefix_entries[0]["seq"],
        "last_seq": prefix_entries[-1]["seq"],
        "count": len(prefix_entries),
        "warm_seq": warm_entry["seq"],
        "summary_digest": warm_entry["summary_digest"],
        "truncation_hash": prefix_entries[-1]["hash"],
        "evaluated_at": now.isoformat(),
    }
    return _log.ActionLog(str(_hot_path(log_path))).append(marker)


def _append_warm_retire_marker(log_path, policy, prefix_entries,
                               cold_entry, now):
    now = _coerce_now(now)
    marker = {
        "kind": WARM_RETIRE_EVENT,
        "tier_policy": policy.policy_id,
        "first_warm_seq": prefix_entries[0]["seq"],
        "last_warm_seq": prefix_entries[-1]["seq"],
        "count": len(prefix_entries),
        "cold_seq": cold_entry["seq"],
        "anchor_digest": cold_entry["anchor_digest"],
        "warm_head_hash": prefix_entries[-1]["hash"],
        "evaluated_at": now.isoformat(),
    }
    return _tier_append(_warm_path(log_path), TIER_WARM, marker)


def _prune_and_truncate(data_path, first_seq, last_seq,
                        sidecar_keep_above, is_marker=None):
    """Remove the retired seq range [first_seq..last_seq] from a JSONL
    file and prune stale checkpoint-sidecar lines, atomically per
    file. Retirement markers inside the range are PERMANENT audit
    records and are kept; only non-marker entries are removed. The new
    retirement marker (appended at the tail, seq > last_seq) survives.
    Must run with the caller holding the append lock for data_path."""
    p = Path(data_path)
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = []
    for line in lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            seq = obj.get("seq", 0)
        except ValueError:
            raise TierError("unparsable line during truncation; refusing "
                            "to rewrite the log")
        in_range = isinstance(seq, int) and first_seq <= seq <= last_seq
        if in_range and is_marker is not None and is_marker(obj):
            in_range = False  # markers are permanent audit records
        if not in_range:
            kept.append(line if line.endswith("\n") else line + "\n")
    if not kept:
        raise TierError("truncation would empty the file: the retirement "
                        "marker must survive; refusing")
    _atomic_rewrite(p, kept)
    cp = p.parent / "checkpoints.jsonl"
    if sidecar_keep_above is not None and cp.exists():
        cp_lines = cp.read_text(encoding="utf-8").splitlines(
            keepends=True)
        kept_cp = []
        for line in cp_lines:
            if not line.strip():
                continue
            try:
                seq = json.loads(line).get("seq", 0)
            except ValueError:
                raise TierError("unparsable checkpoint line during "
                                "prune; refusing")
            if not isinstance(seq, int) or seq > sidecar_keep_above:
                kept_cp.append(line if line.endswith("\n")
                               else line + "\n")
        _atomic_rewrite(cp, kept_cp)


def _complete_hot_truncation(log_path, marker):
    """Finish a retirement: remove the retired hot range so only live
    entries and the tail marker(s) remain."""
    p = _hot_path(log_path)
    with _log._append_locked(str(p)):
        # Re-validate under the lock: the range must still be present.
        entries = _read_hot_entries(log_path)
        seqs = {e.get("seq") for e in entries}
        want = set(range(marker["first_seq"], marker["last_seq"] + 1))
        if not want <= seqs:
            raise TierError("retired range %s..%s not fully present; "
                            "refusing to truncate"
                            % (marker["first_seq"], marker["last_seq"]))
        _prune_and_truncate(p, marker["first_seq"], marker["last_seq"],
                            marker["last_seq"], _is_hot_marker)


def _complete_warm_truncation(log_path, marker):
    p = _warm_path(log_path)
    with _log._append_locked(str(p)):
        entries = _read_tier_entries(p)
        seqs = {e.get("seq") for e in entries}
        want = set(range(marker["first_warm_seq"],
                         marker["last_warm_seq"] + 1))
        if not want <= seqs:
            raise TierError("anchored warm range not fully present; "
                            "refusing to truncate")
        _prune_and_truncate(p, marker["first_warm_seq"],
                            marker["last_warm_seq"], None,
                            _is_warm_marker)


# ------------------------------------------------------------------
# retire_hot / retire_warm (idempotent, crash-safe ordering)
# ------------------------------------------------------------------

def _find_orphan_summary(warm_path, summary):
    """Recovery case B: a summary for this exact range+digest already
    exists (crash between summary-append and marker-append). Reuse it;
    never double-summarize."""
    for e in _read_tier_entries(warm_path):
        if (e.get("kind") == "retirement_summary"
                and e.get("first_seq") == summary["first_seq"]
                and e.get("last_seq") == summary["last_seq"]
                and e.get("summary_digest") == summary["summary_digest"]):
            return e
    return None


def _assert_summary_covers(warm_path, warm_entry, prefix_entries):
    """Re-verify the covering summary BEFORE any destruction: the
    summary must exist, chain-verify, and recompute to the same
    commitment over the exact prefix being retired."""
    entries = _read_tier_entries(warm_path)
    key, epoch = _log._active_key()
    prev = _WARM_GENESIS
    found = None
    for e in entries:
        if not isinstance(e.get("seq"), int) or e["seq"] <= 0:
            raise TierError("warm chain seq break; refusing")
        mac = _log._compute_mac(key, e.get("key_epoch"), prev,
                                _log._canonical(e))
        if not hmac.compare_digest(e.get("hash", ""), mac):
            raise TierError("warm chain MAC mismatch at warm seq %s; "
                            "refusing to retire" % e.get("seq"))
        prev = e["hash"]
        if e["seq"] == warm_entry["seq"]:
            found = e
    if found is None:
        raise TierError("covering warm summary vanished; refusing")
    if _summary_commitment(found) != warm_entry["summary_digest"]:
        raise TierError("covering warm summary commitment mismatch; "
                        "refusing")
    if found["summary_digest"] != _build_warm_summary(
            prefix_entries,
            _policy_for(found),
            found["evaluated_at"])["summary_digest"]:
        raise TierError("covering warm summary does not match the "
                        "retired entries; refusing")
    return True


def _policy_for(summary):
    """Rebuild a policy shell for commitment recomputation. Only the
    deterministic commitment inputs matter (policy_id, field lists);
    TTLs are irrelevant here."""
    fields = {k for p in summary["projections"] for k in p.keys()}
    fields |= {"event", "ts"}  # the audited floor; entries missing
    # one simply project the other (matches the original projection)
    return RetentionPolicy(
        policy_id=summary["policy_id"],
        hot_ttl_by_event={"*": 1},
        warm_fields_by_event={"*": sorted(fields)},
        warm_ttl_seconds=1)


def retire_hot(log_path, policy, *, now=None):
    """Retire the TTL-expired hot prefix per policy.

    Crash-safe ordering: warm summary (fsync) -> chained+audited
    retirement marker -> summary re-verification -> prefix truncation.
    Idempotent: orphan summaries are reused, interrupted truncations
    are completed, completed retirements no-op.

    Raises TierError fail-closed (unverifiable log, TTL unmet is a
    no-op return, never a partial retire).
    """
    if not isinstance(policy, RetentionPolicy):
        raise TypeError("policy must be a RetentionPolicy")
    now = _coerce_now(now)
    verdict = verify_tiered(log_path, policy)
    if not verdict["ok"]:
        raise TierError("refusing to retire from an unverifiable log: %s"
                        % verdict["error"])
    warm_path = _warm_path(log_path)

    # Recovery case A: marker appended, crash before truncation.
    entries = _read_hot_entries(log_path)
    if entries and _is_hot_marker(entries[-1]):
        m = entries[-1]
        seqs = {e.get("seq") for e in entries}
        if set(range(m["first_seq"], m["last_seq"] + 1)) <= seqs:
            _complete_hot_truncation(log_path, m)
            return {"retired": m["count"], "first_seq": m["first_seq"],
                    "last_seq": m["last_seq"], "warm_seq": m["warm_seq"],
                    "marker_seq": m["seq"], "recovered": True,
                    "truncated": True}

    prefix = _eligible_prefix_for_retire(log_path, policy, now)
    if not prefix or not any(not _is_hot_marker(e) for e in prefix):
        # Nothing TTL-expired, or only superseded markers remain: a
        # markers-only "retirement" would just mint a new marker for
        # the old one forever. Safe no-op.
        return {"retired": 0, "recovered": False, "truncated": False}

    # Crash-safe ordering: the covering summary FIRST.
    summary = _build_warm_summary(prefix, policy, now)
    warm_entry = _find_orphan_summary(warm_path, summary)
    recovered = warm_entry is not None
    if warm_entry is None:
        warm_entry = _append_warm_summary(warm_path, summary)

    # The retirement itself is audited as a chained event.
    marker = _append_retirement_marker(log_path, policy, prefix,
                                       warm_entry, now)

    # Never destroy without a verified covering summary.
    _assert_summary_covers(warm_path, warm_entry, prefix)
    _complete_hot_truncation(log_path, marker)
    return {"retired": len(prefix), "first_seq": prefix[0]["seq"],
            "last_seq": prefix[-1]["seq"], "warm_seq": warm_entry["seq"],
            "summary_digest": warm_entry["summary_digest"],
            "marker_seq": marker["seq"], "recovered": recovered,
            "truncated": True}


def retire_warm(log_path, policy, *, now=None):
    """Checkpoint-anchor the warm-TTL-expired warm prefix to cold and
    reclaim it. Mirrors retire_hot's crash-safe ordering and
    idempotency; the cold anchor carries the covered summaries'
    digests so hot markers keep resolving after reclamation."""
    if not isinstance(policy, RetentionPolicy):
        raise TypeError("policy must be a RetentionPolicy")
    now = _coerce_now(now)
    verdict = verify_tiered(log_path, policy)
    if not verdict["ok"]:
        raise TierError("refusing to anchor from an unverifiable tier: "
                        "%s" % verdict["error"])
    warm_path = _warm_path(log_path)
    cold_path = _cold_path(log_path)

    entries = _read_tier_entries(warm_path)
    if entries and _is_warm_marker(entries[-1]):
        m = entries[-1]
        seqs = {e.get("seq") for e in entries}
        if set(range(m["first_warm_seq"],
                     m["last_warm_seq"] + 1)) <= seqs:
            _complete_warm_truncation(log_path, m)
            return {"anchored": m["count"],
                    "first_warm_seq": m["first_warm_seq"],
                    "last_warm_seq": m["last_warm_seq"],
                    "cold_seq": m["cold_seq"], "recovered": True,
                    "truncated": True}

    prefix = _eligible_warm_prefix(log_path, policy, now)
    if not prefix or not any(not _is_warm_marker(e) for e in prefix):
        return {"anchored": 0, "recovered": False, "truncated": False}

    anchor = _build_cold_anchor(prefix, policy, now)
    cold_entry = None
    for e in _read_tier_entries(cold_path):
        if (e.get("kind") == "cold_anchor"
                and e.get("first_warm_seq") == anchor["first_warm_seq"]
                and e.get("last_warm_seq") == anchor["last_warm_seq"]
                and e.get("anchor_digest") == anchor["anchor_digest"]):
            cold_entry = e
            break
    if cold_entry is None:
        cold_entry = _append_cold_anchor(cold_path, anchor)

    marker = _append_warm_retire_marker(log_path, policy, prefix,
                                        cold_entry, now)
    _complete_warm_truncation(log_path, marker)
    return {"anchored": len(prefix),
            "first_warm_seq": prefix[0]["seq"],
            "last_warm_seq": prefix[-1]["seq"],
            "cold_seq": cold_entry["seq"], "recovered": False,
            "truncated": True}


# ------------------------------------------------------------------
# Tier-aware verification (never raises on content problems)
# ------------------------------------------------------------------

def _verify_entry_chain(entries, genesis_label, is_marker,
                        range_keys=None, head_hash_key=None):
    """Verify MAC chain + seq continuity + key_epoch labels over an
    entry list. Returns (ok, error, first_seq).

    ``genesis_label`` is the expected ``prev_hash`` of the first entry
    (``_log.GENESIS`` / tier genesis). When the file's first entry is a
    retirement marker, the genesis check is skipped: the head was
    legitimately retired and the marker's ``prev_hash`` is bound by the
    marker<->summary cross-check instead. The MAC is always verified
    against the stored ``prev_hash``.

    ``range_keys``/``head_hash_key`` make the check retirement-aware:
    retired markers are kept in-file (permanent audit records), so a
    seq gap between consecutive entries is allowed only when a
    retirement marker in the file covers every missing seq
    (``range_keys=(first_key,last_key)``) AND the later entry's
    ``prev_hash`` equals that marker's ``head_hash_key``
    (``truncation_hash``/``warm_head_hash``) -- the cryptographic link
    across the truncated region. Without them, any gap fails.
    """
    try:
        key, epoch = _log._active_key()
    except Exception as e:
        return False, "no key available for verification: %s" % e, None
    prev = None
    first_seq = None
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            return False, "entry %d is not an object" % i, None
        if e.get("format_version") != _log.FORMAT_VERSION:
            return False, "unsupported format_version %r at entry %d" % (
                e.get("format_version"), i), None
        seq = e.get("seq")
        if not isinstance(seq, int) or seq <= 0:
            return False, "bad seq %r at entry %d" % (seq, i), None
        if first_seq is None:
            first_seq = seq
            if not is_marker(e) and e.get("prev_hash") != genesis_label:
                return False, "first entry prev_hash != %s with no " \
                               "retirement marker: head truncated " \
                               "without a covering summary" % (
                                   genesis_label,), None
        elif seq != entries[i - 1]["seq"] + 1:
            ok, err, link = _check_seq_gap(
                entries, i, is_marker, range_keys, head_hash_key)
            if not ok:
                return False, err, None
            if e.get("prev_hash") != link:
                return False, "chain link broken across retirement gap " \
                               "at seq %s" % seq, None
        elif e.get("prev_hash") != prev:
            return False, "chain link broken at seq %s" % seq, None
        label = e.get("key_epoch")
        if label != epoch:
            return False, "key_epoch label mismatch at seq %s" % seq, \
                None
        mac = _log._compute_mac(key, label, e["prev_hash"],
                                _log._canonical(e))
        if not hmac.compare_digest(e.get("hash", ""), mac):
            return False, "MAC mismatch at seq %s (history rewritten " \
                           "or wrong key)" % seq, None
        prev = e["hash"]
    return True, None, first_seq


def _check_seq_gap(entries, i, is_marker, range_keys, head_hash_key):
    """Allow a seq gap only across a cryptographically linked
    retirement. Returns (ok, err, expected_prev_hash)."""
    prev_e, cur_e = entries[i - 1], entries[i]
    if range_keys is None or head_hash_key is None:
        return False, "sequence gap: expected seq %d, got %r " \
                       "(entries deleted or reordered)" % (
                           prev_e["seq"] + 1, cur_e["seq"]), None
    fkey, lkey = range_keys
    gap_start, gap_end = prev_e["seq"] + 1, cur_e["seq"] - 1
    for m in entries:
        if (is_marker(m) and isinstance(m.get(fkey), int)
                and isinstance(m.get(lkey), int)
                and m[fkey] <= gap_start and m[lkey] >= gap_end):
            return True, None, m.get(head_hash_key)
    return False, "sequence gap: seqs %d..%d have no covering " \
                   "retirement (entries deleted without a summary)" % (
                       gap_start, gap_end), None


def _verify_hot_sidecar(log_path, entries, first_seq):
    """F27/F28 adapted: the newest checkpoint at/after the live
    suffix's first seq must exist and agree with the entry there."""
    p = Path(log_path)
    cp_path = p.parent / "checkpoints.jsonl"
    key, epoch = _log._active_key()
    cps, n_bad = [], 0
    missing = not cp_path.exists()
    if not missing:
        try:
            text = cp_path.read_text(encoding="utf-8")
        except OSError as e:
            return False, "checkpoint sidecar unreadable: %s" % e
        cps, n_bad = _log._parse_sidecar_lines(text.splitlines())
    if entries:
        if missing:
            return False, "checkpoint sidecar missing for a non-empty " \
                           "log: tail truncation cannot be ruled out"
        if n_bad:
            return False, "checkpoint sidecar corrupt (%d bad lines)" \
                           % n_bad
        live = [c for c in cps if c["seq"] >= first_seq]
        if not live:
            return False, "no checkpoint anchors the live suffix " \
                           "(first seq %s)" % first_seq
        latest = max(live, key=lambda c: c["seq"])
        if latest.get("key_epoch") != epoch:
            return False, "checkpoint key_epoch label mismatch"
        expect = _log._checkpoint_mac(
            key, latest["key_epoch"], latest["seq"], latest["hash"],
            _log._pin_gen_of(latest))
        if not hmac.compare_digest(latest.get("mac", ""), expect):
            return False, "checkpoint MAC invalid"
        last_seq = entries[-1]["seq"]
        if last_seq < latest["seq"]:
            return False, "tail truncation: log ends at seq %d but " \
                           "newest checkpoint is at seq %d" % (
                               last_seq, latest["seq"])
        # (seq -> entry map: the file may have retirement gaps, so a
        # seq offset is not a list index)
        by_seq = {e["seq"]: e for e in entries}
        if by_seq.get(latest["seq"], {}).get("hash") != latest["hash"]:
            return False, "checkpoint mismatch at seq %d " \
                           "(log rewritten after checkpoint)" % latest[
                               "seq"]
    elif n_bad:
        return False, "checkpoint sidecar corrupt for an empty log"
    elif cps:
        # F187: an empty hot log must never sit under valid checkpoints.
        # Retirement always leaves the permanent marker behind, so
        # checkpoints beyond an empty log mean the marker (or the
        # entries themselves) were deleted after checkpointing.
        latest = max(cps, key=lambda c: c["seq"])
        return False, ("empty log but checkpoint sidecar anchors seq %d "
                       "(tail truncation or retirement-marker deletion)"
                       % latest["seq"])
    return True, None


def _check_marker_contiguity(entries, is_marker, first_key, last_key,
                             label):
    """Markers must tile retired history contiguously: the first
    in-file marker's range may start past 1 (earlier markers retired
    into later summaries -- the warm/cold tiling still starts at 1),
    but each later marker must abut the previous
    (``first == prev.last + 1``). Live entries (past the retired
    region) must start exactly where the retired ranges end; anything
    else is an unrecorded deletion."""
    markers = sorted((e for e in entries if is_marker(e)),
                     key=lambda e: e["seq"])
    if not markers:
        if entries and entries[0].get("seq") != 1:
            return False, "log starts at seq %s with no retirement " \
                           "marker: truncation without a covering " \
                           "summary" % entries[0]["seq"], []
        return True, None, []
    prev_last = None
    for m in markers:
        if prev_last is not None and m[first_key] != prev_last + 1:
            return False, "%s ranges not contiguous: marker seq %s " \
                           "starts at %s, previous range ended at %s" % (
                               label, m["seq"], m[first_key],
                               prev_last), []
        prev_last = m[last_key]
    # Every seq above the retired region must be present: markers live
    # in the same seq space (they are appended at the tail), so they
    # count toward contiguity. Entries still inside the retired region
    # are pending truncation (crash-transient), which is allowed.
    present_above = [e["seq"] for e in entries if e["seq"] > prev_last]
    if present_above and min(present_above) != prev_last + 1:
        return False, "entries above the retired region start at seq " \
                       "%s, expected %s (unrecorded deletion)" % (
                           min(present_above), prev_last + 1), []
    return True, None, markers


def _resolve_warm_summary(warm_by_seq, cold_anchors, marker):
    """Resolve a hot marker's covering summary: directly from warm, or
    transitively through the cold anchor that reclaimed it."""
    wseq = marker["warm_seq"]
    if wseq in warm_by_seq:
        return warm_by_seq[wseq], "warm"
    for a in cold_anchors:
        if a["first_warm_seq"] <= wseq <= a["last_warm_seq"]:
            idx = wseq - a["first_warm_seq"]
            digests = a.get("summary_digests", [])
            if 0 <= idx < len(digests) and digests[idx] == marker[
                    "summary_digest"]:
                return a, "cold"
            return None, "digest-mismatch"
    return None, "missing"


def verify_tiered(log_path, policy=None):
    """Verify a (possibly retired) tiered log. Never raises on content
    problems: returns a verdict dict with ok=False and a loud error.

    With ``policy`` given, TTL compliance of each retirement is
    re-audited (``evaluated_at`` vs the policy's TTL table); without
    it, only cryptographic continuity is checked."""
    verdict = {"ok": False, "error": None, "hot": {}, "warm": {},
               "cold": {}, "retirements": [],
               "orphan_warm_summaries": []}
    try:
        _verify_tiered_inner(log_path, policy, verdict)
    except TierError as e:
        verdict["ok"] = False
        verdict["error"] = str(e)
    except Exception as e:  # fail-closed, loud, never silent
        verdict["ok"] = False
        verdict["error"] = "verifier internal error: %r" % (e,)
    return verdict


def _verify_tiered_inner(log_path, policy, verdict):
    def fail(msg):
        raise TierError(msg)

    # ---- hot suffix ----
    try:
        hot = _read_hot_entries(log_path)
    except Exception as e:
        fail("cannot read hot log: %s" % e)
    if not Path(log_path).exists():
        fail("log file does not exist")
    ok, err, first_seq = _verify_entry_chain(hot, _log.GENESIS,
                                             _is_hot_marker,
                                             ("first_seq", "last_seq"),
                                             "truncation_hash")
    if not ok:
        fail("hot chain: %s" % err)
    verdict["hot"] = {"entries": len(hot), "first_seq": first_seq}
    # F187: always consult the checkpoint sidecar, even for an empty hot
    # log. Post-retirement the hot file always retains at least the
    # permanent retirement marker, so an empty hot file under valid
    # checkpoints means the marker (or the entries) were deleted.
    ok, err = _verify_hot_sidecar(log_path, hot, first_seq)
    if not ok:
        fail("hot checkpoints: %s" % err)
    ok, err, markers = _check_marker_contiguity(
        hot, _is_hot_marker, "first_seq", "last_seq", "hot retirement")
    if not ok:
        fail(err)

    # ---- warm file ----
    warm_path = _warm_path(log_path)
    try:
        warm = _read_tier_entries(warm_path)
    except TierError as e:
        fail("warm: %s" % e)
    for e in warm:
        if e.get("tier") != TIER_WARM:
            fail("warm file holds a non-warm entry at seq %s" % e.get(
                "seq"))
    ok, err, wfirst = _verify_entry_chain(warm, _WARM_GENESIS,
                                          _is_warm_marker,
                                          ("first_warm_seq",
                                           "last_warm_seq"),
                                          "warm_head_hash")
    if not ok:
        fail("warm chain: %s" % err)
    verdict["warm"] = {"entries": len(warm), "first_seq": wfirst}
    ok, err, wmarkers = _check_marker_contiguity(
        warm, _is_warm_marker, "first_warm_seq", "last_warm_seq",
        "warm anchor")
    if not ok:
        fail(err)

    # ---- cold file ----
    cold_path = _cold_path(log_path)
    try:
        cold = _read_tier_entries(cold_path)
    except TierError as e:
        fail("cold: %s" % e)
    for e in cold:
        if e.get("tier") != TIER_COLD:
            fail("cold file holds a non-cold entry at seq %s" % e.get(
                "seq"))
        if e.get("kind") != "cold_anchor":
            fail("cold file holds a non-anchor entry at seq %s" % e.get(
                "seq"))
    ok, err, cfirst = _verify_entry_chain(cold, _COLD_GENESIS,
                                          lambda e: False)
    if not ok:
        fail("cold chain: %s" % err)
    if cold and cfirst != 1:
        fail("cold chain does not start at genesis (seq 1)")
    # Cold anchors tile warm history contiguously from 1.
    prev_last = 0
    for a in cold:
        if a["first_warm_seq"] != prev_last + 1:
            fail("cold anchors not contiguous: anchor seq %s covers "
                 "warm %s.., previous ended at %s"
                 % (a["seq"], a["first_warm_seq"], prev_last))
        prev_last = a["last_warm_seq"]
        # The embedded digest list must recompute to the Merkle root.
        digests = a.get("summary_digests", [])
        if digests:
            root = _merkle.tree_root(
                [bytes.fromhex(d) for d in digests]).hex()
        else:
            root = _merkle.EMPTY_ROOT.hex()
        if root != a.get("merkle_root"):
            fail("cold anchor seq %s: digest list does not recompute "
                 "to the stored Merkle root" % a["seq"])
    verdict["cold"] = {"entries": len(cold)}

    # ---- cross-links: hot markers -> warm summaries ----
    # (resolved before the tiling check so crash-orphaned summaries --
    # superseded by a wider summary after a crash -- are tolerated and
    # merely reported rather than breaking verification)
    warm_by_seq = {e["seq"]: e for e in warm
                   if e.get("kind") == "retirement_summary"}
    referenced = set()
    resolved_ranges = []  # (first_seq, last_seq) per marker, in order
    for m in markers:
        summary, where = _resolve_warm_summary(warm_by_seq, cold, m)
        if summary is None:
            fail("retirement marker seq %s references warm_seq %s "
                 "which has no covering summary (%s): entries "
                 "deleted without a summary" % (m["seq"],
                                                m["warm_seq"], where))
        if where == "warm":
            if (summary["first_seq"] != m["first_seq"]
                    or summary["last_seq"] != m["last_seq"]):
                fail("marker seq %s range != summary warm_seq %s range"
                     % (m["seq"], m["warm_seq"]))
            if summary["summary_digest"] != m["summary_digest"]:
                fail("marker seq %s summary_digest != warm summary "
                     "digest" % m["seq"])
            if _summary_commitment(summary) != m["summary_digest"]:
                fail("warm summary seq %s commitment recompute "
                     "mismatch (summary tampered)" % summary["seq"])
            if summary["truncation_hash"] != m["truncation_hash"]:
                fail("marker seq %s truncation_hash != summary "
                     "truncation_hash" % m["seq"])
            referenced.add(m["warm_seq"])
            # TTL re-audit when the policy is available.
            if policy is not None:
                _reaudit_ttl(summary, m, policy, fail)
        # Cold-resolved: the marker is MAC-protected and its
        # summary_digest is pinned inside the cold anchor's digest
        # list (checked by _resolve_warm_summary); the marker's range
        # fields ride under the same MAC.
        resolved_ranges.append((m["first_seq"], m["last_seq"]))
        verdict["retirements"].append(
            {"marker_seq": m["seq"], "warm_seq": m["warm_seq"],
             "range": [m["first_seq"], m["last_seq"]],
             "summary_digest": m["summary_digest"], "via": where})

    # The marker-resolved retirement ranges must tile hot history from
    # seq 1 (whether the covering summary is still warm or already
    # cold-anchored). Crash-orphaned summaries are audit-visible but
    # not part of the canonical history: tolerated, reported.
    prev_last = 0
    for first, last in resolved_ranges:
        if first != prev_last + 1:
            fail("retirement ranges not contiguous: range starts at "
                 "%s, previous ended at %s" % (first, prev_last))
        prev_last = last
    for s in warm:
        if (s.get("kind") == "retirement_summary"
                and s["seq"] not in referenced):
            verdict["orphan_warm_summaries"].append(s["seq"])

    # ---- cross-links: warm markers -> cold anchors ----
    for wm in wmarkers:
        matches = [a for a in cold
                   if a["seq"] == wm["cold_seq"]]
        if not matches:
            fail("warm marker seq %s references cold_seq %s with no "
                 "covering anchor" % (wm["seq"], wm["cold_seq"]))
        a = matches[0]
        if (a["first_warm_seq"] != wm["first_warm_seq"]
                or a["last_warm_seq"] != wm["last_warm_seq"]
                or a["anchor_digest"] != wm["anchor_digest"]
                or a["warm_head_hash"] != wm["warm_head_hash"]):
            fail("warm marker seq %s does not match cold anchor %s"
                 % (wm["seq"], a["seq"]))

    verdict["ok"] = True
    verdict["error"] = None
    return verdict


def _reaudit_ttl(summary, marker, policy, fail):
    """Re-audit TTL compliance of a retirement against the policy.

    The summary's projections carry each entry's event class and ts;
    the marker carries evaluated_at. Every retired entry must satisfy
    ts + ttl(event) <= evaluated_at. Markers (superseded metadata)
    are exempt."""
    evaluated = _parse_ts(marker["evaluated_at"])
    for p in summary.get("projections", []):
        # The retirement audit event itself is metadata, not evidence:
        # exempt from TTL (its eligibility is structural, enforced at
        # retire time by _eligible_prefix_for_retire, not by TTL).
        if p.get("event") == RETIRE_EVENT:
            continue
        ttl = policy.ttl_for(p.get("event"))
        if _parse_ts(p.get("ts")) + timedelta(seconds=ttl) > evaluated:
            fail("TTL re-audit: retirement marker seq %s covers an "
                 "entry (event %r) whose TTL had not expired at %s"
                 % (marker["seq"], p.get("event"),
                    marker["evaluated_at"]))
