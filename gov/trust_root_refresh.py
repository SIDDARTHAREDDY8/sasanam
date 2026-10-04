"""Versioned trust-root chain with freshness signal (wave-318 lane 3).

The offline verifier's trust root is a static compiled-in document. This
module gives it a rotation story, following the wave-317 prospectus
(``research/prospecting/w317_evidence_next_steps.md`` direction item 3):

* versioned trust-root chain (TUF root pattern): each root is pinned by
  (content-hash, source-commit, review-date);
* rotation is a policy ceremony: a new root is adopted only through a
  rotation record signed by the OLD root's keys -- never silently;
* a short-lived freshness statement (TUF timestamp pattern) the verifier
  checks at verification time;
* chain expiry evaluated at the bundle TIMESTAMP's time, chain-wide
  (CVE-2026-24122 negative rule);
* witness receipts bound to (artifact digest, signature, key)
  (CVE-2026-22703 negative rule).

Stdlib only. Pure functions: every time is caller-supplied (no clock
reads, no I/O), so the module is deterministic and testable with fixed
clocks. Signatures are Ed25519 over domain-separated PAE bytes.

Conventions follow ``gov/evidence_verify_offline.py``: signers expose
``.keyid()`` (method) and ``.sign(bytes)``; ``gov.ed25519.verify``
returns True/False and never raises (the wave-243 lesson: check the
return with ``is True``).
"""

import base64
import binascii
import hashlib
import importlib.util
import json
import os
from datetime import datetime, timezone


def _load_ed25519():
    """Load the vendored Ed25519 by file path.

    ``from gov import ed25519`` would execute ``gov/__init__.py``, whose
    transitive imports include ``urllib`` (via executor) -- network-capable
    code in the import closure. This module is imported by the offline
    verifier, whose contract is zero network; loading ``gov/ed25519.py``
    directly (the ``evidence_verify_offline`` pattern) keeps the true
    import closure socket-free (it imports only hashlib+secrets).
    Fail-closed: a missing/unreadable file raises TrustRootError, never
    a silent fallback.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "ed25519.py")
    try:
        spec = importlib.util.spec_from_file_location(
            "sasanam_standalone_ed25519_trr", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise TrustRootError("trust-root-chain-malformed",
                             "cannot load ed25519 from %r: %s" % (path, exc))
    return module


_ed25519 = None


def _ed():
    global _ed25519
    if _ed25519 is None:
        _ed25519 = _load_ed25519()
    return _ed25519

# Chain document kind tags.
ROTATION_RECORD_TYPE = "trust-root-rotation"
FRESHNESS_STATEMENT_TYPE = "trust-root-freshness"

# Domain separators for the three signed record kinds.
PAE_DOMAIN_ROTATION = b"TRR1-rotation:"
PAE_DOMAIN_FRESHNESS = b"TRR1-freshness:"
PAE_DOMAIN_RECEIPT = b"TRR1-receipt:"

# TUF timestamp pattern: the freshness signal is short-lived.
DEFAULT_FRESHNESS_MAX_AGE_SECONDS = 86400
# Small allowance for clock skew on ceremony/review dates.
REVIEW_SKEW_SECONDS = 300

# Rotation is authorized by the old root at its threshold. The trust
# root's policy-auth convention is threshold 1 (see
# ``evidence_verify_offline._authenticate_policy``); the ceremony keeps it.
ROTATION_THRESHOLD = 1


class TrustRootError(Exception):
    """Typed trust-root failure. ``code`` is one of the ``trust-root-*``
    decision codes; ``detail`` is the human-readable cause."""

    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super(TrustRootError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))


# ---------------------------------------------------------------------------
# Canonical bytes, hashing, time.
# ---------------------------------------------------------------------------

def canonical(obj):
    """Deterministic canonical JSON bytes (sort_keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")) \
        .encode("utf-8")


def content_hash(root_doc):
    """SHA-256 hex of the canonical root doc: the content pin."""
    return hashlib.sha256(canonical(root_doc)).hexdigest()


def _parse_time(value, where):
    """Parse RFC3339 (or pass through an aware datetime)."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise TrustRootError(
                "trust-root-chain-malformed",
                "%s: bad time %r" % (where, value))
    else:
        raise TrustRootError("trust-root-chain-malformed",
                             "%s: bad time %r" % (where, value))
    if dt.tzinfo is None:
        raise TrustRootError("trust-root-chain-malformed",
                             "%s: naive time refused %r" % (where, value))
    return dt


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_root_doc_shape(root_doc):
    """Validate a ``{version, policy_keys}`` root doc; return keyid->pubkey."""
    if not isinstance(root_doc, dict):
        raise TrustRootError("trust-root-chain-malformed",
                             "root doc must be an object")
    keys = root_doc.get("policy_keys")
    if not isinstance(keys, list) or not keys:
        raise TrustRootError("trust-root-chain-malformed",
                             "root doc needs a non-empty policy_keys list")
    out = {}
    for k in keys:
        if not isinstance(k, dict):
            raise TrustRootError("trust-root-chain-malformed",
                                 "policy key must be an object")
        kid = k.get("keyid")
        pub = k.get("pubkey_hex")
        if not isinstance(kid, str) or not kid:
            raise TrustRootError("trust-root-chain-malformed",
                                 "policy key needs a keyid")
        if kid in out:
            raise TrustRootError("trust-root-chain-malformed",
                                 "duplicate policy keyid %r" % (kid,))
        if not isinstance(pub, str):
            raise TrustRootError("trust-root-chain-malformed",
                                 "policy key %r needs pubkey_hex" % (kid,))
        try:
            raw = bytes.fromhex(pub)
        except (ValueError, binascii.Error):
            raw = None
        if raw is None or len(raw) != 32:
            raise TrustRootError("trust-root-chain-malformed",
                                 "policy key %r has a bad pubkey" % (kid,))
        out[kid] = pub.lower()
    return out


def _check_pin_fields(source_commit, review_date, where):
    if not isinstance(source_commit, str) or not source_commit.strip():
        raise TrustRootError("trust-root-chain-malformed",
                             "%s: source_commit must be a non-empty string"
                             % (where,))
    _parse_time(review_date, where + ".review_date")


# ---------------------------------------------------------------------------
# Chain entries.
# ---------------------------------------------------------------------------

def make_entry(root_doc, *, chain_version, source_commit, review_date,
               valid_from=None, valid_until=None):
    """Build a chain entry pinning ``root_doc`` by content hash.

    ``chain_version`` is the strictly N+1 link number. ``source_commit``
    and ``review_date`` are the vendored-root pin fields; ``valid_from`` /
    ``valid_until`` bound the entry's authority window (None = open).
    """
    _check_root_doc_shape(root_doc)
    if not isinstance(chain_version, int) or chain_version < 1:
        raise TrustRootError("trust-root-chain-malformed",
                             "chain_version must be a positive int")
    _check_pin_fields(source_commit, review_date, "entry")
    if valid_from is not None:
        _parse_time(valid_from, "entry.valid_from")
    if valid_until is not None:
        _parse_time(valid_until, "entry.valid_until")
    if valid_from is not None and valid_until is not None \
            and _parse_time(valid_from, "entry.valid_from") > \
            _parse_time(valid_until, "entry.valid_until"):
        raise TrustRootError("trust-root-chain-malformed",
                             "valid_from is after valid_until")
    return {
        "chain_version": chain_version,
        "root_doc": root_doc,
        "content_hash": content_hash(root_doc),
        "source_commit": source_commit,
        "review_date": review_date
        if isinstance(review_date, str) else _iso(review_date),
        "valid_from": valid_from
        if valid_from is None or isinstance(valid_from, str)
        else _iso(valid_from),
        "valid_until": valid_until
        if valid_until is None or isinstance(valid_until, str)
        else _iso(valid_until),
        "rotation_record": None,
    }


def genesis_entry(root_doc, *, source_commit, review_date,
                  valid_from=None, valid_until=None):
    """Wrap an existing trust root as chain v1.

    The compiled-in SHA-256 pin remains the out-of-band anchor; the chain
    extends it, never replaces it.
    """
    return make_entry(root_doc, chain_version=1,
                      source_commit=source_commit, review_date=review_date,
                      valid_from=valid_from, valid_until=valid_until)


# ---------------------------------------------------------------------------
# Rotation ceremony.
# ---------------------------------------------------------------------------

def _rotation_signing_bytes(record):
    return PAE_DOMAIN_ROTATION + canonical(record)


def _keyid_of(signer):
    kid = getattr(signer, "keyid", None)
    return kid() if callable(kid) else kid


def _verify_threshold_signatures(envelope, signing_bytes, keys, where, code):
    """Verify every listed signature; require threshold from ``keys``."""
    if not isinstance(envelope, dict):
        raise TrustRootError(code, "%s: record envelope must be an object"
                             % (where,))
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise TrustRootError(code, "%s: no signatures" % (where,))
    good = 0
    for i, s in enumerate(sigs):
        if not isinstance(s, dict):
            raise TrustRootError(code, "%s: signature %d malformed"
                                 % (where, i))
        kid = s.get("keyid")
        sig_b64 = s.get("sig")
        pub = keys.get(kid) if isinstance(kid, str) else None
        if pub is None:
            raise TrustRootError(code, "%s: signature %d by unpinned key %r"
                                 % (where, i, kid))
        try:
            sig = base64.b64decode(sig_b64)
        except (binascii.Error, ValueError, TypeError):
            raise TrustRootError(code, "%s: signature %d not base64"
                                 % (where, i))
        try:
            ok = _ed().verify(bytes.fromhex(pub), signing_bytes, sig)
        except Exception:  # noqa: BLE001 -- malformed input fails closed
            ok = False
        if ok is not True:
            raise TrustRootError(code, "%s: signature %d does not verify"
                                 % (where, i))
        good += 1
    if good < ROTATION_THRESHOLD:
        raise TrustRootError(code, "%s: %d/%d threshold not met"
                             % (where, good, ROTATION_THRESHOLD))
    return good


def build_rotation_record(old_entry, new_root_doc, *, source_commit,
                          review_date, valid_from=None, valid_until=None,
                          signers):
    """Draft the rotation ceremony record adopting ``new_root_doc``.

    The record is signed by ``signers`` (holders of the OLD root's keys)
    over domain-separated bytes. It carries the new root's full pin
    (content hash, source commit, review date, validity window) so the
    ceremony -- not the entry alone -- is authoritative.
    """
    _check_root_doc_shape(new_root_doc)
    _check_pin_fields(source_commit, review_date, "rotation")
    record = {
        "type": ROTATION_RECORD_TYPE,
        "from_version": old_entry["chain_version"],
        "to_version": old_entry["chain_version"] + 1,
        "new_content_hash": content_hash(new_root_doc),
        "source_commit": source_commit,
        "review_date": review_date
        if isinstance(review_date, str) else _iso(review_date),
        "valid_from": valid_from
        if valid_from is None or isinstance(valid_from, str)
        else _iso(valid_from),
        "valid_until": valid_until
        if valid_until is None or isinstance(valid_until, str)
        else _iso(valid_until),
    }
    signing = _rotation_signing_bytes(record)
    sigs = []
    for s in signers:
        sigs.append({"keyid": _keyid_of(s),
                     "sig": base64.b64encode(s.sign(signing)).decode("ascii")})
    return {"record": record, "signatures": sigs}


def _window_covers(entry, ts):
    start = entry.get("valid_from")
    end = entry.get("valid_until")
    start_dt = _parse_time(start, "entry.valid_from") \
        if start is not None else _parse_time(entry["review_date"],
                                              "entry.review_date")
    if ts < start_dt:
        return False
    if end is not None and ts > _parse_time(end, "entry.valid_until"):
        return False
    return True


def _check_rotation_record(prev_entry, envelope, entry, now):
    """Validate the ceremony that adopted ``entry`` from ``prev_entry``."""
    if not isinstance(envelope, dict):
        raise TrustRootError("trust-root-silent-swap",
                             "v%d adopted without a rotation record: "
                             "silent root swap refused"
                             % (entry["chain_version"],))
    record = envelope.get("record")
    if not isinstance(record, dict) \
            or record.get("type") != ROTATION_RECORD_TYPE:
        raise TrustRootError("trust-root-rotation-invalid",
                             "not a trust-root-rotation record")
    if record.get("from_version") != prev_entry["chain_version"] \
            or record.get("to_version") != entry["chain_version"]:
        raise TrustRootError(
            "trust-root-rotation-invalid",
            "version link %r -> %r does not match chain %d -> %d"
            % (record.get("from_version"), record.get("to_version"),
               prev_entry["chain_version"], entry["chain_version"]))
    if record.get("new_content_hash") != entry["content_hash"] \
            or entry["content_hash"] != content_hash(entry["root_doc"]):
        raise TrustRootError("trust-root-rotation-invalid",
                             "rotation record does not bind the new root doc")
    # The ceremony is authoritative for the pin fields: the entry must
    # match the record exactly.
    for field in ("source_commit", "review_date", "valid_from",
                  "valid_until"):
        if record.get(field) != entry.get(field):
            raise TrustRootError(
                "trust-root-rotation-invalid",
                "entry %s %r != rotation record %r"
                % (field, entry.get(field), record.get(field)))
    review_dt = _parse_time(record["review_date"], "rotation.review_date")
    skew = REVIEW_SKEW_SECONDS
    if (review_dt - now).total_seconds() > skew:
        raise TrustRootError("trust-root-rotation-invalid",
                             "rotation review date is in the future")
    # CVE-2026-24122, chain-wide: the ceremony must have happened while
    # the SIGNING root was valid -- at the record's time, not now.
    if not _window_covers(prev_entry, review_dt):
        raise TrustRootError(
            "trust-root-rotation-invalid",
            "rotation reviewed %s, outside the signing root v%d validity "
            "window (checked at the record's time)"
            % (record["review_date"], prev_entry["chain_version"]))
    prev_keys = _check_root_doc_shape(prev_entry["root_doc"])
    _verify_threshold_signatures(envelope, _rotation_signing_bytes(record),
                              prev_keys, "rotation",
                              "trust-root-rotation-invalid")


def adopt_rotation(chain, rotation_record, new_root_doc, *, now):
    """Append the rotated root to ``chain``; return the NEW chain list.

    The input chain is never mutated. ``now`` is required (no wall-clock
    default: the module never reads the clock). Raises
    ``trust-root-rotation-invalid`` when the ceremony does not check out.
    """
    if not isinstance(chain, list) or not chain:
        raise TrustRootError("trust-root-chain-malformed",
                             "chain must be a non-empty list")
    if not isinstance(rotation_record, dict) \
            or not isinstance(rotation_record.get("record"), dict):
        raise TrustRootError("trust-root-rotation-invalid",
                             "rotation record envelope malformed")
    record = rotation_record["record"]
    now_dt = _parse_time(now, "now")
    prev = chain[-1]
    try:
        entry = make_entry(
            new_root_doc, chain_version=prev["chain_version"] + 1,
            source_commit=record.get("source_commit"),
            review_date=record.get("review_date"),
            valid_from=record.get("valid_from"),
            valid_until=record.get("valid_until"))
    except TrustRootError as exc:
        # A malformed ceremony record is a rotation failure, not a chain
        # shape failure: keep the code on the ceremony.
        raise TrustRootError("trust-root-rotation-invalid", exc.detail)
    entry["rotation_record"] = rotation_record
    _check_rotation_record(prev, rotation_record, entry, now_dt)
    return list(chain) + [entry]


# ---------------------------------------------------------------------------
# Freshness signal.
# ---------------------------------------------------------------------------

def _freshness_signing_bytes(statement):
    return PAE_DOMAIN_FRESHNESS + canonical(statement)


def build_freshness_statement(entry, *, issued_at, signers):
    """Issue the TUF-timestamp-pattern freshness signal for ``entry``."""
    _parse_time(issued_at, "freshness.issued_at")
    statement = {
        "type": FRESHNESS_STATEMENT_TYPE,
        "chain_version": entry["chain_version"],
        "issued_at": issued_at if isinstance(issued_at, str)
        else _iso(issued_at),
    }
    signing = _freshness_signing_bytes(statement)
    return {
        "statement": statement,
        "signatures": [
            {"keyid": _keyid_of(s),
             "sig": base64.b64encode(s.sign(signing)).decode("ascii")}
            for s in signers
        ],
    }


def _check_freshness(tip, freshness, now, max_age_seconds):
    """The freshness signal must be present, fresh, and tip-signed."""
    def _stale(detail):
        raise TrustRootError("trust-root-stale-freshness", detail)

    if not isinstance(freshness, dict):
        _stale("no freshness signal supplied")
    statement = freshness.get("statement")
    if not isinstance(statement, dict) \
            or statement.get("type") != FRESHNESS_STATEMENT_TYPE:
        _stale("not a trust-root-freshness statement")
    if statement.get("chain_version") != tip["chain_version"]:
        _stale("freshness names v%r, chain tip is v%d"
               % (statement.get("chain_version"), tip["chain_version"]))
    try:
        issued = _parse_time(statement.get("issued_at"),
                             "freshness.issued_at")
    except TrustRootError as exc:
        _stale(exc.detail)
    if (issued - now).total_seconds() > REVIEW_SKEW_SECONDS:
        _stale("freshness issued in the future")
    age = (now - issued).total_seconds()
    if age > max_age_seconds:
        _stale("freshness is %.0f seconds old (max %d)"
               % (age, max_age_seconds))
    tip_keys = _check_root_doc_shape(tip["root_doc"])
    try:
        _verify_threshold_signatures(freshness,
                                  _freshness_signing_bytes(statement),
                                  tip_keys, "freshness",
                                  "trust-root-stale-freshness")
    except TrustRootError as exc:
        _stale(exc.detail)


# ---------------------------------------------------------------------------
# Chain verification.
# ---------------------------------------------------------------------------

def _check_chain_shape(chain):
    if not isinstance(chain, list) or not chain:
        raise TrustRootError("trust-root-chain-malformed",
                             "chain must be a non-empty list")
    entries = []
    for i, e in enumerate(chain):
        where = "chain[%d]" % i
        if not isinstance(e, dict):
            raise TrustRootError("trust-root-chain-malformed",
                                 "%s must be an object" % (where,))
        _check_root_doc_shape(e.get("root_doc"))
        ver = e.get("chain_version")
        if not isinstance(ver, int) or ver < 1:
            raise TrustRootError("trust-root-chain-malformed",
                                 "%s: bad chain_version" % (where,))
        if e.get("content_hash") != content_hash(e["root_doc"]):
            raise TrustRootError("trust-root-chain-malformed",
                                 "%s: content hash does not match root doc"
                                 % (where,))
        _check_pin_fields(e.get("source_commit"), e.get("review_date"),
                          where)
        if i > 0 and ver != entries[i - 1]["chain_version"] + 1:
            raise TrustRootError(
                "trust-root-chain-malformed",
                "%s: versions must be strictly consecutive" % (where,))
        entries.append(e)
    if entries[0]["chain_version"] != 1:
        raise TrustRootError("trust-root-chain-malformed",
                             "chain must start at v1 (genesis)")
    return entries


def verify_chain_structure(chain, *, freshness, now,
                            max_age_seconds=
                            DEFAULT_FRESHNESS_MAX_AGE_SECONDS):
    """Validate the chain and its freshness signal; return the tip entry.

    Checks: shape, content hashes, strictly consecutive versions, every
    rotation record (ceremony valid, signed by the previous root, reviewed
    inside the previous root's window -- CVE-2026-24122 chain-wide), and
    freshness at ``now``. Expiry at the bundle timestamp is NOT checked
    here -- see :func:`check_expiry`.
    """
    now_dt = _parse_time(now, "now")
    entries = _check_chain_shape(chain)
    for i in range(1, len(entries)):
        _check_rotation_record(entries[i - 1],
                               entries[i].get("rotation_record"),
                               entries[i], now_dt)
    tip = entries[-1]
    _check_freshness(tip, freshness, now_dt, max_age_seconds)
    return tip


def check_expiry(tip, bundle_timestamp):
    """Refuse when the tip was not valid at the bundle timestamp's time.

    CVE-2026-24122: expiry is evaluated at the TIMESTAMP's time, not at
    verification time. A bundle timestamped inside the window still
    verifies after the root expired (designed grace); a bundle
    timestamped outside it is refused.
    """
    bts = _parse_time(bundle_timestamp, "bundle_timestamp")
    if not _window_covers(tip, bts):
        raise TrustRootError(
            "trust-root-expired",
            "trust root v%d not valid at bundle time %s"
            % (tip["chain_version"], _iso(bts)))
    return tip


def verify_chain(chain, *, freshness, bundle_timestamp, now,
                 max_age_seconds=DEFAULT_FRESHNESS_MAX_AGE_SECONDS):
    """Full check: structure + freshness + expiry at the timestamp's time.

    Returns the chain tip entry (its ``root_doc`` is the authority).
    """
    tip = verify_chain_structure(chain, freshness=freshness, now=now,
                                 max_age_seconds=max_age_seconds)
    return check_expiry(tip, bundle_timestamp)


# ---------------------------------------------------------------------------
# Witness receipt binding (CVE-2026-22703 primitive).
# ---------------------------------------------------------------------------

def bind_receipt(*, artifact_digest, signature_hex, signer_pubkey_hex,
                 receipt, witness_pubkey_hex):
    """Refuse unless ``receipt`` binds (digest, signature, key).

    A valid receipt alone is never enough: the receipt must name the
    artifact digest, the signature, and the signer's pubkey presented by
    the caller, AND its witness signature over the triple must verify
    under ``witness_pubkey_hex``. Any mismatch -> ``trust-root-receipt-unbound``.
    """
    def _unbound(detail):
        raise TrustRootError("trust-root-receipt-unbound", detail)

    if not isinstance(receipt, dict):
        _unbound("receipt must be an object")
    for field, expected in (("artifact_digest", artifact_digest),
                            ("signature", signature_hex),
                            ("signer_pubkey", signer_pubkey_hex)):
        actual = receipt.get(field)
        if not isinstance(actual, str) or not isinstance(expected, str) \
                or actual.lower() != expected.lower():
            _unbound("receipt %s does not match the presented %s"
                     % (field, field))
    for hex_field, value in (("witness_pubkey_hex", witness_pubkey_hex),
                             ("signer_pubkey", signer_pubkey_hex)):
        try:
            raw = bytes.fromhex(value)
        except (ValueError, binascii.Error, TypeError):
            raw = None
        if raw is None or len(raw) != 32:
            _unbound("bad %s" % (hex_field,))
    body = canonical({"artifact_digest": receipt["artifact_digest"].lower(),
                      "signature": receipt["signature"].lower(),
                      "signer_pubkey": receipt["signer_pubkey"].lower()})
    try:
        sig = base64.b64decode(receipt.get("witness_sig"))
    except (binascii.Error, ValueError, TypeError):
        _unbound("receipt witness_sig is not base64")
    try:
        ok = _ed().verify(bytes.fromhex(witness_pubkey_hex),
                            PAE_DOMAIN_RECEIPT + body, sig)
    except Exception:  # noqa: BLE001 -- malformed input fails closed
        ok = False
    if ok is not True:
        _unbound("receipt witness signature does not verify")
    return True
