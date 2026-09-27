"""Offline evidence bundle exporter (attenu-guard adaptation).

Takes the hash-chained audit log (``gov/log.py``) plus an anchor receipt
(``gov/anchor_adapter.py``) and produces a self-contained bundle directory
an auditor can verify WITHOUT our engine, using the standalone verifier
at ``tools/offline-verify`` (stdlib only).

Design adapted from attenu-io/attenu-guard
(``src/attenu_guard/evidence.py``, Apache-2.0): a hash-chained ledger plus
a signed anchor, verified from the bundle alone against three invariants
(integrity / monotonicity / containment), plus a ``redaction_report``
disclosing what was withheld. Adapted to our ledger format:

* attenu-guard chains delegation records; we chain audit-log entries
  (seq/ts/prev_hash/hash preserved as data, plus our own export chain
  because the source HMAC chain needs the operator's key — see below).
* attenu-guard's monotonicity is "delegation child ⊆ parent"; ours is
  "seqs strictly increase by 1".
* attenu-guard's containment is "every allow within held authority";
  ours is "the window [from_seq, to_seq] is fully present, no gaps".
* attenu-guard's JCS canonicalization: our canonical form
  (``json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True,
  default=str)``) is JCS-shaped for the JSON subset we emit (the same
  form ``gov/evidence_verify.py`` relies on); credited here rather than
  vendored twice.
* attenu-guard's receipt shape: our anchor receipt IS the signed receipt
  (``gov/anchor_adapter.py`` — statement + Ed25519 log signature +
  Merkle inclusion proof); the bundle binds the export tip through it.

Why an export chain instead of reusing the source HMAC chain: the source
chain is ``HMAC-SHA256(operator_key, ...)`` — an offline auditor must not
hold the operator key, so they cannot recompute it. The export chain is
deliberately UNKEYED ``SHA-256`` over exactly the bytes shipped in the
bundle; its security comes from the ANCHOR (the Ed25519-signed receipt
commits to the chain tip), not from key secrecy. An attacker who rewrites
the ledger can recompute the unkeyed chain (Kerckhoffs) but cannot forge
the anchor signature — the battery ``evals/offline_bundle_adversarial.py``
pins this (b1/b4).

Per-entry authorship without the HMAC key: entries carry Ed25519
``ed_sig``/``sig_key_id`` (``gov/log.py`` P2, ``gov/signing.py``). The
exporter requires every unredacted entry to be signed under a single
entry-signer key (fail-closed otherwise); the verifier checks each
signature. Redacted entries drop their (now-unverifiable) signatures and
MUST be listed in the redaction report with their redacted fields — a
silently-redacted entry has neither a valid signature nor a report
listing, so the lie is caught (battery b5).

v1 constraints (deliberate, documented):
* The source log must verify (``gov.log.verify_chain``) at export time;
  the exporter refuses to render from a broken chain.
* One entry-signer key per bundle (windows spanning a rotation are
  exported per-epoch).
* Field redaction cannot touch chain bookkeeping (seq/ts/prev_hash/hash/
  format_version/key_epoch/epoch_id) or the signature envelope.
* The anchor adapter must expose its public key (``FakeLogAdapter`` does)
  or the caller passes ``anchor_pubkey=`` explicitly.

$0 spend, synthetic/local only. No network.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from gov import log as _log
from gov.safeguard_bundle import (
    compute_bundle_digest as _compute_bundle_digest,
)

BUNDLE_FORMAT = "offline-evidence-bundle/1.0"
EXPORTER_VERSION = "1.0.0"

#: Domain separation for the export hash chain (unkeyed SHA-256; security
#: via the anchor signature, see module docstring).
EXPORT_CHAIN_DOMAIN = b"offline-export-chain/v1\x00"
EXPORT_GENESIS = "EXPORT-GENESIS"

#: Fields managed by the exporter or load-bearing for chain integrity.
#: Redaction requests naming any of these fail closed.
_RESERVED_FIELDS = frozenset({
    "seq", "ts", "prev_hash", "hash", "format_version",
    "key_epoch", "epoch_id", "ed_sig", "sig_key_id",
    "export_hash", "redacted",
})

REQUIRED_FILES = (
    "VERSION",
    "ledger.jsonl",
    "manifest.json",
    "anchor_receipt.json",
    "REDACTION_REPORT.txt",
    "BUNDLE_DIGEST.sha256",
)


class OfflineBundleError(Exception):
    """The bundle cannot be exported honestly (fail-closed)."""


def _canonical(obj):
    """JCS-shaped canonical bytes (see module docstring)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _chain_hash(prev_export_hash, canonical_entry):
    """One export-chain step (unkeyed; anchor-backed, see docstring)."""
    return hashlib.sha256(
        EXPORT_CHAIN_DOMAIN
        + prev_export_hash.encode("utf-8") + b"\x00"
        + canonical_entry).hexdigest()


def _redaction_digest(redaction_report):
    return hashlib.sha256(_canonical(redaction_report)).hexdigest()


def _anchor_input(manifest):
    """The exact dict the anchor receipt's statement commits to.

    Binds the ledger tip, the window, the bundle id, AND the redaction
    digest — so the "what was withheld" disclosure is tamper-evident,
    not just the ledger.
    """
    return {
        "bundle_id": manifest["bundle_id"],
        "ledger_digest": manifest["ledger_digest"],
        "window": manifest["window"],
        "redaction_digest": _redaction_digest(
            manifest["redaction_report"]),
    }


def _anchor_statement_hash(anchor_input):
    """Recompute the anchor statement hash (mirrors
    ``gov/anchor_adapter.py::bundle_statement``)."""
    from gov import anchor_adapter as _aa
    return _aa.bundle_statement(anchor_input)["bundle_hash"]


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def export_offline_bundle(log_path, bundle_dir, adapter, *,
                          from_seq=None, to_seq=None,
                          redact_fields=(), bundle_id=None,
                          entry_signer_pubkey=None,
                          anchor_pubkey=None):
    """Export an offline-verifiable evidence bundle.

    ``log_path``: the audit-log JSONL file. ``adapter``: a
    ``gov/anchor_adapter.py::AnchorAdapter`` used to anchor the export
    tip (no network in v1 — ``FakeLogAdapter``). ``redact_fields``:
    field names dropped from every entry (never chain bookkeeping).
    ``entry_signer_pubkey``: the 32-byte Ed25519 pubkey that signed the
    window's entries (REQUIRED — the bundle must be self-contained).

    Returns the bundle directory path. Raises ``OfflineBundleError``
    fail-closed on any honesty violation.
    """
    log_path = str(log_path)
    redact_fields = tuple(redact_fields)
    bad = [f for f in redact_fields if f in _RESERVED_FIELDS]
    if bad:
        raise OfflineBundleError(
            "redact_fields names reserved chain fields: %s" % (bad,))

    # 1. The source log must verify — never export from a broken chain.
    ok, broken, _count = _log.verify_chain(log_path)
    if not ok:
        raise OfflineBundleError(
            "source log does not verify (broken at seq %r): refusing "
            "to export" % (broken,))

    entries = _log.read_entries(log_path)
    if not entries:
        raise OfflineBundleError("source log is empty: nothing to export")

    # 2. Window selection.
    lo = from_seq if from_seq is not None else entries[0]["seq"]
    hi = to_seq if to_seq is not None else entries[-1]["seq"]
    window = [e for e in entries if lo <= e["seq"] <= hi]
    if not window:
        raise OfflineBundleError(
            "window %d..%d selects no entries" % (lo, hi))
    seqs = [e["seq"] for e in window]
    if seqs != list(range(lo, hi + 1)):
        raise OfflineBundleError(
            "source log has a gap inside window %d..%d: refusing to "
            "export a gapped window" % (lo, hi))

    # 3. Per-entry signatures: required, single key (v1 constraint),
    # and VALID under the supplied pubkey — fail-closed at export, not
    # just at verification (a bundle with bad signatures would be
    # doomed; refuse to produce it).
    for e in window:
        if not e.get("ed_sig") or not e.get("sig_key_id"):
            raise OfflineBundleError(
                "entry seq %d has no per-entry Ed25519 signature: v1 "
                "requires a signed source log (see module docstring)"
                % (e["seq"],))
    key_ids = {e["sig_key_id"] for e in window}
    if len(key_ids) != 1:
        raise OfflineBundleError(
            "window spans %d entry-signer keys %s: v1 requires one key "
            "per bundle; export per-epoch windows" % (len(key_ids),
                                                      sorted(key_ids)))
    if entry_signer_pubkey is None:
        raise OfflineBundleError(
            "entry_signer_pubkey is required: the bundle must be "
            "self-contained, so the auditor can verify per-entry "
            "signatures without the operator")
    from gov import ed25519 as _ed
    from gov.signing import ed25519_key_id
    pub = bytes(entry_signer_pubkey)
    if len(pub) != 32:
        raise OfflineBundleError("entry_signer_pubkey is not 32 bytes")
    if ed25519_key_id(pub) != next(iter(key_ids)):
        raise OfflineBundleError(
            "entry_signer_pubkey does not match the window's "
            "sig_key_id")
    for e in window:
        try:
            sig = bytes.fromhex(e["ed_sig"])
        except (TypeError, ValueError):
            raise OfflineBundleError(
                "entry seq %d has a malformed ed_sig" % (e["seq"],))
        if not _ed.verify(pub, _log._entry_sig_body(e), sig):
            raise OfflineBundleError(
                "entry seq %d: per-entry Ed25519 signature does not "
                "verify under the supplied pubkey: refusing to export "
                "a doomed bundle" % (e["seq"],))

    # 4. Redact + build the export chain over exactly what is shipped.
    export_entries = []
    field_redactions = []
    prev = EXPORT_GENESIS
    for e in window:
        out = dict(e)
        dropped = [f for f in redact_fields if f in out]
        for f in dropped:
            del out[f]
        if dropped:
            # The signature covered the unredacted content: keeping it
            # would ship a non-verifying signature (worse than none).
            # The key id is preserved in the redaction report.
            out.pop("ed_sig", None)
            out.pop("sig_key_id", None)
            out["redacted"] = True
            field_redactions.append({
                "seq": e["seq"],
                "fields": sorted(dropped),
                "sig_key_id": e["sig_key_id"],
            })
        else:
            out["redacted"] = False
        body = {k: v for k, v in out.items() if k != "export_hash"}
        prev = _chain_hash(prev, _canonical(body))
        out["export_hash"] = prev
        export_entries.append(out)
    tip = prev

    # 5. Manifest (the redaction report is part of the anchored claim).
    if bundle_id is None:
        bundle_id = "ob-" + tip[:16]
    withheld_before = lo - 1          # entries 1..lo-1 exist but are withheld
    withheld_after = entries[-1]["seq"] - hi
    redaction_report = {
        "window_withheld": {
            "before_from_seq": withheld_before,
            "after_to_seq": withheld_after,
            "note": "entries outside the exported window are withheld; "
                    "counts only, no content",
        },
        "field_redactions": field_redactions,
        "entries_redacted": len(field_redactions),
        "note": "Every withheld field is listed here. An entry with "
                "redacted=true MUST appear in field_redactions; an "
                "entry with redacted=false MUST carry a valid per-entry "
                "Ed25519 signature. A silently-redacted entry satisfies "
                "neither and is rejected by the verifier.",
    }
    pubkey = anchor_pubkey
    if pubkey is None:
        pubkey = getattr(adapter, "public_key", None)
    if pubkey is None:
        raise OfflineBundleError(
            "anchor adapter exposes no public key: pass "
            "anchor_pubkey= explicitly")
    pubkey = bytes(pubkey)
    if len(pubkey) != 32:
        raise OfflineBundleError("anchor public key is not 32 bytes")
    manifest = {
        "bundle_format": BUNDLE_FORMAT,
        "bundle_id": bundle_id,
        "exported_at": _utcnow(),
        "exporter": "gov/offline_bundle.py %s" % EXPORTER_VERSION,
        "window": {"from_seq": lo, "to_seq": hi,
                   "entry_count": len(window)},
        "chain": {
            "algorithm": "sha256",
            "domain": "offline-export-chain/v1",
            "genesis": EXPORT_GENESIS,
            "note": "unkeyed by design; integrity via the anchor "
                    "signature (see module docstring)",
        },
        "ledger_digest": tip,
        "anchor": {
            "adapter": adapter.name,
            "log_pubkey_hex": pubkey.hex(),
        },
        "entry_signer": {
            "key_id": next(iter(key_ids)),
            "public_key_hex": bytes(entry_signer_pubkey).hex(),
            "note": "the entry-signer Ed25519 pubkey, pinned in the "
                    "bundle so per-entry signatures verify standalone",
        },
        "redaction_report": redaction_report,
        "trust": [
            "Recorded events only — the bundle cannot prove what was "
            "never logged.",
            "Integrity is not truth — a verified bundle can be a true "
            "record of a bad decision.",
            "Field redaction is trusted at export time: the verifier "
            "checks redacted fields are absent and listed, but cannot "
            "see what was removed.",
            "Timestamps are operator wall-clock.",
            "The source HMAC chain is NOT re-verifiable offline (the "
            "operator's key never leaves the operator); offline "
            "integrity rests on the export chain + anchor signature + "
            "per-entry Ed25519 signatures.",
        ],
    }

    # 6. Anchor the tip (+ window + redaction digest). The receipt's
    # statement commits to all three; equivocation on bundle_id raises.
    anchor_input = _anchor_input(manifest)
    try:
        receipt = adapter.anchor(anchor_input)
    except Exception as e:
        raise OfflineBundleError("anchor refused: %s" % (e,))
    manifest["anchor"]["log_id"] = receipt.get("log_id")

    # 7. Write the bundle directory (deterministic file set).
    os.makedirs(bundle_dir, exist_ok=True)
    with open(os.path.join(bundle_dir, "VERSION"), "w",
              encoding="utf-8") as f:
        f.write(BUNDLE_FORMAT + "\n")
    with open(os.path.join(bundle_dir, "ledger.jsonl"), "w",
              encoding="utf-8") as f:
        for e in export_entries:
            f.write(_canonical(e).decode("utf-8") + "\n")
    with open(os.path.join(bundle_dir, "manifest.json"), "w",
              encoding="utf-8") as f:
        f.write(_canonical(manifest).decode("utf-8") + "\n")
    with open(os.path.join(bundle_dir, "anchor_receipt.json"), "w",
              encoding="utf-8") as f:
        f.write(_canonical(receipt).decode("utf-8") + "\n")
    with open(os.path.join(bundle_dir, "REDACTION_REPORT.txt"), "w",
              encoding="utf-8") as f:
        f.write(_render_redaction_report(manifest, bundle_id))
    digest = _compute_bundle_digest(bundle_dir)
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w",
              encoding="utf-8") as f:
        f.write(digest + "\n")
    return os.path.abspath(bundle_dir)


def _render_redaction_report(manifest, bundle_id):
    rr = manifest["redaction_report"]
    w = manifest["window"]
    lines = [
        "REDACTION REPORT — offline evidence bundle %s" % bundle_id,
        "================================================================",
        "",
        "Window: seq %d..%d (%d entries). Everything outside this window" %
        (w["from_seq"], w["to_seq"], w["entry_count"]),
        "is WITHHELD. Withheld counts:",
        "  - %d entries before seq %d" %
        (rr["window_withheld"]["before_from_seq"], w["from_seq"]),
        "  - %d entries after seq %d" %
        (rr["window_withheld"]["after_to_seq"], w["to_seq"]),
        "",
        "Field redactions: %d entries" % rr["entries_redacted"],
    ]
    for r in rr["field_redactions"]:
        lines.append("  - seq %d: withheld fields: %s (entry-signer key %s)" %
                     (r["seq"], ", ".join(r["fields"]), r["sig_key_id"]))
    if not rr["field_redactions"]:
        lines.append("  (none — every entry ships complete)")
    lines += [
        "",
        "What this means: the verifier checks that every field listed",
        "above is ABSENT from the shipped ledger, and that every entry",
        "NOT listed carries a valid per-entry Ed25519 signature. An",
        "entry that is silently redacted (field removed but not listed)",
        "has no valid signature and no listing, and is REJECTED.",
        "",
        "What the verifier CANNOT check: the content of the withheld",
        "fields or entries. Redaction honesty at export time is trusted;",
        "the anchor signature makes the disclosure tamper-evident after",
        "export (the redaction digest is part of the anchored statement).",
    ]
    return "\n".join(lines) + "\n"
