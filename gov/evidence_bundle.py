"""Evidence bundle v1 — signed, auditor-readable export of a governed window.

Implements ``docs/evidence-bundle-spec.md``: builds the nine-section
payload (``evidence.json``), seals it with a manifest bound to the
verified hash-chained log via Merkle inclusion bundles, signs it with
the operator's Ed25519 key (domain-separated), and assembles the
deterministic transport directory. A standalone stdlib-only verifier
lives at ``tools/evidence-verify`` (byte-identical copy at
``gov/evidence_verify.py`` for the ``gov-evidence-verify`` entry point).

HONESTY CONTRACT (inherited from ``gov/evidence_exports.py``,
non-negotiable):
- Fail-closed; never invent fields — fields no log entry can supply are
  emitted as ``null`` with ``operator_must_supply: true``.
- Every rendered field carries provenance (``{"kind": "log", ...}`` or
  ``{"kind": "operator_must_supply"}``).
- The generator refuses to render when the log chain does not verify.

Integrity wiring (existing machinery, no parallel scheme):
- ``seal()`` binds the export to the log with ``gov.log.verify_chain``
  plus per-entry Merkle inclusion bundles (``gov.log.prove_inclusion``).
- The manifest signature is REQUIRED in v1 (no ``"none"`` scheme): an
  unsigned evidence bundle is not an evidence bundle. The signature is
  domain-separated (``evidence-bundle/v2``) over
  ``export_sha256 || canonical({window, chain_verified,
  checkpoints_digest, inclusion, receipt})`` — the claim is bound into
  the signature so the chain-verification, inclusion-coverage, and
  receipt claims cannot be swapped (F173: the pre-fix triple covered
  only window/chain_verified/checkpoints_digest, letting a no-key
  attacker strip inclusion bundles and adjust the unsigned counts).
- ``log_evidence_bundle_receipt()`` appends a hash-chained receipt of
  the sealed export back into the audit log (the
  ``evidence_export_sealed`` pattern from ``gov/evidence_exports.py``),
  so the export itself is auditable in the same chain. Because the
  receipt is created after ``seal()``, this function re-signs the
  extended claim after attaching the receipt.

P5 decision (signing key domain, coordinator call): reuse
``gov/anchorer.py::resolve_anchor_key`` (``GOV_ANCHOR_KEY`` /
``GOV_ANCHOR_KEY_FILE``) — the only existing operator-held Ed25519
seed seam with a fail-closed provisioning idiom — with the
``evidence-bundle/v2`` domain separation above. One fewer key to
provision; cross-artifact signature reuse is impossible by domain.

$0 spend, synthetic/local only. No network.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

from gov import log as _log
from gov.safeguard_bundle import (
    compute_bundle_digest as _compute_bundle_digest,
)


def _resolve_operator_signer():
    """Resolve the operator Ed25519 signer per spec §4.2 P5.

    Uses ``gov.anchorer.resolve_anchor_key`` (``GOV_ANCHOR_KEY`` /
    ``GOV_ANCHOR_KEY_FILE``). Fails closed when no key is configured:
    an unsigned evidence bundle is not an evidence bundle.
    """
    from gov import anchorer as _anchorer
    from gov.signing import Ed25519Signer as _Ed25519Signer
    try:
        key = _anchorer.resolve_anchor_key()
    except Exception as e:
        raise EvidenceBundleError(
            "seal() refuses: no signer given and the operator anchor "
            "key is not configured (%s). Set GOV_ANCHOR_KEY or "
            "GOV_ANCHOR_KEY_FILE." % (e,))
    if key is None:
        raise EvidenceBundleError(
            "seal() refuses: no signer given and the operator anchor "
            "key is not configured. Set GOV_ANCHOR_KEY or "
            "GOV_ANCHOR_KEY_FILE.")
    # resolve_anchor_key returns bytes (the raw 32-byte seed).
    seed = bytes(key) if not isinstance(key, bytes) else key
    if len(seed) != 32:
        raise EvidenceBundleError(
            "seal() refuses: resolved anchor key is not 32 bytes")
    return _Ed25519Signer(seed)

BUNDLE_VERSION = "evidence-bundle/1.1"
EVIDENCE_SCHEMA_VERSION = "evidence-schema/1.0"
GENERATOR = "gov/evidence_bundle.py"
GENERATOR_VERSION = "1.0.0"

#: Domain separation for the operator's manifest signature (P5).
#: v2: the signed claim changed shape (F173 binds the inclusion
#: presence vector, the inclusion_coverage counts, and the receipt
#: bundle-presence/reason), so the domain is bumped to keep v1-claim
#: signatures unpresentable as v2-claim signatures.
SIGN_DOMAIN = b"evidence-bundle/v2\x00"

#: Signature domain string recorded in manifest["signing"]["domain"].
SIGN_DOMAIN_STR = "evidence-bundle/v2"

#: Last bundle version whose signed claim does NOT bind inclusion
#: coverage or the receipt (F173). The verifier fails these closed;
#: see evals/f173_legacy_binding_decision.md.
LEGACY_BUNDLE_VERSION = "evidence-bundle/1.0"

#: Approval-queue event vocabulary (gov/approvals.py).
APPROVAL_EVENTS = (
    "approval_decision",
    "approval_decision_attempt",
    "approval_late_decision",
    "approval_break_glass",
    "approval_batch_abort",
    "ticket_consumed",
    "quorum_opened",
    "post_review_resolved",
)

#: Policy-change event vocabulary (gov/executor.py).
POLICY_CHANGE_EVENTS = ("policy_pin_mismatch", "policy_pin_absent")

#: Fixed schema for the operator-supplied retention manifest (P3).
#: The verifier checks presence and schema only, never truth.
RETENTION_MANIFEST_SCHEMA = {
    "retention_policy": str,
    "window_coverage": str,
    "archive_locations": list,
}

DIGEST_FILE = "BUNDLE_DIGEST.sha256"


class EvidenceBundleError(Exception):
    """Loud failure: unverifiable chain, missing signer, bad inputs."""


def canonical(obj):
    """Deterministic bytes for hashing/signing.

    The same canonical form as ``IncidentReport.canonical``
    (``gov/evidence_exports.py``) and ``_canonical_body``
    (``gov/signing.py``), with ``gov.log._canonical``'s
    ``default=str`` convention for non-JSON scalars (e.g. in-memory
    ``datetime`` entry timestamps). Using the log's own convention
    matters: Merkle leaf inputs were committed at append time with
    ``str()`` semantics, so the standalone verifier recomputes
    byte-identical leaves from the transported slice.
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), default=str).encode("utf-8")


def _op(note=None):
    """Provenance marker for fields the operator must supply."""
    m = {"kind": "operator_must_supply",
         "note": ("no audit-log entry can supply this field; the operator "
                  "must provide it. It is null, not defaulted.")}
    if note:
        m["note"] = note
    return m


def _logprov(entry, field=None):
    p = {"kind": "log", "seq": entry["seq"], "hash": entry["hash"]}
    if field:
        p["field"] = field
    return p


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


def _inclusion_claim(manifest):
    """Presence vector + coverage counts bound into the signed claim.

    F173: binding *presence* (not the proofs themselves — those are
    anchored via checkpoints_digest and checked by V9) means a no-key
    attacker cannot strip an inclusion bundle and adjust the unsigned
    counts: the signature is over the operator-declared presence, so
    the strip fails V7. An honestly-degraded seal (inclusion service
    genuinely unavailable at seal time) signs bundle_present=False
    with its reason — operator-declared degraded, still verifiable.
    """
    ic = manifest.get("inclusion_coverage") or {}
    presence = []
    for b in manifest.get("inclusion_bundles") or []:
        presence.append({
            "seq": b.get("seq"),
            "bundle_present": b.get("bundle") is not None,
            "unavailable_reason": b.get("unavailable_reason"),
        })
    return {
        "coverage": {"entries": ic.get("entries"),
                     "with_bundle": ic.get("with_bundle")},
        "presence": presence,
    }


def _receipt_claim(manifest):
    """Receipt bundle-presence/reason bound into the signed claim.

    F173: the receipt's own inclusion bundle is the export's chaining
    proof; binding its presence/reason stops a no-key attacker from
    stripping receipt.json's bundle while the bundle VERIFIES. None
    while the receipt is not yet attached (seal time) — the claim then
    says "no receipt bound", and assemble() refuses receipt-less
    manifests, so an unbound receipt can never ship.
    """
    r = manifest.get("receipt")
    if r is None:
        return None
    return {"bundle_present": r.get("bundle") is not None,
            "unavailable_reason": r.get("unavailable_reason")}


class EvidenceBundle:
    """Builds, seals, and assembles a v1 evidence bundle."""

    def __init__(self, log_path, *, window=None, operator_id=None,
                 retention_manifest=None, key_provider=None,
                 sar_manifest=None, eval_session_ids=None,
                 exported_at=None, roster=None):
        self.log_path = str(log_path)
        self._window_req = window
        self._operator_id = operator_id
        self._retention_manifest = retention_manifest
        self._key_provider = key_provider
        self._sar_manifest = sar_manifest
        self._eval_session_ids = eval_session_ids
        self._exported_at = exported_at
        # A5 roster (dict) for threshold checkpoint heads. Required when
        # the window's heads use k-of-n signing; shipped as
        # keys/checkpoint_roster.json so the verifier can check the
        # k-of-n signatures.
        self._roster = roster
        self._entries = None
        self._window = None

    # -- log handling -------------------------------------------------

    def _load_verified(self):
        """Read and chain-verify the log. Raises on any failure."""
        entries = _log.read_entries(self.log_path)
        if not entries:
            raise EvidenceBundleError("log is empty: nothing to export")
        ok, broken_seq, _count = _log.verify_chain(self.log_path)
        if not ok:
            raise EvidenceBundleError(
                "refusing to render: audit-log chain does not verify "
                "(broken at seq %s). An evidence bundle with an "
                "unauthenticated record is worse than no bundle."
                % (broken_seq,))
        self._entries = entries
        return entries

    def _resolve_window(self, entries):
        tip = entries[-1]
        if self._window_req is None:
            w = {"from_seq": entries[0]["seq"], "to_seq": tip["seq"]}
        else:
            req = self._window_req
            if not isinstance(req, dict) or \
                    set(req.keys()) != {"from_seq", "to_seq"}:
                raise EvidenceBundleError(
                    "window must be {'from_seq': int, 'to_seq': int}")
            try:
                w = {"from_seq": int(req["from_seq"]),
                     "to_seq": int(req["to_seq"])}
            except (TypeError, ValueError):
                raise EvidenceBundleError(
                    "window from_seq/to_seq must be integers")
        if w["to_seq"] != tip["seq"]:
            raise EvidenceBundleError(
                "refusing to seal a non-tip window: the export receipt "
                "must chain onto the window tip (receipt prev_hash == "
                "tip hash), which requires to_seq == chain tip "
                "(got to_seq=%d, tip=%d)" % (w["to_seq"], tip["seq"]))
        if not (entries[0]["seq"] <= w["from_seq"] <= w["to_seq"]):
            raise EvidenceBundleError(
                "window out of range: %r" % (self._window_req,))
        self._window = w
        return [e for e in entries
                if w["from_seq"] <= e["seq"] <= w["to_seq"]]

    # -- payload construction -----------------------------------------

    def build(self):
        """Render the seven-section payload dict.

        Every field carries provenance. Fields the log cannot supply
        are ``null`` with ``operator_must_supply: true`` — never
        synthesized, never defaulted.
        """
        entries = self._load_verified()
        window_entries = self._resolve_window(entries)
        tip = window_entries[-1]

        payload = {
            "bundle_meta": self._build_meta(tip),
            "log_slice": self._build_log_slice(window_entries, tip),
            "policy": self._build_policy(window_entries),
            "decisions": self._build_decisions(window_entries),
            "approvals": self._build_approvals(window_entries),
            "citations": self._build_citations(window_entries),
            "benchmark": self._build_benchmark(window_entries),
            "kms_attestation": None,
            "retention_manifest": self._build_retention(),
            "sections_meta": {},
        }
        payload["kms_attestation"], meta = self._build_kms_attestation()
        payload["sections_meta"]["kms_attestation"] = meta
        # Deterministic identity: hash of the payload without bundle_id.
        body = canonical(payload)
        payload["bundle_meta"]["bundle_id"] = (
            "EVB-" + hashlib.sha256(body).hexdigest()[:16])
        return payload

    def _build_meta(self, tip):
        w = self._window
        op_given = self._operator_id is not None
        return {
            "bundle_version": BUNDLE_VERSION,
            "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
            "generator": GENERATOR,
            "generator_version": GENERATOR_VERSION,
            "exported_at": self._exported_at or _utcnow_iso(),
            "operator_id": {
                "value": self._operator_id,
                "operator_must_supply": not op_given,
                "provenance": ({"kind": "operator_supplied"} if op_given
                               else _op()),
            },
            "window": {"from_seq": w["from_seq"], "to_seq": w["to_seq"]},
            "bundle_id": None,  # filled in by build()
        }

    def _build_log_slice(self, window_entries, tip):
        coverage = []
        for e in window_entries:
            try:
                _log.prove_inclusion(self.log_path, e["seq"])
            except ValueError as ex:
                coverage.append({"seq": e["seq"], "hash": e["hash"],
                                 "has_bundle": False,
                                 "unavailable_reason": str(ex)})
            else:
                coverage.append({"seq": e["seq"], "hash": e["hash"],
                                 "has_bundle": True,
                                 "unavailable_reason": None})
        return {
            "entry_count": len(window_entries),
            "from_seq": window_entries[0]["seq"],
            "to_seq": tip["seq"],
            "tip_hash": tip["hash"],
            "coverage": coverage,
        }

    def _build_policy(self, window_entries):
        loaded = [e for e in window_entries
                  if e.get("event") == "policy_loaded"]
        changes = [{"seq": e["seq"], "hash": e["hash"],
                    "event": e.get("event"),
                    "provenance": _logprov(e)}
                   for e in window_entries
                   if e.get("event") in POLICY_CHANGE_EVENTS]

        def fld(value, provenance, must_supply=False):
            return {"value": value, "provenance": provenance,
                    "operator_must_supply": must_supply}

        if not loaded:
            return {
                "policy_version": fld(None, _op(
                    "no policy_loaded event in the window: the bundle "
                    "never guesses which policy governed the window"),
                    must_supply=True),
                "policy_hash": fld(None, _op(), must_supply=True),
                "policy_path": fld(None, _op(), must_supply=True),
                "pinned": fld(None, _op(), must_supply=True),
                "policy_change_events": changes,
            }
        ev = loaded[-1]
        return {
            "policy_version": fld(ev.get("policy_version", "unversioned"),
                                  _logprov(ev, "policy_version")),
            "policy_hash": fld(ev.get("policy_hash"),
                               _logprov(ev, "policy_hash")),
            "policy_path": fld(ev.get("policy_path"),
                               _logprov(ev, "policy_path")),
            "pinned": fld(bool(ev.get("pinned")),
                           _logprov(ev, "pinned")),
            "policy_change_events": changes,
        }

    def _build_decisions(self, window_entries):
        by_event = {}
        refs = []
        for e in window_entries:
            if "decision" not in e:
                continue
            ev = e.get("event")
            by_event[ev] = by_event.get(ev, 0) + 1
            refs.append({"seq": e["seq"], "hash": e["hash"],
                         "event": ev, "decision": e.get("decision"),
                         "provenance": _logprov(e, "decision")})
        return {"by_event": by_event, "refs": refs,
                "note": ("verdict vocabulary is the log's own; the "
                         "bundle does not re-grade decisions")}

    def _build_approvals(self, window_entries):
        out = {name: [] for name in APPROVAL_EVENTS}
        for e in window_entries:
            ev = e.get("event")
            if ev in out:
                out[ev].append({
                    "seq": e["seq"], "hash": e["hash"],
                    "record_digest": e["hash"],
                    "decision": e.get("decision"),
                    "approval_id": e.get("approval_id"),
                    "ticket_id": e.get("ticket_id"),
                    "provenance": _logprov(e),
                })
        out["_honesty_note"] = (
            "approval queue MACs are keyed by the queue's own keys; a "
            "third-party verifier without those keys cannot re-run them. "
            "Approval integrity in the bundle flows from the chained log "
            "+ inclusion bundles, not from re-verified queue MACs.")
        return out

    def _build_citations(self, window_entries):
        checks = []
        violations = []
        for e in window_entries:
            if (e.get("event") == "eval_integrity"
                    and e.get("signal") == "citation_check_completed"):
                checks.append({
                    "seq": e["seq"], "hash": e["hash"],
                    "session_id": e.get("session_id"),
                    "session_open": e.get("session_open"),
                    "policy_version": e.get("policy_version"),
                    "n_citations": e.get("n_citations"),
                    "n_self_planted": e.get("n_self_planted"),
                    "verdict_counts": e.get("verdict_counts"),
                    "accepted": e.get("accepted"),
                    "provenance": _logprov(e),
                })
            elif (e.get("event") == "detector_trip"
                    and e.get("signal") == "self_planted_citation"):
                violations.append({
                    "seq": e["seq"], "hash": e["hash"],
                    "session_id": e.get("session_id"),
                    "reason": e.get("reason"),
                    "provenance": _logprov(e),
                })
        with_checks = sorted({c["session_id"] for c in checks
                              if c["session_id"]})
        missing = []
        if self._eval_session_ids:
            missing = [s for s in self._eval_session_ids
                       if s not in with_checks]
        return {
            "citation_checks": checks,
            "self_planted_violations": violations,
            "sessions_with_checkpoints": with_checks,
            "sessions_without_checkpoints": missing,
            "_honesty_note": (
                "accept_report is opt-in: sessions without a "
                "citation_check_completed record were NOT checked. "
                "Absence of a checkpoint is evidence of absence of the "
                "check, not evidence of clean citations. UNKNOWN is the "
                "default verdict and is never presented as exoneration."),
        }

    def _build_benchmark(self, window_entries):
        receipts = [e for e in window_entries
                    if e.get("event") == "safeguard_benchmark_sealed"]
        base = {"seal_status": "unsealed",
                "safeguard_receipts_in_window": [
                    {"seq": e["seq"], "hash": e["hash"],
                     "report_id": e.get("report_id"),
                     "provenance": _logprov(e)} for e in receipts]}
        if not receipts or self._sar_manifest is None:
            base["note"] = (
                "no sealed SAR verdicts embedded: "
                + ("no safeguard_benchmark_sealed receipt in the window"
                   if not receipts else
                   "SAR seal manifest not supplied to the builder; "
                   "verdicts are never reconstructed from the log"))
            return base
        sar = self._sar_manifest
        rid = sar.get("report_id")
        if not any(e.get("report_id") == rid for e in receipts):
            base["note"] = (
                "supplied SAR manifest report_id %r matches no "
                "safeguard_benchmark_sealed receipt in the window; "
                "verdicts not embedded" % (rid,))
            return base
        prov = {"kind": "sar_manifest", "report_id": rid,
                "note": "verdict section of the supplied sealed SAR; "
                        "cross-referenced by report_id"}
        base["seal_status"] = "sealed"
        base["schema_version"] = {"value": sar.get("schema_version"),
                                  "provenance": prov}
        base["report_id"] = {"value": rid, "provenance": prov}
        base["aggregate_verdict"] = {"value": sar.get("aggregate_verdict"),
                                     "provenance": prov}
        base["per_category"] = {"value": sar.get("per_category"),
                                "provenance": prov}
        base["thresholds"] = {"value": sar.get("thresholds"),
                              "provenance": prov}
        base["taxonomy"] = {"value": sar.get("taxonomy"),
                            "provenance": prov}
        return base

    def _build_kms_attestation(self):
        """Key-custody attestation (P2).

        A claim about the provisioning story, not cryptographic proof
        of hardware custody. No key material ever enters the bundle.
        """
        if self._key_provider is None:
            return None, {"operator_must_supply": True,
                          "provenance": _op(
                              "no key provider supplied to the builder: "
                              "key custody is unattested")}
        kp = self._key_provider
        key_bytes, epoch = kp.resolve()
        key_id = hashlib.sha256(bytes(key_bytes)).hexdigest()[:16]
        att = {
            "provider": kp.provider_name,
            "key_id": key_id,
            "epoch": epoch,
            "describe": kp.describe(),
            "custody_note": (
                "operator-signed statement about the provisioning story "
                "(provider, key id, epoch, runbook reference). NOT "
                "cryptographic proof of HSM custody. In v1 the operator "
                "signing key itself is a software-file key (0600) unless "
                "the deployment did better — see "
                "docs/KEY_CUSTODY_RUNBOOK.md."),
            "runbook": "docs/KEY_CUSTODY_RUNBOOK.md",
            "provenance": {"kind": "key_provider",
                           "provider": kp.provider_name},
        }
        return att, {"operator_must_supply": False,
                     "provenance": {"kind": "key_provider",
                                    "provider": kp.provider_name}}

    def _build_retention(self):
        """Operator-supplied retention record (P3).

        The verifier checks presence and schema only, never truth.
        """
        m = self._retention_manifest
        if m is None:
            return {"value": None, "operator_must_supply": True,
                    "provenance": _op(
                        "retention is operator-owned (no gov/retain.py); "
                        "no retention manifest was supplied")}
        if not isinstance(m, dict):
            raise EvidenceBundleError(
                "retention_manifest must be a dict")
        for field, typ in RETENTION_MANIFEST_SCHEMA.items():
            if field not in m or not isinstance(m[field], typ):
                raise EvidenceBundleError(
                    "retention_manifest field %r must be %s"
                    % (field, typ.__name__))
        for loc in m["archive_locations"]:
            if not isinstance(loc, str):
                raise EvidenceBundleError(
                    "retention_manifest archive_locations must be strings")
        return {"value": {k: m[k]
                          for k in RETENTION_MANIFEST_SCHEMA},
                "operator_must_supply": False,
                "provenance": {"kind": "operator_supplied",
                               "note": ("operator assertion; presence and "
                                        "schema checked, truth not "
                                        "verified")}}

    # -- canonical form + sealing -------------------------------------

    @staticmethod
    def canonical(payload):
        """Deterministic bytes for hashing/signing."""
        return canonical(payload)

    @staticmethod
    def signed_body(manifest):
        """Exact bytes the operator signature covers.

        Domain-separated: ``evidence-bundle/v2`` || export_sha256 ||
        canonical({window, chain_verified, checkpoints_digest,
        inclusion, receipt}).

        The F173 extension binds the per-entry inclusion-bundle
        presence vector, the inclusion_coverage counts, and the
        receipt's bundle-presence/reason into the claim: any unsigned
        alteration of those fields fails the signature (V7) instead of
        sailing through to a VERIFIED verdict. Binding the claim into
        the signature means a signature over the payload digest alone
        cannot be re-presented with a swapped chain-verification,
        coverage, or receipt claim. Mirrored by the standalone
        verifier's ``_signed_claim`` (gov/evidence_verify.py) — the
        two must construct byte-identical claims.
        """
        claim = {
            "window": manifest["window"],
            "chain_verified": manifest["chain_verified"],
            "checkpoints_digest": manifest["checkpoints_digest"],
            "inclusion": _inclusion_claim(manifest),
            "receipt": _receipt_claim(manifest),
        }
        return (SIGN_DOMAIN
                + bytes.fromhex(manifest["export_sha256"])
                + canonical(claim))

    def seal(self, payload, *, signer=None):
        """Bind the rendered payload to the verified log.

        ``signer`` (a ``gov.signing.Signer``) defaults to the operator
        key resolved via ``gov.anchorer.resolve_anchor_key``
        (``GOV_ANCHOR_KEY`` / ``GOV_ANCHOR_KEY_FILE``) per spec §4.2 P5.
        v1 has no ``"none"`` scheme: an unsigned evidence bundle is not
        an evidence bundle — if no signer is given AND the anchor key
        is missing, seal() refuses (fail closed). Re-verifies the chain
        at seal time; refuses when it does not verify.
        """
        if signer is None:
            signer = _resolve_operator_signer()
        if self._entries is None:
            raise EvidenceBundleError(
                "seal() requires build() first (log not loaded)")
        ok, broken_seq, _count = _log.verify_chain(self.log_path)
        if not ok:
            raise EvidenceBundleError(
                "refusing to seal: audit-log chain does not verify "
                "(broken at seq %s)" % (broken_seq,))
        body = canonical(payload)
        digest = hashlib.sha256(body).hexdigest()

        # NOTE: inclusion coverage is recomputed here rather than reused
        # from build() deliberately — seal re-verifies at seal time, so a
        # chain that broke (or a coverage gap that opened) between build
        # and seal cannot be silently carried into the manifest.
        bundles = []
        covered = 0
        for cov in payload["log_slice"]["coverage"]:
            seq = cov["seq"]
            try:
                b = _log.prove_inclusion(self.log_path, seq)
            except ValueError as e:
                b = None
                reason = str(e)
            else:
                reason = None
                covered += 1
            bundles.append({"seq": seq, "bundle": b,
                            "unavailable_reason": reason})

        # Unique covering checkpoint heads, oldest first.
        heads = []
        seen = set()
        for b in bundles:
            cp = (b["bundle"] or {}).get("checkpoint")
            if cp and cp.get("seq") not in seen:
                seen.add(cp["seq"])
                heads.append(cp)
        heads.sort(key=lambda c: c["seq"])
        # Threshold heads require the A5 roster: without it the verifier
        # cannot check the k-of-n signatures, so the bundle would be
        # unverifiable. Fail closed.
        threshold_heads = [h for h in heads
                           if h.get("threshold", 1) != 1]
        if threshold_heads and self._roster is None:
            raise EvidenceBundleError(
                "seal() refuses: window has threshold checkpoint heads "
                "(k-of-n) but no roster was provided. Pass roster= to "
                "EvidenceBundle so keys/checkpoint_roster.json can be "
                "shipped.")
        if self._roster is not None:
            # The roster must be the one the threshold heads bind.
            from gov.signing import roster_hash as _roster_hash
            rh = _roster_hash(self._roster)
            for h in threshold_heads:
                if h.get("roster_hash") != rh:
                    raise EvidenceBundleError(
                        "seal() refuses: provided roster does not match "
                        "threshold head seq %r roster_hash" % h.get("seq"))
        checkpoints_digest = hashlib.sha256(
            canonical(heads)).hexdigest()

        w = payload["bundle_meta"]["window"]
        manifest = {
            "kind": "evidence_bundle_manifest",
            "generator": GENERATOR,
            "generator_version": GENERATOR_VERSION,
            "bundle_id": payload["bundle_meta"]["bundle_id"],
            "bundle_version": BUNDLE_VERSION,
            "export_sha256": digest,
            "window": {
                "from_seq": w["from_seq"],
                "to_seq": w["to_seq"],
                "tip_hash": payload["log_slice"]["tip_hash"],
                "entry_count": payload["log_slice"]["entry_count"],
            },
            "chain_verified": ok,
            "chain_broken_seq": broken_seq,
            "inclusion_coverage": {
                "entries": len(bundles),
                "with_bundle": covered,
                "note": ("inclusion bundles require signed (Ed25519 v2) "
                         "checkpoints; entries without a bundle name "
                         "their reason in unavailable_reason"),
            },
            "inclusion_bundles": bundles,
            "checkpoints": heads,
            "checkpoints_digest": checkpoints_digest,
            "signing": None,  # filled below
            "receipt": None,  # attached by log_evidence_bundle_receipt
        }
        sig = signer.sign(self.signed_body(manifest))
        manifest["signing"] = _signing_block(signer, sig)
        return manifest

    # -- transport assembly -------------------------------------------

    def assemble(self, payload, manifest, *, operator_key,
                 checkpoint_keys, out_dir):
        """Write the deterministic transport directory (§4.1 layout).

        ``payload``/``manifest`` are written VERBATIM (canonical JSON),
        never rewritten. Fail-closed: refuses mismatched payload/
        manifest pairs, manifests without a chained receipt (a bundle
        that could never pass verifier V12 is a lie), malformed key
        envelopes, operator keys that differ from the manifest seal's
        key, checkpoint keys that do not cover the checkpoint signers,
        and non-empty output directories.

        Returns ``{"bundle_dir", "bundle_digest", "files", "bundle_id"}``.
        """
        if not isinstance(payload, dict):
            raise EvidenceBundleError("payload must be a dict")
        if not isinstance(manifest, dict):
            raise EvidenceBundleError("manifest must be a dict")
        if self._entries is None:
            raise EvidenceBundleError(
                "assemble() requires build() first (log not loaded)")
        if manifest.get("bundle_version") != BUNDLE_VERSION:
            raise EvidenceBundleError(
                "refusing to bundle version %r: this assembler only "
                "transports %r (the schema is never silently "
                "re-interpreted)"
                % (manifest.get("bundle_version"), BUNDLE_VERSION))
        bid = (payload.get("bundle_meta") or {}).get("bundle_id")
        if not isinstance(bid, str) or not bid.startswith("EVB-"):
            raise EvidenceBundleError("payload has no well-formed "
                                      "bundle_id")
        if manifest.get("bundle_id") != bid:
            raise EvidenceBundleError(
                "manifest bundle_id %r does not match payload %r: "
                "refusing to bundle a mismatched pair"
                % (manifest.get("bundle_id"), bid))
        if manifest.get("export_sha256") != hashlib.sha256(
                canonical(payload)).hexdigest():
            raise EvidenceBundleError(
                "manifest export_sha256 does not match the payload: "
                "refusing to bundle a mismatched pair")
        receipt = manifest.get("receipt")
        if not isinstance(receipt, dict) or not isinstance(
                receipt.get("entry"), dict):
            raise EvidenceBundleError(
                "manifest carries no chained receipt: the bundle could "
                "never pass verifier V12, so it is not assembled")

        op_id, op_pub_hex = _check_key_envelope(operator_key,
                                                "operator_key")
        if not isinstance(checkpoint_keys, list):
            raise EvidenceBundleError("checkpoint_keys must be a list")
        cp_envelopes = []
        for i, e in enumerate(checkpoint_keys):
            kid, _pub = _check_key_envelope(e, "checkpoint_keys[%d]" % i)
            cp_envelopes.append({"key_id": kid,
                                 "public_key_hex": e["public_key_hex"]})
        if len({d["key_id"] for d in cp_envelopes}) != len(cp_envelopes):
            raise EvidenceBundleError(
                "checkpoint_keys carries duplicate key_ids")
        cp_envelopes.sort(key=lambda d: d["key_id"])

        # The seal binds the sealing operator's key: the envelope must
        # carry that key, not another one.
        seal = manifest.get("signing") or {}
        if (seal.get("scheme") == "ed25519" and seal.get("key_id")
                and seal["key_id"] != op_id):
            raise EvidenceBundleError(
                "operator_key key_id %r does not match the manifest "
                "seal's key_id %r: refusing to ship a bundle that can "
                "never pass verifier V6/V7" % (op_id, seal["key_id"]))

        # The envelope must cover every checkpoint signer.
        sig_kids = set()
        for cp in manifest.get("checkpoints", []):
            for s in cp.get("sigs", []) or []:
                if isinstance(s, dict) and s.get("key_id"):
                    sig_kids.add(s["key_id"])
        env_kids = {d["key_id"] for d in cp_envelopes}
        if not sig_kids.issubset(env_kids):
            raise EvidenceBundleError(
                "checkpoint_keys envelope does not cover the checkpoint "
                "signers %s" % sorted(sig_kids - env_kids))

        out_dir = str(out_dir)
        if os.path.isdir(out_dir) and os.listdir(out_dir):
            raise EvidenceBundleError(
                "output directory %r is not empty: refusing to mix "
                "bundles" % (out_dir,))
        os.makedirs(out_dir, exist_ok=True)

        window_entries = self._entries
        w = manifest["window"]
        slice_entries = [e for e in window_entries
                         if w["from_seq"] <= e["seq"] <= w["to_seq"]]
        files = {
            "VERSION": ("%s\nschema: %s\n"
                        % (BUNDLE_VERSION,
                           EVIDENCE_SCHEMA_VERSION)).encode("utf-8"),
            "evidence.json": canonical(payload) + b"\n",
            "manifest.json": canonical(manifest) + b"\n",
            "log_slice.jsonl": b"".join(
                canonical(e) + b"\n" for e in slice_entries),
            "checkpoints.jsonl": b"".join(
                canonical(h) + b"\n"
                for h in manifest.get("checkpoints", [])),
            "receipt.json": canonical(receipt) + b"\n",
            "keys/operator_ed25519.json": canonical(
                {"key_id": op_id,
                 "public_key_hex": op_pub_hex}) + b"\n",
            "keys/checkpoint_keys.json": canonical(
                cp_envelopes) + b"\n",
            "VERIFY.txt": _VERIFY_TEXT.encode("utf-8"),
        }
        # A5 roster (threshold heads only): the verifier needs the
        # roster to check k-of-n signatures.
        if self._roster is not None:
            files["keys/checkpoint_roster.json"] = \
                canonical(self._roster) + b"\n"
        for rel in sorted(files):
            full = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(files[rel])
        # The digest is computed from the bytes on disk by the same
        # code path the verifier uses — the stored value cannot drift
        # from the verified value.
        digest = _compute_bundle_digest(out_dir)
        with open(os.path.join(out_dir, DIGEST_FILE), "w",
                  encoding="utf-8") as f:
            f.write(digest + "\n")
        return {"bundle_dir": out_dir,
                "bundle_digest": digest,
                "files": sorted(list(files) + [DIGEST_FILE]),
                "bundle_id": bid}


def _check_key_envelope(entry, where):
    """Validate one ``{key_id, public_key_hex}`` envelope entry.

    Returns ``(key_id, public_key_hex)``. The envelope cannot mislabel
    its own keys: ``key_id`` must equal
    ``sha256(pub).hexdigest()[:16]``.
    """
    if not isinstance(entry, dict):
        raise EvidenceBundleError("%s must be a dict" % where)
    pub_hex = entry.get("public_key_hex")
    try:
        pub = bytes.fromhex(pub_hex)
    except (TypeError, ValueError):
        raise EvidenceBundleError(
            "%s public_key_hex is not hex" % where)
    if len(pub) != 32:
        raise EvidenceBundleError(
            "%s public_key is not 32 bytes" % where)
    expect = hashlib.sha256(pub).hexdigest()[:16]
    if entry.get("key_id") != expect:
        raise EvidenceBundleError(
            "%s key_id %r does not match sha256(pub)[:16] %r: the "
            "envelope cannot mislabel its own keys"
            % (where, entry.get("key_id"), expect))
    return expect, pub_hex


_VERIFY_TEXT = """\
Evidence bundle v1 — verification procedure (auditor copy)
===========================================================

This directory is a signed, tamper-evident export of one deployment's
governed audit-log window. Verify it WITHOUT trusting the deployer:

  1. Fetch the standalone verifier (stdlib-only, no install needed):
       tools/evidence-verify   (from the release, byte-identical to
                                gov/evidence_verify.py in the repo)
  2. python3 tools/evidence-verify <this-directory> --format text
  3. For authorship (recommended): pin the operator's public key
     out-of-band and pass --pin-operator-pubkey HEX. Without a pin the
     verifier can only report SELF_CONSISTENT ("internally intact"),
     never "the operator's bundle".
  4. Optional: --pin-checkpoint-key-ids KID (repeatable) pins the
     expected checkpoint signer key ids; --log PATH re-verifies the
     receipt against your copy of the source audit log (V12b).

The verifier runs the section 4.3 procedure V1-V13 (plus v1 extensions
V14-V16): version gate, required files, transport digest, payload
digest, key envelope, authorship pin, operator signature, checkpoint
signatures (single-key or A5 k-of-n), log-slice integrity and
inclusion, manifest completeness, policy-version consistency, export
receipt, citation/approval cross-consistency.

Exit codes: 0 = VERIFIED (pinned) · 1 = FAILED · 2 = SELF_CONSISTENT
(unpinned) · 3 = usage error.

What this proves: the transported log slice is internally consistent
and bound to the operator's signed manifest; every transported entry
is anchored by a checkpoint the operator's keys signed.

What this does NOT prove (normative, see
docs/evidence-bundle-spec.md section 7): the bundle attests to RECORDED
events, not unrecorded ones; integrity is not truth; key custody is
asserted, not proven; timestamps are operator wall-clock (no trusted
timestamp authority in v1); unpinned bundles prove self-consistency
only; UNKNOWN citations are not clean citations; retention and
operator-supplied fields are assertions; safeguard thresholds and
taxonomy are provisional; approval-queue MACs are not independently
re-authenticated; single-tenant scope; no auditor or regulator has
accepted this format.
"""


def _signing_block(signer, sig):
    """Build manifest["signing"] for an Ed25519 signature over the
    F173-extended signed body."""
    return {
        "scheme": "ed25519",
        "key_id": signer.key_id,
        "public_key_hex": signer.public_key.hex(),
        "signature_hex": sig.hex(),
        "domain": SIGN_DOMAIN_STR,
        "signed_bytes": ("domain || export_sha256 || "
                         "canonical({window, chain_verified, "
                         "checkpoints_digest, inclusion, receipt})"),
        "operator_key_custody": (
            "operator-supplied signer object; v1 deployments use a "
            "software-file key (0600, gov/keyfiles.py) unless the "
            "deployment did better"),
    }


def log_evidence_bundle_receipt(manifest, action_log, *, signer=None):
    """Append a hash-chained receipt of the sealed bundle to the audit log.

    Mirrors ``gov.evidence_exports.log_export_receipt``: the receipt
    becomes a chained entry, so the export itself is auditable in the
    same evidence chain the bundle cites. The manifest must already be
    sealed; the receipt (plus its Merkle inclusion bundle when signed
    checkpoints exist) is attached to the manifest in place.

    F173: the receipt did not exist at seal time, so the seal-time
    signature cannot bind it. This function therefore RE-SIGNS the
    extended claim (``EvidenceBundle.signed_body`` — window,
    chain_verified, checkpoints_digest, inclusion presence/coverage,
    receipt bundle-presence/reason) after attaching the receipt and
    replaces ``manifest["signing"]``. The transported bundle's only
    operator signature is the post-receipt one; any unsigned
    alteration of the inclusion or receipt bindings fails V7.
    ``signer`` defaults to the operator key resolved via
    ``gov.anchorer.resolve_anchor_key`` (same fail-closed idiom as
    ``seal()``).

    Returns the appended entry.
    """
    if signer is None:
        signer = _resolve_operator_signer()
    entry = action_log.append({
        "event": "evidence_bundle_sealed",
        "bundle_id": manifest.get("bundle_id"),
        "export_sha256": manifest["export_sha256"],
        "window": manifest["window"],
        "chain_verified_at_seal": manifest.get("chain_verified"),
        "reason": ("Evidence bundle sealed; manifest digest %s"
                   % manifest["export_sha256"][:16]),
    })
    try:
        bundle = _log.prove_inclusion(str(action_log.path),
                                      entry["seq"])
    except ValueError as e:
        bundle = None
        reason = str(e)
    else:
        reason = None
    manifest["receipt"] = {
        # The FULL entry as appended (not a projection): the verifier
        # recomputes the Merkle leaf from this dict, and the leaf was
        # committed at append time over the full entry — so no fields
        # may be added here (not even provenance).
        "entry": dict(entry),
        "bundle": bundle,
        "unavailable_reason": reason,
    }
    # F173 re-sign (see docstring): the seal-time signature predates
    # the receipt; the shipped signature must bind it.
    manifest["signing"] = _signing_block(
        signer, signer.sign(EvidenceBundle.signed_body(manifest)))
    return entry
