"""EU AI Act serious-incident report exports (integrated STREAM-B).

Renders a DRAFT serious-incident report from the hash-chained audit log
(``gov/log.py``) in the shape Regulation (EU) 2024/1689 **Article 73**
requires — NOT Article 55 (Art. 55 covers GPAI models with systemic
risk; serious-incident reporting for high-risk AI systems is Art. 73,
"Reporting of serious incidents").

Legal anchors (public sources, verified 2026-09-23):
- Art. 73(1): providers of high-risk AI systems report serious incidents
  to the market-surveillance authority of the Member State where the
  incident occurred.
- Art. 3(49) "serious incident": (a) death / serious harm to health;
  (b) serious and irreversible disruption of the management or operation
  of critical infrastructure; (c) infringement of obligations under Union
  law intended to protect fundamental rights; (d) serious harm to
  property or the environment.
- Art. 73(2)-(4) deadlines: 15 days default; 10 days where a person
  died; 2 days for widespread infringement or Art. 3(49)(b) critical-
  infrastructure disruption. Clock starts at awareness.
- Art. 73(5): an initial report may be incomplete, followed by a
  complete report. This generator ALWAYS produces an "initial" report:
  operator-supplied fields are absent by construction.
- Report content expectations (industry consensus, NOT an official
  Commission template — the Commission's implementing-act template
  status is unverified; every field below is labeled with its basis):
  incident description, timeline, consequences, corrective measures
  taken/planned, affected Member States and individuals, provider
  contact.

HONESTY CONTRACT (fail-closed, never invent):
- Every rendered field carries ``provenance``: either
  ``{"kind": "log", "seq": N, "hash": "...", "field": "..."}`` or
  ``{"kind": "operator_must_supply"}``.
- Fields no log entry can supply are emitted as ``null`` with
  ``operator_must_supply: true`` — NEVER synthesized, NEVER defaulted.
- The legal classification of the incident (which Art. 3(49) limb, if
  any) is a legal determination: the generator does not make it.
- The generator REFUSES to render when the log chain does not verify
  (``IncidentReportError``) — a report whose timeline cannot be
  authenticated is worse than no report.

Integrity wiring (existing machinery, no parallel scheme):
- ``seal()`` binds the export to the log with ``gov.log.verify_chain``
  plus per-entry Merkle inclusion bundles (``gov.log.prove_inclusion``,
  verified offline with ``gov.log.verify_inclusion_bundle``).
- ``seal()`` optionally signs the manifest digest with a
  ``gov.signing.Signer`` (Ed25519).
- ``log_export_receipt()`` appends a hash-chained receipt of the sealed
  export back into the audit log via ``gov.log.ActionLog``, so the
  export itself is auditable.

$0 spend, synthetic/local only. No network.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from gov import log as _log

GENERATOR_VERSION = "0.2.0"
LEGAL_BASIS = "Regulation (EU) 2024/1689, Article 73 (Reporting of serious incidents)"

#: Event names (verified in main-tree code) that may anchor an incident.
#: detector_trip      <- gov/detection.py::build_detector_trip
#: infection_suspected <- gov/monitor/infection.py::_escalate
#: lineage_quarantine  <- gov/messaging.py::LineageQuarantine (docstring)
DEFAULT_ANCHOR_EVENTS = frozenset({
    "detector_trip",
    "infection_suspected",
    "lineage_quarantine",
})

#: Event-name substrings treated as corrective measures taken.
MITIGATION_HINTS = ("quarantine", "halt", "checkpoint", "recovery",
                    "revok", "decommission")

#: Art. 3(49) serious-incident limbs. The generator lists them; the
#: operator selects. Never auto-classified.
ART3_49_LIMBS = {
    "a": "death of a person, or serious harm to a person's health",
    "b": ("serious and irreversible disruption of the management or "
          "operation of critical infrastructure"),
    "c": ("infringement of obligations under Union law intended to "
          "protect fundamental rights"),
    "d": "serious harm to property or the environment",
}

#: Art. 73(2)-(4) reporting deadlines from awareness, keyed by limb.
DEADLINE_DAYS = {"b": 2, "a": 10, "default": 15}
# Note: "widespread infringement" (Art. 3(61)) also carries the 2-day
# clock; it is an operator determination, listed in the deadline table.


class IncidentReportError(Exception):
    """Loud failure: no anchor, unverifiable chain, or malformed input."""


def _op():
    """Provenance marker for fields the operator must supply."""
    return {"kind": "operator_must_supply", "note":
            "no audit-log entry can supply this field; the operator must "
            "provide it before filing. It is null, not defaulted."}


def _logprov(entry, field=None):
    p = {"kind": "log", "seq": entry["seq"], "hash": entry["hash"]}
    if field:
        p["field"] = field
    return p


def _parse_ts(ts):
    # Log timestamps are ISO-8601 UTC strings (gov/log.py::_utcnow).
    s = str(ts)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class IncidentReport:
    """Builds and seals an Art. 73 draft serious-incident report."""

    def __init__(self, log_path, *, anchor_events=None,
                 mitigation_hints=None):
        self.log_path = str(log_path)
        self.anchor_events = (frozenset(anchor_events)
                              if anchor_events is not None
                              else DEFAULT_ANCHOR_EVENTS)
        self.mitigation_hints = (tuple(mitigation_hints)
                                 if mitigation_hints is not None
                                 else MITIGATION_HINTS)
        self._logmod = _log
        self._entries = None

    # -- log handling -------------------------------------------------

    def _load_verified(self):
        """Read and chain-verify the log. Raises on any failure."""
        entries = self._logmod.read_entries(self.log_path)
        if not entries:
            raise IncidentReportError("log is empty: nothing to report")
        ok, broken_seq, _count = self._logmod.verify_chain(self.log_path)
        if not ok:
            raise IncidentReportError(
                "refusing to render: audit-log chain does not verify "
                "(broken at seq %s). A serious-incident report with an "
                "unauthenticated timeline is worse than no report."
                % (broken_seq,))
        self._entries = entries
        return entries

    def _find_anchor(self, entries, anchor_seq=None):
        """Locate the incident anchor entry.

        ``anchor_seq`` selects a specific entry (must be an anchor event);
        otherwise the earliest anchor-class event wins. Raises when no
        anchor exists — a report without an incident is not a report.
        """
        if anchor_seq is not None:
            for e in entries:
                if e["seq"] == anchor_seq:
                    if e.get("event") not in self.anchor_events:
                        raise IncidentReportError(
                            "seq %d is event %r, not an incident anchor "
                            "(anchor events: %s)"
                            % (anchor_seq, e.get("event"),
                               sorted(self.anchor_events)))
                    return e
            raise IncidentReportError(
                "anchor seq %d not found in log" % (anchor_seq,))
        for e in entries:
            if e.get("event") in self.anchor_events:
                return e
        raise IncidentReportError(
            "no incident anchor in log: no entry with event in %s. "
            "A serious-incident report requires an incident."
            % sorted(self.anchor_events))

    # -- report construction ------------------------------------------

    def build(self, anchor_seq=None):
        """Render the draft report dict. Every field has provenance."""
        entries = self._load_verified()
        anchor = self._find_anchor(entries, anchor_seq)
        awareness = _parse_ts(anchor["ts"])

        window = [e for e in entries if e["seq"] >= anchor["seq"]]
        timeline = [{
            "seq": e["seq"],
            "ts": e["ts"],
            "hash": e["hash"],
            "event": e.get("event"),
            "agent_id": e.get("agent_id"),
            "run_id": e.get("run_id"),
            "summary": str(e.get("reason", e.get("decision", "")))[:500],
            "provenance": _logprov(e),
        } for e in window]

        mitigations = [t for t in timeline
                       if any(h in str(t["event"] or "").lower()
                              for h in self.mitigation_hints)]
        agents = sorted({t["agent_id"] for t in timeline if t["agent_id"]})
        runs = sorted({t["run_id"] for t in timeline if t["run_id"]})

        deadlines = {
            "awareness_ts": awareness.isoformat(),
            "two_day": (awareness + timedelta(days=2)).isoformat(),
            "ten_day": (awareness + timedelta(days=10)).isoformat(),
            "fifteen_day": (awareness + timedelta(days=15)).isoformat(),
            "selection": None,
            "selection_provenance": _op(),
            "note": ("Art. 73(2)-(4): 2 days for widespread infringement "
                     "or Art. 3(49)(b) critical-infrastructure disruption; "
                     "10 days where a person died; 15 days otherwise. "
                     "Which clock applies is an operator legal "
                     "determination."),
        }

        def field(value, provenance):
            return {"value": value, "provenance": provenance}

        report = {
            "report_id": field("EUAIA-73-%s" % uuid.uuid4().hex[:12],
                               {"kind": "generator",
                                "generator": "gov/evidence_exports.py",
                                "version": GENERATOR_VERSION}),
            "legal_basis": field(
                LEGAL_BASIS,
                {"kind": "statute",
                 "citation": ("OJ L, 2024/1689 — Art. 73; serious-incident "
                              "definition Art. 3(49); initial incomplete "
                              "report permitted by Art. 73(5)"),
                 "correction": ("task brief cited Art. 55; corrected: "
                                "Art. 55 concerns GPAI systemic-risk "
                                "obligations, Art. 73 is serious-incident "
                                "reporting")}),
            "completeness": field(
                "initial",
                {"kind": "generator",
                 "note": ("Art. 73(5) permits an initial incomplete report "
                          "followed by a complete report; this generator "
                          "only ever produces 'initial'")}),
            "incident_anchor": field(
                {"event": anchor.get("event"), "seq": anchor["seq"],
                 "ts": anchor["ts"], "hash": anchor["hash"],
                 "agent_id": anchor.get("agent_id"),
                 "run_id": anchor.get("run_id")},
                _logprov(anchor)),
            "incident_description": field(
                str(anchor.get("reason", "")) or None,
                _logprov(anchor, "reason") if anchor.get("reason")
                else _op()),
            "timeline": field(timeline, {"kind": "log_window",
                                         "from_seq": anchor["seq"],
                                         "to_seq": entries[-1]["seq"],
                                         "count": len(timeline)}),
            "affected_systems_observed": field(
                {"agent_ids": agents, "run_ids": runs},
                {"kind": "log_window",
                 "note": "identities observed in the incident window only; "
                         "blast radius beyond the log is operator-supplied"}),
            "affected_member_states": field(None, _op()),
            "individuals_affected": field(None, _op()),
            "serious_incident_classification": field(
                None, {"kind": "operator_must_supply",
                       "limbs": ART3_49_LIMBS,
                       "note": ("legal determination under Art. 3(49); "
                                "the generator does not classify")}),
            "reporting_deadlines": field(deadlines, {"kind": "computed",
                                                     "from": _logprov(anchor, "ts")}),
            "corrective_measures_taken": field(
                [{"seq": m["seq"], "ts": m["ts"], "event": m["event"],
                  "summary": m["summary"], "hash": m["hash"]}
                 for m in mitigations],
                {"kind": "log_window",
                 "heuristic": "event name contains one of %s; review the "
                              "full timeline, not just this list"
                              % (list(self.mitigation_hints),)}),
            "corrective_measures_planned": field(None, _op()),
            "provider_contact": field(None, _op()),
            "deployer_contact": field(None, _op()),
        }
        return report

    # -- canonical form + sealing -------------------------------------

    @staticmethod
    def canonical(report):
        """Deterministic bytes for hashing/signing."""
        return json.dumps(report, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")

    def seal(self, report, *, signer=None):
        """Bind the rendered report to the verified log.

        Returns an integrity manifest: the export digest, the chain-
        verification result, and a Merkle inclusion bundle
        (``gov.log.prove_inclusion``) for every timeline entry, so an
        auditor can re-verify offline that each cited entry is in the
        log the report claims.

        Inclusion bundles require SIGNED (Ed25519 v2) checkpoints; a
        log with HMAC-only checkpoints yields no bundles, and the
        manifest says so explicitly per entry instead of implying
        coverage. This is a deployment property, not a generator
        defect: run the log with a ``gov.signing.Signer`` to get
        third-party-verifiable inclusion proofs.

        ``signer`` (optional) is a ``gov.signing.Signer``: when given,
        the manifest digest is signed and the signature embedded.
        Without a signer the manifest is HMAC-chain-anchored only —
        stated explicitly, not implied.
        """
        entries = self._entries
        if entries is None:
            raise IncidentReportError(
                "seal() requires build() first (log not loaded)")
        body = self.canonical(report)
        digest = hashlib.sha256(body).hexdigest()
        timeline = report["timeline"]["value"]
        bundles = []
        covered = 0
        for t in timeline:
            try:
                b = self._logmod.prove_inclusion(self.log_path, t["seq"])
            except ValueError as e:
                b = None
                reason = str(e)
            else:
                reason = None
                covered += 1
            bundles.append({
                "seq": t["seq"],
                "bundle": b,
                "unavailable_reason": reason,
            })
        ok, broken_seq, _count = self._logmod.verify_chain(self.log_path)
        manifest = {
            "kind": "art73_export_manifest",
            "generator": "gov/evidence_exports.py",
            "generator_version": GENERATOR_VERSION,
            "legal_basis": LEGAL_BASIS,
            "report_id": report["report_id"]["value"],
            "export_sha256": digest,
            "log_path": self.log_path,
            "chain_verified": ok,
            "chain_broken_seq": broken_seq,
            "inclusion_coverage": {
                "entries": len(timeline),
                "with_bundle": covered,
                "note": ("inclusion bundles require signed (Ed25519 v2) "
                         "checkpoints; entries without a bundle name their "
                         "reason in unavailable_reason"),
            },
            "inclusion_bundles": bundles,
            "signing": None,
        }
        if signer is not None:
            sig = signer.sign(digest.encode("ascii"))
            manifest["signing"] = {
                "scheme": "ed25519",
                "key_id": getattr(signer, "key_id", None),
                "signature_hex": sig.hex(),
                "signed_bytes": "utf-8(export_sha256)",
            }
        else:
            manifest["signing"] = {
                "scheme": "none",
                "note": ("no signer configured: manifest is anchored by "
                         "the log's HMAC chain + inclusion proofs only; "
                         "configure a gov.signing.Signer for non-repudiation"),
            }
        return manifest

    # -- rendering ------------------------------------------------------

    @staticmethod
    def to_json(report):
        return json.dumps(report, indent=2, ensure_ascii=True,
                          sort_keys=True) + "\n"

    @staticmethod
    def to_markdown(report):
        """Human-readable draft for operator review before filing."""
        L = []
        A = L.append
        g = lambda f: report[f]["value"]  # noqa: E731
        A("# DRAFT Serious Incident Report — EU AI Act Art. 73")
        A("")
        A("> GENERATED DRAFT — NOT FILED. Art. 73(5) initial report. "
          "Fields marked **[OPERATOR]** must be supplied before filing.")
        A("")
        A("- Report ID: `%s`" % g("report_id"))
        A("- Legal basis: %s" % g("legal_basis"))
        A("- Completeness: %s" % g("completeness"))
        A("")
        A("## Incident")
        anc = g("incident_anchor")
        A("- Anchor event: `%s` at seq %d (%s)" % (anc["event"],
                                                  anc["seq"], anc["ts"]))
        A("- Anchor hash: `%s`" % anc["hash"])
        A("- Description (from log): %s" % (g("incident_description")
                                            or "[OPERATOR: describe]"))
        A("")
        A("## Classification **[OPERATOR]**")
        A("Art. 3(49) limb: _unselected_ — " +
          "; ".join("(%%s) %s" % v for v in
                     ART3_49_LIMBS.values()) % tuple(ART3_49_LIMBS))
        A("")
        A("## Reporting deadlines (from awareness %s)"
          % g("reporting_deadlines")["awareness_ts"])
        dl = g("reporting_deadlines")
        A("- 2-day clock (widespread infringement / Art. 3(49)(b)): %s"
          % dl["two_day"])
        A("- 10-day clock (death of a person): %s" % dl["ten_day"])
        A("- 15-day clock (all other serious incidents): %s"
          % dl["fifteen_day"])
        A("")
        A("## Timeline (%d entries, hash-chained)"
          % len(g("timeline")))
        for t in g("timeline"):
            A("- seq %d `%s` %s — %s" % (t["seq"], t["event"], t["ts"],
                                         t["summary"] or ""))
            A("  hash `%s`" % t["hash"])
        A("")
        A("## Corrective measures taken (observed in log)")
        ms = g("corrective_measures_taken")
        if ms:
            for m in ms:
                A("- seq %d `%s`: %s" % (m["seq"], m["event"], m["summary"]))
        else:
            A("- _none observed in incident window_")
        A("")
        A("## [OPERATOR] To supply before filing")
        for f in ("affected_member_states", "individuals_affected",
                  "corrective_measures_planned", "provider_contact",
                  "deployer_contact"):
            A("- `%s`: %s" % (f, g(f)))
        A("")
        A("## Evidence integrity")
        A("Verify with the export manifest: recompute sha256 of the "
          "canonical JSON, re-verify the log chain, and check each "
          "inclusion bundle with `gov.log.verify_inclusion_bundle`.")
        return "\n".join(L) + "\n"


def log_export_receipt(manifest, action_log):
    """Append a hash-chained receipt of a sealed export to the audit log.

    Uses the existing ``gov.log.ActionLog`` machinery — the receipt
    becomes a chained entry, so the export itself is auditable in the
    same evidence chain the report cites.

    ``manifest`` is the dict returned by :meth:`IncidentReport.seal`;
    ``action_log`` is an open ``gov.log.ActionLog`` on the log the
    report was built from. Appending the receipt does not disturb the
    sealed manifest: the manifest commits to the log state at build
    time, and the receipt is a later chained entry.

    Returns the appended entry.
    """
    return action_log.append({
        "event": "evidence_export_sealed",
        "report_id": manifest.get("report_id"),
        "export_sha256": manifest["export_sha256"],
        "chain_verified_at_seal": manifest.get("chain_verified"),
        "reason": ("EU AI Act Art. 73 draft export sealed; manifest digest "
                   "%s" % manifest["export_sha256"][:16]),
    })
