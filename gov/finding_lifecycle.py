"""Governed finding lifecycle (ADAPT, mechanism only, stdlib only).

Steals the three DefectDojo (django-DefectDojo, BSD-3-Clause, OSS core)
lifecycle patterns named in the wave-282 prospectus -- contract shapes only,
no code vendored, Pro-edition features (SLA Configuration, location-drift
matching) deliberately not taken:

1. **Identity-hash dedup** (``hash_code`` analog): a deterministic sha256
   over a *configurable* field set of the defect shape. Parallel lanes that
   file the same defect converge to one identity, so merge-time renumbering
   becomes a registry lookup instead of commit-timestamp forensics (the
   wave-272 renumber-map workaround dies).
2. **Governed state machine**: open -> under_review -> verified (or
   mitigated via the re-verify sweep); false_positive retained for audit and
   excluded from metrics; risk_accepted acknowledged-but-open and excluded
   from SLA; duplicate linked; out_of_scope. Human edits always win: the
   ``close_old_findings`` sweep never overrides human triage.
3. **close_old_findings as a state transition**: each wave's red-first
   batteries are the "scan"; a finding whose break-first probe no longer
   reproduces transitions to ``mitigated`` with the scan cited as evidence.
4. **Per-severity SLA in waves**: HIGH 1 wave, MEDIUM 2 waves, LOW 3 waves.
   A breach raises loudly (``finding-sla-breached``); risk_accepted and
   false_positive are excluded.

This is a *layer over* ``evals/FINDINGS.md``: :func:`load_findings_md`
parses the prose headers into registry entries (identity computed from the
parsed cells/defect/close-when), so the legacy record participates in the
governed lifecycle without being rewritten.

Deliberate design notes (reviewed, kept):
- ``open -> verified`` is allowed directly: that edge is the red-first
  post-wave closure audit path (the merge coordinator closes findings with
  battery evidence, not by lingering in under_review). ``under_review`` is
  the human-triage-in-progress state; the sweep never overrides it.
- ``load_findings_md`` is the briefed "layer over evals/FINDINGS.md", not
  creep: the parse is heuristic by design (prose), severity defaults to low
  only when no marker is present, and the battery's live-prose pins
  (F311 open, F310 closed) are red-first pins on the record, repointed by
  the merge like any pin.
- SLA statuses are stringly-typed ("ok"/"due"/"excluded"/"unknown") by
  repo convention (string machine codes everywhere).
"""

import hashlib
import json
import re

# ---------------------------------------------------------------------------
# Machine codes (inventory item 1: class-level ``code`` attributes).
# Registered in gov/decision_codes.py.
# ---------------------------------------------------------------------------


class FindingLifecycleError(ValueError):
    """Base lifecycle refusal: illegal transition or missing evidence."""

    code = "finding-illegal-transition"

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code or type(self).code


class FindingSlaBreached(FindingLifecycleError):
    """Raised loudly when an open finding passes its per-severity wave SLA."""

    code = "finding-sla-breached"


# ---------------------------------------------------------------------------
# Identity hash (DefectDojo ``hash_code`` analog).
# ---------------------------------------------------------------------------

#: Canonical identity fields. ``title`` is included by default; callers that
#: resolve parallel-lane collisions use the seam-focused subset, exactly the
#: way DefectDojo makes its hash_code field set configurable per product.
CANONICAL_FIELDS = ("title", "seam", "attack_shape", "close_when")


def _canonicalize(value):
    """Normalize a field for identity purposes: collapse all whitespace."""
    return re.sub(r"\s+", " ", str(value)).strip()


def finding_identity(title, seam, attack_shape, close_when,
                     fields=CANONICAL_FIELDS):
    """Deterministic sha256 identity over the defect shape.

    ``fields`` selects the configurable subset (DefectDojo's configurable
    hash_code); the default is the full canonical set. Canonicalization is
    JSON with sorted keys over whitespace-normalized fields, so paraphrased
    whitespace converges while distinct shapes diverge.
    """
    available = {"title": title, "seam": seam, "attack_shape": attack_shape,
                 "close_when": close_when}
    for f in fields:
        if f not in available:
            raise FindingLifecycleError(
                "unknown identity field %r" % f)
    payload = {f: _canonicalize(available[f]) for f in sorted(fields)}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# State machine.
# ---------------------------------------------------------------------------

STATES = (
    "open",
    "under_review",
    "verified",
    "mitigated",
    "false_positive",
    "risk_accepted",
    "duplicate",
    "out_of_scope",
)

#: Closed transition table. Terminal states have no outgoing edges.
_TRANSITIONS = {
    "open": {"under_review", "verified", "mitigated", "false_positive",
             "risk_accepted", "duplicate", "out_of_scope"},
    "under_review": {"open", "verified", "mitigated", "false_positive",
                     "risk_accepted", "duplicate", "out_of_scope"},
    "verified": set(),
    "mitigated": set(),
    "false_positive": set(),
    "risk_accepted": set(),
    "duplicate": set(),
    "out_of_scope": set(),
}

#: States excluded from the SLA clock (DefectDojo: False Positive retained
#: for audit and excluded from risk; Risk Accepted excluded from SLA).
_SLA_EXCLUDED = {"false_positive", "risk_accepted", "verified", "mitigated",
                 "duplicate", "out_of_scope"}

#: States excluded from finding metrics (pressure ratchets stay honest).
_METRIC_EXCLUDED = {"false_positive", "risk_accepted", "duplicate",
                    "out_of_scope"}

#: Per-severity SLA, expressed in waves.
SLA_WAVES = {"high": 1, "medium": 2, "low": 3}

_SEVERITIES = tuple(SLA_WAVES)

#: Severity rank for escalation comparisons (F322): a higher rank means
#: a tighter SLA clock. Dedup must never silently inherit a WEAKER
#: (lower-rank) SLA.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


class Transition:
    """One evidence-carrying state transition."""

    def __init__(self, from_state, to_state, wave, actor, evidence):
        self.from_state = from_state
        self.to_state = to_state
        self.wave = wave
        self.actor = actor
        self.evidence = dict(evidence or {})

    def to_json(self):
        return {"from_state": self.from_state, "to_state": self.to_state,
                "wave": self.wave, "actor": self.actor,
                "evidence": self.evidence}

    @classmethod
    def from_json(cls, data):
        return cls(data["from_state"], data["to_state"], data["wave"],
                   data["actor"], data.get("evidence", {}))


class Finding:
    """A governed finding record."""

    def __init__(self, number, title, severity, identity_hash, reporter,
                 opened_wave, state="open"):
        if severity not in _SEVERITIES:
            raise FindingLifecycleError(
                "unknown severity %r" % severity)
        if state not in STATES:
            raise FindingLifecycleError("unknown state %r" % state)
        self.number = number
        self.title = title
        self.severity = severity
        self.identity_hash = identity_hash
        self.reporter = reporter
        self.opened_wave = opened_wave
        self.state = state
        #: Canonical finding this record duplicates (set when transitioning
        #: to ``duplicate``; DefectDojo's Duplicate-with-link).
        self.duplicate_of = None
        self.transitions = []
        #: Parallel filings that converged onto this identity (provenance of
        #: the wave-272 collision class, retained without renumbering).
        self.filings = [{"reporter": reporter, "wave": opened_wave,
                         "title": title}]
        self.scan_notes = []

    def to_json(self):
        return {"number": self.number, "title": self.title,
                "severity": self.severity,
                "identity_hash": self.identity_hash,
                "reporter": self.reporter, "opened_wave": self.opened_wave,
                "state": self.state, "duplicate_of": self.duplicate_of,
                "transitions": [t.to_json() for t in self.transitions],
                "filings": self.filings, "scan_notes": self.scan_notes}

    @classmethod
    def from_json(cls, data):
        f = cls(data["number"], data["title"], data["severity"],
                data["identity_hash"], data["reporter"],
                data.get("opened_wave"), state=data.get("state", "open"))
        f.duplicate_of = data.get("duplicate_of")
        f.transitions = [Transition.from_json(t)
                         for t in data.get("transitions", [])]
        f.filings = data.get("filings", f.filings)
        f.scan_notes = data.get("scan_notes", [])
        return f


def _require_closure_evidence(to_state, evidence):
    """Evidence rules per target state (DefectDojo attribution as required
    fields). Raises FindingLifecycleError(code=finding-illegal-transition)."""
    evidence = evidence or {}
    if to_state in ("verified", "mitigated"):
        missing = [k for k in ("battery", "commit") if k not in evidence]
        if missing:
            raise FindingLifecycleError(
                "closure to %r requires red-first evidence (missing %s)"
                % (to_state, ",".join(missing)))
        # F316: key presence alone is not evidence -- a None/empty battery
        # or commit would record a closure backed by nothing.
        empty = [k for k in ("battery", "commit") if not evidence.get(k)]
        if empty:
            raise FindingLifecycleError(
                "closure to %r requires non-empty red-first evidence "
                "(empty %s)" % (to_state, ",".join(empty)))
    if to_state in ("false_positive", "risk_accepted"):
        if not evidence.get("note"):
            raise FindingLifecycleError(
                "state %r requires a triage note (retained for audit)"
                % to_state)
    if to_state == "duplicate":
        if not evidence.get("duplicate_of"):
            raise FindingLifecycleError(
                "state 'duplicate' requires evidence['duplicate_of'] "
                "naming the canonical finding (duplicate-with-link)")


# ---------------------------------------------------------------------------
# Registry.
# ---------------------------------------------------------------------------

class FindingRegistry:
    """Identity-keyed finding registry.

    ``default_fields`` is the configurable identity field set used when
    lanes file findings (seam-focused by default, so parallel lanes filing
    the same defect shape with paraphrased titles converge).
    """

    def __init__(self, next_number=312,
                 default_fields=("seam", "attack_shape", "close_when")):
        self._by_number = {}
        self._by_identity = {}
        self.next_number = next_number
        self.default_fields = tuple(default_fields)

    # -- filing -----------------------------------------------------------

    def file_finding(self, title, seam, attack_shape, close_when, severity,
                     reporter, wave):
        """File a finding. Returns ``(number, kind)`` where kind is
        ``"filed"`` for a new identity or ``"duplicate"`` when the identity
        already exists (the filing is appended to the canonical record's
        provenance; no new F-number is consumed). A duplicate filing whose
        severity outranks the canonical severity ESCALATES the canonical
        record (F322) -- the registry never silently inherits a weaker
        SLA."""
        if severity not in _SEVERITIES:
            raise FindingLifecycleError(
                "unknown severity %r" % severity)
        ident = finding_identity(title, seam, attack_shape, close_when,
                                 fields=self.default_fields)
        if ident in self._by_identity:
            canon = self._by_number[self._by_identity[ident]]
            filing = {"reporter": reporter, "wave": wave, "title": title,
                      "severity": severity}
            canon.filings.append(filing)
            if _SEVERITY_RANK[severity] > _SEVERITY_RANK[canon.severity]:
                # F322: severity-blind dedup let a HIGH filing inherit a
                # pre-seeded LOW's 3-wave SLA. A filing that outranks the
                # canonical severity ESCALATES the canonical record --
                # never silently inherits the weaker SLA. Downgrades are
                # never applied (the canonical keeps its tightest SLA).
                old = canon.severity
                canon.severity = severity
                canon.scan_notes.append(
                    "severity escalated %s -> %s by duplicate filing "
                    "(reporter %s, wave %s)" % (old, severity, reporter,
                                                wave))
            return canon.number, "duplicate"
        number = "F%d" % self.next_number
        self.next_number += 1
        f = Finding(number, title, severity, ident, reporter, wave)
        self._by_number[number] = f
        self._by_identity[ident] = number
        return number, "filed"

    def lookup_identity(self, identity_hash):
        """Resolve a defect shape to its canonical finding number (the
        merge-time renumber-map replacement)."""
        return self._by_identity.get(identity_hash)

    def get(self, number):
        return self._by_number.get(number)

    def all(self):
        return [self._by_number[n]
                for n in sorted(self._by_number,
                                key=lambda n: int(n[1:]))]

    def metric_findings(self):
        """Findings that count toward pressure-ratchet metrics."""
        return [f for f in self.all() if f.state not in _METRIC_EXCLUDED]

    # -- transitions ------------------------------------------------------

    def transition(self, number, to_state, wave, actor, evidence=None):
        f = self.get(number)
        if f is None:
            raise FindingLifecycleError("unknown finding %r" % number)
        if to_state not in STATES:
            raise FindingLifecycleError("unknown state %r" % to_state)
        if to_state not in _TRANSITIONS[f.state]:
            raise FindingLifecycleError(
                "illegal transition %s -> %s" % (f.state, to_state))
        _require_closure_evidence(to_state, evidence)
        t = Transition(f.state, to_state, wave, actor, evidence)
        f.transitions.append(t)
        f.state = to_state
        if to_state == "duplicate":
            f.duplicate_of = evidence["duplicate_of"]
        return t

    # -- SLA --------------------------------------------------------------

    @staticmethod
    def sla_due_wave(finding):
        """The wave at which the finding's SLA clock runs out, or ``None``
        when the finding has no recorded opening wave (legacy prose
        entries) -- the clock cannot be computed, so ``check_sla`` reports
        ``"unknown"`` loudly instead of silently treating it as OK."""
        if finding.opened_wave is None:
            return None
        return finding.opened_wave + SLA_WAVES[finding.severity]

    def check_sla(self, finding, current_wave):
        """``"ok"`` / ``"due"`` / ``"excluded"`` / ``"unknown"``; raises
        :class:`FindingSlaBreached` past the due wave. ``"unknown"`` means
        the opening wave is missing -- a loud signal to triage, never OK."""
        if finding.state in _SLA_EXCLUDED:
            return "excluded"
        due = self.sla_due_wave(finding)
        if due is None:
            return "unknown"
        if current_wave > due:
            raise FindingSlaBreached(
                "%s (%s, opened wave %s) breached its %d-wave SLA at wave %d"
                % (finding.number, finding.severity, finding.opened_wave,
                   SLA_WAVES[finding.severity], current_wave))
        return "due" if current_wave == due else "ok"

    def sla_report(self, current_wave):
        """Wave-boundary SLA roll call over every open finding: maps
        finding number -> one of ``"ok"`` / ``"due"`` / ``"unknown"``.
        Excluded findings are omitted. Never raises."""
        report = {}
        for f in self.all():
            if f.state in _SLA_EXCLUDED:
                continue
            report[f.number] = self.check_sla(f, current_wave)
        return report

    def sweep_sla(self, current_wave):
        """Run the SLA roll call and escalate loudly: raises a single
        :class:`FindingSlaBreached` naming every breached finding, so a
        wave boundary cannot silently age open findings. Returns the list
        of breached numbers when nothing raises."""
        breached = []
        for f in self.all():
            if f.state in _SLA_EXCLUDED:
                continue
            due = self.sla_due_wave(f)
            if due is not None and current_wave > due:
                breached.append(f.number)
        if breached:
            raise FindingSlaBreached(
                "SLA breached at wave %d by: %s" % (current_wave,
                                                   ",".join(breached)))
        return breached

    # -- close_old_findings sweep -----------------------------------------

    def close_old_findings(self, scan, wave, actor):
        """DefectDojo ``close_old_findings`` analog: ``scan`` maps finding
        numbers to ``{"reproduced": bool, "battery": ..., "probes": [...],
        "commit": ...}``. An OPEN finding whose break-first probe no longer
        reproduces transitions to ``mitigated`` carrying the scan as
        evidence. UNDER_REVIEW (human triage) is NEVER overridden; the scan
        is recorded as a note instead. ``reproduced`` must be an explicit
        bool -- a malformed entry raises ``FindingLifecycleError`` LOUD and
        aborts the sweep (entries already processed stay processed; the
        rest defer to the next sweep)."""
        mitigated = []
        for number, result in scan.items():
            f = self.get(number)
            if f is None or f.state in _SLA_EXCLUDED:
                continue
            if not isinstance(result, dict):
                # F316: a non-dict scan value would escape as an uncoded
                # AttributeError on .get -- refuse LOUD with the coded
                # lifecycle error instead.
                raise FindingLifecycleError(
                    "scan entry for %s is not a dict (got %r); refusing "
                    "to close" % (number, result))
            reproduced = result.get("reproduced")
            if not isinstance(reproduced, bool):
                # F316: fail-closed on malformed scan input. An absent (or
                # non-boolean) break-first verdict is not evidence of
                # anything; the old fall-through fabricated a "mitigated"
                # transition with a fabricated evidence note. Loud here,
                # never a closure, never a silent skip.
                raise FindingLifecycleError(
                    "scan entry for %s has no explicit boolean "
                    "'reproduced' (got %r); refusing to close"
                    % (number, reproduced))
            note = {"battery": result.get("battery"),
                    "probes": result.get("probes"),
                    "commit": result.get("commit"), "wave": wave,
                    "reproduced": reproduced}
            if reproduced:
                f.scan_notes.append(note)
                continue
            if f.state == "under_review":
                # Human edits always win.
                f.scan_notes.append(note)
                continue
            self.transition(number, "mitigated", wave, actor,
                            evidence=dict(note, note=(
                                "break-first probe no longer reproduces")))
            mitigated.append(number)
        return mitigated

    # -- persistence ------------------------------------------------------

    def to_json(self):
        return {"next_number": self.next_number,
                "default_fields": list(self.default_fields),
                "findings": [f.to_json() for f in self.all()]}

    @classmethod
    def from_json(cls, data):
        reg = cls(next_number=data.get("next_number", 1),
                  default_fields=tuple(
                      data.get("default_fields",
                               ("seam", "attack_shape", "close_when"))))
        for fd in data.get("findings", []):
            f = Finding.from_json(fd)
            reg._by_number[f.number] = f
            reg._by_identity[f.identity_hash] = f.number
        return reg


# ---------------------------------------------------------------------------
# FINDINGS.md loader: the governed layer over the prose record.
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(r"^##\s+(F\d+)\s*[:\u2014-]\s*(.*?)\s*$", re.M)
_SEV_PAREN_RE = re.compile(r"\((LOW|MEDIUM|HIGH)\)\s*$", re.IGNORECASE)
_SEV_DASH_RE = re.compile(r"\u2014\s*(LOW|MEDIUM|HIGH)\s*\u2014", re.IGNORECASE)
_STATUS_RE = re.compile(r"\*\*Status:\s*(OPEN|CLOSED)\b", re.IGNORECASE)
_WAVE_RE = re.compile(r"[Ww]ave[-\s]?(\d+)")


def _split_sections(body):
    """Split an entry body into its ``**Label:**`` prose sections."""
    sections = {}
    current = None
    for line in body.splitlines():
        m = re.match(r"^\*\*([^*]+):\*\*\s*(.*)$", line)
        if m:
            current = m.group(1).strip().lower()
            sections[current] = m.group(2)
        elif current is not None:
            sections[current] += "\n" + line
    return sections


def _entry_fields(number, title, body):
    sev = None
    m = _SEV_PAREN_RE.search(title)
    if m:
        sev = m.group(1).lower()
        title = title[:m.start()].strip()
    else:
        m = _SEV_DASH_RE.search(title)
        if m:
            sev = m.group(1).lower()
            title = _SEV_DASH_RE.sub(" ", title).strip(" \u2014-")
    sev = sev or "low"
    # F323: a marker-less entry previously imported as "verified",
    # silently closing legacy OPEN findings (verified is SLA- and
    # metrics-excluded). Marker-less entries are unexamined prose: they
    # import as "open" so a human triages them; "verified" requires an
    # explicit **Status:** CLOSED marker.
    status = "open"
    m = _STATUS_RE.search(body)
    if m:
        status = "open" if m.group(1).upper() == "OPEN" else "verified"
    sections = _split_sections(body)
    cells = sections.get("cells", "")
    defect = sections.get("defect", "")
    close_when = sections.get("close-when criteria", "")
    wave = None
    m = _WAVE_RE.search(cells)
    if m:
        wave = int(m.group(1))
    return {"title": title, "severity": sev, "state": status,
            "cells": cells, "defect": defect, "close_when": close_when,
            "wave": wave}


def load_findings_md(path, default_fields=("seam", "attack_shape",
                                          "close_when")):
    """Parse ``evals/FINDINGS.md`` into a :class:`FindingRegistry`.

    Identity is computed over (cells -> seam, defect -> attack_shape,
    close-when -> close_when) with the given field set; the parse is
    heuristic by design (the file is prose). Status maps explicitly:
    ``**Status:** OPEN`` -> ``open``, ``**Status:** CLOSED`` ->
    ``verified``; entries with no ``**Status:**`` marker import as
    ``open`` (F323 -- never silently closed as ``verified``). Severity
    defaults to low when no severity marker is present. Nothing else is
    inferred.
    """
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    reg = FindingRegistry(next_number=1, default_fields=default_fields)
    heads = [(m.start(), m.group(1), m.group(2))
             for m in _HEADER_RE.finditer(src)]
    for i, (pos, number, title) in enumerate(heads):
        end = heads[i + 1][0] if i + 1 < len(heads) else len(src)
        body = src[pos:end]
        info = _entry_fields(number, title, body)
        ident = finding_identity(info["title"], info["cells"],
                                 info["defect"], info["close_when"],
                                 fields=default_fields)
        f = Finding(number, info["title"], info["severity"], ident,
                    reporter="findings-md", opened_wave=info["wave"],
                    state=info["state"])
        reg._by_number[number] = f
        reg._by_identity.setdefault(ident, number)
        reg.next_number = max(reg.next_number,
                              int(number[1:]) + 1)
    return reg
