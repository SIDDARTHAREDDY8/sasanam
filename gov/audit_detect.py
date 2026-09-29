"""Auditor-side detection over chained-audit streams -- product code.

Read-only, offline, NEVER the enforcement hot path. The auditor loads
a signed detection-rule pack (``gov/rule_pack.py`` -- a tampered rule
blinds the auditor, so the pack's signature, version, and expiry are
verified before any rule compiles), evaluates Sigma-shaped rules
(``gov/sigma_subset.py``) over exported chained-audit entries, and
emits a :class:`DetectionReport` of alerts + loud assumption
warnings.

Product lesson (wave-196 spike): detection content and enforcement
semantics must agree. When a rule's world-model assumptions are
violated -- e.g. the events the rule reasons about stopped carrying
the fields it needs -- the report carries a loud warning instead of
failing silently. A rule that cannot see is worse than no rule.

Seams:

* Evaluated over exported chained-audit streams (``gov.log`` entry
  dicts) feeding the evidence-bundle auditor workflow.
* :meth:`DetectionReport.inbox_items` returns review-worklist dicts
  for the auditor's review inbox (plain data; the auditor's workflow
  owns submission).
* Do NOT wire alerts into ``gov.detection``'s enforcement breakers
  without a separate red-team pass: auditor detection and enforcement
  tripping have different false-positive budgets.

Fail-closed codes (``DetectionError.code``):
``rule-tampered`` (pack digest mismatch), ``rule-missing`` (pack
names a rule file that is absent), ``rule-unbound`` (rule file
present but not bound by the pack), ``bad-rule`` (parse/compile
failure), ``unsupported-correlation`` (unknown ``correlation:``
type -- never silently skipped), ``pack-invalid`` (wraps
``RulePackError`` from ``gov.rule_pack``).

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import json
import math
import os

from .rule_pack import RulePackError, verify_rule_pack
from .sigma_subset import (
    RuleError,
    SigmaSubsetError,
    compile_rule,
    event_time,
    parse_rule_text,
    StreamEngine,
)

__all__ = [
    "DetectionError",
    "DetectionReport",
    "ImpossibleTravelCorrelator",
    "check_rule_assumptions",
    "detect_on_entries",
    "detect_on_export",
    "load_rule_pack",
    "DEFAULT_GEO_TABLE",
    "RULE_PACK_FILENAME",
    "REPORT_VERSION",
]

#: The signed pack manifest lives next to the rules it binds.
RULE_PACK_FILENAME = "rule_pack.json"

#: Detection report format tag.
REPORT_VERSION = "sasanam-audit-detection/v1"

#: Operator-tunable city table for the impossible-travel correlator.
#: Deployments override via the ``geo_table`` argument; unknown geo
#: names produce loud warnings (the pair is skipped, never guessed).
DEFAULT_GEO_TABLE = {
    "Lagos": (6.52, 3.37),
    "Abuja": (9.06, 7.49),
    "London": (51.51, -0.13),
    "New York": (40.71, -74.00),
    "Singapore": (1.35, 103.82),
    "Tokyo": (35.68, 139.69),
    "Sydney": (-33.87, 151.21),
}


class DetectionError(Exception):
    """Fail-closed auditor-detection violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        """Build the exception; the message is ``code`` + ``detail``."""
        super(DetectionError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _sha256_pin(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_rule_pack(rules_dir, pack_doc, keyset, *, now=None):
    """Verify the signed pack and load every rule it binds.

    ``rules_dir`` holds ``*.yml`` rule files plus ``rule_pack.json``.
    ``pack_doc`` is the parsed pack manifest; ``keyset`` the
    rule-signing keyset. Fail-closed: the pack must verify (signature,
    version, expiry, purpose); every ``*.yml`` in the directory must
    be bound by the pack (an unbound file is refused -- a smuggled
    rule must not load); every bound rule file must exist and its
    digest must match the pack (a tampered rule is refused loudly);
    every rule must parse and compile. Returns
    ``(RulePack, [CompiledRule])`` sorted by rule file name.
    """
    if not isinstance(rules_dir, str) or not rules_dir:
        raise DetectionError("bad-rule", "rules_dir is required")
    try:
        pack = verify_rule_pack(pack_doc, keyset, now=now)
    except RulePackError as exc:
        raise DetectionError("pack-invalid", str(exc))
    if not os.path.isdir(rules_dir):
        raise DetectionError("bad-rule",
                             "rules_dir is not a directory: %r" % (rules_dir,))
    files = sorted(f for f in os.listdir(rules_dir)
                   if f.endswith((".yml", ".yaml")))
    if not files:
        raise DetectionError("bad-rule",
                             "no rule files in %r" % (rules_dir,))
    bound_ids = set(pack.rules)
    seen_ids = set()
    compiled = []
    for fname in files:
        path = os.path.join(rules_dir, fname)
        raw = _read_text(path).encode("utf-8")
        try:
            doc = parse_rule_text(raw.decode("utf-8"))
        except SigmaSubsetError as exc:
            raise DetectionError("bad-rule",
                                 "%s does not parse: %s" % (fname, exc))
        rid = str(doc.get("id", ""))
        if not rid:
            raise DetectionError("bad-rule",
                                 "%s has no id" % (fname,))
        if rid not in bound_ids:
            # A rule file the pack does not bind must never load --
            # otherwise anyone who can drop a file blinds or floods
            # the auditor.
            raise DetectionError("rule-unbound",
                                 "%s (id %s) is not bound by the rule pack"
                                 % (fname, rid))
        if rid in seen_ids:
            raise DetectionError("bad-rule",
                                 "duplicate rule id %s in %s" % (rid, fname))
        seen_ids.add(rid)
        want = pack.digest_for(rid)
        got = _sha256_pin(raw)
        if got != want:
            raise DetectionError("rule-tampered",
                                 "%s (id %s): digest %s != pack %s"
                                 % (fname, rid, got, want))
        try:
            rule = compile_rule(doc)
        except (RuleError, SigmaSubsetError) as exc:
            raise DetectionError("bad-rule",
                                 "%s does not compile: %s" % (fname, exc))
        compiled.append(rule)
    missing = sorted(bound_ids - seen_ids)
    if missing:
        raise DetectionError("rule-missing",
                             "pack binds rule ids with no file: %s"
                             % ", ".join(missing))
    return pack, compiled


# --------------------------------------------------------------------------
# Correlators: pairwise temporal correlation beyond the selection subset.
# --------------------------------------------------------------------------

def _haversine_km(a, b):
    lat1, lon1 = (math.radians(x) for x in a)
    lat2, lon2 = (math.radians(x) for x in b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = (math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2)
         * math.sin(dlon / 2) ** 2)
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def _geo_coords(geo, geo_table):
    """Resolve a geo value to (lat, lon): [lat, lon] pairs pass
    through; strings resolve via the operator's geo table. Returns
    None when unresolvable (the caller warns loudly)."""
    if isinstance(geo, (list, tuple)) and len(geo) == 2:
        try:
            return (float(geo[0]), float(geo[1]))
        except (TypeError, ValueError):
            return None
    if isinstance(geo, str):
        hit = geo_table.get(geo)
        if hit is None:
            return None
        try:
            return (float(hit[0]), float(hit[1]))
        except (TypeError, ValueError):
            return None
    return None


class ImpossibleTravelCorrelator:
    """Stateful pairwise correlator for impossible-travel rules.

    Parameters come from the rule YAML's ``correlation:`` block
    (``type: impossible_travel``, ``max_km``, ``max_minutes``;
    optional ``key_field``/``geo_field``). Tracks the last (ts, geo)
    per key; alerts when consecutive selected events for one key are
    farther than ``max_km`` apart within ``max_minutes``. Unresolvable
    geo values produce loud warnings (the pair is skipped, never
    guessed). Unknown correlation types are refused at construction --
    a correlator the engine cannot run must never be silently
    ignored.
    """

    def __init__(self, rule, *, geo_table=None):
        """Bind to a compiled rule carrying a ``correlation:`` block."""
        corr = (rule.raw_doc or {}).get("correlation") or {}
        if corr.get("type") != "impossible_travel":
            raise DetectionError(
                "unsupported-correlation",
                "rule %s: correlation.type %r is not implemented"
                % (rule.rule_id, corr.get("type")))
        self.rule = rule
        self.max_km = float(corr.get("max_km", 5000))
        self.max_minutes = float(corr.get("max_minutes", 60))
        self.key_field = str(corr.get("key_field", "agent_id"))
        self.geo_field = str(corr.get("geo_field", "geo"))
        self.geo_table = dict(geo_table if geo_table is not None
                              else DEFAULT_GEO_TABLE)
        self._last = {}
        self.warnings = []

    def feed(self, events):
        """Feed timestamp-ordered events; returns alert dicts."""
        alerts = []
        for ev in sorted(events, key=event_time):
            if not self.rule.matches(ev):
                continue
            key = ev.get(self.key_field)
            geo = ev.get(self.geo_field)
            ts = event_time(ev)
            prev = self._last.get(key)
            self._last[key] = (ts, geo)
            if prev is None or key is None:
                continue
            coords = _geo_coords(geo, self.geo_table)
            prev_coords = _geo_coords(prev[1], self.geo_table)
            if coords is None or prev_coords is None:
                self.warnings.append({
                    "code": "geo-unresolvable",
                    "rule_id": self.rule.rule_id,
                    "detail": ("geo %r (or previous %r) not resolvable "
                               "for key %r; pair skipped"
                               % (geo, prev[1], key)),
                })
                continue
            if coords == prev_coords:
                continue
            km = _haversine_km(prev_coords, coords)
            mins = (ts - prev[0]).total_seconds() / 60.0
            if km > self.max_km and 0 <= mins <= self.max_minutes:
                alerts.append({
                    "rule_id": self.rule.rule_id,
                    "title": self.rule.title,
                    "level": self.rule.level,
                    "logsource": dict(self.rule.logsource),
                    "events": [ev],
                    "detail": {
                        self.key_field: key,
                        "from": prev[1], "to": geo,
                        "km": round(km, 1),
                        "minutes": round(mins, 1),
                    },
                })
        return alerts


def _correlation_driver(rule, *, geo_table=None):
    """Build the correlator for a rule carrying a ``correlation:``
    block, or None. Unknown types raise (loud, never silent)."""
    corr = (rule.raw_doc or {}).get("correlation")
    if not corr:
        return None
    ctype = corr.get("type")
    if ctype == "impossible_travel":
        return ImpossibleTravelCorrelator(rule, geo_table=geo_table)
    raise DetectionError("unsupported-correlation",
                         "rule %s: correlation.type %r is not implemented"
                         % (rule.rule_id, ctype))


# --------------------------------------------------------------------------
# Assumption checks: loud warnings when the world model breaks.
# --------------------------------------------------------------------------

def check_rule_assumptions(rule, events):
    """Check a rule's ``assumptions:`` block against the stream.

    Each assumption is ``{desc, event_type?, requires_field?,
    min_count?, min_fraction?}``. Violations return warning dicts --
    they never raise and never suppress alerts. This is the product
    form of the spike's x30 false-fire lesson: a rule that cannot see
    its world must say so loudly.
    """
    warnings = []
    assumptions = (rule.raw_doc or {}).get("assumptions") or []
    if not isinstance(assumptions, list):
        raise DetectionError("bad-rule",
                             "rule %s: assumptions must be a list"
                             % (rule.rule_id,))
    for i, asm in enumerate(assumptions):
        if not isinstance(asm, dict):
            raise DetectionError("bad-rule",
                                 "rule %s: assumption %d is not a mapping"
                                 % (rule.rule_id, i))
        desc = str(asm.get("desc", "assumption %d" % i))
        etype = asm.get("event_type")
        scoped = [e for e in events
                  if etype is None or e.get("type") == etype]
        min_count = asm.get("min_count")
        if min_count is not None and len(scoped) < int(min_count):
            warnings.append({
                "code": "assumption-violated",
                "rule_id": rule.rule_id,
                "detail": ("%s: only %d events of type %r (need >= %s)"
                           % (desc, len(scoped), etype, min_count)),
            })
        field = asm.get("requires_field")
        if field is not None and scoped:
            have = sum(1 for e in scoped
                       if e.get(field) is not None)
            frac = have / len(scoped)
            want = float(asm.get("min_fraction", 0.5))
            if frac < want:
                warnings.append({
                    "code": "assumption-violated",
                    "rule_id": rule.rule_id,
                    "detail": ("%s: field %r present on %d/%d (%.2f) "
                               "events of type %r, below %.2f -- the "
                               "rule may be blind"
                               % (desc, field, have, len(scoped), frac,
                                  etype, want)),
                })
    return warnings


# --------------------------------------------------------------------------
# Detection report.
# --------------------------------------------------------------------------

def _event_summary(ev):
    out = {}
    for k in ("seq", "ts", "type", "agent_id", "tool", "verdict",
              "sig_key_id", "sig_key_version"):
        if ev.get(k) is not None:
            out[k] = ev[k]
    return out


class DetectionReport:
    """The auditor's detection output: alerts, loud warnings, and the
    pack provenance that produced them. JSON-serializable via
    :meth:`to_dict` / :meth:`to_json`. Plain value object."""

    def __init__(self, *, pack_version, pack_signing_kids, n_events,
                 n_skipped, ts_min, ts_max, rules_evaluated, alerts,
                 warnings):
        """Store the report fields (plain value object)."""
        self.pack_version = pack_version
        self.pack_signing_kids = list(pack_signing_kids)
        self.n_events = n_events
        self.n_skipped = n_skipped
        self.ts_min = ts_min
        self.ts_max = ts_max
        self.rules_evaluated = list(rules_evaluated)
        self.alerts = list(alerts)
        self.warnings = list(warnings)

    def to_dict(self):
        """JSON-serializable report."""
        return {
            "report_version": REPORT_VERSION,
            "pack_version": self.pack_version,
            "pack_signing_kids": list(self.pack_signing_kids),
            "stream": {
                "n_events": self.n_events,
                "n_skipped": self.n_skipped,
                "ts_min": self.ts_min,
                "ts_max": self.ts_max,
            },
            "rules_evaluated": [dict(r) for r in self.rules_evaluated],
            "alerts": [dict(a) for a in self.alerts],
            "warnings": [dict(w) for w in self.warnings],
        }

    def to_json(self):
        """Canonical JSON of the report."""
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False,
                          default=str)

    def inbox_items(self):
        """Review-worklist dicts for the auditor's review inbox.

        One item per alert plus one per warning; plain data -- the
        auditor's workflow owns submission to whatever inbox the
        deployment uses. Each item carries the pack provenance so a
        reviewer can trace the alert to the signed rule content.
        """
        items = []
        prov = {"pack_version": self.pack_version,
                "pack_signing_kids": list(self.pack_signing_kids)}
        for a in self.alerts:
            items.append({
                "item_kind": "detection_alert",
                "rule_id": a.get("rule_id"),
                "title": a.get("title"),
                "level": a.get("level"),
                "detail": dict(a.get("detail") or {}),
                "event": dict(a.get("event") or {}),
                "provenance": dict(prov),
            })
        for w in self.warnings:
            items.append({
                "item_kind": "detection_warning",
                "code": w.get("code"),
                "rule_id": w.get("rule_id"),
                "detail": w.get("detail"),
                "provenance": dict(prov),
            })
        return items


def _serializable_alert(alert):
    out = {
        "rule_id": alert.get("rule_id"),
        "title": alert.get("title"),
        "level": alert.get("level"),
        "logsource": dict(alert.get("logsource") or {}),
        "detail": alert.get("detail"),
    }
    evs = alert.get("events") or []
    out["event"] = _event_summary(evs[0]) if evs else {}
    out["n_events"] = len(evs)
    return out


def detect_on_entries(entries, rules_dir, pack_doc, keyset, *,
                      geo_table=None, now=None):
    """Run auditor detection over chained-audit entry dicts.

    Verifies the signed rule pack, loads and compiles the bound rules,
    feeds the events through the stream engine and any correlators,
    checks each rule's assumptions, and returns a
    :class:`DetectionReport`. Events with unparseable ``ts`` are
    skipped with a loud warning (never silently dropped). Fail-closed
    on pack/rule problems (``DetectionError``); event-data problems
    are warnings, not refusals -- the auditor must see what it can.
    """
    if not isinstance(entries, (list, tuple)):
        raise DetectionError("bad-rule", "entries must be a list")
    pack, rules = load_rule_pack(rules_dir, pack_doc, keyset, now=now)
    usable, skipped = [], 0
    ts_min = ts_max = None
    for ev in entries:
        if not isinstance(ev, dict):
            skipped += 1
            continue
        try:
            t = event_time(ev)
        except SigmaSubsetError:
            skipped += 1
            continue
        usable.append(ev)
        iso = t.isoformat()
        ts_min = iso if ts_min is None or iso < ts_min else ts_min
        ts_max = iso if ts_max is None or iso > ts_max else ts_max
    warnings = []
    if skipped:
        warnings.append({
            "code": "events-skipped",
            "rule_id": None,
            "detail": ("%d events skipped (non-object or unparseable ts); "
                       "they were NOT evaluated" % (skipped,)),
        })
    alerts = []
    rules_evaluated = []
    for rule in rules:
        rules_evaluated.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "level": rule.level,
        })
        # Assumption checks run for EVERY rule, including
        # correlator-driven ones: a blind correlator (no identity
        # events, no geo fields) must warn loudly, never pass
        # silently. This is the product form of the spike's x30
        # false-fire lesson.
        warnings.extend(check_rule_assumptions(rule, usable))
        driver = _correlation_driver(rule, geo_table=geo_table)
        if driver is not None:
            for a in driver.feed(usable):
                alerts.append(_serializable_alert(a))
            warnings.extend(driver.warnings)
            continue
        engine = StreamEngine([rule])
        for a in engine.feed(usable):
            alerts.append(_serializable_alert(a))
    return DetectionReport(
        pack_version=pack.version,
        pack_signing_kids=pack.signing_kids,
        n_events=len(usable),
        n_skipped=skipped,
        ts_min=ts_min,
        ts_max=ts_max,
        rules_evaluated=rules_evaluated,
        alerts=alerts,
        warnings=warnings,
    )


def detect_on_export(export, rules_dir, pack_doc, keyset, *,
                     geo_table=None, now=None):
    """Run detection over an exported chained-audit stream.

    ``export`` is either the entry list itself or a mapping carrying
    it under ``"entries"``. Convenience wrapper over
    :func:`detect_on_entries` for the evidence-bundle auditor
    workflow.
    """
    if isinstance(export, dict):
        entries = export.get("entries")
    else:
        entries = export
    return detect_on_entries(entries, rules_dir, pack_doc, keyset,
                             geo_table=geo_table, now=now)
