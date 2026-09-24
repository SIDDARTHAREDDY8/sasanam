"""Battery-result loading for the Safeguard Benchmark primitive.

Normalizes a probe-battery artifact into the SAR record shape
``{id, category, verdict, severity_weight}`` and maps probe categories
to the provisional S1–S4 incident severity bands (spec §3/§3b).

Wave-95 lesson: deployment mode is declared at module level so the
module works under a clean environment (the harness's declared
ungoverned_ack is refused in production mode).

$0 spend, synthetic/local only. No network.
"""

import os

# Wave-95: new eval batteries must set deployment mode at module level.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json  # noqa: E402


class SafeguardResultsError(Exception):
    """Fail-closed: the battery artifact cannot be normalized honestly."""


#: Re-exported from gov.safeguard_taxonomy (F161 layering fix). The
#: SAR severity taxonomy is product schema data owned by the product
#: layer; the harness keeps these names so existing importers do not
#: change. Do NOT fork copies here — identity with the product module
#: is asserted by tests/test_safeguard_layering.py.
from gov.safeguard_taxonomy import (  # noqa: E402
    CATEGORY_SEVERITY,
    REQUIRED_CATEGORIES,
    SEVERITY_WEIGHTS,
    UNCOVERED_CATEGORIES,
)


_VERDICTS = frozenset({"stopped", "break", "error"})


def _normalize_record(raw):
    if not isinstance(raw, dict):
        raise SafeguardResultsError(
            "battery record is not an object: %r" % (raw,))
    rid = raw.get("id", raw.get("profile_id"))
    if not rid:
        raise SafeguardResultsError(
            "battery record has no id: %r" % (raw,))
    category = raw.get("category", raw.get("class"))
    if not category:
        raise SafeguardResultsError(
            "record %r has no category: refusing to invent one" % (rid,))
    if category not in CATEGORY_SEVERITY:
        raise SafeguardResultsError(
            "record %r: unknown category %r (no severity band; "
            "refusing to grade)" % (rid, category))
    verdict = raw.get("verdict", raw.get("observed"))
    if verdict not in _VERDICTS:
        raise SafeguardResultsError(
            "record %r: unknown verdict %r (expected one of %s; "
            "refusing to coerce)" % (rid, verdict, sorted(_VERDICTS)))
    weight = SEVERITY_WEIGHTS[CATEGORY_SEVERITY[category]]
    if "severity_weight" in raw and raw["severity_weight"] is not None:
        if raw["severity_weight"] != weight:
            raise SafeguardResultsError(
                "record %r: supplied severity_weight %r disagrees with "
                "band %s weight %r" % (
                    rid, raw["severity_weight"],
                    CATEGORY_SEVERITY[category], weight))
    return {"id": rid, "category": category, "verdict": verdict,
            "severity_weight": weight}


def load_battery_results(path):
    """Read a battery artifact into SAR records.

    Accepts a JSON list of records, or a JSON object with a
    ``"results"`` (or ``"probes"``) list. Each record carries
    ``{id, category, verdict}``; ``verdict`` ∈
    {stopped, break, error} (registry-gate ``observed`` accepted as an
    alias). Fail-closed: unknown verdicts, unknown or missing
    categories, and artifacts that use non-probe taxonomies (e.g. the
    stratified-100 actor classes) raise ``SafeguardResultsError``
    instead of being coerced.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        for key in ("results", "probes"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            raise SafeguardResultsError(
                "battery artifact %r: expected a record list or an "
                "object with a 'results'/'probes' list" % (path,))
    if not isinstance(data, list):
        raise SafeguardResultsError(
            "battery artifact %r: expected a record list" % (path,))
    if not data:
        raise SafeguardResultsError(
            "battery artifact %r: no records" % (path,))
    return [_normalize_record(r) for r in data]
