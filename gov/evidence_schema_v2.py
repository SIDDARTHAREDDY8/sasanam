"""Evidence-bundle schema v2: AU-3 audit-record fields + CC8.1 decision-maker
versioning (wave-318 lane 2, additive, stdlib-only, no crypto).

Direction: ``research/prospecting/w317_evidence_next_steps.md`` item 4.

* **AU-3** (NIST SP 800-53 Rev 5, content of audit records): every record
  carries who / what / when / where / result. Fields the log cannot supply
  are null and the record is marked ``complete: false`` -- never
  synthesized, never defaulted.
* **CC8.1** (SOC 2 change management): the decision-maker versions that
  produced each decision -- model name+version, system-prompt digest+version,
  config snapshot digest+version -- plus a change log. A system-prompt change
  alters behaviour as much as a code change; if it isn't in the change log,
  CC8.1 has a gap. The change-log consistency rule (every current
  digest-versioned component must have a change-log entry landing on its
  current digest) makes unlogged behaviour changes detectable.

Schema version ``EVIDENCE_SCHEMA_V2`` (``"evidence-schema/2.0"``); the v1
bundle builder (``"evidence-schema/1.0"``) is byte-identical and untouched.
v2 is opt-in and additive; a v2 bundle without decision-maker context is
refused at build time (fail-fast) rather than issued unverifiable.

Validators are shared by the bundle builder and the offline verifier, so a
bundle that builds is shaped exactly the way the verifier expects.
"""

EVIDENCE_SCHEMA_V2 = "evidence-schema/2.0"

# AU-3 record field checklist (NIST SP 800-53 AU-3: type of event, when,
# where, source, outcome -- rendered here as what/when/where/who/result).
AU3_FIELDS = ("who", "what", "when", "where", "result")

# Extraction order per AU-3 field: first present key wins. Missing keys
# yield None (honest null), never a default.
_AU3_WHO_KEYS = ("principal", "actor")
_AU3_WHAT_KEYS = ("event",)
_AU3_WHEN_KEYS = ("ts",)
_AU3_WHERE_KEYS = ("source", "location")
_AU3_RESULT_KEYS = ("decision", "outcome", "result")

# CC8.1 versioned decision-maker components.
_DM_COMPONENTS = ("model", "system_prompt", "config")
# Components whose versions are content digests (need a change-log landing
# entry keyed by digest, not just a version string).
_DIGEST_COMPONENTS = ("system_prompt", "config")


class SchemaV2Error(ValueError):
    """A v2 schema section is malformed or internally inconsistent.

    ``code`` is the machine-readable refusal token; the offline verifier
    maps it to its own typed failure code.
    """

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _first(entry, keys):
    for k in keys:
        if k in entry and entry[k] is not None:
            return entry[k]
    return None


def extract_au3(entry):
    """Extract one AU-3 record from an audit-log entry.

    Returns ``{"seq", "hash", "au3": {who, what, when, where, result},
    "complete"}``. Fields the entry cannot supply are None and the record
    is ``complete: false``. Never synthesized.
    """
    if not isinstance(entry, dict):
        raise SchemaV2Error("au3-record-not-an-object",
                            "record must be a JSON object")
    au3 = {
        "who": _first(entry, _AU3_WHO_KEYS),
        "what": _first(entry, _AU3_WHAT_KEYS),
        "when": _first(entry, _AU3_WHEN_KEYS),
        "where": _first(entry, _AU3_WHERE_KEYS),
        "result": _first(entry, _AU3_RESULT_KEYS),
    }
    return {
        "seq": entry.get("seq"),
        "hash": entry.get("hash"),
        "au3": au3,
        "complete": all(au3[f] is not None for f in AU3_FIELDS),
    }


def build_au3_records(entries):
    """Build the ``au3_records`` section for a window of log entries."""
    if not isinstance(entries, (list, tuple)):
        raise SchemaV2Error("au3-records-not-a-list",
                            "entries must be a list")
    return [extract_au3(e) for e in entries]


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdefABCDEF" for c in value))


def build_decision_maker_versions(decision_maker, change_log):
    """Build the ``decision_maker_versions`` section.

    ``decision_maker`` is operator-supplied
    ``{model: {name, version}, system_prompt: {digest_sha256, version},
    config: {snapshot_digest_sha256, version}}``; ``change_log`` is a list of
    ``{changed_at, component, from_version, to_version, note}`` with an
    optional ``to_digest`` for digest-versioned components. Either may be
    None (honest absence -> ``operator_must_supply: true``, never defaults).
    """
    if decision_maker is None:
        return {
            "model": {"value": None, "operator_must_supply": True},
            "system_prompt": {"value": None, "operator_must_supply": True},
            "config": {"value": None, "operator_must_supply": True},
            "change_log": [],
            "note": ("no decision-maker context supplied: the bundle never "
                     "guesses which model/prompt/config governed the window"),
        }
    if not isinstance(decision_maker, dict):
        raise SchemaV2Error("decision-maker-not-an-object",
                            "decision_maker must be a JSON object")
    if change_log is None:
        change_log = []
    return {
        "model": _check_versioned_block(decision_maker.get("model"),
                                        ("name", "version"), "model"),
        "system_prompt": _check_versioned_block(
            decision_maker.get("system_prompt"),
            ("digest_sha256", "version"), "system_prompt", digest_key=True),
        "config": _check_versioned_block(
            decision_maker.get("config"),
            ("snapshot_digest_sha256", "version"), "config", digest_key=True),
        "change_log": _check_change_log(change_log),
    }


def _check_versioned_block(block, keys, component, digest_key=False):
    if not isinstance(block, dict):
        raise SchemaV2Error("decision-maker-%s-malformed" % component,
                            "%s must be an object" % component)
    out = {}
    for k in keys:
        val = block.get(k)
        if not isinstance(val, str) or not val:
            raise SchemaV2Error(
                "decision-maker-%s-malformed" % component,
                "%s.%s must be a non-empty string" % (component, k))
        out[k] = val
    if digest_key and not _is_hex64(out[keys[0]]):
        raise SchemaV2Error(
            "decision-maker-%s-malformed" % component,
            "%s.%s must be 64 hex" % (component, keys[0]))
    return out


def _check_change_log(change_log):
    if not isinstance(change_log, list):
        raise SchemaV2Error("change-log-not-a-list",
                            "change_log must be a list")
    seen = {c: [] for c in _DM_COMPONENTS}
    out = []
    for i, entry in enumerate(change_log):
        where = "change_log[%d]" % i
        if not isinstance(entry, dict):
            raise SchemaV2Error("change-log-entry-malformed",
                                "%s must be an object" % where)
        component = entry.get("component")
        if component not in _DM_COMPONENTS:
            raise SchemaV2Error("change-log-entry-malformed",
                                "%s: unknown component %r"
                                % (where, component))
        for k in ("changed_at", "from_version", "to_version", "note"):
            val = entry.get(k)
            if k == "from_version":
                if val is not None and (not isinstance(val, str)
                                        or not val):
                    raise SchemaV2Error(
                        "change-log-entry-malformed",
                        "%s: from_version must be a string or null" % where)
            elif not isinstance(val, str) or not val:
                raise SchemaV2Error(
                    "change-log-entry-malformed",
                    "%s: %s must be a non-empty string" % (where, k))
        to_digest = entry.get("to_digest")
        if component in _DIGEST_COMPONENTS:
            if not _is_hex64(to_digest):
                raise SchemaV2Error(
                    "change-log-entry-malformed",
                    "%s: to_digest must be 64 hex for %s"
                    % (where, component))
        prev = seen[component]
        if not prev:
            if entry["from_version"] is not None:
                raise SchemaV2Error(
                    "change-log-not-chained",
                    "%s: first %s entry must have null from_version "
                    "(genesis)" % (where, component))
        elif entry["from_version"] != prev[-1]["to_version"]:
            raise SchemaV2Error(
                "change-log-not-chained",
                "%s: from_version %r does not chain from previous "
                "to_version %r" % (where, entry["from_version"],
                                   prev[-1]["to_version"]))
        seen[component].append(entry)
        out.append({
            "changed_at": entry["changed_at"],
            "component": component,
            "from_version": entry["from_version"],
            "to_version": entry["to_version"],
            "to_digest": to_digest if component in _DIGEST_COMPONENTS
            else None,
            "note": entry["note"],
        })
    return out


def _landing_digest(change_log, component):
    """The digest the latest change-log entry for a digest-versioned
    component lands on (None when the component has no entries)."""
    landed = None
    for entry in change_log:
        if entry.get("component") == component:
            landed = entry.get("to_digest")
    return landed


def check_changelog_consistency(decision_maker_versions):
    """The CC8.1 change-log consistency rule: every digest-versioned
    component's current digest must have a change-log entry landing on it.

    A system-prompt (or config) change without a change-log entry is the
    gap this rule exists to detect; it refuses loudly rather than reading
    the current digest as self-evidently logged.
    """
    if not isinstance(decision_maker_versions, dict):
        raise SchemaV2Error("decision-maker-versions-not-an-object",
                            "decision_maker_versions must be an object")
    change_log = decision_maker_versions.get("change_log")
    if not isinstance(change_log, list):
        raise SchemaV2Error("change-log-not-a-list",
                            "change_log must be a list")
    for component in _DIGEST_COMPONENTS:
        block = decision_maker_versions.get(component)
        if not isinstance(block, dict):
            continue  # malformed blocks are caught by the shape check
        digest_key = ("digest_sha256" if component == "system_prompt"
                      else "snapshot_digest_sha256")
        current = block.get(digest_key)
        landed = _landing_digest(change_log, component)
        if landed is None:
            raise SchemaV2Error(
                "change-log-gap",
                "%s has no change-log entry at all: the current %s "
                "digest is unlogged" % (component, digest_key))
        if not isinstance(current, str) or current.lower() != landed.lower():
            raise SchemaV2Error(
                "change-log-gap",
                "%s digest changed without a change-log entry landing on "
                "it: current %r, latest logged %r"
                % (component, current, landed))


def validate_au3_records(records):
    """Strict shape validation of an ``au3_records`` section (shared by
    builder and verifier)."""
    if not isinstance(records, list):
        raise SchemaV2Error("au3-records-not-a-list",
                            "au3_records must be a list")
    for i, rec in enumerate(records):
        where = "au3_records[%d]" % i
        if not isinstance(rec, dict):
            raise SchemaV2Error("au3-record-not-an-object",
                                "%s must be an object" % where)
        au3 = rec.get("au3")
        if not isinstance(au3, dict):
            raise SchemaV2Error("au3-record-malformed",
                                "%s.au3 must be an object" % where)
        missing = [f for f in AU3_FIELDS if f not in au3]
        if missing:
            raise SchemaV2Error("au3-record-malformed",
                                "%s.au3 missing fields %r" % (where, missing))
        complete = rec.get("complete")
        if not isinstance(complete, bool):
            raise SchemaV2Error("au3-record-malformed",
                                "%s.complete must be a bool" % where)
        if complete and any(au3[f] is None for f in AU3_FIELDS):
            raise SchemaV2Error("au3-record-malformed",
                                "%s marked complete with null fields"
                                % where)


def validate_decision_maker(claim):
    """Strict shape validation of a ``decision_maker`` predicate claim
    (shared by builder and verifier), including the change-log rule."""
    if not isinstance(claim, dict):
        raise SchemaV2Error("decision-maker-not-an-object",
                            "decision_maker must be an object")
    built = build_decision_maker_versions(
        {k: claim[k] for k in ("model", "system_prompt", "config")
         if k in claim},
        claim.get("change_log"))
    # build_* refuses malformed blocks/chains; now the gap rule.
    check_changelog_consistency(built)


def validate_v2_claims(predicate):
    """Validate the v2 extension claims of a verifier statement predicate.

    The claim keys are the builder payload section names (``au3_records``,
    ``decision_maker_versions``) so a builder-emitted v2 bundle maps 1:1
    onto the predicate the verifier checks.

    Raises :class:`SchemaV2Error` on missing/malformed extension fields or
    a change-log gap. The offline verifier maps this to its typed
    EXTENSION_SCHEMA_INVALID code.
    """
    if not isinstance(predicate, dict):
        raise SchemaV2Error("predicate-not-an-object",
                            "predicate must be an object")
    if "au3_records" not in predicate:
        raise SchemaV2Error("extension-section-missing",
                            "schema 2.0 bundle missing au3_records claim")
    if "decision_maker_versions" not in predicate:
        raise SchemaV2Error(
            "extension-section-missing",
            "schema 2.0 bundle missing decision_maker_versions claim")
    validate_au3_records(predicate["au3_records"])
    validate_decision_maker(predicate["decision_maker_versions"])


def build_v2_sections(entries, decision_maker=None, change_log=None):
    """Build both v2 sections for a bundle payload (builder seam).

    Returns ``{"au3_records": [...], "decision_maker_versions": {...}}``.
    Fail-fast: schema 2.0 exists to carry CC8.1 decision-maker
    versioning, so ``decision_maker`` is required -- callers without
    decision-maker context build schema 1.0. A supplied context whose
    change log has a gap also refuses: a bundle that cannot verify must
    not be issued.
    """
    if decision_maker is None:
        raise SchemaV2Error(
            "decision-maker-required",
            "schema 2.0 requires decision_maker context (model, "
            "system_prompt, config, change_log); build schema 1.0 "
            "instead when the context is unavailable")
    dmv = build_decision_maker_versions(decision_maker, change_log)
    check_changelog_consistency(dmv)
    return {
        "au3_records": build_au3_records(entries),
        "decision_maker_versions": dmv,
    }
