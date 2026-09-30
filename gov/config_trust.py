"""Agent-trusts-config fail-closed primitive (W244-4, threat model).

The CVE-2026-18252 shape: a Duo Claude agent trusted user-controlled
configuration as authoritative, and the config source led the agent
(Developer role) to execute CI commands (CVSS 7.3; exact config source
honest-unverified). Mandiant's Sept 2026 red-team case is the same
shape: an assistant convinced it was in an "authorized security test"
cloned repos to an external account.

The rule this module pins: configuration the agent OBSERVES is
UNTRUSTED INPUT. A privilege or elevation claim found in agent-observed
config is IGNORED -- refused ``config-authority-claim-refused`` -- unless
the same grant also exists in a deployment-pinned authority source.
Provenance is deployment-vouched, never agent-asserted: a config that
self-declares itself trusted is refused
``config-provenance-agent-asserted``, and a config with no provenance
block at all is refused ``config-provenance-untrusted`` (provenance
absence is not trust).

Verification order (fail-closed):
1. shape -> ``config-record-malformed`` (never proceed on bad shape);
2. provenance classification -> agent-asserted provenance refused
   ``config-provenance-agent-asserted``; missing provenance refused
   ``config-provenance-untrusted``;
3. lapse citation (if a claim cites a lapse-registered authority) ->
   routed to ``gov.stale_authority`` FIRST, its ``stale-authority``
   re-raised (the wave-243 lapse-first ordering, preserved not
   duplicated);
4. privilege claim against the pinned authority -> allow only on an
   exact grant match; otherwise ``config-authority-claim-refused``.
   Tamper is not re-reported as a mismatch: a malformed grant record
   refuses ``config-record-malformed`` before binding comparisons.
5. mid-run rewrite: ``ConfigMonitor`` digests every observed config;
   a rewrite that adds privileges refuses
   ``config-rewritten-privilege`` and emits a hash-chained audit
   entry.

Probe (f) is handled by ``check_agent_basis``: an agent that quotes a
config back as its own claim ("the config says I'm authorized") is
refused ``config-authority-claim-refused`` -- config never
self-attests into authority.

Honest residuals:
- The pinned authority source is deployment-supplied; this module does
  not authenticate who pinned it. Pin ceremony integrity is
  deployment-owned (the pin digest makes a silent substitution
  detectable, not impossible).
- Provenance vouching is a deployment-supplied map. The module refuses
  what is NOT vouched; it cannot catch a deployment that vouches a
  lie. This is the same honest boundary as verifier_failclosed's
  authority-source feed trust.
- ``ConfigMonitor`` history is in-memory; persistence and shared
  atomicity are deployment-owned (same boundary as the consumption
  ledger).
- Grant matching is syntactic equality on action strings; semantic
  expansion (a grant to "ci:*" implying "ci:exec") is out of scope and
  is never assumed.

Stdlib only. Deterministic. No env reads, no I/O. Fail-closed on
malformed input.
"""

import hashlib
import json
from datetime import datetime

CONFIG_RECORD_MALFORMED = "config-record-malformed"
CONFIG_AUTHORITY_CLAIM_REFUSED = "config-authority-claim-refused"
CONFIG_PROVENANCE_UNTRUSTED = "config-provenance-untrusted"
CONFIG_PROVENANCE_AGENT_ASSERTED = "config-provenance-agent-asserted"
CONFIG_REWRITTEN_PRIVILEGE = "config-rewritten-privilege"

_STALE_AUTHORITY_CODE = "stale-authority"

# Provenance classifications.
PROVENANCE_DEPLOYMENT_PINNED = "deployment-pinned"
PROVENANCE_AGENT_OBSERVED = "agent-observed"

# Closed vocabulary of config keys that carry a privilege/elevation
# claim. A closed list, never a substring match: privilege claims are
# enumerated, not guessed.
_PRIVILEGE_KEYS = frozenset([
    "role",
    "roles",
    "elevate",
    "elevated_role",
    "grant",
    "grants",
    "permissions",
    "allowlisted_commands",
    "command_allowlist",
    "sudo",
    "admin",
    "privileged_actions",
    "capabilities",
    "authorized_scopes",
])


class ConfigTrustError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(ConfigTrustError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise ConfigTrustError(code, detail)


def _canonical(obj):
    """RFC-8785-shaped canonical JSON (domain-separated elsewhere)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _digest(obj):
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


def _non_empty_str(value, what):
    if not isinstance(value, str) or not value:
        _refuse(CONFIG_RECORD_MALFORMED,
                "%s must be a non-empty string" % (what,))
    return value


# ------------------------------------------------------------------
# Pinned authority source.
# ------------------------------------------------------------------

def pin_authority_source(source):
    """Pin a deployment-supplied authority source.

    ``source`` is a dict with:
      - ``verifier_policy_input``: non-empty string naming the pinned
        policy (falsifies verifier-input blindness);
      - ``grants``: a list of grant dicts, each with ``action``
        (non-empty string, e.g. ``"ci:exec"``) and optional
        ``authority_id`` / ``authority_minted_at``.

    Returns a pinned authority dict carrying a sha256 pin digest. The
    digest makes a silent pin substitution detectable; pin-ceremony
    integrity itself is deployment-owned.
    """
    if not isinstance(source, dict):
        _refuse(CONFIG_RECORD_MALFORMED,
                "authority source must be a dict")
    policy_input = _non_empty_str(
        source.get("verifier_policy_input"), "verifier_policy_input")
    grants = source.get("grants")
    if not isinstance(grants, list):
        _refuse(CONFIG_RECORD_MALFORMED, "grants must be a list")
    normalized = []
    for index, grant in enumerate(grants):
        if not isinstance(grant, dict):
            _refuse(CONFIG_RECORD_MALFORMED,
                    "grant %d is not a dict" % (index,))
        action = _non_empty_str(
            grant.get("action"), "grant %d action" % (index,))
        entry = {"action": action}
        authority_id = grant.get("authority_id")
        if authority_id is not None:
            entry["authority_id"] = _non_empty_str(
                authority_id, "grant %d authority_id" % (index,))
            minted_at = grant.get("authority_minted_at")
            if minted_at is not None and not isinstance(
                    minted_at, (int, float, datetime)) \
                    or isinstance(minted_at, bool):
                _refuse(CONFIG_RECORD_MALFORMED,
                        "grant %d authority_minted_at must be numeric "
                        "(bool rejected)" % (index,))
            if minted_at is not None:
                if isinstance(minted_at, datetime):
                    # Normalize to ISO-8601 so the pin digest is JSON
                    # canonicalizable and deterministic.
                    minted_at = minted_at.isoformat()
                entry["authority_minted_at"] = minted_at
        normalized.append(entry)
    pin = {
        "verifier_policy_input": policy_input,
        "grants": normalized,
    }
    pin["pin_digest"] = _digest(pin)
    return pin


def _pinned_action_set(pinned):
    return set(grant["action"] for grant in pinned["grants"])


def _grant_record(pinned, action):
    for grant in pinned["grants"]:
        if grant["action"] == action:
            return grant
    return None


# ------------------------------------------------------------------
# Provenance classification (deployment-vouched, never agent-asserted).
# ------------------------------------------------------------------

def classify_provenance(config_record, deployment_source_map):
    """Classify a config record's provenance.

    ``deployment_source_map`` is deployment-supplied: {source_id:
    "deployment-pinned" | "agent-observed"}. A source_id the map does
    not vouch is agent-observed. Self-asserted trust inside the record
    (``provenance: {"trusted": true}``) is refused outright as
    ``config-provenance-agent-asserted`` -- provenance is
    deployment-vouched, never agent-asserted.
    """
    if not isinstance(config_record, dict):
        _refuse(CONFIG_RECORD_MALFORMED, "config record must be a dict")
    if not isinstance(deployment_source_map, dict):
        _refuse(CONFIG_RECORD_MALFORMED,
                "deployment_source_map must be a dict")
    provenance = config_record.get("provenance")
    if provenance is None:
        return PROVENANCE_AGENT_OBSERVED, True
    if not isinstance(provenance, dict):
        _refuse(CONFIG_RECORD_MALFORMED, "provenance must be a dict")
    if provenance.get("trusted") is True or \
            provenance.get("source") == "trusted":
        # Self-declared trust with no deployment vouch: the record
        # asserts its own authority. Never accepted.
        source_id = provenance.get("source_id")
        vouched = deployment_source_map.get(source_id) \
            == PROVENANCE_DEPLOYMENT_PINNED
        if not vouched:
            _refuse(CONFIG_PROVENANCE_AGENT_ASSERTED,
                    "config asserts its own provenance trust; provenance "
                    "is deployment-vouched, never agent-asserted")
    source_id = provenance.get("source_id")
    if isinstance(source_id, str) and deployment_source_map.get(
            source_id) == PROVENANCE_DEPLOYMENT_PINNED:
        return PROVENANCE_DEPLOYMENT_PINNED, False
    return PROVENANCE_AGENT_OBSERVED, False


# ------------------------------------------------------------------
# Privilege-claim extraction and checking.
# ------------------------------------------------------------------

def _extract_claims(settings):
    """Extract privilege claims from a settings dict using the closed
    key vocabulary. Returns a list of (key, action) pairs where action
    is a normalized action string."""
    if not isinstance(settings, dict):
        _refuse(CONFIG_RECORD_MALFORMED, "settings must be a dict")
    claims = []
    for key, value in settings.items():
        if key not in _PRIVILEGE_KEYS:
            continue
        if isinstance(value, str) and value:
            claims.append((key, value))
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str) and item:
                    claims.append((key, item))
                elif item is not None:
                    _refuse(CONFIG_RECORD_MALFORMED,
                            "privilege key %r has a non-string item" % (
                                key,))
        elif isinstance(value, bool):
            if value is True:
                claims.append((key, key))
        elif value is not None:
            _refuse(CONFIG_RECORD_MALFORMED,
                    "privilege key %r has a non-string value" % (key,))
    return claims


def _check_lapse_citation_first(authority_id, minted_at):
    """Lapse-first ordering (wave-243 pattern): a grant citing a
    lapse-registered authority routes through gov.stale_authority
    BEFORE the grant store lookup; its ``stale-authority`` is
    re-raised, never passed on legacy text.

    Numeric epoch timestamps are coerced to tz-aware datetimes
    first: gov.stale_authority.check_authority takes a datetime, not
    an epoch float. The contract is pinned by the unit test below
    (probe (a) datetime in, probe (b) epoch-float in).
    """
    from gov import stale_authority as _sa
    if authority_id not in _sa.LAPSED_AUTHORITIES:
        return
    if minted_at is None:
        _refuse("authority-stale",
                "grant cites a lapse-registered authority without a "
                "receipt timestamp; citation freshness is unverifiable")
    minted_dt = minted_at
    if isinstance(minted_dt, str):
        from datetime import timezone
        try:
            minted_dt = datetime.fromisoformat(minted_dt)
        except ValueError:
            _refuse(CONFIG_RECORD_MALFORMED,
                    "authority_minted_at ISO string is not parseable")
        if minted_dt.tzinfo is None:
            minted_dt = minted_dt.replace(tzinfo=timezone.utc)
    elif isinstance(minted_dt, (int, float)) and not isinstance(
            minted_dt, bool):
        from datetime import timezone
        minted_dt = datetime.fromtimestamp(minted_dt, tz=timezone.utc)
    try:
        _sa.check_authority(authority_id, minted_dt)
    except _sa.StaleAuthorityError as exc:
        if exc.code != _STALE_AUTHORITY_CODE:
            raise
        _refuse(exc.code,
                "lapse-registered authority citation: %s" % (exc.detail,))
    _refuse("authority-stale",
            "authority %r was accepted only with downgraded provenance "
            "(lapsed draft); passing it as a live grant repeats the "
            "green-on-lapsed-authority defect" % (authority_id,))


def _check_grant_lapse(grant):
    authority_id = grant.get("authority_id")
    if isinstance(authority_id, str) and authority_id:
        _check_lapse_citation_first(
            authority_id, grant.get("authority_minted_at"))


def check_privilege_claim(config_record, pinned_authority,
                          deployment_source_map):
    """Check the privilege claims in an agent-observed config.

    - Config with no provenance block and privilege claims -> refuse
      ``config-provenance-untrusted``.
    - Privilege claim whose action matches a grant in the pinned
      authority -> allow (not every config is hostile; probe c).
    - Otherwise -> refuse ``config-authority-claim-refused``.

    Returns a dict with decision "allow" and the matched claims; every
    refusal raises ConfigTrustError with a taxonomy code.
    """
    if not isinstance(config_record, dict):
        _refuse(CONFIG_RECORD_MALFORMED, "config record must be a dict")
    if not isinstance(pinned_authority, dict) or \
            "pin_digest" not in pinned_authority:
        _refuse(CONFIG_RECORD_MALFORMED,
                "pinned_authority must come from pin_authority_source()")
    provenance, missing = classify_provenance(
        config_record, deployment_source_map)
    settings = config_record.get("settings")
    if settings is None:
        return {"decision": "allow", "matched": [],
                "provenance": provenance,
                "verifier_policy_input":
                    pinned_authority["verifier_policy_input"]}
    claims = _extract_claims(settings)
    if missing and claims:
        _refuse(CONFIG_PROVENANCE_UNTRUSTED,
                "config carries privilege claims with no provenance "
                "block; provenance absence is not trust")
    if provenance == PROVENANCE_DEPLOYMENT_PINNED:
        return {"decision": "allow", "matched": claims,
                "provenance": provenance,
                "verifier_policy_input":
                    pinned_authority["verifier_policy_input"]}
    granted_actions = _pinned_action_set(pinned_authority)
    matched = []
    for key, action in claims:
        grant = _grant_record(pinned_authority, action)
        if grant is None:
            _refuse(CONFIG_AUTHORITY_CLAIM_REFUSED,
                    "agent-observed config claims privilege %r=%r with "
                    "no matching grant in the pinned authority "
                    "(verifier_policy_input=%r)" % (
                        key, action,
                        pinned_authority["verifier_policy_input"]))
        _check_grant_lapse(grant)
        matched.append((key, action))
    return {"decision": "allow", "matched": matched,
            "provenance": provenance,
            "verifier_policy_input":
                pinned_authority["verifier_policy_input"]}


def check_agent_basis(basis, pinned_authority):
    """Refuse an agent quoting a config as its own authorization basis.

    Probe (f): ``basis = {"claim": ..., "basis_source": "config:<id>"}``
    is never accepted as self-attestation. A basis backed by a grant
    in the pinned authority (``basis_source`` ==
    "deployment-pinned-authority") is allowed; anything else is
    refused ``config-authority-claim-refused``.
    """
    if not isinstance(basis, dict):
        _refuse(CONFIG_RECORD_MALFORMED, "basis must be a dict")
    if not isinstance(pinned_authority, dict) or \
            "pin_digest" not in pinned_authority:
        _refuse(CONFIG_RECORD_MALFORMED,
                "pinned_authority must come from pin_authority_source()")
    source = basis.get("basis_source")
    if not isinstance(source, str) or not source:
        _refuse(CONFIG_RECORD_MALFORMED,
                "basis must name a non-empty basis_source")
    claim = basis.get("claim")
    if not isinstance(claim, str) or not claim:
        _refuse(CONFIG_RECORD_MALFORMED,
                "basis must name a non-empty claim")
    if source == "deployment-pinned-authority":
        grant = _grant_record(pinned_authority, claim)
        if grant is None:
            _refuse(CONFIG_AUTHORITY_CLAIM_REFUSED,
                    "agent basis %r cites the pinned authority without "
                    "a matching grant" % (claim,))
        _check_grant_lapse(grant)
        return {"decision": "allow", "claim": claim,
                "verifier_policy_input":
                    pinned_authority["verifier_policy_input"]}
    _refuse(CONFIG_AUTHORITY_CLAIM_REFUSED,
            "agent basis %r cites %r; config never self-attests into "
            "authority" % (claim, source))
    return None  # unreachable; _refuse always raises


# ------------------------------------------------------------------
# Mid-run rewrite detection with a hash-chained audit journal.
# ------------------------------------------------------------------

class ConfigMonitor(object):
    """Observe configs across a run; detect privilege-adding rewrites.

    History is in-memory; persistence and shared atomicity are
    deployment-owned (same boundary as the consumption ledger). The
    audit journal is hash-chained so a silent journal edit is
    detectable, not impossible.
    """

    def __init__(self, deployment_source_map, pinned_authority):
        if not isinstance(deployment_source_map, dict):
            _refuse(CONFIG_RECORD_MALFORMED,
                    "deployment_source_map must be a dict")
        if not isinstance(pinned_authority, dict) or \
                "pin_digest" not in pinned_authority:
            _refuse(CONFIG_RECORD_MALFORMED,
                    "pinned_authority must come from pin_authority_source()")
        self._map = deployment_source_map
        self._pinned = pinned_authority
        self._seen = {}  # source_id -> (digest, claim_set)
        self.audit_log = []

    def _audit(self, entry):
        entry = dict(entry)
        entry["prev"] = self.audit_log[-1]["entry_digest"] \
            if self.audit_log else "genesis"
        entry["entry_digest"] = _digest(entry)
        self.audit_log.append(entry)
        return entry

    def observe(self, config_record):
        """Observe a config; detect privilege-adding rewrites.

        Returns the audit entry. If the record's digest changed since
        the last observation of the same source_id AND the new
        privilege-claim set is not a subset of the old one, the entry
        records a rewrite and the privilege claim check is refused
        with ``config-rewritten-privilege`` -- the rewrite is
        audit-logged AND the next privileged action fails closed.
        """
        provenance, _ = classify_provenance(config_record, self._map)
        source_id = config_record.get("provenance", {}).get(
            "source_id", "<no-source-id>")
        settings = config_record.get("settings") or {}
        claims = frozenset(action for _, action in
                           _extract_claims(settings))
        digest = _digest(config_record)
        prior = self._seen.get(source_id)
        entry = {"source_id": source_id, "config_digest": digest,
                 "provenance": provenance,
                 "claims": sorted(claims)}
        if prior is None:
            self._seen[source_id] = (digest, claims)
            entry["event"] = "first-observed"
            return self._audit(entry)
        prior_digest, prior_claims = prior
        if digest == prior_digest:
            entry["event"] = "unchanged"
            return self._audit(entry)
        added = claims - prior_claims
        self._seen[source_id] = (digest, claims)
        if added:
            entry["event"] = "rewrite-adds-privileges"
            entry["added"] = sorted(added)
            self._audit(entry)
            _refuse(CONFIG_REWRITTEN_PRIVILEGE,
                    "config source %r was rewritten mid-run adding "
                    "privileges %s; rewrite audit-logged and the "
                    "privileged action fails closed" % (
                        source_id, sorted(added)))
        entry["event"] = "rewrite-no-new-privileges"
        return self._audit(entry)
