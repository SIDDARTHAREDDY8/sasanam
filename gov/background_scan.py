"""Background supply-chain re-verification scheduler + TTL trust standings.

Kyverno background scans (STEAL, pattern) + SPIRE SVID rotation (ADAPT,
principle) -- see research/prospecting/w325_supplychain_prospectus.md.

The admission path (``skill_supply_chain.verify_delegated_authority`` at
install / lifecycle transitions) ENFORCES. This module never enforces: it
re-runs the same verification on three triggers -- interval, policy change,
resource change -- and writes standing REPORTs. A separate actuator consumes
the report and decides what to do with it. There is deliberately no
quarantine/disable/uninstall entry point anywhere in this module.

Trust standings are perishable by construction (the SPIRE principle applied
to artifacts instead of workload identity): every installed skill carries a
standing with a TTL; the standing is RENEWED only by a successful
re-verification; expiry without renewal lapses the standing. Revocation is
by non-renewal -- no CRLs to distribute. The honest limit, stated plainly:
in-flight trust lives out its TTL; the maximum post-compromise exposure is
bounded by the configured TTL, which is auditable in the standing report.

Report schema (the documented seam with the standing-verdict store -- the
parallel lane builds the store; this module does NOT import it, the merge
composes)::

    REPORT_SCHEMA = "sasanam-background-scan-report/v1"
    report = {
        "schema": REPORT_SCHEMA,
        "skill": <skill path>,
        "scanned_at": <epoch>,
        "trigger": "interval" | "policy-change" | "resource-change" | None,
        "scan_performed": bool,
        "verdict": "verified" | "refused" | "not-scanned",
        "code": <decision code or None>,
        "detail": <str>,
        "checked": [...],          # from verify_delegated_authority
        "missed_intervals": [...], # caught-up LOUD, never silently skipped;
                                   # capped at MAX_MISSED_INTERVALS_REPORTED
        "missed_intervals_truncated": bool,  # True when the cap bit
        "missed_intervals_total": int,       # true catch-up count, LOUD
        "clock_trust": "caller-supplied",  # LOUD: TTL/expiry trusts the
            # caller's clock (``now``) or the process clock; the deployment
            # owns clock integrity -- see CLOCK_TRUST.
        "notes": [...],            # crash recovery etc, LOUD
        "standing": {
            "status": "current" | "lapsed" | "never-scanned",
            "last_verdict": "verified" | "refused" | "not-scanned",
            "expires_at": <epoch or None>,
            "ttl_seconds": <int>,
        },
    }

Scheduler state is a single JSON file, written atomically (tmp + fsync +
os.replace). A corrupt state file fails LOUD (``supplychain-scan-state-corrupt``);
a missing state file on ``run_scan`` fails LOUD
(``supplychain-scan-state-missing``) -- silently starting fresh would drop
every baseline. A crash mid-scan is detected via a sidecar marker file and
reported LOUD on the next run (``supplychain-scan-crash-recovered``).

Honest limits, stated plainly:
- In-flight trust lives out its TTL; the maximum post-compromise exposure
  is bounded by the configured TTL, auditable in the standing report.
- The crash sidecar has an inter-skill blind window: a crash between skill
  A's sidecar unlink and skill B's sidecar write leaves no marker. This is
  mitigated coherently -- A's state was already persisted and B's overdue
  interval is caught up LOUD by the missed-interval logic -- but the crash
  itself is undetectable there.
- An unexpected non-``SupplyChainError`` exception aborts the pass: skills
  after the failure get no report that pass. This is fail-loud and
  self-healing (their missed intervals surface LOUD on the next run), but
  the partial pass is a LOUD abort, not a silent skip.
"""

import base64
import hashlib
import json
import os
import tempfile
import time

from gov import skill_supply_chain as _sc

REPORT_SCHEMA = "sasanam-background-scan-report/v1"
STATE_SCHEMA = "sasanam-background-scan-state/v1"

# CLOCK-TRUST ASSUMPTION (stated LOUD, not hidden): every TTL/expiry
# evaluation in this module trusts the caller-supplied ``now`` (or the
# process clock when ``now`` is omitted). A skewed or lying clock moves
# expiry boundaries and the missed-interval accounting. The deployment
# owns clock integrity; this module records the assumption in every
# report's ``clock_trust`` field so no auditor mistakes the timestamps
# for independently verified time.
CLOCK_TRUST = "caller-supplied"

_NEW_CODES = (
    "supplychain-scan-malformed",
    "supplychain-scan-state-corrupt",
    "supplychain-scan-state-missing",
    "supplychain-scan-crash-recovered",
    "supplychain-scan-missed-interval",
    "supplychain-scan-content-mismatch",
    "supplychain-standing-lapsed",
    "supplychain-scan-already-registered",
)

# Bound on the missed_intervals list carried in a report. A pathological
# clock gap (or a huge caller-supplied ``now``) would otherwise build an
# unbounded list; the true total is always carried in
# ``missed_intervals_total`` and the truncation is flagged LOUD, so no
# catch-up is ever silently dropped -- only the per-slot listing is
# capped.
MAX_MISSED_INTERVALS_REPORTED = 128


class BackgroundScanError(ValueError):
    """Loud, machine-coded scheduler refusal. ``code`` names the failure."""

    def __init__(self, code, detail=""):
        if code not in _NEW_CODES:
            raise ValueError("unknown background-scan code %r" % (code,))
        super(BackgroundScanError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code


def _fail(code, detail=""):
    raise BackgroundScanError(code, detail)


# ---------------------------------------------------------------------------
# State handling (atomic, crash-safe).
# ---------------------------------------------------------------------------

def _state_sidecar(state_path):
    return state_path + ".inprogress"


def _load_state(state_path):
    if not isinstance(state_path, str) or not state_path:
        _fail("supplychain-scan-malformed",
              "state_path must be a non-empty str")
    if not os.path.exists(state_path):
        _fail("supplychain-scan-state-missing",
              "no scheduler state at %r: register skills first" % (state_path,))
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (ValueError, OSError, UnicodeDecodeError) as exc:
        _fail("supplychain-scan-state-corrupt",
              "cannot parse %r: %s" % (state_path, exc))
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        _fail("supplychain-scan-state-corrupt",
              "bad schema in %r" % (state_path,))
    skills = state.get("skills")
    if not isinstance(skills, dict):
        _fail("supplychain-scan-state-corrupt",
              "state.skills must be a dict in %r" % (state_path,))
    return state


def _store_state(state_path, state):
    state = dict(state)
    state["schema"] = STATE_SCHEMA
    blob = json.dumps(state, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    d = os.path.dirname(os.path.abspath(state_path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".bgscan-", dir=d)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, state_path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _check_skill_record(rec, where):
    if not isinstance(rec, dict):
        _fail("supplychain-scan-malformed", "%s must be a dict" % where)
    for key in ("digest", "delegations_version", "authz_version",
                "ttl_seconds", "scan_interval_seconds", "next_scan_at",
                "status"):
        if key not in rec:
            _fail("supplychain-scan-malformed",
                  "%s missing %r" % (where, key))


def _digest_of(data):
    if not isinstance(data, (bytes, bytearray)):
        _fail("supplychain-scan-malformed",
              "skill_bytes must be bytes, got %s"
              % type(data).__name__)
    return hashlib.sha256(bytes(data)).hexdigest()


def _delegation_names(delegation_wire):
    """Best-effort delegation-name read (for revocation-by-absence)."""
    try:
        envelope = json.loads(bytes(delegation_wire).decode("utf-8"))
        payload = json.loads(base64.b64decode(envelope["payload"]))
        names = payload.get("delegations")
    except Exception:  # noqa: BLE001 -- trigger hint only
        return None
    if not isinstance(names, list):
        return None
    out = []
    for entry in names:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            out.append(entry["name"])
    return out


def _delegation_version(delegation_wire):
    """Best-effort version read for the policy-change trigger.

    Returns the int version, or None when the wire cannot be parsed (the
    verification step will then fail loudly with the real coded reason;
    for trigger purposes an unparseable wire forces a scan).
    """
    try:
        envelope = json.loads(bytes(delegation_wire).decode("utf-8"))
        payload = json.loads(base64.b64decode(envelope["payload"]))
        version = payload.get("version")
    except Exception:  # noqa: BLE001 -- trigger hint only
        return None
    return version if isinstance(version, int) else None


# ---------------------------------------------------------------------------
# Registration (pins the baseline; the first scan verifies).
# ---------------------------------------------------------------------------

def register_skill(state_path, *, skill_path, delegation_wire, authz_wire,
                   skill_bytes, ttl_seconds, scan_interval_seconds, now=None):
    """Pin a skill's baseline for background re-verification.

    Records the observed bytes digest and delegation/authz versions; the
    standing starts as ``never-scanned`` and the first scan is due
    immediately. Registration itself does not verify -- the scan does.
    """
    if not isinstance(skill_path, str) or not skill_path:
        _fail("supplychain-scan-malformed",
              "skill_path must be a non-empty str")
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        _fail("supplychain-scan-malformed", "ttl_seconds must be a +int")
    if not isinstance(scan_interval_seconds, int) or scan_interval_seconds <= 0:
        _fail("supplychain-scan-malformed",
              "scan_interval_seconds must be a +int")
    for name, wire in (("delegation_wire", delegation_wire),
                       ("authz_wire", authz_wire)):
        if not isinstance(wire, (bytes, bytearray)):
            _fail("supplychain-scan-malformed",
                  "%s must be bytes" % (name,))
    now = int(now if now is not None else _utcnow())
    try:
        state = _load_state(state_path)
    except BackgroundScanError as exc:
        if exc.code != "supplychain-scan-state-missing":
            raise
        state = {"schema": STATE_SCHEMA, "skills": {}}
    if skill_path in state["skills"]:
        # Re-registration is a caller bug, not a refresh: the scan itself
        # re-baselines digests and delegation versions after successful
        # re-verification, so a second register_skill would silently
        # discard scan history (last verdict, consecutive refusals,
        # standing). Refuse LOUD; TTL/interval changes go through
        # update_skill_registration.
        _fail("supplychain-scan-already-registered",
              "skill %r is already registered; re-registration is "
              "refused to protect scan history -- use "
              "update_skill_registration for TTL/interval changes"
              % (skill_path,))
    rec = {
        "digest": _digest_of(skill_bytes),
        "delegations_version": _delegation_version(delegation_wire),
        "delegation_names": _delegation_names(delegation_wire),
        "authz_version": None,
        "ttl_seconds": ttl_seconds,
        "scan_interval_seconds": scan_interval_seconds,
        "next_scan_at": now,
        "last_scan_at": None,
        "status": "never-scanned",
        "last_verdict": "not-scanned",
        "last_code": None,
        "expires_at": None,
        "consecutive_refusals": 0,
    }
    state["skills"][skill_path] = rec
    _store_state(state_path, state)
    return dict(rec)


def update_skill_registration(state_path, *, skill_path, ttl_seconds=None,
                              scan_interval_seconds=None):
    """Change a registered skill's TTL and/or scan interval.

    The legitimate configuration-change path: ``register_skill`` refuses
    re-registration LOUD, so deployments change schedule parameters here.
    Only schedule parameters are touched -- the scan-owned baselines
    (digest, delegation versions, verdict history, standing) are never
    rewritten by this function; the scan itself re-baselines those after
    successful re-verification.
    """
    if not isinstance(skill_path, str) or not skill_path:
        _fail("supplychain-scan-malformed",
              "skill_path must be a non-empty str")
    state = _load_state(state_path)
    rec = state["skills"].get(skill_path)
    if rec is None:
        _fail("supplychain-scan-malformed",
              "skill %r not registered: register_skill first" % (skill_path,))
    if ttl_seconds is not None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) \
                or ttl_seconds <= 0:
            _fail("supplychain-scan-malformed",
                  "ttl_seconds must be a +int")
        rec["ttl_seconds"] = ttl_seconds
    if scan_interval_seconds is not None:
        if isinstance(scan_interval_seconds, bool) \
                or not isinstance(scan_interval_seconds, int) \
                or scan_interval_seconds <= 0:
            _fail("supplychain-scan-malformed",
                  "scan_interval_seconds must be a +int")
        rec["scan_interval_seconds"] = scan_interval_seconds
    _store_state(state_path, state)
    return dict(rec)


def _utcnow():
    return int(time.time())


# ---------------------------------------------------------------------------
# The scan.
# ---------------------------------------------------------------------------

def _evaluate_triggers(rec, *, digest_now, deleg_version_now, now):
    """Return (trigger, missed_intervals, missed_total).

    ``trigger`` may be None. ``missed_intervals`` is capped at
    MAX_MISSED_INTERVALS_REPORTED and ``missed_total`` is the true
    count, so the cap never silently drops a catch-up: the report
    carries the total and a truncation flag LOUD.

    The count is computed ARITHMETICALLY, never by iterating the gap:
    a pathological caller-supplied ``now`` (the clock-trust assumption
    is caller-owned, see CLOCK_TRUST) must not be able to spin the
    scan O(gap/interval). At most MAX_MISSED_INTERVALS_REPORTED slots
    are ever materialized.
    """
    interval = rec["scan_interval_seconds"]
    nxt = rec["next_scan_at"]
    # Missed intervals: every scheduled time strictly before now,
    # excluding the currently-due one, is caught up LOUD. Count of
    # k >= 0 with nxt + k*interval + interval < now.
    total = max(0, (now - nxt - 1) // interval)
    missed = [nxt + k * interval
              for k in range(min(total, MAX_MISSED_INTERVALS_REPORTED))]
    if digest_now != rec["digest"]:
        return "resource-change", missed, total
    if (deleg_version_now is not None
            and rec["delegations_version"] is not None
            and deleg_version_now != rec["delegations_version"]):
        return "policy-change", missed, total
    if deleg_version_now is None and rec["delegations_version"] is not None:
        # The wire no longer parses as a delegation document -- the
        # verification step will fail loudly; force the scan now.
        return "policy-change", missed, total
    if now >= nxt:
        return "interval", missed, total
    return None, missed, total


def _scan_one(skill_path, rec, *, skill_bytes, delegation_wire, authz_wire,
              root_trust, now):
    digest_now = _digest_of(skill_bytes)
    deleg_version_now = _delegation_version(delegation_wire)
    trigger, missed, missed_total = _evaluate_triggers(
        rec, digest_now=digest_now,
        deleg_version_now=deleg_version_now, now=now)
    truncated = missed_total > len(missed)

    report = {
        "schema": REPORT_SCHEMA,
        "skill": skill_path,
        "scanned_at": now,
        "trigger": trigger,
        "scan_performed": trigger is not None,
        "verdict": "not-scanned",
        "code": None,
        "detail": "",
        "checked": [],
        "missed_intervals": missed,
        "missed_intervals_truncated": truncated,
        "missed_intervals_total": missed_total,
        "clock_trust": CLOCK_TRUST,
        "notes": [],
        "standing": {
            "status": rec["status"],
            "last_verdict": rec["last_verdict"],
            "expires_at": rec["expires_at"],
            "ttl_seconds": rec["ttl_seconds"],
        },
    }
    if missed_total:
        note = ("supplychain-scan-missed-interval: %d scheduled scan(s) "
                "missed and caught up now (never silently skipped)"
                % (missed_total,))
        if truncated:
            note += ("; per-slot listing truncated to %d entries, see "
                     "missed_intervals_total"
                     % (MAX_MISSED_INTERVALS_REPORTED,))
        report["notes"].append(note)
        report["code"] = "supplychain-scan-missed-interval"

    new_rec = dict(rec)
    if trigger is not None:
        trusted = None
        if rec["delegations_version"] is not None:
            trusted = {"delegations_version": rec["delegations_version"]}
            names = rec.get("delegation_names")
            if isinstance(names, list):
                trusted["delegations"] = {n: rec["delegations_version"]
                                          for n in names}
        try:
            vreport = _sc.verify_delegated_authority(
                delegation_wire, authz_wire, skill_path, root_trust,
                now, trusted=trusted)
        except _sc.SupplyChainError as exc:
            report["verdict"] = "refused"
            report["code"] = exc.code
            report["detail"] = str(exc)
            new_rec["last_verdict"] = "refused"
            new_rec["last_code"] = exc.code
            new_rec["consecutive_refusals"] = \
                rec.get("consecutive_refusals", 0) + 1
            # A refused scan never renews the standing and never advances
            # the content baseline: the next scan re-checks the same bytes.
        else:
            # Content binding: the authority check does not hash the bytes.
            # The scanner binds the observed bytes to the authorized digest
            # here, so a SkillJacking-style mutation is refused with a coded
            # reason rather than passing on authority alone.
            if digest_now != vreport["digest"]:
                report["verdict"] = "refused"
                report["code"] = "supplychain-scan-content-mismatch"
                report["detail"] = (
                    "observed bytes digest %s != authorized digest %s"
                    % (digest_now, vreport["digest"]))
                new_rec["last_verdict"] = "refused"
                new_rec["last_code"] = report["code"]
                new_rec["consecutive_refusals"] = \
                    rec.get("consecutive_refusals", 0) + 1
            else:
                report["verdict"] = "verified"
                report["checked"] = list(vreport.get("checked", []))
                if trigger in ("resource-change", "policy-change"):
                    # The change is authorized, but it is still flagged
                    # LOUD: the trigger alone is a field, this note is the
                    # human-readable record.
                    report["notes"].append(
                        "%s: drift from the registration baseline was "
                        "re-verified against the current authority "
                        "(digest %s...); standing renewed"
                        % (trigger, digest_now[:16]))
                new_rec["last_verdict"] = "verified"
                new_rec["last_code"] = None
                new_rec["consecutive_refusals"] = 0
                new_rec["digest"] = digest_now
                new_rec["delegations_version"] = deleg_version_now
                new_rec["status"] = "current"
                new_rec["expires_at"] = now + rec["ttl_seconds"]
        new_rec["last_scan_at"] = now
        new_rec["next_scan_at"] = now + rec["scan_interval_seconds"]

    # Standing expiry is time-based and evaluated on every run, scan or not:
    # expiry without renewal lapses the standing, LOUD, never silent.
    # The boundary is >= : at the expiry instant the TTL has fully elapsed.
    if (new_rec["status"] == "current"
            and new_rec["expires_at"] is not None
            and now >= new_rec["expires_at"]):
        new_rec["status"] = "lapsed"
        report["notes"].append(
            "supplychain-standing-lapsed: TTL expired without a successful "
            "re-verification; standing lapsed (revocation by non-renewal)")
        # The lapse is the headline when nothing else fired.
        if report["code"] is None:
            report["code"] = "supplychain-standing-lapsed"

    report["standing"] = {
        "status": new_rec["status"],
        "last_verdict": new_rec["last_verdict"],
        "expires_at": new_rec["expires_at"],
        "ttl_seconds": new_rec["ttl_seconds"],
    }
    return report, new_rec


def run_scan(state_path, inventory, root_trust, *, now=None):
    """Run one background-scan pass over ``inventory``.

    ``inventory``: iterable of dicts with ``skill_path``, ``skill_bytes``,
    ``delegation_wire``, ``authz_wire``. ``root_trust``: the deployment
    root-trust document (out-of-band bootstrap). ``now``: pinned epoch for
    the whole pass (every expiry check uses it and nothing else).

    CLOCK TRUST (deployment assumption, stated LOUD): ``now`` is
    caller-supplied, or the process clock when omitted. Every TTL/expiry
    evaluation and the missed-interval accounting trust that clock; a
    skewed clock moves the boundaries. The deployment owns clock
    integrity. Each report carries ``clock_trust: "caller-supplied"`` so
    the assumption travels with the evidence (see CLOCK_TRUST).

    Returns the list of per-skill reports. Never enforces -- every refusal
    is carried in the report for a separate actuator.
    """
    now = int(now if now is not None else _utcnow())
    state = _load_state(state_path)
    if not isinstance(inventory, (list, tuple)):
        _fail("supplychain-scan-malformed", "inventory must be a list")
    if not isinstance(root_trust, dict):
        _fail("supplychain-scan-malformed", "root_trust must be a dict")

    # Crash recovery: a leftover sidecar means the previous run died
    # mid-scan. Report it LOUD on the affected skill and re-scan it.
    crashed_skill = None
    sidecar = _state_sidecar(state_path)
    if os.path.exists(sidecar):
        try:
            with open(sidecar, "r", encoding="utf-8") as fh:
                crashed_skill = json.load(fh).get("skill")
        except (ValueError, OSError, UnicodeDecodeError):
            crashed_skill = "<unparseable>"
        try:
            os.unlink(sidecar)
        except OSError:
            pass

    reports = []
    for item in inventory:
        if not isinstance(item, dict):
            _fail("supplychain-scan-malformed",
                  "inventory entries must be dicts")
        skill_path = item.get("skill_path")
        if not isinstance(skill_path, str) or not skill_path:
            _fail("supplychain-scan-malformed",
                  "inventory entry needs a skill_path str")
        rec = state["skills"].get(skill_path)
        if rec is None:
            _fail("supplychain-scan-malformed",
                  "skill %r not registered: register_skill first"
                  % (skill_path,))
        _check_skill_record(rec, "state.skills[%r]" % (skill_path,))
        for key in ("skill_bytes", "delegation_wire", "authz_wire"):
            if key not in item:
                _fail("supplychain-scan-malformed",
                      "inventory entry %r missing %r" % (skill_path, key))

        # Mark in-progress BEFORE the scan; clear AFTER the state persist.
        with open(sidecar, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"skill": skill_path,
                                 "started_at": now}))
        report, new_rec = _scan_one(
            skill_path, rec,
            skill_bytes=item["skill_bytes"],
            delegation_wire=item["delegation_wire"],
            authz_wire=item["authz_wire"],
            root_trust=root_trust, now=now)
        if crashed_skill == skill_path:
            report["notes"].insert(
                0, "supplychain-scan-crash-recovered: previous run crashed "
                   "mid-scan of this skill; re-scanned now (never silently "
                   "resumed)")
            if report["code"] is None:
                report["code"] = "supplychain-scan-crash-recovered"
        elif crashed_skill == "<unparseable>":
            # The sidecar itself was corrupt: we cannot tell which skill
            # was mid-scan, so every report carries the LOUD note rather
            # than any skill silently missing its recovery record.
            report["notes"].insert(
                0, "supplychain-scan-crash-recovered: previous run crashed "
                   "mid-scan of an unknown skill (sidecar unparseable); "
                   "all skills re-scanned now")
        state["skills"][skill_path] = new_rec
        _store_state(state_path, state)
        try:
            os.unlink(sidecar)
        except OSError:
            pass
        reports.append(report)
    return reports


def scan_report_digest(report):
    """Stable digest of a scan report (for audit chaining by callers)."""
    blob = json.dumps(report, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
