"""Relying-party admissibility for evidence bundles + replay-digest binding.

Native reimplementation of an EMILIA-style admissibility discipline
(the idea only: verification outcomes are *classified*, and each
verification is *replay-bound* to ``{policy, normalized_facts, as_of}``).
No EMILIA source is vendored and no conformance with any EMILIA
document is claimed -- the relevant IETF drafts are individual and
not adopted. This module sits ON TOP of the existing offline verifier
(``gov/evidence_verify.py``); it does not touch the verifier's check
list, verdict vocabulary, or the ``tools/evidence-verify`` byte-copy.

Two upgrades over pass/fail verification:

1. **Relying-party admissibility policy.** A verification outcome is
   classified, not just passed/failed::

       admissible | missing_evidence | stale | conflicted | unverifiable

   - ``admissible``: every verifier check passed, the evidence the
     bundle references is present, and the bundle is fresh within the
     relying party's ``as_of`` bound.
   - ``missing_evidence``: the bundle references evidence that is not
     present -- a required transport file is absent, or entries carry
     no inclusion bundle (operator-declared degraded coverage is still
     *missing* evidence, honestly labeled). Never silently passes: a
     policy may only accept this class with explicit
     ``acknowledge_risk=True``.
   - ``stale``: the bundle verified, but ``as_of - exported_at``
     exceeds the relying party's ``max_age_seconds``. Freshness is
     explicit, never implied.
   - ``conflicted``: evidence chains disagree -- the payload's policy
     claim contradicts the slice's ``policy_loaded`` record (V11), the
     receipt chain disagrees with the auditor's log copy (V12b), or
     citation/approval cross-consistency fails (V13). Never silently
     passes: same ``acknowledge_risk`` discipline as missing evidence.
   - ``unverifiable``: any other check failure (bad signature, broken
     digest, unparseable age, malformed record). Fail-closed.

   A relying party configures which classes it accepts (an auditor
   requires ``admissible``; a monitor may tolerate ``stale`` with a
   named warning code). Priority on multiple conditions: unverifiable
   > conflicted > missing_evidence > stale > admissible.

2. **Replay-digest binding.** ``bind_verification`` seals a
   verification into a record whose ``replay_digest`` binds
   ``{policy_fingerprint, normalized_facts, as_of, outcome}``. A stale
   verification cannot be replayed against a newer policy or a
   different fact set: ``check_replay`` recomputes the digest from the
   caller-supplied policy/facts/as_of, and any mismatch is
   ``unverifiable`` (code ``replay_binding_mismatch``), not
   ``admissible``. A record replayed after the policy's
   ``max_age_seconds`` is ``stale`` (code ``verification_record_stale``).

$0 spend, synthetic/local only. No network.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from gov import evidence_verify as _ev

#: Classified verification outcomes. The vocabulary is this module's
#: own (admissibility classes), distinct from the verifier's
#: FAILED / SELF_CONSISTENT / VERIFIED verdicts.
OUTCOME_CLASSES = ("admissible", "missing_evidence", "stale",
                   "conflicted", "unverifiable")

#: Check ids whose failure means evidence chains *disagree* (payload
#: claim vs slice record, citation vs violation counts, approval
#: vocabulary vs slice events).
_CONFLICTED_CHECK_IDS = frozenset({"V11", "V13"})

#: Check ids whose failure means the bundle references evidence that
#: is not present (required transport files absent).
_MISSING_CHECK_IDS = frozenset({"V2"})

#: Default freshness bound: a bundle older than this at the ``as_of``
#: anchor is ``stale``.
DEFAULT_MAX_AGE_SECONDS = 30 * 86400

#: Domain prefix for the replay digest (keeps this digest
#: unpresentable in any other digest's role).
REPLAY_DIGEST_DOMAIN = b"bundle-admissibility-replay/v1\x00"

RECORD_FORMAT = "bundle-admissibility-verification/1"


class AdmissibilityError(Exception):
    """Loud failure: malformed record, unparseable time, bad inputs."""


class PolicyAuthoringError(Exception):
    """Loud failure at policy construction: unknown classes, warn not
    a subset of accept, risky classes accepted without explicit
    ``acknowledge_risk=True``, non-positive max_age."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), default=str).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_time(value):
    """Parse an ISO-8601 timestamp to an aware datetime. Raises
    AdmissibilityError (never returns a naive datetime and never
    guesses)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise AdmissibilityError(
                "naive datetime is not a time anchor: pass an aware "
                "datetime or an ISO-8601 string with offset")
        return value
    if not isinstance(value, str):
        raise AdmissibilityError(
            "time anchor must be an ISO-8601 string or aware datetime, "
            "got %r" % type(value).__name__)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise AdmissibilityError(
            "unparseable ISO-8601 timestamp %r" % (value,))
    if dt.tzinfo is None:
        raise AdmissibilityError(
            "timestamp %r has no offset: staleness cannot be bounded "
            "without one" % (value,))
    return dt


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat()


class AdmissibilityPolicy:
    """A relying party's admissibility configuration.

    ``accept``: outcome classes this relying party admits.
    ``warn``: subset of ``accept`` admitted with a named warning code
    (tolerated, not clean).
    ``max_age_seconds``: freshness bound against the ``as_of`` anchor.
    ``acknowledge_risk``: MUST be True to accept ``conflicted`` or
    ``missing_evidence`` -- those classes never pass silently.
    """

    def __init__(self, *, accept=(), warn=(), max_age_seconds=None,
                 acknowledge_risk=False, name=None):
        accept = tuple(accept)
        warn = tuple(warn)
        for cls in accept + warn:
            if cls not in OUTCOME_CLASSES:
                raise PolicyAuthoringError(
                    "unknown outcome class %r (known: %s)"
                    % (cls, ", ".join(OUTCOME_CLASSES)))
        if len(set(accept)) != len(accept):
            raise PolicyAuthoringError("duplicate class in accept")
        if not set(warn) <= set(accept):
            raise PolicyAuthoringError(
                "warn must be a subset of accept: %r not all accepted"
                % (sorted(set(warn) - set(accept)),))
        risky = {"conflicted", "missing_evidence"} & set(accept)
        if risky and not acknowledge_risk:
            raise PolicyAuthoringError(
                "%s may not be accepted without explicit "
                "acknowledge_risk=True: these classes never pass "
                "silently" % sorted(risky))
        if max_age_seconds is None:
            max_age_seconds = DEFAULT_MAX_AGE_SECONDS
        if (isinstance(max_age_seconds, bool)
                or not isinstance(max_age_seconds, (int, float))
                or not max_age_seconds > 0):
            raise PolicyAuthoringError(
                "max_age_seconds must be a positive number, got %r"
                % (max_age_seconds,))
        if name is not None and not isinstance(name, str):
            raise PolicyAuthoringError("name must be a string or None")
        self.accept = accept
        self.warn = warn
        self.max_age_seconds = max_age_seconds
        self.acknowledge_risk = bool(acknowledge_risk)
        self.name = name or "unnamed"

    @classmethod
    def auditor_strict(cls):
        """An auditor admits only fully admissible bundles."""
        return cls(accept=("admissible",), name="auditor-strict")

    @classmethod
    def monitor_lax(cls):
        """A monitor tolerates staleness (with a named warning code)
        but never conflicted / missing_evidence / unverifiable."""
        return cls(accept=("admissible", "stale"), warn=("stale",),
                   name="monitor-lax")

    def fingerprint(self):
        """Deployment pin for the policy: the replay digest binds this,
        so a rotated policy cannot replay an old verification."""
        return _sha256_hex(_canonical({
            "accept": sorted(self.accept),
            "warn": sorted(self.warn),
            "max_age_seconds": self.max_age_seconds,
            "acknowledge_risk": self.acknowledge_risk,
            "name": self.name,
        }))

    def decide(self, outcome_class, reasons=()):
        """Apply the policy to a classified outcome.

        Returns {"accepted", "code", "outcome", "warning", "reasons"}.
        Never raises on a known class; unknown classes are a caller
        bug and raise AdmissibilityError.
        """
        if outcome_class not in OUTCOME_CLASSES:
            raise AdmissibilityError(
                "unknown outcome class %r" % (outcome_class,))
        reasons = list(reasons)
        if outcome_class not in self.accept:
            return {"accepted": False,
                    "code": "rejected_" + outcome_class,
                    "outcome": outcome_class,
                    "warning": None,
                    "reasons": reasons}
        if outcome_class in self.warn:
            return {"accepted": True,
                    "code": "tolerated_" + outcome_class,
                    "outcome": outcome_class,
                    "warning": "bundle_%s_accepted" % outcome_class,
                    "reasons": reasons}
        return {"accepted": True, "code": "admissible",
                "outcome": outcome_class, "warning": None,
                "reasons": reasons}


def _load_manifest(bundle_dir):
    try:
        return _ev._load_json(bundle_dir, "manifest.json")
    except Exception:  # OSError, ValueError: hostile/missing bundle
        return {}


def _load_payload(bundle_dir):
    try:
        return _ev._load_json(bundle_dir, "evidence.json")
    except Exception:
        return {}


def _classify_checks(failed):
    """Map failed verifier checks to (outcome, reasons).

    Priority inside this mapping: unverifiable > conflicted >
    missing_evidence (stale/admissible are decided by later
    inspections). Returns (outcome, reasons, evidence_chain).
    """
    reasons = []
    chain = []
    outcome = None
    for c in failed:
        cid = c.get("id", "?")
        chain.append({"id": cid, "name": c.get("name"),
                      "status": c.get("status"), "detail": c.get("detail")})
    for c in failed:
        cid = c.get("id", "?")
        detail = c.get("detail") or ""
        if cid in _CONFLICTED_CHECK_IDS:
            outcome = "conflicted"
            reasons.append("%s failed: evidence chains disagree (%s)"
                           % (cid, detail[:160]))
        elif cid == "V12" and "V12b source log" in detail:
            # V12b: the bundle's receipt chain disagrees with the
            # auditor's own log copy -- a genuine conflict between
            # evidence chains, not a generic verification failure.
            outcome = "conflicted"
            reasons.append("V12b failed: receipt chain disagrees with "
                           "the auditor's log copy (%s)" % detail[:160])
        elif cid in _MISSING_CHECK_IDS:
            if outcome != "conflicted":
                outcome = "missing_evidence"
            reasons.append("%s failed: referenced evidence not present "
                           "(%s)" % (cid, detail[:160]))
        else:
            outcome = "unverifiable"
            reasons.append("%s failed: %s" % (cid, detail[:160]))
            break  # unverifiable dominates; keep the first as the reason
    return outcome, reasons, chain


def classify(bundle_dir, *, pins=(), pinned_cp_key_ids=None,
             source_log=None, receipt_pins=(), as_of=None,
             max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    """Classify a bundle's verification outcome for a relying party.

    Runs the offline verifier (V1-V19), maps failed checks to
    admissibility classes, inspects inclusion-bundle coverage for
    honestly-labeled missing evidence, and applies the ``as_of``
    freshness bound. Returns a dict with "outcome", "reasons",
    "evidence_chain", "as_of", "bundle_digest", "bundle_id",
    "verifier_verdict", and "max_age_seconds".
    """
    if (isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, (int, float))
            or not max_age_seconds > 0):
        raise AdmissibilityError(
            "max_age_seconds must be a positive number, got %r"
            % (max_age_seconds,))
    as_of_dt = _parse_time(as_of) if as_of is not None \
        else datetime.now(timezone.utc)
    as_of_iso = as_of_dt.isoformat()

    # verify_bundle returns (code, [Check...], summary_dict); on early
    # V0/V1/V2/V3 failure the summary dict is EMPTY, so the failed
    # checks must come from the returned Check objects, not the
    # summary. (Missing this made a missing required file classify as
    # "admissible" -- caught red-first by the wave-218 battery.)
    _code, check_objs, summary = _ev.verify_bundle(
        bundle_dir, pins=pins, pinned_cp_key_ids=pinned_cp_key_ids,
        source_log=source_log, receipt_pins=receipt_pins)
    failed = [c.as_dict() for c in check_objs
              if getattr(c, "status", None) == "fail"]
    outcome, reasons, chain = _classify_checks(failed)

    manifest = _load_manifest(bundle_dir)
    payload = _load_payload(bundle_dir)
    bundle_digest = summary.get("bundle_digest")
    bundle_id = summary.get("bundle_id")

    if outcome is None:
        # No check failed: inspect coverage for honestly-labeled
        # missing evidence (entries without inclusion bundles), then
        # apply the freshness bound.
        ic = manifest.get("inclusion_coverage") or {}
        entries = ic.get("entries")
        with_bundle = ic.get("with_bundle")
        if (isinstance(entries, int) and isinstance(with_bundle, int)
                and with_bundle < entries):
            outcome = "missing_evidence"
            reasons.append(
                "inclusion coverage %d/%d: %d window entr%s reference "
                "inclusion evidence that is not present "
                "(operator-declared degraded or unavailable)"
                % (with_bundle, entries, entries - with_bundle,
                   "y" if entries - with_bundle == 1 else "ies"))
            chain.append({"id": "ADM-COVERAGE", "name": "inclusion coverage",
                          "status": "gap",
                          "detail": "with_bundle=%d entries=%d"
                                    % (with_bundle, entries)})
        if outcome is None:
            exported_at = (payload.get("bundle_meta") or {}).get(
                "exported_at")
            try:
                exp_dt = _parse_time(exported_at)
            except AdmissibilityError:
                outcome = "unverifiable"
                reasons.append(
                    "bundle_meta.exported_at %r is unparseable: "
                    "staleness cannot be bounded" % (exported_at,))
                chain.append({"id": "ADM-STALE",
                              "name": "freshness bound",
                              "status": "unbounded",
                              "detail": "exported_at unparseable"})
            else:
                age = (as_of_dt - exp_dt).total_seconds()
                if age < 0:
                    outcome = "unverifiable"
                    reasons.append(
                        "bundle exported_at is in the future relative "
                        "to as_of: clock or bundle untrustworthy")
                    chain.append({"id": "ADM-STALE",
                                  "name": "freshness bound",
                                  "status": "future",
                                  "detail": "exported_at > as_of"})
                elif age > max_age_seconds:
                    outcome = "stale"
                    reasons.append(
                        "bundle age %.0fs exceeds max_age_seconds=%s "
                        "at as_of %s" % (age, max_age_seconds, as_of_iso))
                    chain.append({"id": "ADM-STALE",
                                  "name": "freshness bound",
                                  "status": "stale",
                                  "detail": "age %.0fs > max_age %s"
                                            % (age, max_age_seconds)})
        if outcome is None:
            outcome = "admissible"

    return {
        "outcome": outcome,
        "reasons": reasons,
        "evidence_chain": chain,
        "as_of": as_of_iso,
        "max_age_seconds": max_age_seconds,
        "bundle_digest": bundle_digest,
        "bundle_id": bundle_id,
        "verifier_verdict": summary.get("verdict"),
    }


def admit(bundle_dir, policy, *, pins=(), pinned_cp_key_ids=None,
          source_log=None, receipt_pins=(), as_of=None,
          max_age_seconds=None):
    """Full admission pipeline: classify, then apply the relying
    party's policy. Returns the classification plus "accepted",
    "code", and "warning"."""
    if not isinstance(policy, AdmissibilityPolicy):
        raise AdmissibilityError(
            "policy must be an AdmissibilityPolicy, got %r"
            % type(policy).__name__)
    if max_age_seconds is None:
        max_age_seconds = policy.max_age_seconds
    result = classify(bundle_dir, pins=pins,
                      pinned_cp_key_ids=pinned_cp_key_ids,
                      source_log=source_log, receipt_pins=receipt_pins,
                      as_of=as_of, max_age_seconds=max_age_seconds)
    decision = policy.decide(result["outcome"], result["reasons"])
    result.update({"accepted": decision["accepted"],
                   "code": decision["code"],
                   "warning": decision["warning"],
                   "policy": policy.name})
    return result


def _default_facts(classification):
    """Normalized facts a verification depends on: bundle identity,
    the classified outcome, and the per-check status vector. A
    verification replayed against a different fact set (different
    bundle, different outcome, different check results) will not match
    the bound digest."""
    checks = {c["id"]: c["status"]
              for c in (classification.get("evidence_chain") or [])
              if "id" in c}
    return {
        "bundle_digest": classification.get("bundle_digest"),
        "bundle_id": classification.get("bundle_id"),
        "outcome": classification.get("outcome"),
        "verifier_verdict": classification.get("verifier_verdict"),
        "check_statuses": checks,
    }


def replay_digest(*, policy_fingerprint, facts, as_of):
    """Bind {policy, normalized facts, as_of} into one digest.

    The policy is identified by its fingerprint (a rotated policy has
    a different fingerprint); the facts are the normalized verification
    inputs; as_of is the verification time anchor. Any substitution of
    one for another fails the replay.
    """
    if not isinstance(policy_fingerprint, str) or not policy_fingerprint:
        raise AdmissibilityError("policy_fingerprint must be a non-empty "
                                 "string")
    if not isinstance(facts, dict):
        raise AdmissibilityError("facts must be a dict")
    as_of_iso = _parse_time(as_of).isoformat() if as_of is not None \
        else _utcnow_iso()
    body = {"policy_fingerprint": policy_fingerprint,
            "facts": facts,
            "as_of": as_of_iso}
    return _sha256_hex(REPLAY_DIGEST_DOMAIN + _canonical(body)), as_of_iso


def bind_verification(bundle_dir, policy, *, facts=None, as_of=None,
                      pins=(), pinned_cp_key_ids=None, source_log=None,
                      receipt_pins=(), max_age_seconds=None):
    """Verify a bundle, classify the outcome, and seal the verification
    into a replay-bound record.

    Returns {"format", "replay_digest", "as_of", "policy_fingerprint",
    "policy_name", "facts", "outcome", "reasons", "bundle_digest",
    "bundle_id", "verifier_verdict"}. The record is self-describing:
    ``check_replay`` needs only the record plus the caller's
    policy/facts/as_of.
    """
    if not isinstance(policy, AdmissibilityPolicy):
        raise AdmissibilityError(
            "policy must be an AdmissibilityPolicy, got %r"
            % type(policy).__name__)
    if max_age_seconds is None:
        max_age_seconds = policy.max_age_seconds
    result = classify(bundle_dir, pins=pins,
                      pinned_cp_key_ids=pinned_cp_key_ids,
                      source_log=source_log, receipt_pins=receipt_pins,
                      as_of=as_of, max_age_seconds=max_age_seconds)
    facts = dict(facts) if facts is not None else _default_facts(result)
    digest, as_of_iso = replay_digest(
        policy_fingerprint=policy.fingerprint(), facts=facts,
        as_of=result["as_of"])
    return {
        "format": RECORD_FORMAT,
        "replay_digest": digest,
        "as_of": as_of_iso,
        "policy_fingerprint": policy.fingerprint(),
        "policy_name": policy.name,
        "facts": facts,
        "outcome": result["outcome"],
        "reasons": result["reasons"],
        "bundle_digest": result["bundle_digest"],
        "bundle_id": result["bundle_id"],
        "verifier_verdict": result["verifier_verdict"],
    }


def check_replay(record, *, policy, facts=None, as_of=None, now=None):
    """Check a bound verification record against a caller-supplied
    policy/facts/as_of.

    - Any mismatch with the bound digest -> ("unverifiable",
      "replay_binding_mismatch"): the verification is being replayed
      against a different policy, a different fact set, or a different
      time anchor. This is fail-closed, never "admissible".
    - The record itself older than the policy's max_age at ``now`` ->
      ("stale", "verification_record_stale").
    - Otherwise -> (record's outcome, "replay_ok").

    ``facts=None`` replays against the record's own facts;
    ``as_of=None`` replays against the record's own anchor;
    ``now=None`` means the current wall clock.
    """
    if not isinstance(record, dict) or \
            record.get("format") != RECORD_FORMAT:
        return {"outcome": "unverifiable",
                "code": "malformed_record",
                "detail": "not a %s record" % RECORD_FORMAT}
    if not isinstance(policy, AdmissibilityPolicy):
        raise AdmissibilityError(
            "policy must be an AdmissibilityPolicy, got %r"
            % type(policy).__name__)
    want_facts = record.get("facts") if facts is None else facts
    want_as_of = record.get("as_of") if as_of is None else as_of
    try:
        digest, _ = replay_digest(
            policy_fingerprint=policy.fingerprint(),
            facts=want_facts, as_of=want_as_of)
    except AdmissibilityError as e:
        return {"outcome": "unverifiable", "code": "malformed_record",
                "detail": str(e)}
    if digest != record.get("replay_digest"):
        return {"outcome": "unverifiable",
                "code": "replay_binding_mismatch",
                "detail": ("the verification was bound to a different "
                           "policy, fact set, or time anchor")}
    now_dt = _parse_time(now) if now is not None \
        else datetime.now(timezone.utc)
    try:
        rec_dt = _parse_time(record["as_of"])
    except AdmissibilityError:
        return {"outcome": "unverifiable", "code": "malformed_record",
                "detail": "record as_of unparseable"}
    age = (now_dt - rec_dt).total_seconds()
    if age > policy.max_age_seconds:
        return {"outcome": "stale",
                "code": "verification_record_stale",
                "detail": ("verification record is %.0fs old at replay "
                           "time (max_age_seconds=%s)"
                           % (age, policy.max_age_seconds))}
    outcome = record.get("outcome")
    if outcome not in OUTCOME_CLASSES:
        return {"outcome": "unverifiable", "code": "malformed_record",
                "detail": "record outcome %r not a known class"
                          % (outcome,)}
    return {"outcome": outcome, "code": "replay_ok",
            "detail": "replay digest matches the bound verification"}
