"""PolicyReport-shaped violation telemetry for the graduation ladder.

Wave-199: ADAPT of kyverno/kyverno (Apache-2.0 -- LICENSE bytes verified
2026-09-29 in the wave-198 prospecting clone):
  (1) ``ValidationFailureAction`` Audit vs Enforce -- the second convergent
      data point for the ladder (Gatekeeper's dryrun->warn->deny from
      wave-196 was the first; the pattern is convergent, not incidental).
  (2) ``PolicyReportResult{source, policy, rule, resources, ...}`` -- the
      telemetry shape for our per-rule hash-chained violation ledger
      (``gov/mode_ledger.py``).

This module PROJECTS the ModeLedger into auditor-consumable
PolicyReport-shaped records. It never mutates the ledger, never sees
request content (material-free: only the request digest), and never
decides anything -- it is telemetry, not enforcement.

Kyverno mapping (our semantics win where we diverge; divergences are
documented here, never silently papered):

  observe  -- STRICTER (weaker authority) than Kyverno Audit. An
              observe-mode hit is recorded in the ledger and named in
              ``observed_hits``, but carries ZERO authority: it can
              never be the decider and cannot weaken default-deny.
              Kyverno Audit still presents the violation as a failed
              result on an admitted resource; our observe is
              diagnostic-only. Projected as ``result: "skip"``.
  warn     -- APPROXIMATES Kyverno Audit: the request is admitted with
              the nominal effect preserved, and the violation is
              recorded and operator-visible. Divergence: Kyverno's
              audit result is per-resource at admission time; ours
              routes warnings through operator warn digests (chained
              audit entries), never as agent interrupts. Projected as
              ``result: "warn"``.
  deny     -- STRONGER than Kyverno Enforce: a deny not only blocks the
              call, it halts the run (canary-style). Deny-mode
              decisions are today's behavior and live in the decision
              BOM, not in this report -- PolicyReport covers the
              ladder rungs (observe/warn) plus mode transitions.
  overrides -- Kyverno's per-namespace
              ``ValidationFailureActionOverride`` has NO Sasanam
              equivalent: per-rule ``mode`` is global per policy
              engine. Documented, not papered.
  ladder    -- Kyverno's action is binary; ours graduates
              observe->warn->deny only on evidence plus an attested
              human quorum (``ModeLedger.evaluate_graduation``).
              Mode transitions (labeled ``graduation``/``demotion``/
              ``emergency_demotion`` in the ledger) project as
              ``result: "pass"`` records with ``category: "ladder"``
              so the auditor sees the evidence the quorum acted on.

Resources: Sasanam governs agent tool calls, not Kubernetes objects, so
``resources[]`` carries ``{kind: "sasanam/request", uid: <request_digest>}``
-- the request identity, never its content. A record without a request
digest projects with an empty ``resources`` list.
"""

import datetime
import hashlib
import json

from . import ed25519 as _ed25519
from . import attested_identity as _attested_identity

#: Version of the report schema this module emits.
REPORT_VERSION = "sasanam-policy-report/1.0"

#: Default ``source`` value on every result (Kyverno puts "kyverno" here).
DEFAULT_SOURCE = "sasanam/ladder"

#: Domain separation for the operator's report signature. Bumped (not
#: reused) so evidence-bundle manifest signatures are unpresentable as
#: policy-report signatures.
SIGN_DOMAIN = b"policy-report/v1\x00"
SIGN_DOMAIN_STR = "policy-report/v1"

#: Ledger record kinds projected into report results. ``violation``
#: records are literal. Mode transitions are detected STRUCTURALLY
#: (payload carries ``old_mode``/``new_mode``) rather than by the
#: record's ``kind`` label, because ``ModeLedger._append`` lets the
#: payload's ``kind`` overwrite the record kind -- real transitions
#: are labeled ``graduation``/``demotion``/``emergency_demotion``.
#: Structural detection means a future transition label can never
#: silently drop out of the report.
VIOLATION_KIND = "violation"


def _is_transition(record):
    """True for mode-transition records (any transition label)."""
    return ("old_mode" in record and "new_mode" in record)


def _record_role(record):
    """Classify a ledger record for projection. Raises loudly on
    anything unprojectable -- the auditor must never get a silently
    half-projected report."""
    kind = record.get("kind")
    if kind == VIOLATION_KIND:
        return "violation"
    if _is_transition(record):
        return "transition"
    raise PolicyReportError(
        "record kind %r is not reportable (violation or a mode "
        "transition with old_mode/new_mode)" % (kind,))


class PolicyReportError(Exception):
    """The report could not be built, sealed, or verified (loud)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _iso_utc(epoch):
    return (datetime.datetime.fromtimestamp(float(epoch),
                                            tz=datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def _check_ledger(ledger):
    """Fail closed unless ``ledger`` looks like a ModeLedger.

    We duck-type the three seams we need (``_chain`` records,
    ``verify_rule_chain``, ``rule_ids``, ``stats``) so a test double
    with the same shape works, but anything else is refused loudly
    -- the auditor must never get a silently half-projected report.
    """
    chain = getattr(ledger, "_chain", None)
    if not isinstance(chain, list):
        raise PolicyReportError(
            "ledger does not expose a record chain (_chain: list)")
    for seam in ("verify_rule_chain", "rule_ids", "stats"):
        if not callable(getattr(ledger, seam, None)):
            raise PolicyReportError(
                "ledger does not expose %s()" % (seam,))
    return chain


def _check_identity_tier(identity_tier):
    """Validate the optional wave-204 attested-identity tier.

    Returns the tier label (``"tier-1-attested"`` / ``"tier-2-kernel-fact"``)
    or None when omitted. Raises PolicyReportError on anything else --
    a report must never silently record a weaker claim than the decision
    actually rested on.
    """
    if identity_tier is None:
        return None
    # bool rejected explicitly: True == 1 in Python, so a bare dict
    # lookup would silently label tier=True as "tier-1-attested".
    if isinstance(identity_tier, bool):
        raise PolicyReportError(
            "identity_tier must be 1 (tier-1-attested) or 2 "
            "(tier-2-kernel-fact), got %r" % (identity_tier,))
    label = _attested_identity.TIER_LABELS.get(identity_tier)
    if label is None:
        raise PolicyReportError(
            "identity_tier must be 1 (tier-1-attested) or 2 "
            "(tier-2-kernel-fact), got %r" % (identity_tier,))
    return label


def project_result(record, *, policy_name, source=DEFAULT_SOURCE,
                   policy_version=None, identity_tier=None):
    """Project one ModeLedger record into a PolicyReportResult dict.

    Only ``violation`` records and mode-transition records (any
    transition label; detected structurally via ``old_mode`` /
    ``new_mode``) project; anything else raises
    :class:`PolicyReportError` (the caller, not this function,
    filters -- a programming error must be loud).

    Wave-204: ``identity_tier`` (1 or 2) records the attested-identity
    tier the deciding agent bootstrapped under; it rides
    ``properties.identity_tier``. Omitted by default (no behavior
    change).
    """
    if not isinstance(record, dict):
        raise PolicyReportError("record must be a dict")
    _check_identity_tier(identity_tier)
    role = _record_role(record)
    if not policy_name or not isinstance(policy_name, str):
        raise PolicyReportError("policy_name must be a non-empty str")

    rule_id = record.get("rule_id")
    properties = {
        "ledger_seq": record.get("seq"),
        "ledger_digest": record.get("digest"),
        "rule_seq": record.get("rule_seq"),
        "rule_prev": record.get("rule_prev"),
    }
    if policy_version is not None:
        properties["policy_version"] = policy_version
    if identity_tier is not None:
        properties["identity_tier"] = identity_tier

    resources = []
    request_digest = record.get("request_digest")
    if request_digest:
        resources.append({"kind": "sasanam/request",
                          "uid": str(request_digest)})
        properties["request_digest"] = str(request_digest)

    if role == "violation":
        mode = record.get("mode")
        nominal = record.get("nominal_effect")
        properties["mode"] = mode
        if nominal is not None:
            properties["nominal_effect"] = nominal
        if mode == "observe":
            result, severity = "skip", "low"
            message = ("observe-mode hit (diagnostic only: recorded, "
                       "zero authority, never the decider)")
        elif mode == "warn":
            result, severity = "warn", "medium"
            message = ("warn-mode hit (admitted with warning; nominal "
                       "effect preserved: %s)" % (nominal,))
        else:
            raise PolicyReportError(
                "violation record with unexpected mode %r" % (mode,))
        category = "ladder-violation"
    else:  # transition (graduation / demotion / emergency_demotion / ...)
        result, severity, category = "pass", "info", "ladder"
        stats = record.get("stats") or {}
        properties["transition"] = record.get("kind")
        properties["old_mode"] = record.get("old_mode")
        properties["new_mode"] = record.get("new_mode")
        properties["approvers"] = record.get("approvers")
        properties["graduation_stats"] = stats
        message = ("rule %s %s: %s -> %s (quorum evidence: "
                   "evaluated=%s violations=%s reviewed=%s fp_rate=%s)"
                   % (rule_id, record.get("kind"), record.get("old_mode"),
                      record.get("new_mode"), stats.get("evaluated"),
                      stats.get("violations"), stats.get("reviewed"),
                      stats.get("fp_rate")))

    return {
        "source": source,
        "policy": policy_name,
        "rule": rule_id,
        "resources": resources,
        "result": result,
        "severity": severity,
        "category": category,
        "message": message,
        "timestamp": _iso_utc(record.get("at", 0)),
        "properties": properties,
    }


def build_report(ledger, *, policy_name, source=DEFAULT_SOURCE,
                 policy_version=None, window_start=None, window_end=None,
                 rule_ids=None, identity_tier=None):
    """Build a PolicyReport dict from a ModeLedger for an audit window.

    ``window_start``/``window_end`` are epoch seconds bounding
    ``record["at"]`` (inclusive start, exclusive end); ``None`` means
    unbounded. ``rule_ids`` restricts the RESULTS to a subset of
    rules; ``ruleStats`` always covers every registered rule (rules
    with evaluations but zero violations have no chain records, yet
    the auditor needs their evaluated counts). The ledger is never
    mutated. Deterministic for a fixed ledger and window.

    Wave-204: ``identity_tier`` (1 or 2) records the attested-identity
    tier the deciding agent bootstrapped under; it rides
    ``metadata.identityTier`` as the tier label. Omitted by default
    (no behavior change).
    """
    chain = _check_ledger(ledger)
    identity_tier_label = _check_identity_tier(identity_tier)
    if rule_ids is not None:
        rule_ids = frozenset(rule_ids)

    results = []
    for record in chain:
        try:
            _record_role(record)
        except PolicyReportError:
            continue  # heartbeats, reviews, warnings_surfaced: stats, not results
        at = record.get("at")
        if window_start is not None and at < window_start:
            continue
        if window_end is not None and at >= window_end:
            continue
        if rule_ids is not None and record.get("rule_id") not in rule_ids:
            continue
        results.append(project_result(
            record, policy_name=policy_name, source=source,
            policy_version=policy_version))

    summary = {"pass": 0, "fail": 0, "warn": 0, "error": 0, "skip": 0}
    for r in results:
        summary[r["result"]] = summary.get(r["result"], 0) + 1
    summary["total"] = len(results)

    # Deterministic as-of time: the latest included record's timestamp
    # (fallback: window_end, then epoch 0). Wall-clock generatedAt
    # would make byte-identical inputs produce different reports, so
    # the auditor could never re-derive a report deterministically.
    as_of = max([r.get("at", 0) for r in chain
                 if r.get("at") is not None] + [0])
    if window_end is not None:
        as_of = max(as_of, window_end)

    # Per-rule stats for every registered rule (not just rules with
    # records): the auditor's graduation/demotion evidence, including
    # the zero-violation case and the surfaced-warning count.
    rule_stats = {}
    for rid in ledger.rule_ids():
        st = ledger.stats(rid)
        if st is None:
            continue
        rule_stats[rid] = {
            "mode": st.get("mode"),
            "pinned": st.get("pinned"),
            "evaluated": st.get("evaluated"),
            "violations": st.get("violations"),
            "reviewed_correct": st.get("reviewed_correct"),
            "reviewed_wrong": st.get("reviewed_wrong"),
            "reviewed_total": st.get("reviewed_total"),
            "fp_rate": st.get("fp_rate"),
            "warnings_surfaced": st.get("warnings_surfaced", 0),
            "warn_since": (_iso_utc(st["warn_since"])
                           if st.get("warn_since") else None),
            "mode_history": st.get("mode_history", []),
        }

    return {
        "apiVersion": "sasanam.io/v1",
        "kind": "PolicyReport",
        "reportVersion": REPORT_VERSION,
        "metadata": {
            "name": "policy-report-%s" % (policy_name,),
            "source": source,
            "generatedAt": _iso_utc(as_of),
            "window": {"start": window_start, "end": window_end},
            **({"policyVersion": policy_version}
               if policy_version is not None else {}),
            **({"identityTier": identity_tier_label}
               if identity_tier_label is not None else {}),
        },
        "summary": summary,
        "results": results,
        "ruleStats": rule_stats,
    }


def _resolve_operator_signer():
    """Resolve the operator Ed25519 signer, fail-closed.

    Mirrors the ``gov/evidence_bundle.py`` pattern: an explicit signer
    is preferred; otherwise the deployment anchor key
    (``GOV_ANCHOR_KEY``/``GOV_ANCHOR_KEY_FILE``) is used. An unsigned
    policy report is not a policy report -- refusal is loud.
    """
    from . import anchorer as _anchorer
    from .signing import Ed25519Signer as _Ed25519Signer
    try:
        key = _anchorer.resolve_anchor_key()
    except Exception as e:
        raise PolicyReportError(
            "seal() refuses: no signer given and the operator anchor "
            "key is not configured (%s). Set GOV_ANCHOR_KEY or "
            "GOV_ANCHOR_KEY_FILE." % (e,))
    if key is None:
        raise PolicyReportError(
            "seal() refuses: no signer given and the operator anchor "
            "key is not configured. Set GOV_ANCHOR_KEY or "
            "GOV_ANCHOR_KEY_FILE.")
    seed = bytes(key) if not isinstance(key, bytes) else key
    if len(seed) != 32:
        raise PolicyReportError(
            "seal() refuses: resolved anchor key is not 32 bytes")
    return _Ed25519Signer(seed)


def seal_report(report, signer):
    """Seal a built report: {report, signing} envelope.

    The signature covers ``SIGN_DOMAIN || sha256(canonical(report))``.
    """
    if not isinstance(report, dict) or report.get("kind") != "PolicyReport":
        raise PolicyReportError("seal() expects a PolicyReport dict")
    key_id = getattr(signer, "key_id", None)
    public_key = getattr(signer, "public_key", None)
    if key_id is None or public_key is None:
        raise PolicyReportError("signer lacks key_id/public_key")
    body = _canonical(report)
    sig = signer.sign(SIGN_DOMAIN + _sha256_hex(body).encode("ascii"))
    return {
        "report": report,
        "signing": {
            "scheme": "ed25519",
            "key_id": key_id,
            "public_key_hex": bytes(public_key).hex(),
            "signature_hex": bytes(sig).hex(),
            "domain": SIGN_DOMAIN_STR,
            "signed_bytes": "domain || sha256(canonical(report))",
        },
    }


def verify_report(envelope, public_key):
    """Verify a sealed envelope. Fail-closed: malformed -> False.

    ``public_key`` is the 32-byte operator public key the auditor
    trusts out-of-band. Returns True only when the report is
    byte-exactly the sealed one.
    """
    try:
        if not isinstance(envelope, dict):
            return False
        report = envelope.get("report")
        signing = envelope.get("signing")
        if not isinstance(report, dict) or not isinstance(signing, dict):
            return False
        if report.get("kind") != "PolicyReport":
            return False
        if signing.get("scheme") != "ed25519":
            return False
        if signing.get("domain") != SIGN_DOMAIN_STR:
            return False
        if not isinstance(public_key, (bytes, bytearray)) \
                or len(public_key) != 32:
            return False
        sig = bytes.fromhex(signing.get("signature_hex", ""))
        body = _canonical(report)
        msg = SIGN_DOMAIN + _sha256_hex(body).encode("ascii")
        return bool(_ed25519.verify(bytes(public_key), msg, sig))
    except Exception:
        return False


def emit_policy_report(ledger, *, policy_name, signer=None, out_dir=None,
                       window_start=None, window_end=None,
                       policy_version=None, source=DEFAULT_SOURCE):
    """Export seam: build, seal, and write one signed report artifact.

    One artifact per audit window. ``out_dir`` defaults to the current
    directory. Returns the artifact path. Fail-closed when no signer
    is available (explicit ``signer`` or the deployment anchor key).
    """
    if signer is None:
        signer = _resolve_operator_signer()
    report = build_report(
        ledger, policy_name=policy_name, source=source,
        policy_version=policy_version, window_start=window_start,
        window_end=window_end)
    envelope = seal_report(report, signer)
    import pathlib
    target = pathlib.Path(out_dir) if out_dir else pathlib.Path(".")
    stamp = ("" if window_end is None
             else "-%d" % int(window_end))
    path = target / ("policy-report-%s%s.json" % (policy_name, stamp))
    path.write_bytes(json.dumps(
        envelope, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return str(path)
