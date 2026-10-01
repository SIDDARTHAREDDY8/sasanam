"""Evidence-ingest gate: the Kyverno-verifyImages watch for evidence bundles.

The wave-270 evidence-bundle v2 trusts producer authorization at ISSUANCE.
The INGEST side -- a bundle arriving at the consumer (pushed to an OCI
registry, handed over as a file) -- has no policy gate. This module is
the admission-time verify-analog: before a received evidence bundle is
trusted, the gate re-verifies

  (a) the bundle's signature attestation against the consumer's
      registered transparency log (inclusion proof + checkpoint);
  (b) the issuance attestation chain in the consumer's replicated audit
      log, including the producer-authorization claim (chain-then-binding
      through the evidence-cert ceremony);
  (c) the bundle's content digests against the revision binding;
  (d) a bounded-staleness rule: the bundle must not reference an
      audit-chain revision older than the configured horizon without an
      explicit freshness annotation.

Steals (pattern, clean-room; nothing copied): kyverno/kyverno @
``1c002d57`` (Apache-2.0) -- the verifyImages admission split
(``ValidationFailureAction``: ``Enforce`` blocks the request, ``Audit``
records it without blocking), the background-scan loop (per-resource
ephemeral reports overwritten in place, ``last-scan-time`` annotation,
forced-rescan interval, partial reconcile on unchanged policy
versions), and the two-tier pipeline split (ephemeral per-subject
scans; aggregation stays operator state).

Kyverno traps NOT reproduced:

- No webhook ``FailurePolicy`` analogue. The enforce/audit mode is
  fixed at gate construction. There is no ambient override, no
  per-namespace downgrade, and no deployment-mode downgrade: the
  gate's own mode governs, always. A gate error in enforce mode is a
  deny, never a bypass.
- Scan staleness is bounded by the forced-rescan interval and every
  scan re-arms its next run. A persistently erroring scan is a loud
  ``ingest-scan-error`` report, never a "stale pass".
- Scan reports and drift events are OPERATOR STATE: mutable,
  per-bundle, overwritten in place. They never enter the
  hash-chained audit log as evidence. Only admission verdicts are
  audit-log-shaped records (for the caller to chain).

Honest limits (on every verdict's ``out_of_scope``):

- Producer authorization is the evidence-cert ceremony (key<->producer
  via cert chain + approval/intent binding). The SLSA-shaped
  producer-authorization claim vocabulary is a sibling build; this
  gate does not mint or require it.
- The revision binding is only as good as its provider. The in-memory
  binding below is a test/deploy-local implementation; a production
  binding pins the producer's revision digests out-of-band.
- Transparency honesty inherits the provider's own ``honest_claims``
  (the in-process log disclaims durability and witnesses).
- The gate proves the bundle came from an authorized producer with
  bound, sufficiently-fresh revisions. It never proves the evidence
  content is true.
"""

import collections
import hashlib
import hmac
import json
import time

from . import evidence_bundle_v2 as _v2
from . import ed25519 as _ed25519
from .evidence_certs import EvidenceCertError as _EvidenceCertError

INGEST_FORMAT = "evidence-ingest.v2"
REPORT_FORMAT = "ingest-scan-report.v2"
FRESHNESS_FORMAT = "ingest-freshness-annotation.v1"

_HEX64 = "0123456789abcdef"


def _is_hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in _HEX64 for c in value)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


_HONEST_LIMITS = (
    "producer authorization = the evidence-cert ceremony "
    "(key<->producer via cert chain + approval/intent binding), not the "
    "SLSA-predicate claim vocabulary (sibling build); the revision "
    "binding is only as good as its provider; transparency honesty is "
    "the provider's own honest_claims; admitted evidence is not proven "
    "true.",
)


class EvidenceIngestGateError(Exception):
    """Coded, fail-closed ingest-gate error. ``code`` is a machine code
    in the ``ingest`` decision-code domain; ``detail`` is human text."""

    def __init__(self, code, detail):
        super(EvidenceIngestGateError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Revision binding provider interface
# ---------------------------------------------------------------------------

class RevisionBinding(object):
    """Content-digest <-> audit-chain-revision binding.

    The gate needs two answers: "is this content digest bound to this
    revision?" and "when was this revision registered?". The registry
    is deployment-owned; this interface is intentionally duck-typed so
    the production binding (pinned producer revision digests) can
    substitute the in-memory test binding without touching the gate.
    """

    provider_name = "abstract"

    def register_revision(self, revision_digest, content_digests,
                          registered_time=None):
        raise NotImplementedError

    def is_bound(self, revision_digest, content_digest):
        raise NotImplementedError

    def revision_time(self, revision_digest):
        """Registered unix time of ``revision_digest``. Raises
        EvidenceIngestGateError(``ingest-revision-unbound``) when the
        revision is unknown -- an unregistered revision is never
        silently treated as bound."""
        raise NotImplementedError


class InMemoryRevisionBinding(RevisionBinding):
    """Deployment-local binding: registered revisions with their
    content digests and registration times. Not durable across
    restarts -- the production binding would pin these out-of-band."""

    provider_name = "inmemory"

    def __init__(self, *, now=None):
        self._now = now or time.time
        self._revisions = {}  # revision_digest -> (set(digests), time)

    def register_revision(self, revision_digest, content_digests,
                          registered_time=None):
        if not _is_hex64(revision_digest):
            raise EvidenceIngestGateError(
                "ingest-malformed",
                "revision_digest must be 64 lowercase hex chars")
        digests = set()
        for d in (content_digests or []):
            if not _is_hex64(d):
                raise EvidenceIngestGateError(
                    "ingest-malformed",
                    "content digest must be 64 lowercase hex chars")
            digests.add(d)
        when = registered_time if registered_time is not None \
            else int(self._now())
        self._revisions[revision_digest] = (digests, when)

    def is_bound(self, revision_digest, content_digest):
        entry = self._revisions.get(revision_digest)
        return entry is not None and content_digest in entry[0]

    def revision_time(self, revision_digest):
        entry = self._revisions.get(revision_digest)
        if entry is None:
            raise EvidenceIngestGateError(
                "ingest-revision-unbound",
                "revision %s is not registered in the binding"
                % (revision_digest[:16],))
        return entry[1]


# ---------------------------------------------------------------------------
# Freshness annotations
# ---------------------------------------------------------------------------

def make_freshness_annotation(*, revision_digest, bundle_id, issuer_seed,
                              annotated_time=None):
    """Mint a freshness annotation: the deployment issuer attests that
    ``revision_digest`` is still the fresh revision of record for
    ``bundle_id`` at ``annotated_time``. Signed Ed25519 over the
    canonical annotation body. Never ambient randomness: the caller
    supplies the issuer seed (the gate's deployment key)."""
    if not _is_hex64(revision_digest):
        raise EvidenceIngestGateError(
            "ingest-malformed",
            "revision_digest must be 64 lowercase hex chars")
    if not isinstance(bundle_id, str) or not bundle_id:
        raise EvidenceIngestGateError(
            "ingest-malformed", "bundle_id must be a non-empty string")
    if not isinstance(issuer_seed, (bytes, bytearray)) \
            or len(issuer_seed) != 32:
        raise EvidenceIngestGateError(
            "ingest-malformed", "issuer_seed must be 32 bytes")
    body = {"format": FRESHNESS_FORMAT,
            "revision_digest": revision_digest,
            "bundle_id": bundle_id,
            "annotated_time": annotated_time}
    sig = _ed25519.sign(bytes(issuer_seed), _canonical(body))
    return {"format": FRESHNESS_FORMAT,
            "body": body,
            "issuer_pub": _ed25519.publickey(bytes(issuer_seed)).hex(),
            "signature": sig.hex()}


def _verify_freshness_annotation(annotation, *, revision_digest, bundle_id,
                                 issuer_pub, now, ttl_s):
    """Verify a freshness annotation against the policy. Fail-closed:
    any malformed/forged/expired/mismatched annotation is
    ``ingest-freshness-invalid``."""
    if not isinstance(annotation, dict) \
            or annotation.get("format") != FRESHNESS_FORMAT:
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation missing or wrong format")
    body = annotation.get("body")
    if not isinstance(body, dict):
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation has no body")
    if body.get("revision_digest") != revision_digest:
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation names a different revision")
    if body.get("bundle_id") != bundle_id:
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation names a different bundle")
    announced = body.get("annotated_time")
    if not isinstance(announced, int):
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation has no integer annotated_time")
    if announced > now:
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation is from the future")
    if now - announced > ttl_s:
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation is older than the annotation TTL")
    try:
        sig = bytes.fromhex(annotation.get("signature", ""))
        ann_pub = bytes.fromhex(annotation.get("issuer_pub", ""))
    except (ValueError, TypeError):
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation has undecodable signature/key")
    if len(sig) != 64 or len(ann_pub) != 32:
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation has bad signature/key lengths")
    if not hmac.compare_digest(ann_pub, issuer_pub):
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation is not from the deployment issuer")
    # wave-243 lesson: verify() returns exact bool -- never ignored.
    if _ed25519.verify(ann_pub, _canonical(body), sig) is not True:
        raise EvidenceIngestGateError(
            "ingest-freshness-invalid",
            "freshness annotation signature does not verify")
    return True


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class IngestPolicy(object):
    """Frozen admission policy. ``mode`` is 'enforce' (deny blocks) or
    'audit' (a would-deny is recorded, never blocks -- Kyverno's
    audit-vs-enforce split). There is deliberately NO ambient override:
    the mode here governs, always (the Kyverno webhook-FailurePolicy /
    per-namespace-override trap is not reproduced)."""

    def __init__(self, *, mode="enforce", max_staleness_seconds=86400,
                 force_rescan_interval_s=3600,
                 freshness_annotation_ttl_s=3600, freshness_issuer_pub,
                 policy_version="ingest-policy/v1"):
        if mode not in ("enforce", "audit"):
            raise EvidenceIngestGateError(
                "ingest-malformed",
                "policy mode must be 'enforce' or 'audit'")
        if not isinstance(freshness_issuer_pub, (bytes, bytearray)) \
                or len(freshness_issuer_pub) != 32:
            raise EvidenceIngestGateError(
                "ingest-malformed",
                "freshness_issuer_pub must be 32 bytes")
        self.mode = mode
        self.max_staleness_seconds = int(max_staleness_seconds)
        self.force_rescan_interval_s = int(force_rescan_interval_s)
        self.freshness_annotation_ttl_s = int(
            freshness_annotation_ttl_s)
        self.freshness_issuer_pub = bytes(freshness_issuer_pub)
        self.policy_version = policy_version

    def describe(self):
        return {"mode": self.mode,
                "max_staleness_seconds": self.max_staleness_seconds,
                "force_rescan_interval_s": self.force_rescan_interval_s,
                "freshness_annotation_ttl_s":
                    self.freshness_annotation_ttl_s,
                "policy_version": self.policy_version}


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

class IngestGate(object):
    """Admission + background-scan gate for received evidence bundles.

    ``transparency_log`` is the consumer's registered transparency log
    (the v2 provider interface); ``audit_log_path`` is the consumer's
    replicated producer audit log; ``ca_public_key`` is the trusted
    evidence CA key; ``revision_binding`` answers content<->revision
    binding. All explicit, none ambient.
    """

    def __init__(self, *, policy, transparency_log, audit_log_path,
                 ca_public_key, revision_binding, now=None):
        if not isinstance(policy, IngestPolicy):
            raise EvidenceIngestGateError(
                "ingest-malformed", "policy must be an IngestPolicy")
        self._policy = policy
        self._log = transparency_log
        self._audit_log_path = audit_log_path
        self._ca_public_key = bytes(ca_public_key)
        self._binding = revision_binding
        self._now = now or time.time
        self._admissions = {}   # bundle_id -> admission record
        self._reports = {}      # bundle_id -> ephemeral scan report
        self._drift_events = collections.deque(maxlen=1024)
        self._drift_seq = 0

    # -- introspection -------------------------------------------------

    @property
    def policy(self):
        return self._policy

    def set_policy(self, policy):
        """Explicit policy switch: a recorded event, never an ambient
        downgrade. Returns the switch record; the next scan re-arms
        every admitted bundle (policy_version changed)."""
        if not isinstance(policy, IngestPolicy):
            raise EvidenceIngestGateError(
                "ingest-malformed", "policy must be an IngestPolicy")
        old = self._policy.policy_version
        self._policy = policy
        return {"event": "ingest-policy-switched",
                "from": old, "to": policy.policy_version,
                "switched_at": int(self._now())}

    def drift_events(self):
        """Bounded operator-state drift log (NOT audit evidence)."""
        return list(self._drift_events)

    def scan_report(self, bundle_id):
        """The ephemeral per-bundle report (overwritten in place by
        scan(); operator state, not evidence)."""
        return self._reports.get(bundle_id)

    # -- admission -----------------------------------------------------

    def _evidence_shape(self, submission):
        if not isinstance(submission, dict) \
                or submission.get("kind") != \
                _v2.SUBMISSION_FORMAT:
            raise EvidenceIngestGateError(
                "ingest-malformed",
                "submission must be an %s record"
                % _v2.SUBMISSION_FORMAT)
        sealed = submission.get("sealed")
        receipt = submission.get("transparency_receipt")
        if not isinstance(sealed, dict) or not isinstance(receipt, dict):
            raise EvidenceIngestGateError(
                "ingest-malformed",
                "submission must carry sealed and transparency_receipt")
        return sealed, receipt

    def _check_transparency(self, *, submission, receipt):
        """Step (a): the signature attestation against the consumer's
        registered transparency log. Recomputes inclusion + checkpoint
        against OUR log handle -- a receipt pointing at a different
        log is refused, never trusted."""
        artifact_digest = submission["sealed"]["artifact"]["artifact_digest"]
        checkpoint = {"log_id": receipt.get("log_id"),
                      "tree_size": receipt.get("tree_size"),
                      "root": receipt.get("root"),
                      "integrated_time": receipt.get("integrated_time")}
        try:
            self._log.verify_checkpoint(checkpoint)
            self._log.verify_inclusion(
                artifact_digest, receipt.get("inclusion_proof"),
                checkpoint)
        except _v2.EvidenceBundleV2Error as e:
            raise EvidenceIngestGateError(
                "ingest-signature-unverified",
                "transparency verification failed (%s): %s"
                % (e.code, e.detail))
        except Exception as e:  # noqa: BLE001 -- fail closed
            raise EvidenceIngestGateError(
                "ingest-signature-unverified",
                "transparency verification errored: %r" % (e,))
        return {"tree_size": checkpoint["tree_size"],
                "log_id": checkpoint["log_id"]}

    def _check_issuance_and_producer(self, *, sealed, verify_time):
        """Step (b): re-verify the three-artifact split, the
        issuance-attestation join against the replicated audit log,
        and the producer-authorization claim (the ceremony is re-run,
        never taken on trust). v2 codes are translated to the gate's
        own ingest-* vocabulary with the underlying code preserved."""
        try:
            verified = _v2.verify_sealed_bundle(
                sealed=sealed,
                audit_log_path=self._audit_log_path,
                ca_public_key=self._ca_public_key,
                verify_time=verify_time)
        except _v2.EvidenceBundleV2Error as e:
            code = e.code
            if code in ("evbundle-malformed",):
                raise EvidenceIngestGateError(
                    "ingest-malformed",
                    "sealed bundle malformed (%s): %s" % (code, e.detail))
            if code == "evbundle-issuance-unverifiable":
                raise EvidenceIngestGateError(
                    "ingest-issuance-unverifiable",
                    "issuance attestation missing/unverifiable (%s): %s"
                    % (code, e.detail))
            if code.startswith("evcert-"):
                raise EvidenceIngestGateError(
                    "ingest-producer-unauthorized",
                    "producer-authorization claim failed (%s): %s"
                    % (code, e.detail))
            raise EvidenceIngestGateError(
                "ingest-signature-unverified",
                "sealed-bundle verification failed (%s): %s"
                % (code, e.detail))
        except _EvidenceCertError as e:
            # verify_sealed_bundle re-runs the ceremony directly, so
            # raw evcert-* refusals surface unwrapped (documented v2
            # behavior: "certificate failures surface as evcert-*").
            raise EvidenceIngestGateError(
                "ingest-producer-unauthorized",
                "producer-authorization claim failed (%s): %s"
                % (e.code, e.detail))
        except Exception as e:  # noqa: BLE001 -- fail closed
            raise EvidenceIngestGateError(
                "ingest-signature-unverified",
                "sealed-bundle verification errored: %r" % (e,))
        return {"cert_digest": verified["cert_digest"],
                "issuance_seq": verified["issuance_seq"]}

    def _check_revision_binding(self, *, sealed):
        """Step (c): content digests against the revision binding.
        The bundle body must declare ``audit_revision_digest`` and the
        artifact digest must be bound to it. Binding discipline: no
        revision, no admission."""
        body = sealed["artifact"].get("body") or {}
        revision = body.get("audit_revision_digest")
        artifact_digest = sealed["artifact"]["artifact_digest"]
        if not _is_hex64(revision):
            raise EvidenceIngestGateError(
                "ingest-revision-unbound",
                "bundle declares no audit_revision_digest: the gate "
                "cannot bind content to a revision")
        if not self._binding.is_bound(revision, artifact_digest):
            raise EvidenceIngestGateError(
                "ingest-revision-unbound",
                "artifact digest %s is not bound to revision %s"
                % (artifact_digest[:16], revision[:16]))
        return {"revision_digest": revision,
                "revision_time": self._binding.revision_time(revision)}

    def _check_staleness(self, *, binding_info, submission, bundle_id, now):
        """Step (d): bounded staleness. A revision older than the
        horizon is refused unless a valid freshness annotation names
        this bundle and revision."""
        revision_time = binding_info["revision_time"]
        age = now - revision_time
        if age <= self._policy.max_staleness_seconds:
            return {"revision_age_s": age, "freshness": "within-horizon"}
        annotation = submission.get("freshness_annotation")
        if annotation is None:
            raise EvidenceIngestGateError(
                "ingest-stale-revision",
                "bundle references revision %s registered %d seconds "
                "ago, beyond the %d-second staleness horizon, with no "
                "freshness annotation"
                % (binding_info["revision_digest"][:16], age,
                   self._policy.max_staleness_seconds))
        _verify_freshness_annotation(
            annotation,
            revision_digest=binding_info["revision_digest"],
            bundle_id=bundle_id,
            issuer_pub=self._policy.freshness_issuer_pub,
            now=now, ttl_s=self._policy.freshness_annotation_ttl_s)
        return {"revision_age_s": age,
                "freshness": "annotated",
                "annotation_time": annotation["body"]["annotated_time"]}

    def _verdict_record(self, *, bundle_id, verdict, code, blocked, now,
                        evidence=None, detail=None,
                        would_deny_detail=None):
        """One constructor for every verdict record (admit, deny,
        audit-recorded, scan-error) so a future field cannot be added
        to three sites and missed at the fourth."""
        record = {"format": INGEST_FORMAT,
                  "bundle_id": bundle_id,
                  "verdict": verdict,
                  "code": code,
                  "blocked": blocked,
                  "policy_version": self._policy.policy_version,
                  "evaluated_at": now,
                  "out_of_scope": _HONEST_LIMITS}
        if evidence is not None:
            record["evidence"] = evidence
        if detail is not None:
            record["detail"] = detail
        if would_deny_detail is not None:
            record["would_deny_detail"] = would_deny_detail
        return record

    def evaluate(self, *, bundle_id, submission, verify_time, now=None):
        """Re-verify a received submission against the CURRENT policy.
        Pure: never stores. Returns the verdict record. In enforce
        mode a failure is a deny verdict (the caller blocks); in audit
        mode a would-deny becomes 'audit-recorded' (never blocks).

        ``evaluate`` never raises on gate discipline: unexpected
        internals are a deny in enforce mode / a recorded error in
        audit mode (the Kyverno FailurePolicy trap is not reproduced).
        """
        now = int(now if now is not None else self._now())
        deny_code = deny_detail = evidence = None
        try:
            sealed, receipt = self._evidence_shape(submission)
            transparency = self._check_transparency(
                submission=submission, receipt=receipt)
            issuance = self._check_issuance_and_producer(
                sealed=sealed, verify_time=verify_time)
            binding_info = self._check_revision_binding(sealed=sealed)
            staleness = self._check_staleness(
                binding_info=binding_info, submission=submission,
                bundle_id=bundle_id, now=now)
            evidence = {"transparency": transparency,
                        "issuance": issuance,
                        "revision": binding_info,
                        "staleness": staleness}
        except EvidenceIngestGateError as e:
            deny_code, deny_detail = e.code, e.detail
        except Exception as e:  # noqa: BLE001 -- deny, never raise
            deny_code, deny_detail = ("ingest-malformed",
                                      "ingest gate internal error: %r"
                                      % (e,))
        if deny_code is None:
            return self._verdict_record(
                bundle_id=bundle_id, verdict="admit",
                code="ingest-admit", blocked=False, now=now,
                evidence=evidence)
        if self._policy.mode == "audit":
            return self._verdict_record(
                bundle_id=bundle_id, verdict="audit-recorded",
                code=deny_code, blocked=False, now=now,
                would_deny_detail=deny_detail)
        return self._verdict_record(
            bundle_id=bundle_id, verdict="deny", code=deny_code,
            blocked=True, now=now, detail=deny_detail)

    def admit(self, *, bundle_id, submission, verify_time, now=None):
        """Evaluate and, in enforce mode, refuse to store denials; in
        audit mode, record everything. Stores the admission record and
        the first ephemeral scan report."""
        verdict = self.evaluate(bundle_id=bundle_id,
                                submission=submission,
                                verify_time=verify_time, now=now)
        if verdict["blocked"]:
            return verdict
        try:
            digest = hashlib.sha256(_canonical(submission)).hexdigest()
        except Exception:  # noqa: BLE001
            digest = None
        record = {"bundle_id": bundle_id,
                  "submission_digest": digest,
                  "_submission": submission,
                  "verdict": verdict,
                  "admitted_at": verdict["evaluated_at"],
                  "policy_version": verdict["policy_version"]}
        self._admissions[bundle_id] = record
        self._reports[bundle_id] = self._make_report(
            bundle_id, record, rescan_due=False)
        return verdict

    # -- background scan ------------------------------------------------

    def _make_report(self, bundle_id, record, *, rescan_due,
                     previous=None):
        verdict = record["verdict"]
        # Drift is code-based, not verdict-string-based: in audit mode
        # a would-deny surfaces as "audit-recorded" (never "deny"),
        # but it is still "would now be refused" -- the Kyverno
        # audit/watch posture. A previously admitted bundle (code
        # ingest-admit) whose re-evaluation yields any other code has
        # drifted.
        drift = (bool(previous)
                 and previous.get("code") == "ingest-admit"
                 and verdict["code"] != "ingest-admit")
        return {"format": REPORT_FORMAT,
                "bundle_id": bundle_id,
                "verdict": verdict["verdict"],
                "code": verdict["code"],
                "last_scan_time": verdict["evaluated_at"],
                "policy_version": verdict["policy_version"],
                "submission_digest": record["submission_digest"],
                "drift": drift,
                "rescan_due": rescan_due,
                "note": "ephemeral operator state: overwritten in place, "
                        "never audit evidence"}

    def scan(self, *, now=None, verify_time=None):
        """Background scan (Kyverno loop, clean-room): re-evaluate
        every admitted bundle against the CURRENT policy, overwrite
        each per-bundle report in place, and emit a drift event when a
        previously admitted bundle would now be DENIED.

        Reconcile discipline: a bundle is re-evaluated when the policy
        version changed, when the submission bytes changed, or when
        the forced-rescan interval elapsed since last_scan_time
        (partial reconcile -- unchanged policies keep their verdict).
        Scan never raises on a per-bundle error: that is a loud
        error verdict in the report, never a stale pass. Scan never
        blocks admission: admission records are not touched.
        """
        now = int(now if now is not None else self._now())
        scanned = reevaluated = drifted = 0
        for bundle_id, record in list(self._admissions.items()):
            scanned += 1
            previous = self._reports.get(bundle_id)
            submission = record.get("_submission")
            current_digest = (hashlib.sha256(
                _canonical(submission)).hexdigest()
                if submission is not None else None)
            changed = (
                previous is None
                or record["policy_version"] != self._policy.policy_version
                or previous.get("policy_version")
                != self._policy.policy_version
                or (current_digest is not None
                    and current_digest != record["submission_digest"])
            )
            interval = self._policy.force_rescan_interval_s
            stale = previous is None or (
                previous.get("last_scan_time") is not None
                and now - previous["last_scan_time"] >= interval
            )
            if not (changed or stale):
                # Partial reconcile: keep the verdict, re-arm the scan.
                self._reports[bundle_id] = self._make_report(
                    bundle_id, record, rescan_due=False,
                    previous=previous)
                continue
            reevaluated += 1
            if submission is None:
                new_verdict = self._verdict_record(
                    bundle_id=bundle_id, verdict="deny",
                    code="ingest-scan-error", blocked=False, now=now,
                    detail="admission record lost its submission bytes; "
                           "cannot re-verify -- loud error, never a "
                           "stale pass")
            else:
                new_verdict = self.evaluate(
                    bundle_id=bundle_id, submission=submission,
                    verify_time=verify_time
                    if verify_time is not None else now,
                    now=now)
                # Scan context never blocks: it reports what enforce
                # WOULD decide today (the audit-scanner analog).
                new_verdict = dict(new_verdict)
                new_verdict["blocked"] = False
            new_record = {"bundle_id": bundle_id,
                          "submission_digest":
                              (current_digest
                               if current_digest is not None
                               else record["submission_digest"]),
                          "_submission": submission,
                          "verdict": new_verdict,
                          "admitted_at": record["admitted_at"],
                          "policy_version": new_verdict["policy_version"]}
            report = self._make_report(bundle_id, new_record,
                                       rescan_due=False,
                                       previous=previous)
            self._reports[bundle_id] = report
            if report["drift"]:
                drifted += 1
                self._drift_seq += 1
                self._drift_events.append(
                    {"seq": self._drift_seq,
                     "bundle_id": bundle_id,
                     "previous_verdict":
                         (previous or {}).get("verdict"),
                     "previous_code": (previous or {}).get("code"),
                     "current_code": new_verdict["code"],
                     "detected_at": now,
                     "policy_version": self._policy.policy_version,
                     "note": "operator state: drift dashboard, not "
                             "audit evidence"})
        return {"scanned": scanned, "reevaluated": reevaluated,
                "drifted": drifted, "scanned_at": now,
                "policy_version": self._policy.policy_version}
