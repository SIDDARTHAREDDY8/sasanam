"""Policy CI: single declared policy source with derived deployment artifacts.

Wave-297 lane 3. Stdlib only. $0 spend. Synthetic/local testing.

STEAL (mechanism only, Apache-2.0, no upstream source vendored) from
plexsystems/konstraint (read 2026-10-02, wave-294 prospecting): the
**single-source / derived-artifact** discipline -- the policy AUTHOR writes
one declared source; every deployment artifact is DERIVED from it, and a
hand-edited artifact is refused at load. Konstraint enforces this via
OPA/Rego tooling; here it is stdlib-only on the authored-policy schema.

Three mechanisms:

1. **Derived artifacts, not authored ones.** ``derive(source)`` compiles the
   declared policy source (the wave-253 authored filters/actions schema in
   ``gov.policy_authoring`` -- reused, no new language) ONCE through
   ``compile_authoring`` and emits a FROZEN artifact: the compiled native
   policy plus a manifest mapping every derived file to its sha256 digest.
   ``load_artifact`` recomputes the digests; a hand-edited derived file
   refuses coded ``policy-ci-derived-tampered``. An artifact derived from a
   DIFFERENT source (stale after a source change) also refuses -- the
   artifact's ``source_digest`` must match the source being loaded.

2. **Mandatory companions.** Every policy change ships with a change note
   and a declared probe battery; ``check(source, artifact, ...)`` fails
   closed coded ``policy-ci-companion-missing`` when either is absent.
   (The companions are DECLARED here; running the battery is the
   deployment's job -- the CI guarantees the battery exists, not its
   verdicts.)

3. **Dryrun-then-enforce rollout.** ``begin_rollout`` opens a ``dryrun``
   state for a declared observation window; ``observe`` logs decisions
   (logged, never applied); ``promote`` moves to ``enforcing`` only when
   the window has elapsed AND a signed dryrun report verifies
   (``ed25519.verify`` checked ``is True``, wave-243). Skipping dryrun --
   no dryrun state, no report, or window not elapsed -- refuses coded
   ``policy-ci-dryrun-skipped``. The state machine is immutable
   (MappingProxyType; transitions return new records) and fail-closed:
   an unknown state refuses coded ``policy-ci-invalid``.

Wiring (additive): ``gov.policy_authoring.compile_authoring`` accepts an
optional ``artifact=`` keyword; when given, the derived artifact is
verified against the source at load time via
``verify_artifact_for_source`` (lazy import -- no import cycle; default
``None`` leaves existing callers untouched). All refusals are LOUD:
coded :class:`PolicyCIError`, never silent, never a vacuous pass.
"""

from __future__ import annotations

import hashlib
import json
import time
from types import MappingProxyType

from . import ed25519 as _ed25519
from .policy_authoring import (
    compile_authoring as _compile_authoring,
    AuthoringError as _AuthoringError,
)

__all__ = [
    "PolicyCIError",
    "DERIVED_TAMPERED",
    "COMPANION_MISSING",
    "DRYRUN_SKIPPED",
    "INVALID",
    "SOURCE_MAX_BYTES",
    "derive",
    "load_artifact",
    "check",
    "verify_artifact_for_source",
    "begin_rollout",
    "observe",
    "dryrun_report",
    "sign_report",
    "promote",
    "status",
    "artifact_digest",
]

#: Decision-code vocabulary (registered in gov/decision_codes.py).
DERIVED_TAMPERED = "policy-ci-derived-tampered"
COMPANION_MISSING = "policy-ci-companion-missing"
DRYRUN_SKIPPED = "policy-ci-dryrun-skipped"
INVALID = "policy-ci-invalid"

ARTIFACT_FORMAT = "sasanam-policy-artifact/v1"
ROLLOUT_FORMAT = "sasanam-policy-rollout/v1"

#: Bounded inputs (fail-closed above these; F351-class sweep covers them).
SOURCE_MAX_BYTES = 256 * 1024
DERIVED_MAX_BYTES = 256 * 1024
NOTE_MAX_CHARS = 4 * 1024
AUTHOR_MAX_CHARS = 256
PROBE_MAX_COUNT = 256
PROBE_MAX_CHARS = 256
DECISIONS_MAX_COUNT = 10_000


class PolicyCIError(Exception):
    """LOUD coded refusal for the policy-CI seam."""

    def __init__(self, message, code=None):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.detail = message


def _canonical(obj):
    """Canonical JSON bytes. Circular/unserializable data refuses coded."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyCIError("not canonical-JSON-serializable: %s" % (exc,),
                            code=INVALID)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _freeze(obj):
    if isinstance(obj, MappingProxyType):
        return obj
    if isinstance(obj, dict):
        return MappingProxyType({k: _freeze(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_freeze(v) for v in obj)
    return obj


def _source_digest(source_text: str) -> str:
    """Stable digest of the declared source (normalized LF, no trailing
    whitespace-only drift)."""
    if not isinstance(source_text, str):
        raise PolicyCIError(
            "policy source must be str, got %s" % type(source_text).__name__,
            code=INVALID)
    if not source_text.strip():
        raise PolicyCIError("policy source is empty", code=INVALID)
    raw = source_text.encode("utf-8")
    if len(raw) > SOURCE_MAX_BYTES:
        raise PolicyCIError(
            "policy source exceeds %d bytes" % SOURCE_MAX_BYTES, code=INVALID)
    normalized = source_text.replace("\r\n", "\n").strip() + "\n"
    return _sha256(normalized.encode("utf-8"))


def _check_companions(author, change_note, probes):
    if not isinstance(author, str) or not author.strip():
        raise PolicyCIError("change ships without an author", code=COMPANION_MISSING)
    if len(author) > AUTHOR_MAX_CHARS:
        raise PolicyCIError("author exceeds %d chars" % AUTHOR_MAX_CHARS,
                            code=COMPANION_MISSING)
    if not isinstance(change_note, str) or not change_note.strip():
        raise PolicyCIError(
            "change ships without a change note", code=COMPANION_MISSING)
    if len(change_note) > NOTE_MAX_CHARS:
        raise PolicyCIError(
            "change note exceeds %d chars" % NOTE_MAX_CHARS,
            code=COMPANION_MISSING)
    if not isinstance(probes, (list, tuple)) or not probes:
        raise PolicyCIError(
            "change ships without a declared probe battery",
            code=COMPANION_MISSING)
    if len(probes) > PROBE_MAX_COUNT:
        raise PolicyCIError("probe battery exceeds %d probes" % PROBE_MAX_COUNT,
                            code=COMPANION_MISSING)
    for probe in probes:
        if not isinstance(probe, str) or not probe.strip():
            raise PolicyCIError("probe battery has a blank probe entry",
                                code=COMPANION_MISSING)
        if len(probe) > PROBE_MAX_CHARS:
            raise PolicyCIError("probe entry exceeds %d chars" % PROBE_MAX_CHARS,
                                code=COMPANION_MISSING)


def _compile_source(source_text):
    try:
        return _compile_authoring(source_text)
    except _AuthoringError as exc:
        raise PolicyCIError(
            "policy source does not compile (%s)" % (exc.detail,),
            code=INVALID)


def derive(source_text, *, author="", change_note="", probes=()):
    """Compile the declared source ONCE and emit the frozen derived
    artifact: {format, source_digest, derived: {name: bytes-text},
    digests: {name: sha256}, author, change_note, probes}.

    Companions are RECORDED here and ENFORCED by ``check``.
    """
    digest = _source_digest(source_text)
    compiled = _compile_source(source_text)
    native = compiled.native_text
    if len(native.encode("utf-8")) > DERIVED_MAX_BYTES:
        raise PolicyCIError("compiled policy exceeds %d bytes" % DERIVED_MAX_BYTES,
                            code=INVALID)
    derived = {"policy.native.yaml": native}
    manifest = {
        "format": "sasanam-policy-manifest/v1",
        "source_digest": digest,
        "files": {},
        "author": author if isinstance(author, str) else "",
        "change_note": change_note if isinstance(change_note, str) else "",
        "probes": [p for p in probes] if isinstance(probes, (list, tuple)) else [],
    }
    for name, text in derived.items():
        manifest["files"][name] = _sha256(text.encode("utf-8"))
    manifest_bytes = _canonical(manifest)
    derived["policy.manifest.json"] = manifest_bytes.decode("utf-8")
    digests = {name: _sha256(text.encode("utf-8"))
               for name, text in derived.items()}
    artifact = {
        "format": ARTIFACT_FORMAT,
        "source_digest": digest,
        "derived": derived,
        "digests": digests,
        "author": manifest["author"],
        "change_note": manifest["change_note"],
        "probes": manifest["probes"],
    }
    return _freeze(artifact)


def artifact_digest(artifact) -> str:
    """Stable pin over the verified artifact (for rollout records)."""
    if not isinstance(artifact, MappingProxyType):
        raise PolicyCIError("artifact is not a verified frozen artifact",
                            code=INVALID)
    return _sha256(_canonical({
        "source_digest": artifact.get("source_digest"),
        "digests": dict(artifact.get("digests") or {}),
    }))


def load_artifact(obj):
    """Verify a derived artifact's internal digests; return it frozen.

    Hand-edited derived files refuse coded ``policy-ci-derived-tampered``.
    """
    if isinstance(obj, MappingProxyType):
        obj = dict(obj)
    if not isinstance(obj, dict):
        raise PolicyCIError(
            "artifact must be a mapping, got %s" % type(obj).__name__,
            code=INVALID)
    if obj.get("format") != ARTIFACT_FORMAT:
        raise PolicyCIError("unknown artifact format %r" % (obj.get("format"),),
                            code=INVALID)
    derived = obj.get("derived")
    digests = obj.get("digests")
    if not isinstance(derived, (dict, MappingProxyType)) or not isinstance(
            digests, (dict, MappingProxyType)):
        raise PolicyCIError("artifact missing derived files or digest manifest",
                            code=DERIVED_TAMPERED)
    for name in list(derived):
        text = derived[name]
        if not isinstance(text, str):
            raise PolicyCIError("derived file %r is not text" % (name,),
                                code=DERIVED_TAMPERED)
        if len(text.encode("utf-8")) > DERIVED_MAX_BYTES:
            raise PolicyCIError("derived file %r exceeds bound" % (name,),
                                code=DERIVED_TAMPERED)
        want = digests.get(name)
        if want != _sha256(text.encode("utf-8")):
            raise PolicyCIError(
                "derived file %r digest mismatch (hand-edited artifact)"
                % (name,), code=DERIVED_TAMPERED)
    # F372: the derived file set is CLOSED. derive() emits exactly the
    # files recorded in the embedded manifest (the manifest lists every
    # file except itself, by construction). An added file -- even with a
    # consistent digests entry -- is not in the closed set and refuses.
    manifest_text = derived.get("policy.manifest.json")
    try:
        manifest = (json.loads(manifest_text)
                    if isinstance(manifest_text, str) else None)
    except ValueError:
        manifest = None
    if (not isinstance(manifest, dict)
            or manifest.get("format") != "sasanam-policy-manifest/v1"):
        raise PolicyCIError("artifact manifest missing or malformed",
                            code=DERIVED_TAMPERED)
    if manifest.get("source_digest") != obj.get("source_digest"):
        raise PolicyCIError(
            "artifact manifest disagrees with artifact source_digest",
            code=DERIVED_TAMPERED)
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, dict):
        raise PolicyCIError("artifact manifest files map malformed",
                            code=DERIVED_TAMPERED)
    closed = set(manifest_files) | {"policy.manifest.json"}
    if set(derived.keys()) != closed:
        raise PolicyCIError(
            "derived file set is not closed (expected %s, got %s)"
            % (sorted(closed), sorted(derived.keys())),
            code=DERIVED_TAMPERED)
    for name, want in manifest_files.items():
        if digests.get(name) != want:
            raise PolicyCIError(
                "manifest digest for %r disagrees with artifact digests"
                % (name,), code=DERIVED_TAMPERED)
    if not obj.get("source_digest"):
        raise PolicyCIError("artifact missing source_digest",
                            code=DERIVED_TAMPERED)
    return _freeze(obj)


def verify_artifact_for_source(artifact, source_text):
    """The load-path check: the artifact must be internally consistent AND
    derived from THIS source. Stale artifacts (source changed after derive)
    refuse coded ``policy-ci-derived-tampered``."""
    verified = load_artifact(artifact)
    if verified["source_digest"] != _source_digest(source_text):
        raise PolicyCIError(
            "artifact is stale for this source (source changed after derive)",
            code=DERIVED_TAMPERED)
    return verified


def check(source_text, artifact, *, author=None, change_note=None, probes=None):
    """CI gate for a policy change: source compiles, companions present,
    artifact fresh and untampered. Fail-closed, coded, in that order."""
    _source_digest(source_text)  # raises INVALID on malformed source
    _compile_source(source_text)
    verified = load_artifact(artifact)
    _check_companions(
        author if author is not None else verified.get("author"),
        change_note if change_note is not None else verified.get("change_note"),
        probes if probes is not None else verified.get("probes"))
    if verified["source_digest"] != _source_digest(source_text):
        raise PolicyCIError(
            "artifact is stale for this source (source changed after derive)",
            code=DERIVED_TAMPERED)
    return verified


# ------------------------------------------------------------------
# Dryrun-then-enforce rollout state machine
# ------------------------------------------------------------------

def _rollout_record(**fields):
    return _freeze(dict({"format": ROLLOUT_FORMAT}, **fields))


def begin_rollout(artifact, *, observation_seconds, now=None):
    """Open a dryrun rollout: decisions are logged, none applied."""
    verified = load_artifact(artifact)
    if isinstance(observation_seconds, bool) or not isinstance(
            observation_seconds, int) or observation_seconds <= 0:
        raise PolicyCIError(
            "observation_seconds must be a positive int", code=INVALID)
    started = time.time() if now is None else now
    if not isinstance(started, (int, float)) or isinstance(started, bool):
        raise PolicyCIError("now must be a number", code=INVALID)
    return _rollout_record(
        state="dryrun",
        artifact_digest=artifact_digest(verified),
        source_digest=verified["source_digest"],
        observation_seconds=observation_seconds,
        started_at=float(started),
        decisions_digest=_sha256(b""),
        decisions_count=0,
    )


def _require_rollout(record):
    if not isinstance(record, MappingProxyType):
        raise PolicyCIError("not a rollout record", code=INVALID)
    if record.get("format") != ROLLOUT_FORMAT:
        raise PolicyCIError("unknown rollout format %r" % (record.get("format"),),
                            code=INVALID)
    state = record.get("state")
    if state not in ("dryrun", "enforcing"):
        raise PolicyCIError("unknown rollout state %r" % (state,), code=INVALID)
    return state


def observe(record, decisions):
    """Log dryrun decisions (canonical, chained); applies NOTHING. Returns
    the new rollout record."""
    state = _require_rollout(record)
    if state != "dryrun":
        raise PolicyCIError("rollout is not in dryrun; refusing observation",
                            code=DRYRUN_SKIPPED)
    if not isinstance(decisions, (list, tuple)):
        raise PolicyCIError("decisions must be a list", code=INVALID)
    if len(decisions) > DECISIONS_MAX_COUNT:
        raise PolicyCIError("too many decisions in one observation",
                            code=INVALID)
    for decision in decisions:
        if not isinstance(decision, dict):
            raise PolicyCIError("decision entries must be mappings", code=INVALID)
    chained = _canonical({
        "prev": record["decisions_digest"],
        "decisions": [dict(d) for d in decisions],
    })
    new = dict(record)
    new["decisions_digest"] = _sha256(
        record["decisions_digest"].encode("utf-8") + chained)
    new["decisions_count"] = record["decisions_count"] + len(decisions)
    return _freeze(new)


def dryrun_report(record):
    """The canonical dryrun report bytes a promoter must sign."""
    state = _require_rollout(record)
    if state != "dryrun":
        raise PolicyCIError("rollout is not in dryrun; no dryrun report",
                            code=DRYRUN_SKIPPED)
    return _canonical({
        "format": "sasanam-policy-dryrun-report/v1",
        "artifact_digest": record["artifact_digest"],
        "source_digest": record["source_digest"],
        "observation_seconds": record["observation_seconds"],
        "started_at": record["started_at"],
        "decisions_digest": record["decisions_digest"],
        "decisions_count": record["decisions_count"],
    })


def sign_report(seed, record):
    """Sign the dryrun report with an Ed25519 seed (32 bytes)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise PolicyCIError("seed must be 32 bytes", code=INVALID)
    report = dryrun_report(record)
    return report, bytes(_ed25519.sign(bytes(seed), report))


def promote(record, *, report, signature, pubkey, now=None):
    """Promote dryrun -> enforcing. Requires the observation window
    elapsed AND a valid signature over THIS rollout's dryrun report.

    Skipping dryrun (no dryrun state / no report / window not elapsed)
    refuses coded ``policy-ci-dryrun-skipped``; a forged or mismatched
    report refuses coded ``policy-ci-invalid``.
    """
    state = _require_rollout(record)
    if state != "dryrun":
        raise PolicyCIError(
            "no dryrun in progress; dryrun cannot be skipped", code=DRYRUN_SKIPPED)
    if not isinstance(report, (bytes, bytearray)) or not report:
        raise PolicyCIError(
            "promotion requires the signed dryrun report", code=DRYRUN_SKIPPED)
    current = time.time() if now is None else now
    if not isinstance(current, (int, float)) or isinstance(current, bool):
        raise PolicyCIError("now must be a number", code=INVALID)
    if current - record["started_at"] < record["observation_seconds"]:
        raise PolicyCIError(
            "dryrun observation window has not elapsed", code=DRYRUN_SKIPPED)
    if bytes(report) != dryrun_report(record):
        raise PolicyCIError(
            "dryrun report does not match this rollout", code=INVALID)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise PolicyCIError("signature must be 64 bytes", code=INVALID)
    if _ed25519.verify(pubkey, bytes(report), bytes(signature)) is not True:
        raise PolicyCIError(
            "dryrun report signature does not verify", code=INVALID)
    new = dict(record)
    new["state"] = "enforcing"
    new["report_digest"] = _sha256(bytes(report))
    return _freeze(new)


def status(record):
    """Current rollout state; unknown records refuse fail-closed."""
    return _require_rollout(record)
