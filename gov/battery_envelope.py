"""Per-sample evidence envelope for adversarial battery runs.

PATTERN LINEAGE: UKGovernmentBEIS/inspect_ai (MIT, LICENSE bytes verified
by the wave-277 prospecting lane) -- the `.eval` log shape: per-sample
records (input, actions, raw outputs, verdict, metadata) + run header +
a published JSON schema + standalone replay. Re-implemented in stdlib
Python against our deterministic battery conventions; no inspect_ai code
is vendored here, only the envelope shape. Also incorporates the
terminal-bench two-sided oracle pattern (Apache-2.0): every sample
declares an ``oracle`` (``violating`` = golden attack case,
``clean`` = golden benign case) so a forged "all green" run is
structurally detectable.

This module is the *battery-run* evidence layer. It does not replace
:mod:`gov.offline_bundle` (audit-log evidence) or
:mod:`gov.evidence_envelope` (DSSE per-record signing for audit entries);
it covers the missing half of "sell evidence, not the engine": a battery
run that is self-describing, digest-sealed, and re-checkable by an
auditor WITHOUT our engine, via the standalone verifier at
``tools/envelope-verify`` (stdlib only).

Envelope (canonical JSON, sorted keys)::

    {
      "format": "battery-evidence-envelope",
      "schema_version": "1.0",
      "header": {
        "battery": "<battery module/file name>",
        "battery_version": "<battery-declared version>",
        "battery_digest": "<sha256 hex of the battery file bytes>",
        "engine_version": "<gov.__version__>",
        "git_sha": "<HEAD sha, env GOV_GIT_SHA, or 'unknown'>",
        "ran_at": "<UTC ISO-8601>",
        "deployment_mode": "<GOV_DEPLOYMENT_MODE>",
        "taxonomy_pin": <int>,
        "sample_count": <int>,
        "run_digest": "<sha256 hex>"
      },
      "samples": [
        {
          "sample_id": "<probe id>",
          "sample_seq": <int, 1-based>,
          "oracle": "violating" | "clean",
          "expected": "BREAK" | "HELD" | "ERROR",
          "verdict": "BREAK" | "HELD" | "ERROR",
          "note": "<what the probe did and saw>",
          "input_digest": "<sha256 of the probe input, optional>",
          "sample_digest": "<sha256 hex, hash-chained>"
        }, ...
      ]
    }

Integrity: each sample's ``sample_digest`` chains the previous digest
(audit-log style), and ``header.run_digest`` commits to the header plus
all sample digests. Tampering with any verdict, note, or oracle breaks
the chain. Forging a verdict *and* its expected value consistently is
caught by the oracle-consistency check: a ``violating`` oracle must
declare ``expected == "BREAK"`` and a ``clean`` oracle must declare
``expected == "HELD"`` -- the verifier re-derives expectations from the
oracle declarations, so a joint forgery still refuses.

Verdict strings are harness-level (like ``tools/offline-verify`` check
names), NOT taxonomy decision codes: no taxonomy entries are added by
this module, and the pin is untouched. Refusals carry ``.reason``.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

FORMAT = "battery-evidence-envelope"
SCHEMA_VERSION = "1.0"

#: Maximum samples verified in one envelope (fail-closed before any
#: digest work, mirroring gov/evidence_envelope.py's work cap).
MAX_SAMPLES = 10000

#: Maximum single-sample canonical bytes.
MAX_SAMPLE_BYTES = 1024 * 1024

_SAMPLE_DOMAIN = b"battery-envelope-sample/v1\x00"
_RUN_DOMAIN = b"battery-envelope-run/v1\x00"
_SAMPLE_GENESIS = "SAMPLE-GENESIS"

_VERDICTS = frozenset(("BREAK", "HELD", "ERROR"))
_ORACLES = frozenset(("violating", "clean"))

# oracle -> the only expected verdict it may declare
_ORACLE_EXPECTED = {"violating": "BREAK", "clean": "HELD"}


class BatteryEnvelopeError(Exception):
    """The envelope is malformed or fails verification (fail-closed).

    ``reason`` is a stable machine-readable refusal string (harness
    vocabulary, not a taxonomy code).
    """

    def __init__(self, reason, detail=""):
        msg = reason if not detail else "%s: %s" % (reason, detail)
        super().__init__(msg)
        self.reason = reason


def _refuse(reason, detail=""):
    raise BatteryEnvelopeError(reason, detail)


def _canonical(obj):
    """JCS-shaped canonical bytes (same form as gov/offline_bundle.py)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git_sha():
    """HEAD sha without spawning an in-repo git subprocess (standing
    supply-chain rule: batteries never run in-repo git)."""
    env = os.environ.get("GOV_GIT_SHA")
    if env:
        return env.strip() or "unknown"
    try:
        repo = os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))
        head_path = os.path.join(repo, ".git", "HEAD")
        with open(head_path, encoding="utf-8") as f:
            head = f.read().strip()
        if head.startswith("ref:"):
            ref_path = os.path.join(
                repo, ".git", *head[4:].strip().split("/"))
            with open(ref_path, encoding="utf-8") as f:
                return f.read().strip() or "unknown"
        if len(head) == 40:
            return head
    except (OSError, ValueError):
        pass
    return "unknown"


def _taxonomy_pin():
    """Live taxonomy literal count (raw source literals, not the
    deduped dict -- wave-260 lesson)."""
    import re
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "decision_codes.py"),
              encoding="utf-8") as f:
        src = f.read()
    return len(re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src))


# ---------------------------------------------------------------------------
# Emission.
# ---------------------------------------------------------------------------

class RunBuilder:
    """Incremental envelope builder for one battery run."""

    def __init__(self, battery, battery_version, battery_path=None):
        if not battery or not isinstance(battery, str):
            _refuse("envelope-bad-header", "battery name must be a "
                                           "non-empty string")
        if not battery_version or not isinstance(battery_version, str):
            _refuse("envelope-bad-header", "battery_version must be a "
                                           "non-empty string")
        self._battery = battery
        self._battery_version = battery_version
        if battery_path is not None:
            with open(battery_path, "rb") as f:
                self._battery_digest = hashlib.sha256(f.read()).hexdigest()
        else:
            self._battery_digest = "unknown"
        self._samples = []
        self._prev_digest = _SAMPLE_GENESIS

    def record(self, sample_id, *, oracle, expected, verdict, note,
               input_digest=None, metadata=None):
        """Append one probe-case evidence record.

        ``oracle``: "violating" (golden attack case) or "clean"
        (golden benign case). ``expected``/``verdict``: BREAK/HELD/ERROR.

        ``metadata``: optional extra JSON-canonicalizable mapping attached
        as the ``lang`` field (wave-280 battery language: the
        plugin/strategy/grader triple, so envelope rows stay
        machine-readable). It is digest-covered like every other field;
        ``None`` keeps the emitted shape byte-identical to before.
        """
        if not sample_id or not isinstance(sample_id, str):
            _refuse("envelope-bad-sample", "sample_id must be a "
                                           "non-empty string")
        if oracle not in _ORACLES:
            _refuse("envelope-bad-sample",
                    "oracle must be one of %s, got %r"
                    % (sorted(_ORACLES), oracle))
        if expected not in _VERDICTS:
            _refuse("envelope-bad-sample",
                    "expected must be one of %s, got %r"
                    % (sorted(_VERDICTS), expected))
        if verdict not in _VERDICTS:
            _refuse("envelope-bad-sample",
                    "verdict must be one of %s, got %r"
                    % (sorted(_VERDICTS), verdict))
        if _ORACLE_EXPECTED[oracle] != expected and expected != "ERROR":
            _refuse("envelope-bad-sample",
                    "oracle %r requires expected %r (or ERROR), got %r"
                    % (oracle, _ORACLE_EXPECTED[oracle], expected))
        if len(self._samples) >= MAX_SAMPLES:
            _refuse("envelope-too-many-samples",
                    "exceeds cap %d" % MAX_SAMPLES)
        sample = {
            "sample_id": sample_id,
            "sample_seq": len(self._samples) + 1,
            "oracle": oracle,
            "expected": expected,
            "verdict": verdict,
            "note": str(note),
        }
        if input_digest is not None:
            sample["input_digest"] = str(input_digest)
        if metadata is not None:
            if not isinstance(metadata, dict):
                _refuse("envelope-bad-sample",
                        "metadata must be a mapping")
            try:
                _canonical(metadata)
            except Exception as exc:
                _refuse("envelope-bad-sample",
                        "metadata not canonicalizable: %s" % exc)
            sample["lang"] = metadata
        body = _canonical(sample)
        if len(body) > MAX_SAMPLE_BYTES:
            _refuse("envelope-sample-too-large",
                    "%d bytes exceed cap %d"
                    % (len(body), MAX_SAMPLE_BYTES))
        digest = hashlib.sha256(
            _SAMPLE_DOMAIN
            + self._prev_digest.encode("utf-8") + b"\x00"
            + body).hexdigest()
        sample["sample_digest"] = digest
        self._prev_digest = digest
        self._samples.append(sample)
        return sample

    def seal(self):
        """Return the sealed envelope dict."""
        header = {
            "battery": self._battery,
            "battery_version": self._battery_version,
            "battery_digest": self._battery_digest,
            "engine_version": _engine_version(),
            "git_sha": _git_sha(),
            "ran_at": _utcnow(),
            "deployment_mode": os.environ.get(
                "GOV_DEPLOYMENT_MODE", "unset"),
            "taxonomy_pin": _taxonomy_pin(),
            "sample_count": len(self._samples),
        }
        digests = b"".join(
            s["sample_digest"].encode("utf-8") for s in self._samples)
        header["run_digest"] = hashlib.sha256(
            _RUN_DOMAIN + _canonical(header) + b"\x00" + digests
        ).hexdigest()
        return {
            "format": FORMAT,
            "schema_version": SCHEMA_VERSION,
            "header": header,
            "samples": list(self._samples),
        }


def _engine_version():
    try:
        from gov import __version__ as v
        return str(v)
    except Exception:  # noqa: BLE001
        return "unknown"


def emit_envelope(path, envelope):
    """Write a sealed envelope to ``path`` (canonical JSON)."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(_canonical(envelope).decode("utf-8") + "\n")
    return os.path.abspath(path)


def emit_for_probe_results(battery, battery_version, battery_path,
                           results, *, artifact_path, oracle_by_id):
    """Convenience emitter for batteries using the ``(pid, expected,
    verdict, ok, note)`` _RESULTS tuple shape (e.g.
    evals/w277_redteam_probes.py).

    ``oracle_by_id`` maps probe id -> "violating"|"clean". Probes with
    no oracle entry default to "clean" when expected is HELD and
    "violating" when expected is BREAK (the oracle contract requires
    the mapping to be exact for BREAK/HELD). ERROR probes default to
    "clean".
    """
    builder = RunBuilder(battery, battery_version,
                         battery_path=battery_path)
    for pid, expected, verdict, _ok, note in results:
        oracle = oracle_by_id.get(pid)
        if oracle is None:
            oracle = ("violating" if expected == "BREAK" else "clean")
        builder.record(pid, oracle=oracle, expected=expected,
                       verdict=verdict, note=note)
    envelope = builder.seal()
    return emit_envelope(artifact_path, envelope)


# ---------------------------------------------------------------------------
# Verification (in-repo).
# ---------------------------------------------------------------------------

def _require(cond, reason, detail=""):
    if not cond:
        _refuse(reason, detail)


def verify_envelope(envelope):
    """Verify a sealed envelope dict; returns the header on success.

    Checks (mirrored by tools/envelope-verify V1..V7):
      V1  format/schema known
      V2  run_digest recomputes over header + sample digests
      V3  every sample_digest recomputes in chain order
      V4  verdict/expected vocabulary; verdict == expected per sample
      V5  oracle consistency: violating -> BREAK, clean -> HELD
      V6  header completeness (battery, engine, git, pin, mode)
      V7  sample_count matches the samples list

    Raises BatteryEnvelopeError fail-closed on the first failure.
    """
    _require(isinstance(envelope, dict), "envelope-malformed",
             "envelope must be a JSON object")
    _require(envelope.get("format") == FORMAT, "envelope-unknown-format",
             "got %r" % (envelope.get("format"),))
    _require(envelope.get("schema_version") == SCHEMA_VERSION,
             "envelope-unknown-schema",
             "got %r" % (envelope.get("schema_version"),))

    header = envelope.get("header")
    _require(isinstance(header, dict), "envelope-bad-header",
             "header must be an object")
    for key in ("battery", "battery_version", "battery_digest",
                "engine_version", "git_sha", "ran_at",
                "deployment_mode", "taxonomy_pin", "sample_count",
                "run_digest"):
        _require(header.get(key) not in (None, ""),
                 "envelope-bad-header", "missing %r" % key)
    _require(isinstance(header["taxonomy_pin"], int),
             "envelope-bad-header", "taxonomy_pin must be int")
    _require(isinstance(header["sample_count"], int),
             "envelope-bad-header", "sample_count must be int")

    samples = envelope.get("samples")
    _require(isinstance(samples, list), "envelope-bad-samples",
             "samples must be a list")
    _require(len(samples) <= MAX_SAMPLES, "envelope-too-many-samples",
             "%d exceed cap %d" % (len(samples), MAX_SAMPLES))
    _require(len(samples) == header["sample_count"],
             "envelope-count-mismatch",
             "header says %d, got %d"
             % (header["sample_count"], len(samples)))

    prev = _SAMPLE_GENESIS
    for i, sample in enumerate(samples):
        _require(isinstance(sample, dict), "envelope-bad-sample",
                 "sample %d must be an object" % i)
        for key in ("sample_id", "sample_seq", "oracle", "expected",
                    "verdict", "note", "sample_digest"):
            _require(sample.get(key) not in (None, ""),
                     "envelope-bad-sample",
                     "sample %d missing %r" % (i, key))
        _require(sample["sample_seq"] == i + 1, "envelope-bad-sample",
                 "sample %d seq %r" % (i, sample["sample_seq"]))
        _require(sample["oracle"] in _ORACLES, "envelope-bad-sample",
                 "sample %r bad oracle %r"
                 % (sample["sample_id"], sample["oracle"]))
        _require(sample["expected"] in _VERDICTS,
                 "envelope-bad-sample",
                 "sample %r bad expected %r"
                 % (sample["sample_id"], sample["expected"]))
        _require(sample["verdict"] in _VERDICTS, "envelope-bad-sample",
                 "sample %r bad verdict %r"
                 % (sample["sample_id"], sample["verdict"]))
        # V4: the recorded expectation must match the verdict.
        _require(sample["verdict"] == sample["expected"],
                 "envelope-verdict-mismatch",
                 "sample %r: verdict %r != expected %r"
                 % (sample["sample_id"], sample["verdict"],
                    sample["expected"]))
        # V5: re-derive the expectation from the oracle declaration.
        if sample["expected"] != "ERROR":
            want = _ORACLE_EXPECTED[sample["oracle"]]
            _require(sample["expected"] == want,
                     "envelope-oracle-mismatch",
                     "sample %r: oracle %r requires expected %r, "
                     "got %r" % (sample["sample_id"], sample["oracle"],
                                 want, sample["expected"]))
        # V3: the digest chain recomputes.
        body = {k: v for k, v in sample.items()
                if k != "sample_digest"}
        recomputed = hashlib.sha256(
            _SAMPLE_DOMAIN + prev.encode("utf-8") + b"\x00"
            + _canonical(body)).hexdigest()
        _require(recomputed == sample["sample_digest"],
                 "envelope-sample-tampered",
                 "sample %r digest mismatch" % (sample["sample_id"],))
        prev = sample["sample_digest"]

    # V2: the run digest commits to the header + all sample digests.
    digests = b"".join(
        s["sample_digest"].encode("utf-8") for s in samples)
    header_no_digest = {k: v for k, v in header.items()
                        if k != "run_digest"}
    recomputed_run = hashlib.sha256(
        _RUN_DOMAIN + _canonical(header_no_digest) + b"\x00"
        + digests).hexdigest()
    _require(recomputed_run == header["run_digest"],
             "envelope-run-tampered", "run digest mismatch")
    return header


def load_envelope(path):
    """Read and JSON-parse an envelope file (no verification)."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Published schema (the inspect `log schema` analog).
# ---------------------------------------------------------------------------

def envelope_schema():
    """Return the JSON-schema-ish description of the envelope."""
    return {
        "$id": "https://sasanam.local/schemas/%s/%s"
               % (FORMAT, SCHEMA_VERSION),
        "title": "Sasanam battery evidence envelope",
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "pattern_lineage": "UKGovernmentBEIS/inspect_ai .eval log "
                           "(MIT); terminal-bench two-sided oracle "
                           "(Apache-2.0)",
        "header": {
            "battery": "string: battery file/module name",
            "battery_version": "string: battery-declared version",
            "battery_digest": "string: sha256 hex of battery file "
                              "bytes (or 'unknown')",
            "engine_version": "string: gov.__version__",
            "git_sha": "string: HEAD sha or 'unknown'",
            "ran_at": "string: UTC ISO-8601",
            "deployment_mode": "string: GOV_DEPLOYMENT_MODE",
            "taxonomy_pin": "integer: decision-code literal count",
            "sample_count": "integer",
            "run_digest": "string: sha256 hex committing header + "
                          "all sample digests",
        },
        "sample": {
            "sample_id": "string: probe id",
            "sample_seq": "integer: 1-based chain order",
            "oracle": "violating | clean (golden attack / golden "
                      "benign case)",
            "expected": "BREAK | HELD | ERROR",
            "verdict": "BREAK | HELD | ERROR (must equal expected)",
            "note": "string: what the probe did and saw",
            "input_digest": "optional string: sha256 of probe input",
            "sample_digest": "string: sha256 hex, hash-chained",
        },
        "verifier": "tools/envelope-verify (stdlib only); checks "
                    "V1..V7 documented in verify_envelope()",
    }


def _main(argv):
    if len(argv) == 2 and argv[1] == "--schema":
        print(_canonical(envelope_schema()).decode("utf-8"))
        return 0
    if len(argv) == 3 and argv[1] == "verify":
        try:
            header = verify_envelope(load_envelope(argv[2]))
        except BatteryEnvelopeError as exc:
            print("ENVELOPE FAILED: %s" % exc)
            return 1
        except (OSError, ValueError) as exc:
            print("ENVELOPE FAILED: cannot read envelope: %s" % exc)
            return 1
        print("ENVELOPE VERIFIED: battery=%s samples=%d pin=%d" % (
            header["battery"], header["sample_count"],
            header["taxonomy_pin"]))
        return 0
    print("usage: python -m gov.battery_envelope --schema | verify "
          "<envelope.json>")
    return 3


if __name__ == "__main__":
    sys.exit(_main(sys.argv))


__all__ = [
    "FORMAT",
    "SCHEMA_VERSION",
    "MAX_SAMPLES",
    "MAX_SAMPLE_BYTES",
    "BatteryEnvelopeError",
    "RunBuilder",
    "emit_envelope",
    "emit_for_probe_results",
    "verify_envelope",
    "load_envelope",
    "envelope_schema",
]
