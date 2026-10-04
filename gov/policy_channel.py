"""Signed policy-update distribution channel (wave-327 lane 3).

The last missing piece of the continuous supply-chain layer per
``research/prospecting/w325_supplychain_prospectus.md``: when knowledge
ingestion flips a standing, the updated POLICY must reach every agent with
bounded latency and cannot be rolled back by an attacker on the wire.

Design (the Sigstore TrustedRoot-via-TUF channel shape, ADAPTED):
- Policy documents are versioned, Ed25519-signed, and distributed as a
  feed the agent polls (a local directory; the feed directory is the
  trust boundary, like ``gov/knowledge_ingest.py``).
- The client applies only versions strictly newer than its rollback
  floor, within a bounded skip window (freeze/DoS bound). Replayed
  older versions are refused loudly and coded; a revoked/superseded
  version is never re-applied. Recovery from a skip-window refusal:
  restore the missing intermediate signed envelopes to the feed (or
  have the publisher re-issue a contiguous version); the next poll
  converges -- no state surgery is needed.
- Activation is atomic (tmp + fsync + os.replace). A crash
  mid-activation is detected on the next poll and reported LOUD; the
  previous policy stays in force. A crash *between* the active-file
  replace and the state store is healed forward loudly (the active
  wire is signed, so completing the state store is safe).
- Every policy cites the knowledge that motivated it
  (origin/collector/known_since -- mandatory, never empty), so an
  auditor can trace policy version -> advisory -> standing flip.
- Trust model: the channel reuses the pinned feed key, the monotonic
  version discipline, and the canonicalization pin
  (``gov.bundle_refresh.tuf_canonical_json`` -- enforced: the payload
  bytes must be byte-identical to the canonical encoding) of the
  audited refresh path -- consumed, not forked. It is a single-stream
  analog of the TUF client workflow, not a second TUF client.

Documented seam with the wave-326 background scanner: the channel's
envelope is wire-compatible with
``gov.background_scan._delegation_version``'s best-effort version read
(``{"payload": base64(json-with-"version")}``), so operators SHOULD
feed the channel's current wire as the scanner's delegation wire --
a delivered policy then fires the scanner's policy-change trigger.
Product code has no import coupling to the scanner; the schema is the
contract.

Stale bound (the prospectus's honest rule): every applied policy
carries ``issued_at``; exceeding ``max_staleness_seconds`` without a
refresh is a loud ``policy-channel-stale`` verdict -- the last
verified policy is still served, loudly, never silently trusted.
"""

import base64
import binascii
import json
import os
import tempfile
import time

from gov import ed25519
from gov.bundle_refresh import tuf_canonical_json

POLICY_SCHEMA = "sasanam-policy-document/v1"
STATE_SCHEMA = "sasanam-policy-channel-state/v1"
DELIVERY_SCHEMA = "sasanam-policy-channel-delivery/v1"

_NEW_CODES = (
    "policy-channel-malformed",
    "policy-channel-unsigned",
    "policy-channel-rollback",
    "policy-channel-version-skip",
    "policy-channel-unknown-policy",
    "policy-channel-superseded",
    "policy-channel-activation-failed",
    "policy-channel-feed-escape",
    "policy-channel-stale",
)


class PolicyChannelError(ValueError):
    """Loud, machine-coded channel refusal. ``code`` names the failure."""

    def __init__(self, code, detail=""):
        if code not in _NEW_CODES:
            raise ValueError("unknown policy-channel code %r" % (code,))
        super(PolicyChannelError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code


def _fail(code, detail=""):
    raise PolicyChannelError(code, detail)


class ChannelConfig(object):
    """Channel configuration (the feed directory is the trust boundary)."""

    def __init__(self, feed_dir, feed_public_key, policy_name,
                 max_skip=4, max_staleness_seconds=86400):
        if isinstance(feed_dir, bool) or not isinstance(feed_dir, str) \
                or not feed_dir:
            _fail("policy-channel-malformed",
                  "feed_dir must be a non-empty str")
        feed_dir = os.path.realpath(feed_dir)
        if not os.path.isdir(feed_dir):
            _fail("policy-channel-malformed",
                  "feed_dir is not a directory: %r" % (feed_dir,))
        if (not isinstance(feed_public_key, (bytes, bytearray))
                or len(feed_public_key) != 32):
            _fail("policy-channel-malformed",
                  "feed_public_key must be 32 bytes")
        if isinstance(policy_name, bool) or not isinstance(policy_name, str) \
                or not policy_name:
            _fail("policy-channel-malformed",
                  "policy_name must be a non-empty str")
        if (not isinstance(max_skip, int) or isinstance(max_skip, bool)
                or max_skip < 1):
            _fail("policy-channel-malformed", "max_skip must be a +int")
        if (not isinstance(max_staleness_seconds, int)
                or isinstance(max_staleness_seconds, bool)
                or max_staleness_seconds <= 0):
            _fail("policy-channel-malformed",
                  "max_staleness_seconds must be a +int")
        self.feed_dir = feed_dir
        self.feed_public_key = bytes(feed_public_key)
        self.policy_name = policy_name
        self.max_skip = max_skip
        self.max_staleness_seconds = max_staleness_seconds


# ---------------------------------------------------------------------------
# Feed trust boundary.
# ---------------------------------------------------------------------------

def _resolve_in_feed(name, config):
    """Resolve a feed file name inside the feed dir (escape -> refuse)."""
    if not isinstance(name, str) or not name:
        _fail("policy-channel-malformed", "feed file name must be str")
    candidate = os.path.realpath(os.path.join(config.feed_dir, name))
    if candidate != config.feed_dir and not candidate.startswith(
            config.feed_dir + os.sep):
        _fail("policy-channel-feed-escape",
              "feed file escapes the feed dir: %r" % (name,))
    return candidate


def _feed_files(config):
    """(version, name) pairs for this policy, sorted by version.

    The sort is numeric on the parsed version (F413): filename order
    ("pol.v10.json" < "pol.v2.json") is not semantic order. Ties are
    impossible for well-formed publisher output (one filename shape per
    version), but the sort is stable over the filename-sorted input so
    even duplicate-version filenames resolve deterministically -- the
    first applies, the rest are skipped as already-held history.
    """
    found = []
    for name in sorted(os.listdir(config.feed_dir)):
        if not name.startswith(config.policy_name + ".v"):
            continue
        if not name.endswith(".json"):
            continue
        mid = name[len(config.policy_name) + 2:-len(".json")]
        if not mid.isdigit():
            continue
        found.append((int(mid), name))
    found.sort(key=lambda pair: pair[0])
    return found


# ---------------------------------------------------------------------------
# Document parsing and verification.
# ---------------------------------------------------------------------------

def _parse_envelope(raw):
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        _fail("policy-channel-malformed", "envelope is not JSON: %s" % (exc,))
    if not isinstance(envelope, dict):
        _fail("policy-channel-malformed", "envelope must be an object")
    for field in ("payload", "signature"):
        if not isinstance(envelope.get(field), str):
            _fail("policy-channel-malformed",
                  "envelope.%s must be a str" % (field,))
    try:
        payload = base64.b64decode(envelope["payload"])
        sig = base64.b64decode(envelope["signature"])
    except (binascii.Error, ValueError) as exc:
        _fail("policy-channel-malformed", "base64 decode failed: %s" % (exc,))
    return payload, sig


def _check_document(payload):
    try:
        doc = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        _fail("policy-channel-malformed", "payload is not JSON: %s" % (exc,))
    if not isinstance(doc, dict):
        _fail("policy-channel-malformed", "document must be an object")
    # Canonicalization pin (consumed from gov.bundle_refresh, not forked):
    # the payload bytes must be byte-identical to the canonical encoding
    # of the parsed document. A correctly-signed payload in any other
    # encoding is refused, closing cross-encoder confusion on this seam.
    try:
        recanonical = tuf_canonical_json(doc)
    except Exception as exc:
        _fail("policy-channel-malformed",
              "payload not canonicalizable: %s" % (exc,))
    if recanonical != bytes(payload):
        _fail("policy-channel-malformed",
              "payload is not in canonical form")
    if doc.get("schema") != POLICY_SCHEMA:
        _fail("policy-channel-malformed",
              "unknown schema: %r" % (doc.get("schema"),))
    version = doc.get("version")
    if not isinstance(version, int) or isinstance(version, bool) \
            or version < 1:
        _fail("policy-channel-malformed", "version must be a +int")
    name = doc.get("policy_name")
    if not isinstance(name, str) or not name:
        _fail("policy-channel-malformed", "policy_name must be a str")
    body = doc.get("body")
    if not isinstance(body, dict):
        _fail("policy-channel-malformed", "body must be an object")
    revokes = doc.get("revokes", [])
    if not isinstance(revokes, list) or any(
            not isinstance(v, int) or isinstance(v, bool) or v < 1
            for v in revokes):
        _fail("policy-channel-malformed", "revokes must be a list of +int")
    # Traceability is mandatory: every policy cites the knowledge that
    # motivated it (origin/collector/known_since). A citation-free
    # policy is refused -- an auditor must always be able to trace
    # policy version -> advisory -> standing flip.
    mot = doc.get("motivated_by", [])
    if not isinstance(mot, list) or not mot:
        _fail("policy-channel-malformed",
              "motivated_by must be a non-empty list")
    for entry in mot:
        if not isinstance(entry, dict):
            _fail("policy-channel-malformed",
                  "motivated_by entries must be objects")
        for field in ("origin", "collector"):
            if not isinstance(entry.get(field), str) or not entry[field]:
                _fail("policy-channel-malformed",
                      "motivated_by.%s must be a non-empty str" % (field,))
        ks = entry.get("known_since")
        if not isinstance(ks, int) or isinstance(ks, bool) or ks < 0:
            _fail("policy-channel-malformed",
                  "motivated_by.known_since must be a non-negative int")
    issued = doc.get("issued_at")
    if not isinstance(issued, int) or isinstance(issued, bool) or issued < 0:
        _fail("policy-channel-malformed",
              "issued_at must be a non-negative int")
    return doc


def verify_document(config, raw):
    """Parse and verify a policy envelope. Returns the document dict.

    Refuses LOUD and coded on any failure; never returns an
    unverified document.
    """
    payload, sig = _parse_envelope(raw)
    # Exact True/False contract (wave-243 lesson): a False return is a
    # refusal, never an exception path, never truthiness.
    if ed25519.verify(config.feed_public_key, payload, sig) is not True:
        _fail("policy-channel-unsigned",
              "signature does not verify under the pinned feed key")
    return _check_document(payload)


# ---------------------------------------------------------------------------
# Channel state (atomic, crash-safe).
# ---------------------------------------------------------------------------

def _state_file(state_dir):
    return os.path.join(state_dir, "channel_state.json")


def _active_file(state_dir):
    return os.path.join(state_dir, "active_policy.json")


def _tmp_prefix():
    return ".policy-activate-"


def _state_tmp_prefix():
    return ".policy-state-"


def _load_state(state_dir):
    path = _state_file(state_dir)
    if not os.path.exists(path):
        return {"schema": STATE_SCHEMA, "policy_name": None,
                "current_version": 0, "revoked_versions": [],
                "current_issued_at": None, "last_poll_at": None,
                "provenance": {}}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (ValueError, OSError, UnicodeDecodeError) as exc:
        _fail("policy-channel-malformed",
              "cannot parse channel state: %s" % (exc,))
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        _fail("policy-channel-malformed", "bad schema in channel state")
    # Wrong-typed fields are malformed state, never a KeyError/TypeError
    # escaping to the caller (G6: the coded-report contract holds).
    try:
        int(state["current_version"])
        list(state["revoked_versions"])
        dict(state.get("provenance", {}))
    except (KeyError, TypeError, ValueError) as exc:
        _fail("policy-channel-malformed",
              "channel state has wrong-typed fields: %s" % (exc,))
    return state


def _store_state(state_dir, state):
    state = dict(state)
    state["schema"] = STATE_SCHEMA
    blob = json.dumps(state, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=_state_tmp_prefix(), suffix=".tmp",
                               dir=state_dir)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, _state_file(state_dir))
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        _fail("policy-channel-activation-failed",
              "could not durably store channel state: %s" % (exc,))


def _detect_orphaned_activation(state_dir):
    """A leftover activation/state tmp means a crash mid-write: LOUD.

    The previous policy stays in force; the orphan is cleaned and the
    poll reports coded. (A crash *between* the active-file replace and
    the state store leaves no tmp; that case is caught by _reconcile.)
    """
    for name in os.listdir(state_dir):
        if (name.startswith((_tmp_prefix(), _state_tmp_prefix()))
                and name.endswith(".tmp")):
            orphan = os.path.join(state_dir, name)
            try:
                os.unlink(orphan)
            except OSError:
                pass
            _fail("policy-channel-activation-failed",
                  "orphaned tmp %r: previous policy stays in force"
                  % (name,))


def _reconcile(config, state_dir):
    """Heal a crash between the active-file replace and the state store.

    If the active wire is NEWER than the recorded state, the process
    died mid-activation. The active wire is signed and verified, so
    healing forward (completing the state store) is safe and
    convergent. Returns the healed version, or None when consistent.
    """
    state = _load_state(state_dir)
    active = _active_file(state_dir)
    if not os.path.exists(active):
        return None
    with open(active, "rb") as fh:
        raw = fh.read()
    doc = verify_document(config, raw)
    if doc["policy_name"] != config.policy_name:
        _fail("policy-channel-unknown-policy",
              "active wire is for %r, channel serves %r"
              % (doc["policy_name"], config.policy_name))
    if doc["version"] <= state["current_version"]:
        return None
    # Crash mid-activation: complete it LOUD.
    revoked = sorted(set(state["revoked_versions"]) | set(doc["revokes"]))
    provenance = dict(state.get("provenance", {}))
    provenance[str(doc["version"])] = doc["motivated_by"]
    _store_state(state_dir, {
        "policy_name": config.policy_name,
        "current_version": doc["version"],
        "revoked_versions": revoked,
        "current_issued_at": doc["issued_at"],
        "last_poll_at": int(time.time()),
        "provenance": provenance,
    })
    return doc["version"]


# ---------------------------------------------------------------------------
# Apply (the rollback floor lives here).
# ---------------------------------------------------------------------------

def apply_document(config, state_dir, raw, *, now=None):
    """Verify and apply one policy envelope (raw bytes). Returns the doc.

    Enforces, in order: shape, signature (exact True), policy name,
    version floor (strictly newer than current), skip window,
    revocation set. Activation is atomic; the previous policy stays
    in force until the new one is durably active.
    """
    now = int(now if now is not None else time.time())
    raw = bytes(raw)
    doc = verify_document(config, raw)
    if doc["policy_name"] != config.policy_name:
        _fail("policy-channel-unknown-policy",
              "document is for %r, channel serves %r"
              % (doc["policy_name"], config.policy_name))
    state = _load_state(state_dir)
    if state["policy_name"] is not None \
            and state["policy_name"] != config.policy_name:
        _fail("policy-channel-malformed",
              "state dir serves %r, config asks %r"
              % (state["policy_name"], config.policy_name))
    current = state["current_version"]
    version = doc["version"]
    if version <= current:
        _fail("policy-channel-rollback",
              "version %d is not newer than floor %d" % (version, current))
    if version > current + config.max_skip:
        _fail("policy-channel-version-skip",
              "version %d jumps beyond window (floor %d + max_skip %d)"
              % (version, current, config.max_skip))
    if version in state["revoked_versions"]:
        _fail("policy-channel-superseded",
              "version %d was revoked; never re-applied" % (version,))
    # Freshness bound (G4): a future-dated issued_at would postpone the
    # staleness budget indefinitely. Beyond a small clock-skew allowance
    # the document is refused.
    if doc["issued_at"] > now + 300:
        _fail("policy-channel-malformed",
              "issued_at %d is in the future (now %d)"
              % (doc["issued_at"], now))
    # Atomic activation: write the new wire, then the new state.
    active_tmp_fd, active_tmp = tempfile.mkstemp(
        prefix=_tmp_prefix(), suffix=".tmp", dir=state_dir)
    try:
        with os.fdopen(active_tmp_fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(active_tmp, _active_file(state_dir))
    except BaseException:
        try:
            os.unlink(active_tmp)
        except OSError:
            pass
        _fail("policy-channel-activation-failed",
              "could not activate version %d" % (version,))
    revoked = sorted(set(state["revoked_versions"]) | set(doc["revokes"]))
    provenance = dict(state.get("provenance", {}))
    provenance[str(version)] = doc["motivated_by"]
    _store_state(state_dir, {
        "policy_name": config.policy_name,
        "current_version": version,
        "revoked_versions": revoked,
        "current_issued_at": doc["issued_at"],
        "last_poll_at": now,
        "provenance": provenance,
    })
    return doc


def poll(config, state_dir, *, now=None):
    """Poll the feed; apply newer versions in order. Returns a report.

    The report schema is ``sasanam-policy-channel-delivery/v1`` (the
    documented seam; consumers act on the report, never on feed files
    directly). A verification failure stops the poll LOUD and coded --
    higher versions are not processed past a tampered file.
    """
    now = int(now if now is not None else time.time())
    if not os.path.isdir(state_dir):
        os.makedirs(state_dir)
    report = {"schema": DELIVERY_SCHEMA, "policy_name": config.policy_name,
              "applied": False, "version": None,
              "current_version": 0,
              "code": None, "detail": "",
              "stale": False, "provenance": None}
    try:
        report["current_version"] = current_version(config, state_dir)
        _detect_orphaned_activation(state_dir)
    except PolicyChannelError as exc:
        report["code"] = exc.code
        report["detail"] = str(exc)
        return report
    try:
        healed = _reconcile(config, state_dir)
    except PolicyChannelError as exc:
        report["code"] = exc.code
        report["detail"] = str(exc)
        return report
    if healed is not None:
        report["code"] = "policy-channel-activation-failed"
        report["detail"] = ("crash mid-activation detected; completed "
                            "activation of version %d loudly" % (healed,))
        report["current_version"] = current_version(config, state_dir)
        return report
    state = _load_state(state_dir)
    current = state["current_version"]
    try:
        for version, name in _feed_files(config):
            if version <= current:
                continue  # feed history; the floor already held
            path = _resolve_in_feed(name, config)
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
            except OSError as exc:
                # Feed transport race (file vanished mid-poll): loud and
                # coded, current policy retained, poll stops here.
                _fail("policy-channel-malformed",
                      "feed file %r unreadable mid-poll: %s" % (name, exc))
            doc = apply_document(config, state_dir, raw, now=now)
            current = doc["version"]
            report["applied"] = True
            report["version"] = current
            report["provenance"] = doc["motivated_by"]
    except PolicyChannelError as exc:
        report["code"] = exc.code
        report["detail"] = str(exc)
    # Stale bound: no refresh within the budget is LOUD, never silent --
    # whether or not this poll applied anything (G4: a newly applied
    # policy with an ancient issued_at still trips the bound).
    issued = _load_state(state_dir)["current_issued_at"]
    if issued is not None \
            and now - issued > config.max_staleness_seconds:
        report["stale"] = True
        if report["code"] is None:
            report["code"] = "policy-channel-stale"
            report["detail"] = (
                "no policy refresh within %d seconds; serving "
                "last verified version %d loudly"
                % (config.max_staleness_seconds,
                   _load_state(state_dir)["current_version"]))
    report["current_version"] = current_version(config, state_dir)
    return report


# ---------------------------------------------------------------------------
# Queries.
# ---------------------------------------------------------------------------

def current_version(config, state_dir):
    """The currently active policy version (0 = none received).

    ``config`` is accepted for API symmetry with the other queries;
    the version is a property of the state dir.
    """
    return _load_state(state_dir)["current_version"]


def current_body(config, state_dir):
    path = _active_file(state_dir)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        raw = fh.read()
    payload, _sig = _parse_envelope(raw)
    return _check_document(payload)["body"]


def current_wire(config, state_dir):
    """The active policy envelope bytes (the scanner-seam wire)."""
    path = _active_file(state_dir)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def policy_provenance(config, state_dir, version):
    """The motivating knowledge for a policy version (traceability)."""
    prov = _load_state(state_dir).get("provenance", {})
    entry = prov.get(str(version))
    if entry is None:
        _fail("policy-channel-malformed",
              "no provenance recorded for version %r" % (version,))
    return entry
