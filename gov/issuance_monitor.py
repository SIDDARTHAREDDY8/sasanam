"""Issuance monitoring: detection is the first half of revocation.

Pattern lineage: sslmate/certspotter (Apache-2.0) -- a stateless,
DB-less certificate-transparency log monitor that detects misissuance
without keeping a database. This module reimplements the *mechanism*
only: a pure function over a supplied issuance log, no network, no
storage, stdlib only.

``scan_issuance_log`` takes a batch of issuance entries and a
``MonitorPolicy`` (allowlisted issuer keys + an authorized issuance
window) and returns a SIGNED monitor report. Findings are emitted for:

* ``entry-malformed`` -- an entry that fails the issuance-entry
  grammar (a malformed log line is itself a finding, never silently
  skipped);
* ``unexpected-issuer-key`` -- the issuer keyid is not allowlisted;
* ``rid-collision`` -- the same rid issued more than once with
  different holder keys or different issuer keys;
* ``duplicate-rid-different-issuer`` -- the same rid under two
  different issuer keyids (the cross-key forgery shape);
* ``outside-issuance-window`` -- ``issued_at`` outside the
  policy's authorized window (both edges are inclusive checks --
  ``issued_at < window_start`` or ``issued_at > window_end`` flags;
  the boundary values themselves are in-window).

The report is signed by the MONITOR key so an auditor can verify it
offline. ``verify_monitor_report`` checks the signature; the
verifier-side gate ``refuse_on_misissuance`` refuses coded
``issuance-monitor-misissuance`` whenever the verified report carries
findings -- detection feeds revocation. An unverifiable report refuses
coded too: a tampered monitor report is not a clean bill of health.

THREAT MODEL (read this before trusting a clean report):

* The monitor sees only the log it is given. Omitted entries are
  invisible -- log completeness is the operator's problem, and a
  malicious log source can simply withhold the misissued entry.
* The monitor key signs reports, not truth. A compromised monitor
  key mints clean reports over a dirty log.
* Window checks are inclusive-boundary: issuance AT the boundary is
  in-window by construction (documented, pinned by unit test).
"""

import hashlib
import json
import re
import time

from gov import ed25519 as _ed25519

REPORT_FORMAT = "sasanam-issuance-monitor-report/1"

MISISSUANCE = "issuance-monitor-misissuance"

_RID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_KEYID_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")

FINDING_KINDS = (
    "entry-malformed",
    "unexpected-issuer-key",
    "rid-collision",
    "duplicate-rid-different-issuer",
    "outside-issuance-window",
)


class MonitorError(Exception):
    """Base class; carries the machine ``code``."""

    code = MISISSUANCE

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise MonitorError(detail, code=code)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _entry_problem(entry):
    """Return a human reason the entry is malformed, or None."""
    if not isinstance(entry, dict):
        return "entry is not a dict"
    rid = entry.get("rid")
    if not isinstance(rid, str) or not _RID_RE.match(rid):
        return "rid fails grammar"
    keyid = entry.get("issuer_keyid")
    if not isinstance(keyid, str) or not _KEYID_RE.match(keyid):
        return "issuer_keyid fails grammar"
    holder = entry.get("holder_pubkey")
    if not isinstance(holder, str) or not _HEX64_RE.match(holder):
        return "holder_pubkey must be 64 lowercase hex chars"
    issued_at = entry.get("issued_at")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) \
            or issued_at < 0:
        return "issued_at must be a non-negative int"
    return None


class MonitorPolicy:
    """The auditor's monitor policy: allowlisted issuer keys and an
    authorized issuance window.

    ``allowed_issuer_keys`` maps keyid -> Ed25519 public key (hex).
    A policy with an empty allowlist is refused at construction
    (vacuous policies admit nothing). ``issuance_window`` is
    ``(window_start, window_end)`` as integer unix times, both edges
    inclusive.
    """

    def __init__(self, policy_id, allowed_issuer_keys,
                 issuance_window):
        if not isinstance(policy_id, str) or \
                not _KEYID_RE.match(policy_id):
            _fail(MISISSUANCE, "policy id fails grammar")
        if not isinstance(allowed_issuer_keys, dict) or \
                not allowed_issuer_keys:
            _fail(MISISSUANCE,
                  "monitor policy admits no issuer keys: vacuous "
                  "policies are refused at construction (they admit "
                  "nothing)")
        self.allowed_issuer_keys = {}
        for keyid, pub in allowed_issuer_keys.items():
            if not isinstance(keyid, str) or \
                    not _KEYID_RE.match(keyid):
                _fail(MISISSUANCE,
                      "issuer keyid fails grammar: %r" % (keyid,))
            if not isinstance(pub, str) or not _HEX64_RE.match(pub):
                _fail(MISISSUANCE,
                      "issuer key %r public key must be 64 lowercase "
                      "hex chars" % (keyid,))
            self.allowed_issuer_keys[keyid] = pub
        if (not isinstance(issuance_window, (list, tuple)) or
                len(issuance_window) != 2):
            _fail(MISISSUANCE, "issuance_window must be (start, end)")
        start, end = issuance_window
        for value, name in ((start, "window_start"),
                            (end, "window_end")):
            if not isinstance(value, int) or isinstance(value, bool) \
                    or value < 0:
                _fail(MISISSUANCE,
                      "%s must be a non-negative int" % name)
        if end < start:
            _fail(MISISSUANCE,
                  "issuance window end precedes start")
        self.policy_id = policy_id
        self.window_start = start
        self.window_end = end

    def policy_digest(self):
        body = {"policy_id": self.policy_id,
                "allowed_issuer_keys": self.allowed_issuer_keys,
                "issuance_window": [self.window_start,
                                    self.window_end]}
        return hashlib.sha256(_canonical(body)).hexdigest()


def scan_issuance_log(entries, policy, monitor_seed, scanned_at=None):
    """Scan a credential-issuance log, statelessly. Returns a signed
    monitor report envelope::

        {"report": {"report_format": "sasanam-issuance-monitor-report/1",
                    "policy_id": <str>, "policy_digest": <64 hex>,
                    "scanned_at": <int>, "entry_count": <int>,
                    "findings": [{"kind": <finding kind>, "rid": <rid|null>,
                                  "detail": <str>}, ...]},
         "signature": <128 hex>, "keyid": "monitor"}

    ``entries`` must be a list; each entry is checked in order and
    every misissuance becomes a finding. The function never raises on
    a dirty log -- dirt becomes findings, and the signed report is the
    evidence. A non-list ``entries`` refuses coded
    ``issuance-monitor-misissuance`` (the monitor refuses to bless an
    un-scannable input).
    """
    if not isinstance(policy, MonitorPolicy):
        _fail(MISISSUANCE, "policy must be a MonitorPolicy")
    if not isinstance(entries, list):
        _fail(MISISSUANCE,
              "issuance log must be a list of entries; refusing to "
              "report on an un-scannable input")
    if not isinstance(monitor_seed, bytes) or len(monitor_seed) != 32:
        _fail(MISISSUANCE, "monitor seed must be 32 raw bytes")
    if scanned_at is None:
        scanned_at = int(time.time())
    elif not isinstance(scanned_at, int) or isinstance(scanned_at, bool) \
            or scanned_at < 0:
        _fail(MISISSUANCE, "scanned_at must be a non-negative int")

    findings = []
    seen = {}  # rid -> (holder_pubkey, issuer_keyid)

    def _finding(kind, rid, detail):
        findings.append({"kind": kind, "rid": rid, "detail": detail})

    for index, entry in enumerate(entries):
        problem = _entry_problem(entry)
        if problem is not None:
            _finding("entry-malformed", None,
                     "entry %d malformed: %s" % (index, problem))
            continue
        rid = entry["rid"]
        keyid = entry["issuer_keyid"]
        holder = entry["holder_pubkey"]
        issued_at = entry["issued_at"]
        if keyid not in policy.allowed_issuer_keys:
            _finding("unexpected-issuer-key", rid,
                     "entry %d: issuer keyid %r is not allowlisted"
                     % (index, keyid))
        if issued_at < policy.window_start or \
                issued_at > policy.window_end:
            _finding("outside-issuance-window", rid,
                     "entry %d: issued_at %d outside window [%d, %d]"
                     % (index, issued_at, policy.window_start,
                        policy.window_end))
        prior = seen.get(rid)
        if prior is not None:
            prior_holder, prior_keyid = prior
            if prior_keyid != keyid:
                _finding("duplicate-rid-different-issuer", rid,
                         "entry %d: rid %r already issued under issuer "
                         "keyid %r" % (index, rid, prior_keyid))
            elif prior_holder != holder:
                _finding("rid-collision", rid,
                         "entry %d: rid %r already issued to a different "
                         "holder" % (index, rid))
            else:
                _finding("rid-collision", rid,
                         "entry %d: rid %r issued more than once"
                         % (index, rid))
        else:
            seen[rid] = (holder, keyid)

    report = {
        "report_format": REPORT_FORMAT,
        "policy_id": policy.policy_id,
        "policy_digest": policy.policy_digest(),
        "scanned_at": scanned_at,
        "entry_count": len(entries),
        "findings": findings,
    }
    signature = _ed25519.sign(monitor_seed, _canonical(report)).hex()
    return {"report": report, "signature": signature, "keyid": "monitor"}


def verify_monitor_report(envelope, monitor_pubkey_hex):
    """Verify a signed monitor report. Returns the report dict. Any
    failure -- malformed envelope, signature mismatch -- refuses coded
    ``issuance-monitor-misissuance``: a tampered monitor report is not
    a clean bill of health."""
    if not isinstance(envelope, dict):
        _fail(MISISSUANCE, "monitor report envelope must be a dict")
    report = envelope.get("report")
    sig_hex = envelope.get("signature")
    if not isinstance(report, dict) or not isinstance(sig_hex, str):
        _fail(MISISSUANCE,
              "monitor report envelope must carry report and signature")
    if report.get("report_format") != REPORT_FORMAT:
        _fail(MISISSUANCE, "monitor report format mismatch")
    if not isinstance(report.get("findings"), list):
        _fail(MISISSUANCE, "monitor report findings must be a list")
    if not _HEX128_RE.match(sig_hex):
        _fail(MISISSUANCE, "monitor report signature is not 128 hex")
    try:
        pub = bytes.fromhex(monitor_pubkey_hex)
    except (TypeError, ValueError):
        _fail(MISISSUANCE, "monitor public key is not hex")
    if len(pub) != 32:
        _fail(MISISSUANCE, "monitor public key is not 32 bytes")
    try:
        canonical = _canonical(report)
    except (TypeError, ValueError):
        # F362: a circular structure makes json.dumps raise uncoded;
        # refuse coded instead.
        _fail(MISISSUANCE, "monitor report is not JSON-canonicalizable")
    ok = _ed25519.verify(pub, canonical,
                         bytes.fromhex(sig_hex))
    if ok is not True:
        _fail(MISISSUANCE,
              "monitor report signature does not verify under the "
              "pinned monitor key")
    return report


def refuse_on_misissuance(report):
    """Verifier-side gate: a verified report with findings refuses LOUD
    coded ``issuance-monitor-misissuance``; a clean report returns
    True. Detection feeds revocation."""
    if not isinstance(report, dict):
        _fail(MISISSUANCE, "report must be a dict")
    findings = report.get("findings")
    if not isinstance(findings, list):
        _fail(MISISSUANCE, "report findings must be a list")
    if findings:
        kinds = sorted({f.get("kind") for f in findings
                        if isinstance(f, dict)})
        _fail(MISISSUANCE,
              "issuance monitor detected %d finding(s) [%s]: misissuance "
              "refuses" % (len(findings), ", ".join(kinds)))
    return True
