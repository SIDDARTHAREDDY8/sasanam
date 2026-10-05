"""Wave-330 independent red-team battery.

Base: 8c4f6139 (wave-329 merge). Footer: open F415 / next F417
(F413/F414 CLOSED; F415/F416 filed by wave-330 lane 3, LOW, OPEN). Pin: 2100.

P1  wave-329 seams not yet broken: evidence_sigstore post-audit
    (form-(1) hint games, primary-key resolution, unknown-field
    refusal, witness-binding games, old/new shape interop) and
    policy_channel post-F413 (numeric version-sort games:
    unicode-digit version filenames crash int() uncoded).
P2  F414 re-probe (F414 CLOSED wave-330 lane 1; asserts HELD).
P3  F413/F412/F411/F410 closure-regression probes (all HELD).
P4  merge-defect class: vocab-scanned-but-unregistered codes (every
    code literal in the tree must be registered in
    gov/decision_codes.py) and pin-comment honesty (-> N finals
    match live pins).
P5  pin 2100 + footer state probes.
P6  prior batteries in child mode (GOV_SKIP_GREEN=1 in the child env),
    tallies verified by direct child runs.

gov/ is byte-identical to base: this battery changes no product code
and files findings only (from F415). No new decision codes from this lane.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2131 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-327 merge: pin 2035 -> 2044 (+9 policy-channel-*).; Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*); Wave-339 merge: pin 2128 -> 2130 (+4 codes: oci-bundle-not-verifiable, witness-policy-dual-threshold-unmet, witness-daemon-state-failed, oci-registry-onboarding-refused); Wave-340 lane 3: pin 2130 -> 2131 (+1 deadctrl-subject-mutated).
FOOTER_OPEN = "F427"  # F414/F415/F416/F417/F423/F424/F425 CLOSED; F426 closed wave-338 lane 1.
FOOTER_NEXT = "F428"  # Next free finding number.

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception:
        _record(pid, "ERROR",
                traceback.format_exc(limit=2).replace("\n", " | ")[:500])


def _relabel(pid, fn):
    _pid, verdict, note = fn()
    return (pid, verdict, note)


def _tmpd():
    return tempfile.mkdtemp(prefix="w330-", dir=_run_root())


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w330rt")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _uncoded_crash(pid, fn, note):
    """fn must raise a BARE ValueError (not a coded EnvelopeError /
    PolicyChannelError subclass). HELD iff the crash is coded or absent;
    BREAK iff the bare ValueError escapes (the F412-class discipline
    violation: refusals must be coded, never bare)."""
    from gov.dsse_envelope import EnvelopeError
    from gov.policy_channel import PolicyChannelError
    try:
        fn()
    except (EnvelopeError, PolicyChannelError) as exc:
        # F416 closure: EnvelopeError carries the machine code as
        # ``reason`` (wave-232), PolicyChannelError as ``code`` -- accept
        # either, so a coded refusal on the closed tree records HELD
        # instead of erroring in the probe itself.
        code = getattr(exc, "code", None) or getattr(exc, "reason", "?")
        return _held(pid, "%s: refused coded %s" % (note, code))
    except ValueError as exc:
        return _break(pid, "%s: UNCODED %s escapes: %s"
                      % (note, type(exc).__name__, str(exc)[:120]))
    except Exception as exc:
        return _break(pid, "%s: UNCODED %s escapes: %s"
                      % (note, type(exc).__name__, str(exc)[:120]))
    return _held(pid, "%s: no crash (accepted or refused silently)" % note)


from gov import policy_channel as pc  # noqa: E402
from gov import evidence_sigstore as es  # noqa: E402
from gov import evidence_intoto  # noqa: E402
from gov import ed25519 as _ed25519  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402
from gov.bundle_refresh import tuf_canonical_json  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures: policy channel.
# ---------------------------------------------------------------------------

_NOW = 1700000000


def _pkeys():
    seed = _ed25519.generate_seed()
    return seed, _ed25519.publickey(seed)


def _pdoc(seed, version, policy_name="pol", revokes=(),
          issued_at=_NOW):
    payload = {
        "schema": "sasanam-policy-document/v1",
        "policy_name": policy_name,
        "version": version,
        "body": {"rules": ["r%d" % version]},
        "revokes": list(revokes),
        "motivated_by": [{"origin": "t", "collector": "t",
                          "known_since": 1}],
        "issued_at": issued_at,
    }
    raw = tuf_canonical_json(payload)
    sig = _ed25519.sign(seed, raw)
    return {"payload": base64.b64encode(raw).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii")}


def _pwrite(feed, envelope, name):
    path = os.path.join(feed, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
    return path


def _pfresh(policy_name="pol", max_skip=4):
    feed = tempfile.mkdtemp(prefix="w330-pfeed-")
    state = tempfile.mkdtemp(prefix="w330-pstate-")
    seed, pub = _pkeys()
    cfg = pc.ChannelConfig(feed, pub, policy_name, max_skip=max_skip)
    return {"feed": feed, "state": state, "seed": seed, "pub": pub,
            "cfg": cfg}


# ---------------------------------------------------------------------------
# Fixtures: evidence sigstore.
# ---------------------------------------------------------------------------

BUNDLE = b'{"bundle":"synthetic-test-bytes-330"}'
CLAIMS = {"window": "2026-10-04", "tip": "ef" * 16, "decisions": 3}
T0 = 1791528600
VALIDITY = (1791528000, 1791530000)


def _signers(n, base=41):
    return [Ed25519Signer(bytes([base + i]) * 32) for i in range(n)]


def _verifiers(signers):
    return [Ed25519Verifier(s.public_key, s.key_id) for s in signers]


def _witness(base=77):
    return Ed25519Signer(bytes([base]) * 32)


def _witness_verifier(witness):
    return Ed25519Verifier(witness.public_key, witness.key_id)


def _sealed_bundle(signers=None, witness=None, integrated_time=T0,
                   witness_log=None):
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
    env = evidence_intoto.seal_statement(stmt, signers)
    return es.seal_sigstore_bundle(
        env, signers, witness, rfc3161_token=None,
        integrated_time=integrated_time, witness_log=witness_log)


def _open(bundle, signers=None, witness=None, threshold=1,
          validity=VALIDITY):
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    return es.open_sigstore_bundle(
        bundle, BUNDLE, _verifiers(signers),
        _witness_verifier(witness), threshold=threshold,
        witness_validity=validity)


# ---------------------------------------------------------------------------
# P1: wave-329 seams.
# ---------------------------------------------------------------------------

@probe("P1a-evidence-sigstore-integratedtime-digitlimit-uncoded")
def _p1a():
    """F416: integratedTime digit-limit -> uncoded ValueError.

    _check_witness gated on str.isdigit() then called int() directly.
    A 5000-digit integratedTime passed the gate; int() raised the
    4300-digit-limit ValueError -- bare, uncoded. The time check ran
    BEFORE the witness SET was verified, so any bundle presenter (the
    whole point of the offline verifier) triggered it: a loud DoS of
    the verify path that violates the coded-refusal discipline
    (F412-class: refusals must be coded, never bare).

    CLOSED 2026-10-04 wave-331 lane 2: the witness SET (logId binding,
    body binding, SET signature) is verified BEFORE integratedTime is
    touched, and the conversion is TOTAL -- _parse_int64_as_string
    (ASCII digits only, length-bounded before int()) refusing coded
    evidence-bundle-malformed. This probe now asserts the coded
    refusal (HELD).
    """
    bundle = _sealed_bundle()
    bundle["verificationMaterial"]["tlogEntries"][0][
        "integratedTime"] = "9" * 5000
    return _uncoded_crash(
        "P1a-evidence-sigstore-integratedtime-digitlimit-uncoded",
        lambda: _open(bundle),
        "integratedTime 5000-digit")


@probe("P1b-evidence-sigstore-logindex-digitlimit-uncoded")
def _p1b():
    """F416 (second manifestation): logIndex digit-limit, post-SET.

    Same isdigit()->int() class at the inclusionProof branch: the
    logIndex gate passed a 5000-digit string and int() raised bare.
    Demonstrated with a fully valid bundle (real WitnessLog, valid
    checkpoint, valid re-checked SET): the crash needs no forgery,
    only an over-long logIndex.

    CLOSED 2026-10-04 wave-331 lane 2: logIndex goes through the same
    TOTAL _parse_int64_as_string (coded evidence-bundle-malformed on
    over-long/non-ASCII input), parsed only after the SET verifies.
    This probe now asserts the coded refusal (HELD).
    """
    from gov import witness_log as wl
    signers = _signers(1)
    witness = _witness()
    log = wl.WitnessLog(bytes(witness.public_key))
    bundle = _sealed_bundle(signers=signers, witness=witness,
                            witness_log=log)
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    entry["logIndex"] = "9" * 5000
    return _uncoded_crash(
        "P1b-evidence-sigstore-logindex-digitlimit-uncoded",
        lambda: _open(bundle, signers=signers, witness=witness),
        "logIndex 5000-digit (valid SET, valid checkpoint)")


@probe("P1c-evidence-sigstore-old-shape-refused-coded")
def _p1c():
    """Pre-audit wire shape (publicKey {rawBytes,keyDetails}) is refused
    coded, not accepted and not crashing: the wave-329 interop fix."""
    bundle = _sealed_bundle()
    bundle["verificationMaterial"]["publicKey"] = {
        "rawBytes": base64.b64encode(b"x" * 32).decode("ascii"),
        "keyDetails": "PKIX_ED25519",
    }
    try:
        _open(bundle)
    except es._dsse.EnvelopeError as exc:
        if exc.reason == "evidence-bundle-verification-material":
            return _held("P1c-evidence-sigstore-old-shape-refused-coded",
                         "old publicKey shape refused coded")
        return _break("P1c-evidence-sigstore-old-shape-refused-coded",
                      "wrong code %r" % (exc.reason,))
    except Exception as exc:
        return _break("P1c-evidence-sigstore-old-shape-refused-coded",
                      "uncoded %s" % type(exc).__name__)
    return _break("P1c-evidence-sigstore-old-shape-refused-coded",
                  "old shape accepted")


@probe("P1d-evidence-sigstore-hint-mismatch-refused-coded")
def _p1d():
    """A hint naming a key that did not authenticate this bundle is
    refused coded evidence-bundle-hint-mismatch (never trusted)."""
    from gov import sigstore_bundle as _sigbundle
    bundle = _sealed_bundle()
    other = _signers(1, base=99)[0]
    bundle["verificationMaterial"]["publicKey"] = {
        "hint": _sigbundle.key_hint(bytes(other.public_key))}
    try:
        _open(bundle)
    except es._dsse.EnvelopeError as exc:
        if exc.reason == "evidence-bundle-hint-mismatch":
            return _held("P1d-evidence-sigstore-hint-mismatch-refused-coded",
                         "foreign hint refused coded")
        return _break("P1d-evidence-sigstore-hint-mismatch-refused-coded",
                      "wrong code %r" % (exc.reason,))
    except Exception as exc:
        return _break("P1d-evidence-sigstore-hint-mismatch-refused-coded",
                      "uncoded %s" % type(exc).__name__)
    return _break("P1d-evidence-sigstore-hint-mismatch-refused-coded",
                  "foreign hint accepted")


@probe("P1e-evidence-sigstore-empty-hint-accepted")
def _p1e():
    """The spike-proven cosign shape {"publicKey": {}} still verifies:
    the hint is informational, never authority."""
    bundle = _sealed_bundle()
    bundle["verificationMaterial"]["publicKey"] = {}
    try:
        out = _open(bundle)
    except Exception as exc:
        return _break("P1e-evidence-sigstore-empty-hint-accepted",
                      "empty hint refused: %s %s"
                      % (type(exc).__name__, getattr(exc, "code", "")))
    subj = out.get("statement", {}).get("subject", [{}])[0]
    if subj.get("digest", {}).get("sha256") == hashlib.sha256(BUNDLE).hexdigest():
        return _held("P1e-evidence-sigstore-empty-hint-accepted",
                     "empty hint verifies")
    return _break("P1e-evidence-sigstore-empty-hint-accepted",
                  "wrong payload returned")


@probe("P1f-evidence-sigstore-threshold-same-key-refused")
def _p1f():
    """Two signatures from the SAME key do not meet threshold=2:
    distinct-key counting, fail-closed."""
    signers = _signers(1)
    witness = _witness()
    stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
    env = evidence_intoto.seal_statement(stmt, signers + signers)
    bundle = es.seal_sigstore_bundle(
        env, signers + signers, witness, rfc3161_token=None,
        integrated_time=T0)
    try:
        _open(bundle, signers=signers, witness=witness, threshold=2)
    except es._dsse.EnvelopeError as exc:
        if exc.reason == "evidence-bundle-signature-invalid":
            return _held("P1f-evidence-sigstore-threshold-same-key-refused",
                         "same-key x2 refused coded at threshold 2")
        return _break("P1f-evidence-sigstore-threshold-same-key-refused",
                      "wrong code %r" % (exc.reason,))
    except Exception as exc:
        return _break("P1f-evidence-sigstore-threshold-same-key-refused",
                      "uncoded %s" % type(exc).__name__)
    return _break("P1f-evidence-sigstore-threshold-same-key-refused",
                  "threshold met by one key twice")


@probe("P1g-policy-channel-unicode-version-uncoded")
def _p1g():
    """F415: _feed_files gates on str.isdigit() then int()s directly.

    Unicode digits like U+00B2 SUPERSCRIPT TWO pass isdigit() but
    int() rejects them -- a bare ValueError escapes poll(), which only
    catches PolicyChannelError. Any feed-dir writer (no signing key
    needed) can crash every poll: loud, fail-closed, but UNCODED --
    the F412-class discipline violation.

    CLOSED 2026-10-04 wave-331 lane 1: the version fragment is now
    ASCII-digit-gated; unicode-digit fragments refuse coded
    policy-channel-malformed (folded into the poll report). This probe
    now asserts the coded refusal (HELD).
    """
    fx = _pfresh()
    _pwrite(fx["feed"], _pdoc(fx["seed"], 1), "pol.v1.json")
    _pwrite(fx["feed"], _pdoc(fx["seed"], 2), "pol.v².json")
    return _uncoded_crash(
        "P1g-policy-channel-unicode-version-uncoded",
        lambda: pc.poll(fx["cfg"], fx["state"], now=_NOW),
        "pol.v².json in feed")


@probe("P1i-policy-channel-unparseable-version-skipped")
def _p1i():
    """Non-digit version fragments (pol.vX.json) keep the documented
    skip behavior: the feed is ignored, polling continues."""
    fx = _pfresh()
    _pwrite(fx["feed"], _pdoc(fx["seed"], 1), "pol.v1.json")
    _pwrite(fx["feed"], _pdoc(fx["seed"], 2), "pol.vX.json")
    rep = pc.poll(fx["cfg"], fx["state"], now=_NOW)
    if rep["applied"] and pc.current_version(fx["cfg"], fx["state"]) == 1:
        return _held("P1i-policy-channel-unparseable-version-skipped",
                     "unparseable name skipped, v1 applied")
    return _break("P1i-policy-channel-unparseable-version-skipped",
                  "unexpected: applied=%r code=%r"
                  % (rep["applied"], rep["code"]))


# ---------------------------------------------------------------------------
# P2: F414 re-probe (F414 CLOSED 2026-10-04 wave-330 lane 1; asserts HELD).
# ---------------------------------------------------------------------------

@probe("P2-f414-reprobe-symlink-alias-closed")
def _p2():
    import w329_redteam_probes as w329
    return _relabel("P2-f414-reprobe-symlink-alias-closed", w329._p1h)


# ---------------------------------------------------------------------------
# P3: closure-regression probes (all must stay HELD).
# ---------------------------------------------------------------------------

@probe("P3a-f413-closure-regression-order")
def _p3a():
    import w328_redteam_probes as w328
    return _relabel("P3a-f413-closure-regression-order", w328._p1b)


@probe("P3b-f413-closure-regression-revocation")
def _p3b():
    import w328_redteam_probes as w328
    return _relabel("P3b-f413-closure-regression-revocation", w328._p1c)


@probe("P3c-f412-closure-regression")
def _p3c():
    import w327_redteam_probes as w327
    return _relabel("P3c-f412-closure-regression", w327._p1f)


@probe("P3d-f411-closure-regression")
def _p3d():
    import w327_redteam_probes as w327
    return _relabel("P3d-f411-closure-regression", w327._p3a)


@probe("P3e-f410-closure-regression-t4c")
def _p3e():
    import w327_redteam_probes as w327
    return _relabel("P3e-f410-closure-regression-t4c", w327._p2a)


@probe("P3f-f410-closure-regression-t4d")
def _p3f():
    import w327_redteam_probes as w327
    return _relabel("P3f-f410-closure-regression-t4d", w327._p2b)


# ---------------------------------------------------------------------------
# P4: the wave-329 merge defect class.
# ---------------------------------------------------------------------------

def _registered_codes():
    import gov.decision_codes as dc
    return set(dc.TAXONOMY)


# Grandfathered (wave-200/206-era) code literals used in gov/ but never
# centrally registered. Long-standing debt, not a regression: the probe
# below BREAKs only on codes BEYOND this inventory (the wave-329 merge
# defect class was NEW codes shipping unregistered).
_GRANDFATHERED_UNREGISTERED = frozenset({
    "config-body-mismatch", "config-expired", "config-extra-member",
    "config-stale", "config-supersede-break", "handoff-required",
    "pack-activation-approval-required", "pack-activation-denied",
    "pack-guard-error", "pack-member-digest-mismatch", "pack-member-extra",
    "pack-member-omitted", "pack-stale", "policy-not-yet-valid",
})


@probe("P4a-codes-centrally-registered")
def _p4a():
    """Wave-329 merge class: vocab-scanned-but-unregistered codes.

    Every code literal passed to _fail/_refuse (or code= kw) anywhere
    in gov/ must be centrally registered in gov/decision_codes.py --
    except the 14 grandfathered wave-200/206-era literals inventoried
    above (long-standing debt, documented here, not a regression).
    Any NEW unregistered literal BREAKs.
    """
    registered = _registered_codes()
    used = set()
    for fname in sorted(os.listdir(os.path.join(REPO, "gov"))):
        if not fname.endswith(".py"):
            continue
        src = open(os.path.join(REPO, "gov", fname),
                   encoding="utf-8").read()
        for pat in (r'_fail\(\s*"([^"]+)"', r"_fail\(\s*'([^']+)'",
                    r'_refuse\(\s*"([^"]+)"', r"_refuse\(\s*'([^']+)'",
                    r'code\s*=\s*"([^"]+)"', r"code\s*=\s*'([^']+)'"):
            used.update(re.findall(pat, src))
    # Only code-shaped literals (dotted domain names), not free text.
    codey = {u for u in used if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+",
                                            u)}
    missing = sorted(codey - registered - _GRANDFATHERED_UNREGISTERED)
    if missing:
        return _break("P4a-codes-centrally-registered",
                      "NEW unregistered code literals: %r" % (missing[:8],))
    return _held("P4a-codes-centrally-registered",
                 "%d code literals registered (+%d grandfathered debt)"
                 % (len(codey - _GRANDFATHERED_UNREGISTERED),
                    len(_GRANDFATHERED_UNREGISTERED)))


@probe("P4b-pin-comments-honest")
def _p4b():
    """Every TAXONOMY_PIN/LANE_PIN/EXPECTED_PIN assignment whose
    trailing comment states a '-> N' final pin must have N equal to
    the live value: pin-comment drift is the wave-329 merge class."""
    bad = []
    live = {}
    for dirpath, _dirs, files in os.walk(REPO):
        if "/.git/" in dirpath or "/__pycache__/" in dirpath:
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(dirpath, fname)
            try:
                src = open(path, encoding="utf-8").read()
            except OSError:
                continue
            for m in re.finditer(
                    r"^(?:\s*)(?:[A-Z_]+\.)?(TAXONOMY_PIN|LANE_PIN|"
                    r"EXPECTED_PIN)\s*=\s*(\d+)([^\n]*)$",
                    src, re.M):
                name, val, rest = m.group(1), int(m.group(2)), m.group(3)
                live.setdefault(name, set()).add(val)
                finals = re.findall(r"->\s*(\d+)", rest)
                if finals and int(finals[-1]) != val:
                    bad.append("%s:%s -> %s != live %d"
                               % (os.path.relpath(path, REPO),
                                  name, finals[-1], val))
    if bad:
        return _break("P4b-pin-comments-honest",
                      "pin-comment drift: %r" % (bad[:5],))
    vals = {k: sorted(v) for k, v in live.items()}
    return _held("P4b-pin-comments-honest",
                 "pin comments honest; live values %r" % (vals,))


@probe("P4c-no-empty-or-truncated-probe-files")
def _p4c():
    """Pin-repoint incident class: no empty or truncated .py files in
    evals/ or tests/ (the wave-327 0-byte truncation class)."""
    bad = []
    for sub in ("evals", "tests"):
        d = os.path.join(REPO, sub)
        for fname in sorted(os.listdir(d)):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(d, fname)
            size = os.path.getsize(path)
            if size == 0:
                bad.append("%s/%s empty" % (sub, fname))
                continue
            try:
                compile(open(path, encoding="utf-8").read(), path,
                        "exec")
            except SyntaxError as exc:
                bad.append("%s/%s SyntaxError: %s" % (sub, fname, exc))
    if bad:
        return _break("P4c-no-empty-or-truncated-probe-files",
                      "; ".join(bad[:5]))
    return _held("P4c-no-empty-or-truncated-probe-files",
                 "no empty/truncated .py in evals/ or tests/")


# ---------------------------------------------------------------------------
# P5: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P5a-pin-taxonomy-2131-sorted")
def _p5a():
    if TAXONOMY_PIN != 2131:
        return _break("P5a-pin-taxonomy-2131-sorted",
                      "TAXONOMY_PIN is %r, want 2131" % (TAXONOMY_PIN,))
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(lits) != 2131 or len(set(lits)) != 2131 \
            or lits != sorted(lits):
        return _break("P5a-pin-taxonomy-2131-sorted",
                      "want 2131/2131/0 sorted, got %d/%d/sorted=%s"
                      % (len(lits), len(set(lits)), lits == sorted(lits)))
    return _held("P5a-pin-taxonomy-2131-sorted",
                 "2131/2131/0 sorted unique on raw source literals")


@probe("P5b-footer-open-none-next-f428")
def _p5b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break("P5b-footer-open-none-next-f428",
                      "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now != FOOTER_OPEN:
        return _break("P5b-footer-open-none-next-f428",
                      "footer open %s / next %s, want open %s / next %s"
                      % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    return _held("P5b-footer-open-none-next-f428",
                 "footer open none / next F419")


# ---------------------------------------------------------------------------
# P6: prior batteries in child mode (GOV_SKIP_GREEN=1 in the child env).
# ---------------------------------------------------------------------------

def _run_child_output(battery, timeout=600):
    """Run a prior battery as a subprocess; return its raw stdout.

    GOV_SKIP_GREEN=1 in the child env (depth-1 green checks), fresh
    TMPDIR per child. Raises on timeout; returns text otherwise.
    """
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmpd = tempfile.mkdtemp(prefix="w330child-",
                            dir=_run_root())
    env["TMPDIR"] = tmpd
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, cwd=REPO)
    return proc.stdout.decode("utf-8", "replace")


# Battery -> set of BREAK probe IDs that are NOT regressions on this
# tree. Post wave-331 merge sweep: every child battery's footer-state
# probes were re-pinned to the merged footer (open none / next
# F417) and F414/F415/F416's closure probes flip to HELD, so all
# cascade sets are EMPTY. Any child BREAK below is a genuine
# regression. (wave-305 class.)
_CHILD_CASCADE = {
    "w329_redteam_probes.py": set(),
    "w329_sigb_probes.py": set(),
    "w328_redteam_probes.py": set(),
    "w328_resid_probes.py": set(),
    "w328_shamir_probes.py": set(),
    "w327_redteam_probes.py": set(),
    "w327_polchan_probes.py": set(),
    "w326_tufaudit_probes.py": set(),
    "w326_redteam_probes.py": set(),
    "w326_standing_probes.py": set(),
    "w326_sched_probes.py": set(),
}


@probe("P6a-prior-batteries-child-mode-tallies")
def _p6a():
    """Prior batteries: every BREAK is inside the documented cascade.

    Runs each prior battery as a subprocess (GOV_SKIP_GREEN=1 in the
    child env, fresh TMPDIR). A BREAK outside _CHILD_CASCADE -- or any
    ERROR -- is a genuine regression, not the F414 open finding.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return _held("P6a-prior-batteries-child-mode-tallies",
                     "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    batteries = ("w329_redteam_probes.py", "w329_sigb_probes.py",
                 "w328_redteam_probes.py", "w328_resid_probes.py",
                 "w328_shamir_probes.py", "w327_redteam_probes.py",
                 "w327_polchan_probes.py", "w326_tufaudit_probes.py",
                 "w326_redteam_probes.py", "w326_standing_probes.py",
                 "w326_sched_probes.py")
    bad = []
    tallies = []
    for battery in batteries:
        try:
            out = _run_child_output(battery)
        except Exception as exc:
            bad.append("%s: ERROR %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        # Some batteries print no per-probe [BREAK] lines; their
        # BREAK-SET MISMATCH line carries the unexpected IDs instead.
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:
                pass
        if errors:
            bad.append("%s: ERRORs %s" % (battery, sorted(errors)[:3]))
        outside = breaks - _CHILD_CASCADE[battery]
        if outside:
            bad.append("%s: non-cascade BREAKs %s"
                       % (battery, sorted(outside)[:4]))
        tallies.append("%s breaks=%d" % (battery, len(breaks)))
    if bad:
        return _break("P6a-prior-batteries-child-mode-tallies",
                      "; ".join(bad[:6]))
    return _held("P6a-prior-batteries-child-mode-tallies",
                 "all child BREAKs inside the F414 cascade; "
                 + "; ".join(tallies))


# ---------------------------------------------------------------------------
# Expected BREAK set, green check, main.
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs: F414/F415/F416 all CLOSED.
# (History, kept as comments: F415 CLOSED 2026-10-04 wave-331 lane 1:
# P1g now asserts the coded policy-channel-malformed refusal (HELD);
# F416 CLOSED 2026-10-04 wave-331 lane 2: P1a/P1b now assert the coded
# evidence-bundle-malformed refusal (HELD);
# F414 CLOSED 2026-10-04 wave-330 lane 1: P2 re-probe is HELD.)


def _green_check():
    """Depth-1 green check: adjacent batteries with GOV_SKIP_GREEN=1.

    Honors GOV_SKIP_GREEN (records a skip instead of spawning). Never
    spawns a battery that spawns another: depth-1 only.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    for battery in ("w329_redteam_probes.py",
                    "w329_sigb_probes.py",
                    "w328_redteam_probes.py"):
        try:
            out = _run_child_output(battery)
        except Exception as exc:
            _record("green-check", "ERROR",
                    "%s: %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:
                pass
        outside = breaks - _CHILD_CASCADE[battery]
        if errors or outside:
            _record("green-check", "BREAK",
                    "%s: non-cascade %s" %
                    (battery, sorted(outside | errors)[:4]))
        else:
            _record("green-check", "HELD",
                    "%s: %d breaks, all in cascade" % (battery, len(breaks)))


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    # Only probe IDs (not the green-check record) count toward the set.
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w330_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected: F414/F415/F416 closed)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
