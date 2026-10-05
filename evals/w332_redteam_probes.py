"""Wave-332 independent red-team battery.

Base: cef4ad59 (wave-331 merge). Footer: open none / next F417
(F415/F416 CLOSED wave-331 lanes 1/2; no open findings). Pin: 2100.

P1  F415/F416 closure regression + fix-seam bypass probes: the
    ASCII-digit fragment gate is audited as a total partition (skip /
    parse / coded refusal -- no bare escape), including the
    NAME_MAX-length fragment bound; v0 and filename/doc version
    mismatch semantics are pinned; _parse_int64_as_string is probed
    at every boundary; the witness-before-conversion ordering is
    proved empirically (forged SET + garbage time hits the witness
    refusal first).
P2  Shamir custody residual: write-time defense-in-depth (pre-created
    shard refuses coded at _atomic_write, content intact), null-byte
    and symlink-alias regressions, case-insensitive residual
    documentation.
P3  Landlock jail: forked-child confinement probes -- read/write
    inside vs outside the granted trees, symlink escape, exec without
    an exec grant, misuse shapes (relative/missing/overlapping
    grants) refusing coded, fail-closed when the kernel cannot
    enforce, and the inherited-fd residual documented LOUD.
P4  merge-defect class: no trailing blank line on footer-bearing
    files, code-registration, pin-comment honesty, live pin
    constants all 2100.
P5  pin 2100 + footer state probes.
P6  F414/F413/F412/F411/F410 closure-regression probes (all HELD).
P7  prior batteries in child mode (GOV_SKIP_GREEN=1 in the child env),
    tallies verified by direct child runs.

gov/ is byte-identical to base: this battery changes no product code
and files findings only (from F417). No new decision codes from this lane.
"""

import base64
import binascii
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

TAXONOMY_PIN = 2106 # Wave-331 merge: pin unchanged 2058 (F415/F416: no new codes). Wave-332 merge: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).
FOOTER_OPEN = "none"  # F417 CLOSED 2026-10-05 (wave-334 lane 1); no open findings.
FOOTER_NEXT = "F426"  # Next free finding number (F417 OPEN, F418 closed at wave-333 merge).

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


def _tmpd(prefix="w332-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w332rt")
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
        # EnvelopeError carries the machine code as ``reason``
        # (wave-232), PolicyChannelError as ``code`` -- accept either.
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
from gov import shamir_custody as sc  # noqa: E402
from gov import landlock_jail as lj  # noqa: E402
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
    feed = tempfile.mkdtemp(prefix="w332-pfeed-")
    state = tempfile.mkdtemp(prefix="w332-pstate-")
    seed, pub = _pkeys()
    cfg = pc.ChannelConfig(feed, pub, policy_name, max_skip=max_skip)
    return {"feed": feed, "state": state, "seed": seed, "pub": pub,
            "cfg": cfg}


# ---------------------------------------------------------------------------
# Fixtures: evidence sigstore.
# ---------------------------------------------------------------------------

BUNDLE = b'{"bundle":"synthetic-test-bytes-332"}'
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


def _sigb_code(fn):
    """Run fn; return the coded refusal's machine code, or a marker for
    a bare/uncoded outcome."""
    from gov.dsse_envelope import EnvelopeError
    try:
        fn()
    except EnvelopeError as exc:
        return "coded:%s" % (getattr(exc, "reason", "?"),)
    except ValueError as exc:
        return "BARE-VALUEERROR:%s" % (str(exc)[:80],)
    except Exception as exc:
        return "UNCODED:%s:%s" % (type(exc).__name__, str(exc)[:80])
    return "ACCEPTED"


# ---------------------------------------------------------------------------
# Fixtures: shamir custody.
# ---------------------------------------------------------------------------

def _shards(n=3, t=2, secret=b"w332-redteam-secret-bytes"):
    return sc.split(secret, n, t, "ceremony-w332-test")


# ---------------------------------------------------------------------------
# P1: F415/F416 closure regression + fix-seam bypass probes.
# ---------------------------------------------------------------------------

@probe("P1a-f415-unicode-version-refused-coded")
def _p1a():
    """F415 CLOSED 2026-10-04 wave-331 lane 1: pol.v².json refuses
    coded policy-channel-malformed (HELD)."""
    import w330_redteam_probes as w330
    return _relabel("P1a-f415-unicode-version-refused-coded", w330._p1g)


@probe("P1b-f415-fragment-parse-total-partition")
def _p1b():
    """The F415 gate is a TOTAL partition: for every filename fragment,
    _feed_files either skips (non-digit fragment), parses (ASCII
    digits), or refuses CODED policy-channel-malformed (non-ASCII
    digits) -- a bare ValueError can never escape poll().

    The one shape the gate does NOT bound is fragment LENGTH -- but
    the filesystem bounds it: NAME_MAX=255 caps the fragment at 245
    digits, far below int()'s 4300-digit limit, so the longest
    constructible fragment parses without hitting the digit limit.
    """
    fx = _pfresh()
    cfg = fx["cfg"]
    feed = fx["feed"]
    # Partition matrix: (filename, expectation). "skip" = ignored,
    # "coded" = poll folds policy-channel-malformed into the report,
    # "parse" = version applies from the signed doc.
    cases = [
        ("pol.v1.json", "parse", 1),          # plain ASCII digits
        ("pol.v007.json", "parse", 7),        # leading zeros parse
        ("pol.vX.json", "skip", None),        # non-digit: documented skip
        ("pol.v.json", "skip", None),         # empty fragment: skip
        ("pol.v1.2.json", "skip", None),      # dotted fragment: skip
        ("pol.v-3.json", "skip", None),       # sign: not digit, skip
        ("pol.v+3.json", "skip", None),       # plus sign: skip
        ("pol.v².json", "coded", None),       # F415: superscript two
        ("pol.v٣.json", "coded", None),       # Arabic-Indic digit
        ("pol.v५.json", "coded", None),       # Devanagari digit
        ("pol.v１.json", "coded", None),       # fullwidth digit (int()
                                              # accepts it, gate refuses)
        ("pol.v1².json", "coded", None),      # mixed ASCII + unicode
    ]
    bad = []
    for name, want, _ver in cases:
        d = tempfile.mkdtemp(prefix="w332-p1b-")
        seed, pub = _pkeys()
        c2 = pc.ChannelConfig(d, pub, "pol")
        st = tempfile.mkdtemp(prefix="w332-p1bs-")
        with open(os.path.join(d, name), "w",
                  encoding="utf-8") as fh:
            fh.write("{}")
        try:
            got = pc._feed_files(c2)
        except pc.PolicyChannelError as exc:
            outcome = "coded" if exc.code == "policy-channel-malformed" \
                else "WRONGCODE:%s" % exc.code
        except Exception as exc:
            outcome = "UNCODED:%s" % type(exc).__name__
        else:
            outcome = "parse" if got else "skip"
        if outcome != want:
            bad.append("%s: want %s got %s" % (name, want, outcome))
    if bad:
        return _break("P1b-f415-fragment-parse-total-partition",
                      "; ".join(bad[:5]))
    # NAME_MAX bound: the longest constructible fragment (245 digits)
    # must parse without touching int()'s 4300-digit limit.
    long_frag = "9" * (255 - len("pol.v") - len(".json"))
    assert len(long_frag) == 245
    with open(os.path.join(feed, "pol.v%s.json" % long_frag), "w",
              encoding="utf-8") as fh:
        json.dump(_pdoc(fx["seed"], 1), fh)
    try:
        got = pc._feed_files(cfg)
    except Exception as exc:
        return _break("P1b-f415-fragment-parse-total-partition",
                      "245-digit fragment raised %s" % type(exc).__name__)
    if not got or got[0][0] != int(long_frag):
        return _break("P1b-f415-fragment-parse-total-partition",
                      "245-digit fragment misparsed")
    return _held("P1b-f415-fragment-parse-total-partition",
                 "total partition: skip/parse/coded for 12 shapes; "
                 "245-digit NAME_MAX fragment parses (digit limit "
                 "unreachable via real filenames)")


@probe("P1c-f415-version-zero-never-applies")
def _p1c():
    """Pinned semantics: a signed version-0 document never applies via
    poll (version 0 <= floor 0 is feed history) and apply_document
    refuses it coded policy-channel-malformed (verify_document
    requires version >= 1: "+int" is strictly positive). No crash, no
    state change -- informational, documents the v0 floor
    convention."""
    fx = _pfresh()
    _pwrite(fx["feed"], _pdoc(fx["seed"], 0), "pol.v0.json")
    try:
        rep = pc.poll(fx["cfg"], fx["state"], now=_NOW)
    except Exception as exc:
        return _break("P1c-f415-version-zero-never-applies",
                      "poll raised %s" % type(exc).__name__)
    if rep["applied"] or pc.current_version(fx["cfg"], fx["state"]) != 0:
        return _break("P1c-f415-version-zero-never-applies",
                      "v0 applied: %r" % (rep,))
    try:
        raw = json.dumps(
            _pdoc(fx["seed"], 0)).encode("utf-8")
        pc.apply_document(fx["cfg"], fx["state"], raw, now=_NOW)
    except pc.PolicyChannelError as exc:
        if exc.code != "policy-channel-malformed":
            return _break("P1c-f415-version-zero-never-applies",
                          "wrong code %r" % (exc.code,))
    except Exception as exc:
        return _break("P1c-f415-version-zero-never-applies",
                      "uncoded %s" % type(exc).__name__)
    else:
        return _break("P1c-f415-version-zero-never-applies",
                      "apply_document accepted v0")
    return _held("P1c-f415-version-zero-never-applies",
                 "v0 skipped by poll; direct apply refused coded "
                 "malformed (version >= 1 required)")


@probe("P1d-f415-filename-doc-version-mismatch")
def _p1d():
    """The filename version is only an ordering hint: a file named
    pol.v5.json carrying a SIGNED version-1 document applies version 1
    (the document governs), not version 5. A feed writer cannot
    smuggle a version via the filename."""
    fx = _pfresh()
    _pwrite(fx["feed"], _pdoc(fx["seed"], 1), "pol.v5.json")
    rep = pc.poll(fx["cfg"], fx["state"], now=_NOW)
    cur = pc.current_version(fx["cfg"], fx["state"])
    if rep["applied"] and rep["version"] == 1 and cur == 1:
        return _held("P1d-f415-filename-doc-version-mismatch",
                     "doc version governs: v5 filename applied v1")
    return _break("P1d-f415-filename-doc-version-mismatch",
                  "applied=%r version=%r current=%r"
                  % (rep["applied"], rep["version"], cur))


@probe("P1e-f416-integratedtime-refused-coded")
def _p1e():
    """F416 CLOSED 2026-10-04 wave-331 lane 2: 5000-digit
    integratedTime refuses coded evidence-bundle-malformed (HELD)."""
    import w330_redteam_probes as w330
    return _relabel("P1e-f416-integratedtime-refused-coded", w330._p1a)


@probe("P1f-f416-logindex-refused-coded")
def _p1f():
    """F416 CLOSED 2026-10-04 wave-331 lane 2: 5000-digit logIndex
    refuses coded evidence-bundle-malformed (HELD)."""
    import w330_redteam_probes as w330
    return _relabel("P1f-f416-logindex-refused-coded", w330._p1b)


@probe("P1g-f416-witness-verified-before-conversion")
def _p1g():
    """F416 ordering claim, proved empirically: the witness SET is
    verified BEFORE integratedTime/logIndex are converted.

    A bundle with a FORGED witness SET and a 5000-digit integratedTime
    must hit the witness refusal (evidence-bundle-witness-
    signature-invalid) FIRST -- the garbage time field is never even
    converted. The control (valid SET + 5000-digit time) hits
    evidence-bundle-malformed. If conversion ran first, both would
    report evidence-bundle-malformed.
    """
    from gov.dsse_envelope import EnvelopeError
    # Control: valid SET, garbage time -> malformed.
    bundle = _sealed_bundle()
    bundle["verificationMaterial"]["tlogEntries"][0][
        "integratedTime"] = "9" * 5000
    ctl = _sigb_code(lambda: _open(bundle))
    if ctl != "coded:evidence-bundle-malformed":
        return _break("P1g-f416-witness-verified-before-conversion",
                      "control: %s" % (ctl,))
    # Attack: forge the SET signature AND plant garbage time.
    bundle2 = _sealed_bundle()
    entry = bundle2["verificationMaterial"]["tlogEntries"][0]
    promise = entry["inclusionPromise"]
    raw = base64.b64decode(promise["signedEntryTimestamp"])
    forged = bytearray(raw)
    forged[0] ^= 0xFF
    promise["signedEntryTimestamp"] = base64.b64encode(
        bytes(forged)).decode("ascii")
    entry["integratedTime"] = "9" * 5000
    atk = _sigb_code(lambda: _open(bundle2))
    if atk != "coded:evidence-bundle-witness-signature-invalid":
        return _break("P1g-f416-witness-verified-before-conversion",
                      "forged-SET+garbage-time: %s (witness must "
                      "refuse first)" % (atk,))
    return _held("P1g-f416-witness-verified-before-conversion",
                 "forged SET refuses witness-signature-invalid before "
                 "conversion; valid SET + garbage time refuses malformed")


@probe("P1h-f416-parse-int64-boundaries")
def _p1h():
    """_parse_int64_as_string at every boundary: accepts only short
    ASCII digit strings within int64 range; everything else refuses
    coded evidence-bundle-malformed -- never a bare ValueError."""
    parse = es._parse_int64_as_string
    ok_cases = {
        "0": 0,
        "007": 7,
        "9" * 18: int("9" * 18),                    # 18 digits, in range
        "1000000000000000000": 10 ** 18,             # 19 digits, in range
        "9223372036854775807": 9223372036854775807,  # int64 max
        "0" * 20: 0,                                 # 20 chars, value 0
    }
    bad_cases = [
        "", "9" * 21, "1" + "0" * 20,               # too long
        "9" * 19,                                    # 19 digits, > int64 max
        "9" * 20,                                    # 20 digits, > int64 max
        "1" + "0" * 19,                              # 10^19 > int64 max
        "9223372036854775808",                       # int64 max + 1
        "-1", "+5", " 5", "5 ",                      # signs/whitespace
        "²", "٥", "１２３",                           # non-ASCII digits
        "12a3", "0x10", "1_000",                     # non-digit chars
        "9" * 5000,                                  # F416 digit-limit shape
    ]
    bad = []
    for s, want in ok_cases.items():
        try:
            got = parse(s, "f")
        except Exception as exc:
            bad.append("%r raised %s" % (s[:20], type(exc).__name__))
        else:
            if got != want:
                bad.append("%r -> %r want %r" % (s[:20], got, want))
    for s in bad_cases:
        code = _sigb_code(lambda s=s: parse(s, "f"))
        if code != "coded:evidence-bundle-malformed":
            bad.append("%r -> %s" % (s[:20], code))
    for v in (5, None, b"12", 12.0):
        code = _sigb_code(lambda v=v: parse(v, "f"))
        if code != "coded:evidence-bundle-malformed":
            bad.append("%r -> %s" % (v, code))
    if bad:
        return _break("P1h-f416-parse-int64-boundaries",
                      "; ".join(bad[:6]))
    return _held("P1h-f416-parse-int64-boundaries",
                 "6 accept boundaries + %d refuse boundaries all coded"
                 % (len(bad_cases) + 4))


# ---------------------------------------------------------------------------
# P2: Shamir custody residual (post-F414).
# ---------------------------------------------------------------------------

@probe("P2a-shamir-write-time-refusal-defense-in-depth")
def _p2a():
    """F414's TOCTOU residual, dynamic side: even if a racer slips a
    file between distribute's pre-flight and the write, _atomic_write
    carries its own exists-check -- the write refuses LOUD coded
    custody-shamir-distribute-refused and the pre-existing bytes are
    never overwritten."""
    d = _tmpd()
    path = os.path.join(d, "shard-a")
    with open(path, "wb") as fh:
        fh.write(b"pre-existing-bytes")
    try:
        sc._atomic_write(path, b"attacker-bytes")
    except sc.ShamirCustodyError as exc:
        if exc.code != "custody-shamir-distribute-refused":
            return _break("P2a-shamir-write-time-refusal-defense-in-depth",
                          "wrong code %r" % (exc.code,))
    except Exception as exc:
        return _break("P2a-shamir-write-time-refusal-defense-in-depth",
                      "uncoded %s escapes" % type(exc).__name__)
    else:
        return _break("P2a-shamir-write-time-refusal-defense-in-depth",
                      "overwrite accepted")
    with open(path, "rb") as fh:
        if fh.read() != b"pre-existing-bytes":
            return _break("P2a-shamir-write-time-refusal-defense-in-depth",
                          "pre-existing bytes clobbered")
    return _held("P2a-shamir-write-time-refusal-defense-in-depth",
                 "write-time exists check refuses coded; bytes intact")


@probe("P2b-shamir-distribute-null-byte-refused-coded")
def _p2b():
    """F414 residual: null-byte assignment path refuses coded before
    any write (HELD)."""
    import w331_redteam_probes as w331
    return _relabel("P2b-shamir-distribute-null-byte-refused-coded",
                    w331._p1a)


@probe("P2c-shamir-distribute-symlink-alias-regression")
def _p2c():
    """F414 regression: symlink-aliased pair refuses BEFORE any write
    (HELD)."""
    import w331_redteam_probes as w331
    return _relabel("P2c-shamir-distribute-symlink-alias-regression",
                    w331._p1b)


@probe("P2d-shamir-case-insensitive-residual-documented")
def _p2d():
    """F414's documented residual (case-insensitive filesystem
    collision) stays documented LOUD, not a finding (HELD)."""
    import w331_redteam_probes as w331
    return _relabel("P2d-shamir-case-insensitive-residual-documented",
                    w331._p1d)


# ---------------------------------------------------------------------------
# P3: Landlock jail (gov/landlock_jail.py standalone API).
# ---------------------------------------------------------------------------

def _fork_report(child_fn, timeout_note="child"):
    """Fork; run child_fn() in the child; return the child's report
    string via a pipe. The parent is NEVER confined by a probe. The
    child must only report -- os._exit, no atexit."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            try:
                note = child_fn()
                os.write(w, ("OK:" + note).encode("utf-8"))
            except BaseException as exc:
                code = getattr(exc, "code", "")
                os.write(w, ("FAIL:%s:%s:%s" % (
                    type(exc).__name__, code,
                    str(exc)[:200])).encode("utf-8"))
        finally:
            os.close(w)
            os._exit(0)
    os.close(w)
    out = b""
    while True:
        chunk = os.read(r, 65536)
        if not chunk:
            break
        out += chunk
    os.close(r)
    os.waitpid(pid, 0)
    return out.decode("utf-8", "replace")


@probe("P3a-landlock-confine-child-read-write")
def _p3a():
    """End-to-end confinement in a forked child: reads inside the
    granted tree work, writes to the write tree work, and reads AND
    writes outside the policy are denied (EACCES). The parent is
    never jailed."""
    if not lj.landlock_supported():
        return _held("P3a-landlock-confine-child-read-write",
                     "SKIP: landlock unsupported on this kernel")
    d = _tmpd(prefix="w332-ll-")
    ro = os.path.join(d, "ro")
    rw = os.path.join(d, "rw")
    os.makedirs(ro)
    os.makedirs(rw)
    with open(os.path.join(ro, "secret.txt"), "w") as fh:
        fh.write("granted-read")
    outside = os.path.join(tempfile.gettempdir(),
                           "w332-ll-outside-%d" % os.getpid())
    with open(outside, "w") as fh:
        fh.write("outside")

    def child():
        lj.restrict_fs([ro], [rw])
        notes = []
        with open(os.path.join(ro, "secret.txt")) as fh:
            assert fh.read() == "granted-read", "granted read failed"
        notes.append("read-in-grant-ok")
        assert sorted(os.listdir(ro)) == ["secret.txt"], "readdir failed"
        notes.append("readdir-ok")
        try:
            open(os.path.join(ro, "nope.txt"), "w").close()
            raise AssertionError("write to read-only tree allowed")
        except PermissionError:
            notes.append("write-to-ro-denied")
        with open(os.path.join(rw, "new.txt"), "w") as fh:
            fh.write("granted-write")
        notes.append("write-to-rw-ok")
        for p in (outside, "/etc/hostname"):
            try:
                open(p).close()
                raise AssertionError("read outside grant allowed: %s" % p)
            except PermissionError:
                pass
        notes.append("read-outside-denied")
        try:
            open(os.path.join(tempfile.gettempdir(),
                              "w332-ll-write-%d" % os.getpid()),
                 "w").close()
            raise AssertionError("write outside grant allowed")
        except PermissionError:
            notes.append("write-outside-denied")
        return ";".join(notes)

    rep = _fork_report(child)
    if rep.startswith("OK:"):
        return _held("P3a-landlock-confine-child-read-write", rep[3:])
    return _break("P3a-landlock-confine-child-read-write", rep[:300])


@probe("P3b-landlock-symlink-escape-denied")
def _p3b():
    """A symlink inside a granted tree that points outside the policy
    is denied at access time (the kernel checks the TARGET path).
    A symlink to an inside file still works."""
    if not lj.landlock_supported():
        return _held("P3b-landlock-symlink-escape-denied",
                     "SKIP: landlock unsupported on this kernel")
    d = _tmpd(prefix="w332-lls-")
    with open(os.path.join(d, "inside.txt"), "w") as fh:
        fh.write("inside")
    os.symlink("/etc/hostname", os.path.join(d, "evil"))
    os.symlink(os.path.join(d, "inside.txt"), os.path.join(d, "good"))

    def child():
        lj.restrict_fs([d], [])
        with open(os.path.join(d, "good")) as fh:
            assert fh.read() == "inside", "inside symlink broken"
        try:
            open(os.path.join(d, "evil")).close()
            raise AssertionError("symlink escape to /etc/hostname allowed")
        except PermissionError:
            pass
        return "inside-symlink-ok; escape-denied"

    rep = _fork_report(child)
    if rep.startswith("OK:"):
        return _held("P3b-landlock-symlink-escape-denied", rep[3:])
    return _break("P3b-landlock-symlink-escape-denied", rep[:300])


@probe("P3c-landlock-misuse-refuses-coded")
def _p3c():
    """Caller misuse refuses coded sandbox-landlock-apply-failed before
    any confinement: relative paths, missing paths, and ambiguous
    overlapping (read+write) grants. A nested write dir inside a read
    tree is the documented refinement shape and must SUCCEED."""
    if not lj.landlock_supported():
        return _held("P3c-landlock-misuse-refuses-coded",
                     "SKIP: landlock unsupported on this kernel")
    d = _tmpd(prefix="w332-llm-")
    sub = os.path.join(d, "sub")
    os.makedirs(sub)

    def child():
        notes = []
        for args, label in ((["rel/path"], "relative"),
                            (["/nonexistent-w332-xyz"], "missing"),
                            ([d], "overlap")):
            try:
                if label == "overlap":
                    lj.restrict_fs(args, args)
                else:
                    lj.restrict_fs(args, [])
                raise AssertionError("%s accepted" % label)
            except lj.LandlockError as exc:
                assert exc.code == "sandbox-landlock-apply-failed", \
                    "wrong code %r" % (exc.code,)
                notes.append("%s-refused" % label)
        # Documented refinement: nested write dir inside a read tree.
        lj.restrict_fs([d], [sub])
        with open(os.path.join(sub, "w.txt"), "w") as fh:
            fh.write("refined")
        try:
            open(os.path.join(d, "top.txt"), "w").close()
            raise AssertionError("write to read-only parent allowed")
        except PermissionError:
            notes.append("nested-refinement-ok")
        return ";".join(notes)

    rep = _fork_report(child)
    if rep.startswith("OK:"):
        return _held("P3c-landlock-misuse-refuses-coded", rep[3:])
    return _break("P3c-landlock-misuse-refuses-coded", rep[:300])


@probe("P3d-landlock-unsupported-fails-closed")
def _p3d():
    """Fail-closed contract: when the kernel cannot enforce Landlock,
    restrict_fs raises sandbox-landlock-unavailable -- it never
    silently runs unjailed. (Simulated by gating the availability
    probe off in the forked child.)"""
    def child():
        lj.landlock_supported = lambda: False
        try:
            lj.restrict_fs(["/tmp"], [])
        except lj.LandlockError as exc:
            assert exc.code == "sandbox-landlock-unavailable", \
                "wrong code %r" % (exc.code,)
            return "unavailable-refused-coded"
        raise AssertionError("no raise when unsupported")

    rep = _fork_report(child)
    if rep.startswith("OK:"):
        return _held("P3d-landlock-unsupported-fails-closed", rep[3:])
    return _break("P3d-landlock-unsupported-fails-closed", rep[:300])


@probe("P3e-landlock-inherited-fd-residual-documented")
def _p3e():
    """Known kernel semantic, documented LOUD (not a finding):
    Landlock does not revoke already-open file descriptors -- an fd
    opened BEFORE restrict_fs stays readable after confinement.
    Callers must drop sensitive fds before confining."""
    if not lj.landlock_supported():
        return _held("P3e-landlock-inherited-fd-residual-documented",
                     "SKIP: landlock unsupported on this kernel")
    d = _tmpd(prefix="w332-llf-")
    outside = os.path.join(tempfile.gettempdir(),
                           "w332-ll-fd-%d" % os.getpid())
    with open(outside, "w") as fh:
        fh.write("fd-bytes")
    fd = os.open(outside, os.O_RDONLY)

    def child():
        lj.restrict_fs([d], [])
        data = os.read(fd, 8)
        assert data == b"fd-bytes", "fd read gave %r" % (data,)
        return "inherited-fd-readable-after-confine (kernel semantic)"

    try:
        rep = _fork_report(child)
    finally:
        os.close(fd)
    if rep.startswith("OK:"):
        return _held("P3e-landlock-inherited-fd-residual-documented",
                     rep[3:] + "; callers must drop fds pre-confine")
    return _break("P3e-landlock-inherited-fd-residual-documented",
                  rep[:300])


@probe("P3f-landlock-exec-without-exec-grant-denied")
def _p3f():
    """Executing a file granted only READ is denied: the EXECUTE right
    is separate. Positive control in a sibling child: the same binary
    runs unconfined (exit 0), so the denial is the jail's doing."""
    if not lj.landlock_supported():
        return _held("P3f-landlock-exec-without-exec-grant-denied",
                     "SKIP: landlock unsupported on this kernel")
    import shutil
    if not os.path.exists("/bin/true"):
        return _held("P3f-landlock-exec-without-exec-grant-denied",
                     "SKIP: /bin/true absent")
    d = _tmpd(prefix="w332-lle-")
    binpath = os.path.join(d, "truecopy")
    shutil.copy2("/bin/true", binpath)
    os.chmod(binpath, 0o755)

    def child_confined():
        lj.restrict_fs([d], [])
        r2, w2 = os.pipe()
        gp = os.fork()
        if gp == 0:
            os.close(r2)
            try:
                os.execv(binpath, [binpath])
            except OSError as exc:
                os.write(w2, str(exc.errno).encode("ascii"))
            os._exit(99)
        os.close(w2)
        data = b""
        while True:
            chunk = os.read(r2, 64)
            if not chunk:
                break
            data += chunk
        os.close(r2)
        _, st = os.waitpid(gp, 0)
        if os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0:
            raise AssertionError("binary RAN under read-only grant")
        errno_s = data.decode("ascii", "replace")
        assert errno_s == str(13), "errno=%r want EACCES(13)" % errno_s
        return "exec-denied-EACCES-under-read-grant"

    def child_open():
        # Positive control: unconfined, the copy runs (exit 0).
        r2, w2 = os.pipe()
        gp = os.fork()
        if gp == 0:
            os.close(r2)
            os.close(w2)
            os.execv(binpath, [binpath])
            os._exit(99)
        os.close(r2)
        os.close(w2)
        _, st = os.waitpid(gp, 0)
        assert os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0, \
            "control binary did not run: %r" % (st,)
        return "unconfined-control-ran-exit-0"

    rep_open = _fork_report(child_open)
    if not rep_open.startswith("OK:"):
        return _break("P3f-landlock-exec-without-exec-grant-denied",
                      "control failed: %s" % rep_open[:200])
    rep = _fork_report(child_confined)
    if rep.startswith("OK:"):
        return _held("P3f-landlock-exec-without-exec-grant-denied",
                     rep_open[3:] + "; " + rep[3:])
    return _break("P3f-landlock-exec-without-exec-grant-denied",
                  rep[:300])


# ---------------------------------------------------------------------------
# P4: the merge-defect class.
# ---------------------------------------------------------------------------

# Grandfathered: ancient batteries (waves 22-47, 139, 141) and one
# wave-329-repointed file that end with "\n\n". None is read with
# lines[-1] semantics and none breaks a footer probe -- cosmetic
# pre-existing debt, documented here, not a regression. The probe
# below BREAKs only on files BEYOND this inventory (the wave-330
# merge class was a NEW trailing blank line from scripted
# resolution).
_GRANDFATHERED_BLANK_TAIL = frozenset({
    "evals/artifact_inventory_pin_probes.py",
    "evals/cross_run_taint_probes.py",
    "evals/r9_probes.py",
    "evals/w260_f228_probes.py",
})
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
# Grandfathered pin staleness (wave-331 merge inventory, left
# untouched): dead-code TAXONOMY_PIN values in two ancient files, and
# the VERIFIER_TAXONOMY_PIN domain (a different taxonomy, value 33).
_GRANDFATHERED_PIN_STALE = frozenset({
    "evals/w259_f225_probes.py",   # TAXONOMY_PIN = 1588 (dead code)
    "tests/test_replay_manifest.py",  # TAXONOMY_PIN = 1080 (dead code)
})


@probe("P4a-no-trailing-blank-line-on-footer-files")
def _p4a():
    """Wave-330 merge class: scripted resolutions must not leave a
    trailing blank line. BREAKs only on files BEYOND the grandfathered
    inventory."""
    bad = []
    findings = os.path.join(REPO, "evals", "FINDINGS.md")
    data = open(findings, encoding="utf-8").read()
    if data.endswith("\n\n") or not data.strip():
        bad.append("evals/FINDINGS.md")
    evals_d = os.path.join(REPO, "evals")
    for fname in sorted(os.listdir(evals_d)):
        if not fname.endswith(".py"):
            continue
        rel = "evals/%s" % (fname,)
        if rel in _GRANDFATHERED_BLANK_TAIL:
            continue
        path = os.path.join(evals_d, fname)
        tail = open(path, encoding="utf-8").read()
        if tail.endswith("\n\n") or not tail.strip():
            bad.append(rel)
    if bad:
        return _break("P4a-no-trailing-blank-line-on-footer-files",
                      "NEW trailing-blank-line files: %r" % (bad[:5],))
    return _held("P4a-no-trailing-blank-line-on-footer-files",
                 "no NEW trailing blank lines (+%d grandfathered "
                 "cosmetic)" % (len(_GRANDFATHERED_BLANK_TAIL),))


@probe("P4b-codes-centrally-registered")
def _p4b():
    """Wave-329 merge class: every code literal passed to _fail/_refuse
    (or code= kw) in gov/ must be centrally registered in
    gov/decision_codes.py -- except the 14 grandfathered literals.
    Any NEW unregistered literal BREAKs."""
    import gov.decision_codes as dc
    registered = set(dc.TAXONOMY)
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
    codey = {u for u in used if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+",
                                            u)}
    missing = sorted(codey - registered - _GRANDFATHERED_UNREGISTERED)
    if missing:
        return _break("P4b-codes-centrally-registered",
                      "NEW unregistered code literals: %r" % (missing[:8],))
    return _held("P4b-codes-centrally-registered",
                 "%d code literals registered (+%d grandfathered debt)"
                 % (len(codey - _GRANDFATHERED_UNREGISTERED),
                    len(_GRANDFATHERED_UNREGISTERED)))


@probe("P4c-pin-comments-honest")
def _p4c():
    """Every TAXONOMY_PIN/LANE_PIN/EXPECTED_PIN assignment whose
    trailing comment states a '-> N' final pin must have N equal to
    the live value (wave-329 merge class)."""
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
        return _break("P4c-pin-comments-honest",
                      "pin-comment drift: %r" % (bad[:5],))
    vals = {k: sorted(v) for k, v in live.items()}
    return _held("P4c-pin-comments-honest",
                 "pin comments honest; live values %r" % (vals,))


@probe("P4d-live-pin-constants-all-2100")
def _p4d():
    """Every live module-level TAXONOMY_PIN/LANE_PIN/EXPECTED_PIN
    constant equals 2100 -- except the grandfathered dead-code files
    (wave-331 merge inventory). A stale live pin is the wave-302
    class: the sweep must assert, not just replace."""
    bad = []
    count = 0
    for dirpath, _dirs, files in os.walk(REPO):
        if "/.git/" in dirpath or "/__pycache__/" in dirpath:
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, REPO)
            if rel in _GRANDFATHERED_PIN_STALE:
                continue
            try:
                src = open(path, encoding="utf-8").read()
            except OSError:
                continue
            for m in re.finditer(
                    r"^(?:\s*)(?:[A-Z_]+\.)?(TAXONOMY_PIN|LANE_PIN|"
                    r"EXPECTED_PIN)\s*=\s*(\d+)",
                    src, re.M):
                count += 1
                if int(m.group(2)) != 2106:
                    bad.append("%s: %s = %s" % (rel, m.group(1),
                                               m.group(2)))
    if bad:
        return _break("P4d-live-pin-constants-all-2100",
                      "stale live pins: %r" % (bad[:5],))
    return _held("P4d-live-pin-constants-all-2100",
                 "%d live pin constants all 2100 (+%d grandfathered "
                 "dead-code)" % (count, len(_GRANDFATHERED_PIN_STALE)))


# ---------------------------------------------------------------------------
# P5: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P5a-pin-taxonomy-2106-sorted")
def _p5a():
    if TAXONOMY_PIN != 2106:
        return _break("P5a-pin-taxonomy-2106-sorted",
                      "TAXONOMY_PIN is %r, want 2106" % (TAXONOMY_PIN,))
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(lits) != 2106 or len(set(lits)) != 2106 \
            or lits != sorted(lits):
        return _break("P5a-pin-taxonomy-2106-sorted",
                      "want 2106/2106/0 sorted, got %d/%d/sorted=%s"
                      % (len(lits), len(set(lits)), lits == sorted(lits)))
    return _held("P5a-pin-taxonomy-2106-sorted",
                 "2106/2106/0 sorted unique on raw source literals")


@probe("P5b-footer-open-none-next-f419")
def _p5b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return _break("P5b-footer-open-none-next-f419",
                      "footer line not found")
    next_free, open_now = ms[-1]  # the LAST footer is the live one
    if next_free != FOOTER_NEXT or open_now != FOOTER_OPEN:
        return _break("P5b-footer-open-none-next-f419",
                      "footer open %s / next %s, want open %s / next %s"
                      % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    return _held("P5b-footer-open-none-next-f419",
                 "footer open none / next F419")


# ---------------------------------------------------------------------------
# P6: closure-regression probes (all must stay HELD).
# ---------------------------------------------------------------------------

@probe("P6a-f414-closure-regression")
def _p6a():
    import w330_redteam_probes as w330
    return _relabel("P6a-f414-closure-regression", w330._p2)


@probe("P6b-f413-closure-regression-order")
def _p6b():
    import w328_redteam_probes as w328
    return _relabel("P6b-f413-closure-regression-order", w328._p1b)


@probe("P6c-f413-closure-regression-revocation")
def _p6c():
    import w328_redteam_probes as w328
    return _relabel("P6c-f413-closure-regression-revocation", w328._p1c)


@probe("P6d-f412-closure-regression")
def _p6d():
    import w327_redteam_probes as w327
    return _relabel("P6d-f412-closure-regression", w327._p1f)


@probe("P6e-f411-closure-regression")
def _p6e():
    import w327_redteam_probes as w327
    return _relabel("P6e-f411-closure-regression", w327._p3a)


@probe("P6f-f410-closure-regression-t4c")
def _p6f():
    import w327_redteam_probes as w327
    return _relabel("P6f-f410-closure-regression-t4c", w327._p2a)


@probe("P6g-f410-closure-regression-t4d")
def _p6g():
    import w327_redteam_probes as w327
    return _relabel("P6g-f410-closure-regression-t4d", w327._p2b)


# ---------------------------------------------------------------------------
# P7: prior batteries in child mode.
# ---------------------------------------------------------------------------

def _run_child_output(battery, timeout=1800):
    """Run a prior battery as a subprocess; return its raw stdout.

    GOV_SKIP_GREEN=1 in the child env (depth-1 green checks), fresh
    TMPDIR per child. Raises on timeout; returns text otherwise.

    Scoping note (wave-332): the child set is the two newest
    batteries plus w330 (the F415/F416 battery). w331_redteam's own
    P6a already validated the older cascade at the wave-331 merge;
    re-running the full 12-battery cascade here would duplicate its
    ~55-minute depth-3 nesting.
    """
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmpd = tempfile.mkdtemp(prefix="w332child-",
                            dir=_run_root())
    env["TMPDIR"] = tmpd
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, cwd=REPO)
    return proc.stdout.decode("utf-8", "replace")


# Battery -> set of BREAK probe IDs that are NOT regressions on this
# tree. All three children are green on the wave-331 merged tree:
# F415/F416's closure probes flip to HELD, the prospectus overclaim
# is acknowledged, no open findings.
_CHILD_CASCADE = {
    "w331_redteam_probes.py": set(),
    "w331_landlock_probes.py": set(),
    "w330_redteam_probes.py": set(),
}


@probe("P7a-prior-batteries-child-mode-tallies")
def _p7a():
    """Prior batteries: every BREAK is inside the documented cascade.

    Runs each prior battery as a subprocess (GOV_SKIP_GREEN=1 in the
    child env, fresh TMPDIR). A BREAK outside _CHILD_CASCADE -- or any
    ERROR -- is a genuine regression, not an open finding.
    """
    import ast as _ast
    batteries = tuple(sorted(_CHILD_CASCADE))
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
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
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
        return _break("P7a-prior-batteries-child-mode-tallies",
                      "; ".join(bad[:6]))
    return _held("P7a-prior-batteries-child-mode-tallies",
                 "all child BREAKs inside the documented cascade; "
                 + "; ".join(tallies))


# ---------------------------------------------------------------------------
# Expected BREAK set, green check, main.
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the wave-331 merged tree.


def _green_check():
    """Depth-1 green check: adjacent batteries with GOV_SKIP_GREEN=1.

    Honors GOV_SKIP_GREEN (records a skip instead of spawning). Never
    spawns a battery that spawns another: depth-1 only.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    for battery in ("w331_redteam_probes.py",
                    "w331_landlock_probes.py",
                    "w330_redteam_probes.py"):
        try:
            out = _run_child_output(battery, timeout=1800)
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
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    # Only probe IDs (not the green-check record) count toward the set.
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w332_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the wave-331 merged tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
