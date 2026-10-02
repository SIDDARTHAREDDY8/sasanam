"""Break-first battery for gov/encrypted_envelopes.py (wave-257 lane 1).

FiloSottile/age ADAPT (pattern only; BSD-3-Clause): recipient-based
encrypted evidence envelopes -- the encryption half to cosign's
signature half. Multi-recipient sealed envelopes with an open,
versioned format; fail-closed opens; a digest-only audit journal.

Red-first discipline: every probe is GAP on a pristine base (module
absent), HELD when the implementation holds, BREAK when a break
attempt succeeds. A genuine BREAK against the final implementation
would file a finding; this battery must be all HELD on the shipped
module.

Related prospectus gap: W256-1 (wave-256 prospectus). Next free: F220.
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1541  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*)

try:
    from gov import decision_codes
    from gov import encrypted_envelopes as ee
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

if HAVE_MODULE:
    # Wave-258 merge: pin -> 1080.
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN,\
        "taxonomy drift: %d != %d" % (len(decision_codes.TAXONOMY),
                                      TAXONOMY_PIN)

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _vault():
    d = tempfile.mkdtemp(prefix="w257env-")
    return ee.EnvelopeVault(os.path.join(d, "envelopes.jsonl")), d


def _recips(n=2):
    return [ee.Recipient("auditor-%d" % i, b"recipient-key-%d" % i * 4)
            for i in range(n)]


_PAYLOAD = b'{"bundle": "evidence", "finding": "F219", "host": "h"}'


def _sealed(n=2, payload=_PAYLOAD):
    v, d = _vault()
    env = v.seal(payload, _recips(n))
    return v, d, env


def _expect_code(fn, code):
    try:
        fn()
    except ee.EnvelopeError as exc:
        return "HELD" if exc.code == code else "BREAK(code=%s)" % exc.code
    except Exception as exc:  # never mask a crash
        return "BREAK(%r)" % (exc,)
    return "BREAK(no-raise)"


@probe
def p_tag_tamper_refused():
    """Flipping one ciphertext byte must fail the tag check -- the
    tampered envelope must not open, and must not leak which check
    failed. The tag is the trailing 32 bytes by format, so the last
    ciphertext byte is layout-independent."""
    v, _d, env = _sealed()
    tampered = bytearray(env)
    tampered[len(tampered) - 33] ^= 0x01  # last ct byte, before tag
    key = b"recipient-key-0" * 4
    return _expect_code(lambda: v.open(bytes(tampered), key),
                        "envelope-open-refused")


@probe
def p_wrong_key_refused():
    """Opening with the wrong key material must refuse with the
    generic open code."""
    v, _d, env = _sealed()
    return _expect_code(lambda: v.open(env, b"wrong-key-material!!"),
                        "envelope-open-refused")


@probe
def p_unknown_recipient_refused():
    """Key material for a recipient never listed in the envelope must
    refuse with the SAME generic code as a wrong key -- recipient
    membership must not leak."""
    v, _d, env = _sealed()
    return _expect_code(lambda: v.open(env, b"recipient-key-99" * 4),
                        "envelope-open-refused")


@probe
def p_truncated_envelope_refused():
    """A torn/truncated envelope must be structurally refused, never
    partially read."""
    v, _d, env = _sealed()
    return _expect_code(lambda: v.open(env[:len(env) // 2],
                                       b"recipient-key-0" * 4),
                        "envelope-malformed")


@probe
def p_multi_recipient_each_opens():
    """Every listed recipient must independently recover the exact
    payload; metadata must name the matching recipient."""
    v, _d, env = _sealed(n=3)
    for i in range(3):
        payload, meta = v.open(env, b"recipient-key-%d" % i * 4)
        if payload != _PAYLOAD:
            return "BREAK(payload-mismatch-%d)" % i
        if meta.get("recipient_id") != "auditor-%d" % i:
            return "BREAK(meta-recipient-%d)" % i
    return "HELD"


@probe
def p_reseal_randomized():
    """Sealing the same payload twice must produce different envelope
    bytes (fresh envelope key per seal), both opening to the payload."""
    v, _d, env1 = _sealed()
    env2 = v.seal(_PAYLOAD, _recips())
    if env1 == env2:
        return "BREAK(deterministic-seal)"
    p1, _m1 = v.open(env1, b"recipient-key-0" * 4)
    p2, _m2 = v.open(env2, b"recipient-key-1" * 4)
    if p1 != _PAYLOAD or p2 != _PAYLOAD:
        return "BREAK(roundtrip)"
    return "HELD"


@probe
def p_payload_digest_matches():
    """sha256 of the opened payload must equal sha256 of the sealed
    payload -- integrity as received."""
    v, _d, env = _sealed()
    payload, meta = v.open(env, b"recipient-key-0" * 4)
    want = hashlib.sha256(_PAYLOAD).hexdigest()
    if hashlib.sha256(payload).hexdigest() != want:
        return "BREAK(digest)"
    if meta.get("payload_digest") != want:
        return "BREAK(meta-digest)"
    return "HELD"


@probe
def p_journal_no_plaintext_no_keys():
    """The audit journal must carry digests only: the raw journal bytes
    must contain neither the payload plaintext nor any key material,
    and must contain the envelope digest."""
    v, d, env = _sealed()
    v.open(env, b"recipient-key-0" * 4)
    with open(os.path.join(d, "envelopes.jsonl"), "rb") as fh:
        raw = fh.read()
    if _PAYLOAD in raw:
        return "BREAK(plaintext-in-journal)"
    if b"recipient-key-0" * 4 in raw:
        return "BREAK(key-in-journal)"
    if hashlib.sha256(env).hexdigest().encode() not in raw:
        return "BREAK(no-envelope-digest)"
    return "HELD"


@probe
def p_unknown_version_refused():
    """An envelope with an unknown version must refuse before any
    cryptographic work."""
    v, _d, env = _sealed()
    forged = bytearray(env)
    forged[8:10] = b"\x00\x02"  # version field after the 8-byte magic
    return _expect_code(lambda: v.open(bytes(forged),
                                       b"recipient-key-0" * 4),
                        "envelope-version-unknown")


@probe
def p_two_recipients_one_wrong_one_right():
    """Sealed to A and B: A's key opens, a wrong key refuses; the
    refusal code is the generic one."""
    v, _d, env = _sealed(n=2)
    payload, _meta = v.open(env, b"recipient-key-0" * 4)
    if payload != _PAYLOAD:
        return "BREAK(right-key)"
    return _expect_code(lambda: v.open(env, b"nope-nope-nope-nope!"),
                        "envelope-open-refused")


@probe
def p_seal_refuses_bad_recipients():
    """Seal must refuse: empty recipient list, duplicate ids, and
    empty key material -- each with its machine code."""
    v, _d = _vault()
    r1 = _expect_code(lambda: v.seal(_PAYLOAD, []), "envelope-seal-refused")
    dup = [ee.Recipient("same", b"k" * 16), ee.Recipient("same", b"j" * 16)]
    r2 = _expect_code(lambda: v.seal(_PAYLOAD, dup), "envelope-seal-refused")
    bad = [ee.Recipient("empty-key", b"")]
    r3 = _expect_code(lambda: v.seal(_PAYLOAD, bad),
                      "envelope-recipient-refused")
    if r1 == r2 == r3 == "HELD":
        return "HELD"
    return "BREAK(%s/%s/%s)" % (r1, r2, r3)


@probe
def p_malformed_open_is_journaled():
    """A structurally malformed open attempt is still an open attempt:
    it must leave a digest-only audit record so attacker probing stays
    visible."""
    v, d, env = _sealed()
    bad = env[:len(env) // 2]
    try:
        v.open(bad, b"recipient-key-0" * 4)
        return "BREAK(no-raise)"
    except ee.EnvelopeError as exc:
        if exc.code != "envelope-malformed":
            return "BREAK(code=%s)" % exc.code
    with open(os.path.join(d, "envelopes.jsonl"), "rb") as fh:
        raw = fh.read()
    if b"open_refused" not in raw:
        return "BREAK(not-journaled)"
    if b"envelope-malformed" not in raw:
        return "BREAK(no-refusal-code)"
    if hashlib.sha256(bad).hexdigest().encode() not in raw:
        return "BREAK(no-digest)"
    if b"recipient-key-0" in raw:
        return "BREAK(key-in-journal)"
    return "HELD"


@probe
def p_failure_code_does_not_leak():
    """Wrong key, tampered tag, and unknown recipient must all raise
    the IDENTICAL code -- the failure must not leak which check or
    which recipient failed."""
    v, _d, env = _sealed()
    codes = []

    def _grab(fn):
        try:
            fn()
        except ee.EnvelopeError as exc:
            codes.append(exc.code)
        except Exception as exc:
            codes.append("CRASH:%r" % (exc,))
        else:
            codes.append("no-raise")

    _grab(lambda: v.open(env, b"wrong-key-material!!"))
    tampered = bytearray(env)
    tampered[-1] ^= 0x01  # tag byte
    _grab(lambda: v.open(bytes(tampered), b"recipient-key-0" * 4))
    _grab(lambda: v.open(env, b"recipient-key-99" * 4))
    if codes == ["envelope-open-refused"] * 3:
        return "HELD"
    return "BREAK(%r)" % (codes,)


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_durable_journal",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    base = "/var/tmp" if os.path.isdir("/var/tmp") else None
    td = tempfile.mkdtemp(prefix="g257-env-green-", dir=base)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: durable_journal + decision_codes green")
    return True


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-38s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d" % (held, brk, gap,
                                                len(results)))
    ok = green_check()
    return held, brk, gap, ok


if __name__ == "__main__":
    held, brk, gap, ok = main()
    if not HAVE_MODULE:
        sys.exit(0 if gap == len(PROBES) else 1)
    sys.exit(0 if (brk == 0 and gap == 0 and ok) else 1)
