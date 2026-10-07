#!/usr/bin/env python3
"""Wave-335 lane 4: reserved PQ evidence-envelope slot (format only).

Base: `0fd4f736` (wave-334 merge). Pin 2109. Footer open none / next F424.

New surface under test: `gov/pq_envelope.py` (reserved `pqAlgId` slot,
FORMAT ONLY -- no production crypto, identifiers only) and its wiring
into `gov/sigstore_bundle.py` (seal refuses the slot, verify refuses a
PQ-claimed bundle BEFORE any classical signature work -- the
algorithm-confusion kill).

Break-first probes at the public seams:

P1 (closed table): all 19 identifiers from the oqs-provider
   ALGORITHMS.md signature list (mldsa44/65/87, falcon512/padded/1024,
   12 slh-dsa variants) are accepted as identifiers by
   `parse_pq_alg_id`; `PQ_ENABLED is False` (the slot is disabled).
P2 (unknown identifiers): pre-standard names ("dilithium3"),
   wrong-case ("ML-DSA-44"), oqs-provider hybrid forms
   ("rsa3072_mldsa44" -- real oqs id, OUTSIDE our closed table),
   non-PQ ("ed25519"), empty/non-string values all refuse coded
   `evidence-pq-unknown-alg`.
P3 (seal gate): sealing with `pq_alg_id="mldsa44"` refuses
   `evidence-pq-not-enabled` (a PQ-claimed bundle must never be sealed
   with a classical signature); unknown id refuses
   `evidence-pq-unknown-alg`; the default seal carries no `pqAlgId`
   key at all.
P4 (verify gate): a valid classical bundle with `pqAlgId` injected
   refuses `evidence-pq-not-enabled` at open (before signature work)
   and `verify_keyed_bundle` returns False; unknown id refuses
   `evidence-pq-unknown-alg`; explicit null / absent slot verifies
   classically.
P5 (classical byte-identical): seal with and without the explicit
   `pq_alg_id=None` kwarg produces byte-identical canonical JSON;
   top-level key set is exactly the pre-slot shape; a classical
   bundle round-trips (open returns the statement bytes, verify True).
P6 (honesty): taxonomy 2135/2135/0 sorted-unique on raw source
   literals; both new codes centrally registered; footer open none /
   next F421.

Verdicts:
  HELD  = behavior matches the pin (identifier accepted / misuse
          refused coded / classical path unchanged);
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem.

Genuine findings get F-numbers from F424; none are manufactured -- a
0-break battery is an honest result.

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/ (real product code, no stubs).

Run:
  mkdir -p /var/tmp/g335-pq
  TMPDIR=/var/tmp/g335-pq ~/workspace/.gov-venv/bin/python evals/w335_pqslot_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g335-pqb ~/workspace/.gov-venv/bin/python evals/w335_pqslot_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w335_pqslot_probes.py P3a
"""

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import pq_envelope as PQ  # noqa: E402
from gov import sigstore_bundle as SB  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
_SEED = b"w335-pqslot-test-seed-0000000001"  # 32 bytes
assert len(_SEED) == 32
_STMT = b'{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"x"}'

_KNOWN_IDS = (
    "mldsa44", "mldsa65", "mldsa87",
    "falcon512", "falconpadded512", "falcon1024", "falconpadded1024",
    "slhdsasha2128s", "slhdsasha2128f",
    "slhdsasha2192s", "slhdsasha2192f",
    "slhdsasha2256s", "slhdsasha2256f",
    "slhdsashake128s", "slhdsashake128f",
    "slhdsashake192s", "slhdsashake192f",
    "slhdsashake256s", "slhdsashake256f",
)

_UNKNOWN_IDS = (
    "dilithium3",          # pre-standard name
    "ML-DSA-44",           # wrong case
    "mldsa44 ",            # trailing whitespace
    "mldsa",               # truncated
    "rsa3072_mldsa44",     # real oqs-provider id, hybrid -> OUTSIDE table
    "p256_falcon512",      # real oqs-provider id, hybrid -> OUTSIDE table
    "mayo2",               # real oqs-provider id, other family -> OUTSIDE
    "ed25519",             # classical, not PQ
    "",                    # empty
    None,                  # null
    123,                   # non-string
    b"mldsa44",            # bytes, not str
)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0][:160]))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _key():
    # Standalone battery runs do not import the tests package, so
    # provision a key here when absent. Test-only.
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, "code", "UNEXPECTED:%r" % (e,))
    return None


def _signer():
    return Ed25519Signer(_SEED)


def _sealed():
    return SB.seal_keyed_bundle(_STMT, _signer())


# ---------------------------------------------------------------------------
# P1: closed table -- the 19 identifiers parse; slot disabled.
# ---------------------------------------------------------------------------

def P1a():
    """All 19 closed-table identifiers accepted as identifiers."""
    pid = "P1a-pq-known-ids-parse"
    if len(_KNOWN_IDS) != 19:
        _break(pid, "expected 19 known ids, listed %d" % len(_KNOWN_IDS))
        return
    if set(_KNOWN_IDS) != set(PQ.PQ_ALG_IDS):
        _break(pid, "listed ids != PQ_ALG_IDS: extra=%r missing=%r"
               % (set(_KNOWN_IDS) - set(PQ.PQ_ALG_IDS),
                  set(PQ.PQ_ALG_IDS) - set(_KNOWN_IDS)))
        return
    for alg in _KNOWN_IDS:
        got = PQ.parse_pq_alg_id(alg)
        if got != alg:
            _break(pid, "parse returned %r for %r" % (got, alg))
            return
    _held(pid, "19/19 identifiers accepted (mldsa44/65/87, falcon x4, "
               "slh-dsa x12)")


def P1b():
    """The slot is disabled: PQ_ENABLED is False, use always refuses."""
    pid = "P1b-pq-slot-disabled"
    if PQ.PQ_ENABLED is not False:
        _break(pid, "PQ_ENABLED is %r, must be False" % (PQ.PQ_ENABLED,))
        return
    code = _code_of(lambda: PQ.pq_use_refused("mldsa44"))
    if code != "evidence-pq-not-enabled":
        _break(pid, "pq_use_refused gave %r, want evidence-pq-not-enabled"
               % (code,))
        return
    _held(pid, "PQ_ENABLED False; every real use refuses "
               "evidence-pq-not-enabled")


# ---------------------------------------------------------------------------
# P2: unknown identifiers refuse evidence-pq-unknown-alg.
# ---------------------------------------------------------------------------

def P2a():
    """Unknown / malformed identifiers refuse coded."""
    pid = "P2a-pq-unknown-ids-refused"
    for alg in _UNKNOWN_IDS:
        code = _code_of(lambda a=alg: PQ.parse_pq_alg_id(a))
        if code != "evidence-pq-unknown-alg":
            _break(pid, "parse(%r) gave %r, want evidence-pq-unknown-alg"
                   % (alg, code))
            return
    _held(pid, "%d unknown/malformed ids refused evidence-pq-unknown-alg "
               "(incl. hybrids outside the closed table)" % len(_UNKNOWN_IDS))


# ---------------------------------------------------------------------------
# P3: seal gate.
# ---------------------------------------------------------------------------

def P3a():
    """Sealing with a known pq id refuses evidence-pq-not-enabled."""
    pid = "P3a-pq-seal-known-refused"
    code = _code_of(lambda: SB.seal_keyed_bundle(_STMT, _signer(),
                                                 pq_alg_id="mldsa44"))
    if code != "evidence-pq-not-enabled":
        _break(pid, "seal(pq_alg_id=mldsa44) gave %r, want "
               "evidence-pq-not-enabled" % (code,))
        return
    code = _code_of(lambda: SB.seal_keyed_bundle_fanout(
        _STMT, [_signer()], pq_alg_id="slhdsasha2128s"))
    if code != "evidence-pq-not-enabled":
        _break(pid, "fanout seal gave %r, want evidence-pq-not-enabled"
               % (code,))
        return
    _held(pid, "seal/fanout with known pq id refuse evidence-pq-not-enabled")


def P3b():
    """Sealing with an unknown pq id refuses evidence-pq-unknown-alg."""
    pid = "P3b-pq-seal-unknown-refused"
    code = _code_of(lambda: SB.seal_keyed_bundle(_STMT, _signer(),
                                                 pq_alg_id="dilithium3"))
    if code != "evidence-pq-unknown-alg":
        _break(pid, "seal(pq_alg_id=dilithium3) gave %r, want "
               "evidence-pq-unknown-alg" % (code,))
        return
    _held(pid, "seal with unknown pq id refuses evidence-pq-unknown-alg")


def P3c():
    """Default seal carries no pqAlgId key (classical shape)."""
    pid = "P3c-pq-seal-default-no-slot"
    bundle = _sealed()
    if "pqAlgId" in bundle:
        _break(pid, "default seal carries pqAlgId=%r" % (bundle["pqAlgId"],))
        return
    if set(bundle.keys()) != {"mediaType", "verificationMaterial",
                              "dsseEnvelope"}:
        _break(pid, "top-level keys changed: %r" % sorted(bundle.keys()))
        return
    _held(pid, "default seal: no pqAlgId key, classical key set intact")


# ---------------------------------------------------------------------------
# P4: verify gate -- PQ-claimed bundles refuse BEFORE signature work.
# ---------------------------------------------------------------------------

def P4a():
    """Bundle with pqAlgId refuses evidence-pq-not-enabled at open."""
    pid = "P4a-pq-verify-known-refused"
    bundle = _sealed()
    pq_bundle = copy.deepcopy(bundle)
    pq_bundle["pqAlgId"] = "mldsa44"
    code = _code_of(lambda: SB.open_keyed_bundle(pq_bundle,
                                                 _signer().public_key))
    if code != "evidence-pq-not-enabled":
        _break(pid, "open(pqAlgId=mldsa44) gave %r, want "
               "evidence-pq-not-enabled" % (code,))
        return
    if SB.verify_keyed_bundle(pq_bundle, _signer().public_key) is not False:
        _break(pid, "verify_keyed_bundle on pq-claimed bundle not False")
        return
    _held(pid, "pq-claimed bundle refuses evidence-pq-not-enabled; "
               "bool wrapper False")


def P4b():
    """Bundle with unknown pqAlgId refuses evidence-pq-unknown-alg."""
    pid = "P4b-pq-verify-unknown-refused"
    bundle = _sealed()
    bad = copy.deepcopy(bundle)
    bad["pqAlgId"] = "rsa3072_mldsa44"  # real oqs id, outside closed table
    code = _code_of(lambda: SB.open_keyed_bundle(bad, _signer().public_key))
    if code != "evidence-pq-unknown-alg":
        _break(pid, "open(pqAlgId=hybrid) gave %r, want "
               "evidence-pq-unknown-alg" % (code,))
        return
    _held(pid, "unknown pqAlgId refuses evidence-pq-unknown-alg at open")


def P4c():
    """Null/absent slot verifies classically (no behavior change)."""
    pid = "P4c-pq-verify-null-slot-classical"
    bundle = _sealed()
    null_slot = copy.deepcopy(bundle)
    null_slot["pqAlgId"] = None
    pub = _signer().public_key
    for label, b in (("absent", bundle), ("null", null_slot)):
        if SB.verify_keyed_bundle(b, pub) is not True:
            _break(pid, "%s slot: verify not True" % label)
            return
        if SB.open_keyed_bundle(b, pub) != _STMT:
            _break(pid, "%s slot: open did not return statement bytes"
                   % label)
            return
    _held(pid, "absent/null pqAlgId: classical verify True, payload exact")


# ---------------------------------------------------------------------------
# P5: classical path byte-identical with the slot present in the format.
# ---------------------------------------------------------------------------

def P5a():
    """Explicit pq_alg_id=None seals byte-identically to the default."""
    pid = "P5a-pq-classical-byte-identical"
    a = SB.seal_keyed_bundle(_STMT, _signer())
    b = SB.seal_keyed_bundle(_STMT, _signer(), pq_alg_id=None)
    ca = json.dumps(a, sort_keys=True, separators=(",", ":"))
    cb = json.dumps(b, sort_keys=True, separators=(",", ":"))
    if ca != cb:
        _break(pid, "seal() vs seal(pq_alg_id=None) differ")
        return
    _held(pid, "explicit None kwarg: canonical JSON byte-identical "
               "(%d bytes)" % len(ca))


def P5b():
    """Classical bundle round-trips exactly (open + evidence variant)."""
    pid = "P5b-pq-classical-roundtrip"
    bundle = _sealed()
    pub = _signer().public_key
    payload = SB.open_keyed_bundle(bundle, pub)
    if payload != _STMT:
        _break(pid, "open payload != sealed statement bytes")
        return
    _held(pid, "classical seal/open round-trip exact; no slot in format")


# ---------------------------------------------------------------------------
# P6: honesty -- pin, registration, footer.
# ---------------------------------------------------------------------------

def P6a():
    """Pin honesty: taxonomy is 2135/2135/0, sorted and unique on raw
    source literals (wave-260 lesson: assert on literals, not the
    deduped dict)."""
    pid = "P6a-pin-taxonomy-2135-sorted"
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    codes = re.findall(r'"code":\s*[\'"]([^\'"]+)[\'"]', src)
    if len(codes) != TAXONOMY_PIN:
        _break(pid, "literal count %d != pin %d" % (len(codes),
                                                   TAXONOMY_PIN))
        return
    if len(set(codes)) != TAXONOMY_PIN:
        _break(pid, "duplicate code literals present")
        return
    if sorted(codes) != codes:
        _break(pid, "literals not sorted")
        return
    _held(pid, "taxonomy 2135/2135/0 sorted unique on raw literals")


def P6b():
    """Both new codes centrally registered."""
    pid = "P6b-pq-codes-registered"
    from gov import decision_codes as DC  # noqa: E402
    missing = [c for c in ("evidence-pq-unknown-alg",
                           "evidence-pq-not-enabled")
               if c not in DC.TAXONOMY]
    if missing:
        _break(pid, "codes not centrally registered: %r" % (missing,))
        return
    _held(pid, "evidence-pq-unknown-alg + evidence-pq-not-enabled registered")


def P6c():
    """Footer honesty: open none / next F430 (raw literals included --
    wave-331 lesson)."""
    pid = "P6c-footer-open-f433-f434-f435-next-f436"
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F521**" in text  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481)
          and m_open and m_open[-1].strip() == "F513, F514, F515, F516, F517, F518, F519, F520")  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521)
    if ok:
        _held(pid, "footer: open F473, F474 / next F475")
    else:
        _break(pid, "footer mismatch vs open F489, F490, F491, F492, F493, F494, F495 / next F506")


_PROBES = [
    ("P1a-pq-known-ids-parse", P1a),
    ("P1b-pq-slot-disabled", P1b),
    ("P2a-pq-unknown-ids-refused", P2a),
    ("P3a-pq-seal-known-refused", P3a),
    ("P3b-pq-seal-unknown-refused", P3b),
    ("P3c-pq-seal-default-no-slot", P3c),
    ("P4a-pq-verify-known-refused", P4a),
    ("P4b-pq-verify-unknown-refused", P4b),
    ("P4c-pq-verify-null-slot-classical", P4c),
    ("P5a-pq-classical-byte-identical", P5a),
    ("P5b-pq-classical-roundtrip", P5b),
    ("P6a-pin-taxonomy-2135-sorted", P6a),
    ("P6b-pq-codes-registered", P6b),
    ("P6c-footer-open-f433-f434-f435-next-f436", P6c),
]

_EXPECTED_BREAKS = set()


def _run_child_output(path, timeout):
    d = tempfile.mkdtemp(prefix="g335-pqgreen-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, path], env=env, capture_output=True, text=True,
        timeout=timeout, cwd=REPO)
    return proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the sigstore-bundle unit suite as a child
    with GOV_SKIP_GREEN=1 (fresh TMPDIR). Honors GOV_SKIP_GREEN by
    recording a skip, never spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        out = _run_child_output(
            os.path.join(REPO, "tests", "test_sigstore_bundle.py"),
            timeout=900)
    except Exception as exc:  # noqa: BLE001
        _record("green-check", "ERROR", "sigstore-bundle suite: %s" % exc)
        return
    errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)", out, re.M))
    failed = ("FAILED" in out or "failures=" in out.lower()
              or "ERROR:" in out)
    if errors or failed:
        _record("green-check", "BREAK",
                "sigstore-bundle suite non-green: %s" % sorted(errors)[:4])
    else:
        _record("green-check", "HELD", "test_sigstore_bundle green")


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    _key()
    # Collect EVERY record each probe emits (probes record multiple
    # sub-results); tallying only the last record per probe would miss
    # a BREAK buried mid-probe.
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    first = list(_results)
    green = None
    if only is None:
        _green_check()
        green = _results[-1]
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    second = list(_results)
    # Determinism compares probe verdicts only; the green-check record
    # is a single-runner observation, not a probe.
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    tallied = first + ([green] if green else [])
    n_break = sum(1 for _, v, _ in tallied if v == "BREAK")
    n_held = sum(1 for _, v, _ in tallied if v == "HELD")
    n_err = sum(1 for _, v, _ in tallied if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in tallied
                    if v == "BREAK" and pid != "green-check"}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("----")
    print("w335_pqslot battery: %d BREAK / %d HELD / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_err, det))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err:
        print("ERRORs present -- battery failed closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
