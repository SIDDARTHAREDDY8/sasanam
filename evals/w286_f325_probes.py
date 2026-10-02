"""Wave-286 lane 1 red-first battery: F325 ReDoS gate in gov/attack_manifest.py.

Base: wave-285 push 76e0f2425f64484f3e10b339f2962fde3bef0b45
(verified via git rev-parse HEAD before work).

F325 (LOW): validate_template ran re.compile only on matcher/extractor
regexes, so nested-quantifier shapes like ^(a+)+$ were accepted; at run
time a 29-byte non-matching observation took 17.34 s (~1.85x/byte
exponential backtracking). The fix is a load-time static gate
(manifest-regex-unsafe): any repetition applied to a nullable,
ambiguous, or self-overlapping operand is refused with a coded refusal.

Red-first: on the pristine base this battery BREAKs (evil patterns
accepted); after the fix every probe HELDs.

$0 spend, synthetic/local, deterministic (no wall-clock equality
assertions; the one timing probe asserts a >8x scaling ratio where the
defect produces ~300x, so machine noise cannot flip it). Stdlib only,
no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g286-f325 && TMPDIR=/var/tmp/g286-f325 \
    ~/workspace/.gov-venv/bin/python evals/w286_f325_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g286-f325b \
    ~/workspace/.gov-venv/bin/python evals/w286_f325_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-286 lane 1: pin 1641 -> 1642 (+1 manifest-regex-unsafe, F325 gate).
TAXONOMY_PIN = 1730

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    if "manifest-regex-unsafe" not in lits:
        return _record("pin-taxonomy", "BREAK",
                       "manifest-regex-unsafe literal missing")
    _record("pin-taxonomy", "HELD", "1642/1642/0 sorted")


def _template(pattern, extractor=False):
    base = {
        "id": "f325-probe", "version": "1.0.0",
        "info": {"name": "r", "author": ["x"], "severity": "low",
                 "description": "d", "reference": [], "tags": ["t"],
                 "protocol": None, "metadata": {}},
    }
    if extractor:
        base["matchers"] = [{"type": "word", "words": ["x"]}]
        base["extractors"] = [{"type": "regex", "name": "e",
                               "pattern": pattern}]
    else:
        base["matchers"] = [{"type": "regex", "pattern": pattern}]
        base["extractors"] = []
    return base


def _expect_refused(pid, pattern, extractor=False):
    from gov import attack_manifest as am
    try:
        am.validate_template(_template(pattern, extractor=extractor))
    except Exception as e:  # noqa: BLE001 - any refusal counts; code checked
        code = getattr(e, "code", type(e).__name__)
        if code != "manifest-regex-unsafe":
            return _record(pid, "BREAK",
                           "refused but with wrong code %r (want "
                           "manifest-regex-unsafe)" % (code,))
        if not isinstance(e, am.ManifestError):
            return _record(pid, "BREAK",
                           "refusal is not a ManifestError: %r"
                           % (type(e).__name__,))
        return _record(pid, "HELD",
                       "evil pattern refused: %s" % (code,))
    _record(pid, "BREAK", "evil pattern accepted: %r" % (pattern,))


def p_evil_matcher_refused():
    # The exact red-team shape: ^(a+)+$ on a 29-byte observation took
    # 17.34 s pre-fix.
    _expect_refused("f325-evil-matcher", r"^(a+)+$")


def p_evil_extractor_refused():
    _expect_refused("f325-evil-extractor", r"(a+)+$", extractor=True)


# Known-evil shapes, each verified red on the pristine base (accepted
# pre-fix) and refused post-fix. The set covers nested quantifiers,
# nullable-inner repetition, ambiguous alternation, and bounded-repeat
# nesting.
_EVIL_VARIANTS = [
    r"(a+)+",
    r"(a*)*",
    r"(a|a)+",
    r"(a|aa)+$",
    r"([a-z]+\s*)+",
    r"(a+)+b",
    r"(.*a)+",
    r"(a+){2,}",
    r"(a+){2,5}",
    r"(\w+\d*)+",
    r"(x*)+y",
]


def p_evil_variants_refused():
    from gov import attack_manifest as am
    bad = []
    for pat in _EVIL_VARIANTS:
        try:
            am.validate_template(_template(pat))
            bad.append(pat)
        except am.RegexUnsafe:
            pass
        except am.ManifestError as e:
            bad.append("%s (wrong code %s)" % (pat, e.code))
    if bad:
        return _record("f325-evil-variants", "BREAK",
                       "accepted evil shapes: %r" % (bad,))
    _record("f325-evil-variants", "HELD",
            "%d evil shapes refused" % (len(_EVIL_VARIANTS),))


# Benign shapes that MUST keep working: realistic nuclei-style
# patterns plus near-miss shapes the analyzer must not over-refuse
# ((ab+)+, (\d{4})+, (a|ab)+ are linear -- verified empirically).
_BENIGN = [
    r"cipher[=:]\s*\S+",
    r"cipher[=:]\s*(\S+)",
    r"(x)",
    r"\d{4}-\d{2}-\d{2}",
    r"\"token\":\s*\"[^\"]+\"",
    r"(foo|bar)+",
    r"[a-f0-9]{64}",
    r"\d+\.\d+",
    r"^[a-z]+$",
    r"(?:ab|cd){2}",
    r"(ab+)+",
    r"(\d{4})+",
    r"admin",
    r"(a|ab)+",
    r"password\s*=\s*.+",
    r"[A-Z][a-z]+",
]


def p_benign_patterns_accepted():
    from gov import attack_manifest as am
    bad = []
    for pat in _BENIGN:
        try:
            am.validate_template(_template(pat))
        except am.ManifestError as e:
            bad.append("%s (%s)" % (pat, e.code))
    if bad:
        return _record("f325-benign", "BREAK",
                       "over-refused benign patterns: %r" % (bad,))
    _record("f325-benign", "HELD",
            "%d benign patterns accepted" % (len(_BENIGN),))


def p_engine_blowup_documents_threat():
    # Documents that the threat is real on the stdlib engine: 18 vs 26
    # a's must scale super-linearly (defect measured ~1.85x/byte, so
    # 8 extra bytes expect ~256x; assert >8x so machine noise cannot
    # flip the probe).
    pat = r"^(a+)+$"
    t0 = time.perf_counter()
    re.search(pat, "a" * 18 + "b")
    t1 = time.perf_counter()
    re.search(pat, "a" * 26 + "b")
    t2 = time.perf_counter()
    small, big = t1 - t0, t2 - t1
    ratio = big / max(small, 1e-9)
    if ratio < 8:
        return _record("f325-engine-blowup", "BREAK",
                       "no super-linear blowup (ratio %.1f); threat "
                       "model unconfirmed on this engine" % (ratio,))
    _record("f325-engine-blowup", "HELD",
            "stdlib engine blowup confirmed (18B: %.3fs, 26B: %.3fs, "
            "ratio %.0fx)" % (small, big, ratio))


def p_refusal_contract():
    # The refusal honors the repo's coded-refusal contract: a
    # ManifestError (ValueError family) carrying the exact code, and
    # the code is registered in the taxonomy.
    from gov import attack_manifest as am
    try:
        am.validate_template(_template(r"^(a+)+$"))
    except am.RegexUnsafe as e:
        assert e.code == "manifest-regex-unsafe", e.code
        assert isinstance(e, am.ManifestError), type(e)
        assert isinstance(e, ValueError), type(e)
        assert "manifest-regex-unsafe" in _literals()
        return _record("f325-refusal-contract", "HELD",
                       "coded ManifestError manifest-regex-unsafe, "
                       "registered in taxonomy")
    except am.ManifestError as e:  # noqa: BLE001
        return _record("f325-refusal-contract", "BREAK",
                       "wrong ManifestError code: %r" % (e.code,))
    _record("f325-refusal-contract", "BREAK", "no refusal raised")


def p_deep_nesting_refused():
    # Pathological group nesting must surface as the coded refusal,
    # never an uncaught RecursionError (the re module accepts deeper
    # nesting than a recursive-descent parser can survive).
    from gov import attack_manifest as am
    pat = "(" * 200 + "a" + ")" * 200
    try:
        am.validate_template(_template(pat))
    except am.RegexUnsafe as e:
        assert e.code == "manifest-regex-unsafe", e.code
        return _record("f325-deep-nesting", "HELD",
                       "200-deep nesting refused: %s" % (e.code,))
    except RecursionError:
        return _record("f325-deep-nesting", "BREAK",
                       "uncaught RecursionError on deep nesting")
    except am.ManifestError as e:  # noqa: BLE001
        return _record("f325-deep-nesting", "BREAK",
                       "wrong code on deep nesting: %r" % (e.code,))
    _record("f325-deep-nesting", "BREAK", "deep nesting accepted")


# ---------------------------------------------------------------------------
# Depth-1 green checks (GOV_SKIP_GREEN=1 in the child env; never nested).
# ---------------------------------------------------------------------------

_GREEN = [
    # (argv, expected_breaks, label, kind)
    ([sys.executable, "-m", "unittest", "tests.test_attack_manifest"],
     0, "unit-attack-manifest", "unittest"),
    ("evals/w284_nuclei_probes.py", 0, "nuclei-battery", "battery"),
    # Wave-286 merge: F325-F330 all CLOSED; 0 BREAK expected.
    ("evals/w285_redteam_probes.py", 0, "w285-redteam", "battery"),
    ("evals/w284_redteam_probes.py", 0, "w284-redteam", "battery"),
]


def _run_green():
    for target, expected, label, kind in _GREEN:
        d = tempfile.mkdtemp(prefix="w286-f325-green-")
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                   GOV_RUN_ROOT=os.path.join(d, "gov-run"))
        try:
            if kind == "unittest":
                proc = subprocess.run(target, capture_output=True, text=True,
                                      timeout=600, cwd=REPO, env=env)
                nbreak = 0 if proc.returncode == 0 else 1
            else:
                proc = subprocess.run(
                    [sys.executable, os.path.join(REPO, target)],
                    capture_output=True, text=True, timeout=600, env=env)
                out = proc.stdout + proc.stderr
                # The footer ("<name>: N BREAK / ...") is the last
                # "<digits> BREAK" in the output; probe notes may embed
                # their own counts earlier (e.g. "1 BREAK, expected 0").
                ms = re.findall(r"(\d+)\s+BREAK", out)
                nbreak = int(ms[-1]) if ms else -1
        except Exception as e:  # noqa: BLE001
            _record("green-" + label, "ERROR", "subprocess failed: %r"
                    % (e,))
            continue
        if nbreak == expected:
            _record("green-" + label, "HELD",
                    "%s: %d BREAK as expected" % (label, nbreak))
        else:
            _record("green-" + label, "BREAK",
                    "%s: %d BREAK, expected %d" % (label, nbreak, expected))


def main():
    p_taxonomy_pin()
    p_evil_matcher_refused()
    p_evil_extractor_refused()
    p_evil_variants_refused()
    p_benign_patterns_accepted()
    p_engine_blowup_documents_threat()
    p_refusal_contract()
    p_deep_nesting_refused()
    if not SKIP_GREEN:
        _run_green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("%-28s %-6s %s" % (pid, verdict, note))
    print("%d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
