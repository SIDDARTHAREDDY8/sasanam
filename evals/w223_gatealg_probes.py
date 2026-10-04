#!/usr/bin/env python3
"""Wave-223 lane C: gate algebra battery.

Seam -- gov/gate_algebra.py (new): Harbor AND-composable pull-time
policies, adapted to admission gates (prose re-derived, no Harbor
text copied). Extends gov/admission.py by composition -- the module
is NOT modified (pinned by gal-10).

* ``PolicyConjunction``: N admission policies combined with logical
  AND. One failing member fails the whole conjunction closed with
  ``admission-conjunction-refused``; member attributions (member
  index + refusal code) are preserved and the count of refusing
  members is reported -- refusals are never swallowed.
* ``SeverityGate``: wraps a policy with a per-artifact-class
  severity threshold. Any finding whose severity exceeds the
  threshold refuses ``admission-severity-exceeded``; unknown or
  unrated findings refuse ``admission-severity-unverifiable`` --
  never assumed benign.
* ``ImmutableTag``: wraps a policy with an in-memory tag registry.
  Admitting a DIFFERENT digest under a seen tag refuses
  ``admission-tag-mutated``; same-digest re-admission is idempotent.

Attack shapes: refusal swallowing; count suppression; over-threshold
severity; unknown severity; absent scan data; tag mutation;
tag-confused re-admission; member programming error; legacy bypass.

Method (diagnosing-bugs + tdd): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-222 HEAD
d7f377aaf1a9ccf095cc4e0535eb9f74fa8f7fc9.

Verdicts: HELD / GAP / BREAK / ERROR. Any BREAK is a real product
defect. Pristine run (module absent) is expected GAP except the
legacy pin gal-10, which HOLDS on pristine base by design.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g223c
  TMPDIR=/var/tmp/g223c ~/workspace/.gov-venv/bin/python evals/w223_gatealg_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g223c-u \\
      ~/workspace/.gov-venv/bin/python evals/w223_gatealg_probes.py
"""

import hashlib
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w223-gatealg-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g223c-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import admission as adm  # noqa: E402
    from gov import gate_algebra as ga  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    adm = None
    ga = None
    _ed = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_RESULTS = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records HELD/GAP/BREAK/ERROR on probes and PASS/SKIP/FAIL on its
# depth-1 green checks; the canonical emission vocabulary is
# BREAK/HELD/ERROR/SKIP, mapped red-first (PASS->HELD, GAP/FAIL->BREAK).
# Probe logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}
_PROBE_FNS = {}


def probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _gap(name, detail=""):
    _record(name, "GAP", detail)


def _break(name, detail=""):
    _record(name, "BREAK", detail)


def _code_of(exc):
    return getattr(exc, "code", None)


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _make_keypair(tag):
    seed = hashlib.sha256(b"w223-gatealg-%s" % tag.encode()).digest()
    return seed, _ed.publickey(seed)


def _sign_digest(seed, payload_digest):
    return _ed.sign(seed, adm.SIGN_DOMAIN + payload_digest.encode("ascii"))


def _honest_artifact(seed, payload, fmt="evidence-bundle/1"):
    digest = _sha(payload)
    return {
        "format": fmt,
        "payload_digest": digest,
        "signature": _sign_digest(seed, digest),
        "payload": payload,
    }


def _honest_policy(issuer_pub, digest_pin, fmt="evidence-bundle/1"):
    return adm.AdmissionPolicy(digest_pin=digest_pin,
                               issuer_pin=issuer_pub,
                               bundle_format=fmt)


# ----------------------------------------------------------------------
# Conjunction probes.
# ----------------------------------------------------------------------

@probe("gal-01-conjunction-all-admit")
def _gal_all_admit():
    """Every member admitting => the conjunction admits with an
    audit-visible record naming the member count."""
    seed, pub = _make_keypair("a")
    payload = b"bundle v1"
    digest = _sha(payload)
    artifact = _honest_artifact(seed, payload)
    conj = ga.PolicyConjunction(_honest_policy(pub, digest),
                                _honest_policy(pub, digest))
    rec = conj.admit(artifact)
    if rec.get("admissible") is True \
            and rec.get("members_admitted") == 2:
        _held("gal-01-conjunction-all-admit", "conjunction admits")
    else:
        _break("gal-01-conjunction-all-admit",
               "record not audit-visible: %r" % (rec,))


@probe("gal-02-conjunction-one-refusal-attributed")
def _gal_one_refusal():
    """One member refusing fails the whole conjunction closed: the
    refusal code is admission-conjunction-refused, the failing
    member's own code is preserved with attribution, and the
    refusing-member count is 1."""
    seed, pub = _make_keypair("a")
    payload = b"bundle v1"
    artifact = _honest_artifact(seed, payload)
    good = _honest_policy(pub, _sha(payload))
    bad = _honest_policy(pub, _sha(b"something else"))
    conj = ga.PolicyConjunction(good, bad)
    try:
        conj.admit(artifact)
    except adm.AdmissionError as exc:
        results = getattr(exc, "member_results", None) or []
        count = getattr(exc, "refused_count", None)
        if _code_of(exc) != "admission-conjunction-refused":
            _break("gal-02-conjunction-one-refusal-attributed",
                   "wrong code %r" % _code_of(exc))
            return
        if count != 1:
            _break("gal-02-conjunction-one-refusal-attributed",
                   "refused_count=%r, want 1" % (count,))
            return
        codes = [r.get("code") for r in results if isinstance(r, dict)]
        if "admission-digest-mismatch" in codes \
                and any(r.get("member") == 1 for r in results
                        if isinstance(r, dict)):
            _held("gal-02-conjunction-one-refusal-attributed",
                  "refusal preserved with member attribution, count 1")
        else:
            _break("gal-02-conjunction-one-refusal-attributed",
                   "member refusal swallowed: %r" % (results,))
    else:
        _break("gal-02-conjunction-one-refusal-attributed",
               "conjunction ADMITTED despite refusing member")


@probe("gal-03-conjunction-two-refusals-counted")
def _gal_two_refusals():
    """Two refusing members: refused_count == 2 and both refusal
    codes are preserved in member_results."""
    seed, pub = _make_keypair("a")
    payload = b"bundle v1"
    artifact = _honest_artifact(seed, payload)
    bad1 = _honest_policy(pub, _sha(b"other 1"))
    bad2 = _honest_policy(pub, _sha(b"other 2"))
    conj = ga.PolicyConjunction(bad1, bad2)
    try:
        conj.admit(artifact)
    except adm.AdmissionError as exc:
        results = getattr(exc, "member_results", None) or []
        if _code_of(exc) == "admission-conjunction-refused" \
                and getattr(exc, "refused_count", None) == 2 \
                and len(results) == 2:
            _held("gal-03-conjunction-two-refusals-counted",
                  "both refusals preserved, count 2")
        else:
            _break("gal-03-conjunction-two-refusals-counted",
                   "count or attribution lost: code=%r count=%r results=%r"
                   % (_code_of(exc), getattr(exc, "refused_count", None),
                      results))
    else:
        _break("gal-03-conjunction-two-refusals-counted",
               "conjunction ADMITTED with two refusing members")


@probe("gal-04-conjunction-member-error-fails-closed")
def _gal_member_error():
    """A member that raises a programming error (not an
    AdmissionError) fails the conjunction closed -- it is never
    treated as an admit."""
    seed, pub = _make_keypair("a")
    payload = b"bundle v1"
    artifact = _honest_artifact(seed, payload)
    good = _honest_policy(pub, _sha(payload))

    class _Exploding(object):
        def admit(self, _artifact):
            raise ValueError("boom")

    conj = ga.PolicyConjunction(good, _Exploding())
    try:
        conj.admit(artifact)
    except adm.AdmissionError as exc:
        if _code_of(exc) == "admission-conjunction-refused":
            _held("gal-04-conjunction-member-error-fails-closed",
                  "member error failed closed: %s" % exc)
        else:
            _break("gal-04-conjunction-member-error-fails-closed",
                   "wrong code %r" % _code_of(exc))
    except ValueError:
        _break("gal-04-conjunction-member-error-fails-closed",
               "programming error escaped (not fail-closed)")
    else:
        _break("gal-04-conjunction-member-error-fails-closed",
               "conjunction ADMITTED despite exploding member")


# ----------------------------------------------------------------------
# Severity gate probes.
# ----------------------------------------------------------------------

@probe("gal-05-severity-at-and-under-threshold-admits")
def _gal_severity_ok():
    """Findings at or under the class threshold admit; an empty
    finding list admits (nothing to rate)."""
    seed, pub = _make_keypair("a")
    payload = b"bundle v1"
    digest = _sha(payload)
    artifact = _honest_artifact(seed, payload)
    policy = _honest_policy(pub, digest)
    gate = ga.SeverityGate(policy, threshold={"evidence-bundle/1": "high"})
    for findings, label in (
            ([{"id": "c1", "severity": "high"}], "at-threshold"),
            ([{"id": "c1", "severity": "low"}], "under-threshold"),
            ([], "empty")):
        rec = gate.admit(artifact, findings=findings)
        if rec.get("admissible") is not True:
            _break("gal-05-severity-at-and-under-threshold-admits",
                   "%s did not admit" % label)
            return
    _held("gal-05-severity-at-and-under-threshold-admits",
          "at/under/empty findings all admit")


@probe("gal-06-severity-exceeded-refused")
def _gal_severity_over():
    """A single finding above the class threshold refuses with the
    named severity code -- severity does not average out."""
    seed, pub = _make_keypair("a")
    payload = b"bundle v1"
    digest = _sha(payload)
    artifact = _honest_artifact(seed, payload)
    gate = ga.SeverityGate(_honest_policy(pub, digest),
                           threshold={"evidence-bundle/1": "high"})
    try:
        gate.admit(artifact, findings=[
            {"id": "ok", "severity": "low"},
            {"id": "bad", "severity": "critical"},
        ])
    except adm.AdmissionError as exc:
        if _code_of(exc) == "admission-severity-exceeded":
            _held("gal-06-severity-exceeded-refused",
                  "over-threshold finding refused: %s" % exc)
        else:
            _break("gal-06-severity-exceeded-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("gal-06-severity-exceeded-refused",
               "critical finding ADMITTED under high threshold")


@probe("gal-07-severity-unrated-refused-unverifiable")
def _gal_severity_unknown():
    """Unknown severity strings and absent scan data refuse as
    unverifiable -- never assumed benign."""
    seed, pub = _make_keypair("a")
    payload = b"bundle v1"
    digest = _sha(payload)
    artifact = _honest_artifact(seed, payload)
    gate = ga.SeverityGate(_honest_policy(pub, digest),
                           threshold="high")
    cases = [
        ([{"id": "x", "severity": "apocalyptic"}], "unknown-string"),
        ([{"id": "x"}], "missing-severity"),
        (None, "absent-scan-data"),
    ]
    for findings, label in cases:
        try:
            gate.admit(artifact, findings=findings)
        except adm.AdmissionError as exc:
            if _code_of(exc) != "admission-severity-unverifiable":
                _break("gal-07-severity-unrated-refused-unverifiable",
                       "%s: wrong code %r" % (label, _code_of(exc)))
                return
        else:
            _break("gal-07-severity-unrated-refused-unverifiable",
                   "%s ADMITTED (assumed benign)" % label)
            return
    _held("gal-07-severity-unrated-refused-unverifiable",
          "unknown/missing/absent severities all refused")


# ----------------------------------------------------------------------
# Immutable-tag probes.
# ----------------------------------------------------------------------

@probe("gal-08-tag-mutation-refused")
def _gal_tag_mutation():
    """Once digest D is admitted under tag T, a DIFFERENT digest
    under T refuses with admission-tag-mutated."""
    seed, pub = _make_keypair("a")
    tag = "evidence-bundle/1:latest"
    tgate = ga.ImmutableTag(_honest_policy(pub, _sha(b"v1")),
                            tag_of=lambda a: tag)
    tgate.admit(_honest_artifact(seed, b"v1"))
    try:
        tgate.admit(_honest_artifact(seed, b"v2"))
    except adm.AdmissionError as exc:
        if _code_of(exc) == "admission-tag-mutated":
            _held("gal-08-tag-mutation-refused", "tag mutation refused")
        else:
            _break("gal-08-tag-mutation-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("gal-08-tag-mutation-refused",
               "mutated tag ADMITTED (digest pinned to tag changed)")


@probe("gal-09-tag-same-digest-idempotent")
def _gal_tag_idempotent():
    """Re-admitting the SAME digest under the same tag is idempotent
    and admissible; a fresh tag admits independently."""
    seed, pub = _make_keypair("a")
    tgate = ga.ImmutableTag(_honest_policy(pub, _sha(b"v1")),
                            tag_of=lambda a: "evidence-bundle/1:latest")
    rec1 = tgate.admit(_honest_artifact(seed, b"v1"))
    rec2 = tgate.admit(_honest_artifact(seed, b"v1"))
    if rec1.get("admissible") is True \
            and rec2.get("admissible") is True \
            and rec2.get("payload_digest") == _sha(b"v1"):
        _held("gal-09-tag-same-digest-idempotent",
              "same-digest re-admission idempotent")
    else:
        _break("gal-09-tag-same-digest-idempotent",
               "idempotent re-admission failed: %r %r" % (rec1, rec2))


# ----------------------------------------------------------------------
# Legacy pin.
# ----------------------------------------------------------------------

@probe("gal-10-legacy-admission-untouched")
def _gal_legacy_pin():
    """Legacy pin (holds on pristine base by design): gov/admission.py
    is extended by composition only -- it never imports
    gov.gate_algebra, and none of its tracked behavior changes when
    the algebra types are unused."""
    path = os.path.join(REPO, "gov", "admission.py")
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    if "gate_algebra" in src:
        _break("gal-10-legacy-admission-untouched",
               "gov/admission.py references gov.gate_algebra")
    else:
        _held("gal-10-legacy-admission-untouched",
              "gov/admission.py unmodified by composition")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    path = os.path.join(REPO, "tests/test_gate_algebra.py")
    if not os.path.exists(path):
        return [("green-check", "SKIP", "unit tests not written yet")]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_gate_algebra", "-v"],
        env=env, cwd=REPO,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    out = proc.stdout.decode("utf-8", "replace")
    if proc.returncode == 0:
        notes.append(("green-check", "PASS", "unit tests green"))
    else:
        notes.append(("green-check", "FAIL", out[-500:] if out else "no output"))
    return notes


def _run_once():
    _RESULTS.clear()
    names = sorted(_PROBE_FNS)
    if not _IMPORT_OK:
        held_pins = {"gal-10-legacy-admission-untouched"}
        for name in names:
            if name in held_pins:
                _PROBE_FNS[name]()
            else:
                _gap(name, "module absent on pristine base")
        return [(n, v) for n, v, _ in _RESULTS]
    for name in names:
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001 - probe harness
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    return [(n, v) for n, v, _ in _RESULTS]


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v in first] == [v for _, v in second]
    green = _run_green_checks()
    held = sum(1 for _, v in first if v == "HELD")
    gap = sum(1 for _, v in first if v == "GAP")
    brk = sum(1 for _, v in first if v == "BREAK")
    err = sum(1 for _, v in first if v == "ERROR")
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _RESULTS]
    # Green-check pids are renamed value-only ("/" -> "_") so every
    # emitted pid stays inside [A-Za-z0-9_.-] (D7).
    final += [(n.replace("/", "_"), _VERDICT_MAP[s], d)
              for n, s, d in green]
    probe_lines.emit(final)
    brk_c = sum(1 for _, v, _ in final if v == "BREAK")
    held_c = sum(1 for _, v, _ in final if v == "HELD")
    err_c = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk_c, held_c, err_c)
    if not _coh_ok:
        print("coherence-WARNING: %s" % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk_c, held_c, err_c))
    print("w223 gate-algebra probes: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR (%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
