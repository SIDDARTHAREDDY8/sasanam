#!/usr/bin/env python3
"""Wave-221 lane C: artifact-admission gate + bundle inspection
discipline battery.

Seam 1 -- gov/admission.py (new): Harbor pull-time content-trust gate
ADAPTed to artifacts/bundles BEFORE they enter the evidence pipeline.
``AdmissionPolicy`` pins ``{digest_pin, issuer_pin, bundle_format}``;
``admit(artifact)`` returns ``admissible`` only when the digest
matches the pin (constant-time compare), the issuer signature verifies
against the pinned keyset (domain-separated), and the format tag is
the exact expected tag. Refusal codes: ``admission-digest-mismatch``,
``admission-issuer-untrusted``, ``admission-format-unknown``;
unsigned-but-claimed artifacts refuse as
``admission-unverifiable`` -- never silently admitted. Fail closed;
opt-in: the existing evidence pipeline is byte-identical when the
gate is unused (pinned by adm-07).

Seam 2 -- gov/bundle_inspection.py (new): in-toto inspection
discipline (pattern only, prose re-derived -- NOT in-toto spec text)
for the evidence bundle's own verifier. Every inspection link is
verifier-attributed with the verifier id + the bundle digest it was
bound to; inspection results are consumed in order (evidence before
admission); a bundle whose inspection link lacks attribution refuses
with ``bundle-link-unverifiable``. Composes with gov/inspection.py
(composition, not duplication). Wired optionally into the admission
gate: ``require_inspection=True`` refuses
``admission-inspection-missing`` / ``admission-inspection-bundle-mismatch``.
Existing bundle behavior byte-identical when unused (pinned by bin-04).

Attack shapes: digest mismatch; wrong issuer; unknown format tag;
unsigned artifact; inspection required but absent; inspection link
bound to a different bundle; unattributed inspection link;
out-of-order evidence (forged seq); tampered outputs; hand-made
link; legacy pipeline bypassing the gate.

Method (diagnosing-bugs + tdd): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-220 HEAD
c0c25caa5d7cfd83b2cb0fcf92bd305d65fb34b4.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (modules absent) is expected GAP except
the legacy pins adm-07/bin-04, which HOLD on pristine base by design.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g221c
  TMPDIR=/var/tmp/g221c ~/workspace/.gov-venv/bin/python evals/w221_admission_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g221c-u \\
      ~/workspace/.gov-venv/bin/python evals/w221_admission_probes.py
"""

import hashlib
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w221-admission-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g221c-%d" % os.getpid()
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
    from gov import bundle_inspection as bi  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no modules
    adm = None
    bi = None
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
    seed = hashlib.sha256(b"w221-admission-%s" % tag.encode()).digest()
    return seed, _ed.publickey(seed)


def _sign_artifact(seed, payload_digest):
    return _ed.sign(seed, adm.SIGN_DOMAIN + payload_digest.encode("ascii"))


def _honest_artifact(seed, payload, digest_pin=None, fmt="evidence-bundle/1"):
    digest = _sha(payload)
    return {
        "format": fmt,
        "payload_digest": digest,
        "signature": _sign_artifact(seed, digest),
        "payload": payload,
    }


def _honest_policy(issuer_pub, digest_pin, require_inspection=False):
    return adm.AdmissionPolicy(digest_pin=digest_pin,
                               issuer_pin=issuer_pub,
                               bundle_format="evidence-bundle/1",
                               require_inspection=require_inspection)


# ----------------------------------------------------------------------
# Admission seam probes.
# ----------------------------------------------------------------------

@probe("adm-01-digest-mismatch-refused")
def _adm_digest_mismatch():
    """An artifact whose digest does not match the pin is refused with
    the named code -- even when its signature is valid over its own
    digest (the pin binds, not the signature)."""
    seed, pub = _make_keypair("a")
    payload = b"bundle payload v1"
    policy = _honest_policy(pub, digest_pin=_sha(b"something else"))
    artifact = _honest_artifact(seed, payload)
    try:
        policy.admit(artifact)
    except adm.AdmissionError as exc:
        if _code_of(exc) == "admission-digest-mismatch":
            _held("adm-01-digest-mismatch-refused",
                  "digest mismatch refused: %s" % exc)
        else:
            _break("adm-01-digest-mismatch-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("adm-01-digest-mismatch-refused",
               "mismatched digest ADMITTED (pin not enforced)")


@probe("adm-02-issuer-untrusted-refused")
def _adm_issuer_untrusted():
    """Correct digest pin, signature by a DIFFERENT key: refused with
    the issuer code -- a forged signature cannot smuggle a bundle in."""
    seed, pub = _make_keypair("a")
    evil_seed, _ = _make_keypair("evil")
    payload = b"bundle payload v1"
    digest = _sha(payload)
    policy = _honest_policy(pub, digest_pin=digest)
    artifact = _honest_artifact(evil_seed, payload)
    try:
        policy.admit(artifact)
    except adm.AdmissionError as exc:
        if _code_of(exc) == "admission-issuer-untrusted":
            _held("adm-02-issuer-untrusted-refused",
                  "foreign signature refused: %s" % exc)
        else:
            _break("adm-02-issuer-untrusted-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("adm-02-issuer-untrusted-refused",
               "foreign-key artifact ADMITTED (issuer pin not enforced)")


@probe("adm-03-format-unknown-refused")
def _adm_format_unknown():
    """A format tag that is not the exact pinned tag is refused --
    the gate does not guess formats."""
    seed, pub = _make_keypair("a")
    payload = b"bundle payload v1"
    policy = _honest_policy(pub, digest_pin=_sha(payload))
    artifact = _honest_artifact(seed, payload, fmt="Evidence-Bundle/1")
    try:
        policy.admit(artifact)
    except adm.AdmissionError as exc:
        if _code_of(exc) == "admission-format-unknown":
            _held("adm-03-format-unknown-refused",
                  "case-variant format refused")
        else:
            _break("adm-03-format-unknown-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("adm-03-format-unknown-refused",
               "unknown format ADMITTED")


@probe("adm-04-unsigned-refused-unverifiable")
def _adm_unsigned():
    """Unsigned-but-claimed artifacts refuse as unverifiable -- never
    silently admitted on a bare digest claim."""
    seed, pub = _make_keypair("a")
    payload = b"bundle payload v1"
    policy = _honest_policy(pub, digest_pin=_sha(payload))
    artifact = _honest_artifact(seed, payload)
    artifact["signature"] = None
    try:
        policy.admit(artifact)
    except adm.AdmissionError as exc:
        if _code_of(exc) == "admission-unverifiable":
            _held("adm-04-unsigned-refused-unverifiable",
                  "unsigned artifact refused, not silently admitted")
        else:
            _break("adm-04-unsigned-refused-unverifiable",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("adm-04-unsigned-refused-unverifiable",
               "unsigned artifact ADMITTED")


@probe("adm-05-honest-admits")
def _adm_honest():
    """Pinned digest + pinned issuer + exact format admits, with an
    audit-visible record."""
    seed, pub = _make_keypair("a")
    payload = b"bundle payload v1"
    digest = _sha(payload)
    policy = _honest_policy(pub, digest_pin=digest)
    rec = policy.admit(_honest_artifact(seed, payload))
    if rec.get("admissible") is True \
            and rec.get("payload_digest") == digest \
            and rec.get("format") == "evidence-bundle/1" \
            and rec.get("issuer_fingerprint") == _sha(pub) \
            and rec.get("inspection_verified") is False:
        _held("adm-05-honest-admits", "audit-visible admission record")
    else:
        _break("adm-05-honest-admits", "record not audit-visible: %r" % (rec,))


@probe("adm-06-require-inspection")
def _adm_require_inspection():
    """With require_inspection=True: absent inspection refuses
    ``admission-inspection-missing``; a link bound to a DIFFERENT
    bundle refuses ``admission-inspection-bundle-mismatch``; an
    honest verifier-attributed link for THIS bundle admits."""
    seed, pub = _make_keypair("a")
    payload = b"bundle payload v1"
    digest = _sha(payload)
    policy = _honest_policy(pub, digest_pin=digest,
                            require_inspection=True)
    artifact = _honest_artifact(seed, payload)
    # (a) no inspection at all.
    try:
        policy.admit(artifact)
    except adm.AdmissionError as exc:
        if _code_of(exc) != "admission-inspection-missing":
            _break("adm-06-require-inspection",
                   "missing inspection: wrong code %r" % _code_of(exc))
            return
    else:
        _break("adm-06-require-inspection",
               "admitted with inspection required but absent")
        return
    # (b) inspection link bound to a different bundle.
    other_log = bi.BundleInspectionLog(verifier_id="v1",
                                       bundle_digest=_sha(b"other bundle"))
    script = b"#!/bin/sh\necho ok\n"
    other_link = other_log.admit("scan", script, _sha(script), 0, b"ok")
    try:
        policy.admit(artifact, inspection=(other_log, other_link))
    except adm.AdmissionError as exc:
        if _code_of(exc) != "admission-inspection-bundle-mismatch":
            _break("adm-06-require-inspection",
                   "foreign-bundle link: wrong code %r" % _code_of(exc))
            return
    else:
        _break("adm-06-require-inspection",
               "admitted with inspection for a DIFFERENT bundle")
        return
    # (c) honest link for this bundle admits.
    log = bi.BundleInspectionLog(verifier_id="v1", bundle_digest=digest)
    link = log.admit("scan", script, _sha(script), 0, b"ok")
    rec = policy.admit(artifact, inspection=(log, link))
    if rec.get("admissible") is True \
            and rec.get("inspection_verified") is True:
        _held("adm-06-require-inspection",
              "missing / foreign-bundle / honest cases all correct")
    else:
        _break("adm-06-require-inspection",
               "honest inspected artifact did not admit: %r" % (rec,))


@probe("adm-07-legacy-pipeline-untouched")
def _adm_legacy_pin():
    """Legacy pin (holds on pristine base by design): the evidence
    pipeline consults the admission gate NOWHERE unless the caller
    opts in -- gov/evidence_bundle.py and
    gov/bundle_admissibility.py never import gov.admission."""
    srcs = []
    for mod in ("gov/evidence_bundle.py", "gov/bundle_admissibility.py",
                "gov/evidence_verify.py"):
        path = os.path.join(REPO, mod)
        with open(path, "r", encoding="utf-8") as fh:
            srcs.append(fh.read())
    refs = [src for src in srcs
            if "gov.admission" in src or "import admission" in src]
    if refs:
        _break("adm-07-legacy-pipeline-untouched",
               "a legacy pipeline file references gov.admission")
    else:
        _held("adm-07-legacy-pipeline-untouched",
              "no legacy pipeline file imports gov.admission")


# ----------------------------------------------------------------------
# Bundle-inspection seam probes.
# ----------------------------------------------------------------------

@probe("bin-01-unattributed-link-refused")
def _bin_unattributed():
    """A bundle whose inspection link lacks verifier attribution is
    refused with ``bundle-link-unverifiable`` -- attribution is
    structural, not decorative."""
    log = bi.BundleInspectionLog(verifier_id="v1",
                                 bundle_digest=_sha(b"bundle"))
    handmade = {"name": "scan",
                "script_digest": _sha(b"#!/bin/sh\necho ok\n"),
                "verifier_id": "v1",
                "verifier_attributed": False,
                "bundle_digest": _sha(b"bundle"),
                "evidence_seq": 1,
                "outputs_digest": _sha(b"ok")}
    try:
        log.verify_link(handmade)
    except bi.BundleInspectionError as exc:
        if _code_of(exc) == "bundle-link-unverifiable":
            _held("bin-01-unattributed-link-refused",
                  "unattributed link refused")
        else:
            _break("bin-01-unattributed-link-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("bin-01-unattributed-link-refused",
               "unattributed link VERIFIED")


@probe("bin-02-out-of-order-refused")
def _bin_out_of_order():
    """Evidence must precede admission: a link whose evidence_seq
    resolves to no record (forged/reordered) is refused, and a link
    emitted before any evidence cannot verify."""
    log = bi.BundleInspectionLog(verifier_id="v1",
                                 bundle_digest=_sha(b"bundle"))
    script = b"#!/bin/sh\necho ok\n"
    link = log.admit("scan", script, _sha(script), 0, b"ok")
    forged = dict(link)
    forged["evidence_seq"] = 999
    try:
        log.verify_link(forged)
    except bi.BundleInspectionError as exc:
        if _code_of(exc) == "bundle-link-unverifiable":
            _held("bin-02-out-of-order-refused",
                  "forged evidence_seq refused")
        else:
            _break("bin-02-out-of-order-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("bin-02-out-of-order-refused",
               "reordered link VERIFIED (ordering broken)")


@probe("bin-03-honest-attributed-verifies")
def _bin_honest():
    """An honestly admitted link carries the verifier id + the bound
    bundle digest and verifies against the log."""
    digest = _sha(b"bundle")
    log = bi.BundleInspectionLog(verifier_id="v1", bundle_digest=digest)
    script = b"#!/bin/sh\necho ok\n"
    link = log.admit("scan", script, _sha(script), 0, b"ok")
    if link.get("verifier_attributed") is not True \
            or link.get("verifier_id") != "v1" \
            or link.get("bundle_digest") != digest:
        _break("bin-03-honest-attributed-verifies",
               "link missing attribution fields: %r" % (link,))
        return
    if log.verify_link(link) is True:
        _held("bin-03-honest-attributed-verifies",
              "attributed link verifies; carries verifier id + digest")
    else:
        _break("bin-03-honest-attributed-verifies",
               "honest link did not verify")


@probe("bin-04-legacy-bundle-untouched")
def _bin_legacy_pin():
    """Legacy pin (holds on pristine base by design): the bundle
    verifier consumes no bundle-inspection module unless the caller
    opts in -- gov/bundle_admissibility.py and
    gov/evidence_verify.py never import gov.bundle_inspection."""
    for mod in ("gov/bundle_admissibility.py", "gov/evidence_verify.py"):
        path = os.path.join(REPO, mod)
        with open(path, "r", encoding="utf-8") as fh:
            src = fh.read()
        if "bundle_inspection" in src:
            _break("bin-04-legacy-bundle-untouched",
                   "%s references bundle_inspection" % mod)
            return
    _held("bin-04-legacy-bundle-untouched",
          "legacy bundle files import no bundle_inspection")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    path = os.path.join(REPO, "tests/test_admission.py")
    if not os.path.exists(path):
        return [("green-check", "SKIP", "unit tests not written yet")]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_admission", "-v"],
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
        held_pins = {"adm-07-legacy-pipeline-untouched",
                     "bin-04-legacy-bundle-untouched"}
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
    print("w221 admission probes: %d HELD / %d GAP / %d BREAK / "
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
