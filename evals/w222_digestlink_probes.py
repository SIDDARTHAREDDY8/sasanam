#!/usr/bin/env python3
"""Wave-222 lane B: digest-linkage approval flow.

Seam under test: gov/digest_link.py (new, stdlib only).

Gap addressed (re-derived from draft-ruvalcaba-nhe-authz-00 section 6
digest linkage, NOT the draft's text): the wave-219 ARAP
``context_binding`` (the digest that scopes the credential) and the
wave-221 ``RenderingCommitment`` (the digest of what the approver was
shown) live in separate pipes. An approver can therefore see one digest
while the credential authorizes another. This module enforces the
invariant at the approval seam: the SAME canonical digest that scopes
the credential MUST be the digest the approver's render was bound to.

Attack shapes: diverged digests across the two pipes; a forged
DigestLinkage record offered as an authority; malformed digest fields
(non-hex, wrong length, non-string) slipping through as "matching";
legacy approval paths (no lease, no commitment) changing behavior.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-221 HEAD
194588b78321b7d8b9bc454799c55a32ca2756e3.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g222b
  TMPDIR=/var/tmp/g222b ~/workspace/.gov-venv/bin/python evals/w222_digestlink_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g222b-u \\
      ~/workspace/.gov-venv/bin/python evals/w222_digestlink_probes.py
"""

import hashlib
import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w222-digestlink-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g222b-%d" % os.getpid()
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
    from gov import digest_link as dl  # noqa: E402
    from gov import permit_leases as pl  # noqa: E402
    from gov import render_commit as rc  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    dl = None
    pl = None
    rc = None
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

def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


def _break(name, detail):
    _record(name, "BREAK", detail)


def _code_of(exc):
    return getattr(exc, "code", None)


def _digest(tag):
    """A valid digest string under one of the pipeline's real schemes."""
    return "sha256:" + hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _hmac_digest(tag):
    """The ARAP context_binding scheme (hmac-sha256-v1:<64-hex>)."""
    return ("hmac-sha256-v1:"
            + hashlib.sha256(b"arap:" + tag.encode("utf-8")).hexdigest())


def _lease_for(digest, grant_scope=None):
    return pl.PermitLease.issue(
        "permit-probe", params_digest=digest,
        grant_scope=grant_scope or {"action": {"read"}})


def _commitment_for(digest):
    return rc.commit(b"the render the approver saw", digest,
                     renderer_id="queue-view")


_PROBE_FNS = {}


def probe(fn):
    _PROBE_FNS[fn.__name__] = fn
    return fn


# ----------------------------------------------------------------------
# p01: equal digests bind into a linkage record.
# ----------------------------------------------------------------------


@probe
def p01_bind_equal_digests():
    d = _digest("same-parameters")
    link = dl.bind_credential_to_render(d, d)
    if not isinstance(link, dict):
        return _break("p01", "linkage is not a dict")
    if link.get("credential_digest") != d or link.get("render_digest") != d:
        return _break("p01", "linkage does not carry both equal digests")
    if "bound_at" not in link:
        return _break("p01", "linkage lacks bound_at")
    _held("p01_bind_equal_digests")


# ----------------------------------------------------------------------
# p02: unequal digests refuse at bind time with the named code.
# ----------------------------------------------------------------------


@probe
def p02_bind_unequal_digests_refuses():
    try:
        dl.bind_credential_to_render(_digest("params-a"), _digest("params-b"))
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "digest-linkage-mismatch":
            return _held("p02_bind_unequal_digests_refuses")
        return _break("p02", "wrong code: %r" % (_code_of(exc),))
    _break("p02", "unequal digests bound without refusal")


# ----------------------------------------------------------------------
# p03: approval flow with matching digests proceeds.
# ----------------------------------------------------------------------


@probe
def p03_flow_matching_digests_passes():
    d = _hmac_digest("arap-params-1")
    lease = _lease_for(d)
    commitment = _commitment_for(d)
    if dl.check_approval_flow(lease, commitment) is True:
        return _held("p03_flow_matching_digests_passes")
    _break("p03", "matching flow did not return True")


# ----------------------------------------------------------------------
# p04: diverged digests refuse with approval-digest-diverged.
# ----------------------------------------------------------------------


@probe
def p04_flow_diverged_digests_refuse():
    lease = _lease_for(_hmac_digest("arap-params-1"))
    commitment = _commitment_for(_digest("a-different-artifact"))
    try:
        dl.check_approval_flow(lease, commitment)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "approval-digest-diverged":
            return _held("p04_flow_diverged_digests_refuse")
        return _break("p04", "wrong code: %r" % (_code_of(exc),))
    _break("p04", "diverged flow passed without refusal")


# ----------------------------------------------------------------------
# p05/p06/p07: absent lease and/or commitment -> legacy passthrough.
# ----------------------------------------------------------------------


@probe
def p05_flow_no_lease_is_legacy_passthrough():
    if dl.check_approval_flow(None, _commitment_for(_digest("x"))) is True:
        return _held("p05_flow_no_lease_is_legacy_passthrough")
    _break("p05", "absent lease did not pass through")


@probe
def p06_flow_no_commitment_is_legacy_passthrough():
    if dl.check_approval_flow(_lease_for(_digest("x")), None) is True:
        return _held("p06_flow_no_commitment_is_legacy_passthrough")
    _break("p06", "absent commitment did not pass through")


@probe
def p07_flow_neither_is_legacy_passthrough():
    if dl.check_approval_flow(None, None) is True:
        return _held("p07_flow_neither_is_legacy_passthrough")
    _break("p07", "absent both did not pass through")


# ----------------------------------------------------------------------
# p08: a linkage record offered as a lease fails closed (TypeError).
# ----------------------------------------------------------------------


@probe
def p08_linkage_record_not_authority_as_lease():
    d = _digest("params")
    link = dl.bind_credential_to_render(d, d)
    try:
        dl.check_approval_flow(link, _commitment_for(d))
    except TypeError:
        return _held("p08_linkage_record_not_authority_as_lease")
    except Exception as exc:  # noqa: BLE001
        return _break("p08", "wrong refusal type: %s %r"
                      % (type(exc).__name__, _code_of(exc)))
    _break("p08", "linkage dict accepted as a lease")


# ----------------------------------------------------------------------
# p09: a linkage record offered as a commitment fails closed.
# ----------------------------------------------------------------------


@probe
def p09_linkage_record_not_authority_as_commitment():
    d = _digest("params")
    link = dl.bind_credential_to_render(d, d)
    try:
        dl.check_approval_flow(_lease_for(d), link)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "rendering-commitment-broken":
            return _held("p09_linkage_record_not_authority_as_commitment")
        return _break("p09", "wrong code: %r" % (_code_of(exc),))
    _break("p09", "linkage dict accepted as a commitment")


# ----------------------------------------------------------------------
# p10/p11/p12: malformed digest fields refuse (runtime data, named).
# ----------------------------------------------------------------------


@probe
def p10_malformed_nonhex_digest_refuses():
    bad = "sha256:" + "zz" * 32
    try:
        dl.bind_credential_to_render(bad, bad)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "digest-linkage-malformed":
            return _held("p10_malformed_nonhex_digest_refuses")
        return _break("p10", "wrong code: %r" % (_code_of(exc),))
    _break("p10", "non-hex digest accepted")


@probe
def p11_malformed_short_digest_refuses():
    bad = "sha256:" + "ab" * 31  # 62 hex, not 64
    try:
        dl.bind_credential_to_render(bad, bad)
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "digest-linkage-malformed":
            return _held("p11_malformed_short_digest_refuses")
        return _break("p11", "wrong code: %r" % (_code_of(exc),))
    _break("p11", "short digest accepted")


@probe
def p12_malformed_nonstring_digest_refuses():
    try:
        dl.bind_credential_to_render(None, _digest("x"))
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "digest-linkage-malformed":
            return _held("p12_malformed_nonstring_digest_refuses")
        return _break("p12", "wrong code: %r" % (_code_of(exc),))
    _break("p12", "non-string digest accepted")


# ----------------------------------------------------------------------
# p13: a lease carrying a malformed digest fails the flow closed.
# ----------------------------------------------------------------------


@probe
def p13_flow_malformed_lease_digest_refuses():
    lease = _lease_for("not-a-digest-at-all")
    try:
        dl.check_approval_flow(lease, _commitment_for(_digest("x")))
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == "digest-linkage-malformed":
            return _held("p13_flow_malformed_lease_digest_refuses")
        return _break("p13", "wrong code: %r" % (_code_of(exc),))
    _break("p13", "malformed lease digest passed the flow")


# ----------------------------------------------------------------------
# p14: the audit hook sees refusals.
# ----------------------------------------------------------------------


@probe
def p14_refusal_is_audit_visible():
    seen = []
    lease = _lease_for(_digest("params-a"))
    commitment = _commitment_for(_digest("params-b"))
    try:
        dl.check_approval_flow(lease, commitment, audit=seen.append)
    except Exception:  # noqa: BLE001
        pass
    if seen and seen[0].get("code") == "approval-digest-diverged":
        return _held("p14_refusal_is_audit_visible")
    _break("p14", "refusal not audit-visible: %r" % (seen,))


# ----------------------------------------------------------------------
# Runner (conventions: depth-1 green checks, determinism double-run).
# ----------------------------------------------------------------------


def _run_green_checks():
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_permit_leases.py",
                 "tests/test_render_commit.py",
                 "tests/test_arap.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    status = "PASS" if all(s in ("PASS", "SKIP") for _, s, _ in notes) \
        else "FAIL"
    return [("green-check", status, "%s: %s" % (name, detail))
            for name, status, detail in notes]


def _run_once():
    _RESULTS.clear()
    names = sorted(_PROBE_FNS)
    if not _IMPORT_OK:
        for name in names:
            _gap(name)
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
    print("w222 digest-linkage probes: %d HELD / %d GAP / %d BREAK / "
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
