#!/usr/bin/env python3
"""Row-6 hardening battery: the at-use check must bind to CONTENT, not stat.

Residual under test: ``SkillWatch.check_at_use`` uses an
``(mtime_ns, size)`` stat prefilter — when the hint matches the
last-verified hint, the pinned content digest is NOT re-verified and
the check attests ``(True, "clean")`` on metadata alone. An attacker
with write access to the skill file (but NOT the operator key that
MACs the pin file, H22) can rewrite the bytes and restore
``(mtime_ns, size)`` via utime: ``check_at_use`` then attests clean
while the bytes differ from the pinned digest. The scheduled sweep
(``verify_all``, which always re-hashes) is the documented backstop,
so the exposure window is <= SWEEP_INTERVAL_SECONDS *if* the
deployment runs sweeps — but the use-time attestation itself is wrong
for that whole window, and the row-6 status text claims
"registry-root compromise now requires the operator key", which is
false while this window exists.

The property under test: ``check_at_use`` returns clean ONLY IF the
current content bytes hash to the pinned digest.

Verdicts:
- BREAK    = the property is violated (clean attestation on divergent
             bytes, or a missing fail-closed).
- HELD     = the watcher quarantines fail-closed (or the control is a
             pre-existing one, noted as baseline).
- EXPECTED = the probe needs the new seam (fetch_verified_at_use),
             which does not exist pre-seam.
- ERROR    = probe/instrumentation problem, not a verdict.

Probes:
  p1 STAT-RESTORE RUG PULL: register V1; rewrite same-length V2;
     restore the original (mtime_ns, size) via os.utime(ns=);
     check_at_use.
     pre-seam:  (True, "clean") while bytes != pin -> BREAK.
     post-seam: (False, "mutated-quarantined")      -> HELD.
  p2 CONTROL: clean file -> (True, "clean"). HELD pre+post.
  p3 CONTROL: mtime bumped (utime to a fixed future stamp), bytes
     identical -> (True, "clean"). HELD pre+post (no false positive
     on legitimate mtime changes).
  p4 CONTROL: size-changed rewrite, no stat restore -> quarantined.
     HELD pre+post (the slow path; pre-existing).
  p5 VERIFIED-BYTES HANDOFF: fetch_verified_at_use returns exactly
     the bytes that were hashed against the pin (single fetch on a
     counting source; sha256(returned) == pinned digest).
     pre-seam:  EXPECTED (no seam). post-seam: HELD.
  p6 HANDOFF UNDER ATTACK: p1 setup, then fetch_verified_at_use ->
     (False, None, "mutated-quarantined") and quarantined.
     pre-seam:  EXPECTED (no seam). post-seam: HELD.

Deterministic. Synthetic/local only, no network. The stat restore
uses os.utime(ns=...) with the exact recorded (atime_ns, mtime_ns); the
probe asserts the restore landed before trusting the result.

Run: TMPDIR=/tmp/gov-fp ~/workspace/.gov-venv/bin/python \\
         evals/skill_fastpath_content_probes.py
Also:  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-fp \\
         ~/workspace/.gov-venv/bin/python evals/skill_fastpath_content_probes.py
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov.skill_watch import (  # noqa: E402
    SkillWatch, FileContentSource, CallableContentSource,
)
import probe_lines  # noqa: E402  (canonical probe-line form)

RESULTS = []

V1 = b"SKILL-CONTENT-v1:" + b"x" * 48
V2 = b"SKILL-CONTENT-v2:" + b"Y" * 48
assert len(V1) == len(V2) and V1 != V2

ORIGIN = {"registry_url": "https://registry.synthetic.local/s/probe",
          "installer_identity": "operator:alice",
          "installed_at": "2026-09-27T00:00:00+00:00"}


def _record(name, verdict, detail):
    # Wave-316 lane-3: append-only; emission happens once in main()
    # via probe_lines.emit (canonical form).
    RESULTS.append((name, verdict, detail))


def _fresh_watch(content=V1):
    tmpdir = tempfile.mkdtemp(prefix="fp-")
    fpath = os.path.join(tmpdir, "s.skill")
    with open(fpath, "wb") as f:
        f.write(content)
    w = SkillWatch()
    origin = dict(ORIGIN)
    origin["content_path"] = fpath
    w.register_skill("s", FileContentSource(fpath), origin=origin)
    return w, fpath


def _sha(b):
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------
# p1: stat-restore rug pull
# --------------------------------------------------------------------------
def _p1():
    w, path = _fresh_watch()
    st0 = os.stat(path)
    with open(path, "wb") as f:
        f.write(V2)
    # Attacker restores the exact (atime_ns, mtime_ns); size already
    # matches because len(V2) == len(V1).
    os.utime(path, ns=(st0.st_atime_ns, st0.st_mtime_ns))
    st1 = os.stat(path)
    if (st1.st_mtime_ns, st1.st_size) != (st0.st_mtime_ns, st0.st_size):
        return ("ERROR",
                "filesystem did not honor the ns stat restore "
                "(mtime_ns=%d size=%d)" % (st1.st_mtime_ns, st1.st_size))
    with open(path, "rb") as f:
        live = f.read()
    if live != V2:
        return "ERROR", "rewrite did not land"
    ok, detail = w.check_at_use("s")
    if ok:
        return ("BREAK",
                "check_at_use attests %r while live bytes != pinned "
                "digest (stat-restore rug pull)" % (detail,))
    if w.is_quarantined("s") and detail == "mutated-quarantined":
        return ("HELD",
                "stat-restore rewrite quarantined fail-closed (%s)"
                % detail)
    return "ERROR", "denied without quarantine: %r" % (detail,)


# --------------------------------------------------------------------------
# p2: control — clean file
# --------------------------------------------------------------------------
def _p2():
    w, _ = _fresh_watch()
    ok, detail = w.check_at_use("s")
    if (ok, detail) == (True, "clean"):
        return "HELD", "unmodified skill attests clean"
    return ("BREAK",
            "clean skill did not attest clean: %r" % ((ok, detail),))


# --------------------------------------------------------------------------
# p3: control — mtime bump, identical bytes
# --------------------------------------------------------------------------
def _p3():
    w, path = _fresh_watch()
    # Legitimate mtime change (backup tools, touch) with identical bytes.
    os.utime(path, ns=(1_800_000_000_000_000_000, 1_800_000_000_000_000_000))
    ok, detail = w.check_at_use("s")
    if (ok, detail) == (True, "clean"):
        return "HELD", "mtime bump with identical bytes stays clean"
    return ("BREAK",
            "false positive: identical bytes quarantined after mtime "
            "bump: %r" % ((ok, detail),))


# --------------------------------------------------------------------------
# p4: control — size-changed rewrite, no restore (slow path)
# --------------------------------------------------------------------------
def _p4():
    w, path = _fresh_watch()
    with open(path, "wb") as f:
        f.write(V2 + b"longer-tail")
    ok, detail = w.check_at_use("s")
    if not ok and w.is_quarantined("s"):
        return "HELD", "size-changed rewrite quarantined (%s)" % detail
    return ("BREAK",
            "size-changed rewrite not quarantined: %r" % ((ok, detail),))


# --------------------------------------------------------------------------
# p5: verified-bytes handoff — returned bytes are exactly the hashed bytes
# --------------------------------------------------------------------------
class _CountingSource(CallableContentSource):
    def __init__(self, content):
        self.content = content
        self.reads = 0
        super().__init__(self._read)

    def _read(self):
        self.reads += 1
        return self.content


def _p5():
    if not hasattr(SkillWatch, "fetch_verified_at_use"):
        return ("EXPECTED",
                "no fetch_verified_at_use seam pre-fix")
    w = SkillWatch()
    src = _CountingSource(V1)
    w.register_skill("s", src, origin=ORIGIN)
    reads_before = src.reads
    ok, data, detail = w.fetch_verified_at_use("s")
    if not ok or data is None:
        return ("BREAK",
                "handoff failed on clean content: %r" % ((ok, detail),))
    if src.reads != reads_before + 1:
        return ("BREAK",
                "handoff fetched %d times (want exactly 1: no second "
                "observation to equivocate on)"
                % (src.reads - reads_before,))
    if bytes(data) != V1:
        return "BREAK", "handoff returned bytes != content bytes"
    if _sha(bytes(data)) != _sha(V1):
        return "BREAK", "handoff bytes do not hash to the pinned digest"
    return ("HELD",
            "handoff returns exactly the hashed bytes (single fetch)")


# --------------------------------------------------------------------------
# p6: handoff under attack
# --------------------------------------------------------------------------
def _p6():
    if not hasattr(SkillWatch, "fetch_verified_at_use"):
        return ("EXPECTED",
                "no fetch_verified_at_use seam pre-fix")
    w, path = _fresh_watch()
    st0 = os.stat(path)
    with open(path, "wb") as f:
        f.write(V2)
    os.utime(path, ns=(st0.st_atime_ns, st0.st_mtime_ns))
    ok, data, detail = w.fetch_verified_at_use("s")
    if ok or data is not None:
        return ("BREAK",
                "handoff passed bytes under stat-restore attack: %r"
                % ((ok, detail),))
    if w.is_quarantined("s") and detail == "mutated-quarantined":
        return ("HELD",
                "handoff quarantines under stat-restore attack, "
                "no bytes handed over")
    return "ERROR", "denied without quarantine: %r" % (detail,)


def main():
    probes = [("p1", _p1), ("p2", _p2), ("p3", _p3),
              ("p4", _p4), ("p5", _p5), ("p6", _p6)]
    for name, fn in probes:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- ERROR, not a verdict
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:200]))
        _record(name, verdict, detail)
    n_break = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    n_held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    n_exp = sum(1 for _, v, _ in RESULTS if v == "EXPECTED")
    n_err = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    # Wave-316 lane-3 decision (D1): EXPECTED -> HELD with an
    # "expected: " prefix (probe needs the fetch_verified_at_use seam;
    # exit-neutral in this battery).
    mapped = [(n, "HELD", "expected: " + d) if v == "EXPECTED" else (n, v, d)
              for n, v, d in RESULTS]
    probe_lines.emit(mapped)
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        mapped, n_break, n_held + n_exp, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (n_break, n_held + n_exp, n_err))
    print("----")
    print("%d BREAK / %d HELD / %d EXPECTED / %d ERROR"
          % (n_break, n_held, n_exp, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
