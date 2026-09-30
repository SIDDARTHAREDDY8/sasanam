"""Wave-241 host-identity mint-once probes (W241-1, red-first).

treeship N-41 (v0.31.12): receipts carry a random per-install host id
(``host_`` + 16 hex from OS randomness), minted once per install at
``~/.treeship/host_id`` (0600, ``O_CREAT|O_EXCL|O_NOFOLLOW`` -- never
through a symlink), race loser reads the winner's id. Hostname,
hostname-digest, per-run UUID, env-only and race-unsafe were all
rejected with reasons: "a digest with no secret reverses from a short
guess list of common machine names."

Re-derived here as a Sasanam invariant in ``gov/host_identity.py``:

- mint-once: ``O_CREAT|O_EXCL|O_NOFOLLOW``; the loser of a mint race
  reads the winner's id (both callers see the same id);
- id file is 0600 and never a symlink; a symlink at the id path is
  refused with ``hostid-symlink-at-id-path``;
- evidence receipts that name a host identity MUST carry the random
  id: a hostname refuses ``hostid-hostname-not-identity``, a
  hostname-digest refuses ``hostid-hostname-digest-not-identity``;
- a receipt that names no host identity yields the explicit fallback
  ``host_unknown`` (which can never validate as a minted id).

Probes:
  hostid-mint-stable -- mint twice: same id, matches ``host_[0-9a-f]{16}``,
      file is 0600, not a symlink (positive control).
  hostid-race-same-id -- two threads mint concurrently through a
      barrier: both callers see the identical id.
  hostid-symlink-refused -- symlink at the id path: mint refuses
      hostid-symlink-at-id-path.
  hostid-hostname-refused -- receipt carrying the hostname as host
      identity refuses hostid-hostname-not-identity; the minted id
      validates (positive control).
  hostid-hostname-digest-refused -- receipt carrying sha256(hostname)
      hex (and sha1) refuses hostid-hostname-digest-not-identity.
  hostid-unknown-fallback -- receipt without host_identity yields
      ``host_unknown``; ``host_unknown`` never validates as a minted id.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import hashlib
import os
import socket
import stat
import sys
import tempfile
import threading
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import host_identity as _hi
    HAVE_NEW_API = all(hasattr(_hi, n) for n in (
        "mint_host_id", "read_host_id", "validate_host_identity",
        "assert_receipt_host_identity", "default_id_path",
        "HostIdentityError", "HOST_ID_PATTERN", "HOST_UNKNOWN",
        "DEFAULT_DIR_NAME"))
except ImportError:
    _hi = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_HOSTNAME = socket.gethostname()
_HOST_SHA256 = hashlib.sha256(_HOSTNAME.encode()).hexdigest()
_HOST_SHA1 = hashlib.sha1(_HOSTNAME.encode()).hexdigest()

def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise HostIdentityError with .code == code; returns note."""
    try:
        fn()
    except _hi.HostIdentityError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


def _fresh_dir():
    return tempfile.mkdtemp(prefix="hostid-probe-")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_mint_stable():
    d = _fresh_dir()
    path = os.path.join(d, "host_id")
    first = _hi.mint_host_id(path)
    second = _hi.mint_host_id(path)
    assert first == second, "mint not stable: %r vs %r" % (first, second)
    assert _hi.HOST_ID_PATTERN.match(first), "bad shape: %r" % (first,)
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode), "id file is not a regular file"
    assert stat.S_IMODE(st.st_mode) == 0o600, \
        "mode %o, expected 600" % stat.S_IMODE(st.st_mode)
    assert _hi.read_host_id(path) == first, "read != minted"
    return "stable %s; mode 600; regular file" % first


def _probe_race_same_id():
    d = _fresh_dir()
    path = os.path.join(d, "host_id")
    barrier = threading.Barrier(3)
    seen = []

    def worker():
        barrier.wait()
        seen.append(_hi.mint_host_id(path))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    barrier.wait()
    for t in threads:
        t.join()
    assert seen[0] == seen[1], "race diverged: %r vs %r" % tuple(seen)
    assert _hi.HOST_ID_PATTERN.match(seen[0])
    return "both callers saw %s" % seen[0]


def _probe_symlink_refused():
    d = _fresh_dir()
    real = os.path.join(d, "real_target")
    with open(real, "w") as fh:
        fh.write("host_0000000000000000")
    link = os.path.join(d, "host_id")
    os.symlink(real, link)
    return _expect_refusal(lambda: _hi.mint_host_id(link),
                           "hostid-symlink-at-id-path")


def _probe_hostname_refused():
    d = _fresh_dir()
    minted = _hi.mint_host_id(os.path.join(d, "host_id"))
    receipt = {"host_identity": _HOSTNAME}
    note = _expect_refusal(
        lambda: _hi.assert_receipt_host_identity(receipt),
        "hostid-hostname-not-identity")
    assert _hi.assert_receipt_host_identity(
        {"host_identity": minted}) == minted, "minted id must validate"
    return "%s; minted id validates" % note


def _probe_hostname_digest_refused():
    d = _fresh_dir()
    minted = _hi.mint_host_id(os.path.join(d, "host_id"))
    assert minted != _HOST_SHA256  # sanity: random id != digest
    note = _expect_refusal(
        lambda: _hi.assert_receipt_host_identity(
            {"host_identity": _HOST_SHA256}),
        "hostid-hostname-digest-not-identity")
    note2 = _expect_refusal(
        lambda: _hi.assert_receipt_host_identity(
            {"host_identity": _HOST_SHA1}),
        "hostid-hostname-digest-not-identity")
    return "%s; %s" % (note, note2)


def _probe_unknown_fallback():
    assert _hi.assert_receipt_host_identity({}) == _hi.HOST_UNKNOWN
    assert _hi.HOST_UNKNOWN == "host_unknown"
    note = _expect_refusal(
        lambda: _hi.validate_host_identity(_hi.HOST_UNKNOWN),
        "hostid-malformed-identity")
    return "absent -> host_unknown; %s" % note


_PROBES = {
    "hostid-mint-stable": _probe_mint_stable,
    "hostid-race-same-id": _probe_race_same_id,
    "hostid-symlink-refused": _probe_symlink_refused,
    "hostid-hostname-refused": _probe_hostname_refused,
    "hostid-hostname-digest-refused": _probe_hostname_digest_refused,
    "hostid-unknown-fallback": _probe_unknown_fallback,
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("hostid-hostname-not-identity",
                     "hostid-hostname-digest-not-identity",
                     "hostid-symlink-at-id-path",
                     "hostid-id-file-corrupt",
                     "hostid-malformed-identity"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-241 host-identity mint-once probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in _PROBES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-38s %s %s" % (name, verdict, note))
    print("HELD %d / GAP %d / BREAK %d / ERROR %d" % (held, gap, brk, err))
    for note in _run_green_checks():
        print("green-check: %s" % note)
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
