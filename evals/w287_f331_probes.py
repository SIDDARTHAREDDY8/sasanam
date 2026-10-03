"""Wave-287 lane 1 battery: close F331 (LOW).

Red-first: on the pristine base, uncoded exceptions escape
gov/evidence_anchor.py public seams (raw ValueError from
render_checkpoint on a non-hex sig; raw NotADirectoryError from
TransparencyLog on a file log_root; raw TypeError/KeyError from
malformed sig entries and non-bytes inclusion inputs). After the fix,
every public seam refuses LOUD with a coded AnchorError in the
anchor-* domain (F327-class coded-refusal contract).

No new decision codes: the fix reuses anchor-checkpoint-invalid,
anchor-log-corrupt, and anchor-inclusion-mismatch. Taxonomy pin
unchanged at 1700.

Run:
  mkdir -p /var/tmp/g287-f331 && TMPDIR=/var/tmp/g287-f331 \
    ~/workspace/.gov-venv/bin/python evals/w287_f331_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g287-f331b \
    ~/workspace/.gov-venv/bin/python evals/w287_f331_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe
# +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*). This lane adds
# no decision codes: the fix reuses existing anchor-* codes.
TAXONOMY_PIN = 1820  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*)

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
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


_BODY = {"origin": "o", "size": 1, "root": b"x" * 32, "timestamp": 1,
         "witness_policy_id": "none"}


def _coded_anchor(pid, label, fn, want_code):
    """Assert fn raises coded AnchorError (BREAK if raw escapes)."""
    from gov import evidence_anchor as ea
    try:
        fn()
    except ea.AnchorError as e:
        if e.code == want_code:
            return _record(pid, "HELD",
                           "%s refused coded: %s" % (label, e.code))
        return _record(pid, "BREAK",
                       "%s coded but wrong code %r, want %r"
                       % (label, e.code, want_code))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "raw %s escapes %s -- expected coded "
                       "AnchorError" % (type(e).__name__, label))
    _record(pid, "BREAK", "%s accepted silently" % label)


def p_f331_render_nonhex_sig():
    from gov import evidence_anchor as ea
    _coded_anchor("f331-render-nonhex-sig", "render_checkpoint(non-hex)",
                  lambda: ea.render_checkpoint(_BODY, [{"keyid": "k",
                                                       "sig": "zzzz"}]),
                  "anchor-checkpoint-invalid")


def p_f331_render_sig_not_dict():
    from gov import evidence_anchor as ea
    _coded_anchor("f331-render-sig-not-dict", "render_checkpoint(str)",
                  lambda: ea.render_checkpoint(_BODY, ["nope"]),
                  "anchor-checkpoint-invalid")


def p_f331_render_sig_missing_key():
    from gov import evidence_anchor as ea
    _coded_anchor("f331-render-sig-missing-key",
                  "render_checkpoint(missing sig)",
                  lambda: ea.render_checkpoint(_BODY, [{"keyid": "k"}]),
                  "anchor-checkpoint-invalid")


def p_f331_render_sig_int():
    from gov import evidence_anchor as ea
    _coded_anchor("f331-render-sig-int", "render_checkpoint(int sig)",
                  lambda: ea.render_checkpoint(_BODY, [{"keyid": "k",
                                                       "sig": 123}]),
                  "anchor-checkpoint-invalid")


def p_f331_render_root_not_bytes():
    from gov import evidence_anchor as ea
    bad = dict(_BODY, root="x" * 32)
    _coded_anchor("f331-render-root-not-bytes",
                  "render_checkpoint(str root)",
                  lambda: ea.render_checkpoint(
                      bad, [{"keyid": "k", "sig": "ab" * 32}]),
                  "anchor-checkpoint-invalid")


def p_f331_render_wpid_not_str():
    from gov import evidence_anchor as ea
    bad = dict(_BODY, witness_policy_id=7)
    _coded_anchor("f331-render-wpid-not-str",
                  "render_checkpoint(int wpid)",
                  lambda: ea.render_checkpoint(
                      bad, [{"keyid": "k", "sig": "ab" * 32}]),
                  "anchor-checkpoint-invalid")


def p_f331_logroot_file():
    import tempfile as _tf
    from gov import evidence_anchor as ea
    fd, fpath = _tf.mkstemp(prefix="w287-f331-")
    os.close(fd)
    try:
        _coded_anchor("f331-logroot-file", "TransparencyLog(file)",
                      lambda: ea.TransparencyLog(fpath, "op", "opkey"),
                      "anchor-log-corrupt")
    finally:
        os.unlink(fpath)


def p_f331_verify_inclusion_leaf_not_bytes():
    from gov import evidence_anchor as ea
    proof = {"leaf_index": 0, "tree_size": 1, "hashes": []}
    _coded_anchor("f331-verify-inclusion-leaf-not-bytes",
                  "verify_inclusion(str leaf)",
                  lambda: ea.verify_inclusion("str", proof, b"x" * 32),
                  "anchor-inclusion-mismatch")


def p_f331_verify_inclusion_root_not_bytes():
    from gov import evidence_anchor as ea
    proof = {"leaf_index": 0, "tree_size": 1, "hashes": []}
    _coded_anchor("f331-verify-inclusion-root-not-bytes",
                  "verify_inclusion(str root)",
                  lambda: ea.verify_inclusion(b"x" * 32, proof, "str"),
                  "anchor-inclusion-mismatch")


def _no_over_refusal(pid, label, fn, expect=None):
    """Assert the good path still works (BREAK if it refuses/errors)."""
    from gov import evidence_anchor as ea
    try:
        got = fn()
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "%s over-refuses: %s %s"
                       % (label, type(e).__name__, str(e)[:60]))
    if expect is not None and got != expect:
        return _record(pid, "BREAK",
                       "%s returned %r, want %r" % (label, got, expect))
    _record(pid, "HELD", "%s good path intact" % label)


def p_guard_render_good():
    from gov import evidence_anchor as ea
    note = ea.render_checkpoint(
        _BODY, [{"keyid": "k", "sig": "ab" * 32}])
    if "\u2014 k " in note:
        _record("guard-render-good", "HELD",
                "render_checkpoint(valid) good path intact")
    else:
        _record("guard-render-good", "BREAK",
                "render_checkpoint(valid) dropped the sig line")


def p_guard_verify_inclusion_good():
    from gov import evidence_anchor as ea
    leaf = ea._hash_leaf(b"data")
    root = ea._tree_root_hashes([leaf])
    proof = {"leaf_index": 0, "tree_size": 1, "hashes": []}
    _no_over_refusal("guard-verify-inclusion-good",
                     "verify_inclusion(valid)",
                     lambda: ea.verify_inclusion(leaf, proof, root),
                     expect=True)


def p_guard_log_construct_good():
    import tempfile as _tf
    from gov import evidence_anchor as ea
    d = _tf.mkdtemp(prefix="w287-f331-good-")
    _no_over_refusal("guard-log-construct-good", "TransparencyLog(dir)",
                     lambda: ea.TransparencyLog(
                         d, "op", "opkey")._size, expect=0)


def _green_checks():
    if SKIP_GREEN:
        _record("green-skipped", "HELD",
                "depth-1 green checks skipped (GOV_SKIP_GREEN=1)")
        return
    # Depth-1: adjacent anchor-composition batteries only.
    checks = [
        "evals/w285_tessera_probes.py",
        "evals/w286_receipts_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w287-f331-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r"
                    % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    p_f331_render_nonhex_sig()
    p_f331_render_sig_not_dict()
    p_f331_render_sig_missing_key()
    p_f331_render_sig_int()
    p_f331_render_root_not_bytes()
    p_f331_render_wpid_not_str()
    p_f331_logroot_file()
    p_f331_verify_inclusion_leaf_not_bytes()
    p_f331_verify_inclusion_root_not_bytes()
    p_guard_render_good()
    p_guard_verify_inclusion_good()
    p_guard_log_construct_good()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w287_f331: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
