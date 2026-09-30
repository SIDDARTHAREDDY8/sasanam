#!/usr/bin/env python3
"""Wave-234 lane A: octet-digest receipt chaining.

Break-first probes for the octet-digest chain link (prospectus W234-6,
three-source consensus: templeman framing-space-01,
sahu-agent-action-receipts-00, and the project's own evidence-bundle
rule): every appended audit-log entry commits to the EXACT transmitted
bytes of the previous record via ``prev_record_octets_digest``
(SHA-256 over the raw stored line bytes -- never a re-serialization),
HMAC-bound into the chain like every other link field.

Seams under test (all public):
* gov.log.ActionLog.append -- stamps the digest; genesis uses the
  documented OCTET_DIGEST_GENESIS constant; the field is reserved
  chain metadata (a caller-supplied value is dropped, never trusted).
* gov.log.verify_chain(path, require_octet_digest=True) -- verifies
  every link against the actual stored octets of the previous record.
  Refusals name the chain-domain taxonomy codes:
    chain-octet-digest-mismatch -- previous record re-encoded
        (byte-different, semantically equal); the deliberate failure
        mode: a canonicalizing linker MUST break this check.
    chain-octet-digest-absent -- entry carries no digest field;
        refuses instead of silently degrading to semantic chaining.
    chain-record-truncated -- previous record's bytes do not decode;
        refuses instead of silently skipping.
* Default verify_chain(path) behavior is unchanged (tighten-only).

Attack shapes: re-encode the previous record (sorted keys) and re-link
+ re-MAC the next entry (valid MAC, valid prev_hash -- only the octets
differ); strip the digest field and re-MAC (legacy log); truncate the
previous record's bytes mid-line; smuggle a caller-chosen digest value
in the append event; flip a digest hex char (must break the MAC).

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-233 HEAD
55d588664180cbe4657a07c4342df680c28cdc54.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (helpers absent) is
expected GAP. Any BREAK is a real product defect.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g234a
  TMPDIR=/var/tmp/g234a ~/workspace/.gov-venv/bin/python evals/w234_octetchain_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import inspect
import json
import secrets
import sys
import tempfile
import time
import traceback

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w234-octetchain-probes")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_MODULE = False
_log = None
try:
    from gov import log as _log
    HAVE_MODULE = all([
        getattr(_log, "OCTET_DIGEST_GENESIS", None) == "0" * 64,
        "require_octet_digest" in inspect.signature(
            _log.verify_chain).parameters,
        "require_octet_digest" in inspect.signature(
            _log.ActionLog.__init__).parameters,
        hasattr(_log, "OctetDigestError"),
    ])
except ImportError:
    _log = None

PROBE_NAMES = [
    "octetchain-valid-links-held",
    "octetchain-reencoded-previous-refused",
    "octetchain-absent-field-refused",
    "octetchain-truncated-previous-refused",
    "octetchain-genesis-constant",
    "octetchain-strict-writer-appends",
    "octetchain-default-verify-unchanged",
    "octetchain-field-hmac-bound",
    "octetchain-caller-cannot-forge-field",
]


def _held(cond, detail=""):
    return "HELD" if cond else "BREAK\n" + detail


def _gap(name):
    return "GAP (octet-digest helpers absent)"


def _new_log(path):
    return _log.ActionLog(path)


def _raw_lines(path):
    with open(path, "rb") as f:
        return f.read().split(b"\n")


def _write_chain(path, n=4, strict=False):
    log = _log.ActionLog(path, require_octet_digest=strict)
    for i in range(n):
        log.append({"kind": "octet-probe", "i": i})
    return log


def _read_entries(path):
    lines = _raw_lines(path)
    return [json.loads(l.decode("utf-8")) for l in lines if l.strip()]


def _write_legacy_log(path, raws):
    """Write a legacy-style log: no digest fields at all, MACs and the
    checkpoint sidecar recomputed so the chain is otherwise fully
    valid (what a pre-wave-234 writer's output looks like)."""
    key, epoch = _log._active_key()
    lines, cps = [], []
    prev = _log.GENESIS
    for raw in raws:
        e = json.loads(raw.decode("utf-8"))
        e.pop("prev_record_octets_digest", None)
        # Re-chain: prev_hash must point at the recomputed predecessor
        # hash, not the original (which covered the removed field).
        e["prev_hash"] = prev
        e["hash"] = _log._compute_mac(
            key, epoch, e["prev_hash"], _log._canonical(e))
        prev = e["hash"]
        lines.append((json.dumps(e, ensure_ascii=True) + "\n")
                     .encode("utf-8"))
        cps.append({"seq": e["seq"], "hash": e["hash"],
                    "key_epoch": epoch,
                    "format_version": _log.FORMAT_VERSION,
                    "mac": _log._checkpoint_mac(key, epoch, e["seq"],
                                                e["hash"])})
    with open(path, "wb") as f:
        f.write(b"".join(lines))
    cp_path = os.path.join(os.path.dirname(path), "checkpoints.jsonl")
    with open(cp_path, "w", encoding="utf-8") as f:
        for cp in cps:
            f.write(json.dumps(cp, ensure_ascii=True) + "\n")


def _reanchor_tail_checkpoint(log_dir, seq, new_hash):
    """Rewrite the seq-N checkpoint line with new_hash + a fresh MAC.

    A fully consistent forgery (re-linked entry + re-MAC) must also
    re-anchor the checkpoint sidecar: _verify checks the LATEST
    checkpoint's (seq, hash) against the tail (F27). The attacker in
    these probes holds the key, so the sidecar is re-minted exactly
    as ActionLog.write_checkpoint would mint it.
    """
    key, epoch = _log._active_key()
    cp_path = os.path.join(log_dir, "checkpoints.jsonl")
    out = []
    with open(cp_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cp = json.loads(line)
            if cp.get("seq") == seq:
                cp = {"seq": seq, "hash": new_hash,
                      "key_epoch": epoch,
                      "format_version": _log.FORMAT_VERSION,
                      "mac": _log._checkpoint_mac(key, epoch, seq,
                                                  new_hash)}
                line = json.dumps(cp, ensure_ascii=True)
            out.append(line)
    with open(cp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


# -- probes ---------------------------------------------------------------

def _probe_valid_links_held():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        _write_chain(path, 4)
        ok, broken, n = _log.verify_chain(path, require_octet_digest=True)
        return _held(ok and broken is None and n == 4,
                     "require_octet_digest=True failed a clean chain: "
                     "ok=%r broken=%r n=%r" % (ok, broken, n))


def _probe_reencoded_previous_refused():
    # The deliberate failure mode: the previous record is re-encoded
    # (semantically identical, byte-different) and the next entry is
    # re-linked over the RE-ENCODED bytes with a VALID MAC. The octet
    # check must refuse chain-octet-digest-mismatch even though the
    # MAC and prev_hash links are intact.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        _write_chain(path, 3)
        raws = [l for l in _raw_lines(path) if l.strip()]
        assert len(raws) == 3
        e2 = json.loads(raws[1].decode("utf-8"))
        reencoded = (json.dumps(e2, sort_keys=True, ensure_ascii=True)
                     + "\n").encode("utf-8")
        assert reencoded != raws[1] + b"\n", \
            "re-encoding must change the bytes for this probe"
        e3 = json.loads(raws[2].decode("utf-8"))
        e3["prev_record_octets_digest"] = \
            hashlib.sha256(reencoded).hexdigest()
        key, epoch = _log._active_key()
        e3["hash"] = _log._compute_mac(
            key, epoch, e3["prev_hash"], _log._canonical(e3))
        forged3 = (json.dumps(e3, ensure_ascii=True) + "\n").encode("utf-8")
        with open(path, "wb") as f:
            f.write(raws[0] + b"\n" + raws[1] + b"\n" + forged3)
        # Fully consistent forgery: the checkpoint sidecar is
        # re-anchored to the re-linked tail, so MACs, prev_hash links,
        # AND checkpoints all verify. Only the octet layer sees it.
        _reanchor_tail_checkpoint(d, 3, e3["hash"])
        ok, broken, n = _log.verify_chain(path, require_octet_digest=True)
        v = _log._verify(path, require_octet_digest=True)
        strict_names = v.get("error", "")
        # Default (opt-out) verification must still accept: MAC,
        # prev_hash, and checkpoints are all intact; only the octet
        # layer is stricter.
        default_triple = _log.verify_chain(path)
        return _held(
            (not ok) and "chain-octet-digest-mismatch" in strict_names
            and default_triple == (True, None, 3),
            "re-encoded previous record not refused by octet check: "
            "ok=%r error=%r default=%r"
            % (ok, strict_names, default_triple))


def _probe_absent_field_refused():
    # Legacy log: entries carry no digest field at all (MACs recomputed
    # so the chain is otherwise valid). require_octet_digest=True must
    # refuse chain-octet-digest-absent -- never silently degrade to
    # semantic chaining.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        _write_chain(path, 3)
        raws = [l for l in _raw_lines(path) if l.strip()]
        # The legacy chain is otherwise fully valid (MACs, prev_hash,
        # checkpoints); the only thing missing is the octet discipline.
        _write_legacy_log(path, raws)
        ok, broken, n = _log.verify_chain(path, require_octet_digest=True)
        v = _log._verify(path, require_octet_digest=True)
        default_triple = _log.verify_chain(path)
        return _held(
            (not ok) and "chain-octet-digest-absent" in v.get("error", "")
            and default_triple == (True, None, 3),
            "legacy log without digest fields not refused: ok=%r "
            "error=%r default=%r" % (ok, v.get("error"), default_triple))


def _probe_truncated_previous_refused():
    # The previous record's stored bytes are truncated mid-line (do not
    # decode). The octet check must refuse chain-record-truncated --
    # never silently skip the undecodable bytes.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        _write_chain(path, 3)
        raws = [l for l in _raw_lines(path) if l.strip()]
        truncated = raws[1][:len(raws[1]) // 2]
        assert truncated != raws[1]
        with open(path, "wb") as f:
            f.write(raws[0] + b"\n" + truncated + b"\n" + raws[2] + b"\n")
        ok, broken, n = _log.verify_chain(path, require_octet_digest=True)
        v = _log._verify(path, require_octet_digest=True)
        return _held(
            (not ok) and "chain-record-truncated" in v.get("error", ""),
            "truncated previous record not refused: ok=%r error=%r"
            % (ok, v.get("error")))


def _probe_genesis_constant():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        _write_chain(path, 1)
        entries = _read_entries(path)
        field = entries[0].get("prev_record_octets_digest")
        ok, broken, n = _log.verify_chain(path, require_octet_digest=True)
        return _held(field == "0" * 64 and ok and n == 1,
                     "genesis field=%r ok=%r n=%r" % (field, ok, n))


def _probe_strict_writer_appends():
    # Strict writer mode: normal appends carry the digest; the chain
    # verifies under require_octet_digest=True.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        log = _log.ActionLog(path, require_octet_digest=True)
        for i in range(3):
            e = log.append({"kind": "strict", "i": i})
            assert isinstance(
                e.get("prev_record_octets_digest"), str), \
                "strict writer must stamp the field"
        ok, broken, n = _log.verify_chain(path, require_octet_digest=True)
        return _held(ok and n == 3,
                     "strict-writer chain failed require verify: ok=%r n=%r"
                     % (ok, n))


def _probe_default_verify_unchanged():
    # Tighten-only: default verification accepts both new logs and
    # legacy logs (fields absent) exactly as before.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        _write_chain(path, 3)
        ok_new = _log.verify_chain(path)
        raws = [l for l in _raw_lines(path) if l.strip()]
        # The legacy log lives in its own directory so its checkpoint
        # sidecar anchors it (sidecars are per-directory).
        d2 = os.path.join(d, "legacy")
        os.mkdir(d2)
        path2 = os.path.join(d2, "audit.jsonl")
        _write_legacy_log(path2, raws)
        ok_legacy = _log.verify_chain(path2)
        return _held(ok_new == (True, None, 3)
                     and ok_legacy == (True, None, 3),
                     "default verify changed: new=%r legacy=%r"
                     % (ok_new, ok_legacy))


def _probe_field_hmac_bound():
    # Flipping one hex char of the digest field must break the MAC --
    # the field is bound into the chain, not cosmetic.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        _write_chain(path, 3)
        raws = [l for l in _raw_lines(path) if l.strip()]
        e2 = json.loads(raws[1].decode("utf-8"))
        old = e2["prev_record_octets_digest"]
        e2["prev_record_octets_digest"] = (
            ("0" if old[0] != "0" else "1") + old[1:])
        forged = (json.dumps(e2, ensure_ascii=True) + "\n").encode("utf-8")
        with open(path, "wb") as f:
            f.write(raws[0] + b"\n" + forged + b"\n" + raws[2] + b"\n")
        ok, broken, n = _log.verify_chain(path)
        return _held(not ok,
                     "tampered digest field passed default verify: ok=%r"
                     % (ok,))


def _probe_caller_cannot_forge_field():
    # The digest field is reserved chain metadata: a caller-supplied
    # value in the append event is dropped, the writer's own digest
    # stands, and the chain verifies under require_octet_digest=True.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.jsonl")
        log = _new_log(path)
        log.append({"kind": "a"})
        bogus = "f" * 64
        e = log.append({"kind": "b",
                        "prev_record_octets_digest": bogus})
        raws = [l for l in _raw_lines(path) if l.strip()]
        expected = hashlib.sha256(raws[0] + b"\n").hexdigest()
        ok, broken, n = _log.verify_chain(path, require_octet_digest=True)
        return _held(e.get("prev_record_octets_digest") == expected
                     and e.get("prev_record_octets_digest") != bogus
                     and ok and n == 2,
                     "caller value survived or chain failed: stored=%r "
                     "expected=%r ok=%r"
                     % (e.get("prev_record_octets_digest"),
                        expected, ok))


_PROBES = {
    "octetchain-valid-links-held": _probe_valid_links_held,
    "octetchain-reencoded-previous-refused":
        _probe_reencoded_previous_refused,
    "octetchain-absent-field-refused": _probe_absent_field_refused,
    "octetchain-truncated-previous-refused":
        _probe_truncated_previous_refused,
    "octetchain-genesis-constant": _probe_genesis_constant,
    "octetchain-strict-writer-appends": _probe_strict_writer_appends,
    "octetchain-default-verify-unchanged":
        _probe_default_verify_unchanged,
    "octetchain-field-hmac-bound": _probe_field_hmac_bound,
    "octetchain-caller-cannot-forge-field":
        _probe_caller_cannot_forge_field,
}


def _green_check():
    """Depth-1: adjacent suites run once, never nested."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIP (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    ok = True
    targets = [
        ["tests/test_log_octet_chain.py"],
        ["tests/test_log_integrity.py"],
        ["tests/test_decision_log_v2.py"],
        ["tests/test_decision_codes.py"],
    ]
    for t in targets:
        cmd = [sys.executable, "-m", "unittest", t[0]]
        proc = subprocess.run(cmd, cwd=REPO, env=env,
                              capture_output=True, text=True, timeout=600)
        label = " ".join(t)
        if proc.returncode != 0:
            print("green check: FAIL %s\n%s" % (label, proc.stderr[-800:]))
            ok = False
        else:
            print("green check: PASS %s" % label)
    return ok


def _run_all():
    results = {}
    for name in PROBE_NAMES:
        try:
            results[name] = _PROBES[name]()
        except Exception:  # noqa: BLE001
            results[name] = "ERROR\n" + traceback.format_exc(limit=3)
    return results


def main():
    t0 = time.time()
    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            print("%-42s %s" % (name, _gap(name)))
        print("summary: 0 HELD / %d GAP / 0 BREAK / 0 ERROR"
              % len(PROBE_NAMES))
        return 2
    results = _run_all()
    held = sum(1 for v in results.values() if v == "HELD")
    gap = sum(1 for v in results.values() if v.startswith("GAP"))
    brk = sum(1 for v in results.values() if v.startswith("BREAK"))
    err = sum(1 for v in results.values() if v.startswith("ERROR"))
    for name in PROBE_NAMES:
        verdict = results.get(name, "ERROR: missing")
        first = verdict.split("\n")[0]
        print("%-42s %s" % (name, first))
        if "\n" in verdict:
            print(verdict.split("\n", 1)[1])
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)"
          % (held, gap, brk, err, time.time() - t0))
    green_ok = _green_check()
    return 0 if (brk == 0 and err == 0 and green_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
