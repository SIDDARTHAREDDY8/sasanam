#!/usr/bin/env python3
"""Wave-236 lane A: close-record signer binding (treeship TS-2026-004 steal).

Attack shapes at the public seams (break-first, red-first on base):
* the chain verifier pins the close-record signer to the chain-root
  session-start signer: a close record signed by a different-but-LISTED
  key refuses ``close-signer-mismatch`` (names expected vs observed ids),
  even when the different key is pinned in the external trust root;
* a rewritten receipt re-presented under a different signer refuses,
  naming the signer mismatch;
* a close record re-pointing a trust id (same kid label, different key
  material) refuses ``close-trust-repointed`` via the wave-235
  trust_material key-id->material pinning, reused additively;
* a verifier asked to rely on a scope/authority field outside the
  close record's signature-covered body refuses ``close-unsigned-scope``
  fail-closed, never silently accepting or silently ignoring it;
* a close record whose chain digest does not match the recomputed
  digest over the chain refuses ``close-chain-digest-mismatch``
  (rewritten records break the binding by construction);
* control: a legitimate close record (same signer, digest matches,
  trust root binds, signature verifies, relied fields covered)
  verifies;
* a forged close record that merely CLAIMS the session signer's id
  and carries the correct pinned material -- but is signed by an
  attacker's key -- refuses ``close-signature-invalid`` (the
  signature is authenticated against the root's pinned material,
  never the record's self-assertion);
* log.py seam: the opt-in ``require_close_binding=True`` mode fails
  closed with ``close-signer-absent`` on plain HMAC logs that carry no
  signer identity, and the default ``verify_chain`` path is
  byte-identical in behavior.

Seams under test:
* gov/close_signer_binding.py -- verify_close_record, session_start_signer,
  canonical_chain_digest, adapt_log_entries, CloseSignerBindingError codes.
* gov/log.py -- verify_chain(..., require_close_binding=,
  close_record=, close_trust_root=, close_relied_scope_fields=)
  (additive keyword-only seams).

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-235 HEAD 3a5c97f6b421c89791b0c7811efe804252701dff.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g236a
  TMPDIR=/var/tmp/g236a ~/workspace/.gov-venv/bin/python evals/w236_closebind_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import secrets
import sys
import time
import traceback

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w236-closebind-probes")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

from gov import trust_material as _tm  # noqa: E402  (wave-235, always present)
from gov import ed25519 as _ed  # noqa: E402  (vendored stdlib-only)

HAVE_NEW_API = False
try:
    from gov import close_signer_binding as _cb
    HAVE_NEW_API = all(hasattr(_cb, n) for n in (
        "verify_close_record", "session_start_signer",
        "canonical_chain_digest", "adapt_log_entries",
        "close_sig_body", "CloseSignerBindingError"))
except ImportError:
    _cb = None

# Real Ed25519 keypairs (deterministic seeds; never secrets, fixtures
# only). The trust root pins the PUBLIC keys; close records are signed
# with the seeds. SEED_REPOINT is an attacker key the root never pins.
SEED_ROOT_A = hashlib.sha256(b"w236-closebind-seed-a").digest()
SEED_ROOT_B = hashlib.sha256(b"w236-closebind-seed-b").digest()
SEED_REPOINT = hashlib.sha256(b"w236-closebind-seed-attacker").digest()
PUB_A = _ed.publickey(SEED_ROOT_A)
PUB_B = _ed.publickey(SEED_ROOT_B)

PROBE_NAMES = [
    "closebind-different-listed-key-refused",
    "closebind-rewritten-receipt-signer-mismatch",
    "closebind-trust-id-repoint-refused",
    "closebind-unsigned-scope-refused",
    "closebind-chain-digest-mismatch-refused",
    "closebind-legitimate-close-verifies",
    "closebind-forged-close-signature-refused",
    "closebind-log-seam-optin",
]


def _record(signer_id, body, key_material=None, signed_fields=None):
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    rec = {"signer_id": signer_id, "digest": digest, "body": body}
    if key_material is not None:
        rec["key_material"] = key_material
    rec["signed_fields"] = tuple(sorted(signed_fields if signed_fields
                                        else body.keys()))
    return rec


def _chain(n=3, signer="key-a", seed=SEED_ROOT_A):
    return [_record(signer, {"seq": i, "op": "act-%d" % i},
                    key_material=seed) for i in range(n)]


def _close_record(chain, signer_id, seed, key_material, signed_fields=("seq",)):
    """A genuinely SIGNED close record: ed_sig over the sig body."""
    rec = {
        "signer_id": signer_id,
        "key_material": key_material,
        "chain_digest": _cb.canonical_chain_digest(chain),
        "signed_fields": tuple(sorted(signed_fields)),
    }
    rec["ed_sig"] = _ed.sign(seed, _cb.close_sig_body(rec)).hex()
    return rec


def _root():
    return _tm.TrustRoot({"key-a": PUB_A, "key-b": PUB_B})


def _code_of(exc):
    return getattr(exc, "code", None)


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return (name, "BREAK", "GAP: module absent on base")
    t0 = time.time()
    try:
        verdict, note = fn()
    except Exception:  # noqa: BLE001
        return (name, "ERROR", traceback.format_exc(limit=3).strip())
    return (name, "HELD" if verdict else "BREAK",
            "%s (%.1fms)" % (note, 1000 * (time.time() - t0)))


def probe_different_listed_key():
    # The close record is signed by key-b, which IS pinned in the external
    # trust root -- but the session started under key-a. Must still refuse,
    # naming expected vs observed ids.
    chain = _chain(signer="key-a")
    close = _close_record(chain, "key-b", SEED_ROOT_B, PUB_B)
    try:
        _cb.verify_close_record(chain, close, trust_root=_root())
    except _cb.CloseSignerBindingError as exc:
        ok = (exc.code == "close-signer-mismatch"
              and "key-a" in (exc.detail or "")
              and "key-b" in (exc.detail or ""))
        return ok, "refused %s naming expected/observed" % exc.code
    return False, "different-but-listed signer was ACCEPTED"


def probe_rewritten_receipt_signer_mismatch():
    # Attacker rewrites a middle receipt, re-signs the whole chain under
    # key-b, and presents a close record signed by key-b. The rewritten
    # chain re-verifies on its own terms -- the binding must refuse by
    # naming the signer mismatch against the ORIGINAL session start.
    chain = _chain(signer="key-a")
    rewritten = _chain(signer="key-b")  # attacker re-mints under key-b
    close = _close_record(rewritten, "key-b", SEED_ROOT_B, PUB_B)
    try:
        _cb.verify_close_record(chain, close, trust_root=_root())
    except _cb.CloseSignerBindingError as exc:
        ok = (exc.code == "close-signer-mismatch"
              and "key-a" in (exc.detail or "")
              and "key-b" in (exc.detail or ""))
        return ok, "rewritten chain refused, signer mismatch named"
    return False, "rewritten chain's close record was ACCEPTED"


def probe_trust_id_repoint():
    # Same kid label "key-a", but the close record carries DIFFERENT key
    # material than the externally-pinned root: the label was re-pointed.
    chain = _chain(signer="key-a")
    attacker_pub = _ed.publickey(SEED_REPOINT)
    close = _close_record(chain, "key-a", SEED_REPOINT, attacker_pub)
    try:
        _cb.verify_close_record(chain, close, trust_root=_root())
    except _cb.CloseSignerBindingError as exc:
        ok = exc.code == "close-trust-repointed"
        return ok, "re-pointed trust id refused with %s" % exc.code
    return False, "re-pointed trust id was ACCEPTED"


def probe_unsigned_scope():
    # The verifier is asked to rely on "approval_limit", which is NOT in
    # the close record's signature-covered fields: fail closed.
    chain = _chain(signer="key-a")
    close = _close_record(chain, "key-a", SEED_ROOT_A, PUB_A,
                          signed_fields=("seq",))
    try:
        _cb.verify_close_record(chain, close, trust_root=_root(),
                                relied_scope_fields=("approval_limit",))
    except _cb.CloseSignerBindingError as exc:
        ok = exc.code == "close-unsigned-scope"
        return ok, "unsigned scope reliance refused with %s" % exc.code
    return False, "unsigned scope field was silently consulted"


def probe_chain_digest_mismatch():
    # The close record's chain_digest is stale: a chain record was
    # rewritten (byte-different) after the close record was minted.
    chain = _chain(signer="key-a")
    close = _close_record(chain, "key-a", SEED_ROOT_A, PUB_A)
    tampered = [dict(r) for r in chain]
    tampered[1] = _record("key-a", {"seq": 1, "op": "act-1-EVIL"},
                         key_material=SEED_ROOT_A)
    try:
        _cb.verify_close_record(tampered, close, trust_root=_root())
    except _cb.CloseSignerBindingError as exc:
        ok = exc.code == "close-chain-digest-mismatch"
        return ok, "rewritten record refused with %s" % exc.code
    return False, "stale chain digest was ACCEPTED"


def probe_legitimate_close():
    # Control: same signer, digest matches, trust root binds the exact
    # pinned material, relied fields are signature-covered -> verifies.
    chain = _chain(signer="key-a")
    close = _close_record(chain, "key-a", SEED_ROOT_A, PUB_A,
                          signed_fields=("seq", "chain_digest"))
    verdict = _cb.verify_close_record(
        chain, close, trust_root=_root(),
        relied_scope_fields=("seq",))
    ok = (isinstance(verdict, dict) and verdict.get("ok") is True
          and verdict.get("session_start_signer") == "key-a"
          and verdict.get("close_signer") == "key-a")
    return ok, "legitimate close record verifies"


def probe_forged_close_signature():
    # The spec review's attack: a forged close record that merely CLAIMS
    # the session signer's id "key-a" and carries the CORRECT pinned
    # material -- but is signed by the attacker's key. The binding must
    # authenticate the signature against the root's pinned material and
    # refuse close-signature-invalid, not trust the self-asserted id.
    chain = _chain(signer="key-a")
    close = _close_record(chain, "key-a", SEED_REPOINT, PUB_A,
                          signed_fields=("seq", "chain_digest"))
    try:
        _cb.verify_close_record(chain, close, trust_root=_root(),
                                relied_scope_fields=("seq",))
    except _cb.CloseSignerBindingError as exc:
        ok = exc.code == "close-signature-invalid"
        return ok, "forged close record refused with %s" % exc.code
    return False, "forged close record was ACCEPTED"


def probe_log_seam_optin():
    # gov/log.py seam: default path unchanged; opt-in mode on a plain
    # HMAC log (no signer identity) fails closed with close-signer-absent.
    from gov import log as _log
    import tempfile
    tmp = tempfile.mkdtemp(prefix="closebind-seam-")
    path = os.path.join(tmp, "audit.log")
    lg = _log.ActionLog(path)
    lg.append({"op": "a1"})
    lg.append({"op": "a2"})
    default = _log.verify_chain(path)
    if not (default[0] is True and default[2] == 2):
        return False, "default verify_chain did not verify the test log"
    # Core: chain record with no signer identity -> session-start signer
    # cannot be pinned -> close-signer-absent (close record itself is
    # well-formed so the shape checks pass first).
    chain = [{"signer_id": None, "digest": "ab" * 32}]
    try:
        _cb.verify_close_record(
            chain,
            {"signer_id": "key-a",
             "chain_digest": _cb.canonical_chain_digest(chain),
             "signed_fields": ()})
    except _cb.CloseSignerBindingError as exc:
        core = exc.code == "close-signer-absent"
    else:
        core = False
    # Opt-in mode through the log seam: plain HMAC log entries carry no
    # sig_key_id -> adapt them, mint a close record with the CORRECT
    # chain digest, and the post-pass must still fail closed with
    # close-signer-absent, never silently pass.
    with open(path, encoding="utf-8") as fh:
        parsed = [json.loads(line) for line in fh.read().splitlines()
                  if line.strip()]
    records = _cb.adapt_log_entries(parsed)
    err = _log._verify(path, require_close_binding=True,
                       close_record={"signer_id": "key-a",
                                     "key_material": SEED_ROOT_A,
                                     "chain_digest":
                                         _cb.canonical_chain_digest(records),
                                     "signed_fields": ()})
    seam = (err.get("ok") is False
            and "close-signer-absent" in (err.get("error") or ""))
    ok = core and seam
    return ok, ("core absent-signer refusal %s; log-seam opt-in fails "
                "closed %s" % ("ok" if core else "MISSING",
                               "ok" if seam else "MISSING"))


_PROBES = {
    "closebind-different-listed-key-refused": probe_different_listed_key,
    "closebind-rewritten-receipt-signer-mismatch":
        probe_rewritten_receipt_signer_mismatch,
    "closebind-trust-id-repoint-refused": probe_trust_id_repoint,
    "closebind-unsigned-scope-refused": probe_unsigned_scope,
    "closebind-chain-digest-mismatch-refused": probe_chain_digest_mismatch,
    "closebind-legitimate-close-verifies": probe_legitimate_close,
    "closebind-forged-close-signature-refused": probe_forged_close_signature,
    "closebind-log-seam-optin": probe_log_seam_optin,
}


def main():
    print("wave-236 close-record signer binding probes "
          "(new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
