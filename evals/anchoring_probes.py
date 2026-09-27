"""Break-first battery: pluggable external anchoring on the K-060 export path.

K-060 residual: the export bundle proves authenticity of INCLUDED entries,
not completeness against a key-holding exporter; and without a pinned
external anchor, verification proves self-consistency only. This battery
pins the pluggable anchoring seam:

* ``gov.anchoring`` re-exports the repo's established anchor interface
  (``gov.anchor_backend.AnchorBackend`` -- NOT a second parallel interface)
  and provides the export-path wiring: ``bundle_head_digest``,
  ``anchor_bundle``, ``verify_bundle_anchor``.
* ``gov.log.export_bundle`` accepts ``anchor_backend=None``; when supplied,
  the bundle carries ``anchor_receipt`` over the canonical head digest of
  its signed checkpoints. ``None`` = zero behavior change.
* ``gov.log.verify_export_bundle`` verifies the receipt when a backend is
  supplied; a receipt with no backend fails closed (never a silent skip).

Break-first: this battery was written BEFORE the seam existed (red:
ImportError on ``gov.anchoring``).

Honest ceilings (documented, not hidden):
* The default ``LocalAnchorLog`` backend adds NO external trust -- it is a
  second local hash chain in the same trust domain as the operator. It
  raises the bar from one-file tampering to two-file tampering and proves
  the anchor FORMAT and verification PATH, nothing more.
* Live external anchoring (RekorBackend exists in gov.anchor_backend but
  needs network + operator key pinning) remains unvalidated in this repo.
* A receipt verified without a pinned/independent anchor proves
  self-consistency only -- the pre-existing K-060 ceiling, restated.
* Anchoring binds the exporter to the committed checkpoints; it does not
  prove filter-completeness (an exporter who omits entries before
  anchoring is still invisible -- H20 pins this adversarially).
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from gov import anchoring as _anch  # noqa: E402  (RED before the seam lands)
from gov import log as _log  # noqa: E402
from gov import signing as _signing  # noqa: E402
from keyfixture import provision_test_key  # noqa: E402


def _seed(n):
    return bytes([n & 0xFF]) * 32


def _signed_log(n=6):
    """Fresh signed log dir; returns (log_path, signer, trust)."""
    provision_test_key(epoch="dev")
    d = Path(tempfile.mkdtemp(prefix="govanchor-"))
    signer = _signing.Ed25519Signer(_seed(1))
    lg = _log.ActionLog(str(d / "actions.jsonl"), signer=signer)
    for i in range(1, n + 1):
        lg.append({"event": "tool_call", "n": i, "principal": "org1",
                   "agent_id": "a1"})
    trust = {signer.key_id: signer.public_key}
    return str(d / "actions.jsonl"), signer, trust, d


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def a1_local_backend_roundtrip():
    """LocalAnchorLog anchors a digest and verifies the receipt."""
    d = Path(tempfile.mkdtemp(prefix="govanchor-"))
    backend = _anch.LocalAnchorLog(str(d / "anchors.jsonl"))
    digest = hashlib.sha256(b"head-bytes").hexdigest()
    receipt = backend.submit(digest)
    if not isinstance(receipt, dict) or "backend" not in receipt:
        return ("BREAK", "submit did not return a receipt dict: %r"
                % (receipt,))
    ok, reason = backend.verify_receipt(receipt, anchor_hash=digest)
    if not ok:
        return ("BREAK", "fresh receipt failed verification: %s" % reason)
    return ("HELD", "local backend anchors + verifies a digest")


def a2_tampered_digest_fails():
    """A receipt verified against a DIFFERENT digest must fail."""
    d = Path(tempfile.mkdtemp(prefix="govanchor-"))
    backend = _anch.LocalAnchorLog(str(d / "anchors.jsonl"))
    digest = hashlib.sha256(b"head-bytes").hexdigest()
    receipt = backend.submit(digest)
    other = hashlib.sha256(b"other-bytes").hexdigest()
    ok, reason = backend.verify_receipt(receipt, anchor_hash=other)
    if ok:
        return ("BREAK", "receipt verified against a tampered digest")
    return ("HELD", "tampered digest rejected (%s)" % reason)


def a3_tampered_anchor_file_fails_closed():
    """Corrupting the local anchor file must fail verification closed,
    not crash and not pass."""
    d = Path(tempfile.mkdtemp(prefix="govanchor-"))
    apath = d / "anchors.jsonl"
    backend = _anch.LocalAnchorLog(str(apath))
    digest = hashlib.sha256(b"head-bytes").hexdigest()
    receipt = backend.submit(digest)
    # Tamper: rewrite the chained hash of the first record.
    lines = apath.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["chain_hash"] = "0" * 64
    apath.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    try:
        ok, reason = backend.verify_receipt(receipt, anchor_hash=digest)
    except Exception as e:  # noqa: BLE001 -- fail-closed means no raise
        return ("BREAK", "verify_receipt raised on tampered file: %r" % e)
    if ok:
        return ("BREAK", "tampered anchor file still verifies")
    return ("HELD", "tampered anchor file fails closed (%s)" % reason)


def a4_export_carries_verifiable_receipt():
    """export_bundle(anchor_backend=...) includes an anchor_receipt over
    the log head that verifies against the backend."""
    log_path, _signer, trust, d = _signed_log()
    backend = _anch.LocalAnchorLog(str(d / "anchors.jsonl"))
    bundle = _log.export_bundle(log_path, principal="org1",
                               anchor_backend=backend)
    receipt = bundle.get("anchor_receipt")
    if not isinstance(receipt, dict):
        return ("BREAK", "no anchor_receipt in bundle: %s"
                % sorted(bundle.keys()))
    ok, reason = _anch.verify_bundle_anchor(bundle, receipt, backend)
    if not ok:
        return ("BREAK", "bundle receipt failed verification: %s" % reason)
    # And through the public verify path:
    ok, err = _log.verify_export_bundle(bundle, trust,
                                        anchor_backend=backend)
    if not ok:
        return ("BREAK", "verify_export_bundle rejected anchored bundle: "
                "%s" % err)
    # The receipt must bind the checkpoints actually in the bundle:
    # swapping in different checkpoints must break receipt verification.
    other_path, _s2, _t2, _d2 = _signed_log(n=9)
    other = _log.export_bundle(other_path, principal="org1")
    tampered = copy.deepcopy(bundle)
    tampered["checkpoints"] = other["checkpoints"]
    ok, _ = _anch.verify_bundle_anchor(tampered, receipt, backend)
    if ok:
        return ("BREAK", "receipt verified against swapped checkpoints")
    return ("HELD", "export carries a verifiable head-anchored receipt")


def a5_no_backend_is_byte_identical():
    """anchor_backend=None (and omitting the kwarg) must produce exactly
    the pre-seam bundle: no new keys, no behavior change."""
    log_path, _signer, _trust, _d = _signed_log()
    b1 = _log.export_bundle(log_path, principal="org1")
    b2 = _log.export_bundle(log_path, principal="org1",
                            anchor_backend=None)
    # exported_at is wall-clock; normalize it, everything else must be
    # byte-identical under canonical encoding.
    for b in (b1, b2):
        b["exported_at"] = "NORMALIZED"
    if _canon(b1) != _canon(b2):
        return ("BREAK", "anchor_backend=None changed the bundle")
    if "anchor_receipt" in b2:
        return ("BREAK", "anchor_receipt present without a backend")
    return ("HELD", "no-backend export is byte-identical to pre-seam")


def a6_custom_backend_plugs_in():
    """A third-party backend implementing the interface plugs into the
    export seam (proves the interface is real, not a LocalAnchorLog
    special case)."""
    from gov.anchor_backend import AnchorBackend

    class GistCalendarBackend(AnchorBackend):
        """Test double for the BYO 'calendar-hash via public gist' shape:
        the receipt mirrors the documented gist receipt
        (``gov/anchoring.py`` BYO section 3)."""

        def __init__(self):
            self.published = []
            self.calendar_head = "0" * 64

        def submit(self, anchor_hash):
            from gov.anchor_backend import _check_anchor_hash
            ahash = _check_anchor_hash(anchor_hash)
            self.calendar_head = hashlib.sha256(
                b"gist-calendar/v1\x00"
                + bytes.fromhex(self.calendar_head)
                + bytes.fromhex(ahash)).hexdigest()
            receipt = {"backend": "gist-calendar",
                       "gist_id": "deadbeef" * 8,
                       "gist_rev": "rev-%d" % len(self.published),
                       "anchor_hash": ahash,
                       "calendar_hash": self.calendar_head,
                       "witness_time": "2026-09-27T00:00:00+00:00"}
            self.published.append(receipt)
            return receipt

        def verify_receipt(self, receipt, *, anchor_hash):
            try:
                if receipt.get("backend") != "gist-calendar":
                    return False, "wrong backend"
                if receipt.get("anchor_hash") != anchor_hash:
                    return False, "different anchor"
                if not receipt.get("gist_id") or \
                        not receipt.get("gist_rev"):
                    return False, "no published gist reference"
                # The calendar link is recomputable by the auditor from
                # the published chain; here we check the receipt is
                # well-formed and self-consistent (the out-of-band gist
                # fetch at the pinned rev is the auditor's job).
                int(receipt["calendar_hash"], 16)
                return True, None
            except (TypeError, ValueError) as e:
                return False, "malformed: %s" % e

    log_path, _signer, trust, _d = _signed_log()
    backend = GistCalendarBackend()
    bundle = _log.export_bundle(log_path, principal="org1",
                               anchor_backend=backend)
    receipt = bundle.get("anchor_receipt")
    if not isinstance(receipt, dict) or receipt.get("backend") \
            != "gist-calendar":
        return ("BREAK", "custom backend receipt missing: %s"
                % sorted(bundle.keys()))
    ok, err = _log.verify_export_bundle(bundle, trust,
                                        anchor_backend=backend)
    if not ok:
        return ("BREAK", "custom backend receipt rejected: %s" % err)
    return ("HELD", "third-party backend plugs into the export seam")


def a7_receipt_without_backend_fails_closed():
    """An anchored bundle verified WITHOUT a backend must fail closed --
    never silently skip the receipt."""
    log_path, _signer, trust, d = _signed_log()
    backend = _anch.LocalAnchorLog(str(d / "anchors.jsonl"))
    bundle = _log.export_bundle(log_path, principal="org1",
                               anchor_backend=backend)
    ok, err = _log.verify_export_bundle(bundle, trust)
    if ok:
        return ("BREAK", "anchored bundle verified with no backend "
                "(receipt silently skipped)")
    return ("HELD", "receipt without backend fails closed (%s)" % err)


PROBES = [a1_local_backend_roundtrip,
          a2_tampered_digest_fails,
          a3_tampered_anchor_file_fails_closed,
          a4_export_carries_verifiable_receipt,
          a5_no_backend_is_byte_identical,
          a6_custom_backend_plugs_in,
          a7_receipt_without_backend_fails_closed]


def main():
    import traceback
    tmp = os.environ.get("TMPDIR", "/tmp")
    Path(tmp).mkdir(parents=True, exist_ok=True)
    held = brk = err = 0
    for probe in PROBES:
        name = probe.__name__
        try:
            status, detail = probe()
        except Exception:  # noqa: BLE001
            status, detail = ("ERROR", traceback.format_exc(limit=3))
        print("  %-38s %-5s %s" % (name, status, detail))
        if status == "HELD":
            held += 1
        elif status == "BREAK":
            brk += 1
        else:
            err += 1
    print("anchoring battery: %d BREAK / %d HELD / %d ERROR" % (brk, held,
                                                               err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
