#!/usr/bin/env python3
"""Break-first battery: filter-binding in K-060 anchor statements
(wave-142 lane 3).

K-060 residual (H20, wave-125): exporter-narrowing before anchoring
stays invisible -- the anchor binds the checkpoint head but not WHAT
was filtered to produce the export. ``evals/anchoring_probes.py``
pinned the pluggable anchor seam; this battery pins the
filter-binding on top of it:

* ``gov.anchoring.export_filter_digest(filter_params)`` -- canonical
  SHA-256 over the export's filter/selection parameters (the
  ``**query`` of ``gov.log.export_bundle``: seq/ts ranges, run
  filters, limit; never raw data).
* ``gov.log.export_bundle(..., anchor_backend=...)`` sets
  ``bundle["filter_digest"]`` BEFORE anchoring, so the anchored body
  (``bundle_head_digest``) commits to checkpoints AND the filter.
* ``gov.log.verify_export_bundle`` recomputes the filter digest from
  ``bundle["query"]`` and fails closed on mismatch -- filter
  parameters altered after anchoring do not verify.

Break-first: this battery was written BEFORE the seam existed (red:
``export_filter_digest`` missing from ``gov.anchoring``).

Probes:
  f1_different_filters_different_digests: two exports of the same
     log with different selection filters (limit=2 vs limit=4) ->
     different ``filter_digest`` values; BOTH verify (backend
     supplied).
  f2_altered_filter_fails: export with a backend; alter
     ``bundle["query"]`` after anchoring -> ``verify_export_bundle``
     fails (filter_digest mismatch). Tampering with
     ``bundle["filter_digest"]`` itself -> fails too (the anchor
     receipt binds the committed digest).
  f3_empty_filter_verifies: export with NO filter params + backend
     -> ``filter_digest`` is the digest of the empty/canonical-default
     filter; the bundle verifies.
  f4_no_backend_byte_identical: ``anchor_backend=None`` (and omitting
     the kwarg) produces exactly the pre-wave-142 bundle: no
     ``filter_digest`` key, no ``anchor_receipt`` key, no behavior
     change when anchoring is off.
  f5_receipt_binds_filter: the anchor receipt commits to the filter
     digest -- re-anchoring is the only way to change it: a bundle
     whose query was narrowed and whose filter_digest was recomputed
     WITHOUT re-anchoring fails receipt verification (the receipt
     still binds the old digest).
  f6_deterministic_x2: byte-identical verdicts across 2 runs.

Honest ceilings (documented, not hidden):
* The digest proves the filter parameters are AS STATED, not that
  they were WISE -- a malicious-but-disclosed narrowing is still the
  operator's/auditor's judgment call. Narrowing is now VISIBLE, not
  prevented.
* Unpinned verification still proves self-consistency only (the
  pre-existing K-060 ceiling, restated): without an independent
  anchor, a key-holder can re-anchor a narrowed export.
* The digest covers the SELECTION parameters (the export's query),
  never entry contents -- it cannot leak raw data, and it cannot
  prove anything about entries the filter excluded beyond the fact
  that the filter, as stated, excludes them.

$0 spend, synthetic/local, deterministic. Stdlib only.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from gov import anchoring as _anch  # noqa: E402
from gov import log as _log  # noqa: E402
from gov import signing as _signing  # noqa: E402
from keyfixture import provision_test_key  # noqa: E402

_HAVE_FILTER = hasattr(_anch, "export_filter_digest")

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-38s %-10s %s" % (name, verdict, detail))


def _seed(n):
    return bytes([n & 0xFF]) * 32


def _signed_log(n=6):
    """Fresh signed log dir; returns (log_path, trust, backend, dir)."""
    provision_test_key(epoch="dev")
    d = Path(tempfile.mkdtemp(prefix="govfilterbind-"))
    signer = _signing.Ed25519Signer(_seed(1))
    lg = _log.ActionLog(str(d / "actions.jsonl"), signer=signer)
    for i in range(1, n + 1):
        lg.append({"event": "tool_call", "n": i, "principal": "org1",
                   "agent_id": "a1"})
    trust = {signer.key_id: signer.public_key}
    backend = _anch.LocalAnchorLog(str(d / "anchors.jsonl"))
    return str(d / "actions.jsonl"), trust, backend, d


def _missing():
    return ("BREAK", "filter-binding seam MISSING: "
            "gov.anchoring.export_filter_digest not implemented")


# ---------------------------------------------------------------- probes

def f1_different_filters_different_digests():
    name = "f1_different_filters_different_digests"
    if not _HAVE_FILTER:
        _record(name, *_missing())
        return
    log_path, trust, backend, _d = _signed_log()
    b_narrow = _log.export_bundle(log_path, principal="org1", limit=2,
                                  anchor_backend=backend)
    b_wide = _log.export_bundle(log_path, principal="org1", limit=4,
                                anchor_backend=backend)
    fn, fw = b_narrow.get("filter_digest"), b_wide.get("filter_digest")
    if not isinstance(fn, str) or not isinstance(fw, str):
        _record(name, "BREAK",
                "filter_digest missing: narrow=%r wide=%r" % (fn, fw))
        return
    if fn == fw:
        _record(name, "BREAK",
                "different filters produced the SAME filter_digest")
        return
    for b, label in ((b_narrow, "narrow"), (b_wide, "wide")):
        ok, err = _log.verify_export_bundle(b, trust,
                                             anchor_backend=backend)
        if not ok:
            _record(name, "BREAK",
                    "%s export failed verification: %s" % (label, err))
            return
    _record(name, "HELD",
            "limit=2 vs limit=4 -> distinct filter_digests "
            "(%.12s... vs %.12s...); both verify"
            % (fn, fw))


def f2_altered_filter_fails():
    name = "f2_altered_filter_fails"
    if not _HAVE_FILTER:
        _record(name, *_missing())
        return
    log_path, trust, backend, _d = _signed_log()
    bundle = _log.export_bundle(log_path, principal="org1", limit=4,
                                anchor_backend=backend)
    # Attack 1: narrow the stated filter after anchoring (the
    # exporter covers a wider pull with a narrower story).
    tampered = copy.deepcopy(bundle)
    tampered["query"]["limit"] = 2
    ok, err = _log.verify_export_bundle(tampered, trust,
                                        anchor_backend=backend)
    if ok:
        _record(name, "BREAK",
                "altered filter parameters verified (filter_digest "
                "not bound to the query)")
        return
    # Attack 2: rewrite the filter_digest itself -- the anchor
    # receipt still binds the committed (original) digest.
    tampered2 = copy.deepcopy(bundle)
    tampered2["filter_digest"] = "0" * 64
    ok2, err2 = _log.verify_export_bundle(tampered2, trust,
                                          anchor_backend=backend)
    if ok2:
        _record(name, "BREAK",
                "rewritten filter_digest verified (receipt does not "
                "bind the digest)")
        return
    _record(name, "HELD",
            "post-anchor filter tampering fails (%s); digest "
            "rewrite fails (%s)" % (err, err2))


def f3_empty_filter_verifies():
    name = "f3_empty_filter_verifies"
    if not _HAVE_FILTER:
        _record(name, *_missing())
        return
    log_path, trust, backend, _d = _signed_log()
    bundle = _log.export_bundle(log_path, anchor_backend=backend)
    fd = bundle.get("filter_digest")
    if not isinstance(fd, str):
        _record(name, "BREAK", "no filter_digest on no-filter export")
        return
    if fd != _anch.export_filter_digest({}):
        _record(name, "BREAK",
                "no-filter digest != digest of the empty filter")
        return
    ok, err = _log.verify_export_bundle(bundle, trust,
                                        anchor_backend=backend)
    if not ok:
        _record(name, "BREAK",
                "no-filter anchored export failed verification: %s"
                % (err,))
        return
    _record(name, "HELD",
            "no-filter export: filter_digest over the empty filter "
            "(%.12s...), verifies" % (fd,))


def f4_no_backend_byte_identical():
    name = "f4_no_backend_byte_identical"
    log_path, _trust, _backend, _d = _signed_log()

    def _canon(obj):
        import json as _json
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, default=str)

    b1 = _log.export_bundle(log_path, principal="org1")
    b2 = _log.export_bundle(log_path, principal="org1",
                            anchor_backend=None)
    for b in (b1, b2):
        b["exported_at"] = "NORMALIZED"
    if _canon(b1) != _canon(b2):
        _record(name, "BREAK", "anchor_backend=None changed the bundle")
        return
    if "filter_digest" in b2 or "anchor_receipt" in b2:
        _record(name, "BREAK",
                "no-backend export carries filter_digest/anchor_receipt")
        return
    _record(name, "HELD",
            "no-backend export byte-identical to pre-wave-142 "
            "(no filter_digest, no anchor_receipt)")


def f5_receipt_binds_filter():
    name = "f5_receipt_binds_filter"
    if not _HAVE_FILTER:
        _record(name, *_missing())
        return
    log_path, trust, backend, _d = _signed_log()
    bundle = _log.export_bundle(log_path, principal="org1", limit=4,
                                anchor_backend=backend)
    receipt = bundle.get("anchor_receipt")
    # The exporter narrows the story AND recomputes the digest to
    # match, but does NOT re-anchor (re-anchoring would be visible
    # to the witness as a second anchor event).
    forged = copy.deepcopy(bundle)
    forged["query"]["limit"] = 2
    forged["filter_digest"] = _anch.export_filter_digest(
        forged["query"])
    ok, reason = _anch.verify_bundle_anchor(forged, receipt, backend)
    if ok:
        _record(name, "BREAK",
                "receipt verified against a re-digested narrowed "
                "filter (receipt does not bind the filter)")
        return
    _record(name, "HELD",
            "receipt binds the anchored filter digest: narrowed + "
            "re-digested bundle fails receipt verification (%s)"
            % (reason,))


def _run_all():
    global _RESULTS
    _RESULTS = []
    f1_different_filters_different_digests()
    f2_altered_filter_fails()
    f3_empty_filter_verifies()
    f4_no_backend_byte_identical()
    f5_receipt_binds_filter()
    return list(_RESULTS)


def f6_deterministic_x2():
    name = "f6_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r" % (v1, v2))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    _run_all()
    f6_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("export_filter_binding_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
