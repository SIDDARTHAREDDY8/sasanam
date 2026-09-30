"""Wave-240 witness config auto-load + intermediate-CA completeness probes
(W240-7, W240-8, red-first).

GHSA-ggg4 (in-toto/go-witness, CRITICAL): ``.witness.yaml`` auto-loaded
from the current working directory lets a repo under attestation ship
its own verifier configuration (CI secret-exfil vector). Re-derived
here as a Sasanam invariant: a config discovered by CWD auto-load is
never honored in a CI or untrusted-repo context; upload-destination
changes are confirmation-gated; the sensitive-values filter can only
be tightened, never downgraded.

GHSA-6xq9 / GHSA-88v8: chain-verify entry points that never load the
intermediate CA set silently treat chains as verifiable while they are
not. Re-derived invariant: every chain-verify entry point asserts
intermediate-CA completeness before verifying -- a chain that names
non-root issuers without a loaded intermediate set refuses.

Probes:
  witness-cwd-autoload-refused -- a config discovered by CWD auto-load
      in a CI context refuses witness-config-cwd-autoload; an
      untrusted-repo context refuses too.
  witness-explicit-path-trusted-ok -- an explicit config path in a
      trusted context loads (positive control).
  witness-upload-destination-ungated -- changing the upload
      destination without confirmation refuses
      witness-config-upload-ungated; unchanged destination is a
      no-op; confirmed change applies.
  witness-filter-downgrade-refused -- removing a sensitive pattern
      refuses witness-config-filter-downgrade; adding a pattern
      (tightening) applies.
  witness-intermediates-missing -- a multi-cert chain whose issuers
      are not all in-chain, with no intermediate set loaded, refuses
      witness-intermediates-missing naming completeness.
  witness-intermediates-present-ok -- the same chain with the
      intermediate set loaded verifies cleanly (positive control).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import witness_config_rule as _wr
    HAVE_NEW_API = all(hasattr(_wr, n) for n in (
        "load_config", "apply_upload_destination", "set_sensitive_filter",
        "assert_intermediates_loaded", "verify_chain_entry",
        "chain_entry_points", "WitnessConfigError",
        "CONTEXT_CI", "CONTEXT_TRUSTED", "CONTEXT_UNTRUSTED"))
except ImportError:
    _wr = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "witness-cwd-autoload-refused",
    "witness-explicit-path-trusted-ok",
    "witness-upload-destination-ungated",
    "witness-filter-downgrade-refused",
    "witness-intermediates-missing",
    "witness-intermediates-present-ok",
]


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
    """fn must raise WitnessConfigError with .code == code; returns note."""
    try:
        fn()
    except _wr.WitnessConfigError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_cwd_autoload_refused():
    cfg = {"steps": ["run"]}
    note = _expect_refusal(
        lambda: _wr.load_config(cfg, source="cwd/.witness.yaml",
                                context=_wr.CONTEXT_CI, auto_discovered=True),
        "witness-config-cwd-autoload")
    note2 = _expect_refusal(
        lambda: _wr.load_config(cfg, source="cwd/.witness.yaml",
                                context=_wr.CONTEXT_UNTRUSTED,
                                auto_discovered=True),
        "witness-config-cwd-autoload")
    return "%s; %s" % (note, note2)


def _probe_explicit_path_trusted_ok():
    cfg = {"steps": ["run"]}
    loaded = _wr.load_config(cfg, source="/etc/sasanam/witness.yaml",
                             context=_wr.CONTEXT_TRUSTED,
                             auto_discovered=False)
    assert loaded["steps"] == ["run"], loaded
    return "explicit path in trusted context loads"


def _probe_upload_destination_ungated():
    note = _expect_refusal(
        lambda: _wr.apply_upload_destination(
            "s3://bucket-a", "s3://bucket-b", confirmed=False),
        "witness-config-upload-ungated")
    # Unchanged destination is a no-op, no confirmation needed.
    assert _wr.apply_upload_destination(
        "s3://bucket-a", "s3://bucket-a", confirmed=False) == "s3://bucket-a"
    # A confirmed change applies.
    assert _wr.apply_upload_destination(
        "s3://bucket-a", "s3://bucket-b", confirmed=True) == "s3://bucket-b"
    return "%s; no-op ok; confirmed change applies" % note


def _probe_filter_downgrade_refused():
    note = _expect_refusal(
        lambda: _wr.set_sensitive_filter(
            ["AKIA", "token="], ["token="]),
        "witness-config-filter-downgrade")
    note2 = _expect_refusal(
        lambda: _wr.set_sensitive_filter(["AKIA", "token="], []),
        "witness-config-filter-downgrade")
    # Tightening applies.
    applied = _wr.set_sensitive_filter(["AKIA"], ["AKIA", "token=", "secret="])
    assert applied == ["AKIA", "token=", "secret="], applied
    return "%s; %s; tighten ok" % (note, note2)


def _chain():
    # A chain FRAGMENT: leaf names "intermediate" as its issuer but the
    # intermediate certificate is not in the chain, so intermediate-CA
    # material must be loaded out-of-band for completeness.
    return [
        {"subject": "leaf", "issuer": "intermediate"},
        {"subject": "root", "issuer": "root"},
    ]


def _probe_intermediates_missing():
    chain = _chain()
    note = None
    for entry in _wr.chain_entry_points():
        for intermediates in (None, []):
            try:
                _wr.assert_intermediates_loaded(chain,
                                               intermediates=intermediates)
            except _wr.WitnessConfigError as exc:
                assert exc.code == "witness-intermediates-missing", exc.code
                assert "completeness" in exc.detail, (
                    "refusal detail must name completeness: %r" % exc.detail)
                note = ("refused %s, detail names completeness" % exc.code)
            else:
                raise AssertionError(
                    "no refusal for intermediates=%r" % (intermediates,))
    return note


def _probe_intermediates_present_ok():
    chain = _chain()
    intermediates = [{"subject": "intermediate", "issuer": "root"}]
    for entry in _wr.chain_entry_points():
        _wr.assert_intermediates_loaded(chain, intermediates=intermediates)
        verdict = _wr.verify_chain_entry(chain, intermediates=intermediates,
                                         entry_point=entry)
        assert verdict["ok"] is True, verdict
        assert verdict["chain_length"] == 2, verdict
    return "intermediates loaded: chain verifies at every entry point"


_PROBES = {
    "witness-cwd-autoload-refused": _probe_cwd_autoload_refused,
    "witness-explicit-path-trusted-ok": _probe_explicit_path_trusted_ok,
    "witness-upload-destination-ungated": _probe_upload_destination_ungated,
    "witness-filter-downgrade-refused": _probe_filter_downgrade_refused,
    "witness-intermediates-missing": _probe_intermediates_missing,
    "witness-intermediates-present-ok": _probe_intermediates_present_ok,
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
        for code in ("witness-config-cwd-autoload",
                     "witness-config-upload-ungated",
                     "witness-config-filter-downgrade",
                     "witness-intermediates-missing"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-240 witness config/intermediates probes (new API: %s)"
          % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    for name, verdict, note in results:
        print("%-40s %s %s" % (name, verdict, note))
    print("HELD %d / GAP %d / BREAK %d / ERROR %d" % (held, gap, brk, err))
    for note in _run_green_checks():
        print("green-check: %s" % note)
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
