"""Wave-243 action-bound permits, red-first (W243-5).

ADAPT of the bound-permit direction: a cross-trust-boundary permit is
bound to exactly one (recipient, key, request, action-instance) via the
``present_bound`` obligation hook. The permit declares a currentness
mode, every refusal it can raise comes from a REGISTERED vocabulary
(no ad-hoc refusal strings), and the recipient's confirmation is
signature-bound to the binding digest.

Probes:
  presenter-match-admitted -- the bound key presenting the bound
      action instance -> admitted (positive control).
  presenter-mismatch-refused -- a DIFFERENT key presenting the bound
      permit -> refused ``permit-presenter-mismatch``.
  instance-replay-refused -- the bound key replays the permit for a
      DIFFERENT action instance -> refused ``permit-instance-replay``.
  tamper-refused -- the binding record is edited after issue -> refused
      ``permit-tampered`` (falsifies silent re-binding).
  ad-hoc-refusal-vocabulary-refused -- a permit carrying (or raising)
      an unregistered refusal reason -> the permit itself is refused as
      non-conformant ``permit-refusal-vocabulary-invalid`` (falsifies
      ad-hoc refusal vocabulary).
  registered-refusal-admitted -- a permit whose refusal reason IS
      registered parses (positive control for the registry gate).
  currentness-fresh-admitted -- mode ``fresh-at-use`` presented WITH
      freshness evidence -> admitted (positive control).
  currentness-violated-refused -- mode ``fresh-at-use`` presented
      WITHOUT freshness evidence -> refused
      ``permit-currentness-violated``.
  currentness-none-admitted -- mode ``none`` presented without
      freshness evidence -> admitted (positive control).
  malformed-permit-refused -- non-dict / missing-field permits ->
      refused ``permit-malformed`` (falsifies shape blindness).

Stdlib + in-repo gov.ed25519 only. Deterministic. No in-repo git
subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_ABP = False
try:
    from gov import action_bound_permits as _abp
    HAVE_ABP = all(hasattr(_abp, n) for n in (
        "bind_permit", "present_bound", "raise_refusal",
        "registered_refusals", "ActionBoundPermitError"))
except ImportError:
    _abp = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "presenter-match-admitted",
    "presenter-mismatch-refused",
    "instance-replay-refused",
    "tamper-refused",
    "ad-hoc-refusal-vocabulary-refused",
    "registered-refusal-admitted",
    "currentness-fresh-admitted",
    "currentness-violated-refused",
    "currentness-none-admitted",
    "malformed-permit-refused",
]

_ISSUER_KEY = b"w243-lane-d-issuer-key-test-only-00"


def _permit(mode="none", key_ref="key://w1"):
    return _abp.bind_permit(
        recipient="agent://w1",
        key_ref=key_ref,
        request_digest="ab" * 32,
        action_instance="act-001",
        currentness_mode=mode,
        issuer_key=_ISSUER_KEY,
    )


def _ok(result, err_name):
    return result is True


def p_match():
    permit = _permit()
    return _abp.present_bound(permit, "key://w1", "act-001",
                             issuer_key=_ISSUER_KEY)


def p_mismatch():
    permit = _permit()
    try:
        _abp.present_bound(permit, "key://intruder", "act-001",
                           issuer_key=_ISSUER_KEY)
    except _abp.ActionBoundPermitError as e:
        return e.code == "permit-presenter-mismatch"
    return False


def p_replay():
    permit = _permit()
    try:
        _abp.present_bound(permit, "key://w1", "act-002",
                           issuer_key=_ISSUER_KEY)
    except _abp.ActionBoundPermitError as e:
        return e.code == "permit-instance-replay"
    return False


def p_tamper():
    permit = _permit()
    permit = dict(permit)
    permit["key_ref"] = "key://forged"
    try:
        _abp.present_bound(permit, "key://forged", "act-001",
                           issuer_key=_ISSUER_KEY)
    except _abp.ActionBoundPermitError as e:
        return e.code == "permit-tampered"
    return False


def p_adhoc_vocab():
    try:
        _abp.raise_refusal("not-a-registered-reason", "hand-waved")
    except _abp.ActionBoundPermitError as e:
        return e.code == "permit-refusal-vocabulary-invalid"
    return False


def p_registered_vocab():
    reasons = _abp.registered_refusals()
    return isinstance(reasons, (tuple, frozenset, list)) and all(
        isinstance(r, str) for r in reasons) and \
        "permit-presenter-mismatch" in reasons


def p_current_fresh():
    permit = _permit(mode="fresh-at-use")
    return _abp.present_bound(permit, "key://w1", "act-001",
                              issuer_key=_ISSUER_KEY,
                              freshness_evidence="fresh-at:2026-09-30")


def p_current_violated():
    permit = _permit(mode="fresh-at-use")
    try:
        _abp.present_bound(permit, "key://w1", "act-001",
                           issuer_key=_ISSUER_KEY)
    except _abp.ActionBoundPermitError as e:
        return e.code == "permit-currentness-violated"
    return False


def p_current_none():
    permit = _permit(mode="none")
    return _abp.present_bound(permit, "key://w1", "act-001",
                              issuer_key=_ISSUER_KEY)


def p_malformed():
    try:
        _abp.present_bound({"version": 1}, "key://w1", "act-001",
                           issuer_key=_ISSUER_KEY)
    except _abp.ActionBoundPermitError as e:
        return e.code == "permit-malformed"
    return False


_PROBES = {
    "presenter-match-admitted": p_match,
    "presenter-mismatch-refused": p_mismatch,
    "instance-replay-refused": p_replay,
    "tamper-refused": p_tamper,
    "ad-hoc-refusal-vocabulary-refused": p_adhoc_vocab,
    "registered-refusal-admitted": p_registered_vocab,
    "currentness-fresh-admitted": p_current_fresh,
    "currentness-violated-refused": p_current_violated,
    "currentness-none-admitted": p_current_none,
    "malformed-permit-refused": p_malformed,
}


def _run_probe(name):
    fn = _PROBES[name]
    if not HAVE_ABP:
        return name, "GAP", "capability absent on pristine base"
    try:
        held = fn()
    except Exception:
        return name, "ERROR", traceback.format_exc(limit=3)
    return name, ("HELD" if held else "FAIL"), \
        ("held" if held else "probe condition not met")


def main():
    results = [_run_probe(n) for n in PROBE_NAMES]
    held = sum(1 for _, s, _ in results if s == "HELD")
    for name, status, note in results:
        print("%-38s %-5s %s" % (name, status, note))
    print("%d/%d HELD" % (held, len(results)))
    return 0 if held == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
