"""Wave-296 F368 closure battery: the invocation-pipeline invoke-time drift
digest must bind filter code + callable identity, not names only.

F368 (LOW): `_stack_digest` digested `[_filter_name(fn) for fn in filters]`
-- function `__name__` strings only. A wholesale in-process replacement of
`_filters` with same-named functions kept the digest byte-identical, so the
drift check passed and the replacement filters executed inside the
"unavoidable" pipeline.

Close-when: (1) the drift digest covers filter-code identity, so a
wholesale `_filters` replacement with same-named functions refuses coded
`toolcall-filter-frozen`, while the unchanged stack's digest stays stable
across invocations; (2) probe `drift-samename` flips to HELD; (3) adjacent
batteries stay green.

BASE: wave-295 merge 10777555. EXPECTED ON BASE: 1 BREAK / 6 HELD
(`drift-samename` BREAK; everything else HELD).
EXPECTED FIXED: 0 BREAK / 7 HELD / 0 ERROR.

No new decision codes: the refusal reuses `toolcall-filter-frozen`
(documented choice -- the defect is a freeze-bypass, and that code is the
freeze contract). Taxonomy pin stays 1750.

New batteries set the deployment mode at module level (wave-95 lesson)
and are verified under `env -u GOV_DEPLOYMENT_MODE`. Depth-1 green
checks: this battery's green check runs the adjacent batteries' mains
with GOV_SKIP_GREEN=1; every green-check function honors the var.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import re
import subprocess
import sys
import tempfile

_RESULTS = []

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import invocation_pipeline as ip  # noqa: E402

TAXONOMY_PIN = 2069 #; Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*)




def _record(pid, verdict, note):
    _RESULTS.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note))


def _ctx(call_id="f368"):
    return ip.InvocationContext(
        tool="t", args={}, caller={"identity": "tester"},
        session_id="s-f368", call_id=call_id)


def _sentinel_filter(context, next):
    return next(context)


def p_taxonomy_pin():
    src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
    codes = re.findall(r"""['"]code['"]\s*:\s*['"]([^'"]+)['"]""", src)
    if len(codes) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(codes), TAXONOMY_PIN))
    if len(set(codes)) != len(codes):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if codes != sorted(codes):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD",
            "taxonomy pin %d raw literals, unique, sorted (no new codes)"
            % (TAXONOMY_PIN,))


def p_drift_samename():
    # F368: wholesale _filters replacement with SAME-NAMED functions.
    # Two sub-cases: (a) different code, same name; (b) same code,
    # different closure instance (same __code__, different object).
    sub_breaks = []

    def evil(ctx, nxt):
        result = nxt(ctx)
        return "EVIL:" + str(result)

    evil.__name__ = _sentinel_filter.__name__  # same name as the original
    stack = ip.build_filter_stack([_sentinel_filter], name="f368-a")
    stack._filters = (evil,)
    try:
        result = stack.invoke(lambda c: "body", _ctx("f368-a"))
    except ip.InvocationPipelineError as e:
        if e.code != ip.FILTER_FROZEN:
            sub_breaks.append("sub-case (a): refused with %r, not "
                              "toolcall-filter-frozen" % (e.code,))
    else:
        if result == "EVIL:body":
            sub_breaks.append("sub-case (a): same-named different-code "
                              "replacement executed inside the pipeline")

    def _make_tagged(tag):
        def tagged_filter(context, nxt):
            result = nxt(context)
            return "TAG:%s:" % (tag,) + str(result)
        return tagged_filter

    legit = _make_tagged("legit")
    other_instance = _make_tagged("evil-instance")
    # Sanity: same name AND same code object, different objects.
    assert legit.__name__ == other_instance.__name__
    assert legit.__code__ is other_instance.__code__
    assert legit is not other_instance
    stack2 = ip.build_filter_stack([legit], name="f368-b")
    stack2._filters = (other_instance,)
    try:
        result2 = stack2.invoke(lambda c: "body", _ctx("f368-b"))
    except ip.InvocationPipelineError as e:
        if e.code != ip.FILTER_FROZEN:
            sub_breaks.append("sub-case (b): refused with %r, not "
                              "toolcall-filter-frozen" % (e.code,))
    else:
        if str(result2).startswith("TAG:evil-instance:"):
            sub_breaks.append("sub-case (b): same-code different-instance "
                              "replacement executed inside the pipeline")

    if sub_breaks:
        _record("drift-samename", "BREAK",
                "F368: " + "; ".join(sub_breaks))
    else:
        _record("drift-samename", "HELD",
                "same-name wholesale _filters replacement refuses coded "
                "toolcall-filter-frozen (different code AND different "
                "closure instance)")


def p_drift_othername():
    # Control: different-name replacement is (and was) caught.
    def other(ctx, nxt):
        return nxt(ctx)

    other.__name__ = "different_name"
    stack = ip.build_filter_stack([_sentinel_filter], name="f368-ctl")
    stack._filters = (other,)
    try:
        stack.invoke(lambda c: "body", _ctx("f368-ctl"))
    except ip.InvocationPipelineError as e:
        if e.code == ip.FILTER_FROZEN:
            return _record("drift-othername", "HELD",
                           "different-name replacement refuses coded "
                           "toolcall-filter-frozen")
        return _record("drift-othername", "BREAK",
                       "different-name replacement refused with %r"
                       % (e.code,))
    _record("drift-othername", "BREAK",
            "different-name replacement NOT caught")


def p_digest_stable():
    # The unchanged stack's digest stays stable across invocations.
    stack = ip.build_filter_stack([_sentinel_filter], name="f368-stable")
    d0 = stack.digest
    for i in range(3):
        stack.invoke(lambda c: "ok-%d" % i, _ctx("f368-stable-%d" % i))
    if stack.digest == d0 == ip._stack_digest(
            "f368-stable", stack._filters, stack._gate_holder):
        _record("digest-stable", "HELD",
                "construction digest == invoke-time digest across 3 "
                "invocations")
    else:
        _record("digest-stable", "BREAK",
                "digest moved under a legitimate stack")


def p_normal_invoke():
    # A legitimate stack still executes: the fix must not break the
    # pipeline itself.
    stack = ip.build_filter_stack([_sentinel_filter], name="f368-normal")
    try:
        result = stack.invoke(lambda c: "body", _ctx("f368-normal"))
    except Exception as e:  # noqa: BLE001
        return _record("normal-invoke", "BREAK",
                       "legitimate invoke refused: %r" % (e,))
    if result == "body":
        _record("normal-invoke", "HELD",
                "legitimate stack executes; body result passes through")
    else:
        _record("normal-invoke", "BREAK",
                "legitimate invoke returned %r" % (result,))


def p_add_filter_frozen():
    # The freeze contract itself still refuses LOUD.
    stack = ip.build_filter_stack([_sentinel_filter], name="f368-freeze")
    try:
        stack.add_filter(_sentinel_filter)
    except ip.InvocationPipelineError as e:
        if e.code == ip.FILTER_FROZEN:
            return _record("add-filter-frozen", "HELD",
                           "add_filter refuses coded toolcall-filter-frozen")
        return _record("add-filter-frozen", "BREAK",
                       "add_filter refused with %r" % (e.code,))
    _record("add-filter-frozen", "BREAK", "add_filter did not refuse")


def p_digest_binds_names():
    # Names remain part of the digest (no regression on the control).
    d1 = ip._stack_digest("n", [_sentinel_filter], None)

    def other_name(ctx, nxt):
        return nxt(ctx)

    d2 = ip._stack_digest("n", [other_name], None)
    if d1 != d2:
        _record("digest-binds-names", "HELD",
                "different filter names still produce different digests")
    else:
        _record("digest-binds-names", "BREAK",
                "name change no longer moves the digest")


# ---------------------------------------------------------------------------
# Depth-1 green checks (honor GOV_SKIP_GREEN; children spawn nothing).
# ---------------------------------------------------------------------------

def _run_child(name, want_breaks, want_break_ids=None, forbid_ids=()):
    pid = "green-" + name.replace("_probes.py", "")
    d = tempfile.mkdtemp(prefix="g296-f368-")
    try:
        proc = subprocess.run(
            [sys.executable, "evals/" + name],
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
            capture_output=True, text=True, timeout=1500,
            cwd=_REPO)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR", "child run failed: %r" % (e,))
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", proc.stdout)
    if not m:
        return _record(pid, "ERROR",
                       "no summary line in %s; rc=%d tail=%r"
                       % (name, proc.returncode, proc.stdout[-300:]))
    breaks = int(m.group(1))
    break_ids = re.findall(r"\[BREAK\] ([A-Za-z0-9_.-]+)", proc.stdout)
    if breaks != want_breaks:
        return _record(pid, "BREAK",
                       "%s: %d BREAK, want %d (ids=%r)"
                       % (name, breaks, want_breaks, break_ids))
    if want_break_ids is not None and set(break_ids) != set(want_break_ids):
        return _record(pid, "BREAK",
                       "%s: BREAK ids=%r, want %r"
                       % (name, break_ids, want_break_ids))
    for fid in forbid_ids:
        if fid in break_ids:
            return _record(pid, "BREAK",
                           "%s: %s still BREAK after F368 closure"
                           % (name, fid))
    _record(pid, "HELD", "%s: %d BREAK as expected" % (name, breaks))


def green_check():
    """Depth-1 green check. Honors GOV_SKIP_GREEN (wave-173 lesson)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    # w295_redteam: on the composed wave-296 tree F367/F368/F369/F370
    # are all CLOSED, so 0 BREAK expected (the lane-local tree had 3
    # still open). All four finding probes must be HELD.
    _run_child("w295_redteam_probes.py", 0,
               forbid_ids=("lease-future-issued-preempts",
                           "pipeline-drift-samename",
                           "pipeline-audit-aliasing",
                           "schema-nested-credkey-1",
                           "schema-nested-credkey-2"))
    # w294_filter_pipeline: F311-F364 CLOSED, 0 BREAK.
    _run_child("w294_filter_pipeline_probes.py", 0)


def main():
    green_check()
    p_taxonomy_pin()
    p_drift_samename()
    p_drift_othername()
    p_digest_stable()
    p_normal_invoke()
    p_add_filter_frozen()
    p_digest_binds_names()

    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
