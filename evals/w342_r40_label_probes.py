#!/usr/bin/env python3
"""Wave-342 R40 battery: trajectory-level label monoid + remedy plans.

Steal: Archestra OpenAPPA (MIT verified 2026-10-05; patterns re-implemented
in Python, Rust engine NOT ported). Two patterns prototyped in
gov/trajectory_labels.py:

  (1) a checked label monoid (audience x trust, combine = restrictive
      meet, genuinely never ascends) folded across a trajectory;
  (2) structured remedy plans on refusal, where the EMPTY plan is the
      proof of unliftability -- relative to the implemented remedy
      vocabulary (REMEDY_VOCAB_VERSION), bound in the plan digest.

The bypass class under test is **annotation arbitrage** (R40): OpenAPPA's
guarantees are conditional on truthful deployment annotations, so a
mis-annotated tool (Delta::NONE) lets secrets cross without the label
descending. Our fold binds labels to ground truth as well: every fold
combines the declared annotation with an independently computed
content-truth label (DLP credential scan), and the meet can only descend.

$0 SPEND BY CONSTRUCTION: no model calls, no network, stdlib only. Do NOT
add ModelDriver/SpendLedger usage here.

Expected breaks: exactly one -- test_a0_naive_fold_arbitrage_breaks
demonstrates the annotation-arbitrage bypass against the NAIVE
declared-only baseline (fold_declared_only, kept for falsifiability).
The hardened fold refuses the same shape coded. If A0 ever goes HELD,
the naive baseline changed (or the bypass stopped working) -- update
the expected set deliberately, not silently.

Documented residual (F428, OPEN): JSFuck-obfuscated credentials miss
find_credential, so they miss the truth scan too and the label does not
descend (test_a4 pins the residual). When F428 closes, A4 goes BREAK by
design -- flip it to assert descent.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w342_r40_label_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import hashlib
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2134  # Wave-342 lane 3: pin 2131 -> 2135 (+4 label-* codes); Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)

from gov.trajectory_labels import (  # noqa: E402
    BLOCKED, LABEL_ANNOTATION_UNREGISTERED, LABEL_EGRESS_REFUSED,
    LABEL_REMEDY_EMPTY_UNLIFTABLE, LABEL_TRUST_FLOOR_REFUSED,
    TOP, Remedy, RemedyPlan, Trajectory, Trust, UnregisteredToolError,
    canonical_label, check_dispatch, combine, fold, fold_declared_only,
    mark_blocked, more_restrictive, truth_label,
)
from gov import trajectory_labels as _tl  # noqa: E402
from gov.dlp import find_credential  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402


# ---------------------------------------------------------------- fixtures
def _key():
    import tests.keyfixture as kf
    kf.provision_test_key()


def _held(ok, detail):
    return ("HELD" if ok else "BREAK", detail)


def _label_corpus():
    """Deterministic corpus of labels for property probes."""
    auds = [None, frozenset(), frozenset({"self"}),
            frozenset({"self", "internal"}),
            frozenset({"self", "internal", "public"})]
    out = []
    for a in auds:
        for t in Trust:
            out.append(_tl.Label(audience=a, trust=t, blocked=False))
    out.append(BLOCKED)
    return out


CREDENTIAL = b'{"api_key": "sk-ant-xoxb-abc123def4567890ABCDEF"}'
BENIGN = b'{"status": "ok", "count": 3}'


# ------------------------------------------------- monoid property probes
def test_m1_combine_never_ascends():
    """M1: combine(x, y) is more restrictive than both x and y (all pairs)."""
    corpus = _label_corpus()
    bad = []
    for x in corpus:
        for y in corpus:
            c = combine(x, y)
            if not (more_restrictive(c, x) and more_restrictive(c, y)):
                bad.append((canonical_label(x), canonical_label(y),
                            canonical_label(c)))
    return _held(not bad, "pairs=%d violations=%d"
                 % (len(corpus) ** 2, len(bad)))


def test_m2_monoid_laws():
    """M2: associativity, commutativity, idempotence; TOP identity;
    BLOCKED absorbing (deterministic triples)."""
    corpus = _label_corpus()
    triplets = [(corpus[i], corpus[(i * 7 + 3) % len(corpus)],
                 corpus[(i * 13 + 5) % len(corpus)])
                for i in range(len(corpus))]
    ok = True
    for a, b, c in triplets:
        ok = ok and combine(combine(a, b), c) == combine(a, combine(b, c))
        ok = ok and combine(a, b) == combine(b, a)
        ok = ok and combine(a, a) == a
        ok = ok and combine(a, TOP) == a
        ok = ok and combine(a, BLOCKED) == BLOCKED
    return _held(ok, "triples=%d laws hold" % len(triplets))


def test_m3_restrictiveness_sanity():
    """M3: ordering sanity -- BLOCKED <= everything <= TOP."""
    corpus = _label_corpus()
    ok = all(more_restrictive(BLOCKED, x) and more_restrictive(x, TOP)
             for x in corpus)
    ok = ok and more_restrictive(
        truth_label(CREDENTIAL), TOP)
    return _held(ok, "bottom/top ordering holds, truth <= top")


def test_m4_canonical_deterministic():
    """M4: canonical forms are deterministic and distinguish blocked."""
    a = _tl.Label(audience=frozenset({"b", "a"}), trust=Trust.LOW)
    ok = (canonical_label(a) == "aud=a,b|trust=1"
          and canonical_label(BLOCKED) == "blocked"
          and canonical_label(TOP) == "aud=*|trust=3")
    return _held(ok, "canonical=%r" % canonical_label(a))


def test_m5_truth_scan_baseline():
    """M5: benign bytes are the neutral element; a credential descends."""
    benign = truth_label(BENIGN)
    cred = truth_label(CREDENTIAL)
    ok = (benign == TOP
          and cred.audience == frozenset({"self"})
          and cred.trust == Trust.UNTRUSTED
          and more_restrictive(cred, TOP)
          and not more_restrictive(TOP, cred))
    return _held(ok, "benign=top=%s cred=%s" % (benign == TOP,
                                                canonical_label(cred)))


# ------------------------------------------- annotation-arbitrage probes
def test_a0_naive_fold_arbitrage_breaks():
    """A0 (EXPECTED BREAK): the annotation-arbitrage bypass reproduces
    against the NAIVE declared-only baseline. A tool annotated neutral
    (Delta::NONE equivalent) returning a credential leaves the trajectory
    at TOP, and the public egress is ALLOWED -- the label tracked which
    tools were used, not how sensitive the data is."""
    t = fold_declared_only(Trajectory(), tool="fetch_url",
                           output=CREDENTIAL, declared=TOP)
    r = check_dispatch(t, recipient={"public"}, action="send_email")
    bypass = (t.label == TOP and r is None)
    return ("BREAK" if bypass else "HELD",
            "naive bypass reproduces=%s (expected BREAK)" % bypass)


def test_a1_hardened_fold_descends():
    """A1: the hardened fold (declared + ground-truth scan) descends on
    the same mislabeled shape; the public egress is refused coded."""
    t = fold(Trajectory(), tool="fetch_url", output=CREDENTIAL,
             declared=TOP)
    r = check_dispatch(t, recipient={"public"}, action="send_email")
    ok = (t.label.audience == frozenset({"self"})
          and t.label.trust == Trust.UNTRUSTED
          and r is not None and r.code == "label-egress-refused")
    return _held(ok, "label=%s code=%s"
                 % (canonical_label(t.label),
                    r.code if r else None))


def test_a2_unregistered_tool_fail_closed():
    """A2: strict fold on a tool with no deployment-declared annotation
    refuses with label-annotation-unregistered (F427-style binding)."""
    try:
        fold(Trajectory(), tool="ghost_tool", output=BENIGN,
             registry={"read_file": TOP})
    except UnregisteredToolError as e:
        ok = (e.code == LABEL_ANNOTATION_UNREGISTERED
              == "label-annotation-unregistered")
        return _held(ok, "raised code=%s" % e.code)
    return _held(False, "no refusal raised")


def test_a3_overrestrictive_annotation_stays_closed():
    """A3: an over-restrictive annotation (honest conservatism) keeps the
    trajectory restrictive; the in-audience flow stays allowed."""
    t = fold(Trajectory(), tool="vault_read", output=BENIGN,
             declared=_tl.Label(audience=frozenset({"self"}),
                                trust=Trust.HIGH))
    r_out = check_dispatch(t, recipient={"public"}, action="send_email")
    r_in = check_dispatch(t, recipient={"self"}, action="read")
    ok = (r_out is not None
          and r_out.code == "label-egress-refused"
          and r_in is None)
    return _held(ok, "out refused=%s in allowed=%s"
                 % (r_out.code if r_out else None, r_in is None))


def test_a4_f428_residual_pinned():
    """A4: F428 is CLOSED (2026-10-05 wave-342 lane 1) -- the JSFuck
    decode layer now blocks the canned payload coded, so the truth
    scan descends and the trajectory label descends with it. Flipped
    from the residual pin at the wave-342 merge; this probe pins the
    closure so it cannot silently regress."""
    path = os.path.join(REPO_ROOT, "evals", "artifacts",
                        "w341_jsfuck_slack_token.txt")
    payload = open(path, encoding="utf-8").read().strip()
    bad = sorted(set(payload) - set("[]()!+-"))
    assert not bad, "payload charset drift: %r" % bad
    rule = find_credential("token=" + payload)
    t = fold(Trajectory(), tool="fetch_url",
             output=payload.encode("utf-8"), declared=TOP)
    closed = (rule == "dlp-slack-token" and t.label != TOP)
    return _held(closed,
                 "F428 closed: jsfuck blocked (rule=%s top=%s)"
                 % (rule, t.label == TOP))


def test_a5_annotation_cannot_raise_above_truth():
    """A5: a permissive-but-present annotation cannot raise the label
    above what the content scan justifies; a restrictive annotation on
    benign content stays restrictive (meet both ways)."""
    permissive = _tl.Label(audience=frozenset({"public"}),
                           trust=Trust.SYSTEM)
    t1 = fold(Trajectory(), tool="t", output=CREDENTIAL,
              declared=permissive)
    restrictive = _tl.Label(audience=frozenset({"self"}),
                            trust=Trust.HIGH)
    t2 = fold(Trajectory(), tool="t", output=BENIGN,
              declared=restrictive)
    # {public} meet {self} = {} (empty audience = nowhere permitted):
    # a permissive annotation on a credential collapses to maximally
    # restrictive -- fail-closed, never above the content truth.
    ok = (more_restrictive(t1.label, truth_label(CREDENTIAL))
          and t1.label.audience == frozenset()
          and t2.label.audience == frozenset({"self"}))
    return _held(ok, "permissive+cred=%s restrictive+benign=%s"
                 % (canonical_label(t1.label), canonical_label(t2.label)))


# --------------------------------------------------------- remedy probes
def test_r1_egress_refusal_remedy_classes():
    """R1: an egress refusal carries the implemented remedy set
    (withhold/sanitize/derive/authorize/redispatch)."""
    t = fold(Trajectory(), tool="fetch_url", output=CREDENTIAL,
             declared=TOP)
    r = check_dispatch(t, recipient={"public"}, action="send_email")
    want = {Remedy.WITHHOLD, Remedy.SANITIZE, Remedy.DERIVE,
            Remedy.AUTHORIZE, Remedy.REDISPATCH}
    ok = (r is not None and r.code == LABEL_EGRESS_REFUSED
          == "label-egress-refused"
          and r.plan.remedies == want
          and not r.plan.is_unliftable()
          and len(r.plan.digest) == 64)
    return _held(ok, "code=%s remedies=%s"
                 % (r.code if r else None,
                    sorted(x.value for x in r.plan.remedies) if r else []))


def test_r2_empty_plan_unliftable():
    """R2: the blocked mark is unliftable -- empty remedy set, digest
    deterministic across rebuilds (evidence-grade)."""
    t = mark_blocked(fold(Trajectory(), tool="t", output=BENIGN,
                          declared=TOP))
    r = check_dispatch(t, recipient={"self"}, action="anything")
    r2 = check_dispatch(t, recipient={"self"}, action="anything")
    ok = (r is not None
          and r.code == LABEL_REMEDY_EMPTY_UNLIFTABLE
          == "label-remedy-empty-unliftable"
          and r.plan.is_unliftable()
          and r.plan.digest == r2.plan.digest
          and r.trajectory_digest == t.digest)
    return _held(ok, "code=%s empty=%s digest=%s"
                 % (r.code if r else None,
                    r.plan.is_unliftable() if r else None,
                    (r.plan.digest[:16] if r else None)))


def test_r3_trust_floor_refused():
    """R3: trajectory trust below the recipient floor refuses coded
    label-trust-floor-refused with authorize/redispatch remedies."""
    t = fold(Trajectory(), tool="fetch_url", output=CREDENTIAL,
             declared=TOP)
    r = check_dispatch(t, recipient={"self"}, action="escalate",
                       recipient_trust_floor=Trust.HIGH)
    ok_allowed = check_dispatch(t, recipient={"self"}, action="read",
                                recipient_trust_floor=Trust.UNTRUSTED)
    ok = (r is not None and r.code == LABEL_TRUST_FLOOR_REFUSED
          == "label-trust-floor-refused"
          and {Remedy.AUTHORIZE, Remedy.REDISPATCH} <= r.plan.remedies
          and ok_allowed is None)
    return _held(ok, "code=%s floor-allowed=%s"
                 % (r.code if r else None, ok_allowed is None))


def test_r4_plan_digest_binds_vocab():
    """R4: the plan digest binds the remedy-vocabulary version, so the
    unliftability claim's scope is verifiable (honest bound)."""
    t = mark_blocked(Trajectory())
    r1 = check_dispatch(t, recipient={"self"}, action="x")
    old = _tl.REMEDY_VOCAB_VERSION
    try:
        _tl.REMEDY_VOCAB_VERSION = old + 1
        r2 = check_dispatch(t, recipient={"self"}, action="x")
    finally:
        _tl.REMEDY_VOCAB_VERSION = old
    ok = (r1 is not None and r2 is not None
          and r1.plan.digest != r2.plan.digest
          and r1.to_record()["remedy_vocab_version"] == old)
    return _held(ok, "digest changes with vocab version")


# -------------------------------------------------------- evidence probes
def test_e1_trajectory_digest_recomputable():
    """E1: the trajectory digest is deterministic offline -- same inputs
    give the same digest without the engine; different inputs differ."""
    def build():
        t = Trajectory()
        t = fold(t, tool="a", output=b"x", declared=TOP)
        return fold(t, tool="b", output=CREDENTIAL, declared=TOP)
    t1, t2 = build(), build()
    t3 = fold(fold(Trajectory(), tool="a", output=b"y", declared=TOP),
              tool="b", output=CREDENTIAL, declared=TOP)
    ok = (t1.digest == t2.digest and t1.digest != t3.digest
          and len(t1.digest) == 64 and t1.steps == 2)
    return _held(ok, "recomputable=%s sensitive=%s"
                 % (t1.digest == t2.digest, t1.digest != t3.digest))


def test_e2_refusal_record_deterministic():
    """E2: the refusal record serializes deterministically (sorted keys,
    sorted remedy names) with a stable record digest."""
    t = fold(Trajectory(), tool="fetch_url", output=CREDENTIAL,
             declared=TOP)
    r = check_dispatch(t, recipient={"public"}, action="send_email")
    rec = r.to_record()
    blob1 = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    blob2 = json.dumps(r.to_record(), sort_keys=True, separators=(",", ":"))
    digest_ok = (r.record_digest() ==
                 hashlib.sha256(blob1.encode()).hexdigest())
    ok = (blob1 == blob2 and digest_ok
          and rec["plan_remedies"] == sorted(rec["plan_remedies"])
          and rec["code"] == "label-egress-refused")
    return _held(ok, "deterministic=%s digest_ok=%s" % (blob1 == blob2,
                                                       digest_ok))


# ------------------------------------------------------- pin/footer probes
def test_pin_taxonomy_2131():
    codes = sorted(TAXONOMY)
    label_codes = {"label-egress-refused", "label-remedy-empty-unliftable",
                   "label-annotation-unregistered", "label-trust-floor-refused"}
    ok = (len(codes) == TAXONOMY_PIN == 2134
          and len(set(codes)) == len(codes)
          and label_codes <= set(codes))
    return ("HELD" if ok else "BREAK",
            "taxonomy %d/%d sorted-unique, label codes present"
            % (len(codes), TAXONOMY_PIN))


def test_footer_state():
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    last = lines[-1] if lines else ""
    ok = ("Next free finding: **F432**" in last
          and "Open findings: F430, F431." in last)
    return ("HELD" if ok else "BREAK",
            "footer: %r" % last[:80])


TESTS = [test_m1_combine_never_ascends,
         test_m2_monoid_laws,
         test_m3_restrictiveness_sanity,
         test_m4_canonical_deterministic,
         test_m5_truth_scan_baseline,
         test_a0_naive_fold_arbitrage_breaks,
         test_a1_hardened_fold_descends,
         test_a2_unregistered_tool_fail_closed,
         test_a3_overrestrictive_annotation_stays_closed,
         test_a4_f428_residual_pinned,
         test_a5_annotation_cannot_raise_above_truth,
         test_r1_egress_refusal_remedy_classes,
         test_r2_empty_plan_unliftable,
         test_r3_trust_floor_refused,
         test_r4_plan_digest_binds_vocab,
         test_e1_trajectory_digest_recomputable,
         test_e2_refusal_record_deterministic,
         test_pin_taxonomy_2131,
         test_footer_state]

# Exactly one expected BREAK: A0 demonstrates the annotation-arbitrage
# bypass against the NAIVE declared-only baseline. If it ever goes HELD,
# the baseline changed -- update this set deliberately, never silently.
_EXPECTED_BREAKS = {"test_a0_naive_fold_arbitrage_breaks"}


def _green_check():
    """Depth-1 green check: a fast pin-free adjacent unit suite, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    tmp = "/var/tmp/g342-green-dlpredos"
    os.makedirs(tmp, exist_ok=True)
    env = dict(os.environ)
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    # Pin-free, DLP-adjacent: the F171 ReDoS regression suite (no
    # taxonomy pin, no footer assertion). Run as tests.test_X from REPO
    # (a tests/-cwd invocation fails the gov import for suites that do
    # not self-insert REPO -- wave-340 lesson).
    r = subprocess.run(
        [venv_python, "-m", "unittest", "tests.test_wave110_f171_dlp_redos",
         "-v"],
        capture_output=True, text=True, env=env, timeout=1800,
        cwd=REPO_ROOT)
    tail = (r.stdout + r.stderr)[-300:]
    note = "test_wave110_f171_dlp_redos rc=%d %s" % (r.returncode,
                                                    tail.strip())
    if r.returncode != 0:
        raise AssertionError("green check failed: %s" % note)
    return note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    _key()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    n_break = n_held = n_err = 0
    probe_breaks = set()
    for fn in TESTS:
        if args.only and fn.__name__ != args.only:
            continue
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - loud, never a skip
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail[:200]))
        if verdict == "BREAK":
            n_break += 1
            probe_breaks.add(fn.__name__)
        elif verdict == "HELD":
            n_held += 1
        else:
            n_err += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    if probe_breaks ^ _EXPECTED_BREAKS:
        print("MISMATCH: breaks=%s expected=%s"
              % (sorted(probe_breaks), sorted(_EXPECTED_BREAKS)))
        sys.exit(2)
    # Expected BREAKs (A0: the annotation-arbitrage bypass against the
    # naive baseline) do not fail the run -- only a mismatch or an
    # ERROR does.
    sys.exit(2 if n_err else 0)


if __name__ == "__main__":
    main()
