"""Wave-292 lane 3 battery: delegation decay with theft lineage probes.

Base: wave-291 push 255478f (verified via git rev-parse HEAD before work).

New product surface (gov/delegation_chain.py):
  (a) bounded lifetime -- every delegation carries issued_at +
      ttl_seconds (+ generation counter); delegate() requires an
      explicit ttl; expiry (issued_at + ttl) is verified at each hop
      (coded delegation-expired); pre-decay records without the new
      fields are refused fail-closed (treated as expired);
  (b) rotation -- rotate() re-issues a leaf (same slot, same
      delegator, narrowing-only, generation+1) and mints a signed
      succession record binding retired_digest -> successor_digest;
  (c) theft lineage -- DelegationVerifier.register_succession()
      maintains a bounded retirement lineage; presenting a retired
      leaf is a REVOCATION EVENT (delegation-retired-reuse), not an
      auth failure; the immediate predecessor is tolerated once
      (RECENT_PREV, signed lineage note in the receipt); a forked
      child under a retired leaf refuses delegation-orphaned-branch;
      an older generation with a newer succession refuses
      delegation-stale-lineage; a full lineage refuses new
      successions fail-closed (delegation-lineage-overflow).

Red-first: on the pristine base the new-API probes BREAK (feature
absent: AttributeError on rotate/register_succession, no ttl
requirement, no lineage); on the fixed tree they must HELD with
loud coded refusals.

Run:
  mkdir -p /var/tmp/g292-decay && TMPDIR=/var/tmp/g292-decay \
    ~/workspace/.gov-venv/bin/python evals/w292_delegation_decay_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g292-decay2 \
    ~/workspace/.gov-venv/bin/python evals/w292_delegation_decay_probes.py
"""

import copy
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import delegation_chain as dc  # noqa: E402
from gov import ed25519  # noqa: E402

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1797  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


NOW = 1700000000.0
ACTION = {"with": "fs:/docs/report", "can": "read"}
_RWINDOW = {"not_before": NOW - 100.0, "not_after": NOW + 3600.0}


def _seed(label):
    return hashlib.sha256(b"w292-decay-" + label.encode()).digest()


def _pub(label):
    return ed25519.publickey(_seed(label)).hex()


def _caps(with_, cans):
    return [{"with": with_, "can": list(cans)}]


def _delegate(seed, held, audience_pub, caps, parent=None, ttl=3700,
              **kw):
    req = {"audience": audience_pub,
           "capabilities": caps,
           "not_before": NOW - 100.0,
           "not_after": NOW - 100.0 + ttl,
           "ttl": ttl,
           "parent": parent}
    req.update(kw)
    return dc.delegate(seed, held, req)


def _chain3(ttl=3700):
    """root(r->a) -> mid(a->b) -> leaf(b->c), all narrowing."""
    r, a, b, c = (_seed("r"), _seed("a"), _seed("b"), _seed("c"))
    root = _delegate(r, None, _pub("a"),
                    _caps("fs:/", ["read", "write"]), ttl=ttl)
    mid = _delegate(a, _caps("fs:/", ["read", "write"]), _pub("b"),
                    _caps("fs:/", ["read", "write"]), parent=root,
                    ttl=ttl)
    leaf = _delegate(b, _caps("fs:/", ["read", "write"]), _pub("c"),
                     _caps("fs:/docs", ["read"]), parent=mid, ttl=ttl)
    v = dc.DelegationVerifier([_pub("r")], seed=_seed("vseed"))
    return (r, a, b, c), [root, mid, leaf], v


def _code_of(fn):
    try:
        fn()
    except dc.DelegationError as e:
        return e.code
    except AttributeError as e:
        return "ATTR:" + str(e)
    return None


# ---------------------------------------------------------------------------
# Taxonomy pin.
# ---------------------------------------------------------------------------

def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    codes = _literals()
    ok = (len(codes) == TAXONOMY_PIN and len(set(codes)) == TAXONOMY_PIN
          and codes == sorted(codes))
    for new in ("delegation-retired-reuse", "delegation-orphaned-branch",
                "delegation-stale-lineage", "delegation-lineage-overflow"):
        if new not in codes:
            ok = False
    # delegation-expired is reused, not re-minted (lane-6 precedent).
    if ok:
        _record("pin-taxonomy", "HELD", "1797/1797/0 sorted")
    else:
        _record("pin-taxonomy", "BREAK",
                "taxonomy pin mismatch: %d literals" % len(codes))


# ---------------------------------------------------------------------------
# Repins (subprocess, depth-1, GOV_SKIP_GREEN=1, fresh TMPDIRs).
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # Wave-291 build lane: narrowing must stay green under decay.
    ("evals/w291_delegation_probes.py", 0, "w291-delegation"),
    # Wave-291 red team: F356 (2 BREAK) still open in this lane.
    # Wave-292 merge: F356 closed by wave-292 lane 1, so the
    # w291-redteam repin is 0 BREAK on the composed tree.
    ("evals/w291_redteam_probes.py", 0, "w291-redteam"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w292-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=1200,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("repin-" + label, "ERROR",
                    "subprocess failed: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # Wave-286 lesson: take the LAST "N BREAK" match (the footer),
        # not per-probe notes.
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak == expected_breaks:
            _record("repin-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("repin-" + label, "BREAK",
                    "%s: %d BREAK, expected %d"
                    % (rel, nbreak, expected_breaks))


# ---------------------------------------------------------------------------
# Probes: ttl / decay (feature-absent on base).
# ---------------------------------------------------------------------------

def p_ttl_required_at_issue():
    """delegate() without ttl must refuse (no unbounded delegations)."""
    req = {"audience": _pub("a"), "capabilities": _caps("fs:/", ["read"]),
           "not_before": NOW - 100.0, "not_after": NOW + 3600.0,
           "parent": None}
    code = _code_of(lambda: dc.delegate(_seed("r"), None, req))
    if code == "delegation-malformed":
        _record("ttl-required", "HELD", "missing ttl refused at issue")
    elif code is None:
        _record("ttl-required", "BREAK",
                "delegate() issued a delegation with no ttl")
    else:
        _record("ttl-required", "BREAK", "unexpected code %r" % code)


def p_ttl_zero_negative_refused():
    bad = []
    for ttl in (0, -5, 0.0):
        req = {"audience": _pub("a"),
               "capabilities": _caps("fs:/", ["read"]),
               "not_before": NOW - 100.0, "not_after": NOW + 3600.0,
               "ttl": ttl, "parent": None}
        if _code_of(lambda: dc.delegate(_seed("r"), None, req)) is None:
            bad.append(ttl)
    if not bad:
        _record("ttl-nonpositive", "HELD", "zero/negative ttl refused")
    else:
        _record("ttl-nonpositive", "BREAK",
                "non-positive ttl accepted: %r" % (bad,))


def p_ttl_excessive_refused():
    req = {"audience": _pub("a"), "capabilities": _caps("fs:/", ["read"]),
           "not_before": NOW - 100.0, "not_after": NOW + 3600.0,
           "ttl": 2 ** 40 + 1, "parent": None}
    code = _code_of(lambda: dc.delegate(_seed("r"), None, req))
    if code == "delegation-malformed":
        _record("ttl-excessive", "HELD", "ttl > 2**40 refused")
    elif code is None:
        _record("ttl-excessive", "BREAK", "excessive ttl accepted")
    else:
        _record("ttl-excessive", "BREAK", "unexpected code %r" % code)


def p_body_carries_decay_fields():
    sealed = _delegate(_seed("r"), None, _pub("a"),
                       _caps("fs:/", ["read"]))
    body = sealed["delegation"]
    missing = [f for f in ("issued_at", "ttl_seconds", "generation")
               if f not in body]
    if not missing and body["ttl_seconds"] == 3700 \
            and body["generation"] == 0:
        _record("decay-fields", "HELD",
                "issued_at/ttl_seconds/generation present")
    else:
        _record("decay-fields", "BREAK",
                "missing or wrong decay fields: %r" % (missing,))


def p_ttl_window_consistency():
    """A caller-supplied window disagreeing with issued_at+ttl is a
    confused issuer: refused at issue, never silently repaired."""
    req = {"audience": _pub("a"), "capabilities": _caps("fs:/", ["read"]),
           "not_before": NOW - 100.0, "not_after": NOW + 99999.0,
           "ttl": 3700, "parent": None}
    code = _code_of(lambda: dc.delegate(_seed("r"), None, req))
    if code == "delegation-malformed":
        _record("ttl-consistency", "HELD",
                "window/ttl disagreement refused at issue")
    elif code is None:
        _record("ttl-consistency", "BREAK",
                "inconsistent window silently accepted")
    else:
        _record("ttl-consistency", "BREAK", "unexpected code %r" % code)


def p_decay_expiry_refused():
    """issued_at + ttl elapsed -> coded delegation-expired at verify."""
    (r, a, b, c), chain, v = _chain3(ttl=100)
    code = _code_of(lambda: v.verify(chain, ACTION, now=NOW + 200.0))
    if code == "delegation-expired":
        _record("decay-expiry", "HELD", "elapsed ttl refused coded")
    elif code is None:
        _record("decay-expiry", "BREAK", "elapsed ttl verified OK")
    else:
        _record("decay-expiry", "BREAK", "unexpected code %r" % code)


def p_decay_midchain_expiry():
    """Expiry at hop 2 of 3 refuses the whole chain."""
    r, a, b, c = (_seed("r"), _seed("a"), _seed("b"), _seed("c"))
    root = _delegate(r, None, _pub("a"), _caps("fs:/", ["read", "write"]))
    mid = _delegate(a, _caps("fs:/", ["read", "write"]), _pub("b"),
                    _caps("fs:/", ["read", "write"]), parent=root, ttl=100)
    leaf = _delegate(b, _caps("fs:/", ["read", "write"]), _pub("c"),
                     _caps("fs:/docs", ["read"]), parent=mid)
    v = dc.DelegationVerifier([_pub("r")])
    code = _code_of(lambda: v.verify([root, mid, leaf], ACTION,
                                     now=NOW + 200.0))
    if code == "delegation-expired":
        _record("decay-midchain", "HELD", "hop-2 expiry refused coded")
    elif code is None:
        _record("decay-midchain", "BREAK", "expired mid hop verified")
    else:
        _record("decay-midchain", "BREAK", "unexpected code %r" % code)


def p_legacy_record_refused():
    """A pre-decay record (no issued_at/ttl_seconds/generation),
    re-signed by its issuer, is refused fail-closed (treated as
    expired) -- never grandfathered into the new verifier."""
    r, a = _seed("r"), _seed("a")
    sealed = _delegate(r, None, _pub("a"), _caps("fs:/", ["read"]))
    legacy_body = {k: v for k, v in sealed["delegation"].items()
                   if k not in ("issued_at", "ttl_seconds", "generation")}
    sig = ed25519.sign(r, dc.SIGN_DOMAIN + dc._canonical(legacy_body)
                       ).hex()
    legacy = {"delegation": legacy_body, "signature": sig}
    v = dc.DelegationVerifier([_pub("r")])
    code = _code_of(lambda: v.verify([legacy], ACTION, now=NOW))
    if code == "delegation-expired":
        _record("legacy-refused", "HELD",
                "pre-decay record refused fail-closed")
    elif code is None:
        _record("legacy-refused", "BREAK",
                "pre-decay record verified OK (grandfathered)")
    else:
        _record("legacy-refused", "BREAK", "unexpected code %r" % code)


# ---------------------------------------------------------------------------
# Probes: rotation + theft lineage (feature-absent on base).
# ---------------------------------------------------------------------------

class _FeatureAbsent(Exception):
    pass


def _rotated():
    """Rotate the leaf of a 3-hop chain; register the succession.

    Raises _FeatureAbsent on the pristine base (no rotate API)."""
    (r, a, b, c), chain, v = _chain3()
    root, mid, leaf = chain
    try:
        rotate = dc.rotate
    except AttributeError:
        raise _FeatureAbsent("dc.rotate absent")
    succ, succession = rotate(
        _seed("b"), mid, leaf,
        {"audience": _pub("c"), "ttl": 3700, **_RWINDOW})
    v.register_succession(leaf, succ, succession)
    return (r, a, b, c), chain, succ, succession, v


def p_rotate_mints_succession():
    (r, a, b, c), chain, v = _chain3()
    root, mid, leaf = chain
    try:
        succ, succession = dc.rotate(
            _seed("b"), mid, leaf, {"audience": _pub("c"), "ttl": 3700, **_RWINDOW})
    except AttributeError as e:
        _record("rotate-mints", "BREAK", "dc.rotate absent: %s" % e)
        return
    sbody = succ["delegation"]
    ok = (sbody["generation"] == 1
          and sbody["parent_digest"] == leaf["delegation"]["parent_digest"]
          and sbody["issuer"] == leaf["delegation"]["issuer"]
          and succession["delegation"]["type"] == "delegation.succession.1"
          and succession["delegation"]["retired_digest"]
          == dc.digest_of(leaf["delegation"])
          and succession["delegation"]["successor_digest"]
          == dc.digest_of(sbody))
    if ok:
        _record("rotate-mints", "HELD",
                "successor + signed succession record minted")
    else:
        _record("rotate-mints", "BREAK", "succession shape wrong")


def p_rotate_wrong_key_refused():
    """Only the delegator (the retired leaf's issuer) can rotate."""
    (r, a, b, c), chain, v = _chain3()
    root, mid, leaf = chain
    code = _code_of(lambda: dc.rotate(
        _seed("a"), mid, leaf, {"audience": _pub("c"), "ttl": 3700, **_RWINDOW}))
    if code == "delegation-malformed":
        _record("rotate-custody", "HELD",
                "non-issuer rotation seed refused")
    elif code is None:
        _record("rotate-custody", "BREAK",
                "rotation by non-issuer succeeded")
    elif code and code.startswith("ATTR:"):
        _record("rotate-custody", "BREAK", "dc.rotate absent")
    else:
        _record("rotate-custody", "BREAK", "unexpected code %r" % code)


def p_rotate_widening_refused():
    """Rotation can only narrow (standing delegation rule)."""
    (r, a, b, c), chain, v = _chain3()
    root, mid, leaf = chain
    code = _code_of(lambda: dc.rotate(
        _seed("b"), mid, leaf,
        {"audience": _pub("c"), "ttl": 3700, **_RWINDOW,
         "capabilities": _caps("fs:/", ["read", "write"])}))
    if code == "delegation-would-widen":
        _record("rotate-narrow", "HELD", "rotation widening refused")
    elif code is None:
        _record("rotate-narrow", "BREAK", "rotation widened scope")
    elif code and code.startswith("ATTR:"):
        _record("rotate-narrow", "BREAK", "dc.rotate absent")
    else:
        _record("rotate-narrow", "BREAK", "unexpected code %r" % code)


def p_retired_reuse_is_revocation_event():
    """Presenting the retired leaf after succession: the FIRST retry
    is the tolerated RECENT_PREV (signed note); the SECOND is the
    revocation event (delegation-retired-reuse) -- never a quiet
    auth failure."""
    try:
        (r, a, b, c), chain, succ, succession, v = _rotated()
    except _FeatureAbsent:
        _record("retired-reuse", "BREAK", "lineage API absent")
        return
    root, mid, leaf = chain
    first = _code_of(lambda: v.verify(chain, ACTION, now=NOW))
    if first is not None:
        if first.startswith("ATTR:"):
            _record("retired-reuse", "BREAK", "lineage API absent")
        else:
            _record("retired-reuse", "BREAK",
                    "first retry refused with %r (expected tolerate)"
                    % first)
        return
    second = _code_of(lambda: v.verify(chain, ACTION, now=NOW))
    if second == "delegation-retired-reuse":
        _record("retired-reuse", "HELD",
                "second presentation is a coded revocation event")
    elif second is None:
        _record("retired-reuse", "BREAK",
                "retired leaf verified twice without event")
    else:
        _record("retired-reuse", "BREAK", "unexpected code %r" % second)


def p_recent_prev_signed_note():
    """The tolerated RECENT_PREV retry carries a signed lineage note
    in the receipt -- the tolerance is declared, not silent."""
    try:
        (r, a, b, c), chain, succ, succession, v = _rotated()
    except _FeatureAbsent:
        _record("recent-prev-note", "BREAK", "lineage API absent")
        return
    try:
        receipt = v.verify(chain, ACTION, now=NOW)
    except AttributeError:
        _record("recent-prev-note", "BREAK", "lineage API absent")
        return
    except dc.DelegationError as e:
        _record("recent-prev-note", "BREAK",
                "first retry refused with %r" % e.code)
        return
    if receipt.get("lineage") == "recent-prev-tolerated" \
            and receipt.get("signature"):
        _record("recent-prev-note", "HELD",
                "tolerance declared in signed receipt")
    else:
        _record("recent-prev-note", "BREAK",
                "no lineage note in receipt: %r"
                % (receipt.get("lineage"),))


def p_orphaned_branch_refused():
    """A NEW child issued under the retired leaf's authority after
    succession is a fork: delegation-orphaned-branch."""
    try:
        (r, a, b, c), chain, succ, succession, v = _rotated()
    except _FeatureAbsent:
        _record("orphaned-branch", "BREAK", "lineage API absent")
        return
    root, mid, leaf = chain
    fork = _delegate(_seed("c"), _caps("fs:/docs", ["read"]), _pub("d"),
                     _caps("fs:/docs", ["read"]), parent=leaf)
    code = _code_of(lambda: v.verify([root, mid, leaf, fork], ACTION,
                                     now=NOW))
    if code == "delegation-orphaned-branch":
        _record("orphaned-branch", "HELD", "fork refused coded")
    elif code is None:
        _record("orphaned-branch", "BREAK", "forked branch verified")
    elif code.startswith("ATTR:"):
        _record("orphaned-branch", "BREAK", "lineage API absent")
    else:
        _record("orphaned-branch", "BREAK", "unexpected code %r" % code)


def p_stale_lineage_refused():
    """Two successions; the oldest generation is stale."""
    try:
        (r, a, b, c), chain, succ, succession, v = _rotated()
    except _FeatureAbsent:
        _record("stale-lineage", "BREAK", "lineage API absent")
        return
    root, mid, leaf = chain
    succ2, succession2 = dc.rotate(
        _seed("b"), mid, succ, {"audience": _pub("c"), "ttl": 3700, **_RWINDOW})
    v.register_succession(succ, succ2, succession2)
    code = _code_of(lambda: v.verify(chain, ACTION, now=NOW))
    if code == "delegation-stale-lineage":
        _record("stale-lineage", "HELD", "superseded generation refused")
    elif code is None:
        _record("stale-lineage", "BREAK", "stale leaf verified")
    elif code.startswith("ATTR:"):
        _record("stale-lineage", "BREAK", "lineage API absent")
    else:
        _record("stale-lineage", "BREAK", "unexpected code %r" % code)


def p_lineage_overflow_failclosed():
    """A full retirement lineage refuses new successions fail-closed;
    it never evicts and accepts."""
    v = dc.DelegationVerifier([_pub("r")])
    try:
        cap = dc._LINEAGE_MAX
    except AttributeError:
        _record("lineage-overflow", "BREAK", "lineage API absent")
        return
    r, a = _seed("r"), _seed("a")
    prev = _delegate(r, None, _pub("a"), _caps("fs:/", ["read"]))
    for i in range(cap):
        succ, succession = dc.rotate(
            r, None, prev,
            {"audience": _pub("a"), "ttl": 3700, **_RWINDOW,
             "nonce": "ovf-%d" % i,
             "succession_nonce": "sovf-%d" % i})
        v.register_succession(prev, succ, succession)
        prev = succ
    extra_succ, extra_succession = dc.rotate(
        r, None, prev,
        {"audience": _pub("a"), "ttl": 3700, **_RWINDOW, "nonce": "ovf-extra",
         "succession_nonce": "sovf-extra"})
    code = _code_of(lambda: v.register_succession(
        prev, extra_succ, extra_succession))
    if code == "delegation-lineage-overflow":
        _record("lineage-overflow", "HELD",
                "full lineage refuses fail-closed")
    elif code is None:
        _record("lineage-overflow", "BREAK",
                "succession registered past the bound (eviction?)")
    else:
        _record("lineage-overflow", "BREAK", "unexpected code %r" % code)


def p_successor_chain_verifies():
    """The live successor chain verifies normally after succession."""
    try:
        (r, a, b, c), chain, succ, succession, v = _rotated()
    except _FeatureAbsent:
        _record("successor-verifies", "BREAK", "lineage API absent")
        return
    root, mid, leaf = chain
    code = _code_of(lambda: v.verify([root, mid, succ], ACTION, now=NOW))
    if code is None:
        _record("successor-verifies", "HELD",
                "successor chain verifies clean")
    elif code.startswith("ATTR:"):
        _record("successor-verifies", "BREAK", "lineage API absent")
    else:
        _record("successor-verifies", "BREAK",
                "successor chain refused: %r" % code)


def p_succession_forgery_refused():
    """A succession record signed by the wrong key is refused."""
    (r, a, b, c), chain, v = _chain3()
    root, mid, leaf = chain
    try:
        succ, succession = dc.rotate(
            _seed("b"), mid, leaf, {"audience": _pub("c"), "ttl": 3700, **_RWINDOW})
        domain = dc.SUCCESSION_DOMAIN
    except AttributeError:
        _record("succession-forgery", "BREAK", "lineage API absent")
        return
    forged = copy.deepcopy(succession)
    evil_sig = ed25519.sign(
        _seed("evil"),
        domain + dc._canonical(forged["delegation"])).hex()
    forged["signature"] = evil_sig
    code = _code_of(lambda: v.register_succession(leaf, succ, forged))
    if code == "delegation-signature-invalid":
        _record("succession-forgery", "HELD", "forged succession refused")
    elif code is None:
        _record("succession-forgery", "BREAK", "forged succession kept")
    elif code.startswith("ATTR:"):
        _record("succession-forgery", "BREAK", "lineage API absent")
    else:
        _record("succession-forgery", "BREAK", "unexpected code %r" % code)


# ---------------------------------------------------------------------------
# Regression probes (must HELD on base and fixed tree).
# ---------------------------------------------------------------------------

def p_valid_chain_regression():
    (r, a, b, c), chain, v = _chain3()
    try:
        receipt = v.verify(chain, ACTION, now=NOW)
    except dc.DelegationError as e:
        _record("regression-valid", "BREAK", "valid chain refused: %r"
                % e.code)
        return
    if receipt.get("decision") == "ok":
        _record("regression-valid", "HELD", "3-hop chain verifies")
    else:
        _record("regression-valid", "BREAK", "bad receipt")


def p_narrowing_regression():
    (r, a, b, c), chain, v = _chain3()
    root, mid, leaf = chain
    # held=None skips the issue-time widening check so the widening is
    # exercised at verification (attenuation-inverted), not at issue.
    # "delete" is not in the parent's {read, write}: not covered.
    wide = _delegate(_seed("b"), None, _pub("x"),
                     _caps("fs:/", ["delete"]), parent=mid)
    code = _code_of(lambda: v.verify([root, mid, wide], ACTION, now=NOW))
    if code == "delegation-attenuation-inverted":
        _record("regression-narrow", "HELD", "narrowing still enforced")
    else:
        _record("regression-narrow", "BREAK", "code was %r" % code)


def p_pop_regression():
    (r, a, b, c), chain, v = _chain3()
    challenge = b"pop-challenge-0001"
    leaf_digest = dc.digest_of(chain[-1]["delegation"])
    pop_bytes = (dc.POP_DOMAIN + dc._canonical(
        {"invoker": _pub("c"), "challenge": challenge.hex(),
         "chain_digest": leaf_digest}))
    pop_sig = ed25519.sign(_seed("c"), pop_bytes).hex()
    try:
        receipt = v.verify_invocation(
            chain, ACTION, invoker_pubkey_hex=_pub("c"),
            pop_challenge=challenge, pop_signature_hex=pop_sig, now=NOW)
    except dc.DelegationError as e:
        _record("regression-pop", "BREAK", "PoP refused: %r" % e.code)
        return
    if receipt.get("type") == "delegation.invocation-receipt.1":
        _record("regression-pop", "HELD", "proof-of-possession works")
    else:
        _record("regression-pop", "BREAK", "bad receipt type")


_PROBES = [
    p_taxonomy_pin,
    p_ttl_required_at_issue,
    p_ttl_zero_negative_refused,
    p_ttl_excessive_refused,
    p_body_carries_decay_fields,
    p_ttl_window_consistency,
    p_decay_expiry_refused,
    p_decay_midchain_expiry,
    p_legacy_record_refused,
    p_rotate_mints_succession,
    p_rotate_wrong_key_refused,
    p_rotate_widening_refused,
    p_retired_reuse_is_revocation_event,
    p_recent_prev_signed_note,
    p_orphaned_branch_refused,
    p_stale_lineage_refused,
    p_lineage_overflow_failclosed,
    p_successor_chain_verifies,
    p_succession_forgery_refused,
    p_valid_chain_regression,
    p_narrowing_regression,
    p_pop_regression,
]


def main():
    for probe in _PROBES:
        _safe(probe.__name__, probe)
    if not SKIP_GREEN:
        _run_repins()
    nb = sum(1 for _, v, _ in _results if v == "BREAK")
    nh = sum(1 for _, v, _ in _results if v == "HELD")
    ne = sum(1 for _, v, _ in _results if v == "ERROR")
    print("=" * 72)
    print("w292_delegation_decay_probes: %d BREAK / %d HELD / %d ERROR"
          % (nb, nh, ne))
    for pid, verdict, note in _results:
        print("  %-36s %-5s %s" % (pid, verdict, note.split("\n")[0]))


if __name__ == "__main__":
    main()
