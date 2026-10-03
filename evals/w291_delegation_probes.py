"""Wave-291 lane 6 battery: delegation narrowing (zcap pattern) probes.

Base: wave-290 push 9c12f9b4 (verified via git rev-parse HEAD before work).

New product surface (gov/delegation_chain.py):
  (a) verify_invocation -- proof of possession of the leaf audience
      key (POP_DOMAIN-signed challenge bound to the exact chain);
  (b) ceremony binding -- optional ceremony_nonce on delegations,
      cross-ceremony replay refuses coded;
  (c) bounded root policy -- root grants covered by the anchor's
      pinned capability bound;
  (d) narrowing cryptographically enforced at each verify hop.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: AttributeError/TypeError on the new kwargs/methods); on the
fixed tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g291-delegation && TMPDIR=/var/tmp/g291-delegation \
    ~/workspace/.gov-venv/bin/python evals/w291_delegation_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g291-delegation2 \
    ~/workspace/.gov-venv/bin/python evals/w291_delegation_probes.py
"""

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

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1827  # Wave-292 lane 3: pin 1715 -> 1719 (+4 delegation-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

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
    _record("pin-taxonomy", "HELD", "1827/1827/0 sorted")


# ---------------------------------------------------------------------------
# Repins (subprocess, depth-1, GOV_SKIP_GREEN=1, fresh TMPDIRs).
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # Wave-290 merge: F311-F351 ALL CLOSED; the w290 red team carries
    # F352-F355 (6 BREAK) on the wave-290 tree.
    # Wave-291 merge re-pin: F352-F355 ALL closed -> 0 BREAK.
    ("evals/w290_redteam_probes.py", 0, "w290-redteam"),
    # Wave-289 closure lanes stay green: ceremony + admission + eat.
    ("evals/w289_ceremony_probes.py", 0, "w289-ceremony"),
    ("evals/w288_admission_probes.py", 0, "w288-admission"),
    ("evals/w288_eat_probes.py", 0, "w288-eat"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w291-repin-")
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
# Fixtures.
# ---------------------------------------------------------------------------

from gov import delegation_chain as dc  # noqa: E402
from gov import ed25519  # noqa: E402

NOW = 4000000000.0
NONCE_A = "aa" * 16   # 64-bit verifier challenge, ceremony A
NONCE_B = "bb" * 16   # 64-bit verifier challenge, ceremony B


def _seed():
    return ed25519.generate_seed()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _caps(with_, cans):
    return [{"with": with_, "can": list(cans)}]


def _delegate(seed, held, audience, caps, parent=None, **kw):
    req = {"audience": _pub(audience),
           "capabilities": caps,
           "not_before": NOW - 100.0,
           "not_after": NOW + 3600.0,
           "ttl": 3700,
           "parent": parent}
    req.update(kw)
    return dc.delegate(seed, held, req)


def _chain(ceremony_nonce=None):
    """root -> alice -> bob -> mallory, narrowing at every hop."""
    r, a, b, x = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]),
                     ceremony_nonce=ceremony_nonce)
    hop2 = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                     _caps("fs:/docs", ["read"]), parent=root,
                     ceremony_nonce=ceremony_nonce)
    hop3 = _delegate(b, _caps("fs:/docs", ["read"]), x,
                     _caps("fs:/docs/report", ["read"]), parent=hop2,
                     ceremony_nonce=ceremony_nonce)
    return (r, a, b, x), [root, hop2, hop3]


_POP_DOMAIN = getattr(dc, "POP_DOMAIN",
                      b"gov-delegation-pop/v1\x00")


def _pop_sign(seed, invoker_pub_hex, challenge, leaf_digest):
    msg = _POP_DOMAIN + dc._canonical({
        "invoker": invoker_pub_hex,
        "challenge": bytes(challenge).hex(),
        "chain_digest": leaf_digest,
    })
    return ed25519.sign(bytes(seed), msg).hex()


def _leaf_digest(chain):
    body, _ = dc._check_sealed(chain[-1])
    return dc.digest_of(body)


def _expect_coded(pid, fn, code):
    try:
        fn()
    except dc.DelegationError as e:
        if e.code == code:
            return _record(pid, "HELD", "coded %s" % code)
        return _record(pid, "BREAK",
                       "wrong code: %r, want %r" % (e.code, code))
    except (AttributeError, TypeError) as e:
        # Feature absent on the pristine base: the new kwarg/method
        # does not exist.
        return _record(pid, "BREAK", "feature absent on base: %r" % (e,))
    return _record(pid, "BREAK", "no refusal")


def _expect_ok(pid, fn, note=""):
    try:
        fn()
    except (AttributeError, TypeError) as e:
        return _record(pid, "BREAK", "feature absent on base: %r" % (e,))
    return _record(pid, "HELD", note or "ok")


# ---------------------------------------------------------------------------
# Probes.
# ---------------------------------------------------------------------------

def p_pop_happy():
    keys, chain = _chain()
    r, a, b, x = keys
    chal = os.urandom(32)
    leaf_digest = _leaf_digest(chain)
    sig = _pop_sign(x, _pub(x), chal, leaf_digest)
    def run():
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        rcpt = v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex=sig, now=NOW)
        assert rcpt["type"] == "delegation.invocation-receipt.1", \
            rcpt["type"]
        assert rcpt["invoker"] == _pub(x)
    _expect_ok("pop-happy", run, "PoP verified, receipt minted")


def p_pop_no_proof():
    keys, chain = _chain()
    r, a, b, x = keys
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    _expect_coded(
        "pop-no-proof",
        lambda: v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=None,
            pop_signature_hex=None, now=NOW),
        "delegation-invocation-not-proven")


def p_pop_wrong_key():
    keys, chain = _chain()
    r, a, b, x = keys
    mallory = _seed()
    chal = os.urandom(32)
    leaf_digest = _leaf_digest(chain)
    sig = _pop_sign(mallory, _pub(mallory), chal, leaf_digest)
    def run():
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(mallory), pop_challenge=chal,
            pop_signature_hex=sig, now=NOW)
    _expect_coded("pop-wrong-key", run,
                  "delegation-invocation-audience-mismatch")


def p_pop_forged_signature():
    keys, chain = _chain()
    r, a, b, x = keys
    chal = os.urandom(32)
    leaf_digest = _leaf_digest(chain)
    forged = _pop_sign(_seed(), _pub(x), chal, leaf_digest)
    def run():
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex=forged, now=NOW)
    _expect_coded("pop-forged-signature", run,
                  "delegation-pop-signature-invalid")


def p_pop_cross_chain_replay():
    (r, a, b, x), chain = _chain()
    # A second chain with the SAME leaf audience key x but different
    # capabilities (hence a different leaf digest).
    root2 = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
    hop2 = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                     _caps("fs:/docs", ["read"]), parent=root2)
    hop3 = _delegate(b, _caps("fs:/docs", ["read"]), x,
                     _caps("fs:/docs/archive", ["read"]), parent=hop2)
    chain2 = [root2, hop2, hop3]
    chal = os.urandom(32)
    # PoP minted over chain's leaf digest, replayed against chain2.
    sig = _pop_sign(x, _pub(x), chal, _leaf_digest(chain))
    def run():
        v = dc.DelegationVerifier([_pub(r)], seed=_seed())
        v.verify_invocation(
            chain2, {"with": "fs:/docs/archive", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex=sig, now=NOW)
    _expect_coded("pop-cross-chain-replay", run,
                  "delegation-pop-signature-invalid")


def p_pop_nonhex_signature():
    keys, chain = _chain()
    r, a, b, x = keys
    chal = os.urandom(32)
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    def run():
        v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex="zz" * 64, now=NOW)
    _expect_coded("pop-nonhex-signature", run,
                  "delegation-pop-signature-invalid")


def p_pop_bad_challenge_shape():
    keys, chain = _chain()
    r, a, b, x = keys
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    _expect_coded(
        "pop-bad-challenge-shape",
        lambda: v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge="not-bytes",
            pop_signature_hex="ff" * 64, now=NOW),
        "delegation-malformed")


def p_ceremony_cross_replay():
    keys, chain = _chain(ceremony_nonce=NONCE_A)
    r = keys[0]
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    _expect_coded(
        "ceremony-cross-replay",
        lambda: v.verify(chain, {"with": "fs:/docs/report",
                                 "can": "read"},
                        now=NOW, expected_ceremony_nonce=NONCE_B),
        "delegation-ceremony-mismatch")


def p_ceremony_missing_when_expected():
    keys, chain = _chain()
    r = keys[0]
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    _expect_coded(
        "ceremony-missing-when-expected",
        lambda: v.verify(chain, {"with": "fs:/docs/report",
                                 "can": "read"},
                        now=NOW, expected_ceremony_nonce=NONCE_A),
        "delegation-ceremony-mismatch")


def p_ceremony_happy():
    keys, chain = _chain(ceremony_nonce=NONCE_A)
    r = keys[0]
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    def run():
        v.verify(chain, {"with": "fs:/docs/report", "can": "read"},
                 now=NOW, expected_ceremony_nonce=NONCE_A)
    _expect_ok("ceremony-happy", run, "bound chain verifies in-ceremony")


def p_ceremony_tampered_nonce():
    keys, chain = _chain(ceremony_nonce=NONCE_A)
    r = keys[0]
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    chain[2]["delegation"]["ceremony_nonce"] = NONCE_B
    _expect_coded(
        "ceremony-tampered-nonce",
        lambda: v.verify(chain, {"with": "fs:/docs/report",
                                 "can": "read"},
                        now=NOW, expected_ceremony_nonce=NONCE_A),
        "delegation-signature-invalid")


def p_ceremony_none_expected():
    keys, chain = _chain(ceremony_nonce=NONCE_A)
    r = keys[0]
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    def run():
        v.verify(chain, {"with": "fs:/docs/report", "can": "read"},
                 now=NOW)
    _expect_ok("ceremony-none-expected", run,
               "no ceremony discipline without expected nonce")


def p_ceremony_malformed_at_issue():
    r, a = _seed(), _seed()
    def run():
        _delegate(r, None, a, _caps("fs:/", ["read"]),
                  ceremony_nonce="short")
    _expect_coded("ceremony-malformed-at-issue", run,
                  "delegation-malformed")


def p_root_policy_violation():
    r, a, b, x = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
    hop2 = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                     _caps("fs:/docs", ["read"]), parent=root)
    hop3 = _delegate(b, _caps("fs:/docs", ["read"]), x,
                     _caps("fs:/docs/report", ["read"]), parent=hop2)
    policy = {_pub(r): _caps("fs:/docs", ["read", "write"])}
    def run():
        v = dc.DelegationVerifier([_pub(r)], seed=_seed(),
                                  root_policy=policy)
        v.verify([root, hop2, hop3],
                 {"with": "fs:/docs/report", "can": "read"},
                 now=NOW)
    _expect_coded("root-policy-violation", run,
                  "delegation-root-exceeds-policy")


def p_root_policy_happy():
    r, a, b, x = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/docs", ["read", "write"]))
    hop2 = _delegate(a, _caps("fs:/docs", ["read", "write"]), b,
                     _caps("fs:/docs", ["read"]), parent=root)
    policy = {_pub(r): _caps("fs:/docs", ["read", "write"])}
    def run():
        v = dc.DelegationVerifier([_pub(r)], seed=_seed(),
                                  root_policy=policy)
        v.verify([root, hop2], {"with": "fs:/docs", "can": "read"},
                 now=NOW)
    _expect_ok("root-policy-happy", run, "in-policy root verifies")


def p_root_unbounded_anchor():
    keys, chain = _chain()
    r = keys[0]
    # Policy covers a DIFFERENT anchor; the root anchor stays
    # unbounded-but-trusted (documented CA-like assumption).
    policy = {_pub(_seed()): _caps("fs:/", ["read"])}
    def run():
        v = dc.DelegationVerifier([_pub(r)], seed=_seed(),
                                  root_policy=policy)
        v.verify(chain, {"with": "fs:/docs/report", "can": "read"},
                 now=NOW)
    _expect_ok("root-unbounded-anchor", run,
               "anchor without policy entry stays trusted")


def p_narrowing_hop3_expansion():
    keys, chain = _chain()
    r, a, b, x = keys
    # Bypass the issue-time widening refusal (held=None) to present a
    # widening hop at verification time.
    wide = _delegate(b, None, x, _caps("fs:/", ["read", "write"]),
                     parent=chain[1])
    chain[2] = wide
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    _expect_coded(
        "narrowing-hop3-expansion",
        lambda: v.verify(chain, {"with": "fs:/", "can": "write"},
                        now=NOW),
        "delegation-attenuation-inverted")


def p_narrowing_happy_3hop():
    keys, chain = _chain()
    r = keys[0]
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    def run():
        v.verify(chain, {"with": "fs:/docs/report", "can": "read"},
                 now=NOW)
    _expect_ok("narrowing-happy-3hop", run,
               "narrowing 3-hop chain verifies")


def p_with_widening_refused():
    r, a, b = _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/docs", ["read"]))
    hop2 = _delegate(a, _caps("fs:/docs", ["read"]), b,
                     _caps("fs:/docs/report", ["read"]), parent=root)
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    _expect_coded(
        "with-widening-refused",
        lambda: v.verify([root, hop2],
                         {"with": "fs:/other", "can": "read"},
                         now=NOW),
        "delegation-action-refused")


def p_old_style_chain_verifies():
    keys, chain = _chain()
    r = keys[0]
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    def run():
        v.verify(chain, {"with": "fs:/docs/report", "can": "read"},
                 now=NOW)
    _expect_ok("old-style-chain-verifies", run,
               "pre-ceremony chains stay verifiable")


def p_invocation_uncoded_escape_sweep():
    keys, chain = _chain()
    r, a, b, x = keys
    v = dc.DelegationVerifier([_pub(r)], seed=_seed())
    chal = os.urandom(32)
    cases = [
        lambda: v.verify_invocation(
            "not-a-chain", {"with": "fs:/", "can": "read"},
            invoker_pubkey_hex=_pub(x), pop_challenge=chal,
            pop_signature_hex="ff" * 64, now=NOW),
        lambda: v.verify_invocation(
            chain, {"with": "fs:/docs/report", "can": "read"},
            invoker_pubkey_hex="zz" * 32, pop_challenge=chal,
            pop_signature_hex="ff" * 64, now=NOW),
    ]
    for i, fn in enumerate(cases):
        try:
            fn()
        except dc.DelegationError as e:
            _record("escape-%d" % i, "HELD", "coded %s" % e.code)
        except (AttributeError, TypeError):
            _record("escape-%d" % i, "BREAK", "feature absent on base")
        except Exception as e:  # noqa: BLE001
            _record("escape-%d" % i, "BREAK",
                    "uncoded escape: %r" % (e,))


_PROBES = [
    p_pop_happy, p_pop_no_proof, p_pop_wrong_key,
    p_pop_forged_signature, p_pop_cross_chain_replay,
    p_pop_nonhex_signature, p_pop_bad_challenge_shape,
    p_ceremony_cross_replay, p_ceremony_missing_when_expected,
    p_ceremony_happy, p_ceremony_tampered_nonce,
    p_ceremony_none_expected, p_ceremony_malformed_at_issue,
    p_root_policy_violation, p_root_policy_happy,
    p_root_unbounded_anchor, p_narrowing_hop3_expansion,
    p_narrowing_happy_3hop, p_with_widening_refused,
    p_old_style_chain_verifies, p_invocation_uncoded_escape_sweep,
]


def main():
    p_taxonomy_pin()
    for probe in _PROBES:
        _safe(probe.__name__, probe)
    if not SKIP_GREEN:
        _run_repins()
    nb = sum(1 for _, v, _ in _results if v == "BREAK")
    nh = sum(1 for _, v, _ in _results if v == "HELD")
    ne = sum(1 for _, v, _ in _results if v == "ERROR")
    print("=" * 72)
    print("w291_delegation_probes: %d BREAK / %d HELD / %d ERROR"
          % (nb, nh, ne))
    for pid, verdict, note in _results:
        print("  %-36s %-5s %s" % (pid, verdict, note.split("\n")[0]))


if __name__ == "__main__":
    main()
