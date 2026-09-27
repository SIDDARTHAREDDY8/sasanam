#!/usr/bin/env python3
"""Break round v2: ceremony discriminator + delegation receipt evasion.

Adversarial battery against the two seams this team shipped:

TARGET 1 -- the scope-discriminator veto (gov/target_match.py,
row-11 follow-up leg). The shipped closed lists (_QUANT_CANON,
_QUARTER_RE, _YEAR_RE) are calibration lists, and calibration lists
get dodged. This battery attacks them:

  e1  unlisted quantifier synonym: "the whole" (widening, unmapped)
  e2  ordinal quarter: "3rd quarter" vs a Q4 reference
  e3  word ordinal: "third-quarter" vs a Q4 reference
  e4  fiscal shorthand: "FY26Q3" vs a Q4 reference
  e5  month name: "Sept quarter" vs a Q4 reference
  e6  month phrase: "the quarter ending September" vs a Q4 reference
  e7  roman numeral: "QIII" vs a Q4 reference
  e8  fullwidth: "Q4" (U+FF31 U+FF14) vs a Q3 reference
  e9  zero-width: "Q<ZWSP>4" vs a Q3 reference (F183's class, new seam)
  e10-e13 omission weaponization: "delete the thing" / "remove it" /
      "erase stuff" / "delete everything" vs "delete the Q3 report"
      (the pinned contradiction-only narrowing leaves the
      nounless-typed direction open)
  e14 same-quarter variants must STAY accepted (no false refusals)
  e15 same-size contradiction (attack-5 shape) must stay refused
  e16-e18 pinned residuals (H2, "full", "complete set of"): EXPECTED
      while accepted, HELD if a close catches them as a side effect

TARGET 2 -- delegation receipts (gov/delegation_tokens.py):

  r1  near-miss session: trailing space ("sess-1" vs "sess-1 ")
  r2  near-miss session: case variant ("sess-1" vs "SESS-1")
  r3  chain confusion: receipt-A presented with chain-B's tokens
  r4  swapped parent chain: child receipt verified against a foreign
      parent hop
  r5  int user_id at issuance (123, not "123")
  r6  empty user_id at issuance ("")
  r7  int sub in the presented receipt (123 vs "123")
  r8  null act in the presented receipt

Plus e19 (existing ceremony/receipt batteries reproduce their
recorded numbers EXACTLY) and e20 (determinism x2).

RED-FIRST: run against the tree before the break-round closes land.
Expect: e1-e13 BREAK, e14-e15 HELD, e16-e18 EXPECTED, r1-r8 HELD
(the receipt seam was built fail-closed; the probes confirm it),
e19-e20 HELD. Post-close: e1-e13 HELD, e16-e18 EXPECTED-or-HELD.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only.

Run:
  mkdir -p /tmp/gov-evas
  TMPDIR=/tmp/gov-evas ~/workspace/.gov-venv/bin/python \\
      evals/ceremony_receipt_evasion_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-evas-u \\
      ~/workspace/.gov-venv/bin/python evals/ceremony_receipt_evasion_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-evas-%d" % os.getpid())

import sys
import subprocess
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

from gov.approvals import _type_to_confirm_ok  # noqa: E402
from gov import delegation_tokens as _dt  # noqa: E402

REF = "delete the Q3 report"
Q4REF = "delete the Q4 report"

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-40s %-10s %s" % (name, verdict, detail))


def _ceremony(typed, ref):
    ok, score, _d, _m = _type_to_confirm_ok([ref], typed)
    return ok, score


# ---------------------------------------------------------------------------
# Target 1: ceremony discriminator evasion
# ---------------------------------------------------------------------------

def _want_refuse(name, typed, ref):
    ok, score = _ceremony(typed, ref)
    if not ok:
        _record(name, "HELD", "refused (score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "ceremony ACCEPTED %r vs %r (score %.3f)"
                % (typed, ref, score))


def _want_accept(name, typed, ref):
    ok, score = _ceremony(typed, ref)
    if ok:
        _record(name, "HELD", "accepted (score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "FALSE REFUSAL: %r vs %r refused (score %.3f)"
                % (typed, ref, score))


def _pinned_residual(name, typed, ref, reason):
    ok, score = _ceremony(typed, ref)
    if not ok:
        _record(name, "HELD",
                "closed as a side effect (score %.3f)" % score)
    else:
        _record(name, "EXPECTED",
                "pinned residual (%s): accepted at %.3f"
                % (reason, score))


def e1_whole_widening():
    _want_refuse("e1_whole_widening",
                 "remove the whole archive", REF)


def e2_ordinal_quarter():
    _want_refuse("e2_ordinal_quarter",
                 "delete the 3rd quarter report", Q4REF)


def e3_word_ordinal_quarter():
    _want_refuse("e3_word_ordinal_quarter",
                 "delete the third-quarter filing", Q4REF)


def e4_fy_quarter():
    _want_refuse("e4_fy_quarter",
                 "erase the FY26Q3 document", Q4REF)


def e5_month_quarter():
    _want_refuse("e5_month_quarter",
                 "obliterate the Sept quarter filing", Q4REF)


def e6_month_phrase_quarter():
    _want_refuse("e6_month_phrase_quarter",
                 "delete the quarter ending September report", Q4REF)


def e7_roman_quarter():
    _want_refuse("e7_roman_quarter",
                 "delete the QIII report", Q4REF)


def e8_fullwidth_quarter():
    _want_refuse("e8_fullwidth_quarter",
                 "delete the \uff31\uff14 report", REF)


def e9_zero_width_quarter():
    _want_refuse("e9_zero_width_quarter",
                 "delete the Q\u200b4 report", REF)


def e10_thing_omission():
    _want_refuse("e10_thing_omission", "delete the thing", REF)


def e11_it_omission():
    _want_refuse("e11_it_omission", "remove it", REF)


def e12_stuff_omission():
    _want_refuse("e12_stuff_omission", "erase stuff", REF)


def e13_everything_omission():
    _want_refuse("e13_everything_omission", "delete everything", REF)


def e14_same_quarter_variants_accepted():
    name = "e14_same_quarter_variants_accepted"
    pairs = [
        ("delete the 3rd quarter report", "delete the Q3 report"),
        ("erase the FY26Q3 document", "delete the Q3 report"),
        ("delete the September report", "delete the Q3 report"),
        ("delete the QIII filing", "delete the Q3 report"),
    ]
    bad = []
    for typed, ref in pairs:
        ok, score = _ceremony(typed, ref)
        if not ok:
            bad.append("%r vs %r (%.3f)" % (typed, ref, score))
    if bad:
        _record(name, "BREAK",
                "FALSE REFUSAL on same-quarter variants: "
                + "; ".join(bad))
    else:
        _record(name, "HELD",
                "%d/%d same-quarter variants accepted" % (len(pairs),
                                                          len(pairs)))


def e15_same_size_contradiction():
    name = "e15_same_size_contradiction"
    pairs = [
        ("delete the Q3 report", "delete the Q4 report"),
        ("delete all reports", "delete the entire report"),
    ]
    bad = []
    for typed, ref in pairs:
        ok, score = _ceremony(typed, ref)
        if ok:
            bad.append("%r vs %r (%.3f)" % (typed, ref, score))
    if bad:
        _record(name, "BREAK",
                "same-size contradiction accepted: " + "; ".join(bad))
    else:
        _record(name, "HELD",
                "same-size contradictions refused (symmetric veto)")


def e16_h2_residual():
    _pinned_residual("e16_h2_residual", "delete the H2 report", Q4REF,
                     "half-year is not a quarter: interval semantics "
                     "outside the quarter discriminator")


def e17_full_residual():
    _pinned_residual("e17_full_residual", "delete the full report", REF,
                     "'full' is an ambiguous adjective (comprehensive "
                     "vs entire); not pinned as widening")


def e18_complete_set_residual():
    _pinned_residual("e18_complete_set_residual",
                     "erase the complete set of filings", REF,
                     "multiword quantifier phrase needs phrase-level "
                     "parsing, outside the token tier")


# ---------------------------------------------------------------------------
# Target 2: delegation receipt evasion
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)
_SID = "sess-evas"
_REVOKE_URI = "https://revoke.example.invalid/deleg"


class _K(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, agents):
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={a: self.parent[1] for a in agents})


def _trio(keys, user_id, agent_id, session, scope=("tool:read_file",)):
    user_tok = _dt.issue_user_token(keys.idp[0], user_id, scope,
                                    session, now=_NOW)
    agent_tok = _dt.issue_agent_token(keys.authority[0], agent_id,
                                      "scout", user_id, scope,
                                      session, now=_NOW)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], user_id, user_tok, agent_tok, scope,
        session, _REVOKE_URI, now=_NOW)
    return user_tok, agent_tok, deleg_tok


def _bound(keys, trust, user_id, agent_id, session):
    toks = _trio(keys, user_id, agent_id, session)
    ctx = _dt.DelegationContext(
        user_token=toks[0], agent_token=toks[1],
        delegation_token=toks[2], parent_chain=[],
        trust=trust, session_id=session).bind(now=_NOW)
    return ctx, toks


def _rprobe(name, fn):
    r1 = fn()
    r2 = fn()
    if r1[0] != r2[0]:
        _record(name, "ERROR",
                "NONDETERMINISTIC: %r vs %r" % (r1, r2))
        return
    _record(name, "HELD" if r1[0] else "BREAK", r1[1])


def _r1_fn():
    keys = _K()
    trust = keys.trust(["agent-1"])
    ctx, toks = _bound(keys, trust, "user-7", "agent-1", _SID)
    receipt = _dt.delegation_receipt(ctx)
    try:
        _dt.verify_delegation_receipt(
            receipt, user_token=toks[0], agent_token=toks[1],
            delegation_token=toks[2], parent_chain=[], trust=trust,
            session_id=_SID + " ", now=_NOW)  # trailing space
    except _dt.DelegationError:
        return True, "trailing-space session refused"
    return False, "receipt verified in 'sess-1 ' (near-miss session)"


def _r2_fn():
    keys = _K()
    trust = keys.trust(["agent-1"])
    ctx, toks = _bound(keys, trust, "user-7", "agent-1", _SID)
    receipt = _dt.delegation_receipt(ctx)
    try:
        _dt.verify_delegation_receipt(
            receipt, user_token=toks[0], agent_token=toks[1],
            delegation_token=toks[2], parent_chain=[], trust=trust,
            session_id=_SID.upper(), now=_NOW)  # case variant
    except _dt.DelegationError:
        return True, "case-variant session refused"
    return False, "receipt verified in 'SESS-EVAS' (near-miss session)"


def _r3_fn():
    ka, kb = _K(), _K()
    trust_a, trust_b = ka.trust(["agent-1"]), kb.trust(["agent-2"])
    _ctx_a, _ = _bound(ka, trust_a, "user-7", "agent-1", _SID)
    _ctx_b, toks_b = _bound(kb, trust_b, "user-9", "agent-2", _SID)
    receipt_a = _dt.delegation_receipt(_ctx_a)
    try:
        # Attacker presents chain-A's receipt with chain-B's tokens.
        _dt.verify_delegation_receipt(
            receipt_a, user_token=toks_b[0], agent_token=toks_b[1],
            delegation_token=toks_b[2], parent_chain=[],
            trust=trust_b, session_id=_SID, now=_NOW)
    except _dt.DelegationError:
        return True, "chain-A receipt refused against chain-B tokens"
    return False, "chain-A receipt VERIFIED against chain-B tokens"


def _r4_fn():
    ka, kb = _K(), _K()
    trust_a, trust_b = ka.trust(["agent-1"]), kb.trust(["agent-2"])
    ctx_a, toks_a = _bound(ka, trust_a, "user-7", "agent-1", _SID)
    child = ctx_a.spawn("agent-2", ["tool:read_file"], ka.parent[0],
                        now=_NOW)
    trust_a2 = ka.trust(["agent-1", "agent-2"])
    receipt = _dt.delegation_receipt(child)
    _, toks_b = _bound(kb, trust_b, "user-9", "agent-2", _SID)
    try:
        # Attacker swaps the parent hop for a foreign chain's token.
        _dt.verify_delegation_receipt(
            receipt, user_token=toks_a[0], agent_token=toks_a[1],
            delegation_token=child.delegation_token,
            parent_chain=[toks_b[2]], trust=trust_a2,
            session_id=_SID, now=_NOW)
    except _dt.DelegationError:
        return True, "foreign parent hop refused"
    return False, "child receipt VERIFIED with a foreign parent hop"


def _r5_fn():
    keys = _K()
    try:
        _dt.issue_user_token(keys.idp[0], 123, ("tool:read_file",),
                             _SID, now=_NOW)
    except (ValueError, TypeError):
        return True, "int user_id refused at issuance"
    return False, "user token minted with int user_id=123"


def _r6_fn():
    keys = _K()
    try:
        _dt.issue_user_token(keys.idp[0], "", ("tool:read_file",),
                             _SID, now=_NOW)
    except (ValueError, TypeError):
        return True, "empty user_id refused at issuance"
    return False, "user token minted with empty user_id"


def _r7_fn():
    keys = _K()
    trust = keys.trust(["agent-1"])
    ctx, toks = _bound(keys, trust, "user-7", "agent-1", _SID)
    forged = deepcopy(_dt.delegation_receipt(ctx))
    forged["sub"] = 123  # int, not "123"
    try:
        _dt.verify_delegation_receipt(
            forged, user_token=toks[0], agent_token=toks[1],
            delegation_token=toks[2], parent_chain=[], trust=trust,
            session_id=_SID, now=_NOW)
    except _dt.DelegationError:
        return True, "int sub refused (canonical type mismatch)"
    return False, "receipt with int sub=123 VERIFIED"


def _r8_fn():
    keys = _K()
    trust = keys.trust(["agent-1"])
    ctx, toks = _bound(keys, trust, "user-7", "agent-1", _SID)
    forged = deepcopy(_dt.delegation_receipt(ctx))
    forged["act"] = None
    try:
        _dt.verify_delegation_receipt(
            forged, user_token=toks[0], agent_token=toks[1],
            delegation_token=toks[2], parent_chain=[], trust=trust,
            session_id=_SID, now=_NOW)
    except _dt.DelegationError:
        return True, "null act refused"
    return False, "receipt with null act VERIFIED"


def r1_near_miss_session_space():
    _rprobe("r1_near_miss_session_space", _r1_fn)


def r2_near_miss_session_case():
    _rprobe("r2_near_miss_session_case", _r2_fn)


def r3_chain_confusion():
    _rprobe("r3_chain_confusion", _r3_fn)


def r4_swapped_parent_chain():
    _rprobe("r4_swapped_parent_chain", _r4_fn)


def r5_int_user_id_issuance():
    _rprobe("r5_int_user_id_issuance", _r5_fn)


def r6_empty_user_id_issuance():
    _rprobe("r6_empty_user_id_issuance", _r6_fn)


def r7_int_sub_receipt():
    _rprobe("r7_int_sub_receipt", _r7_fn)


def r8_null_act_receipt():
    _rprobe("r8_null_act_receipt", _r8_fn)


# ---------------------------------------------------------------------------
# Regression pins + determinism
# ---------------------------------------------------------------------------

def _run_adjacent(path, want_summary):
    tmp = tempfile.mkdtemp(prefix="evas-adj-", dir=os.environ["TMPDIR"])
    env = dict(os.environ, TMPDIR=tmp)
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, path)],
        env=env, capture_output=True, text=True, timeout=600)
    out = (proc.stdout or "").strip().splitlines()
    tail = out[-1] if out else ""
    if proc.returncode != 0:
        return "exit=%d (%s)" % (proc.returncode, tail)
    if want_summary not in (proc.stdout or ""):
        return "summary mismatch: want %r, tail %r" % (want_summary, tail)
    return None


def e19_existing_batteries_exact():
    name = "e19_existing_batteries_exact"
    pins = [
        ("evals/type_discriminator_probes.py",
         "type_discriminator_probes: 10 HELD / 0 BREAK / 0 EXPECTED / 0 ERROR"),
        ("evals/delegation_receipt_probes.py",
         "12 HELD / 0 BREAK / 0 ERROR"),
        ("evals/type_to_confirm_probes.py",
         "6/6 HELD, 0 BREAK, 0 ERROR"),
        ("evals/type_synonym_probes.py",
         "== 7 HELD / 0 BREAK / 0 ERROR =="),
        ("evals/type_structure_probes.py",
         "type_structure_probes: 7 HELD / 0 BREAK / 0 EXPECTED / 0 ERROR"),
    ]
    bad = []
    for path, want in pins:
        err = _run_adjacent(path, want)
        if err:
            bad.append("%s: %s" % (path, err))
    if bad:
        _record(name, "BREAK", "; ".join(bad))
        return
    _record(name, "HELD",
            "all five ceremony/receipt batteries reproduce recorded "
            "numbers exactly")


CEREMONY_PROBES = [
    e1_whole_widening, e2_ordinal_quarter, e3_word_ordinal_quarter,
    e4_fy_quarter, e5_month_quarter, e6_month_phrase_quarter,
    e7_roman_quarter, e8_fullwidth_quarter, e9_zero_width_quarter,
    e10_thing_omission, e11_it_omission, e12_stuff_omission,
    e13_everything_omission, e14_same_quarter_variants_accepted,
    e15_same_size_contradiction, e16_h2_residual, e17_full_residual,
    e18_complete_set_residual,
]

RECEIPT_PROBES = [
    r1_near_miss_session_space, r2_near_miss_session_case,
    r3_chain_confusion, r4_swapped_parent_chain,
    r5_int_user_id_issuance, r6_empty_user_id_issuance,
    r7_int_sub_receipt, r8_null_act_receipt,
]


def _run_all():
    global _RESULTS
    _RESULTS = []
    for probe in CEREMONY_PROBES:
        probe()
    for probe in RECEIPT_PROBES:
        probe()
    e19_existing_batteries_exact()
    return list(_RESULTS)


def e20_deterministic_x2():
    name = "e20_deterministic_x2"
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
    e20_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("ceremony_receipt_evasion_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
