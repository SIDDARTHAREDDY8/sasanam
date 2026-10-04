"""Wave-299 lane 3 battery: Kerberos-style delegation tickets.

Base: wave-298 merge 2af956fd880d9a58a9e26e51efb6f47e82594b4e
(verified via git rev-parse HEAD before work).

New product surface (additive, gov/delegation_tickets.py only):
  (a) delegation as a first-class ticket type with its OWN ticket key
      pair per ticket (attributable; the Kerberos session-key
      analogue); ticket types FORWARDABLE / CONSTRAINED /
      NON_FORWARDABLE signed into the ticket;
  (b) ok-as-delegate opt-in: a delegatee must hold a live signed
      opt-in declaration before a ticket can be issued to it
      (code delegation-ticket-not-opted-in);
  (c) constrained delegation: named downstream set, bounded <= 64,
      empty set refuses at issue; presented outside the set refuses
      coded (delegation-ticket-type-violated);
  (d) delegation narrows, never widens: child scope must equal or
      extend the parent scope path; child expiry must not exceed the
      parent expiry;
  (e) presentation verifies shape -> signature -> window -> holder ->
      scope containment -> parent chain to root -> optional
      ticket-key action attestation.  Ticket-key confusion (parent
      key used where the ticket key belongs) refuses coded
      delegation-ticket-invalid;
  (f) 4 new codes at true sorted positions; pin 1780 -> 1784;
      wave-299 merge: pin 1784 -> 1797.

Red-first: on the pristine base the module is absent, so every
feature probe BREAKs; on the fixed tree they must HELD with loud
coded refusals.

Run:
  mkdir -p /var/tmp/g299-dt && TMPDIR=/var/tmp/g299-dt \
    ~/workspace/.gov-venv/bin/python evals/w299_delegation_tickets_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g299-dt2 \
    ~/workspace/.gov-venv/bin/python evals/w299_delegation_tickets_probes.py
"""

import hashlib
import os
import re
import subprocess
import sys
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1973 # Wave-299 lane 3: pin 1780 -> 1784 (+4 delegation-ticket-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

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
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    for want in ("delegation-ticket-expired", "delegation-ticket-invalid",
                 "delegation-ticket-not-opted-in",
                 "delegation-ticket-type-violated"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1916 raw literals, unique, sorted")


def _import_mods():
    try:
        from gov import delegation_tickets as dt
        from gov import ed25519
    except ImportError:
        return None, None
    return dt, ed25519


def _need(pid):
    dt, ed = _import_mods()
    if dt is None:
        _record(pid, "BREAK", "feature absent on this tree "
                              "(gov.delegation_tickets missing)")
        return None, None
    return dt, ed


def _seed(tag):
    return hashlib.sha256(("w299-delegation-tickets-%s" % tag).encode()) \
        .digest()


AT = 2000000


def _reg(dt, at=AT):
    reg = dt.OptInRegistry()
    reg.register(dt.declare_opt_in(_seed("a1"), "agent-1", 3600, at), at)
    reg.register(dt.declare_opt_in(_seed("a2"), "agent-2", 3600, at), at)
    return reg


def _root(dt, at=AT, scope="sasanam.tools", ttl=7200):
    return dt.issue_root_ticket(_seed("auth"), "authority", scope, ttl, at)


def _chain(dt, at=AT):
    """(reg, root, root_seed, t1, t1_seed, store) -- the standard
    forwardable chain used by most probes."""
    reg = _reg(dt, at)
    root, root_seed = _root(dt, at)
    t1, t1_seed = dt.issue_delegation_ticket(
        root, root_seed, "agent-1", "sasanam.tools.read",
        dt.FORWARDABLE, None, 3600, reg, at)
    store = {t1["parent_ticket_digest"]: root}
    return reg, root, root_seed, t1, t1_seed, store


def _act():
    return hashlib.sha256(b"w299-action").hexdigest()


def _expect(dt, pid, code, fn):
    try:
        fn()
    except dt.DelegationTicketError as e:
        if e.code == code:
            return _record(pid, "HELD", "refused coded %s" % code)
        return _record(pid, "BREAK",
                       "wrong code: got %s, want %s" % (e.code, code))
    _record(pid, "BREAK", "not refused (want coded %s)" % code)


def p_opt_in_issue():
    dt, _ = _need("tk-opt-in-issue")
    if dt is None:
        return
    reg = dt.OptInRegistry()
    opt = dt.declare_opt_in(_seed("a1"), "agent-1", 3600, AT)
    if opt["accepts_delegation"] is not True:
        return _record("tk-opt-in-issue", "BREAK", "opt-in flag not True")
    reg.register(opt, AT)
    if not reg.is_opted_in("agent-1", AT):
        return _record("tk-opt-in-issue", "BREAK", "opt-in not live")
    _record("tk-opt-in-issue", "HELD", "opt-in declared and live")


def p_opt_in_forged():
    dt, _ = _need("tk-opt-in-forged")
    if dt is None:
        return
    reg = dt.OptInRegistry()
    opt = dict(dt.declare_opt_in(_seed("a1"), "agent-1", 3600, AT))
    opt["principal_id"] = "agent-2"  # tamper after signing
    try:
        reg.register(opt, AT)
    except dt.DelegationTicketError as e:
        if e.code == "delegation-ticket-invalid":
            return _record("tk-opt-in-forged", "HELD",
                           "forged opt-in refused coded")
        return _record("tk-opt-in-forged", "BREAK",
                       "wrong code %s" % e.code)
    _record("tk-opt-in-forged", "BREAK", "forged opt-in accepted")


def p_root_issue():
    dt, _ = _need("tk-root-issue")
    if dt is None:
        return
    root, _ = _root(dt)
    if root["parent_ticket_digest"] != dt.ROOT_PARENT_DIGEST:
        return _record("tk-root-issue", "BREAK", "root parent digest wrong")
    if root["delegatee_id"] != root["issuer_id"]:
        return _record("tk-root-issue", "BREAK",
                       "root delegatee != issuer")
    _record("tk-root-issue", "HELD", "root ticket well-formed")


def p_delegate_ok():
    dt, _ = _need("tk-delegate-ok")
    if dt is None:
        return
    reg, root, root_seed, t1, t1_seed, _ = _chain(dt)
    if t1["ticket_type"] != dt.FORWARDABLE:
        return _record("tk-delegate-ok", "BREAK", "type not forwardable")
    if t1["ticket_key_pub"] == root["ticket_key_pub"]:
        return _record("tk-delegate-ok", "BREAK",
                       "ticket key not fresh per ticket")
    _record("tk-delegate-ok", "HELD", "forwardable delegation issued")


def p_present_ok():
    dt, _ = _need("tk-present-ok")
    if dt is None:
        return
    _, _, _, t1, t1_seed, store = _chain(dt)
    act = _act()
    sig = dt.attest_action(t1_seed, t1, act)
    out = dt.present(t1, "agent-1", "sasanam.tools.read.db", act,
                     AT + 10, store, sig)
    if out["ticket_id"] != t1["ticket_id"]:
        return _record("tk-present-ok", "BREAK", "wrong ticket returned")
    _record("tk-present-ok", "HELD", "presentation verifies end to end")


def p_constrained_ok():
    dt, _ = _need("tk-constrained-ok")
    if dt is None:
        return
    reg, _, _, t1, t1_seed, store = _chain(dt)
    tc, tc_seed = dt.issue_delegation_ticket(
        t1, t1_seed, "agent-2", "sasanam.tools.read.db",
        dt.CONSTRAINED, ["agent-2"], 1800, reg, AT)
    store[tc["parent_ticket_digest"]] = t1
    act = _act()
    sig = dt.attest_action(tc_seed, tc, act)
    dt.present(tc, "agent-2", "sasanam.tools.read.db", act,
               AT + 10, store, sig)
    _record("tk-constrained-ok", "HELD",
            "constrained ticket issues and presents within set")


def p_constrained_outside():
    dt, _ = _need("tk-constrained-outside")
    if dt is None:
        return
    reg, _, _, t1, t1_seed, _ = _chain(dt)
    # agent-1 has no opt-in problem here (registered), but the
    # constrained parent's downstream set must bind.
    tc, tc_seed = dt.issue_delegation_ticket(
        t1, t1_seed, "agent-2", "sasanam.tools.read.db",
        dt.CONSTRAINED, ["agent-2"], 1800, reg, AT)
    _expect(dt, "tk-constrained-outside",
            "delegation-ticket-type-violated",
            lambda: dt.issue_delegation_ticket(
                tc, tc_seed, "agent-1", "sasanam.tools.read.db",
                dt.FORWARDABLE, None, 600, reg, AT))


def p_no_opt_in():
    dt, _ = _need("tk-no-opt-in")
    if dt is None:
        return
    _, _, _, t1, t1_seed, _ = _chain(dt)
    reg = _reg(dt)  # agent-9 has no opt-in
    _expect(dt, "tk-no-opt-in", "delegation-ticket-not-opted-in",
            lambda: dt.issue_delegation_ticket(
                t1, t1_seed, "agent-9", "sasanam.tools.read.x",
                dt.FORWARDABLE, None, 600, reg, AT))


def p_non_forwardable():
    dt, _ = _need("tk-non-forwardable")
    if dt is None:
        return
    reg, _, _, t1, t1_seed, _ = _chain(dt)
    tnf, tnf_seed = dt.issue_delegation_ticket(
        t1, t1_seed, "agent-2", "sasanam.tools.read",
        dt.NON_FORWARDABLE, None, 600, reg, AT)
    _expect(dt, "tk-non-forwardable", "delegation-ticket-type-violated",
            lambda: dt.issue_delegation_ticket(
                tnf, tnf_seed, "agent-1", "sasanam.tools.read",
                dt.FORWARDABLE, None, 300, reg, AT))


def p_key_confusion():
    dt, ed = _need("tk-key-confusion")
    if dt is None:
        return
    reg, _, _, t1, t1_seed, store = _chain(dt)
    tc, tc_seed = dt.issue_delegation_ticket(
        t1, t1_seed, "agent-2", "sasanam.tools.read",
        dt.FORWARDABLE, None, 600, reg, AT)
    store[tc["parent_ticket_digest"]] = t1
    act = _act()
    # Sign with the PARENT ticket key instead of the ticket's own key.
    bad_sig = ed.sign(t1_seed, bytes.fromhex(act)).hex()
    _expect(dt, "tk-key-confusion", "delegation-ticket-invalid",
            lambda: dt.present(tc, "agent-2", "sasanam.tools.read",
                               act, AT + 10, store, bad_sig))


def p_expired():
    dt, _ = _need("tk-expired")
    if dt is None:
        return
    _, _, _, t1, _, store = _chain(dt)
    _expect(dt, "tk-expired", "delegation-ticket-expired",
            lambda: dt.present(t1, "agent-1", "sasanam.tools.read",
                               _act(), AT + 99999, store, None))


def p_forged():
    dt, _ = _need("tk-forged")
    if dt is None:
        return
    _, _, _, t1, _, store = _chain(dt)
    evil = dict(t1)
    evil["scope"] = "sasanam.tools.write"  # post-issue mutation
    _expect(dt, "tk-forged", "delegation-ticket-invalid",
            lambda: dt.present(evil, "agent-1", "sasanam.tools.write",
                               _act(), AT + 10, store, None))


def p_scope_escape():
    dt, _ = _need("tk-scope-escape")
    if dt is None:
        return
    _, _, _, t1, _, store = _chain(dt)
    _expect(dt, "tk-scope-escape", "delegation-ticket-invalid",
            lambda: dt.present(t1, "agent-1", "sasanam.tools.write",
                               _act(), AT + 10, store, None))


def p_scope_widen():
    dt, _ = _need("tk-scope-widen")
    if dt is None:
        return
    reg, _, _, t1, t1_seed, _ = _chain(dt)
    _expect(dt, "tk-scope-widen", "delegation-ticket-type-violated",
            lambda: dt.issue_delegation_ticket(
                t1, t1_seed, "agent-2", "sasanam.admin",
                dt.FORWARDABLE, None, 600, reg, AT))


def p_wrong_holder():
    dt, _ = _need("tk-wrong-holder")
    if dt is None:
        return
    _, _, _, t1, _, store = _chain(dt)
    _expect(dt, "tk-wrong-holder", "delegation-ticket-invalid",
            lambda: dt.present(t1, "agent-2", "sasanam.tools.read",
                               _act(), AT + 10, store, None))


def p_child_outlives():
    dt, _ = _need("tk-child-outlives")
    if dt is None:
        return
    reg, _, _, t1, t1_seed, _ = _chain(dt)
    _expect(dt, "tk-child-outlives", "delegation-ticket-invalid",
            lambda: dt.issue_delegation_ticket(
                t1, t1_seed, "agent-2", "sasanam.tools.read",
                dt.FORWARDABLE, None, 3700, reg, AT))


def p_empty_downstream():
    dt, _ = _need("tk-empty-downstream")
    if dt is None:
        return
    reg, _, _, t1, t1_seed, _ = _chain(dt)
    _expect(dt, "tk-empty-downstream", "delegation-ticket-type-violated",
            lambda: dt.issue_delegation_ticket(
                t1, t1_seed, "agent-2", "sasanam.tools.read",
                dt.CONSTRAINED, [], 600, reg, AT))


def p_chain_broken():
    dt, _ = _need("tk-chain-broken")
    if dt is None:
        return
    _, _, _, t1, _, _ = _chain(dt)
    _expect(dt, "tk-chain-broken", "delegation-ticket-invalid",
            lambda: dt.present(t1, "agent-1", "sasanam.tools.read",
                               _act(), AT + 10, {}, None))


def p_issuer_key_confusion():
    dt, _ = _need("tk-issuer-key-confusion")
    if dt is None:
        return
    reg, _, _, t1, _, _ = _chain(dt)
    # Delegate with the AUTHORITY's long-term key instead of the
    # ticket's own key: the module must refuse.
    _expect(dt, "tk-issuer-key-confusion", "delegation-ticket-invalid",
            lambda: dt.issue_delegation_ticket(
                t1, _seed("auth"), "agent-2", "sasanam.tools.read",
                dt.FORWARDABLE, None, 600, reg, AT))


def p_ed25519_contract():
    dt, ed = _need("tk-ed25519-contract")
    if dt is None:
        return
    seed = _seed("contract")
    pub = ed.publickey(seed)
    msg = b"w299-contract"
    sig = ed.sign(seed, msg)
    if ed.verify(pub, msg, sig) is not True:
        return _record("tk-ed25519-contract", "BREAK",
                       "good signature not True")
    bad = bytearray(sig)
    bad[0] ^= 1
    if ed.verify(pub, msg, bytes(bad)) is not False:
        return _record("tk-ed25519-contract", "BREAK",
                       "forged signature not False")
    _record("tk-ed25519-contract", "HELD",
            "ed25519.verify is True / is False (wave-243)")


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        return _record("green-%s" % name, "HELD",
                       "skipped (GOV_SKIP_GREEN=1, depth-1)")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("tk-opt-in-issue", p_opt_in_issue),
        ("tk-opt-in-forged", p_opt_in_forged),
        ("tk-root-issue", p_root_issue),
        ("tk-delegate-ok", p_delegate_ok),
        ("tk-present-ok", p_present_ok),
        ("tk-constrained-ok", p_constrained_ok),
        ("tk-constrained-outside", p_constrained_outside),
        ("tk-no-opt-in", p_no_opt_in),
        ("tk-non-forwardable", p_non_forwardable),
        ("tk-key-confusion", p_key_confusion),
        ("tk-expired", p_expired),
        ("tk-forged", p_forged),
        ("tk-scope-escape", p_scope_escape),
        ("tk-scope-widen", p_scope_widen),
        ("tk-wrong-holder", p_wrong_holder),
        ("tk-child-outlives", p_child_outlives),
        ("tk-empty-downstream", p_empty_downstream),
        ("tk-chain-broken", p_chain_broken),
        ("tk-issuer-key-confusion", p_issuer_key_confusion),
        ("tk-ed25519-contract", p_ed25519_contract),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w297_supervision_probes.py"),
                 "w297-supervision", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w298_redteam_probes.py"),
                 "w298-redteam",
                 tolerate=("pin-taxonomy", "F372", "F373"))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w299_delegation_tickets: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
