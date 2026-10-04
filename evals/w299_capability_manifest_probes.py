"""Wave-299 lane 4 battery: Fuchsia-style capability manifests for supervision.

Base: wave-298 merge 2af956fd880d9a58a9e26e51efb6f47e82594b4e
(verified via git rev-parse HEAD before work).

New product surface (all additive, gov/supervision.py only):
  (a) ChildSpec(..., capabilities={use:[...], offer:[...], expose:[...]})
      -- declared, bounded, deep-frozen capability manifest;
  (b) Supervisor(..., endowment={cap: rights | {rights, held, from}})
      -- the supervisor's closed capability inventory;
  (c) offer-time attenuation: use-from-parent / offer rights must be a
      subset of held rights -- refused coded at DECLARATION time,
      before the child ever runs (supervision-capability-rights-exceeded);
  (d) no silent retention: held="route" endowment entries are merely
      routed -- Supervisor.exercise() on one refuses coded
      supervision-capability-route-violation; routing an undeclared
      capability refuses supervision-capability-undeclared;
  (e) expose routes further only with a matching from:<child> endowment
      entry, else terminates explicitly (exposed_routing());
  (f) restart decisions carry capability_grants for manifested children
      -- a restarted child gets exactly its declared capabilities.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ChildSpec rejects the capabilities kwarg); on the fixed tree
they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g299-cm && TMPDIR=/var/tmp/g299-cm \
    ~/workspace/.gov-venv/bin/python evals/w299_capability_manifest_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g299-cm2 \
    ~/workspace/.gov-venv/bin/python evals/w299_capability_manifest_probes.py
"""

import hashlib
import json
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

TAXONOMY_PIN = 2056 # Wave-299 lane 4: pin 1780 -> 1783 (+3 supervision-capability-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*)



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
    for want in ("supervision-capability-undeclared",
                 "supervision-capability-rights-exceeded",
                 "supervision-capability-route-violation"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1827 raw literals, unique, sorted")


def _import_mods():
    try:
        from gov import supervision
        from gov import ed25519
    except ImportError:
        return None, None
    return supervision, ed25519


def _need(pid):
    sup, ed = _import_mods()
    if sup is None:
        _record(pid, "BREAK", "feature absent on this tree "
                              "(gov.supervision missing)")
        return None, None
    return sup, ed


def _seed(tag):
    return hashlib.sha256(("w299-cap-manifest-%s" % tag).encode()).digest()


def _pub(ed, seed):
    return ed.publickey(seed).hex()


def _manifest(**kw):
    m = {"use": [], "offer": [], "expose": []}
    m.update(kw)
    return m


def _use(cap, rights, src="parent"):
    return {"capability": cap, "rights": list(rights), "from": src}


def _sup2(sup, ed, specs, endowment, name="sup-cm"):
    s = sup.Supervisor(name, specs, _seed("sup-" + name), endowment=endowment)
    s.start(at=0)
    return s


def _expect(pid, fn, code, note):
    sup, ed = _need(pid)
    if sup is None:
        return
    try:
        fn(sup, ed)
    except sup.SupervisionError as e:
        if e.code == code:
            return _record(pid, "HELD", note)
        return _record(pid, "BREAK",
                       "wrong code: got %r want %r (%s)" % (e.code, code, note))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK", "uncoded escape %r (%s)" % (e, note))
    _record(pid, "BREAK", "no refusal at all (%s)" % note)


def _expect_ok(pid, fn, note):
    """HELD when fn() returns truthy without raising."""
    sup, ed = _need(pid)
    if sup is None:
        return
    try:
        got = fn(sup, ed)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK", "unexpected raise %r (%s)" % (e, note))
    if got:
        return _record(pid, "HELD", note)
    _record(pid, "BREAK", "falsy result (%s)" % note)


# -- declaration ---------------------------------------------------------

def p_spec_accepts(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             use=[_use("fs-read", ["r"], "parent")]))
    assert spec.manifest["use"][0]["capability"] == "fs-read"
    return True


def p_spec_badshape(sup, ed):
    sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                  100, 3600,
                  capabilities={"use": [_use("x", ["r"], "parent")]})
    # missing offer/expose sections -> supervision-invalid


def p_spec_empty_rights(sup, ed):
    sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                  100, 3600, capabilities=_manifest(
                      use=[_use("fs-read", [], "parent")]))


def p_spec_bad_right_token(sup, ed):
    sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                  100, 3600, capabilities=_manifest(
                      use=[{"capability": "fs-read", "rights": ["RW"],
                             "from": "parent"}]))


def p_spec_frozen(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600,
                         capabilities=_manifest(
                             use=[_use("fs-read", ["r"], "parent")]))
    spec.capabilities = None  # F330/F340 pattern: frozen at declaration


def p_manifest_deepfreeze(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             use=[_use("fs-read", ["r"], "parent")]))
    s = _sup2(sup, ed, [spec], {"fs-read": {"r"}})
    leaked = spec.manifest
    leaked["use"].append(_use("net", ["r", "w"], "parent"))
    leaked["use"][0]["rights"].append("w")
    got = s.granted_capabilities("child-a")
    assert got == {"fs-read": ["r"]}, "deep freeze broken: %r" % (got,)
    return True


def p_offer_attenuation(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             use=[_use("fs-read", ["r", "w"], "parent")]))
    _sup2(sup, ed, [spec], {"fs-read": {"r"}})


def p_undeclared_use(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             use=[_use("net", ["r"], "parent")]))
    _sup2(sup, ed, [spec], {"fs-read": {"r"}})


def p_offer_no_hold(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             offer=[_use("fs-read", ["r"], "parent")]))
    _sup2(sup, ed, [spec], {"fs-read": {"r"}})


def p_offer_wider(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             use=[_use("fs-read", ["r"], "parent")],
                             offer=[_use("fs-read", ["r", "w"], "parent")]))
    _sup2(sup, ed, [spec], {"fs-read": {"r", "w"}})


def p_expose_wider(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             expose=[{"capability": "metrics",
                                       "rights": ["r", "w"], "from": "self"}]))
    _sup2(sup, ed, [spec], {"metrics": {"rights": {"r"}, "held": "route",
                                        "from": "child-a"}})


def p_expose_terminates(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             expose=[{"capability": "debug",
                                       "rights": ["r"], "from": "self"}]))
    s = _sup2(sup, ed, [spec], {"fs-read": {"r"}})
    routing = s.exposed_routing()
    assert routing == {"child-a": {"debug": {"status": "terminated",
                                             "rights": ["r"]}}}, routing
    return True


def p_expose_routed(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             expose=[{"capability": "metrics",
                                       "rights": ["r"], "from": "self"}]))
    s = _sup2(sup, ed, [spec], {"metrics": {"rights": {"r"}, "held": "route",
                                            "from": "child-a"}})
    routing = s.exposed_routing()
    assert routing == {"child-a": {"metrics": {"status": "routed",
                                              "rights": ["r"]}}}, routing
    return True


def p_endowment_named_child_undeclared(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600)
    _sup2(sup, ed, [spec], {"pipe": {"rights": {"r"}, "held": "route",
                                     "from": "ghost-child"}})


# -- exercise (no silent retention) ---------------------------------------

def p_exercise_ok(sup, ed):
    s = _sup2(sup, ed, [sup.ChildSpec("child-a", _pub(ed, _seed("c-a")),
                                      "one_for_one", 100, 3600)],
                {"fs-read": {"rights": {"r", "w"}, "held": "use",
                             "from": "parent"}})
    return s.exercise("fs-read", {"r"}) is True


def p_exercise_route(sup, ed):
    s = _sup2(sup, ed, [sup.ChildSpec("child-a", _pub(ed, _seed("c-a")),
                                      "one_for_one", 100, 3600)],
                {"metrics": {"rights": {"r"}, "held": "route",
                             "from": "parent"}})
    s.exercise("metrics", {"r"})


def p_exercise_undeclared(sup, ed):
    s = _sup2(sup, ed, [sup.ChildSpec("child-a", _pub(ed, _seed("c-a")),
                                      "one_for_one", 100, 3600)],
                {"fs-read": {"r"}})
    s.exercise("net", {"r"})


def p_exercise_wider(sup, ed):
    s = _sup2(sup, ed, [sup.ChildSpec("child-a", _pub(ed, _seed("c-a")),
                                      "one_for_one", 100, 3600)],
                {"fs-read": {"rights": {"r"}, "held": "use",
                             "from": "parent"}})
    s.exercise("fs-read", {"r", "w"})


# -- grants + restart ----------------------------------------------------

def p_grant_exact(sup, ed):
    spec = sup.ChildSpec("child-a", _pub(ed, _seed("c-a")), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             use=[_use("fs-read", ["r"], "parent"),
                                   _use("mem", ["w"], "self")]))
    s = _sup2(sup, ed, [spec], {"fs-read": {"r", "w"}})
    got = s.granted_capabilities("child-a")
    assert got == {"fs-read": ["r"], "mem": ["w"]}, got
    return True


def p_restart_grant(sup, ed):
    cseed = _seed("c-a")
    spec = sup.ChildSpec("child-a", _pub(ed, cseed), "one_for_one",
                         100, 3600, capabilities=_manifest(
                             use=[_use("fs-read", ["r"], "parent")]))
    plain = sup.ChildSpec("child-b", _pub(ed, _seed("c-b")), "one_for_one",
                          100, 3600)
    s = _sup2(sup, ed, [spec, plain], {"fs-read": {"r", "w"}}, name="sup-rg")
    body = {"child_id": "child-a", "reason_kind": "exit",
            "reason_bytes": "boom", "crashed_at": 10}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    rep = dict(body)
    rep["signature"] = ed.sign(cseed, raw).hex()
    decision = s.report_crash("child-a", rep, at=10)
    grants = decision.get("capability_grants")
    assert grants == {"child-a": {"fs-read": ["r"]}}, grants
    # A restarted plain child gets no grant key at all -- and a plain
    # supervisor's decisions keep their exact legacy shape.
    s2 = _sup2(sup, ed, [plain], None, name="sup-plain")
    body2 = {"child_id": "child-b", "reason_kind": "exit",
             "reason_bytes": "boom", "crashed_at": 10}
    raw2 = json.dumps(body2, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()
    rep2 = dict(body2)
    rep2["signature"] = ed.sign(_seed("c-b"), raw2).hex()
    d2 = s2.report_crash("child-b", rep2, at=10)
    assert "capability_grants" not in d2, d2.keys()
    assert "lease_obligations" not in d2, d2.keys()
    return True


def p_ed25519_contract(sup, ed):
    # Forged crash report must refuse coded supervision-invalid, and
    # the ed25519 True/False contract holds (wave-243 lesson).
    cseed = _seed("c-a")
    wrong = _seed("wrong")
    spec = sup.ChildSpec("child-a", _pub(ed, cseed), "one_for_one",
                         100, 3600)
    s = _sup2(sup, ed, [spec], None, name="sup-e2e")
    body = {"child_id": "child-a", "reason_kind": "exit",
            "reason_bytes": "boom", "crashed_at": 10}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    assert ed.verify(bytes.fromhex(_pub(ed, cseed)),
                     raw, ed.sign(cseed, raw)) is True
    assert ed.verify(bytes.fromhex(_pub(ed, cseed)), raw,
                     ed.sign(wrong, raw)) is False
    rep = dict(body)
    rep["signature"] = ed.sign(wrong, raw).hex()
    s.report_crash("child-a", rep, at=10)


# -- green checks (depth-1) ----------------------------------------------

def _green_check(path, name, tolerate=()):
    if os.environ.get("GOV_SKIP_GREEN") == "1":
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
        ("cm-spec-accepts", p_spec_accepts),
    ]:
        _safe(pid, lambda pid=pid, fn=fn: _expect_ok(
            pid, fn, "valid manifest accepted"))
    for pid, fn, code in [
        ("cm-spec-badshape", p_spec_badshape, "supervision-invalid"),
        ("cm-spec-empty-rights", p_spec_empty_rights, "supervision-invalid"),
        ("cm-spec-bad-right-token", p_spec_bad_right_token,
         "supervision-invalid"),
        ("cm-spec-frozen", p_spec_frozen, "supervision-invalid"),
        ("cm-offer-attenuation", p_offer_attenuation,
         "supervision-capability-rights-exceeded"),
        ("cm-undeclared-use", p_undeclared_use,
         "supervision-capability-undeclared"),
        ("cm-offer-no-hold", p_offer_no_hold,
         "supervision-capability-undeclared"),
        ("cm-offer-wider", p_offer_wider,
         "supervision-capability-rights-exceeded"),
        ("cm-expose-wider", p_expose_wider,
         "supervision-capability-rights-exceeded"),
        ("cm-exercise-route", p_exercise_route,
         "supervision-capability-route-violation"),
        ("cm-exercise-undeclared", p_exercise_undeclared,
         "supervision-capability-undeclared"),
        ("cm-exercise-wider", p_exercise_wider,
         "supervision-capability-rights-exceeded"),
        ("cm-endowment-named-child", p_endowment_named_child_undeclared,
         "supervision-undeclared-child"),
        ("cm-ed25519-contract", p_ed25519_contract, "supervision-invalid"),
    ]:
        _safe(pid, lambda pid=pid, fn=fn, code=code: _expect(
            pid, fn, code, "coded refusal"))
    for pid, fn in [
        ("cm-manifest-deepfreeze", p_manifest_deepfreeze),
        ("cm-expose-terminates", p_expose_terminates),
        ("cm-expose-routed", p_expose_routed),
        ("cm-exercise-ok", p_exercise_ok),
        ("cm-grant-exact", p_grant_exact),
        ("cm-restart-grant", p_restart_grant),
    ]:
        _safe(pid, lambda pid=pid, fn=fn: _expect_ok(
            pid, fn, "positive behavior held"))
    _green_check(os.path.join(REPO, "evals", "w297_supervision_probes.py"),
                 "w297-supervision", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w298_supervision_lease_probes.py"),
                 "w298-supervision-lease", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w299_capability_manifest: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
