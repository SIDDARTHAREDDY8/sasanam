"""Red-first probes for wave-239 lane B: claim-at-dispatch (AgentSafe ADAPT).

An ALLOW is not permission; a claimed grant is. A claim must be
presented immediately before the handler runs; the handler never sees
the grant token. A locally-verified-but-never-claimed grant MUST NOT
dispatch. Dispatch budget = min(upstream timeout, remaining grant,
claim lease) on a monotonic clock. Claim succeeded then crash before
the handler ran: the grant is NOT released for a second claim; the
claim lease and the finalization record say what happened.

Each probe returns (probe_id, "HELD"/"GAP"/"ERROR", detail).
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _import():
    try:
        import gov.claim_at_dispatch as mod
        return mod
    except Exception:
        return None


def _refusal(mod, fn, *args, **kwargs):
    """Run fn; return (code, message) if a refusal was raised, else (None, result)."""
    try:
        return None, fn(*args, **kwargs)
    except mod.ClaimDispatchError as exc:
        return exc.code, str(exc)
    except Exception as exc:  # a non-refusal error is a probe ERROR
        raise RuntimeError("unexpected %r: %s" % (type(exc).__name__, exc))


@probe
def p01_unclaimed_grant_must_not_dispatch(_ctx):
    mod = _import()
    if mod is None:
        return "P01", "GAP", "gov.claim_at_dispatch not importable"
    grant = mod.issue_grant(grant_id="g-1", decision_id="d-1", dossier_id="f-1",
                            remaining=600.0)
    code, _res = _refusal(mod, mod.dispatch, grant, timeout=60.0, lease=30.0,
                          run_handler=lambda: "ran")
    if code == "claim-not-presented":
        return "P01", "HELD", "locally-verified-but-never-claimed grant refused"
    return "P01", "GAP", "expected claim-not-presented, got %r" % (code,)


@probe
def p02_crash_after_claim_no_second_claim(_ctx):
    mod = _import()
    if mod is None:
        return "P02", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-2", decision_id="d-2", dossier_id="f-2",
                            remaining=600.0)
    claim1 = authority.claim(grant)
    # The process crashes before the handler runs: finalize as crashed,
    # no release for a second claim.
    final = mod.finalize(authority, claim1, "crashed")
    claim2_code, _ = _refusal(mod, authority.claim, grant)
    claim2_code2, _ = _refusal(mod, mod.dispatch, grant, timeout=60.0,
                               lease=30.0, run_handler=lambda: "ran",
                               authority=authority)
    if (claim2_code == "claim-not-releasable" and claim2_code2 == "claim-not-presented"
            and final is not None):
        return ("P02", "HELD",
                "second claim refused; finalization record explains")
    return "P02", "GAP", "second claim not refused as expected (%r, %r)" % (
        claim2_code, claim2_code2)


@probe
def p03_double_presentation_is_replay(_ctx):
    mod = _import()
    if mod is None:
        return "P03", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-3", decision_id="d-3", dossier_id="f-3",
                            remaining=600.0)
    claim = authority.claim(grant)
    first = authority.present(claim, timeout=60.0)
    code, _ = _refusal(mod, authority.present, claim, timeout=60.0)
    if first is not None and code == "claim-replay":
        return "P03", "HELD", "second presentation refused as replay"
    return "P03", "GAP", "expected claim-replay, got %r" % (code,)


@probe
def p04_claimed_within_lease_dispatches(_ctx):
    mod = _import()
    if mod is None:
        return "P04", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-4", decision_id="d-4", dossier_id="f-4",
                            remaining=600.0)
    claim = authority.claim(grant)
    receipt = authority.present(claim, timeout=60.0)
    handler_saw = []
    result = mod.dispatch_grant(grant, claim, timeout=60.0,
                                run_handler=lambda ids: (handler_saw.append(ids), "ok")[1],
                                authority=authority)
    if result is not None and receipt is not None and "grant" not in str(handler_saw):
        return "P04", "HELD", "claimed grant dispatches; handler never saw token"
    return "P04", "GAP", "clean dispatch path failed"


@probe
def p05_handler_never_sees_grant_token(_ctx):
    mod = _import()
    if mod is None:
        return "P05", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-5", decision_id="d-5", dossier_id="f-5",
                            remaining=600.0)
    claim = authority.claim(grant)
    authority.present(claim, timeout=60.0)
    seen = []
    mod.dispatch_grant(grant, claim, timeout=60.0,
                       run_handler=lambda ids: seen.append(ids),
                       authority=authority)
    ids = seen[0] if seen else {}
    forbidden = ("grant_token", "token", "secret")
    leaked = [k for k in ids if any(f in k for f in forbidden)]
    if not leaked and ids.get("decision_id") == "d-5" and ids.get("dossier_id") == "f-5":
        return "P05", "HELD", "handler received only identifiers, no token"
    return "P05", "GAP", "handler saw token-shaped material: %r" % (leaked,)


@probe
def p06_dispatch_budget_is_minimum(_ctx):
    mod = _import()
    if mod is None:
        return "P06", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-6", decision_id="d-6", dossier_id="f-6",
                            remaining=600.0)
    claim = authority.claim(grant, lease=10.0)
    budget = mod.dispatch_budget(grant, claim, timeout=120.0)
    # The lease is the minimum term; it has decayed only by the
    # microseconds since claim() ran, so the budget is within 0.5 s
    # of 10.0 (P11 pins the decay itself).
    if 9.5 < budget <= 10.0:
        return "P06", "HELD", "budget = min(timeout, remaining, lease)"
    return "P06", "GAP", "budget not the minimum: %r" % (budget,)


@probe
def p07_claim_after_expiry_refuses(_ctx):
    mod = _import()
    if mod is None:
        return "P07", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-7", decision_id="d-7", dossier_id="f-7",
                            remaining=600.0)
    claim = authority.claim(grant, lease=0.0)
    code, _ = _refusal(mod, authority.present, claim, timeout=60.0)
    if code == "claim-lease-expired":
        return "P07", "HELD", "expired claim lease refused"
    return "P07", "GAP", "expected claim-lease-expired, got %r" % (code,)


@probe
def p08_mismatched_digest_claims_nothing(_ctx):
    mod = _import()
    if mod is None:
        return "P08", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-8", decision_id="d-8", dossier_id="f-8",
                            remaining=600.0)
    grant_tampered = dict(grant)
    grant_tampered["payload_digest"] = "0" * 64
    code, _ = _refusal(mod, authority.claim, grant_tampered)
    if code == "claim-invalid-grant":
        return "P08", "HELD", "tampered grant claims nothing"
    return "P08", "GAP", "expected claim-invalid-grant, got %r" % (code,)


@probe
def p09_cross_grant_claim_cannot_dispatch(_ctx):
    """A presented claim for grant A cannot dispatch never-claimed grant B."""
    mod = _import()
    if mod is None:
        return "P09", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant_a = mod.issue_grant(grant_id="g-9a", decision_id="d-9a",
                              dossier_id="f-9a", remaining=600.0)
    grant_b = mod.issue_grant(grant_id="g-9b", decision_id="d-9b",
                              dossier_id="f-9b", remaining=600.0)
    claim_a = authority.claim(grant_a, lease=30.0)
    authority.present(claim_a, timeout=60.0)
    code, res = _refusal(mod, mod.dispatch_grant, grant_b, claim_a,
                         timeout=60.0, run_handler=lambda ids: "ran",
                         authority=authority)
    if code == "claim-invalid-grant":
        return "P09", "HELD", "claim for grant A cannot dispatch grant B"
    return "P09", "GAP", "expected claim-invalid-grant, got %r / %r" % (code, res)


@probe
def p10_dispatch_never_twice(_ctx):
    """The second dispatch_grant against one presentation must not run the handler."""
    mod = _import()
    if mod is None:
        return "P10", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-10", decision_id="d-10",
                            dossier_id="f-10", remaining=600.0)
    claim = authority.claim(grant, lease=30.0)
    authority.present(claim, timeout=60.0)
    runs = []
    mod.dispatch_grant(grant, claim, timeout=60.0,
                       run_handler=lambda ids: runs.append(1),
                       authority=authority)
    code, res = _refusal(mod, mod.dispatch_grant, grant, claim, timeout=60.0,
                         run_handler=lambda ids: runs.append(1),
                         authority=authority)
    if code == "claim-replay" and len(runs) == 1:
        return "P10", "HELD", "second dispatch refused; handler ran once"
    return "P10", "GAP", "expected claim-replay with one run, got %r runs=%d" % (code, len(runs))


@probe
def p11_dispatch_budget_reads_the_clock(_ctx):
    """dispatch_budget decays with elapsed lease time, not the full lease."""
    mod = _import()
    if mod is None:
        return "P11", "GAP", "gov.claim_at_dispatch not importable"
    import time
    authority = mod.ClaimAuthority()
    grant = mod.issue_grant(grant_id="g-11", decision_id="d-11",
                            dossier_id="f-11", remaining=600.0)
    claim = authority.claim(grant, lease=0.6)
    time.sleep(0.3)
    budget = mod.dispatch_budget(grant, claim, timeout=60.0)
    if budget <= 0.6 - 0.3 + 0.05:
        return "P11", "HELD", "budget decayed with elapsed lease (%.3f)" % budget
    return "P11", "GAP", "budget did not read the clock: %.3f" % (budget,)


@probe
def p12_claim_checks_expected_payload_digest(_ctx):
    """A valid-sealed grant for another intent hash claims nothing when the
    pipeline names the digest it expects."""
    mod = _import()
    if mod is None:
        return "P12", "GAP", "gov.claim_at_dispatch not importable"
    authority = mod.ClaimAuthority()
    grant_other = mod.issue_grant(grant_id="g-12", decision_id="d-12",
                                  dossier_id="f-12", remaining=600.0)
    code, _ = _refusal(mod, authority.claim, grant_other,
                       expected_payload_digest="0" * 64)
    if code == "claim-invalid-grant":
        return "P12", "HELD", "grant for another intent hash claims nothing"
    return "P12", "GAP", "expected claim-invalid-grant, got %r" % (code,)


def main():
    rows = []
    for fn in PROBES:
        try:
            rows.append(fn({}))
        except Exception as exc:
            rows.append((fn.__name__, "ERROR", repr(exc)))
    held = sum(1 for r in rows if r[1] == "HELD")
    gap = sum(1 for r in rows if r[1] == "GAP")
    err = sum(1 for r in rows if r[1] == "ERROR")
    for pid, status, detail in rows:
        print("%s %-5s %s" % (pid, status, detail))
    print("HELD %d / GAP %d / ERROR %d (total %d)" % (held, gap, err, len(rows)))
    if err or gap:
        raise SystemExit(2)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
