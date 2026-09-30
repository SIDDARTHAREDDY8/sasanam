#!/usr/bin/env python3
"""Wave-235 lane C: grant anti-widening for delegated grants.

Delegated grants refine scope, never extend (kroehl AAE direction,
re-derived): delegation transfers the attenuated envelope, never copies
rights. Attack shapes at the public seams (break-first, red-first on
base):

* a delegation whose attenuation widens any scope dimension of the
  parent grant must refuse ``grant-widened`` -- never silently accept;
* the attenuation chain is audited hop-by-hop: the child grant carries
  the full chain (each hop's digest + the narrowing asserted); a hop
  that fails to narrow (a copy, not an attenuation) refuses
  ``grant-attenuation-gap``; a tampered hop digest refuses the same;
* per-hop revocation binding: a revoked middle link refuses
  ``grant-revoked`` NAMING the revoked hop -- the whole chain is
  verified, never just the leaf;
* a leaf-only presentation (a grant with no attenuation chain) refuses
  ``grant-chain-required``.

Seams under test:
* gov/grant_attenuation.py -- mint_root_grant / delegate /
  verify_delegation_chain / GrantAttenuationError.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-234 HEAD 0390dcbd2e65a7d7b15f8c1b0c89efe1807f63d7.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g235c
  TMPDIR=/var/tmp/g235c ~/workspace/.gov-venv/bin/python evals/w235_antiwiden_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def _canon_digest(obj):
    """Local canonical-digest helper for the forgeries below.

    Deliberately NOT the module's own digest helper: a red-team battery
    that recomputes digests with the code under test would pass a
    broken helper tautologically.
    """
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()

HAVE_NEW_API = False
try:
    from gov import grant_attenuation as _ga
    HAVE_NEW_API = all(hasattr(_ga, n) for n in (
        "mint_root_grant", "delegate", "verify_delegation_chain",
        "GrantAttenuationError"))
except ImportError:
    _ga = None

PROBE_NAMES = [
    "antiwiden-root-and-delegate-narrows",
    "antiwiden-widening-attenuation-refused",
    "antiwiden-chain-audit-hop-by-hop",
    "antiwiden-non-narrowing-hop-refused",
    "antiwiden-widen-at-hop-refused",
    "antiwiden-revoked-middle-link-refused",
    "antiwiden-leaf-only-refused",
]

_ROOT_SCOPE = {
    "actions": ["read", "write", "delete"],
    "regions": ["us", "eu"],
    "tier": "standard",
}


def _expect_code(fn, code):
    """Run fn; return ("HELD", detail) iff a GrantAttenuationError with
    the exact machine code is raised, else ("BREAK"/"ERROR", detail)."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - battery records, never masks
        got = getattr(exc, "code", None)
        if got is None:
            got = type(exc).__name__
        if got == code:
            return ("HELD", "raised %r" % (got,))
        return ("BREAK", "wrong code: %r (want %r): %s"
                % (got, code, str(exc)[:160]))
    return ("BREAK", "no refusal raised (want %r)" % (code,))


def _rec(results, name, verdict, detail=""):
    results[name] = verdict if not detail else "%s\n  %s" % (verdict, detail)


def _p1_narrows(results):
    try:
        root = _ga.mint_root_grant("grant-root-1", dict(_ROOT_SCOPE))
        child = _ga.delegate(root, {"actions": ["read"]}, "deleg-1")
        scope = child["scope"]
        assert scope["actions"] == ["read"], scope
        assert sorted(scope["regions"]) == ["eu", "us"], scope
        assert scope["tier"] == "standard", scope
        # The parent grant is never mutated: rights are transferred as
        # an attenuated envelope, not copied out of the parent.
        assert sorted(root["scope"]["actions"]) == ["delete", "read", "write"], \
            root["scope"]
        assert len(child["attenuation_chain"]) == 1, child
        hop = child["attenuation_chain"][0]
        assert hop["delegation_id"] == "deleg-1", hop
        assert hop["narrowing"] == {"actions": ["read"]}, hop
        _rec(results, PROBE_NAMES[0], "HELD",
             "child scope narrowed to %r; parent untouched" % (scope,))
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


def _p2_widen_refused(results):
    try:
        root = _ga.mint_root_grant("grant-root-2", dict(_ROOT_SCOPE))
        # Value widening: 'admin' was never in the parent's actions.
        v, d = _expect_code(
            lambda: _ga.delegate(root, {"actions": ["read", "admin"]},
                                  "deleg-wide-val"),
            "grant-widened")
        assert v == "HELD", d
        # Dimension widening: 'zones' never existed in the parent scope.
        v, d = _expect_code(
            lambda: _ga.delegate(root, {"zones": ["a"]}, "deleg-wide-dim"),
            "grant-widened")
        assert v == "HELD", d
        # Scalar change is not provable narrowing: refused as widening.
        v, d = _expect_code(
            lambda: _ga.delegate(root, {"tier": "gold"}, "deleg-wide-scalar"),
            "grant-widened")
        assert v == "HELD", d
        _rec(results, PROBE_NAMES[1], "HELD",
             "value/dimension/scalar widening all refused grant-widened")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


def _p3_chain_audit(results):
    try:
        root = _ga.mint_root_grant("grant-root-3", dict(_ROOT_SCOPE))
        c1 = _ga.delegate(root, {"actions": ["read", "write"]}, "deleg-3a")
        c2 = _ga.delegate(c1, {"regions": ["us"]}, "deleg-3b")
        audit = _ga.verify_delegation_chain(c2)
        assert audit["chain_length"] == 2, audit
        hops = audit["hops"]
        assert hops[0]["delegation_id"] == "deleg-3a", hops[0]
        assert hops[1]["delegation_id"] == "deleg-3b", hops[1]
        assert hops[0]["narrowing"] == {"actions": ["read", "write"]}, hops[0]
        assert hops[1]["narrowing"] == {"regions": ["us"]}, hops[1]
        # The audit names what each hop narrowed, hop by hop.
        assert c2["scope"]["actions"] == ["read", "write"], c2["scope"]
        assert c2["scope"]["regions"] == ["us"], c2["scope"]
        _rec(results, PROBE_NAMES[2], "HELD",
             "chain_length=2; per-hop narrowing named: %s"
             % ([h["narrowing"] for h in hops],))
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


def _forge_copy_hop_chain(child):
    """Forge a child whose last hop narrows NOTHING (a rights copy)
    but carries consistent digests, so only the narrowing re-derivation
    can catch it."""
    import copy
    forged = copy.deepcopy(child)
    chain = forged["attenuation_chain"]
    last = chain[-1]
    last["narrowing"] = {}
    last["child_scope"] = dict(last["parent_scope"])
    last["child_scope_digest"] = _canon_digest(last["child_scope"])
    body = {k: v for k, v in last.items() if k != "hop_digest"}
    last["hop_digest"] = _canon_digest(body)
    # Recompute the forged child's grant digest so the only lie is the
    # non-narrowing hop.
    grant_body = {k: v for k, v in forged.items() if k != "grant_digest"}
    forged["grant_digest"] = _canon_digest(grant_body)
    return forged


def _p4_copy_hop_refused(results):
    try:
        root = _ga.mint_root_grant("grant-root-4", dict(_ROOT_SCOPE))
        c1 = _ga.delegate(root, {"actions": ["read"]}, "deleg-4a")
        forged = _forge_copy_hop_chain(c1)
        v, d = _expect_code(
            lambda: _ga.verify_delegation_chain(forged),
            "grant-attenuation-gap")
        assert v == "HELD", d
        # A tampered hop digest is the same refusal class: the hop does
        # not check out as a narrowing step.
        import copy
        tampered = copy.deepcopy(c1)
        tampered["attenuation_chain"][0]["hop_digest"] = "0" * 64
        grant_body = {k: v for k, v in tampered.items()
                      if k != "grant_digest"}
        tampered["grant_digest"] = _canon_digest(grant_body)
        v, d = _expect_code(
            lambda: _ga.verify_delegation_chain(tampered),
            "grant-attenuation-gap")
        assert v == "HELD", d
        _rec(results, PROBE_NAMES[3], "HELD",
             "copy-hop and tampered-hop both refused grant-attenuation-gap")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


def _p5_widen_at_hop_refused(results):
    try:
        root = _ga.mint_root_grant("grant-root-5", dict(_ROOT_SCOPE))
        c1 = _ga.delegate(root, {"actions": ["read"]}, "deleg-5a")
        # Craft hop 2 (on c1) that widens actions back to include
        # 'delete', with internally consistent digests so only the
        # widening re-derivation refuses.
        import copy
        forged = copy.deepcopy(c1)
        parent_scope = dict(forged["scope"])
        narrowing = {"actions": ["read", "delete"]}
        child_scope = dict(parent_scope)
        child_scope["actions"] = ["read", "delete"]
        hop = {
            "delegation_id": "deleg-5b",
            "parent_grant_id": forged["grant_id"],
            "child_grant_id": "deleg-5b",
            "parent_scope": parent_scope,
            "narrowing": narrowing,
            "child_scope": child_scope,
            "revocation_endpoint": None,
        }
        hop["parent_scope_digest"] = _canon_digest(parent_scope)
        hop["child_scope_digest"] = _canon_digest(child_scope)
        hop_body = {k: v for k, v in hop.items() if k != "hop_digest"}
        hop["hop_digest"] = _canon_digest(hop_body)
        forged["attenuation_chain"] = forged["attenuation_chain"] + [hop]
        forged["grant_id"] = "deleg-5b"
        forged["scope"] = child_scope
        forged["parent_grant_id"] = c1["grant_id"]
        grant_body = {k: v for k, v in forged.items()
                      if k != "grant_digest"}
        forged["grant_digest"] = _canon_digest(grant_body)
        v, d = _expect_code(
            lambda: _ga.verify_delegation_chain(forged), "grant-widened")
        assert v == "HELD", d
        _rec(results, PROBE_NAMES[4], "HELD",
             "hop-2 widening refused grant-widened")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


def _p6_revoked_middle_refused(results):
    try:
        root = _ga.mint_root_grant("grant-root-6", dict(_ROOT_SCOPE))
        c1 = _ga.delegate(root, {"actions": ["read", "write"]}, "deleg-6a")
        c2 = _ga.delegate(c1, {"regions": ["us"]}, "deleg-6b")
        c3 = _ga.delegate(c2, {"actions": ["read"]}, "deleg-6c")
        middle_digest = c3["attenuation_chain"][1]["hop_digest"]
        registry = {middle_digest: True}
        try:
            _ga.verify_delegation_chain(c3, revocation_registry=registry)
            _rec(results, PROBE_NAMES[5], "BREAK",
                 "revoked middle link was not refused")
            return
        except Exception as exc:  # noqa: BLE001 - expected refusal
            got = getattr(exc, "code", None)
            assert got == "grant-revoked", \
                "wrong code: %r (want 'grant-revoked')" % (got,)
            # The refusal names the revoked hop.
            assert "deleg-6b" in str(exc), str(exc)[:200]
        # And without the revocation the same chain verifies: revocation
        # is what refused, not chain shape.
        audit = _ga.verify_delegation_chain(c3)
        assert audit["chain_length"] == 3, audit
        _rec(results, PROBE_NAMES[5], "HELD",
             "revoked hop 1 (deleg-6b) refused grant-revoked; "
             "unrevoked chain verifies")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


def _p7_leaf_only_refused(results):
    try:
        root = _ga.mint_root_grant("grant-root-7", dict(_ROOT_SCOPE))
        v, d = _expect_code(
            lambda: _ga.verify_delegation_chain(root), "grant-chain-required")
        assert v == "HELD", d
        # A hand-made leaf grant dict with no chain at all.
        leaf = {"v": 1, "grant_id": "leaf-x", "scope": dict(_ROOT_SCOPE)}
        v, d = _expect_code(
            lambda: _ga.verify_delegation_chain(leaf), "grant-chain-required")
        assert v == "HELD", d
        _rec(results, PROBE_NAMES[6], "HELD",
             "root grant and chain-less dict both refused grant-chain-required")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


def _run_all():
    results = {}
    _p1_narrows(results)
    _p2_widen_refused(results)
    _p3_chain_audit(results)
    _p4_copy_hop_refused(results)
    _p5_widen_at_hop_refused(results)
    _p6_revoked_middle_refused(results)
    _p7_leaf_only_refused(results)
    return results


def main():
    t0 = time.time()
    if not HAVE_NEW_API:
        for name in PROBE_NAMES:
            print("%-42s GAP (grant attenuation module absent)" % name)
        print("summary: 0 HELD / %d GAP / 0 BREAK / 0 ERROR"
              % len(PROBE_NAMES))
        return 2
    results = _run_all()

    def _v(name):
        return results.get(name, "ERROR: missing").split("\n")[0]
    held = sum(1 for name in PROBE_NAMES if _v(name) == "HELD")
    gap = sum(1 for name in PROBE_NAMES if _v(name).startswith("GAP"))
    brk = sum(1 for name in PROBE_NAMES if _v(name).startswith("BREAK"))
    err = sum(1 for name in PROBE_NAMES if _v(name).startswith("ERROR"))
    for name in PROBE_NAMES:
        verdict = results.get(name, "ERROR: missing")
        first = verdict.split("\n")[0]
        print("%-42s %s" % (name, first))
        if "\n" in verdict:
            print(verdict.split("\n", 1)[1])
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)"
          % (held, gap, brk, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
