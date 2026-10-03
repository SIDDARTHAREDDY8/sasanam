"""Wave-299 lane 5 battery: delegation revocation propagation.

Base: wave-298 merge 2af956fd880d9a58a9e26e51efb6f47e82594b4e
(verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/delegation_revocation.py -- signed revocation records,
      append-only bounded per-delegator revocation lists, epoch
      revocation, is_live chain walk (shape -> signature ->
      revocation -> expiry; revocation beats expiry), monotonic
      revocation (no un-revoke API);
  (b) 3 new codes at true sorted positions
      (delegation-revocation-invalid, delegation-revocation-list-full,
      delegation-revoked); lane pin 1780 -> 1783; wave-299 merge: pin 1783 -> 1797.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module, and the pin probe sees 1780
literals); on the fixed tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g299-dr && TMPDIR=/var/tmp/g299-dr \
    ~/workspace/.gov-venv/bin/python evals/w299_delegation_revoke_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g299-dr2 \
    ~/workspace/.gov-venv/bin/python evals/w299_delegation_revoke_probes.py
"""

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
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 1872  # Wave-301 merge pin 1812; wave-299 lane 5: pin 1780 -> 1783 (+3 delegation-revocation-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception:  # noqa: BLE001
        _record(pid, "ERROR", traceback.format_exc(limit=3))


def _seed(tag):
    return hashlib.sha256(b"w299-battery:" + tag.encode()).digest()


def _mod():
    import gov.delegation_revocation as dr
    return dr


def p_taxonomy_pin():
    dr = _mod()
    src = open(os.path.join(REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code": \'([^\']+)\'', src)
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    for want in ("delegation-revoked", "delegation-revocation-invalid",
                 "delegation-revocation-list-full"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK", "missing code %s" % want)
    if not (dr.RV_REVOKED == "delegation-revoked"
            and dr.RV_INVALID == "delegation-revocation-invalid"
            and dr.RV_LIST_FULL == "delegation-revocation-list-full"):
        return _record("pin-taxonomy", "BREAK",
                       "module code constants drift from taxonomy")
    _record("pin-taxonomy", "HELD", "1872/1872/0 sorted")


class _H:
    """Harness: root -> a -> b chain, all keys known."""

    def __init__(self):
        dr = _mod()
        from gov import ed25519
        self.dr = dr
        self.ed = ed25519
        self.seeds = {n: _seed("key-" + n) for n in ("root", "a", "b")}
        self.keyring = {n: ed25519.publickey(s).hex()
                        for n, s in self.seeds.items()}
        self.revoker = dr.DelegationRevoker(self.seeds["root"], "root")
        self.root = dr.make_receipt(self.seeds["root"], "root", "a",
                                    None, 0, ["read", "write"], 0, 1000)
        self.hop1 = dr.make_receipt(self.seeds["a"], "a", "b",
                                    self.root["receipt_id"], 1,
                                    ["read"], 0, 1000)
        self.hop2 = dr.make_receipt(self.seeds["b"], "b", "c",
                                    self.hop1["receipt_id"], 2,
                                    ["read"], 0, 1000)

    def chain(self):
        return [dict(self.root), dict(self.hop1), dict(self.hop2)]


def _expect_code(pid, fn, code):
    dr = _mod()
    try:
        fn()
    except dr.RevocationError as e:
        if e.code == code:
            return _record(pid, "HELD", "refused coded %s" % code)
        return _record(pid, "BREAK",
                       "wrong code: %s, want %s" % (e.code, code))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK", "uncoded escape: %r" % (e,))
    return _record(pid, "BREAK", "no refusal (held when it should refuse)")


def p_import():
    try:
        _mod()
    except ImportError:
        return _record("dr-import", "BREAK", "gov.delegation_revocation absent")
    _safe("pin-taxonomy", p_taxonomy_pin)


def p_live_chain():
    h = _H()
    leaf = h.revoker.is_live(h.chain(), 500, h.keyring)
    if leaf == h.hop2["receipt_id"]:
        _record("dr-live-chain", "HELD", "honest chain live")
    else:
        _record("dr-live-chain", "BREAK", "wrong leaf returned")


def p_use_after_revoke_direct():
    h = _H()
    h.revoker.revoke(h.hop2["receipt_id"], 100, target_epoch=2)
    _expect_code("dr-use-after-revoke-direct",
                 lambda: h.revoker.is_live(h.chain(), 500, h.keyring),
                 "delegation-revoked")


def p_descendant_dies_with_ancestor():
    # Revoking the ROOT kills the whole downstream subtree: the leaf is
    # refused even though only the root was revoked.
    h = _H()
    h.revoker.revoke(h.root["receipt_id"], 100, target_epoch=0)
    _expect_code("dr-descendant-dies",
                 lambda: h.revoker.is_live(h.chain(), 500, h.keyring),
                 "delegation-revoked")


def p_redelegation_under_revoked_refused():
    # A NEW receipt parented under a revoked receipt still chains
    # through the revoked ancestor -> refused.
    h = _H()
    h.revoker.revoke(h.hop1["receipt_id"], 100, target_epoch=1)
    fresh = h.dr.make_receipt(h.seeds["b"], "b", "d",
                              h.hop1["receipt_id"], 3, ["read"], 0, 1000)
    ring = dict(h.keyring)
    _expect_code("dr-redelegation-under-revoked",
                 lambda: h.revoker.is_live(
                     [h.root, h.hop1, fresh], 500, ring),
                 "delegation-revoked")


def p_revocation_beats_expiry():
    # Revoked-but-unexpired receipt refuses delegation-revoked, NOT
    # delegation-expired: the revocation check runs first.
    h = _H()
    long = h.dr.make_receipt(h.seeds["root"], "root", "z", None, 0,
                             ["read"], 0, 10 ** 9)
    h.revoker.revoke(long["receipt_id"], 100, target_epoch=0)
    _expect_code("dr-revocation-beats-expiry",
                 lambda: h.revoker.is_live([long], 500, h.keyring),
                 "delegation-revoked")


def p_expired_still_expired():
    h = _H()
    _expect_code("dr-expired",
                 lambda: h.revoker.is_live(h.chain(), 5000, h.keyring),
                 "delegation-expired")


def p_forged_revocation():
    dr = _mod()
    h = _H()
    evil = dr.DelegationRevoker(_seed("evil"), "root")  # wrong key, same id
    forged = evil.revoke(h.root["receipt_id"], 100, target_epoch=0)
    try:
        h.revoker.verify_revocation(forged)
    except dr.RevocationError as e:
        if e.code == "delegation-signature-invalid":
            return _record("dr-forged-revocation", "HELD",
                           "forged revocation refuses signature-invalid")
        return _record("dr-forged-revocation", "BREAK",
                       "wrong code: %s" % e.code)
    return _record("dr-forged-revocation", "BREAK",
                   "forged revocation verified")


def p_idempotent_rerevoke():
    h = _H()
    r1 = h.revoker.revoke(h.root["receipt_id"], 100, target_epoch=0)
    r2 = h.revoker.revoke(h.root["receipt_id"], 200, target_epoch=0)
    if r1["revocation_id"] == r2["revocation_id"] and len(h.revoker) == 1:
        _record("dr-idempotent-rerevoke", "HELD",
                "re-revoke returns existing record, no duplicate")
    else:
        _record("dr-idempotent-rerevoke", "BREAK",
                "re-revoke duplicated or diverged")


def p_no_unrevoke_api():
    h = _H()
    for name in ("rescind", "unrevoke", "un_revoke", "remove", "delete",
                 "retract"):
        if hasattr(h.revoker, name):
            return _record("dr-no-unrevoke", "BREAK",
                           "un-revoke API exists: %s" % name)
    _record("dr-no-unrevoke", "HELD", "no un-revoke API (AttributeError)")


def p_list_overflow():
    dr = _mod()
    r = dr.DelegationRevoker(_seed("overflow"), "ov")
    # shrink the bound via a fresh instance is not possible; instead
    # exercise the real bound check by monkey-checking the constant
    # path: temporarily lower the module bound.
    old = dr.MAX_REVOCATIONS
    dr.MAX_REVOCATIONS = 2
    try:
        r.revoke("00" * 32, 1)
        r.revoke("11" * 32, 2)
        _expect_code("dr-list-overflow",
                     lambda: r.revoke("22" * 32, 3),
                     "delegation-revocation-list-full")
    finally:
        dr.MAX_REVOCATIONS = old


def p_backwards_revoked_at():
    h = _H()
    h.revoker.revoke(h.root["receipt_id"], 500, target_epoch=0)
    _expect_code("dr-backwards-revoked-at",
                 lambda: h.revoker.revoke(h.hop1["receipt_id"], 100,
                                         target_epoch=1),
                 "delegation-revocation-invalid")


def p_bad_target_shape():
    h = _H()
    _expect_code("dr-bad-target-shape",
                 lambda: h.revoker.revoke("not-hex", 100),
                 "delegation-revocation-invalid")


def p_tampered_revocation_id():
    dr = _mod()
    h = _H()
    rec = h.revoker.revoke(h.root["receipt_id"], 100, target_epoch=0)
    rec = dict(rec)
    rec["target_epoch"] = 99  # tamper post-signing
    try:
        h.revoker.verify_revocation(rec)
    except dr.RevocationError as e:
        if e.code in ("delegation-revocation-invalid",
                      "delegation-signature-invalid"):
            return _record("dr-tampered-revocation", "HELD",
                           "tampered revocation refuses coded %s" % e.code)
        return _record("dr-tampered-revocation", "BREAK",
                       "wrong code: %s" % e.code)
    return _record("dr-tampered-revocation", "BREAK", "tampered record held")


def p_broken_chain_linkage():
    h = _H()
    chain = h.chain()
    chain[2]["parent_receipt_id"] = "ff" * 32  # graft
    _expect_code("dr-broken-linkage",
                 lambda: h.revoker.is_live(chain, 500, h.keyring),
                 "delegation-revocation-invalid")


def p_forged_receipt_sig():
    h = _H()
    chain = h.chain()
    # Linkage and digest hold; only the signature is wrong (signed by a
    # key that is not the delegator's) -> delegation-signature-invalid.
    evil_seed = _seed("evil-a")
    body = {k: chain[1][k] for k in h.dr._RECEIPT_UNSIGNED_FIELDS}
    bad = dict(chain[1])
    bad["signature"] = h.ed.sign(evil_seed, h.dr._canon(body)).hex()
    chain[1] = bad
    try:
        h.revoker.is_live(chain, 500, h.keyring)
    except h.dr.RevocationError as e:
        if e.code == "delegation-signature-invalid":
            return _record("dr-forged-receipt-sig", "HELD",
                           "forged hop refuses signature-invalid")
        return _record("dr-forged-receipt-sig", "BREAK",
                       "wrong code: %s" % e.code)
    return _record("dr-forged-receipt-sig", "BREAK", "forged hop held")


def p_epoch_revoke():
    h = _H()
    r2 = h.dr.make_receipt(h.seeds["root"], "root", "x", None, 1,
                           ["read"], 0, 1000)
    recs = h.revoker.revoke_epoch(1, [r2["receipt_id"]], 700)
    if len(recs) == 1 and recs[0]["target_epoch"] == 1:
        try:
            h.revoker.is_live([r2], 500, h.keyring)
        except h.dr.RevocationError as e:
            if e.code == "delegation-revoked":
                return _record("dr-epoch-revoke", "HELD",
                               "epoch-wide revocation kills the receipt")
            return _record("dr-epoch-revoke", "BREAK",
                           "wrong code: %s" % e.code)
        return _record("dr-epoch-revoke", "BREAK", "revoked receipt live")
    return _record("dr-epoch-revoke", "BREAK", "epoch revoke malformed")


def p_offline_list_verify():
    dr = _mod()
    h = _H()
    h.revoker.revoke(h.root["receipt_id"], 100, target_epoch=0)
    h.revoker.revoke(h.hop1["receipt_id"], 200, target_epoch=1)
    exported = h.revoker.export_list()
    fresh = dr.DelegationRevoker(_seed("other"), "root")
    if fresh.verify_list(exported, pubkey_hex=h.keyring["root"]) is True:
        _record("dr-offline-list-verify", "HELD",
                "exported list verifies offline under delegator key")
    else:
        _record("dr-offline-list-verify", "BREAK", "verify_list not True")


def p_list_digest_chained():
    h = _H()
    d0 = h.revoker.list_digest()
    h.revoker.revoke(h.root["receipt_id"], 100, target_epoch=0)
    d1 = h.revoker.list_digest()
    if d0 != d1 and len(d1) == 64:
        _record("dr-list-digest", "HELD", "list digest chains entries")
    else:
        _record("dr-list-digest", "BREAK", "list digest did not advance")


def p_ed25519_contract():
    # Wave-243 lesson: verify() returns True/False; callers must check.
    from gov import ed25519
    s = _seed("contract")
    pub = ed25519.publickey(s)
    msg = b"contract-probe"
    sig = ed25519.sign(s, msg)
    good = ed25519.verify(pub, msg, sig) is True
    bad = ed25519.verify(pub, b"other", sig) is False
    if good and bad:
        _record("dr-ed25519-contract", "HELD", "verify is True / is False")
    else:
        _record("dr-ed25519-contract", "BREAK", "verify contract drift")


def p_sink_never_breaks():
    dr = _mod()
    h = _H()

    def boom(event):
        raise RuntimeError("sink exploded")

    dr.set_sink(boom)
    try:
        victim = h.dr.make_receipt(h.seeds["root"], "root", "v",
                                   None, 0, ["read"], 0, 1000)
        h.revoker.revoke(h.root["receipt_id"], 100, target_epoch=0)
        leaf = h.revoker.is_live([victim], 500, h.keyring)
        if leaf == victim["receipt_id"]:
            _record("dr-sink-never-breaks", "HELD",
                    "exploding sink does not break the module")
        else:
            _record("dr-sink-never-breaks", "BREAK", "wrong leaf")
    finally:
        dr.set_sink(None)


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    tmp = tempfile.mkdtemp(prefix="g299-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
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
    try:
        _mod()
    except ImportError:
        _record("dr-import", "BREAK", "gov.delegation_revocation absent")
        for pid, fn in [("pin-taxonomy", p_taxonomy_pin)]:
            try:
                fn()
            except ImportError:
                _record(pid, "BREAK", "module absent; pin sees 1780")
            except Exception:  # noqa: BLE001
                _record(pid, "ERROR", traceback.format_exc(limit=3))
        n_break = sum(1 for _, v, _ in _results if v == "BREAK")
        n_held = sum(1 for _, v, _ in _results if v == "HELD")
        n_err = sum(1 for _, v, _ in _results if v == "ERROR")
        print("w299_delegation_revoke: %d BREAK / %d HELD / %d ERROR"
              % (n_break, n_held, n_err))
        _coh_ok, _coh_diags = probe_lines.check_coherence(
            _results, n_break, n_held, n_err)
        if not _coh_ok:
            print("coherence-WARNING: %s" % "; ".join(_coh_diags))
        sys.exit(1)
    _safe("dr-import", p_import)
    for pid, fn in [
        ("dr-live-chain", p_live_chain),
        ("dr-use-after-revoke-direct", p_use_after_revoke_direct),
        ("dr-descendant-dies", p_descendant_dies_with_ancestor),
        ("dr-redelegation-under-revoked", p_redelegation_under_revoked_refused),
        ("dr-revocation-beats-expiry", p_revocation_beats_expiry),
        ("dr-expired", p_expired_still_expired),
        ("dr-forged-revocation", p_forged_revocation),
        ("dr-idempotent-rerevoke", p_idempotent_rerevoke),
        ("dr-no-unrevoke", p_no_unrevoke_api),
        ("dr-list-overflow", p_list_overflow),
        ("dr-backwards-revoked-at", p_backwards_revoked_at),
        ("dr-bad-target-shape", p_bad_target_shape),
        ("dr-tampered-revocation", p_tampered_revocation_id),
        ("dr-broken-linkage", p_broken_chain_linkage),
        ("dr-forged-receipt-sig", p_forged_receipt_sig),
        ("dr-epoch-revoke", p_epoch_revoke),
        ("dr-offline-list-verify", p_offline_list_verify),
        ("dr-list-digest", p_list_digest_chained),
        ("dr-ed25519-contract", p_ed25519_contract),
        ("dr-sink-never-breaks", p_sink_never_breaks),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w297_supervision_probes.py"),
                 "w297-supervision", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w296_decision_trace_probes.py"),
                 "w296-decision-trace", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w299_delegation_revoke: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
