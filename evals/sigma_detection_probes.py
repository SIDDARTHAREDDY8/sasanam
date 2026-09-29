"""Red-first battery for auditor-side Sigma detection (wave-198).

Auditor-side, read-only, offline: the pack signature is verified
before any rule compiles; a tampered rule is refused loudly (it must
never silently blind the auditor); the 4 rules fire on the labeled
attack streams and stay quiet on the normal ones; world-model
assumption violations produce loud warnings instead of silent passes.

Modes:
  --red-phase : gap demonstration. On a pristine tree (no
      gov.audit_detect) the import fails -> GAP SHOWN. On the fixed
      tree it runs the auditor's own red-team: attacks against the
      auditor (tampered rule, unbound rule, forged pack, expired pack,
      unknown correlator) must all fail loudly -> HELD.
  (default)   : closure battery: attack streams fire, normal streams
      don't, assumption violations warn loudly, malformed events are
      skipped with warnings.

Deterministic x2; identical under `env -u GOV_DEPLOYMENT_MODE`;
GOV_SKIP_GREEN honored; green check is depth-1
(tests/test_audit_detect only, child env GOV_SKIP_GREEN=1);
`os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")` at module
level per the wave-95 lesson.

$0 spend, synthetic/local deterministic only. No network.
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")  # noqa: E402

import copy
import glob
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TREE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sigma_detection_streams import build_streams  # noqa: E402

RULE_SHORT = {
    "7c4a1d02-3f8e-4b6a-9c1d-5e6f7a8b9c0d": "impossible_travel",
    "8d5b2e13-4a9f-4c7b-8d2e-6f7a8b9c0d1e": "approval_velocity",
    "9e6c3f24-5b0a-4d8c-9e3f-7a8b9c0d1e2f": "key_ceremony_window",
    "af7d4025-6c1b-4e9d-af40-8b9c0d1e2f30": "revoked_key_signature",
}

_SEED = bytes.fromhex("41" * 32)
_ISSUED = "2026-09-01T00:00:00+00:00"
_FUTURE = "2030-01-01T00:00:00+00:00"
# A pack that was valid at mint time but expired before verification:
# mint allows it (expiry after issue); verify must refuse it.
_EXPIRED = "2026-09-15T00:00:00+00:00"


def _import_product():
    """Import the product modules; on a pristine tree this raises
    ImportError, which the red phase reports as the demonstrated gap."""
    from gov import audit_detect as ad  # noqa: E402
    from gov import rule_pack as rp  # noqa: E402
    from gov.keyset import new_keyset, keyset_signer_for_version  # noqa: E402
    return ad, rp, new_keyset, keyset_signer_for_version


def _sha256_pin(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _World:
    """A temp rules dir + a signed pack binding it (test keyset)."""

    def __init__(self, ad, rp, new_keyset, keyset_signer_for_version,
                 expires_at=_FUTURE, threshold=1):
        self.ad = ad
        self.rp = rp
        self.dir = tempfile.mkdtemp(prefix="sigma-pack-")
        for src in sorted(glob.glob(os.path.join(
                TREE, "detection_rules", "*.yml"))):
            shutil.copy(src, self.dir)
        self.keyset, _ = new_keyset(_SEED,
                                    purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        self.signers = [keyset_signer_for_version(self.keyset, 1, _SEED)]
        self.pack_doc = self._mint(expires_at, threshold)
        with open(os.path.join(self.dir, ad.RULE_PACK_FILENAME), "w",
                   encoding="utf-8") as f:
            json.dump(self.pack_doc, f, indent=2, sort_keys=True)

    def _mint(self, expires_at, threshold):
        from gov.sigma_subset import parse_rule_text as _prt  # noqa: E402
        rules = {}
        for fname in sorted(os.listdir(self.dir)):
            if not fname.endswith(".yml"):
                continue
            raw = open(os.path.join(self.dir, fname), "rb").read()
            # rule id comes from the YAML, not the filename
            rid = str(_prt(raw.decode("utf-8"))["id"])
            rules[rid] = _sha256_pin(raw)
        return self.rp.mint_rule_pack(
            self.keyset, self.signers, rules=rules, pack_version=1,
            issued_at=_ISSUED, expires_at=expires_at, threshold=threshold)

    def detect(self, entries, **kw):
        pack_doc = json.load(open(os.path.join(
            self.dir, self.ad.RULE_PACK_FILENAME), encoding="utf-8"))
        return self.ad.detect_on_entries(entries, self.dir, pack_doc,
                                         self.keyset, **kw)

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def _red_probes():
    """Auditor red-team: attacks against the auditor must fail loudly."""
    try:
        ad, rp, new_keyset, ksfv = _import_product()
    except ImportError as e:
        return [("red: auditor detection absent (module missing)",
                 "GAP SHOWN", str(e))]
    out = []

    def check(name, fn, want_code):
        w = _World(ad, rp, new_keyset, ksfv)
        try:
            try:
                fn(w)
            except ad.DetectionError as e:
                ok = (e.code == want_code)
                out.append((name, "HELD" if ok else "FAIL",
                            "code=%s want=%s" % (e.code, want_code)))
                return
            except Exception as e:  # noqa: BLE001
                out.append((name, "FAIL", "wrong exc: %r" % (e,)))
                return
            out.append((name, "FAIL", "no refusal raised"))
        finally:
            w.cleanup()

    def tamper_rule(w):
        p = os.path.join(w.dir, "approval_velocity.yml")
        raw = open(p, "rb").read().replace(b"> 25", b"> 2500", 1)
        open(p, "wb").write(raw)
        w.detect([])

    def unbound_rule(w):
        p = os.path.join(w.dir, "zz_evil.yml")
        open(p, "w").write(
            "title: evil\nid: 00000000-0000-0000-0000-000000000000\n"
            "detection:\n    s:\n        type: identity\n"
            "    condition: s\n")
        w.detect([])

    def forge_pack_sig(w):
        p = os.path.join(w.dir, w.ad.RULE_PACK_FILENAME)
        doc = json.load(open(p, encoding="utf-8"))
        doc["signatures"][0]["sig"] = "00" * 64
        json.dump(doc, open(p, "w", encoding="utf-8"))
        w.detect([])

    def missing_rule_file(w):
        rid = next(iter(w.pack_doc["rules"]))
        fname = [f for f in os.listdir(w.dir) if f.endswith(".yml")][0]
        os.unlink(os.path.join(w.dir, fname))
        w.detect([])

    def unknown_correlator(w):
        p = os.path.join(w.dir, "impossible_travel.yml")
        raw = open(p, "rb").read().replace(b"type: impossible_travel",
                                           b"type: near", 1)
        # re-mint so the digest matches: the refusal must come from the
        # correlator type, not the tamper check
        open(p, "wb").write(raw)
        w.pack_doc = w._mint(_FUTURE, 1)
        json.dump(w.pack_doc, open(
            os.path.join(w.dir, w.ad.RULE_PACK_FILENAME), "w",
            encoding="utf-8"), indent=2, sort_keys=True)
        w.detect(build_streams(seed=196)[6]["events"])

    check("red: tampered rule file refused", tamper_rule, "rule-tampered")
    check("red: unbound rule file refused", unbound_rule, "rule-unbound")
    check("red: forged pack signature refused", forge_pack_sig,
          "pack-invalid")
    check("red: missing bound rule file refused", missing_rule_file,
          "rule-missing")
    check("red: unknown correlation type refused", unknown_correlator,
          "unsupported-correlation")

    # Expired pack: separate world (mint-time expiry in the past).
    w = _World(ad, rp, new_keyset, ksfv, expires_at=_EXPIRED)
    try:
        try:
            w.detect([])
            out.append(("red: expired pack refused", "FAIL",
                        "no refusal raised"))
        except ad.DetectionError as e:
            out.append(("red: expired pack refused",
                        "HELD" if e.code == "pack-invalid" else "FAIL",
                        "code=%s" % (e.code,)))
    finally:
        w.cleanup()
    return out


def _green_check():
    """Depth-1: adjacent unit module only, child env GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="sigma-green-")
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_audit_detect", "-v"],
            capture_output=True, text=True, timeout=600, cwd=TREE,
            env=env)
        tail = (p.stdout + p.stderr)[-1500:]
        print("green check (tests/test_audit_detect):\n%s" % tail)
        return p.returncode == 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    red_phase = "--red-phase" in argv
    if red_phase:
        try:
            _import_product()
            have_product = True
        except ImportError:
            have_product = False
        if not have_product:
            print("== sigma detection probes (RED-PHASE: gap demonstration) ==")
            print("GAP SHOWN: gov.audit_detect absent -- "
                  "the auditor has no detection capability")
            return 0
        results = _red_probes()
    else:
        results = []
        for name, fn in _green_probe_fns():
            try:
                status, detail = fn()
            except AssertionError as e:
                status, detail = "FAIL", "assertion: %s" % (e,)
            except Exception as e:  # noqa: BLE001
                status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
            results.append((name, status, detail))
    # Determinism: run twice, compare (name, status, detail).
    # Detail is included (not just status) so the check is
    # signature-level: a nondeterministic alert payload would fail
    # here, not just a flipped verdict.
    if red_phase:
        second = _red_probes()
    else:
        second = []
        for name, fn in _green_probe_fns():
            try:
                status, detail = fn()
            except Exception as e:  # noqa: BLE001
                status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
            second.append((name, status, detail))
    det_ok = ([(n, s, d) for n, s, d in results]
              == [(n, s, d) for n, s, d in second])
    width = max(len(n) for n, _, _ in results)
    print("== sigma detection probes (%s) =="
          % ("RED-PHASE: auditor red-team" if red_phase else
             "GREEN-PHASE: closure battery"))
    for n, s, d in results:
        print("%-*s %s %s" % (width, n, s, d))
    print("deterministic x2: %s" % det_ok)
    n_fail = sum(1 for _, s, _ in results if s not in ("PASS", "HELD"))
    if not red_phase:
        print("--- green check ---")
        green_ok = _green_check()
    else:
        green_ok = True
    all_ok = (n_fail == 0) and det_ok and green_ok
    print("RESULT: %s" % ("ALL PASS" if all_ok else "FAILURES PRESENT"))
    return 0 if all_ok else 1


def _green_probe_fns():
    """Green probes as (name, thunk) pairs for the x2 harness."""
    try:
        ad, rp, new_keyset, ksfv = _import_product()
    except ImportError as e:
        return [("green: product import",
                 lambda: ("FAIL", "missing: %s" % (e,)))]

    def contingency():
        w = _World(ad, rp, new_keyset, ksfv)
        try:
            streams = build_streams(seed=196)
            table = {s: {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
                     for s in RULE_SHORT.values()}
            for st in streams:
                rep = w.detect(st["events"])
                fired = {}
                for a in rep.alerts:
                    fired.setdefault(RULE_SHORT[a["rule_id"]], []).append(a)
                for short in RULE_SHORT.values():
                    f = bool(fired.get(short))
                    x = bool(st["expect"].get(short))
                    if f and x:
                        table[short]["TP"] += 1
                    elif f and not x:
                        table[short]["FP"] += 1
                    elif not f and x:
                        table[short]["FN"] += 1
                    else:
                        table[short]["TN"] += 1
            bad = {s: r for s, r in table.items()
                   if not (r["TP"] == 1 and r["FP"] == 0
                           and r["FN"] == 0 and r["TN"] == 9)}
            assert not bad, "contingency off: %s" % (bad,)
            return "PASS", ""
        finally:
            w.cleanup()

    def assumption_warns():
        w = _World(ad, rp, new_keyset, ksfv)
        try:
            st = [s for s in build_streams(seed=196)
                  if s["name"] == "N1_steady_ops"][0]
            stripped = copy.deepcopy(st["events"])
            for e in stripped:
                e.pop("ceremony_window_end", None)
            rep = w.detect(stripped)
            warns = [x for x in rep.warnings
                     if x.get("code") == "assumption-violated"
                     and (x.get("rule_id") or "").startswith("9e6c3f24")]
            assert warns, "no assumption warning for blinded rule"
            blind = [a for a in rep.alerts
                     if a["rule_id"].startswith("9e6c3f24")]
            assert not blind, "blinded rule fired: %d" % len(blind)
            return "PASS", "%d warnings" % len(warns)
        finally:
            w.cleanup()

    def bad_ts_skipped():
        w = _World(ad, rp, new_keyset, ksfv)
        try:
            st = [s for s in build_streams(seed=196)
                  if s["name"] == "N1_steady_ops"][0]
            evs = copy.deepcopy(st["events"][:20])
            evs.append({"seq": 999, "ts": "not-a-time",
                        "type": "identity"})
            rep = w.detect(evs)
            assert rep.n_skipped == 1, "skipped=%d" % rep.n_skipped
            assert any(x.get("code") == "events-skipped"
                       for x in rep.warnings), "no skip warning"
            return "PASS", ""
        finally:
            w.cleanup()

    def unknown_geo_warns():
        w = _World(ad, rp, new_keyset, ksfv)
        try:
            st = [s for s in build_streams(seed=196)
                  if s["name"] == "N1_steady_ops"][0]
            evs = copy.deepcopy(st["events"][:10])
            base = evs[0]["ts"]
            evs.append({"seq": 1001, "ts": base, "type": "identity",
                        "agent_id": "agent-zz", "geo": "Atlantis"})
            evs.append({"seq": 1002, "ts": base, "type": "identity",
                        "agent_id": "agent-zz", "geo": "Lagos"})
            rep = w.detect(evs)
            assert any(x.get("code") == "geo-unresolvable"
                       for x in rep.warnings), "no geo warning"
            return "PASS", ""
        finally:
            w.cleanup()

    def report_shape():
        w = _World(ad, rp, new_keyset, ksfv)
        try:
            st = [s for s in build_streams(seed=196)
                  if s["name"] == "N1_steady_ops"][0]
            rep = w.detect(st["events"])
            d = rep.to_dict()
            assert d["report_version"] == ad.REPORT_VERSION
            assert d["pack_version"] == 1
            assert len(d["pack_signing_kids"]) == 1
            assert isinstance(rep.to_json(), str)
            items = rep.inbox_items()
            assert all("provenance" in i for i in items)
            return "PASS", ""
        finally:
            w.cleanup()

    def correlator_assumptions_evaluated():
        # The Req-6 fix: a stream with no identity events must warn
        # loudly for the correlator-driven travel rule, not pass
        # silently.
        w = _World(ad, rp, new_keyset, ksfv)
        try:
            evs = [{"seq": 1, "ts": "2026-09-20T10:00:00+00:00",
                    "type": "decision", "verdict": "allow",
                    "agent_id": "a1"}]
            rep = w.detect(evs)
            warns = [x for x in rep.warnings
                     if x.get("code") == "assumption-violated"
                     and (x.get("rule_id") or "").startswith("7c4a1d02")]
            assert warns, "no assumption warning for blinded correlator"
            blind = [a for a in rep.alerts
                     if a["rule_id"].startswith("7c4a1d02")]
            assert not blind, "blinded correlator fired: %d" % len(blind)
            return "PASS", "%d warnings" % len(warns)
        finally:
            w.cleanup()

    return [
        ("green: per-rule contingency 1/0/0/9", contingency),
        ("green: assumption violation warns loudly", assumption_warns),
        ("green: correlator assumptions evaluated", correlator_assumptions_evaluated),
        ("green: bad-ts skipped with warning", bad_ts_skipped),
        ("green: unknown geo warns, no crash", unknown_geo_warns),
        ("green: report serializes + inbox provenance", report_shape),
    ]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
