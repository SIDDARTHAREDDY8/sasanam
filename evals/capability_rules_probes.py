#!/usr/bin/env python3
"""Wave-200: red-first battery for the capa-style capability rules.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.capability_rules -- absent there -- so the pristine run is
uniformly ERROR (missing public seams), and the fixed tree holds.
The battery compiles rule packs from text (no repo fixture
dependence for the attack shapes) and uses the shipped
capability_rules/ pack for the migration-equivalence probes.
Probes:

  cr_compile_strict_top_not      -- top-level not refused at load.
  cr_compile_strict_unknown      -- unknown statement node refused.
  cr_compile_strict_bad_target   -- match to unknown namespace refused.
  cr_compile_strict_dup          -- duplicate namespace refused.
  cr_compile_strict_cycle        -- dependency cycle refused.
  cr_compile_strict_leaf_bundle  -- bare leaf in bundle rule refused
                                   at COMPILE (not deferred to eval).
  cr_migration_equiv            -- the 40 primitive rules detect
                                   byte-identically to the flat lint
                                   on the fixture corpus.
  cr_composite_cred_egress      -- egress + secrets in one module ->
                                   credential-bearing egress fires.
  cr_composite_quiet            -- egress alone does NOT fire it.
  cr_mixed_trust_cross_module   -- secrets in A + egress in B ->
                                   mixed-trust-exfil fires.
  cr_mixed_trust_same_module    -- same-module secrets+egress does
                                   NOT fire mixed-trust-exfil.
  cr_diff_escalation           -- diff_namespaces reports the new
                                   egress namespace on upgrade.
  cr_evaluator_fail_closed     -- a simulated evaluator bug under
                                   strict=True raises; the manifest
                                   seam refuses the load (never a
                                   vacuous pass).
  cr_manifest_seam             -- verify_skill_manifest with a rule
                                   pack: undeclared egress fails;
                                   granted egress passes.
"""

import glob
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO_ROOT)

_records = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records PASS/FAIL/HELD/BROKEN/GAP/RED/GREEN/ERROR/SKIP; the
# canonical emission vocabulary is BREAK/HELD/ERROR/SKIP, mapped
# red-first (PASS/GREEN->HELD, FAIL/BROKEN/GAP/RED->BREAK). Probe
# logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


def _setup():
    from gov import capability_rules as cr
    from gov import capability_manifests as cm
    return cr, cm


def _pack(cr, *docs):
    files = {}
    for i, doc in enumerate(docs):
        files["r%d.yml" % i] = doc.encode("utf-8")
    return cr.load_pack_files(files)


_ONE_RULE = """\
rules:
  -
    meta:
      name: "egress socket"
      namespace: capability/egress/socket
      scopes:
        static: module
      capability_tags: [capability/egress]
      label: "import socket"
    features:
      pattern: "\\\\bimport\\\\s+socket\\\\b"
"""


def _shipping_pack(cr):
    files = {}
    base = os.path.join(REPO_ROOT, "capability_rules")
    for path in sorted(glob.glob(os.path.join(base, "*.yml"))):
        with open(path, "rb") as f:
            files[os.path.basename(path)] = f.read()
    return cr.load_pack_files(files)


def _expect_rule_error(cr, *docs):
    try:
        _pack(cr, *docs)
        return ("FAIL", "malformed pack compiled")
    except cr.RuleError as e:
        return ("PASS", "refused: %s" % str(e)[:70])


def p_compile_strict_top_not():
    cr, _cm = _setup()
    return _expect_rule_error(cr, """\
rules:
  -
    meta:
      name: bad
      namespace: capability/x/bad
      scopes:
        static: module
      capability_tags: []
    features:
      not:
        pattern: "x"
""")


def p_compile_strict_unknown():
    cr, _cm = _setup()
    return _expect_rule_error(cr, """\
rules:
  -
    meta:
      name: bad
      namespace: capability/egress/bad
      scopes:
        static: module
      capability_tags: []
    features:
      frobnicate: "x"
""")


def p_compile_strict_bad_target():
    cr, _cm = _setup()
    return _expect_rule_error(cr, """\
rules:
  -
    meta:
      name: bad
      namespace: capability/egress/bad
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/nonexistent/rule
""")


def p_compile_strict_dup():
    cr, _cm = _setup()
    return _expect_rule_error(cr, _ONE_RULE, _ONE_RULE)


def p_compile_strict_cycle():
    cr, _cm = _setup()
    return _expect_rule_error(cr, """\
rules:
  -
    meta:
      name: a
      namespace: capability/x/a
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/x/b
  -
    meta:
      name: b
      namespace: capability/x/b
      scopes:
        static: module
      capability_tags: []
    features:
      match: capability/x/a
""")


def p_compile_strict_leaf_bundle():
    cr, _cm = _setup()
    return _expect_rule_error(cr, """\
rules:
  -
    meta:
      name: bad
      namespace: capability/x/bad
      scopes:
        static: bundle
      capability_tags: []
    features:
      pattern: "x"
""")


def p_migration_equiv():
    cr, cm = _setup()
    full = _shipping_pack(cr)
    prim_files = {}
    base = os.path.join(REPO_ROOT, "capability_rules")
    for path in sorted(glob.glob(os.path.join(base, "*.yml"))):
        name = os.path.basename(path)
        if name in ("composite.yml", "composition.yml"):
            continue
        with open(path, "rb") as f:
            prim_files[name] = f.read()
    prim = cr.load_pack_files(prim_files)
    assert len(prim.rules) == 40, "want 40 primitives, got %d" % len(
        prim.rules)
    assert len(full.rules) == 42, "want 42 rules, got %d" % len(
        full.rules)
    fixtures = {
        "clean": b"def add(a, b):\n    return a + b\n",
        "egress": b"import socket\ns = socket.create_connection(('h', 80))\n",
        "env": b"import os\ntok = os.environ['API_TOKEN']\n",
        "tool": b"@tool\ndef tool_search(q):\n    pass\n",
        "exec": b"import subprocess\nsubprocess.run(['ls'])\n",
        "fs": b"open('/etc/passwd').read()\n",
        "secrets": b"import getpass\np = getpass.getpass('pw: ')\n",
        "multi": b"import socket, subprocess, os\n"
                 b"open('/tmp/x').write(os.environ['K'])\n",
    }
    for name, content in fixtures.items():
        flat = cm.detect_capabilities(content)
        ruled = cr.detect_capabilities(content, prim)
        if ruled != flat:
            return ("FAIL", "migration differs on %r" % name)
    return ("PASS", "40 primitives byte-identical on 8 fixtures")


def p_composite_cred_egress():
    cr, _cm = _setup()
    pack = _shipping_pack(cr)
    ns, _ev = cr.evaluate_module(
        pack, b"import socket\nimport getpass\n"
              b"s = socket.create_connection(('h', 80))\n")
    ok = "capability/egress/credential-bearing" in ns
    return ("PASS" if ok else "FAIL",
            "credential-bearing in %d namespaces" % len(ns))


def p_composite_quiet():
    cr, _cm = _setup()
    pack = _shipping_pack(cr)
    ns, _ev = cr.evaluate_module(
        pack, b"import socket\ns = socket.socket()\n")
    ok = "capability/egress/credential-bearing" not in ns
    return ("PASS" if ok else "FAIL", "no false composite")


def p_mixed_trust_cross_module():
    cr, _cm = _setup()
    pack = _shipping_pack(cr)
    bns, _res = cr.evaluate_bundle(pack, {
        "a": b"import getpass\np = getpass.getpass()\n",
        "b": b"import socket\n"
             b"s = socket.create_connection(('h', 80))\n",
    })
    ok = "capability/composition/mixed-trust-exfil" in bns
    return ("PASS" if ok else "FAIL", "mixed-trust fired")


def p_mixed_trust_same_module():
    cr, _cm = _setup()
    pack = _shipping_pack(cr)
    bns, _res = cr.evaluate_bundle(pack, {
        "a": b"import socket\nimport getpass\n"
             b"s = socket.create_connection(('h', 80))\n",
    })
    ok = "capability/composition/mixed-trust-exfil" not in bns
    return ("PASS" if ok else "FAIL",
            "same-module correctly quiet")


def p_diff_escalation():
    cr, _cm = _setup()
    pack = _shipping_pack(cr)
    d = cr.diff_namespaces(b"def f():\n    return 1\n",
                           b"import socket\n", pack)
    ok = ("capability/egress/prim-00" in d["added"]
          and d["removed"] == [])
    return ("PASS" if ok else "FAIL", "added=%s" % d["added"][:3])


def p_evaluator_fail_closed():
    cr, cm = _setup()
    import gov.capability_rules as crmod
    pack = _shipping_pack(cr)
    content = b"import socket\n"
    real = crmod._eval_stmt
    crmod._eval_stmt = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom"))
    try:
        try:
            crmod.detect_capabilities(content, pack, strict=True)
            return ("FAIL", "strict=True did not raise")
        except cr.RuleError:
            pass
        # The load-time seam must refuse, never vacuous-pass.
        from gov import ed25519 as _ed
        seed = b"\x41" * 32
        manifest = cm.make_manifest(
            "s", content, capabilities={"egress": ["import socket"]},
            kid="k1", seed=seed)
        store = cm.ManifestStore(
            keys={"k1": _ed.publickey(seed)},
            manifests={"s": manifest}, capability_pack=pack)
        ok, detail = cm.verify_skill_manifest("s", content, store)
        if ok or detail != "manifest-capability-eval-failed":
            return ("FAIL", "load did not refuse: %r" % detail)
        return ("PASS", "strict raises; load refuses closed")
    finally:
        crmod._eval_stmt = real


def p_manifest_seam():
    cr, cm = _setup()
    from gov import ed25519 as _ed
    pack = _shipping_pack(cr)
    content = (b"import socket\nimport getpass\n"
               b"s = socket.create_connection(('h', 80))\n")
    seed = b"\x41" * 32

    def store_for(caps):
        manifest = cm.make_manifest("s", content,
                                    capabilities=caps, kid="k1",
                                    seed=seed)
        return cm.ManifestStore(
            keys={"k1": _ed.publickey(seed)},
            manifests={"s": manifest}, capability_pack=pack)

    ok1, d1 = cm.verify_skill_manifest(
        "s", content, store_for({"secrets": ["getpass"]}))
    ok2, d2 = cm.verify_skill_manifest(
        "s", content,
        store_for({"egress": ["import socket"],
                   "secrets": ["getpass"]}))
    ok = (not ok1 and "capability-drift" in d1 and ok2)
    return ("PASS" if ok else "FAIL",
            "undeclared-egress=%s granted-egress=%s" % (d1, d2))


PROBES = [
    p_compile_strict_top_not,
    p_compile_strict_unknown,
    p_compile_strict_bad_target,
    p_compile_strict_dup,
    p_compile_strict_cycle,
    p_compile_strict_leaf_bundle,
    p_migration_equiv,
    p_composite_cred_egress,
    p_composite_quiet,
    p_mixed_trust_cross_module,
    p_mixed_trust_same_module,
    p_diff_escalation,
    p_evaluator_fail_closed,
    p_manifest_seam,
]


def _run_once():
    _records.clear()
    for probe in PROBES:
        try:
            verdict, detail = probe()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, detail = "ERROR", "%s: %s" % (
                type(e).__name__, e)
        _record(probe.__name__, verdict, detail)
    return list(_records)


def _green_check_adjacent():
    """Depth-1 green check: adjacent unit tests, GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "tests/test_capability_rules.py standalone")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="cr-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_capability_rules", "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "tests.test_capability_rules rc=%d %s"
            % (r.returncode, tail[0]))


def main():
    first = _run_once()
    second = _run_once()  # determinism: identical verdicts twice
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(PROBES)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    npass = sum(1 for _, v, _ in _records if v == "PASS")
    nfail = sum(1 for _, v, _ in _records if v in ("FAIL", "ERROR"))
    skipped = sum(1 for _, v, _ in _records if v == "SKIP")
    print("== capability-rules battery ==")
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _records]
    probe_lines.emit(final)
    brk = sum(1 for _, v, _ in final if v == "BREAK")
    held = sum(1 for _, v, _ in final if v == "HELD")
    err = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s"
              % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    print("PASS=%d FAIL/ERROR=%d SKIP=%d" % (npass, nfail, skipped))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
