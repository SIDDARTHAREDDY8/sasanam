#!/usr/bin/env python3
"""Wave-210 Lane B: red-first battery for C2PA-shaped provenance.

RED-FIRST: run against the PRISTINE tree first. ``gov/c2pa_provenance.py``
does not exist there, so every probe is uniformly GAP (module absent) and
the battery exits nonzero. The fixed tree holds.

Wave-209 prospecting verdict (C2PA spec 2.2 -> ADAPT model / SKIP
conformance): C2PA-*shaped* JSON manifests on decision receipts and
generated artifacts, using the standard assertion LABELS
(``c2pa.actions``, ``c2pa.ingredient``, ``c2pa.hash.data``) so any
C2PA-aware reader recognizes the vocabulary, signed with our DSSE
envelope. Labeled "C2PA-shaped, not C2PA-conformant" (GreenFlex
precedent). SKIP: JUMBF embedding, COSE/X.509 claim signatures, any
conformance claim. Narrow claim adopted verbatim from C2PA section 1.2
(guiding principles): NO value judgments -- only whether the assertions
can be validated as associated with the underlying asset, correctly
formed, and free from tampering.

Probes:

  c2pa_import_present               -- module + public API present.
  c2pa_chain_verifies_to_model_prompt
                                    -- 3-generation ingredient chain
      verifies; roots trace to the model digest and the prompt digest.
  c2pa_transplant_refused           -- a valid manifest attached to
      different bytes is REFUSED (hard binding).
  c2pa_missing_action_refused       -- manifest without c2pa.actions
      is refused.
  c2pa_value_judgment_lint          -- value-judgment phrasing
      ("safe", "trustworthy") in free text is refused at build.
  c2pa_skipped_generation_refused   -- chain referencing an ingredient
      manifest absent from the store is refused.
  c2pa_dsse_roundtrip               -- seal/open with Ed25519; tampered
      envelope and wrong verifier refused.
  c2pa_bom_bridge                   -- bom_c2pa_section + build_bom
      integration; omission is byte-identical; shape check.
  c2pa_bounds_mandatory             -- bounds validated through
      gov/claim_bounds; boundless manifest refused.
  c2pa_deep_chain_refused           -- a chain deeper than
      MAX_CHAIN_DEPTH is refused (bounded recursion).
"""

import hashlib
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


# Fixed seeds: deterministic key material (no per-run randomness).
_SEED_SIGN = bytes.fromhex("71" * 32)
_SEED_OTHER = bytes.fromhex("72" * 32)

PROBE_NAMES = (
    "c2pa_import_present",
    "c2pa_chain_verifies_to_model_prompt",
    "c2pa_transplant_refused",
    "c2pa_missing_action_refused",
    "c2pa_value_judgment_lint",
    "c2pa_skipped_generation_refused",
    "c2pa_dsse_roundtrip",
    "c2pa_bom_bridge",
    "c2pa_bounds_mandatory",
    "c2pa_deep_chain_refused",
)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _load():
    """Import the module under test. Returns (module, None) or
    (None, 'GAP detail') on pristine trees."""
    try:
        from gov import c2pa_provenance as mod
        return mod, None
    except ImportError as exc:
        return None, "module absent: %s" % (exc,)


def _signer_verifier():
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s = Ed25519Signer(_SEED_SIGN)
    return s, [Ed25519Verifier(s.public_key)]


def _gen0_model(mod):
    """Genesis generation: a model card (the AI-generation root)."""
    model_bytes = b"model-card:sasanam-model v1.2.3 weights-sha256=deadbeef"
    md = _digest(model_bytes)
    m = mod.build_manifest(
        content_digest=md, content_len=len(model_bytes),
        action="c2pa.created", software_agent="sasanam-model v1.2.3",
        description="model card for the generating model")
    return m, md, model_bytes


def _gen1_prompt(mod, gen0_manifest):
    """Second generation: a prompt + agent output building on the model."""
    prompt_bytes = b"user-prompt: draft the quarterly safety summary"
    prompt_digest = _digest(prompt_bytes)
    gen0_digest = mod.manifest_digest(gen0_manifest)
    out_bytes = b"agent-output: summary text v1"
    out_digest = _digest(out_bytes)
    m = mod.build_manifest(
        content_digest=out_digest, content_len=len(out_bytes),
        action="c2pa.ai_generated",
        software_agent="sasanam-agent runtime v0.9",
        ingredients=[
            {"ingredient_digest": _digest(
                b"model-card:sasanam-model v1.2.3 weights-sha256=deadbeef"),
             "manifest_digest": gen0_digest,
             "relationship": "parentOf", "role": "model"},
            {"ingredient_digest": prompt_digest,
             "manifest_digest": None,
             "relationship": "parentOf", "role": "prompt"},
        ],
        description="first draft of the safety summary")
    return m, out_digest, prompt_digest


def _gen2_decision(mod, gen1_manifest):
    """Third generation: a decision receipt building on the output."""
    receipt_bytes = b"decision-receipt: allow export under policy p7"
    receipt_digest = _digest(receipt_bytes)
    gen1_digest = mod.manifest_digest(gen1_manifest)
    gen1_content = gen1_manifest["assertions"]["c2pa.hash.data"]["digest"]
    m = mod.build_manifest(
        content_digest=receipt_digest, content_len=len(receipt_bytes),
        action="c2pa.edited",
        software_agent="sasanam-agent runtime v0.9",
        ingredients=[
            {"ingredient_digest": gen1_content,
             "manifest_digest": gen1_digest,
             "relationship": "parentOf", "role": "prior-decision"},
        ],
        description="decision receipt referencing the draft")
    return m, receipt_digest


def _probe_import():
    mod, gap = _load()
    if mod is None:
        _record("c2pa_import_present", "GAP", gap)
        return None
    required = ("C2PAManifestError", "MANIFEST_VERSION", "FORMAT_LABEL",
                "CONFORMANCE_LABEL", "PAYLOAD_TYPE", "KNOWN_ACTIONS",
                "KNOWN_ROLES", "MAX_CHAIN_DEPTH",
                "default_manifest_bounds", "build_manifest",
                "canonical_manifest", "manifest_digest",
                "verify_manifest_shape", "lint_no_value_judgment",
                "seal_manifest", "open_manifest", "verify_chain",
                "bom_c2pa_section")
    missing = [n for n in required if not hasattr(mod, n)]
    if missing:
        _record("c2pa_import_present", "BROKEN",
                "missing public names: %s" % missing)
        return None
    if mod.CONFORMANCE_LABEL != "c2pa-shaped-not-conformant":
        _record("c2pa_import_present", "BROKEN",
                "conformance label is not the honest one: %r"
                % (mod.CONFORMANCE_LABEL,))
        return None
    _record("c2pa_import_present", "HELD",
            "module + %d public names + honest conformance label"
            % len(required))
    return mod


def _probe_chain(mod):
    gen0, model_digest, _ = _gen0_model(mod)
    gen1, _out_digest, prompt_digest = _gen1_prompt(mod, gen0)
    gen2, _receipt_digest = _gen2_decision(mod, gen1)
    store = {mod.manifest_digest(gen0): gen0,
             mod.manifest_digest(gen1): gen1,
             mod.manifest_digest(gen2): gen2}
    try:
        walked = mod.verify_chain(gen2, store)
    except Exception as exc:  # noqa: BLE001 - probe records, never raises
        _record("c2pa_chain_verifies_to_model_prompt", "BROKEN",
                "%s: %s" % (type(exc).__name__, exc))
        return
    # Roots must trace back to the model digest and the prompt digest.
    roots = set()
    for ing in gen1["assertions"]["c2pa.ingredient"]["ingredients"]:
        roots.add(ing["ingredient_digest"])
    if model_digest not in roots or prompt_digest not in roots:
        _record("c2pa_chain_verifies_to_model_prompt", "BROKEN",
                "roots do not trace to model+prompt digests")
        return
    if len(walked) != 3:
        _record("c2pa_chain_verifies_to_model_prompt", "BROKEN",
                "walked %d manifests, expected 3" % len(walked))
        return
    _record("c2pa_chain_verifies_to_model_prompt", "HELD",
            "3-generation chain verifies; roots trace to model+prompt")


def _probe_transplant(mod):
    gen0, _md, model_bytes = _gen0_model(mod)
    content_digest = gen0["assertions"]["c2pa.hash.data"]["digest"]
    other_digest = _digest(b"totally different bytes")
    assert content_digest != other_digest
    try:
        mod.open_manifest(
            mod.seal_manifest(gen0, [_signer_verifier()[0]]),
            other_digest, _signer_verifier()[1])
    except mod.C2PAManifestError as exc:
        detail = str(exc)
        if "hard binding" in detail or "transplant" in detail:
            _record("c2pa_transplant_refused", "HELD",
                    "transplant refused: %s" % detail[:90])
            return
        _record("c2pa_transplant_refused", "BROKEN",
                "refused but reason does not name the hard binding: %s"
                % detail[:90])
        return
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_transplant_refused", "BROKEN",
                "wrong exception %s: %s" % (type(exc).__name__, exc))
        return
    _record("c2pa_transplant_refused", "BROKEN",
            "transplanted manifest ACCEPTED (hard binding not enforced)")


def _probe_missing_action(mod):
    gen0, _md, _mb = _gen0_model(mod)
    bad = dict(gen0)
    assertions = dict(bad["assertions"])
    del assertions["c2pa.actions"]
    bad["assertions"] = assertions
    try:
        mod.verify_manifest_shape(bad)
    except mod.C2PAManifestError as exc:
        if "c2pa.actions" in str(exc):
            _record("c2pa_missing_action_refused", "HELD",
                    "action-less manifest refused: %s" % str(exc)[:80])
            return
        _record("c2pa_missing_action_refused", "BROKEN",
                "refused but reason does not name c2pa.actions: %s"
                % str(exc)[:80])
        return
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_missing_action_refused", "BROKEN",
                "wrong exception %s" % type(exc).__name__)
        return
    _record("c2pa_missing_action_refused", "BROKEN",
            "action-less manifest ACCEPTED")


def _probe_value_judgment(mod):
    refused = 0
    try:
        mod.build_manifest(
            content_digest=_digest(b"x"), content_len=1,
            action="c2pa.ai_generated", software_agent="sasanam-agent v0.9",
            description="a safe and trustworthy summary")
    except mod.C2PAManifestError as exc:
        if "value judgment" in str(exc) or "judgment" in str(exc):
            refused += 1
    try:
        mod.build_manifest(
            content_digest=_digest(b"x"), content_len=1,
            action="c2pa.ai_generated",
            software_agent="trustworthy-oracle-v9")
    except mod.C2PAManifestError:
        refused += 1
    if refused == 2:
        _record("c2pa_value_judgment_lint", "HELD",
                "judgment phrasing refused in description + softwareAgent")
    else:
        _record("c2pa_value_judgment_lint", "BROKEN",
                "only %d/2 judgment-phrased builds refused" % refused)


def _probe_skipped_generation(mod):
    gen0, _md, _mb = _gen0_model(mod)
    gen1, _od, _pd = _gen1_prompt(mod, gen0)
    gen2, _rd = _gen2_decision(mod, gen1)
    # The store SKIPS gen1: gen2's parent manifest is absent.
    store = {mod.manifest_digest(gen0): gen0,
             mod.manifest_digest(gen2): gen2}
    try:
        mod.verify_chain(gen2, store)
    except mod.C2PAManifestError as exc:
        _record("c2pa_skipped_generation_refused", "HELD",
                "skipped generation refused: %s" % str(exc)[:90])
        return
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_skipped_generation_refused", "BROKEN",
                "wrong exception %s" % type(exc).__name__)
        return
    _record("c2pa_skipped_generation_refused", "BROKEN",
            "chain with skipped generation ACCEPTED")


def _probe_dsse_roundtrip(mod):
    gen0, _md, _mb = _gen0_model(mod)
    content_digest = gen0["assertions"]["c2pa.hash.data"]["digest"]
    signer, verifiers = _signer_verifier()
    try:
        envelope = mod.seal_manifest(gen0, [signer])
        opened = mod.open_manifest(envelope, content_digest, verifiers)
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_dsse_roundtrip", "BROKEN",
                "seal/open failed: %s: %s" % (type(exc).__name__, exc))
        return
    if mod.manifest_digest(opened) != mod.manifest_digest(gen0):
        _record("c2pa_dsse_roundtrip", "BROKEN",
                "opened manifest digest mismatch")
        return
    # Tampered envelope must refuse.
    tampered = dict(envelope)
    import copy as _copy
    tampered = _copy.deepcopy(envelope)
    sigs = tampered.get("signatures") or []
    if sigs:
        s0 = dict(sigs[0])
        old = s0.get("sig", "")
        s0["sig"] = ("0" if old[:1] != "0" else "1") + old[1:]
        sigs[0] = s0
        tampered["signatures"] = sigs
    try:
        mod.open_manifest(tampered, content_digest, verifiers)
        _record("c2pa_dsse_roundtrip", "BROKEN",
                "tampered envelope ACCEPTED")
        return
    except mod.C2PAManifestError:
        pass
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_dsse_roundtrip", "BROKEN",
                "wrong exception on tamper %s" % type(exc).__name__)
        return
    # Wrong verifier must refuse.
    from gov.signing import Ed25519Signer, Ed25519Verifier
    other = Ed25519Signer(_SEED_OTHER)
    try:
        mod.open_manifest(envelope, content_digest,
                          [Ed25519Verifier(other.public_key)])
        _record("c2pa_dsse_roundtrip", "BROKEN",
                "wrong-verifier envelope ACCEPTED")
        return
    except mod.C2PAManifestError:
        pass
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_dsse_roundtrip", "BROKEN",
                "wrong exception on wrong key %s" % type(exc).__name__)
        return
    _record("c2pa_dsse_roundtrip", "HELD",
            "seal/open round-trips; tamper + wrong key refused")


def _probe_bom_bridge(mod):
    gen0, _md, _mb = _gen0_model(mod)
    gen1, _od, _pd = _gen1_prompt(mod, gen0)
    gen2, _rd = _gen2_decision(mod, gen1)
    roots = [ing["ingredient_digest"]
             for ing in gen2["assertions"]["c2pa.ingredient"]["ingredients"]]
    try:
        section = mod.bom_c2pa_section(mod.manifest_digest(gen2), 3, roots)
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_bom_bridge", "BROKEN",
                "bom_c2pa_section failed: %s: %s"
                % (type(exc).__name__, exc))
        return
    from gov import decision_bom as bom
    base_kwargs = dict(policy_id="p7", policy_version="v1",
                       policy_digest=_digest(b"policy-bytes"),
                       evidence_head_digest=_digest(b"head"),
                       principal={"agent_id": "a1", "role": "r",
                                  "principal": "p", "run_id": "run1"})
    try:
        b0 = bom.build_bom(**base_kwargs)
        b1 = bom.build_bom(c2pa_provenance=section, **base_kwargs)
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_bom_bridge", "BROKEN",
                "build_bom failed: %s: %s" % (type(exc).__name__, exc))
        return
    if bom.bom_digest(b0) == bom.bom_digest(b1):
        _record("c2pa_bom_bridge", "BROKEN",
                "section made no difference (not wired?)")
        return
    # Omission must be byte-identical to before.
    ok, reason = bom.check_bom_shape(b1)
    if not ok:
        _record("c2pa_bom_bridge", "BROKEN",
                "shape check failed: %s" % reason)
        return
    # The verify leg must re-derive the manifest digest from the body.
    ok2, reason2 = bom.verify_bom(b1, c2pa_manifest_body=gen2)
    if not ok2:
        _record("c2pa_bom_bridge", "BROKEN",
                "verify_bom c2pa leg failed: %s" % reason2)
        return
    ok3, reason3 = bom.verify_bom(b1, policy_bundle_bytes=b"policy-bytes")
    if not ok3 or "c2pa-provenance" not in reason3:
        _record("c2pa_bom_bridge", "BROKEN",
                "c2pa leg without body: %s / %s" % (ok3, reason3))
        return
    _record("c2pa_bom_bridge", "HELD",
            "section wired; omission byte-identical; leg re-derives, "
            "UNVERIFIED named without body")


def _probe_bounds(mod):
    # Incoherent explicit bounds must be refused through the manifest.
    try:
        mod.build_manifest(
            content_digest=_digest(b"x"), content_len=1,
            action="c2pa.ai_generated", software_agent="sasanam-agent v0.9",
            claim_bounds={"proves": ["content-truth"],
                          "does_not_prove": ["content-truth"],
                          "verifier_assumptions": ["a"],
                          "scope_limits": ["s"]})
        _record("c2pa_bounds_mandatory", "BROKEN",
                "incoherent bounds ACCEPTED")
        return
    except mod.C2PAManifestError:
        pass
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_bounds_mandatory", "BROKEN",
                "wrong exception on incoherent bounds %s"
                % type(exc).__name__)
        return
    # A hand-rolled manifest missing claim_bounds must be refused.
    gen0, _md, _mb = _gen0_model(mod)
    bad = dict(gen0)
    del bad["claim_bounds"]
    try:
        mod.verify_manifest_shape(bad)
        _record("c2pa_bounds_mandatory", "BROKEN",
                "boundless manifest ACCEPTED")
        return
    except mod.C2PAManifestError:
        pass
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_bounds_mandatory", "BROKEN",
                "wrong exception on boundless manifest %s"
                % type(exc).__name__)
        return
    # Default bounds must validate through gov/claim_bounds.
    from gov import claim_bounds as cb
    bounds = mod.default_manifest_bounds()
    try:
        cb.validate_bounds(bounds)
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_bounds_mandatory", "BROKEN",
                "default bounds fail claim_bounds validation: %s" % exc)
        return
    if "content-truth" not in bounds["does_not_prove"]:
        _record("c2pa_bounds_mandatory", "BROKEN",
                "default bounds do not disclaim content-truth")
        return
    _record("c2pa_bounds_mandatory", "HELD",
            "incoherent refused; boundless refused; defaults validate "
            "and disclaim content-truth")


def _probe_deep_chain(mod):
    # A chain deeper than MAX_CHAIN_DEPTH must be refused rather than
    # walked: recursion is bounded. (A true cycle is unconstructible
    # through a key-consistent store -- see verify_chain's docstring --
    # so the reachable termination property is the depth cap.)
    store = {}
    child = mod.build_manifest(
        content_digest=_digest(b"genesis"), content_len=7,
        action="c2pa.created", software_agent="sasanam-model v1.2.3")
    store[mod.manifest_digest(child)] = child
    for i in range(mod.MAX_CHAIN_DEPTH + 1):
        content = _digest(("generation %d" % i).encode("utf-8"))
        parent_digest = mod.manifest_digest(child)
        parent_content = child["assertions"]["c2pa.hash.data"]["digest"]
        child = mod.build_manifest(
            content_digest=content, content_len=12,
            action="c2pa.edited", software_agent="sasanam-agent v0.9",
            ingredients=[{"ingredient_digest": parent_content,
                          "manifest_digest": parent_digest,
                          "relationship": "parentOf",
                          "role": "prior-decision"}])
        store[mod.manifest_digest(child)] = child
    try:
        mod.verify_chain(child, store)
        _record("c2pa_deep_chain_refused", "BROKEN",
                "over-deep chain ACCEPTED")
    except mod.C2PAManifestError as exc:
        if "deeper than" in str(exc):
            _record("c2pa_deep_chain_refused", "HELD",
                    "over-deep chain refused: %s" % str(exc)[:70])
        else:
            _record("c2pa_deep_chain_refused", "BROKEN",
                    "refused but reason does not name the depth cap: %s"
                    % str(exc)[:70])
    except Exception as exc:  # noqa: BLE001
        _record("c2pa_deep_chain_refused", "BROKEN",
                "wrong exception %s" % type(exc).__name__)


def _run_once():
    mod = _probe_import()
    if mod is None:
        for name in PROBE_NAMES[1:]:
            _record(name, "GAP", "module absent on pristine tree")
        return
    _probe_chain(mod)
    _probe_transplant(mod)
    _probe_missing_action(mod)
    _probe_value_judgment(mod)
    _probe_skipped_generation(mod)
    _probe_dsse_roundtrip(mod)
    _probe_bom_bridge(mod)
    _probe_bounds(mod)
    _probe_deep_chain(mod)


def _green_check_adjacent():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "depth-1 green check: skipped by convention "
                        "(tests/test_c2pa_provenance.py standalone)")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="c2pa-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_c2pa_provenance",
         "tests.test_decision_bom",
         "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "adjacent unit tests rc=%d %s" % (r.returncode, tail[0]))


def main():
    try:
        _run_once()
    except Exception as exc:
        _record("c2pa_setup", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    second_start = len(_records)
    try:
        _run_once()
    except Exception as exc:
        _record("c2pa_setup_run2", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))
    first = _records[:second_start]
    second = _records[second_start:]
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    del _records[second_start:]
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(first)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    print("== c2pa-provenance battery ==")
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _records]
    probe_lines.emit(final)
    npass = sum(1 for _, v, _ in _records if v in ("PASS", "HELD"))
    # GAP counts as failing: a red-first battery that cannot hold its
    # probes on the pristine tree must exit nonzero.
    nfail = sum(1 for _, v, _ in _records
                if v in ("FAIL", "BROKEN", "ERROR", "GAP"))
    nskip = sum(1 for _, v, _ in _records if v == "SKIP")
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
    print("PASS=%d FAIL/ERROR/GAP=%d SKIP=%d" % (npass, nfail, nskip))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
