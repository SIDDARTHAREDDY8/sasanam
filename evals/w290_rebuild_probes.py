"""Wave-290 lane 6 battery: re-derivation receipts (oss-rebuild pattern).

"Evidence carries the PROCEDURE to reproduce the proof": provenance
claims may carry a bounded, auditable rebuild_recipe; the verifier
re-executes it over verifier-supplied material bytes and the derived
digest must equal the claimed artifact digest.

Base: wave-289 push eb08e95ae9eb6862d689f9eede5489d0177a5ceb.
On the pristine base every defect probe BREAKs (re-derivation seams
absent). After the build every probe must HELD: happy-path
re-derivation, coded refusal on digest mismatch (critical), recipe
substitution breaking the builder signature, coded refusals for
missing/invalid/unknown-transform recipes, byte budgets, and a
rebuild receipt feeding the trust_vector verify/validate split.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-289 merge: pin 1706; wave-290 lane 6: pin 1706 -> 1710
# (+4 provenance-rebuild-* codes).
TAXONOMY_PIN = 1863  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


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
    for code in ("provenance-rebuild-invalid",
                 "provenance-rebuild-mismatch",
                 "provenance-rebuild-missing",
                 "provenance-rebuild-transform-unknown"):
        if code not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing literal %r" % (code,))
    _record("pin-taxonomy", "HELD", "1863/1863/0 sorted, rebuild codes")


# -- fixtures ------------------------------------------------------------

SEAMS = ("check_rebuild_recipe", "execute_rebuild", "verify_rebuild",
         "rebuild_receipt")


def _seams(pid):
    """Import gov.evidence_provenance with the rebuild seams.

    On the pristine base the seams are absent: record a BREAK (the
    red-first reading) instead of erroring.
    """
    try:
        from gov import evidence_provenance as ep
    except ImportError as e:
        _record(pid, "BREAK", "module absent on base: %s" % (e,))
        return None
    missing = [n for n in SEAMS if not callable(getattr(ep, n, None))]
    try:
        import inspect
        sig = inspect.signature(ep.make_provenance_claim)
        if "rebuild_recipe" not in sig.parameters:
            missing.append("make_provenance_claim(rebuild_recipe=)")
        sig = inspect.signature(ep.verify_provenance)
        if "require_rebuild" not in sig.parameters:
            missing.append("verify_provenance(require_rebuild=)")
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "fixture introspection failed: %r" % (e,))
        return None
    if missing:
        _record(pid, "BREAK",
                "rebuild seams absent on base: %s" % (missing,))
        return None
    return ep


_MATS = {"material/a": b"A" * 32, "material/b": b"B" * 48}


def _builder(ep, rebuild_required=()):
    from gov import ed25519
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    bid = "build.example.com/ci"
    policy = ep.BuilderPolicy("auditor-pin-1", {bid: pub},
                              rebuild_required=rebuild_required)
    return seed, "key-1", bid, policy


def _recipe(order=("material/a", "material/b")):
    return {
        "recipe_format": "sasanam-rebuild/1",
        "inputs": ["material/a", "material/b"],
        "steps": [
            {"op": "concat", "order": list(order)},
            {"op": "sha256"},
        ],
    }


def _claim_sealed(ep, seed, keyid, bid, recipe=_recipe(), issued=1700000000):
    order = recipe["steps"][0]["order"] if recipe else ()
    artifact = hashlib.sha256(b"".join(_MATS[u] for u in order)
                              ).hexdigest() if recipe else "ab" * 32
    materials = [{"uri": u, "digest": hashlib.sha256(b).hexdigest(),
                  "completeness": "verified"}
                 for u, b in _MATS.items()]
    claim = ep.make_provenance_claim(bid, keyid, artifact, materials,
                                     issued_at=issued,
                                     rebuild_recipe=recipe)
    return ep.seal_provenance(claim, seed), artifact


def _expect_code(pid, want, note, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == want:
            _record(pid, "HELD", note + " (coded %s)" % (want,))
        else:
            _record(pid, "BREAK",
                    "wrong/uncoded refusal: want %s, got %r (%r)"
                    % (want, code, e))
        return
    _record(pid, "BREAK", "succeeded but must refuse %s" % (want,))


# -- attack probes -------------------------------------------------------

def p_rebuild_happy_path():
    pid = "rebuild-happy-path"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    try:
        derived = ep.verify_rebuild(env, policy, dict(_MATS))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "valid re-derivation refused: %r" % (e,))
    if derived != artifact:
        return _record(pid, "BREAK",
                       "derived %s != artifact %s" % (derived, artifact))
    _record(pid, "HELD", "re-derivation reproduces the artifact digest")


def p_rebuild_digest_mismatch():
    pid = "rebuild-digest-mismatch"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    env, _artifact = _claim_sealed(ep, seed, keyid, bid)
    tampered = dict(_MATS)
    tampered["material/a"] = b"X" * 32
    _expect_code(pid, "provenance-rebuild-mismatch",
                 "tampered material bytes refuse coded",
                 ep.verify_rebuild, env, policy, tampered)


def p_rebuild_recipe_substitution():
    pid = "rebuild-recipe-substitution"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    env, _artifact = _claim_sealed(ep, seed, keyid, bid)
    evil = {
        "recipe_format": "sasanam-rebuild/1",
        "inputs": ["material/a"],
        "steps": [
            {"op": "concat", "order": ["material/a"]},
            {"op": "sha256"},
        ],
    }
    env["provenance"]["rebuild_recipe"] = evil
    _expect_code(pid, "provenance-signature-invalid",
                 "post-seal recipe substitution breaks the signature",
                 ep.verify_rebuild, env, policy, dict(_MATS))


def p_rebuild_missing_kwarg():
    pid = "rebuild-missing-kwarg"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    env, _artifact = _claim_sealed(ep, seed, keyid, bid, recipe=None)
    _expect_code(pid, "provenance-rebuild-missing",
                 "strict verifier without a recipe refuses coded",
                 ep.verify_provenance, env, policy, require_rebuild=True,
                 material_bytes=dict(_MATS))


def p_rebuild_missing_policy():
    pid = "rebuild-missing-policy"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(
        ep, rebuild_required=["build.example.com/ci"])
    env, _artifact = _claim_sealed(ep, seed, keyid, bid, recipe=None)
    _expect_code(pid, "provenance-rebuild-missing",
                 "strict builder policy demands re-derivation without kwarg",
                 ep.verify_provenance, env, policy)


def p_rebuild_optional_by_default():
    pid = "rebuild-optional-by-default"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    env, _artifact = _claim_sealed(ep, seed, keyid, bid, recipe=None)
    try:
        ok = ep.verify_provenance(env, policy)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "re-derivation became a silent default: %r" % (e,))
    if ok is not True:
        return _record(pid, "BREAK", "verify_provenance did not return True")
    _record(pid, "HELD",
            "re-derivation stays opt-in; admission posture unchanged")


def _hand_sealed(ep, seed, bid, keyid, recipe):
    from gov import ed25519
    mats = [{"uri": u, "digest": hashlib.sha256(b).hexdigest(),
             "completeness": "verified"} for u, b in _MATS.items()]
    claim = {"claim_format": "sasanam-provenance/1",
             "builder": {"id": bid, "keyid": keyid},
             "artifact": {"digest": "ab" * 32, "kind": "evidence-bundle"},
             "materials": mats, "invocation": {}, "issued_at": 1700000000,
             "rebuild_recipe": recipe}
    sig = ed25519.sign(seed, ep._canonical(claim)).hex()
    return {"provenance": claim, "signature": sig, "keyid": keyid}


def p_rebuild_undeclared_input():
    pid = "rebuild-undeclared-input"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    evil = _recipe()
    evil["inputs"] = ["material/a", "material/ghost"]
    evil["steps"][0]["order"] = ["material/a", "material/ghost"]
    try:
        ep.make_provenance_claim(bid, keyid, "ab" * 32,
                                 [{"uri": "material/a", "digest": "cd" * 32,
                                   "completeness": "verified"}],
                                 rebuild_recipe=evil)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "provenance-rebuild-invalid":
            _record(pid, "HELD",
                    "undeclared recipe input refused at registration")
            return
        return _record(pid, "BREAK", "wrong refusal: %r" % (e,))
    _record(pid, "BREAK", "undeclared recipe input accepted at build")
    env = _hand_sealed(ep, seed, bid, keyid, evil)
    _expect_code(pid + "-verify", "provenance-rebuild-invalid",
                 "undeclared recipe input refused at verify",
                 ep.verify_provenance, env, policy)


def p_rebuild_transform_unknown():
    pid = "rebuild-transform-unknown"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    evil = _recipe()
    evil["steps"] = [{"op": "eval", "code": "import os"}, {"op": "sha256"}]
    env = _hand_sealed(ep, seed, bid, keyid, evil)
    _expect_code(pid, "provenance-rebuild-transform-unknown",
                 "unlisted transform refuses coded (recipes describe, "
                 "never execute)", ep.verify_provenance, env, policy)


def p_rebuild_oversized_header():
    pid = "rebuild-oversized-header"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    evil = _recipe()
    evil["steps"] = [
        {"op": "concat", "order": ["material/a", "material/b"]},
        {"op": "prefix", "bytes": "ff" * (ep.MAX_REBUILD_HEADER_BYTES + 1)},
        {"op": "sha256"},
    ]
    try:
        ep.make_provenance_claim(bid, keyid, "ab" * 32,
                                 [{"uri": "material/a", "digest": "cd" * 32,
                                   "completeness": "verified"},
                                  {"uri": "material/b", "digest": "ef" * 32,
                                   "completeness": "verified"}],
                                 rebuild_recipe=evil)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == "provenance-rebuild-invalid":
            _record(pid, "HELD",
                    "oversized header literal refused at registration")
            return
        return _record(pid, "BREAK", "wrong refusal: %r" % (e,))
    _record(pid, "BREAK", "oversized header literal accepted")


def p_rebuild_no_terminal_hash():
    pid = "rebuild-no-terminal-hash"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    evil = _recipe()
    evil["steps"] = [{"op": "concat",
                      "order": ["material/a", "material/b"]}]
    env = _hand_sealed(ep, seed, bid, keyid, evil)
    _expect_code(pid, "provenance-rebuild-invalid",
                 "recipe without terminal sha256 refuses (cannot "
                 "re-derive)", ep.verify_provenance, env, policy)


def p_rebuild_grammar_composition():
    pid = "rebuild-grammar-composition"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    recipe = {
        "recipe_format": "sasanam-rebuild/1",
        "inputs": ["material/a", "material/b"],
        "steps": [
            {"op": "concat", "order": ["material/b", "material/a"]},
            {"op": "slice", "offset": 8, "length": 32},
            {"op": "prefix", "bytes": "deadbeef"},
            {"op": "hex"},
            {"op": "sha256"},
        ],
    }
    pre = b"".join([_MATS["material/b"], _MATS["material/a"]])[8:40]
    pre = bytes.fromhex("deadbeef") + pre
    artifact = hashlib.sha256(pre.hex().encode("ascii")).hexdigest()
    mats = [{"uri": u, "digest": hashlib.sha256(b).hexdigest(),
             "completeness": "verified"} for u, b in _MATS.items()]
    claim = ep.make_provenance_claim(bid, keyid, artifact, mats,
                                     issued_at=1700000000,
                                     rebuild_recipe=recipe)
    env = ep.seal_provenance(claim, seed)
    try:
        derived = ep.verify_rebuild(env, policy, dict(_MATS))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "grammar composition refused: %r" % (e,))
    if derived != artifact:
        return _record(pid, "BREAK", "composition derived wrong digest")
    _record(pid, "HELD",
            "slice/prefix/hex composition re-derives exactly")


def p_rebuild_input_budget():
    pid = "rebuild-input-budget"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    env, _artifact = _claim_sealed(ep, seed, keyid, bid)
    old = ep.MAX_REBUILD_INPUT_BYTES
    ep.MAX_REBUILD_INPUT_BYTES = 16
    try:
        _expect_code(pid, "provenance-rebuild-invalid",
                     "input byte budget enforced fail-closed",
                     ep.verify_rebuild, env, policy, dict(_MATS))
    finally:
        ep.MAX_REBUILD_INPUT_BYTES = old


def p_rebuild_receipt_seam():
    pid = "rebuild-receipt-seam"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    try:
        receipt = ep.rebuild_receipt(env, policy, dict(_MATS))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK", "receipt build refused: %r" % (e,))
    if receipt.get("scheme_id") != "provenance-rebuild/v1":
        return _record(pid, "BREAK", "receipt scheme id wrong")
    end = receipt.get("endorsement")
    if not isinstance(end, dict):
        return _record(pid, "BREAK", "receipt has no endorsement dict")
    for field in ("builder_id", "builder_policy", "artifact_digest",
                  "derived_digest", "recipe_digest"):
        if not end.get(field):
            return _record(pid, "BREAK",
                           "receipt endorsement missing %r" % (field,))
    if end["derived_digest"] != artifact:
        return _record(pid, "BREAK", "receipt derived digest wrong")
    if receipt.get("claim_digest") != ep.claim_digest(env["provenance"]):
        return _record(pid, "BREAK", "receipt claim digest wrong")
    _record(pid, "HELD",
            "receipt carries the trust_vector verify/validate seam")


def p_rebuild_anchor_gated():
    pid = "rebuild-anchor-gated"
    ep = _seams(pid)
    if ep is None:
        return
    seed, keyid, bid, policy = _builder(ep)
    from gov import evidence_anchor as ea
    from gov import ed25519
    env, artifact = _claim_sealed(ep, seed, keyid, bid)
    root = tempfile.mkdtemp(prefix="w290-rebuild-")
    log = ea.TransparencyLog(root, origin="unit-log.example",
                             signer_keyid="op-1",
                             signer_seed=ed25519.generate_seed())
    tampered = dict(_MATS)
    tampered["material/a"] = b"X" * 32
    before = len(log.entries()) if hasattr(log, "entries") else None
    _expect_code(pid, "provenance-rebuild-mismatch",
                 "gated anchor refuses on re-derivation mismatch",
                 ep.anchor_bundle_gated, log, artifact, env, policy,
                 require_rebuild=True, material_bytes=tampered)
    if before is not None:
        try:
            if len(log.entries()) != before:
                _record(pid + "-log", "BREAK",
                        "refused bundle left a log entry")
                return
        except Exception as e:  # noqa: BLE001
            _record(pid + "-log", "ERROR", "%r" % (e,))
            return
    root2 = tempfile.mkdtemp(prefix="w290-rebuild-ok-")
    log2 = ea.TransparencyLog(root2, origin="unit-log.example",
                              signer_keyid="op-1",
                              signer_seed=ed25519.generate_seed())
    try:
        receipt = ep.anchor_bundle_gated(log2, artifact, env, policy,
                                         require_rebuild=True,
                                         material_bytes=dict(_MATS))
    except Exception as e:  # noqa: BLE001
        return _record(pid + "-happy", "BREAK",
                       "gated anchor with valid rebuild refused: %r" % (e,))
    if receipt.get("bundle_digest") != artifact:
        return _record(pid + "-happy", "BREAK", "anchor receipt wrong")
    _record(pid + "-happy", "HELD",
            "gated anchor sequences after successful re-derivation")


# -- green checks (depth-1) ----------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w289_redteam_probes.py",
        "evals/w287_provenance_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            _record(os.path.basename(rel), "HELD",
                    "green check: battery absent on this tree, skipped")
            continue
        d = tempfile.mkdtemp(prefix="w290-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR",
                    "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    probes = [p_taxonomy_pin, p_rebuild_happy_path,
              p_rebuild_digest_mismatch, p_rebuild_recipe_substitution,
              p_rebuild_missing_kwarg, p_rebuild_missing_policy,
              p_rebuild_optional_by_default, p_rebuild_undeclared_input,
              p_rebuild_transform_unknown, p_rebuild_oversized_header,
              p_rebuild_no_terminal_hash, p_rebuild_grammar_composition,
              p_rebuild_input_budget, p_rebuild_receipt_seam,
              p_rebuild_anchor_gated]
    for probe in probes:
        try:
            probe()
        except Exception as e:  # noqa: BLE001
            _record(probe.__name__, "ERROR", "unexpected: %r" % (e,))
    _green_checks()
    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("%-42s %-6s %s" % (pid, verdict, note))
    print("w290_rebuild: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
