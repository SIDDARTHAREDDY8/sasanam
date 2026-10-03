"""Wave-292 F356 closure battery (Lane 1): execute_rebuild self-validation.

Base: wave-291 merge commit 255478fc50beaf723eed0c4f3824d1a13f621535
(verified via git rev-parse HEAD after clone).

F356 (LOW, OPEN at base): gov/evidence_provenance.py::execute_rebuild is a
public seam whose docstring claims execution "trusts nothing and still bounds
every operation", but it never runs check_rebuild_recipe (unlike
verify_rebuild/_rederive_and_compare). Two facets:
  (a) malformed recipes ({}, {"inputs": []}, {"inputs": ["u"], "steps": "x"})
      escape as a bare KeyError (code=None) -- F351/F344/F342 class;
  (b) a step with an unknown op silently passes the bytes through unchanged
      instead of refusing coded provenance-rebuild-transform-unknown.
Only reachable by a caller that skips validation (all in-repo callers
validate), hence LOW. Close-when: execute_rebuild self-validates (or maps
malformed inputs to coded provenance-rebuild-* refusals); probes
f356-keyerror + f356-unknown-op flip to HELD; adjacent batteries stay green.

Expected base reading: 2 BREAK (f356-keyerror, f356-unknown-op), rest HELD.
Expected post-fix: 0 BREAK.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g292-f356 && TMPDIR=/var/tmp/g292-f356 \\
    ~/workspace/.gov-venv/bin/python evals/w292_f356_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g292-f356b \\
    ~/workspace/.gov-venv/bin/python evals/w292_f356_probes.py
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

# Wave-291 merge: pin 1710 -> 1715 (+5 delegation-*).
TAXONOMY_PIN = 1857  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    silent pass."""
    try:
        fn()
    except Exception:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected exception: %s"
                % traceback.format_exc(limit=3).replace("\n", " | "))
        return
    if not any(p == pid or p.startswith(pid + "-")
               for p, _, _ in _results):
        _record(pid, "ERROR", "probe recorded nothing")


def _literals():
    # Wave-260 lesson: assert on source literals in decision_codes.py,
    # not len(TAXONOMY) (dict dedup hides duplicate inserts).
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
    _record("pin-taxonomy", "HELD", "1857/1857/0 sorted")


_MATS = {"material/a": b"A" * 32, "material/b": b"B" * 48}


def _ep():
    from gov import evidence_provenance as ep
    return ep


def _valid_recipe():
    return {
        "recipe_format": "sasanam-rebuild/1",
        "inputs": ["material/a", "material/b"],
        "steps": [
            {"op": "concat", "order": ["material/a", "material/b"]},
            {"op": "sha256"},
        ],
    }


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
    _record(pid, "BREAK", note + ": no refusal raised")


# ---------------------------------------------------------------------------
# F356 facets (BREAK on base)
# ---------------------------------------------------------------------------

def p_f356_keyerror():
    """F356 facet (a): malformed recipes must refuse LOUD with a coded
    provenance-rebuild-invalid from execute_rebuild itself, never a bare
    KeyError (code=None)."""
    ep = _ep()
    for bad in ({}, {"inputs": []}, {"inputs": ["u"], "steps": "x"}):
        try:
            ep.execute_rebuild(bad, {})
        except KeyError:
            return _record("f356-keyerror", "BREAK",
                           "execute_rebuild(%r) escapes as KeyError "
                           "(code=None)" % (bad,))
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) == "provenance-rebuild-invalid":
                continue
            return _record("f356-keyerror", "BREAK",
                           "execute_rebuild(%r) escapes uncoded: %r"
                           % (bad, e))
        return _record("f356-keyerror", "BREAK",
                       "execute_rebuild(%r) did not refuse" % (bad,))
    _record("f356-keyerror", "HELD",
            "malformed recipes refuse coded provenance-rebuild-invalid")


def p_f356_unknown_op():
    """F356 facet (b): a step with an unknown op must refuse coded
    provenance-rebuild-transform-unknown from execute_rebuild itself,
    never silently pass bytes through."""
    ep = _ep()
    recipe = {"recipe_format": "sasanam-rebuild/1",
              "inputs": ["material/a"],
              "steps": [{"op": "weaponize"}, {"op": "sha256"}]}
    try:
        out = ep.execute_rebuild(recipe, {"material/a": b"data"})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) == \
                "provenance-rebuild-transform-unknown":
            return _record("f356-unknown-op", "HELD",
                           "unknown op refused coded in direct execution")
        return _record("f356-unknown-op", "BREAK",
                       "unknown op escapes uncoded: %r" % (e,))
    _record("f356-unknown-op", "BREAK",
            "unknown op silently passed bytes through: %r" % (out,))


# ---------------------------------------------------------------------------
# Shape coverage around the self-validation (HELD on base already)
# ---------------------------------------------------------------------------

def p_f356_nondict_recipe():
    _expect_code("f356-nondict-recipe", "provenance-rebuild-invalid",
                 "non-dict recipe refuses coded",
                 _ep().execute_rebuild, None, {})


def p_f356_wrong_format():
    recipe = _valid_recipe()
    recipe["recipe_format"] = "sasanam-rebuild/99"
    _expect_code("f356-wrong-format", "provenance-rebuild-invalid",
                 "wrong recipe_format refuses coded",
                 _ep().execute_rebuild, recipe, dict(_MATS))


def p_f356_nonterminal():
    recipe = _valid_recipe()
    recipe["steps"] = [{"op": "concat",
                        "order": ["material/a", "material/b"]}]
    _expect_code("f356-nonterminal", "provenance-rebuild-invalid",
                 "missing terminal sha256 refuses coded",
                 _ep().execute_rebuild, recipe, dict(_MATS))


def p_f356_undeclared_input():
    recipe = _valid_recipe()
    recipe["inputs"] = ["material/a", "material/z"]
    _expect_code("f356-undeclared-input", "provenance-rebuild-invalid",
                 "input not among supplied materials refuses coded",
                 _ep().execute_rebuild, recipe, dict(_MATS))


def p_f356_missing_material_bytes():
    recipe = _valid_recipe()
    mats = {"material/a": b"A" * 32}
    _expect_code("f356-missing-material-bytes", "provenance-rebuild-invalid",
                 "recipe input absent from material_bytes refuses coded",
                 _ep().execute_rebuild, recipe, mats)


def p_f356_nondict_materials():
    _expect_code("f356-nondict-materials", "provenance-rebuild-invalid",
                 "non-dict material bytes refuse coded",
                 _ep().execute_rebuild, _valid_recipe(), None)


# ---------------------------------------------------------------------------
# Positive controls (self-validation must not break legitimate execution)
# ---------------------------------------------------------------------------

def p_f356_valid_still_works():
    """The self-validation must not change the happy path: a valid
    recipe over its materials still executes and reproduces the
    independent sha256 digest."""
    ep = _ep()
    try:
        out = ep.execute_rebuild(_valid_recipe(), dict(_MATS))
    except Exception as e:  # noqa: BLE001
        return _record("f356-valid-still-works", "BREAK",
                       "valid recipe refused after self-validation: %r"
                       % (e,))
    want = hashlib.sha256(b"A" * 32 + b"B" * 48).digest()
    if out != want:
        return _record("f356-valid-still-works", "BREAK",
                       "valid recipe produced the wrong digest")
    _record("f356-valid-still-works", "HELD",
            "valid recipe executes; digest matches independent sha256")


def p_f356_verify_rebuild_path():
    """The in-repo caller path (verify_rebuild over a sealed envelope)
    still succeeds after the change -- the double validation is a
    no-op for already-valid recipes."""
    from gov import ed25519
    ep = _ep()
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    bid = "build.example.com/ci"
    policy = ep.BuilderPolicy("auditor-pin-1", {bid: pub})
    recipe = _valid_recipe()
    artifact = hashlib.sha256(b"A" * 32 + b"B" * 48).hexdigest()
    materials = [{"uri": u,
                  "digest": hashlib.sha256(b).hexdigest(),
                  "completeness": "verified"}
                 for u, b in _MATS.items()]
    claim = ep.make_provenance_claim(bid, "key-1", artifact, materials,
                                     issued_at=1700000000,
                                     rebuild_recipe=recipe)
    env = ep.seal_provenance(claim, seed)
    try:
        derived = ep.verify_rebuild(env, policy, dict(_MATS))
    except Exception as e:  # noqa: BLE001
        return _record("f356-verify-rebuild-path", "BREAK",
                       "verify_rebuild broke: %r" % (e,))
    if derived != artifact:
        return _record("f356-verify-rebuild-path", "BREAK",
                       "derived %s != artifact %s" % (derived, artifact))
    _record("f356-verify-rebuild-path", "HELD",
            "verify_rebuild path unchanged by self-validation")


# ---------------------------------------------------------------------------
# Green checks (depth-1; subprocess with GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w292-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=900,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("repin-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("repin-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("repin-" + label, "BREAK",
                "%s: %d BREAK, expected %d"
                % (rel, nbreak, expected_breaks))


_W291_REDTEAM_EXPECTED_BREAKS = 0  # set by main() from the facet results


def _green_checks():
    if SKIP_GREEN:
        return
    _run_battery("evals/w290_rebuild_probes.py", 0, "w290-rebuild")
    _run_battery("evals/w291_redteam_probes.py",
                 _W291_REDTEAM_EXPECTED_BREAKS, "w291-redteam")


def main():
    global _W291_REDTEAM_EXPECTED_BREAKS
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("f356-keyerror", p_f356_keyerror)
    _safe("f356-unknown-op", p_f356_unknown_op)
    # Red-first: on the base tree F356 is genuinely open, so the
    # w291 redteam re-pin shows 2 BREAK; after the fix it shows 0.
    nfacet = sum(1 for p, v, _ in _results
                 if p in ("f356-keyerror", "f356-unknown-op")
                 and v == "BREAK")
    _W291_REDTEAM_EXPECTED_BREAKS = 2 if nfacet else 0
    _safe("f356-nondict-recipe", p_f356_nondict_recipe)
    _safe("f356-wrong-format", p_f356_wrong_format)
    _safe("f356-nonterminal", p_f356_nonterminal)
    _safe("f356-undeclared-input", p_f356_undeclared_input)
    _safe("f356-missing-material-bytes", p_f356_missing_material_bytes)
    _safe("f356-nondict-materials", p_f356_nondict_materials)
    _safe("f356-valid-still-works", p_f356_valid_still_works)
    _safe("f356-verify-rebuild-path", p_f356_verify_rebuild_path)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w292_f356: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
