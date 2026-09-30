"""Wave-248 skill-admission probes (red-first).

W248-2: build ``gov/skill_admission.py`` -- an in-toto-inspired skill
admission gate (pattern adaptation; NO in-toto code vendored,
Apache-2.0). A skill bundle ships a signed layout (steps: fetch, scan,
...); each step ships signed link metadata (what it consumed /
produced, what command it ran). The registry admits only when:

1. the layout signature verifies under the registry-known layout
   authority key,
2. the layout authority is a DIFFERENT principal from every step
   signer (structural signer != executor/authorizer separation --
   in-toto's record-then-sign-in-one-process weakness, refused here),
3. every step has a link whose signature verifies under the step's
   layout-authorized signer key,
4. the link's signer is exactly the layout-authorized signer for that
   step,
5. the link's command matches the layout's authorized command EXACTLY
   (in-toto only WARNS on command mismatch; we HARD-REFUSE), and
6. the link's materials/products satisfy the step's artifact rules
   (REQUIRE/MATCH fail closed on absent materials; terminal DISALLOW
   refuses leftovers -- a step that produced nothing cannot pass a
   REQUIRE products rule, the F193 vacuous-proof answer).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import hashlib
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_SA = False
_sa = None
try:
    from gov import skill_admission as _sa
    HAVE_SA = all(
        hasattr(_sa, n) for n in (
            "make_layout", "make_link", "admit", "SkillAdmissionError"))
except ImportError:
    _sa = None

HAVE_ED = False
try:
    from gov import ed25519 as _ed
    HAVE_ED = True
except ImportError:
    _ed = None

HAVE_ALL = HAVE_SA and HAVE_ED

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

LAYOUT_ID = "skill/weather-v1"

_D1 = hashlib.sha256(b"skill-src-bytes").hexdigest()
_D2 = hashlib.sha256(b"skill-tar-bytes").hexdigest()
_D3 = hashlib.sha256(b"scan-report-bytes").hexdigest()

_FETCH_RULES = [("REQUIRE", "skill-src.zip"),
                ("MATCH", "skill.tar.gz", _D2),
                ("DISALLOW",)]
_SCAN_RULES = [("REQUIRE", "skill.tar.gz"),
               ("MATCH", "scan-report.json", _D3),
               ("DISALLOW",)]

_FETCH_CMD = ["fetch-skill", "--src", "skill-src.zip"]
_SCAN_CMD = ["scan-skill", "--in", "skill.tar.gz"]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _keys():
    authority_seed = _ed.generate_seed()
    fetch_seed = _ed.generate_seed()
    scan_seed = _ed.generate_seed()
    return {
        "authority_seed": authority_seed,
        "authority_pub": _ed.publickey(authority_seed).hex(),
        "fetch_seed": fetch_seed,
        "fetch_pub": _ed.publickey(fetch_seed).hex(),
        "scan_seed": scan_seed,
        "scan_pub": _ed.publickey(scan_seed).hex(),
    }


def _good_layout(keys):
    return _sa.make_layout(
        LAYOUT_ID,
        steps=[
            {"name": "fetch", "command": list(_FETCH_CMD),
             "signer_pub": keys["fetch_pub"], "rules": _FETCH_RULES},
            {"name": "scan", "command": list(_SCAN_CMD),
             "signer_pub": keys["scan_pub"], "rules": _SCAN_RULES},
        ],
        layout_seed=keys["authority_seed"])


def _good_links(keys):
    fetch = _sa.make_link(
        LAYOUT_ID, "fetch", list(_FETCH_CMD),
        materials={"skill-src.zip": _D1},
        products={"skill.tar.gz": _D2},
        signer_seed=keys["fetch_seed"])
    scan = _sa.make_link(
        LAYOUT_ID, "scan", list(_SCAN_CMD),
        materials={"skill.tar.gz": _D2},
        products={"scan-report.json": _D3},
        signer_seed=keys["scan_seed"])
    return [fetch, scan]


def _probe_happy_path_admits():
    keys = _keys()
    verdict = _sa.admit(_good_layout(keys), _good_links(keys),
                        keys["authority_pub"])
    assert verdict["admitted"] is True, verdict
    assert verdict["code"] is None, verdict
    return "valid layout + links admit with evidence"


def _probe_forged_layout_signature():
    keys = _keys()
    layout = _good_layout(keys)
    sig = layout["signature"]
    forged = ("0" if sig[0] != "0" else "1") + sig[1:]
    layout["signature"] = forged
    verdict = _sa.admit(layout, _good_links(keys), keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == \
        "skill-admission-layout-signature-invalid", verdict
    return "forged layout signature refused"


def _probe_missing_materials_vacuous():
    # F193 vacuous-proof class: a step that produced nothing cannot
    # pass a REQUIRE products rule.
    keys = _keys()
    empty = _sa.make_link(
        LAYOUT_ID, "fetch", list(_FETCH_CMD),
        materials={"skill-src.zip": _D1}, products={},
        signer_seed=keys["fetch_seed"])
    verdict = _sa.admit(_good_layout(keys), [empty], keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == \
        "skill-admission-artifact-rule-violated", verdict
    return "vacuous step (no products) refused by REQUIRE rule"


def _probe_tampered_digest():
    keys = _keys()
    evil_digest = hashlib.sha256(b"trojan-bytes").hexdigest()
    tampered = _sa.make_link(
        LAYOUT_ID, "fetch", list(_FETCH_CMD),
        materials={"skill-src.zip": _D1},
        products={"skill.tar.gz": evil_digest},
        signer_seed=keys["fetch_seed"])
    verdict = _sa.admit(_good_layout(keys), [tampered],
                        keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == \
        "skill-admission-artifact-rule-violated", verdict
    return "MATCH digest mismatch refused"


def _probe_command_substitution():
    # in-toto only warns on command mismatch; we hard-refuse.
    keys = _keys()
    evil_cmd = ["fetch-skill", "--src", "skill-src.zip",
                "--also", "evil.example"]
    evil = _sa.make_link(
        LAYOUT_ID, "fetch", evil_cmd,
        materials={"skill-src.zip": _D1},
        products={"skill.tar.gz": _D2},
        signer_seed=keys["fetch_seed"])
    verdict = _sa.admit(_good_layout(keys), [evil], keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == "skill-admission-command-mismatch", verdict
    return "command substitution hard-refused (not a warning)"


def _probe_wrong_signer():
    keys = _keys()
    rogue_seed = _ed.generate_seed()
    rogue = _sa.make_link(
        LAYOUT_ID, "fetch", list(_FETCH_CMD),
        materials={"skill-src.zip": _D1},
        products={"skill.tar.gz": _D2},
        signer_seed=rogue_seed)
    verdict = _sa.admit(_good_layout(keys), [rogue], keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] in (
        "skill-admission-unauthorized-signer",
        "skill-admission-link-signature-invalid"), verdict
    return "unauthorized signer refused"


def _probe_self_authorized_layout():
    # Structural signer != authority separation: the layout authority
    # key must differ from every step signer key.
    keys = _keys()
    layout = _sa.make_layout(
        LAYOUT_ID,
        steps=[{"name": "fetch", "command": list(_FETCH_CMD),
                "signer_pub": keys["authority_pub"],
                "rules": _FETCH_RULES}],
        layout_seed=keys["authority_seed"])
    link = _sa.make_link(
        LAYOUT_ID, "fetch", list(_FETCH_CMD),
        materials={"skill-src.zip": _D1},
        products={"skill.tar.gz": _D2},
        signer_seed=keys["authority_seed"])
    verdict = _sa.admit(layout, [link], keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == \
        "skill-admission-authority-is-step-signer", verdict
    return "self-authorized layout refused structurally"


def _probe_missing_link():
    keys = _keys()
    verdict = _sa.admit(_good_layout(keys), [], keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == "skill-admission-link-missing", verdict
    return "absent link for a layout step refused"


def _probe_forged_link_signature():
    keys = _keys()
    links = _good_links(keys)
    sig = links[0]["signature"]
    links[0]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    verdict = _sa.admit(_good_layout(keys), links, keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == \
        "skill-admission-link-signature-invalid", verdict
    return "forged link signature refused"


def _probe_disallow_leftover():
    keys = _keys()
    extra = hashlib.sha256(b"extra-bytes").hexdigest()
    bloated = _sa.make_link(
        LAYOUT_ID, "fetch", list(_FETCH_CMD),
        materials={"skill-src.zip": _D1},
        products={"skill.tar.gz": _D2, "bonus.bin": extra},
        signer_seed=keys["fetch_seed"])
    verdict = _sa.admit(_good_layout(keys), [bloated],
                        keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == \
        "skill-admission-artifact-rule-violated", verdict
    return "unconsumed leftover product refused by terminal DISALLOW"


def _probe_malformed_layout():
    keys = _keys()
    verdict = _sa.admit({"nope": True}, [], keys["authority_pub"])
    assert verdict["admitted"] is False, verdict
    assert verdict["code"] == "skill-admission-layout-malformed", verdict
    return "malformed layout refused before any crypto"


def _probe_codes_in_taxonomy():
    from gov import decision_codes
    for code in (
            "skill-admission-layout-malformed",
            "skill-admission-layout-signature-invalid",
            "skill-admission-authority-is-step-signer",
            "skill-admission-link-missing",
            "skill-admission-link-malformed",
            "skill-admission-link-signature-invalid",
            "skill-admission-unauthorized-signer",
            "skill-admission-command-mismatch",
            "skill-admission-artifact-rule-violated"):
        assert code in decision_codes.TAXONOMY, code
    return "all 9 refusal codes are registered taxonomy codes"


def _probe_evidence_names_principals():
    keys = _keys()
    verdict = _sa.admit(_good_layout(keys), _good_links(keys),
                        keys["authority_pub"])
    assert verdict["admitted"] is True, verdict
    evidence = verdict["evidence"]
    assert evidence["authority_pub"] == keys["authority_pub"], evidence
    step_signers = {s["signer_pub"] for s in evidence["steps"]}
    assert keys["fetch_pub"] in step_signers, evidence
    assert keys["scan_pub"] in step_signers, evidence
    assert evidence["authority_pub"] not in step_signers, evidence
    return "admission evidence names authority and step signers"


_PROBES = {
    "happy-path-admits": (_probe_happy_path_admits, HAVE_ALL),
    "forged-layout-signature": (_probe_forged_layout_signature, HAVE_ALL),
    "missing-materials-vacuous": (_probe_missing_materials_vacuous,
                                  HAVE_ALL),
    "tampered-digest": (_probe_tampered_digest, HAVE_ALL),
    "command-substitution": (_probe_command_substitution, HAVE_ALL),
    "wrong-signer": (_probe_wrong_signer, HAVE_ALL),
    "self-authorized-layout": (_probe_self_authorized_layout, HAVE_ALL),
    "missing-link": (_probe_missing_link, HAVE_ALL),
    "forged-link-signature": (_probe_forged_link_signature, HAVE_ALL),
    "disallow-leftover": (_probe_disallow_leftover, HAVE_ALL),
    "malformed-layout": (_probe_malformed_layout, HAVE_ALL),
    "codes-in-taxonomy": (_probe_codes_in_taxonomy, HAVE_ALL),
    "evidence-names-principals": (_probe_evidence_names_principals,
                                  HAVE_ALL),
}

PROBE_NAMES = list(_PROBES)


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1.
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    for mod in ("tests.test_skill_admission",):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            cwd=root, env=env, capture_output=True, text=True, timeout=300)
        notes.append("unit %s rc=%d" % (mod, proc.returncode))
        if proc.returncode != 0:
            notes.append("unit tail: %s" % (proc.stderr[-500:],))
    return notes


def main():
    print("wave-248 skill_admission probes (module present: %s)" % (HAVE_SA,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-28s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
