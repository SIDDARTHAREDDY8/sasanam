"""Wave-289 lane 1 red-first battery: F343 closure (trust_vector).

F343 (LOW): RULE_OPERATOR_TRUST affirms on a producer_id string match;
`compile_policy` requires `trust_anchors` to map producer id -> key id,
implying key-pinned trust, but `_grade_dimension` only checks
`evidence.producer_id in policy.trust_anchors` -- no signature exists
anywhere in the evidence model. Key rotation changes nothing; a claimant
needs no key at all to be "affirmed".

Close-when (FINDINGS.md): (1) operator-trust requires key-based producer
verification, or the dimension is renamed/re-documented to a
name-allowlist with the key-id requirement removed from the policy
contract; (2) probe `f343-operator-trust-name-only` flips to HELD;
(3) adjacent batteries stay green.

Decision (documented in REPORT.md): the evidence model carries no
signatures anywhere (declared-claims; submission is the privileged act),
so key-based verification would be bolted-on theater. This lane takes
the second close-when option: `trust_anchors` (producer id -> key id) is
RENAMED to `trusted_producers` (producer id -> non-empty authority
label), the old key-implying field refuses LOUD at compile time, and
the module's honest-limitations block discloses the name-allowlist
contract.

Base: wave-288 push 18beb4044a26cba48bd895d95b505d7adc327422
(verified via git rev-parse HEAD before work).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g289-f343 && TMPDIR=/var/tmp/g289-f343 \\
    ~/workspace/.gov-venv/bin/python evals/w288_f343_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g289-f343b \\
    ~/workspace/.gov-venv/bin/python evals/w288_f343_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

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

# Wave-288 merge pin; this lane adds no decision codes.
TAXONOMY_PIN = 1973 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

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
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN,
                                                       TAXONOMY_PIN))


_SCHEME = "w289.operator-trust"


def _scheme(tv):
    if _SCHEME not in tv.registered_schemes():
        tv.register_scheme(tv.SchemeDescriptor(
            _SCHEME, {"fw": "str"},
            [{"name": "firmware", "rule": "operator-trust",
              "claims": ["fw"]}]))
    return _SCHEME


def _pin(tv, policy):
    d = tempfile.mkdtemp(prefix="w289-f343-")
    pinpath = os.path.join(d, "pins.json")
    tv.pin_appraisal_policy(policy.policy_id, policy.digest, pinpath)
    return tv.load_appraisal_pins(pinpath)


def p_f343_operator_trust_name_only():
    """The original red-team repro: name-only affirmation."""
    from gov import trust_vector as tv
    scheme_id = _scheme(tv)
    try:
        pol = tv.compile_policy(
            {"format": tv.POLICY_FORMAT, "policy_id": "w289p1",
             "scheme_id": scheme_id,
             "trust_anchors": {"prodA": "keyid-AAAAAAAAAAAAAAAA"}})
    except tv.TrustVectorError as e:
        # Fixed behavior: the key-implying field refuses LOUD.
        return _record("f343-operator-trust-name-only", "HELD",
                       "old trust_anchors field refuses LOUD coded %s"
                       % (e.code,))
    ev = tv.submit_evidence(scheme_id, {"fw": "1.0"}, "prodA")
    ear = tv.appraise(ev, [], pol, _pin(tv, pol))
    if (ear["overall"] == "affirmed"
            and ear["vector"].get("firmware") == "affirmed"):
        return _record("f343-operator-trust-name-only", "BREAK",
                       "operator-trust affirmed on a producer_id string "
                       "match; the pinned key ids in trust_anchors are "
                       "never consulted -- key rotation is theater")
    _record("f343-operator-trust-name-only", "HELD",
            "operator-trust no longer affirms on the bare string match")


def p_f343_old_field_refuses_coded():
    """The refusal must be coded POLICY_INVALID, never raw."""
    from gov import trust_vector as tv
    scheme_id = _scheme(tv)
    try:
        tv.compile_policy(
            {"format": tv.POLICY_FORMAT, "policy_id": "w289p2",
             "scheme_id": scheme_id,
             "trust_anchors": {"prodA": "keyid-AAAAAAAAAAAAAAAA"}})
    except tv.TrustVectorError as e:
        if e.code == tv.POLICY_INVALID:
            return _record("f343-old-field-refuses-coded", "HELD",
                           "old field refuses coded %s" % (e.code,))
        return _record("f343-old-field-refuses-coded", "BREAK",
                       "old field refuses but with unexpected code %s"
                       % (e.code,))
    except Exception as e:  # noqa: BLE001 -- must be coded, never raw
        return _record("f343-old-field-refuses-coded", "BREAK",
                       "old field escapes as raw %r" % (type(e).__name__,))
    _record("f343-old-field-refuses-coded", "BREAK",
            "old key-implying trust_anchors field silently accepted")


def p_f343_name_allowlist_affirms():
    """The honest contract: trusted_producers is a name-allowlist."""
    from gov import trust_vector as tv
    scheme_id = _scheme(tv)
    try:
        pol = tv.compile_policy(
            {"format": tv.POLICY_FORMAT, "policy_id": "w289p3",
             "scheme_id": scheme_id,
             "trusted_producers": {"prodA": "release-authority"}})
    except tv.TrustVectorError as e:
        return _record("f343-name-allowlist-affirms", "BREAK",
                       "trusted_producers refused: %s: %s"
                       % (e.code, e.message))
    pins = _pin(tv, pol)
    ear_a = tv.appraise(tv.submit_evidence(scheme_id, {"fw": "1.0"},
                                          "prodA"), [], pol, pins)
    ear_b = tv.appraise(tv.submit_evidence(scheme_id, {"fw": "1.0"},
                                          "prodB"), [], pol, pins)
    if (ear_a["vector"].get("firmware") == "affirmed"
            and ear_b["vector"].get("firmware") == "insufficient"):
        return _record("f343-name-allowlist-affirms", "HELD",
                       "listed producer affirms; unlisted is insufficient")
    _record("f343-name-allowlist-affirms", "BREAK",
            "name-allowlist semantics wrong: prodA=%s prodB=%s"
            % (ear_a["vector"].get("firmware"),
               ear_b["vector"].get("firmware")))


def p_f343_no_trust_anchors_identifier():
    """The key-implying identifier must be gone from the module's code.

    Docstring/comment references that explain the rename are allowed;
    tokenize-level NAME tokens are what would be live code.
    """
    import tokenize
    path = os.path.join(REPO, "gov", "trust_vector.py")
    with open(path, "rb") as fh:
        names = [tok.string for tok in tokenize.tokenize(fh.readline)
                 if tok.type == tokenize.NAME]
    if "trust_anchors" in names:
        return _record("f343-no-trust-anchors-identifier", "BREAK",
                       "trust_anchors still a live code identifier")
    _record("f343-no-trust-anchors-identifier", "HELD",
            "trust_anchors appears only in rename-documentation text")


def p_f343_docstring_honest():
    """The module must disclose the name-allowlist contract."""
    with open(os.path.join(REPO, "gov", "trust_vector.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    if "map producer id -> key id" in src:
        return _record("f343-docstring-honest", "BREAK",
                       "docstring still promises key-pinned trust")
    if "name-allowlist" in src:
        return _record("f343-docstring-honest", "HELD",
                       "name-allowlist contract disclosed in module docs")
    _record("f343-docstring-honest", "BREAK",
            "no name-allowlist disclosure in module docs")


def _green_checks():
    if SKIP_GREEN:
        _record("green-checks", "SKIPPED", "GOV_SKIP_GREEN=1 (depth-1)")
        return
    # w287_ear must stay 0 BREAK (it is updated to trusted_producers).
    # Merge-time (wave-289): F344/F345 are also closed, so w288_redteam
    # is 0 BREAK on the composed tree (it was 2 expected-open at lane
    # time when only F343 was closed).
    for rel, expected in (("evals/w287_ear_probes.py", 0),
                         ("evals/w288_redteam_probes.py", 0)):
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w289-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != expected:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)" % (nbreak,
                                                            expected))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


def main():
    p_taxonomy_pin()
    p_f343_operator_trust_name_only()
    p_f343_old_field_refuses_coded()
    p_f343_name_allowlist_affirms()
    p_f343_no_trust_anchors_identifier()
    p_f343_docstring_honest()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w288_f343: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld,
                                                       nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
