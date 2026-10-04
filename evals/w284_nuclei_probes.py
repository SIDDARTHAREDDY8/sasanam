"""Wave-284 lane 4 red-first battery: nuclei-pattern attack-manifest DSL.

Base: wave-283 push 9a7cffc6d2b3. The gap under test is the missing
declarative attack-template layer: the wave-281 attack ledger replays
imperative scenario plans, the wave-282 battery language binds atomic
specs, and the wave-283 campaign planner chains them -- but there is
no nuclei-style TEMPLATE skeleton (id/info/matchers/extractors), no
-tc selection grammar for picking template subsets, and no
unsigned-template supply-chain posture for manifest trust.

Mechanism provenance: projectdiscovery/nuclei (MIT -- LICENSE.md
bytes verified by the wave-283 prospecting lane; clean-room Python
reimplementation of the DSL skeleton, the 5-level severity taxonomy,
the -tc field grammar, and the unsigned-template verification posture;
no nuclei code vendored). The active-network-probing ENGINE is
explicitly out of scope -- only the declarative DSL shape is stolen.

Red-first: on the pristine base (module absent) every capability
probe BREAKs. After the build, all HELD in staging and
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (no wall-clock assertions).
Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g284-nuclei && TMPDIR=/var/tmp/g284-nuclei \
    ~/workspace/.gov-venv/bin/python evals/w284_nuclei_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g284-nuclei2 \
    ~/workspace/.gov-venv/bin/python evals/w284_nuclei_probes.py
"""

import json
import os
import re
import secrets
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w284-nuclei")
os.environ.setdefault("TMPDIR", "/var/tmp/g284-nuclei")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Wave-284 lane 4: +4 manifest-* codes (unsigned, malformed,
# selection-invalid, signature-invalid).
TAXONOMY_PIN = 1964 # Wave-283 merge: 1579 -> 1587 (+2 finding-* + 6 inventory-*); Wave-284 lane 4: pin 1587 -> 1591 (+4 manifest-*).; Wave-284 merge: pin 1591 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []

PLUGIN_META = ("authz-bypass", "direct", "held-vs-expected")
PROBE_METADATA = {}


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_modules(probe_id):
    try:
        from gov import attack_manifest as am
        return am
    except ImportError:
        _record(probe_id, "BREAK", "gov.attack_manifest absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
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
    for code in ("manifest-template-unsigned", "manifest-template-malformed",
                 "manifest-selection-invalid", "manifest-signature-invalid"):
        if code not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "new code %r missing from literals" % (code,))
    _record("pin-taxonomy", "HELD",
            "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


def _good_template(**kw):
    t = {
        "id": "ssh-weak-cipher",
        "version": "1.0.0",
        "info": {
            "name": "SSH weak cipher offered",
            "author": ["red-team"],
            "severity": "high",
            "description": "server offers a weak cipher",
            "reference": ["https://example.invalid/ref"],
            "tags": ["ssh", "crypto"],
            "protocol": "ssh",
            "metadata": {"protocol": "ssh"},
        },
        "matchers-condition": "or",
        "matchers": [
            {"type": "word", "words": ["3des", "arcfour"],
             "case-insensitive": True},
            {"type": "regex", "pattern": r"cipher[=:]\s*\S+"},
        ],
        "extractors": [
            {"type": "regex", "name": "cipher", "pattern": r"cipher[=:]\s*(\S+)",
             "group": 1},
        ],
    }
    t.update(kw)
    return t


def p_severity_taxonomy():
    am = _needs_modules("p_severity_taxonomy")
    if am is None:
        return
    want = ("info", "low", "medium", "high", "critical")
    if tuple(am.SEVERITIES) != want:
        return _record("p_severity_taxonomy", "BREAK",
                       "severity taxonomy %r != pinned %r"
                       % (am.SEVERITIES, want))
    _record("p_severity_taxonomy", "HELD",
            "5-level severity taxonomy pinned (nuclei contract)")


def p_template_skeleton():
    am = _needs_modules("p_template_skeleton")
    if am is None:
        return
    norm = am.validate_template(_good_template())
    if norm["id"] != "ssh-weak-cipher" or norm["version"] != "1.0.0":
        return _record("p_template_skeleton", "BREAK",
                       "identity/version not preserved")
    if norm["info"]["severity"] != "high":
        return _record("p_template_skeleton", "BREAK",
                       "info.severity not preserved")
    for bad in ({"version": "1.0.0"},                       # no id
                {"id": "x", "version": "1.0.0", "info": {},
                 "matchers": []},                            # empty matchers
                dict(_good_template(), id="BAD ID"),         # bad id shape
                dict(_good_template(),
                     info=dict(_good_template()["info"],
                               severity="severe"))):         # bad severity
        try:
            am.validate_template(bad)
        except am.TemplateMalformed as e:
            if e.code != "manifest-template-malformed":
                return _record("p_template_skeleton", "BREAK",
                               "wrong code %r" % (e.code,))
        else:
            return _record("p_template_skeleton", "BREAK",
                           "malformed template accepted: %r" % (bad,))
    _record("p_template_skeleton", "HELD",
            "id/info/version skeleton validated, malformed refused "
            "with manifest-template-malformed")


def p_matchers_word_regex():
    am = _needs_modules("p_matchers_word_regex")
    if am is None:
        return
    norm = am.validate_template(_good_template())
    segs = [
        {"segment_id": "s1", "observation": b"server offers cipher: 3des-cbc",
         "verdict": "BREAK"},
        {"segment_id": "s2", "observation": b"all ciphers modern",
         "verdict": "HELD"},
    ]
    rec = am.run_template(norm, segs, target="isolated")
    fired = {s["segment_id"]: s["fired"] for s in rec["per_segment"]}
    if fired != {"s1": True, "s2": False}:
        return _record("p_matchers_word_regex", "BREAK",
                       "fired map %r" % (fired,))
    if rec["extracted"].get("cipher") != ["3des-cbc"]:
        return _record("p_matchers_word_regex", "BREAK",
                       "extractor got %r" % (rec["extracted"],))
    _record("p_matchers_word_regex", "HELD",
            "word+regex matchers fire on the right segments; "
            "regex extractor chains evidence")


def p_matchers_binary():
    am = _needs_modules("p_matchers_binary")
    if am is None:
        return
    norm = am.validate_template(_good_template(matchers=[
        {"type": "binary", "signature": "deadbeef"},
    ]))
    segs = [{"segment_id": "b1",
             "observation": b"\x00\xde\xad\xbe\xef\x00",
             "verdict": "BREAK"}]
    rec = am.run_template(norm, segs, target="isolated")
    if not rec["per_segment"][0]["fired"]:
        return _record("p_matchers_binary", "BREAK",
                       "binary hex signature did not fire on raw bytes")
    bad = _good_template(matchers=[{"type": "binary", "signature": "xyz"}])
    try:
        am.validate_template(bad)
    except am.TemplateMalformed:
        pass
    else:
        return _record("p_matchers_binary", "BREAK",
                       "non-hex binary signature accepted")
    _record("p_matchers_binary", "HELD",
            "binary matcher works on raw bytes; bad hex refused at load")


def p_matchers_dsl():
    am = _needs_modules("p_matchers_dsl")
    if am is None:
        return
    norm = am.validate_template(_good_template(matchers=[
        {"type": "dsl",
         "expr": 'len(observation) > 10 && contains("secret")'},
        {"type": "dsl", "expr": 'verdict == "BREAK"', "negative": True},
    ], **{"matchers-condition": "and"}))
    segs = [
        {"segment_id": "d1",
         "observation": b"this leaks a secret value",
         "verdict": "HELD"},
        {"segment_id": "d2",
         "observation": b"this leaks a secret value",
         "verdict": "BREAK"},
    ]
    rec = am.run_template(norm, segs, target="isolated")
    fired = {s["segment_id"]: s["fired"] for s in rec["per_segment"]}
    # d1: dsl1 true && (NOT verdict==BREAK) true -> fired
    # d2: dsl1 true && (NOT verdict==BREAK) false -> not fired
    if fired != {"d1": True, "d2": False}:
        return _record("p_matchers_dsl", "BREAK", "dsl fired map %r"
                       % (fired,))
    # Closed vocabulary: no eval() escape hatch.
    for evil in ('__import__("os").system("x")',
                 'open("/etc/passwd").read()'):
        bad = _good_template(matchers=[{"type": "dsl", "expr": evil}])
        try:
            am.validate_template(bad)
        except am.TemplateMalformed:
            pass
        else:
            return _record("p_matchers_dsl", "BREAK",
                           "dsl accepted hostile expr %r" % (evil,))
    _record("p_matchers_dsl", "HELD",
            "dsl matcher: closed-vocab expr, negative inversion, "
            "and-composition; hostile exprs refused at load")


def p_selection_grammar():
    am = _needs_modules("p_selection_grammar")
    if am is None:
        return
    a = am.validate_template(_good_template())
    b = am.validate_template(_good_template(
        id="http-banner-leak", version="2.1.0",
        info=dict(_good_template()["info"], severity="low",
                  tags=["http", "disclosure"],
                  protocol="http",
                  metadata={"protocol": "http"})))
    got = am.select([a, b], "severity == 'high'")
    if [t["id"] for t in got] != ["ssh-weak-cipher"]:
        return _record("p_selection_grammar", "BREAK",
                       "severity select got %r" % ([t["id"] for t in got],))
    got = am.select([a, b], "'ssh' in tags || severity == 'low'")
    if sorted(t["id"] for t in got) != ["http-banner-leak",
                                        "ssh-weak-cipher"]:
        return _record("p_selection_grammar", "BREAK",
                       "tag||severity select got %r"
                       % ([t["id"] for t in got],))
    got = am.select([a, b], "!(severity == 'high')")
    if [t["id"] for t in got] != ["http-banner-leak"]:
        return _record("p_selection_grammar", "BREAK",
                       "negation select got %r" % ([t["id"] for t in got],))
    got = am.select([a, b], "metadata.protocol == 'ssh'")
    if [t["id"] for t in got] != ["ssh-weak-cipher"]:
        return _record("p_selection_grammar", "BREAK",
                       "metadata select got %r" % ([t["id"] for t in got],))
    _record("p_selection_grammar", "HELD",
            "-tc analog: severity/tag/id/protocol/metadata selection with "
            "&& || ! composition")


def p_protocol_field():
    am = _needs_modules("p_protocol_field")
    if am is None:
        return
    a = am.validate_template(_good_template())
    b = am.validate_template(_good_template(
        id="http-banner-leak", version="2.1.0",
        info=dict(_good_template()["info"], protocol="http")))
    got = am.select([a, b], "protocol == 'ssh'")
    if [t["id"] for t in got] != ["ssh-weak-cipher"]:
        return _record("p_protocol_field", "BREAK",
                       "protocol select got %r" % ([t["id"] for t in got],))
    # A template declaring no protocol never matches a protocol
    # predicate (no silent match).
    c = am.validate_template(_good_template(
        id="no-proto", info=dict(_good_template()["info"],
                                 protocol=None)))
    got = am.select([c], "protocol == 'ssh'")
    if got:
        return _record("p_protocol_field", "BREAK",
                       "protocol-less template matched a protocol predicate")
    got = am.select([a, b], "version == '2.1.0'")
    if [t["id"] for t in got] != ["http-banner-leak"]:
        return _record("p_protocol_field", "BREAK",
                       "version select got %r" % ([t["id"] for t in got],))
    _record("p_protocol_field", "HELD",
            "protocol is a first-class selection field; version too")


def p_templates_from_atomics():
    am = _needs_modules("p_templates_from_atomics")
    if am is None:
        return
    atomics = [
        {"name": "SSH Weak Cipher", "description": "probe ssh ciphers",
         "severity": "high", "tags": ["ssh"]},
        {"name": "HTTP Banner", "description": "probe http banner"},
    ]
    tmpls = am.templates_from_atomics(atomics)
    if [t["id"] for t in tmpls] != ["ssh-weak-cipher", "http-banner"]:
        return _record("p_templates_from_atomics", "BREAK",
                       "ids %r" % ([t["id"] for t in tmpls],))
    if [t["info"]["severity"] for t in tmpls] != ["high", "info"]:
        return _record("p_templates_from_atomics", "BREAK",
                       "severities %r"
                       % ([t["info"]["severity"] for t in tmpls],))
    # The -tc grammar selects over the derived population, and the
    # derived break-matcher fires on BREAK verdicts.
    got = am.select(tmpls, "severity == 'high' && 'ssh' in tags")
    if [t["id"] for t in got] != ["ssh-weak-cipher"]:
        return _record("p_templates_from_atomics", "BREAK",
                       "select over atomics got %r"
                       % ([t["id"] for t in got],))
    rec = am.run_template(
        tmpls[0],
        [{"segment_id": "x", "observation": b"anything",
          "verdict": "BREAK"}],
        target="isolated")
    if not rec["per_segment"][0]["fired"]:
        return _record("p_templates_from_atomics", "BREAK",
                       "derived dsl matcher did not fire on BREAK")
    try:
        am.templates_from_atomics([{"name": "", "description": "x"}])
    except am.TemplateMalformed:
        pass
    else:
        return _record("p_templates_from_atomics", "BREAK",
                       "nameless atomic accepted")
    _record("p_templates_from_atomics", "HELD",
            "campaign atomics derive a selectable template population; "
            "break-matchers fire on BREAK verdicts")


def p_nesting_refusal():
    am = _needs_modules("p_nesting_refusal")
    if am is None:
        return
    deep = "(" * 5000 + 'contains("x")' + ")" * 5000
    try:
        am.validate_template(_good_template(matchers=[{
            "type": "dsl", "expr": deep}]))
    except am.TemplateMalformed:
        pass
    except RecursionError:
        return _record("p_nesting_refusal", "BREAK",
                       "pathological dsl nesting escaped as RecursionError")
    else:
        return _record("p_nesting_refusal", "BREAK",
                       "pathological dsl nesting accepted")
    try:
        am.select([am.validate_template(_good_template())],
                  "(" * 5000 + "severity == 'high'" + ")" * 5000)
    except am.SelectionInvalid:
        pass
    except RecursionError:
        return _record("p_nesting_refusal", "BREAK",
                       "pathological selection nesting escaped as "
                       "RecursionError")
    else:
        return _record("p_nesting_refusal", "BREAK",
                       "pathological selection nesting accepted")
    _record("p_nesting_refusal", "HELD",
            "pathological nesting refuses LOUD with coded errors, never "
            "RecursionError")


def p_bare_metadata_refused():
    am = _needs_modules("p_bare_metadata_refused")
    if am is None:
        return
    try:
        am.select([am.validate_template(_good_template())],
                  "metadata == 'ssh'")
    except am.SelectionInvalid:
        pass
    else:
        return _record("p_bare_metadata_refused", "BREAK",
                       "bare metadata predicate silently evaluated False")
    _record("p_bare_metadata_refused", "HELD",
            "bare metadata (no key) refuses with "
            "manifest-selection-invalid")


def p_selection_invalid():
    am = _needs_modules("p_selection_invalid")
    if am is None:
        return
    a = am.validate_template(_good_template())
    for evil in ("severity == 'high' &&", "nosuchfield == 'x'",
                 "'a' in 'b' in 'c'", "severity = 'high'"):
        try:
            am.select([a], evil)
        except am.SelectionInvalid as e:
            if e.code != "manifest-selection-invalid":
                return _record("p_selection_invalid", "BREAK",
                               "wrong code %r" % (e.code,))
        else:
            return _record("p_selection_invalid", "BREAK",
                           "bad selection accepted: %r" % (evil,))
    _record("p_selection_invalid", "HELD",
            "malformed/unknown-field selections refuse with "
            "manifest-selection-invalid")


def p_unsigned_isolated_only():
    am = _needs_modules("p_unsigned_isolated_only")
    if am is None:
        return
    norm = am.validate_template(_good_template())
    segs = [{"segment_id": "u1", "observation": b"cipher: 3des",
             "verdict": "BREAK"}]
    # Isolated fixtures: fine.
    rec = am.run_template(norm, segs, target="isolated")
    if rec["trust"] != "unsigned":
        return _record("p_unsigned_isolated_only", "BREAK",
                       "trust not recorded as unsigned")
    # Production target with an unsigned template: LOUD refusal.
    try:
        am.run_template(norm, segs, target="production")
    except am.TemplateUnsigned as e:
        if e.code != "manifest-template-unsigned":
            return _record("p_unsigned_isolated_only", "BREAK",
                           "wrong code %r" % (e.code,))
    else:
        return _record("p_unsigned_isolated_only", "BREAK",
                       "unsigned template ran against production target")
    # Explicit opt-out (the -nmhe analog): runs, but the opt-out is
    # recorded loudly in the run record.
    rec = am.run_template(norm, segs, target="production",
                          allow_unsigned=True,
                          optout_reason="analyst override w284")
    if not rec.get("unsigned_optout"):
        return _record("p_unsigned_isolated_only", "BREAK",
                       "opt-out not recorded in run record")
    try:
        am.run_template(norm, segs, target="production",
                        allow_unsigned=True, optout_reason="")
    except am.TemplateMalformed:
        pass
    else:
        return _record("p_unsigned_isolated_only", "BREAK",
                       "empty optout_reason accepted")
    _record("p_unsigned_isolated_only", "HELD",
            "unsigned templates run only against isolated fixtures; "
            "production requires signature or a LOUD recorded opt-out")


def p_sign_verify():
    am = _needs_modules("p_sign_verify")
    if am is None:
        return
    from gov import ed25519 as ed
    norm = am.validate_template(_good_template())
    seed = ed.generate_seed()
    pub = ed.publickey(seed)
    env = am.sign_template(seed, norm)
    if not am.verify_signed_template(env):
        return _record("p_sign_verify", "BREAK",
                       "freshly signed template failed verification")
    # Tamper with the signed body: verification must fail LOUD.
    tampered = json.loads(json.dumps(env))
    tampered["template"]["info"]["severity"] = "critical"
    try:
        am.verify_signed_template(tampered)
    except am.SignatureInvalid as e:
        if e.code != "manifest-signature-invalid":
            return _record("p_sign_verify", "BREAK", "wrong code %r"
                           % (e.code,))
    else:
        return _record("p_sign_verify", "BREAK",
                       "tampered template verified clean")
    # A signed template runs against production with no opt-out.
    segs = [{"segment_id": "v1", "observation": b"cipher: 3des",
             "verdict": "BREAK"}]
    rec = am.run_signed_template(env, pub, segs, target="production")
    if rec["trust"] != "signed" or not rec["per_segment"][0]["fired"]:
        return _record("p_sign_verify", "BREAK",
                       "signed production run misbehaved: %r" % (rec,))
    _record("p_sign_verify", "HELD",
            "Ed25519 binds id+version+content-digest; tamper fails LOUD; "
            "signed templates run at production trust")


def p_ledger_composition():
    am = _needs_modules("p_ledger_composition")
    if am is None:
        return
    from gov import attack_ledger as al
    d = tempfile.mkdtemp(prefix="nuc-", dir=os.environ["TMPDIR"])
    ledger = al.AttackLedger(os.path.join(d, "ledger.db"))
    try:
        norm = am.validate_template(_good_template())
        segs = [{"segment_id": "c1",
                 "observation": b"cipher: 3des", "verdict": "BREAK"}]
        rec = am.run_template(norm, segs, target="isolated")
        bound = am.bind_template_run(ledger, norm, rec)
        if not bound["piece_id"] or not bound["score_id"]:
            return _record("p_ledger_composition", "BREAK",
                           "bind returned %r" % (bound,))
        if not ledger.verify_chain():
            return _record("p_ledger_composition", "BREAK",
                           "ledger hash chain broken after bind")
    finally:
        ledger.close()
    _record("p_ledger_composition", "HELD",
            "template runs bind into the attack ledger as pieces+scores; "
            "chain verifies (composition, not duplication)")


def p_kval_extractor():
    am = _needs_modules("p_kval_extractor")
    if am is None:
        return
    norm = am.validate_template(_good_template(
        matchers=[{"type": "word", "words": ["token"]}],
        extractors=[
            {"type": "kval", "name": "token", "key": "api_token"},
        ]))
    segs = [{"segment_id": "k1",
             "observation": b"config: api_token=hunter2; other=1",
             "verdict": "BREAK"}]
    rec = am.run_template(norm, segs, target="isolated")
    if rec["extracted"].get("token") != ["hunter2"]:
        return _record("p_kval_extractor", "BREAK",
                       "kval extracted %r" % (rec["extracted"],))
    _record("p_kval_extractor", "HELD",
            "kval extractor pulls key=value evidence from fired segments")


def _green_check(mod_name):
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-" + mod_name, "HELD", "skipped (depth-1)")
        return
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "evals/%s_probes.py" % mod_name],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True, text=True, env=env, timeout=600)
    out = (r.stdout or "") + (r.stderr or "")
    bad = ("[ERROR]" in out) or (r.returncode != 0)
    _record("green-" + mod_name, "HELD" if not bad else "BREAK",
            "rc=%d" % r.returncode)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    p_taxonomy_pin()
    p_severity_taxonomy()
    p_template_skeleton()
    p_matchers_word_regex()
    p_matchers_binary()
    p_matchers_dsl()
    p_selection_grammar()
    p_protocol_field()
    p_templates_from_atomics()
    p_nesting_refusal()
    p_bare_metadata_refused()
    p_selection_invalid()
    p_unsigned_isolated_only()
    p_sign_verify()
    p_ledger_composition()
    p_kval_extractor()
    _green_check("w283_caldera")

    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("[%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    print("== %d BREAK / %d HELD / %d ERROR ==" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
