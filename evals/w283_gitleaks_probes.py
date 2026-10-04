"""Wave-283 lane-4 (Gitleaks STEAL) battery: the ``secret_canonicalizer``
rule engine must be the single detection seam for the F306 emission
family (triad, shields, GuardChain, future emission sites).

Contract (adapted from gitleaks/gitleaks, MIT -- rule-engine shapes
only, no vendored code):
  - ``keywords`` cheap prefilter -> regex rule match -> ``secretGroup``
    separation (the structured finding carries the secret's digest,
    NEVER the raw bytes)
  - decode/composite evasion semantics (base64/hex/percent layers,
    proximity-bounded composite rules)
  - ``stdin`` streaming seam (chunked scanning with overlap; secrets
    split across chunk boundaries are still caught, exactly once)
  - reporter redaction invariant: matched bytes physically cannot
    cross the emission boundary -- findings and sanitized text are
    the only things that leave the engine
  - fingerprint + allowlist exception registry (governed, auditable,
    expiring exceptions)
  - fail-closed on rule errors (a malformed rule refuses at
    construction; the engine never half-initializes)

Red-first: on the pristine wave-282 base the module does not exist, so
every capability probe BREAKs. After the build they HELD.

$0 spend, synthetic/local, deterministic (fixed fixtures, no
wall-clock assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g283-gitleaks && TMPDIR=/var/tmp/g283-gitleaks \
    ~/workspace/.gov-venv/bin/python evals/w283_gitleaks_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g283-gitleaks-b \
    ~/workspace/.gov-venv/bin/python evals/w283_gitleaks_probes.py
"""

import os
import re
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 2018 # Wave-282 merge: 1563 -> 1579 (no new codes in this lane); Wave-283 merge: pin 1579 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _sc():
    """Import the engine; None on the pristine base (module absent)."""
    try:
        from gov import secret_canonicalizer as sc
        return sc
    except ImportError:
        return None


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
    _record("pin-taxonomy", "HELD", "1588/1588/0 sorted")


# ---------------------------------------------------------------------------
# Fixtures (synthetic, never real credentials)
# ---------------------------------------------------------------------------

_AWS = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
_GH = "github token ghp_abcdefghijklmnopqrstuvwx1234567890ab"
_B64 = ("cGFzc3dvcmQ9aHVudGVyMi1odW50ZXIyLXg5",  # base64("password=hunter2-hunter2-x9")
        "password=hunter2-hunter2-x9")


def p_keyword_prefilter_and_hit():
    """keywords prefilter must not skip real hits; the finding carries
    structured parts (detector/kind/location) and no raw secret bytes."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-keyword-hit", "BREAK", "module absent")
    findings = sc.scan("deploy config " + _AWS, location="test/keyword-hit")
    if not findings:
        return _record("gitleaks-keyword-hit", "BREAK", "aws key not detected")
    f = findings[0]
    parts = f.to_dict()
    if not all(k in parts for k in ("detector", "kind", "location")):
        return _record("gitleaks-keyword-hit", "BREAK",
                       "structured parts missing: %r" % sorted(parts))
    blob = repr(parts) + repr(findings)
    if "AKIAIOSFODNN7EXAMPLE" in blob or "aws_access_key_id" in parts.get("detector", ""):
        # the DETECTOR name may carry the rule id; the raw secret must not
        if "AKIAIOSFODNN7EXAMPLE" in blob:
            return _record("gitleaks-keyword-hit", "BREAK",
                           "raw secret bytes escaped into finding repr")
    _record("gitleaks-keyword-hit", "HELD",
            "detector=%s kind=%s (no raw bytes)" % (f.detector, f.kind))


def p_secret_group_separation():
    """The secretGroup must separate the secret from its context: the
    sanitized text keeps the ``api_key=`` context and withholds only the
    secret span, kind-preserving."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-secret-group", "BREAK", "module absent")
    text = "rejection: api_key=hunter2-hunter2-x9 denied"
    sanitized, findings = sc.sanitize(text, location="test/secret-group")
    if "hunter2" in sanitized:
        return _record("gitleaks-secret-group", "BREAK",
                       "secret bytes survived sanitize")
    if not sanitized.startswith("rejection: api_key="):
        return _record("gitleaks-secret-group", "BREAK",
                       "context mangled: %r" % sanitized)
    if not findings or "[REDACTED" not in sanitized:
        return _record("gitleaks-secret-group", "BREAK",
                       "no kind-preserving placeholder: %r" % sanitized)
    _record("gitleaks-secret-group", "HELD",
            "context kept, secret withheld: %r" % sanitized)


def p_decode_evasion():
    """A base64-encoded credential must be caught at the decode layer
    (gitleaks --max-decode-depth semantics); the finding is tagged with
    the encoding and the decoded bytes never leave the engine."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-decode", "BREAK", "module absent")
    text = "blob: " + _B64[0]
    findings = sc.scan(text, location="test/decode")
    tagged = [f for f in findings if f.encoding == "base64"]
    if not tagged:
        return _record("gitleaks-decode", "BREAK",
                       "base64-layer credential not detected")
    blob = repr([f.to_dict() for f in findings])
    if _B64[1] in blob:
        return _record("gitleaks-decode", "BREAK",
                       "decoded secret bytes escaped into findings")
    _record("gitleaks-decode", "HELD",
            "base64 layer detected (encoding=base64, no raw bytes)")


def p_composite_proximity():
    """Composite rule: a high-entropy token is only a finding when a
    credential keyword is nearby (proximity-bounded). Far-apart entropy
    is not a hit; adjacent is."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-composite", "BREAK", "module absent")
    token = "x9fK2mQ8vL4nR7tW1"
    far = "password: nothing here " + "x" * 600 + token
    near = "password: see value " + token
    # The far TOKEN itself must carry no finding (the generic rule may
    # still flag the keyword-adjacent word "nothing" by design -- that
    # is adjacency, not proximity violation).
    far_token_hits = [f for f in sc.scan(far)
                      if f.offset <= far.index(token) < f.offset + f.length]
    if far_token_hits:
        return _record("gitleaks-composite", "BREAK",
                       "far-apart token fired (proximity not bounded)")
    # Isolate the composite rule itself: the near fixture also fires
    # generic-password on "see", so assert the composite detector.
    near_composite = [f for f in sc.scan(near)
                      if f.detector == "composite-keyword-entropy"]
    if not near_composite:
        return _record("gitleaks-composite", "BREAK",
                       "composite rule did not fire on adjacent keyword+token")
    _record("gitleaks-composite", "HELD",
            "proximity-bounded composite (far token silent, near fires)")


def p_allowlist_registry():
    """A fingerprint+allowlist exception suppresses exactly the
    registered finding (governed, auditable); anything else still fires;
    expired exceptions stop suppressing."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-allowlist", "BREAK", "module absent")
    reg = sc.ExceptionRegistry()
    text = "ci config " + _GH
    findings = sc.scan(text, location="test/allowlist")
    if not findings:
        return _record("gitleaks-allowlist", "BREAK", "fixture not detected")
    f = findings[0]
    audit = reg.register(fingerprint=f.fingerprint, reason="test-only fixture",
                         approver="lane-4-battery")
    if not reg.is_allowed(f.fingerprint):
        return _record("gitleaks-allowlist", "BREAK", "registered fp not allowed")
    kept, suppressed = reg.suppress(findings)
    if kept or len(suppressed) != 1:
        return _record("gitleaks-allowlist", "BREAK",
                       "suppression miscounted: kept=%d suppressed=%d"
                       % (len(kept), len(suppressed)))
    other = sc.scan("other " + _AWS, location="test/allowlist")
    kept2, suppressed2 = reg.suppress(other)
    if suppressed2 or not kept2:
        return _record("gitleaks-allowlist", "BREAK",
                       "allowlist suppressed an unregistered finding")
    expired = sc.ExceptionRegistry()
    expired.register(fingerprint=f.fingerprint, reason="stale",
                     approver="lane-4-battery", expires_at=0)
    if expired.is_allowed(f.fingerprint):
        return _record("gitleaks-allowlist", "BREAK",
                       "expired exception still suppressing")
    if "approver" not in audit or audit.get("reason") != "test-only fixture":
        return _record("gitleaks-allowlist", "BREAK",
                       "exception registration not auditable")
    _record("gitleaks-allowlist", "HELD",
            "exact-fp suppression, expiry honored, registration auditable")


def p_streaming_seam():
    """stdin streaming seam: a secret split across chunk boundaries is
    caught exactly once, with absolute offsets."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-streaming", "BREAK", "module absent")
    text = "prefix " + _AWS + " suffix"
    chunks = [text[:20], text[20:40], text[40:]]
    scanner = sc.Scanner(location="test/streaming")
    seen = []
    for c in chunks:
        seen.extend(scanner.feed(c))
    seen.extend(scanner.finish())
    fps = [f.fingerprint for f in seen]
    if len(fps) != 1:
        return _record("gitleaks-streaming", "BREAK",
                       "split secret found %d times, want 1" % len(fps))
    f = seen[0]
    if f.offset != text.index("AKIAIOSFODNN7EXAMPLE"):
        return _record("gitleaks-streaming", "BREAK",
                       "offset not absolute: %d" % f.offset)
    _record("gitleaks-streaming", "HELD",
            "cross-chunk secret caught once at absolute offset %d" % f.offset)


def p_fail_closed_rules():
    """Fail-closed on rule errors: a malformed rule refuses at
    construction (RuleError); the engine never half-initializes; an
    unknown rule id is refused."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-fail-closed", "BREAK", "module absent")
    try:
        sc.compile_rules([{"id": "bad", "regex": "(unclosed"}])
        return _record("gitleaks-fail-closed", "BREAK",
                       "malformed regex did not refuse")
    except sc.RuleError:
        pass
    try:
        sc.compile_rules([{"id": "no-group", "regex": "password=\\S+"}])
        return _record("gitleaks-fail-closed", "BREAK",
                       "rule without a secret group did not refuse")
    except sc.RuleError:
        pass
    try:
        sc.get_rule("no-such-rule")
        return _record("gitleaks-fail-closed", "BREAK",
                       "unknown rule id not refused")
    except sc.RuleError:
        pass
    _record("gitleaks-fail-closed", "HELD",
            "malformed rules refuse loudly at construction")


def p_fingerprint_stability():
    """Fingerprints are stable for the same (rule, secret, location) and
    differ across locations; two different secrets never collide."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-fingerprint", "BREAK", "module absent")
    a = sc.scan(_AWS, location="a")[0].fingerprint
    b = sc.scan(_AWS, location="a")[0].fingerprint
    c = sc.scan(_AWS, location="b")[0].fingerprint
    d = sc.scan(_GH, location="a")[0].fingerprint
    if not (a == b and a != c and a != d):
        return _record("gitleaks-fingerprint", "BREAK",
                       "fingerprint unstable or colliding")
    _record("gitleaks-fingerprint", "HELD",
            "stable per (rule, secret, location); distinct across both axes")


def p_reporter_invariant():
    """Reporter redaction invariant: across every fixture, the repr of
    findings and sanitized text never contains any raw secret bytes."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-reporter-invariant", "BREAK", "module absent")
    fixtures = [
        ("aws", _AWS, "AKIAIOSFODNN7EXAMPLE"),
        ("github", _GH, "ghp_abcdefghijklmnopqrstuvwx1234567890ab"),
        ("b64", "blob: " + _B64[0], "hunter2-hunter2-x9"),
        ("deny", "PluginDeny: blocked: password= hunter2-hunter2-x9 present",
         "hunter2-hunter2-x9"),
    ]
    for name, text, raw in fixtures:
        findings = sc.scan(text, location="test/reporter")
        sanitized, _ = sc.sanitize(text, location="test/reporter")
        blob = repr([f.to_dict() for f in findings]) + repr(findings) + sanitized
        if raw in blob:
            return _record("gitleaks-reporter-invariant", "BREAK",
                           "fixture %r leaked raw bytes" % name)
    # Decode-layer sanitize: the WHOLE encoded span must be redacted --
    # redacting the decoded-local span corrupts the text and leaves
    # decodable fragments (wave-283 spec-review MEDIUM-1).
    import base64
    b64 = base64.b64encode(b"password=hunter2-hunter2-x9").decode()
    text = "blob: " + b64
    sanitized, findings = sc.sanitize(text, location="test/reporter")
    if not findings or not any(f.encoding for f in findings):
        return _record("gitleaks-reporter-invariant", "BREAK",
                       "decode-layer fixture produced no finding")
    if b64 in sanitized:
        return _record("gitleaks-reporter-invariant", "BREAK",
                       "encoded span not fully redacted")
    # No residual fragment may still decode to secret material.
    import re as _re
    for frag in _re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", sanitized):
        try:
            dec = base64.b64decode(frag, validate=True)
        except Exception:
            continue
        if b"hunter2" in dec or b"password" in dec:
            return _record("gitleaks-reporter-invariant", "BREAK",
                           "decodable secret fragment survived sanitize")
    if sanitized != "blob: [REDACTED:password]":
        return _record("gitleaks-reporter-invariant", "BREAK",
                       "decode-layer sanitize corrupted text: %r" % sanitized)
    _record("gitleaks-reporter-invariant", "HELD",
            "no raw secret bytes in findings or sanitized text (5 fixtures)")


def p_anti_false_positive():
    """Benign text must not fire: uuids, timestamps, prose without
    credential shapes. (FPs would fail the F306 elicitation-style bans
    closed on legitimate traffic.)"""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-anti-fp", "BREAK", "module absent")
    benign = [
        "request id 550e8400-e29b-41d4-a716-446655440000 processed",
        "no PII spans found",
        "rejection: tool blocked by policy p-123 at 2026-10-02T03:00:00Z",
        "the password policy requires 12 characters",
        "api_key=",
    ]
    for text in benign:
        if sc.credential_material_present(text):
            return _record("gitleaks-anti-fp", "BREAK",
                           "false positive on: %r" % text)
    _record("gitleaks-anti-fp", "HELD", "5 benign fixtures silent")


def p_triad_funnel_routes_through_seam():
    """Composition: the F306 triad funnel detects via the
    canonicalizer. A credential-shaped rejection note is withheld with
    the F306 placeholder convention; the verdict is preserved; clean
    notes pass verbatim."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-triad-funnel", "BREAK", "module absent")
    from gov import tool_guardrails as tg
    note = "rejection: password= hunter2-hunter2-x9 rejected by policy"
    out = tg._sanitize_note(note)
    if "hunter2" in out:
        return _record("gitleaks-triad-funnel", "BREAK",
                       "triad funnel echoes the credential")
    if not out.startswith("rejection: ") or "withheld" not in out:
        return _record("gitleaks-triad-funnel", "BREAK",
                       "F306 placeholder convention broken: %r" % out)
    clean = "rejection: tool blocked by policy p-7"
    if tg._sanitize_note(clean) != clean:
        return _record("gitleaks-triad-funnel", "BREAK",
                       "clean note mangled: %r" % tg._sanitize_note(clean))
    _record("gitleaks-triad-funnel", "HELD",
            "triad detects via canonicalizer; F306 convention intact")


def p_shield_funnel_routes_through_seam():
    """Composition: the F310 shield funnel detects via the
    canonicalizer; verdict preserved; clean rationale verbatim."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-shield-funnel", "BREAK", "module absent")
    from gov import guardrail_evidence as ge
    raw = "ShieldViolation: blocked: saw secret= hunter2-hunter2-x9 in args"
    out = ge._sanitize_shield_rationale(raw)
    if "hunter2" in out:
        return _record("gitleaks-shield-funnel", "BREAK",
                       "shield funnel echoes the credential")
    if not out.startswith("ShieldViolation: ") or "withheld" not in out:
        return _record("gitleaks-shield-funnel", "BREAK",
                       "F310 placeholder convention broken: %r" % out)
    clean = "ShieldViolation: blocked by policy"
    if ge._sanitize_shield_rationale(clean) != clean:
        return _record("gitleaks-shield-funnel", "BREAK", "clean mangled")
    _record("gitleaks-shield-funnel", "HELD",
            "shield funnel detects via canonicalizer; F310 convention intact")


def p_guardchain_funnel_routes_through_seam():
    """Composition: the GuardChain emit sites (F311's defect site)
    detect via the canonicalizer. A credential-quoting PluginDeny
    records a kind-preserving placeholder; the block verdict still
    enforces; the transform record's detail is redacted in place."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-guardchain-funnel", "BREAK", "module absent")
    import shutil
    from gov.log import ActionLog, read_entries
    from gov import guard_plugins as gp
    from gov.guardrail_evidence import GuardrailEvidenceWriter

    d = tempfile.mkdtemp(prefix="w283-gitleaks-gc-")
    try:
        _gc_funnel_body(sc, d, gp, ActionLog, read_entries,
                        GuardrailEvidenceWriter)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _gc_funnel_body(sc, d, gp, ActionLog, read_entries,
                    GuardrailEvidenceWriter):
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    writer = GuardrailEvidenceWriter(log)
    reg = gp.PluginRegistry()

    def _evil_run(ctx):
        raise gp.PluginDeny("blocked: password= hunter2-hunter2-x9 present")

    reg.register("evil-deny", hooks=("before_tool_call",), run=_evil_run)
    chain = gp.GuardChain(reg, writer, log)
    verdict = chain.run_hook("before_tool_call", tool_name="t",
                             payload={"a": 1}, plugin_ids=["evil-deny"])
    if verdict.allowed:
        return _record("gitleaks-guardchain-funnel", "BREAK",
                       "deny did not enforce")
    leaked = [r for r in read_entries(log.path)
              if "hunter2" in repr(r)]
    if leaked:
        return _record("gitleaks-guardchain-funnel", "BREAK",
                       "GuardChain record echoes the credential (%d records)"
                       % len(leaked))
    recs = [r for r in read_entries(log.path)
            if r.get("record_type") == "guardrail-run"]
    if not recs or "withheld" not in recs[-1].get("rationale", ""):
        return _record("gitleaks-guardchain-funnel", "BREAK",
                       "deny rationale lacks the redacted placeholder")
    _record("gitleaks-guardchain-funnel", "HELD",
            "GuardChain deny path sanitized via canonicalizer; verdict kept")


def p_guardchain_transform_detail_redacted():
    """The guard-plugin-transform record's ``detail`` field is
    redacted in place (span-level, kind-preserving); the transform
    verdict still applies and digests are unaffected."""
    sc = _sc()
    if sc is None:
        return _record("gitleaks-transform-detail", "BREAK", "module absent")
    from gov import guard_plugins as gp
    import shutil
    from gov.log import ActionLog, read_entries
    from gov.guardrail_evidence import GuardrailEvidenceWriter
    d = tempfile.mkdtemp(prefix="w283-gitleaks-tx-")
    try:
        _tx_detail_body(sc, d, gp, ActionLog, read_entries,
                        GuardrailEvidenceWriter)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _tx_detail_body(sc, d, gp, ActionLog, read_entries,
                    GuardrailEvidenceWriter):
    def _evil_run(ctx):
        return gp.transform_outcome(
            {"a": 2},
            "rewrote args quoting password= hunter2-hunter2-x9 from input")

    log = ActionLog(os.path.join(d, "audit.jsonl"))
    writer = GuardrailEvidenceWriter(log)
    reg = gp.PluginRegistry()
    reg.register("evil-xform", hooks=("before_tool_call",), run=_evil_run)
    chain = gp.GuardChain(reg, writer, log)
    verdict = chain.run_hook("before_tool_call", tool_name="t",
                             payload={"a": 1}, plugin_ids=["evil-xform"])
    if verdict.payload.get("a") != 2:
        return _record("gitleaks-transform-detail", "BREAK",
                       "transform did not apply")
    tx = [r for r in read_entries(log.path)
          if r.get("record_type") == "guard-plugin-transform"]
    if not tx:
        return _record("gitleaks-transform-detail", "BREAK",
                       "no transform record")
    detail = tx[0].get("detail", "")
    if "hunter2" in detail:
        return _record("gitleaks-transform-detail", "BREAK",
                       "transform detail echoes the credential")
    if "[REDACTED" not in detail:
        return _record("gitleaks-transform-detail", "BREAK",
                       "transform detail lacks redacted placeholder: %r"
                       % detail)
    _record("gitleaks-transform-detail", "HELD",
            "transform detail redacted in place; verdict applied")


    # ---------------------------------------------------------------------------
    # Green checks (depth-1 per the wave-176 lesson)
    # ---------------------------------------------------------------------------

def _reorder_break_first(m):
    """Normalize a BREAK-first summary match to (HELD, BREAK, ERROR) groups."""
    class _M:
        def group(self, i):
            if i == 0:
                return m.group(0)
            return {1: m.group(2), 2: m.group(1), 3: m.group(3)}[i]
    return _M()


def _green_checks():
    if SKIP_GREEN:
        _record("green-skip", "HELD", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    checks = [
        (["evals/w281_f306_probes.py"], "w281-f306"),
        (["evals/w282_f310_probes.py"], "w282-f310"),
        (["evals/w280_shields_probes.py"], "w280-shields"),
    ]
    for argv, name in checks:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        if "TMPDIR" not in env:
            env["TMPDIR"] = tempfile.mkdtemp(prefix="g283-gitleaks-green-")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            out = subprocess.run(
                [sys.executable] + argv, cwd=REPO, env=env,
                capture_output=True, text=True, timeout=600)
        except Exception as exc:  # noqa: BLE001
            _record("green-" + name, "BREAK", "green check error: %r" % (exc,))
            continue
        rows = out.stdout + out.stderr
        m = re.search(r"(\d+)\s*HELD\s*/\s*(\d+)\s*BREAK\s*/\s*(\d+)\s*ERROR",
                      rows)
        if m is None:
            m = re.search(r"(\d+)\s*BREAK\s*/\s*(\d+)\s*HELD\s*/\s*(\d+)\s*ERROR",
                          rows)
            if m:
                m = _reorder_break_first(m)
        if m and m.group(2) == "0" and m.group(3) == "0":
            _record("green-" + name, "HELD", m.group(0).strip())
        else:
            _record("green-" + name, "BREAK",
                    "exit %d: %s" % (out.returncode, rows[-400:]))


def main():
    p_taxonomy_pin()
    p_keyword_prefilter_and_hit()
    p_secret_group_separation()
    p_decode_evasion()
    p_composite_proximity()
    p_allowlist_registry()
    p_streaming_seam()
    p_fail_closed_rules()
    p_fingerprint_stability()
    p_reporter_invariant()
    p_anti_false_positive()
    p_triad_funnel_routes_through_seam()
    p_shield_funnel_routes_through_seam()
    p_guardchain_funnel_routes_through_seam()
    p_guardchain_transform_detail_redacted()
    _green_checks()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w283_gitleaks: %d HELD / %d BREAK / %d ERROR" % (n_held, n_break, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
