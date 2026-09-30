#!/usr/bin/env python3
"""Wave-221 lane B: untrusted-text rendering policy — the EMILIA PIP-007
ADAPT.

Seam under test: gov/untrusted_render.py — untrusted-source text (model
output, tool results, fetched content) must render to the approver
plain-text-only, capped, labeled as an UNVERIFIED CLAIM, and kept
separate from the operator-rendered Action Object. "The approver's
decision input is the rendered Action Object", never the model's prose.

* render_untrusted_claim(text, *, max_chars, source_label, strict=False)
  -> UntrustedClaim {plain_text (no markup, no control chars),
  capped_text, was_truncated, source_label, claim_digest}.
  Over-length input truncates (was_truncated=True, never silent) or
  refuses with ``untrusted-claim-too-long`` when strict=True.
* render_action_object(fields) -> ActionObject (typed: action verb,
  parameter_digest, constraints; type tag). An embedded UntrustedClaim
  refuses with ``action-object-contaminated``; a missing/malformed field
  with ``action-object-malformed``.
* check_render_pair(action_object, untrusted_claims) — the approval-path
  gate: refuses fail-closed when the decision input is not a typed
  ActionObject (``render-pair-no-action-object``) or a claim fails its
  digest (``render-pair-claim-tampered``). Legacy approval behavior is
  byte-identical when the gate is unused.

Attack shapes: markup/control-char injection in untrusted text,
over-length claim smuggling, missing source label, claim digest
tamper, claim-into-ActionObject contamination, ActionObject-into-claim
contamination, raw prose as decision input, legacy behavior drift.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-220 HEAD
c0c25caa5d7cfd83b2cb0fcf92bd305d65fb34b4.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP — except
the legacy pin, which is verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g221u
  TMPDIR=/var/tmp/g221u ~/workspace/.gov-venv/bin/python evals/w221_untrusted_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g221u-u \
      ~/workspace/.gov-venv/bin/python evals/w221_untrusted_probes.py
"""

import os
import secrets
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w221-untrusted-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g221u-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import untrusted_render as ur  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    ur = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

from gov import approvals  # noqa: E402 - present on base (legacy pin)

_RESULTS = []
_PROBE_FNS = {}

_PARAM_DIGEST = "ab" * 32  # 64-hex stand-in parameter digest


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _break(name, detail=""):
    _record(name, "BREAK", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


def _code_of(exc):
    return getattr(exc, "code", type(exc).__name__)


def _claim_fields(overrides=None):
    base = {"action": "read_file",
            "parameter_digest": _PARAM_DIGEST,
            "constraints": ["scope:project"]}
    if overrides:
        base.update(overrides)
    return base


def _expect_refusal(name, code, fn):
    """The attack shape must be refused with exactly this named code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - code is the contract
        got = _code_of(exc)
        if got == code:
            _held(name, "refused with %s" % got)
        else:
            _break(name, "refused with %s, expected %s" % (got, code))
        return
    _break(name, "NOT refused (expected %s)" % code)


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("markup-stripped")
def _p_markup():
    if not _IMPORT_OK:
        return _gap("markup-stripped")
    claim = ur.render_untrusted_claim(
        "<b>hello</b> <script>alert(1)</script> <img src=x onerror=y> world",
        max_chars=200, source_label="tool-x")
    if "<" in claim.plain_text or ">" in claim.plain_text:
        _break("markup-stripped", "markup survived: %r" % claim.plain_text)
    elif "hello" not in claim.plain_text or "world" not in claim.plain_text:
        _break("markup-stripped", "content lost: %r" % claim.plain_text)
    else:
        _held("markup-stripped", "tags stripped, prose kept")


@_probe("control-chars-stripped")
def _p_controls():
    if not _IMPORT_OK:
        return _gap("control-chars-stripped")
    # NUL, BEL, zero-width space, bidi override, ANSI escape opener.
    claim = ur.render_untrusted_claim(
        "a\x00\x07b\u200bc\u202ed\x1b[31me\tf\ng",
        max_chars=200, source_label="tool-x")
    text = claim.plain_text
    import unicodedata
    bad = [ch for ch in text
           if unicodedata.category(ch).startswith("C")
           and ch not in ("\t", "\n")]
    # The ANSI escape opener is a control char and must go; its visible
    # parameter tail ("[31m") is inert plain text, not a control.
    if bad:
        _break("control-chars-stripped",
               "controls survived: %r" % bad)
    elif text != "abcd[31me\tf\ng":
        _break("control-chars-stripped", "unexpected output: %r" % text)
    else:
        _held("control-chars-stripped", "controls stripped, tab/newline kept")


@_probe("over-length-truncated-with-flag")
def _p_truncate():
    if not _IMPORT_OK:
        return _gap("over-length-truncated-with-flag")
    claim = ur.render_untrusted_claim("x" * 100, max_chars=10,
                                      source_label="tool-x")
    if len(claim.capped_text) != 10:
        _break("over-length-truncated-with-flag",
               "cap not applied: len=%d" % len(claim.capped_text))
    elif not claim.was_truncated:
        _break("over-length-truncated-with-flag", "truncation was silent")
    else:
        _held("over-length-truncated-with-flag", "capped + flagged")


@_probe("strict-cap-refuses")
def _p_strict():
    if not _IMPORT_OK:
        return _gap("strict-cap-refuses")
    _expect_refusal(
        "strict-cap-refuses", "untrusted-claim-too-long",
        lambda: ur.render_untrusted_claim("x" * 100, max_chars=10,
                                          source_label="tool-x",
                                          strict=True))


@_probe("source-label-required")
def _p_label():
    if not _IMPORT_OK:
        return _gap("source-label-required")
    _expect_refusal(
        "source-label-required", "untrusted-claim-malformed",
        lambda: ur.render_untrusted_claim("hi", max_chars=10,
                                          source_label=""))


@_probe("claim-digest-binds-content")
def _p_digest():
    if not _IMPORT_OK:
        return _gap("claim-digest-binds-content")
    claim = ur.render_untrusted_claim("bind me", max_chars=50,
                                      source_label="tool-x")
    if not ur.verify_claim(claim):
        _break("claim-digest-binds-content", "fresh claim fails verify")
        return
    # Tamper with the rendered text: the digest must stop matching.
    import copy
    tampered = copy.copy(claim)
    object.__setattr__(tampered, "capped_text", "bind YOU")
    if ur.verify_claim(tampered):
        _break("claim-digest-binds-content",
               "tampered claim still verifies")
    else:
        _held("claim-digest-binds-content", "tamper detected")


@_probe("action-object-rejects-embedded-claim")
def _p_contam():
    if not _IMPORT_OK:
        return _gap("action-object-rejects-embedded-claim")
    claim = ur.render_untrusted_claim("sneaky", max_chars=50,
                                      source_label="tool-x")
    _expect_refusal(
        "action-object-rejects-embedded-claim",
        "action-object-contaminated",
        lambda: ur.render_action_object(
            _claim_fields({"constraints": [claim]})))


@_probe("claim-rejects-action-object-instance")
def _p_claim_rejects_ao_instance():
    """An actual ActionObject record offered as claim text must refuse
    with the contamination code, not a generic malformed error."""
    if not _IMPORT_OK:
        _gap("claim-rejects-action-object-instance", "import failed")
        return
    ao = ur.render_action_object(_claim_fields())
    try:
        ur.render_untrusted_claim(ao, max_chars=200, source_label="x")
    except ur.UntrustedClaimContaminatedError as exc:
        if exc.code == "untrusted-claim-contaminated":
            _held("claim-rejects-action-object-instance",
                  "AO instance refused as claim text")
        else:
            _break("claim-rejects-action-object-instance",
                   "wrong code: %r" % exc.code)
    else:
        _break("claim-rejects-action-object-instance",
               "ActionObject accepted as claim text")


@_probe("action-object-rejects-deep-nested-claim")
def _p_ao_deep_nested():
    """A claim nested 9+ levels deep inside constraints must still be
    refused — the scan has no depth cap to evade."""
    if not _IMPORT_OK:
        _gap("action-object-rejects-deep-nested-claim", "import failed")
        return
    claim = ur.render_untrusted_claim("deep", max_chars=200,
                                      source_label="tool-x")
    nested = claim
    for _ in range(12):
        nested = [nested]
    try:
        ur.render_action_object(_claim_fields({"constraints": [nested]}))
    except ur.ActionObjectContaminatedError as exc:
        if exc.code == "action-object-contaminated":
            _held("action-object-rejects-deep-nested-claim",
                  "12-deep nested claim refused")
        else:
            _break("action-object-rejects-deep-nested-claim",
                   "wrong code: %r" % exc.code)
    else:
        _break("action-object-rejects-deep-nested-claim",
               "deep-nested claim evaded the scan")


@_probe("check-pair-refuses-tampered-action-object")
def _p_pair_tampered_ao():
    """The gate re-verifies the Action Object's own digest — a
    post-render swap (action changed after render) fails closed."""
    if not _IMPORT_OK:
        _gap("check-pair-refuses-tampered-action-object",
             "import failed")
        return
    ao = ur.render_action_object(_claim_fields())
    object.__setattr__(ao, "action", "delete_all")
    try:
        ur.check_render_pair(ao, [])
    except ur.RenderPairError as exc:
        if exc.code == "render-pair-action-object-tampered":
            _held("check-pair-refuses-tampered-action-object",
                  "tampered AO refused at gate")
        else:
            _break("check-pair-refuses-tampered-action-object",
                   "wrong code: %r" % exc.code)
    else:
        _break("check-pair-refuses-tampered-action-object",
               "tampered ActionObject passed the gate")


@_probe("wrong-python-types-are-type-errors")
def _p_type_discipline():
    """Wrong Python types at the seams are authoring misuse: plain
    TypeError, not named codes. The named codes stay reserved for
    attack shapes and malformed values."""
    if not _IMPORT_OK:
        _gap("wrong-python-types-are-type-errors", "import failed")
        return
    cases = [
        ("text", lambda: ur.render_untrusted_claim(
            123, max_chars=10, source_label="s")),
        ("max_chars", lambda: ur.render_untrusted_claim(
            "x", max_chars="10", source_label="s")),
        ("source_label", lambda: ur.render_untrusted_claim(
            "x", max_chars=10, source_label=123)),
        ("fields", lambda: ur.render_action_object(["action"])),
        ("claims", lambda: ur.check_render_pair(
            ur.render_action_object(_claim_fields()), "notalist")),
    ]
    for name, thunk in cases:
        try:
            thunk()
        except TypeError:
            continue
        except Exception as exc:  # noqa: BLE001 - pinning the refusal kind
            _break("wrong-python-types-are-type-errors",
                   "%s refused with %r, not TypeError" % (name, exc))
            return
        else:
            _break("wrong-python-types-are-type-errors",
                   "%s accepted" % name)
            return
    _held("wrong-python-types-are-type-errors",
          "5 seams raise TypeError for wrong types")


@_probe("claim-rejects-action-object")
def _p_reverse_contam():
    if not _IMPORT_OK:
        return _gap("claim-rejects-action-object")
    ao = ur.render_action_object(_claim_fields())
    _expect_refusal(
        "claim-rejects-action-object", "untrusted-claim-contaminated",
        lambda: ur.render_untrusted_claim(ao, max_chars=50,
                                          source_label="tool-x"))


@_probe("check-pair-happy-path")
def _p_pair_ok():
    if not _IMPORT_OK:
        return _gap("check-pair-happy-path")
    events = []
    ao = ur.render_action_object(_claim_fields())
    claims = [ur.render_untrusted_claim("note one", max_chars=50,
                                        source_label="tool-a"),
              ur.render_untrusted_claim("note two", max_chars=50,
                                        source_label="tool-b")]
    report = ur.check_render_pair(ao, claims, audit=events.append)
    if not report.get("pair_ok"):
        _break("check-pair-happy-path", "valid pair not accepted")
    elif report.get("action_object_digest") != ao.object_digest:
        _break("check-pair-happy-path", "report digest mismatch")
    elif not any(e.get("event") == "render_pair_verified" for e in events):
        _break("check-pair-happy-path", "no audit entry")
    else:
        _held("check-pair-happy-path", "accepted + audited")


@_probe("check-pair-refuses-raw-prose-input")
def _p_pair_raw():
    if not _IMPORT_OK:
        return _gap("check-pair-refuses-raw-prose-input")
    claim = ur.render_untrusted_claim("the prose", max_chars=50,
                                      source_label="tool-x")
    # The decision input is raw untrusted prose, not a typed Action
    # Object — the core violation this gate exists to catch.
    _expect_refusal(
        "check-pair-refuses-raw-prose-input",
        "render-pair-no-action-object",
        lambda: ur.check_render_pair(
            {"action": "read_file"}, [claim]))


@_probe("check-pair-refuses-tampered-claim")
def _p_pair_tamper():
    if not _IMPORT_OK:
        return _gap("check-pair-refuses-tampered-claim")
    import copy
    ao = ur.render_action_object(_claim_fields())
    claim = ur.render_untrusted_claim("real note", max_chars=50,
                                      source_label="tool-x")
    tampered = copy.copy(claim)
    object.__setattr__(tampered, "capped_text", "fake note")
    _expect_refusal(
        "check-pair-refuses-tampered-claim",
        "render-pair-claim-tampered",
        lambda: ur.check_render_pair(ao, [tampered]))


@_probe("claim-is-labeled-unverified")
def _p_labeled():
    if not _IMPORT_OK:
        return _gap("claim-is-labeled-unverified")
    claim = ur.render_untrusted_claim("some note", max_chars=50,
                                      source_label="tool-x")
    shown = claim.render()
    if "UNVERIFIED CLAIM" not in shown:
        _break("claim-is-labeled-unverified", "label missing: %r" % shown)
    elif "tool-x" not in shown:
        _break("claim-is-labeled-unverified", "source missing: %r" % shown)
    else:
        _held("claim-is-labeled-unverified", "label + source shown")


@_probe("legacy-approvals-byte-identical")
def _p_legacy():
    # Verifiable on BASE: the new module must not touch the legacy
    # approval path — canonical_packet output is identical whether or
    # not gov.untrusted_render is imported.
    import json
    record = {"tool": "read_file", "args": {"path": "/a/b"},
              "policy_id": "p1", "packet_risk_score": 0.1,
              "packet_risk_factors": ["f1"], "preview": "pre",
              "agent_id": "a1", "role": "ops", "principal": "u1"}
    before = json.dumps(approvals.canonical_packet(record), sort_keys=True)
    if _IMPORT_OK:
        import importlib
        importlib.reload(ur)
    after = json.dumps(approvals.canonical_packet(record), sort_keys=True)
    if before != after:
        _break("legacy-approvals-byte-identical", "canonical_packet drifted")
    else:
        _held("legacy-approvals-byte-identical", "legacy path untouched")


@_probe("determinism")
def _p_determinism():
    if not _IMPORT_OK:
        return _gap("determinism")
    c1 = ur.render_untrusted_claim("same text", max_chars=50,
                                   source_label="tool-x")
    c2 = ur.render_untrusted_claim("same text", max_chars=50,
                                   source_label="tool-x")
    a1 = ur.render_action_object(_claim_fields())
    a2 = ur.render_action_object(_claim_fields())
    if (c1.claim_digest, c1.capped_text) == (c2.claim_digest, c2.capped_text) \
            and a1.object_digest == a2.object_digest:
        _held("determinism", "renders agree")
    else:
        _break("determinism", "nondeterministic render")


# ----------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------

def _run_once():
    _RESULTS.clear()
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001 - never lose a probe
            _record(name, "ERROR", "%r" % (exc,))
    return list(_RESULTS)


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green/approvals-adjacent", "SKIP", "nested run")]
    return [("green/approvals-adjacent", "SKIP",
             "owned by merge; lane runs adjacent suites directly")]


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w221 untrusted probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-40s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-40s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
