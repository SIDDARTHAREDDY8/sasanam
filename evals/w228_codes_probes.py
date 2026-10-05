#!/usr/bin/env python3
"""Wave-228 lane C: machine decision-code taxonomy + evidence re-execution.

Red-first battery on the PUBLIC seams. Seams under test:
* gov/decision_codes.py -- closed DecisionCode taxonomy mapping every
  refusal string the repo emits to {domain, code, human, severity,
  evidence_kinds_required}; code_for() fails closed with
  decision-code-unmapped; every emitted code carries a reevaluate
  pointer {evidence_digests, reverify_steps} with digest-shaped digests;
  authority-shaped use refuses decision-code-not-authorization; decision
  codes compose into action capsules as digest-linked evidence (no
  authority semantics).
* gov/decision_packet.py -- additive keyword-only ``decision_code``
  (None default, legacy packets byte-identical; attached code is
  signature-covered).

Attack shapes: unmapped refusal string presented to code_for; malformed
digest in reevaluate.evidence_digests; emitted code tampered to carry
authority; packet decision_code section swapped after signing; capsule
decision-code link swapped; unknown refusal string smuggled into a
packet section.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-227 HEAD
e42637b61e5c62c7289445e70c8e730ebfe8f4b3.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent) is
expected GAP. Determinism is run-twice over the whole battery.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g228c
  TMPDIR=/var/tmp/g228c ~/workspace/.gov-venv/bin/python evals/w228_codes_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g228c-u \\
      ~/workspace/.gov-venv/bin/python evals/w228_codes_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import json
import re
import subprocess
import sys
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import decision_codes as _dc
    from gov import decision_packet as _dp
    from gov import decision_bom as _bom
    from gov import action_capsule as _ac
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

# ---------------------------------------------------------------------------
# Independent refusal-vocabulary inventory.
#
# Re-implements the audited refusal idioms directly from source (never
# importing gov/decision_codes), so the coverage probe is independent
# of the module under test:
#
# Idiom 1: class-level machine code (``code = "some-refusal"``).
# Idiom 2: module-level constants (``FOO = "some-refusal"``) with a
#   refusal-flavoured suffix, OR demonstrably used as a code: raised
#   directly, passed as code=/code attr, passed to a code-first
#   exception constructor, or used as a "kind" finding value. The
#   usage check runs a 100-char lookbehind over the whole file so
#   multi-line raise sites count. Name-only constants are excluded
#   deliberately (e.g. *_PATH, *_ENV names).
# Idiom 3: code-first exception constructors -- public error classes
#   whose FIRST positional argument is the machine code, e.g.
#   TrustConfigError("config-body-malformed", ...).
# Idiom 4: dynamic self.code assignment (``self.code = "..."``).
# Idiom 5: reason="..." values (reason keyword only; the four
#   lifecycle status markers evaluated/manual/human_confirm/
#   uninitialized are not refusal codes).
# Idiom 6: _refuse*("...") refusal helpers (comment lines between
#   the paren and the literal are tolerated).
# Idiom 7: raise-site pre-colon literals
#   (``raise SomeError("some-code: detail")``), the approval_render.py
#   / presentation.py idiom. Lowercase-leading only: camelCase field
#   paths (claimBounds.proves) are field references, not codes.
# Idiom 8: PlatformEgressError("code: detail") literals.
#
# Deliberately excluded (audited, non-refusal machine strings):
#   envelope, jail, quorum, arap-context, read, write
#       -- generic words also used as codes elsewhere; excluded as
#          standalone refusal vocabulary
#   user, agent_action        -- intent_slice.py step kinds
#   lifecycle                 -- discovery_diff.py event kind
#   warm_retired              -- evidence_tiers.py journal event kind
#   ceremony-tip-manifest     -- custody.py manifest document kind
#   signer-share-store        -- custody.py store document kind
#   verify_chain,             -- checkpoints.py location label in a human
#   evidence_digest              exception message, not a machine code
#                                (wave-229 merge: audited, non-refusal)
# ---------------------------------------------------------------------------

_CLASS_ATTR_RE = re.compile(
    r'(?m)^\s*code\s*=\s*["\']([A-Za-z0-9_.-]+)["\']')
_CONST_DEF_RE = re.compile(
    r'(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*["\']([a-z0-9][a-z0-9_.-]*)["\']')
_REFUSAL_SUFFIX = (
    "_MISMATCH", "_DIVERGED", "_DRIFT", "_REFUSED", "_REPLAY_REFUSED",
    "_VIOLATION", "_REUSED", "_AMBIGUOUS_REFUSED", "_UNVERIFIABLE",
    "_UNBOUND", "_NOT_BOUND", "_NO_PTR", "_STALE",
)
# Public code-first exception classes: first positional arg is the code.
_CODE_FIRST_CLASSES = (
    "AdmissionError", "AuthorizationReceiptError", "BundleInspectionError",
    "C2PA24Error", "CardVerificationError", "CorpusManifestError",
    "DelegationError", "DetectionError", "GitSanitizeError",
    "GitSpawnHostileConfigError", "GitSanitizeUnparseableError",
    "GitSpawnInRepoRefusedError", "IdentityRejection", "InspectionError",
    "JailPCIError", "JailPolicyError", "ManifestVerificationError",
    "MeasurementPolicyError", "NamespaceError", "PackActivationError",
    "PolicyViolation", "QuarantineError", "RegistrationRefused",
    "RulePackError", "TrustConfigError", "VersionManifestError",
)
_CALL_RE = re.compile(
    r'\b(?:%s)\(\s*["\']([a-z0-9][a-z0-9_.-]*)["\']'
    % "|".join(_CODE_FIRST_CLASSES))
_DYNAMIC_RE = re.compile(
    r'self\.code\s*=\s*["\']([a-z0-9][a-z0-9_.-]*)["\']')
_REASON_KW_RE = re.compile(
    r'reason\s*=\s*["\']([a-z0-9][a-z0-9_.-]*)["\']')
_REASON_STATUS_MARKERS = frozenset(
    ["evaluated", "manual", "human_confirm", "uninitialized"])
_REFUSE_CALL_RE = re.compile(
    r'\b_refuse\w*\(\s*(?:#[^\n]*\n\s*)*["\']([a-z0-9][a-z0-9_.-]*)["\']')
_PRECOLON_RE = re.compile(
    r'\braise\s+\w+\(\s*["\']([a-z0-9][a-z0-9_.-]*[-_.][a-z0-9_.-]*):')
_EGRESS_RE = re.compile(
    r'\bPlatformEgressError\(\s*["\']([a-z0-9][a-z0-9_.-]+)(?::|\s*["\'])')
_NON_CODES = frozenset([
    "envelope", "jail", "quorum", "arap-context", "read", "write",
    "user", "agent_action", "lifecycle", "warm_retired",
    "ceremony-tip-manifest", "signer-share-store",
    "verify_chain", "evidence_digest",
    # Wave-270 lane (feat-evbundle): record-kind discriminators for the
    # v2 evidence bundle / submission records -- not refusal codes.
    "evidence-bundle.v2", "evidence-submission.v2", "evidence-artifact.v2",
    # Wave-311 merge: the sigstore-bundle witness kind discriminator
    # ("kind": WITNESS_KIND) -- a type tag, not a refusal code.
    "sasanam-witness",
    # Wave-312 lane D: the witness-log entry body kind discriminator
    # ("kind": WITNESS_ENTRY_BODY_KIND) -- a type tag, not a refusal
    # code.
    "sasanam-witness-log",
    # Wave-267 merge: gov/behavioral_sig_packs.py error-message prefixes
    # (function names, not decision codes).
    "enrich_event", "match_pack",
    # Wave-273 merge: gov/evidence_fanout.py + gov/anchorer.py queue-submit
    # reasons (drop-accounting labels in `dropped_by_reason`, not refusal
    # codes).
    "enqueue", "recover", "anchor-job", "retry",
    # Wave-281 merge: gov/pending_approvals.py digest-helper error-message
    # prefixes (function names in human ValueError messages, not decision
    # codes).
    "args_digest", "proposal_digest_of",
    # Wave-321 merge: gov/sigstore_bundle.py error-message prefix
    # (function name in a human ValueError message, not a decision code).
    "open_keyed_bundle",
    # Wave-335 merge: gov/policy.py + gov/tool_rate_limit.py config-key
    # prefix in human ValueError messages ("tool_rate_limits: ...",
    # "tool_rate_limits[%r]: ...") -- a policy section name, not a
    # decision code (the coded refusal is tool-rate-limit-config-invalid).
    "tool_rate_limits",
    # Wave-337 lane 5: gov/policy.py + gov/tool_budget.py config-key
    # prefix in human ValueError messages ("tool_budgets: ...",
    # "tool_budgets[%r]: ...") -- a policy section name, not a
    # decision code (the coded refusal is tool-budget-config-invalid).
    "tool_budgets",
])


def _const_used_as_code(text, name):
    for m in re.finditer(r'\b%s\b' % re.escape(name), text):
        pre = text[max(0, m.start() - 100):m.start()]
        if re.search(r'raise\s+\w+\(\s*$', pre):
            return True
        if re.search(r'(?:\(\s*|,\s*)code\s*=\s*$', pre):
            return True
        if re.search(r'\.code\s*=\s*$', pre):
            return True
        if re.search(r'\b(?:%s)\(\s*$' % "|".join(_CODE_FIRST_CLASSES),
                     pre):
            return True
        # finding-kind idiom: "kind": CONST
        if re.search(r'["\']kind["\']\s*:\s*$', pre):
            return True
    return False


def _scan_vocabulary():
    codes = set()
    govdir = os.path.join(REPO, "gov")
    for fname in sorted(os.listdir(govdir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(govdir, fname), "r",
                  encoding="utf-8") as fh:
            text = fh.read()
        for m in _CLASS_ATTR_RE.finditer(text):
            codes.add(m.group(1))
        for m in _CONST_DEF_RE.finditer(text):
            name, val = m.group(1), m.group(2)
            if name.endswith(_REFUSAL_SUFFIX) or \
                    _const_used_as_code(text, name):
                codes.add(val)
        for m in _CALL_RE.finditer(text):
            codes.add(m.group(1))
        for m in _DYNAMIC_RE.finditer(text):
            codes.add(m.group(1))
        for m in _REASON_KW_RE.finditer(text):
            if m.group(1) not in _REASON_STATUS_MARKERS:
                codes.add(m.group(1))
        for m in _REFUSE_CALL_RE.finditer(text):
            codes.add(m.group(1))
        for m in _EGRESS_RE.finditer(text):
            codes.add(m.group(1))
        for m in _PRECOLON_RE.finditer(text):
            if m.group(1) not in _NON_CODES:
                codes.add(m.group(1))
    codes -= _NON_CODES
    # Curated: memory-inbox pending-review reasons are refusal strings
    # by construction (fail-closed pending review), not literals.
    codes.update({"untrusted_tier", "tainted_run", "carrier_mismatch"})
    return codes


VOCAB = _scan_vocabulary()

PROBE_NAMES = [
    "codes-01-vocabulary-covered",
    "codes-02-unmapped-fails-closed",
    "codes-03-reevaluate-pointer",
    "codes-04-digest-shaped",
    "codes-05-packet-signature-covers",
    "codes-06-packet-legacy-bytes-identical",
    "codes-07-authority-refused",
    "codes-08-capsule-attach",
    "codes-09-spot-domains",
    "codes-10-taxonomy-wellformed",
    "codes-11-emitted-never-authority",
    "codes-12-verify-replays-code",
    "codes-13-bad-input-fails-closed",
]


def _refuses_code(fn, code):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _minimal_kwargs(**over):
    kw = dict(decision="allow", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              policy_id="default", policy_version="unversioned",
              issued_at="2026-09-28T00:00:00+00:00")
    kw.update(over)
    if "bill_of_materials" not in over:
        kw["bill_of_materials"] = _bom.build_bom(
            policy_id=kw["policy_id"],
            policy_version=kw["policy_version"],
            policy_digest="ab" * 32,
            evidence_head_digest=kw["evidence_head_digest"],
            principal={"agent_id": None, "role": None,
                       "principal": None, "run_id": None})
    return kw


_SEED = bytes.fromhex("11" * 32)
_GOOD_DIGESTS = ("ab" * 32, "cd" * 32)


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP",
                "gov.decision_codes absent on this tree")
        return results

    # codes-01: every refusal string the repo emits has a mapping.
    try:
        missing = []
        for code in sorted(VOCAB):
            try:
                _dc.code_for(code)
            except Exception:  # noqa: BLE001
                missing.append(code)
        ok = not missing
        rec("codes-01-vocabulary-covered", "HELD" if ok else "BREAK",
            "%d/%d refusal strings mapped%s"
            % (len(VOCAB) - len(missing), len(VOCAB),
               ("" if ok else "; missing: " + ",".join(missing[:5]))))
    except Exception as exc:  # noqa: BLE001
        rec("codes-01-vocabulary-covered", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-02: an unmapped refusal string fails closed.
    try:
        held = _refuses_code(
            lambda: _dc.code_for("no-such-refusal-code-xyz"),
            "decision-code-unmapped")
        rec("codes-02-unmapped-fails-closed", "HELD" if held else "BREAK",
            "unknown refusal fails closed" if held
            else "unknown refusal did not fail closed")
    except Exception as exc:  # noqa: BLE001
        rec("codes-02-unmapped-fails-closed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-03: every emitted code carries the reevaluate pointer.
    try:
        sample = ["capsule-count-mismatch", "receipt-pair-decision-drift",
                  "permit-revoked", "gitspawn-hostile-config",
                  "svr-no-reproduction-pointer", "reverify-stale",
                  "key-identity-revoked", "rollback-detected",
                  "effect-status-refused", "decision-labels-invalid"]
        bad = []
        for code in sample:
            mc = _dc.emit(code, evidence_digests=_GOOD_DIGESTS)
            ree = mc.get("reevaluate")
            if not isinstance(ree, dict):
                bad.append(code + ":no-reevaluate")
                continue
            if ree.get("evidence_digests") != list(_GOOD_DIGESTS):
                bad.append(code + ":digests-not-carried")
            if not ree.get("reverify_steps"):
                bad.append(code + ":no-steps")
        ok = not bad
        rec("codes-03-reevaluate-pointer", "HELD" if ok else "BREAK",
            "reevaluate pointer present on %d sampled codes" % len(sample)
            if ok else "; ".join(bad))
    except Exception as exc:  # noqa: BLE001
        rec("codes-03-reevaluate-pointer", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-04: evidence digests must be digest-shaped.
    try:
        ok_good = True
        try:
            _dc.emit("capsule-count-mismatch",
                     evidence_digests=_GOOD_DIGESTS)
        except Exception:  # noqa: BLE001
            ok_good = False
        bad1 = _refuses_code(
            lambda: _dc.emit("capsule-count-mismatch",
                             evidence_digests=("zzz",)),
            "decision-code-digest-malformed")
        bad2 = _refuses_code(
            lambda: _dc.emit("capsule-count-mismatch",
                             evidence_digests=(123,)),
            "decision-code-digest-malformed")
        ok = ok_good and bad1 and bad2
        rec("codes-04-digest-shaped", "HELD" if ok else "BREAK",
            "digest-shaped accepted, malformed refused" if ok
            else "digest validation gap (good=%r bad1=%r bad2=%r)"
            % (ok_good, bad1, bad2))
    except Exception as exc:  # noqa: BLE001
        rec("codes-04-digest-shaped", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-05: a packet-attached decision code is signature-covered.
    try:
        body = _dp.build_decision_packet(
            **_minimal_kwargs(decision_code="capsule-count-mismatch"))
        pkt = _dp.sign_packet(body, _SEED)
        ok, _reason = _dp.verify_decision_packet(pkt)
        tampered = copy.deepcopy(pkt)
        tampered["decision_code"]["value"]["refusal"] = "permit-revoked"
        ok2, _reason2 = _dp.verify_decision_packet(tampered)
        held = ok and not ok2
        rec("codes-05-packet-signature-covers", "HELD" if held else "BREAK",
            "attached code verifies; swapped code breaks signature"
            if held else "signature coverage gap (ok=%r tampered_ok=%r)"
            % (ok, ok2))
    except Exception as exc:  # noqa: BLE001
        rec("codes-05-packet-signature-covers", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-06: legacy packet bytes are unchanged by the additive kwarg.
    try:
        legacy = _dp.build_decision_packet(**_minimal_kwargs())
        explicit = _dp.build_decision_packet(
            **_minimal_kwargs(decision_code=None))
        b1 = _dp._canonical(legacy)
        b2 = _dp._canonical(explicit)
        held = b1 == b2
        rec("codes-06-packet-legacy-bytes-identical",
            "HELD" if held else "BREAK",
            "legacy body byte-identical" if held
            else "legacy body changed by additive kwarg")
    except Exception as exc:  # noqa: BLE001
        rec("codes-06-packet-legacy-bytes-identical", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-07: authority-shaped use of a decision code is refused.
    try:
        mc = _dc.emit("capsule-count-mismatch")
        bad = copy.deepcopy(mc)
        bad["authority"] = True
        r1 = _refuses_code(lambda: _dc.require_evidence_only(bad),
                           "decision-code-not-authorization")
        bad2 = copy.deepcopy(mc)
        bad2["grants"] = ["tool:exec"]
        r2 = _refuses_code(lambda: _dc.require_evidence_only(bad2),
                           "decision-code-not-authorization")
        ok3 = _dc.require_evidence_only(mc) is True
        held = r1 and r2 and ok3
        rec("codes-07-authority-refused", "HELD" if held else "BREAK",
            "authority-shaped use refused; evidence use passes" if held
            else "authority boundary gap (flag=%r grants=%r clean=%r)"
            % (r1, r2, ok3))
    except Exception as exc:  # noqa: BLE001
        rec("codes-07-authority-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-08: decision-code evidence composes into action capsules by
    # digest linkage, with no authority semantics.
    try:
        cap = _ac.seal_capsule({"attempt": {"tool": "t", "args": {}},
                                "effect": {"status": "refused",
                                           "code": "receipt-pair-decision-drift",
                                           "evidence": "evidence-bundle"}})
        mc = _dc.emit("receipt-pair-decision-drift",
                      evidence_digests=_GOOD_DIGESTS)
        linked = _dc.attach_decision_code(cap, mc)
        got = _dc.verify_capsule_decision_code(linked, mc)
        recomputed = _dc.machine_code_digest(mc)
        link_ok = got == recomputed
        # A valid machine code for a different refusal breaks the link.
        alt = _dc.emit("permit-revoked", evidence_digests=_GOOD_DIGESTS)
        tamper_refused = _refuses_code(
            lambda: _dc.verify_capsule_decision_code(linked, alt),
            "decision-code-digest-mismatch")
        held = link_ok and tamper_refused
        rec("codes-08-capsule-attach", "HELD" if held else "BREAK",
            "digest-linked; tampered code breaks the link" if held
            else "capsule composition gap (link=%r tamper=%r)"
            % (link_ok, tamper_refused))
    except Exception as exc:  # noqa: BLE001
        rec("codes-08-capsule-attach", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-09: spot-check domain/severity assignments on independent
    # vectors (not derived from the module's own table).
    try:
        vectors = {
            "capsule-count-mismatch": ("capsule", "critical"),
            "permit-revoked": ("permit", None),
            "decision-labels-invalid": ("decision", None),
            "gitspawn-hostile-config": ("gitspawn", None),
            "svr-no-reproduction-pointer": ("svr", None),
            "reverify-stale": ("reverify", None),
            "single-use-replay-refused": ("single_use", "high"),
        }
        bad = []
        for code, (domain, sev) in vectors.items():
            got = _dc.code_for(code)
            if got["domain"] != domain:
                bad.append("%s domain=%s want %s"
                           % (code, got["domain"], domain))
            if sev and got["severity"] != sev:
                bad.append("%s severity=%s want %s"
                           % (code, got["severity"], sev))
        ok = not bad
        rec("codes-09-spot-domains", "HELD" if ok else "BREAK",
            "spot vectors hold" if ok else "; ".join(bad))
    except Exception as exc:  # noqa: BLE001
        rec("codes-09-spot-domains", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-10: the taxonomy is well-formed and closed.
    try:
        sev_ok = {"low", "medium", "high", "critical"}
        bad = []
        for code, entry in _dc.TAXONOMY.items():
            if not isinstance(entry, dict):
                bad.append(code + ":not-dict")
                continue
            for key in ("domain", "code", "human", "severity",
                        "evidence_kinds_required", "reverify_steps"):
                if key not in entry:
                    bad.append("%s:missing-%s" % (code, key))
            if entry.get("code") != code:
                bad.append("%s:code-mismatch" % code)
            if entry.get("severity") not in sev_ok:
                bad.append("%s:bad-severity" % code)
            if not entry.get("human"):
                bad.append("%s:empty-human" % code)
            for key in ("evidence_kinds_required", "reverify_steps"):
                val = entry.get(key)
                if not isinstance(val, list) or not val:
                    bad.append("%s:empty-%s" % (code, key))
        ok = not bad
        rec("codes-10-taxonomy-wellformed", "HELD" if ok else "BREAK",
            "%d entries well-formed" % len(_dc.TAXONOMY)
            if ok else "; ".join(bad[:8]))
    except Exception as exc:  # noqa: BLE001
        rec("codes-10-taxonomy-wellformed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-11: emitted codes never carry authority.
    try:
        mc = _dc.emit("effect-status-refused")
        held = (mc.get("authority") is False
                and _dc.require_evidence_only(mc) is True)
        rec("codes-11-emitted-never-authority", "HELD" if held else "BREAK",
            "emitted code is evidence-only" if held
            else "emitted code carries authority semantics")
    except Exception as exc:  # noqa: BLE001
        rec("codes-11-emitted-never-authority", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-12: packet verification replays the attached code against
    # the live taxonomy -- a section naming an unmapped refusal is
    # rejected, not trusted.
    try:
        body = _dp.build_decision_packet(
            **_minimal_kwargs(decision_code="effect-status-refused"))
        pkt = _dp.sign_packet(body, _SEED)
        forged = copy.deepcopy(body)
        forged["decision_code"]["value"]["refusal"] = \
            "no-such-refusal-code-xyz"
        forged["decision_code"]["value"]["code"] = "no-such-refusal-code-xyz"
        # A forged section cannot survive the signature either way, but
        # the verifier must ALSO refuse the code at the taxonomy seam.
        held_sig = _dp.verify_decision_packet(
            _dp.sign_packet(forged, _SEED))[0] is False
        held = held_sig
        rec("codes-12-verify-replays-code", "HELD" if held else "BREAK",
            "unmapped refusal in section is rejected" if held
            else "verifier trusted an unmapped section code")
    except Exception as exc:  # noqa: BLE001
        rec("codes-12-verify-replays-code", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # codes-13: bad input fails closed at every seam.
    try:
        r1 = _refuses_code(lambda: _dc.code_for(""),
                           "decision-code-unmapped")
        r2 = _refuses_code(lambda: _dc.code_for(None),
                           "decision-code-unmapped")
        r3 = _refuses_code(lambda: _dc.emit(None),
                           "decision-code-unmapped")
        r4 = _refuses_code(
            lambda: _dp.build_decision_packet(
                **_minimal_kwargs(decision_code="no-such-code")),
            "decision-code-unmapped")
        r5 = _refuses_code(
            lambda: _dc.attach_decision_code("not-a-capsule",
                                             _dc.emit("effect-status-refused")),
            "decision-code-malformed")
        held = r1 and r2 and r3 and r4 and r5
        rec("codes-13-bad-input-fails-closed", "HELD" if held else "BREAK",
            "empty/None/unknown/malformed all fail closed" if held
            else "fail-closed gap (%r,%r,%r,%r,%r)" % (r1, r2, r3, r4, r5))
    except Exception as exc:  # noqa: BLE001
        rec("codes-13-bad-input-fails-closed", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_decision_codes.py",
                 "tests/test_decision_packet.py",
                 "tests/test_action_capsule.py",
                 "tests/test_effect_status.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w228 decision-code probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
