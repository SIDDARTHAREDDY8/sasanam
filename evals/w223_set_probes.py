#!/usr/bin/env python3
"""Wave-223 lane A: posture signals (signed, scope-bound, never authority).

ADAPT of the EMILIA PIP-011 EP-EYE-SET-v1 pattern (re-derived prose;
nothing copied): when revocation or denial events occur, the system
emits a signed posture SIGNAL record shaped like an RFC 8417 Security
Event Token — {iss, jti, iat, sub, events, scope} — riding IN-BAND
with the decision, never as the decision. The key invariant: a signal
is NEVER the sole gate; offering a signal where authorization is
required fails closed with ``signal-not-authorization``.

Seams under test:
* gov/posture.py — emit_signal(event, subject_digest, scope,
  issuer_seed, *, issuer_id, kind=None) -> PostureSignal {v, iss,
  jti, iat, sub, events, scope, signature} (domain
  sasanam-posture/v1:, vendored Ed25519); verify_signal(signal,
  issuer_pubkeys, require_scope=None); scope mismatch ->
  signal-scope-mismatch; unsigned/forged/tampered ->
  signal-unverifiable; unknown event -> signal-unknown-event;
  missing/unknown kind -> signal-kind-required /
  signal-unknown-kind; signal_carries_no_authority (spec-named
  guard; require_authorization kept as an alias) refuses
  signal-not-authorization for signals AND stripped fragments,
  while real non-signal records (incl. attestation statements
  with iss/jti) pass through.
* emit_absence_signal(issuer, subject_digest, scope, ...) —
  composes gov/absence.py: attests through the issuer's absence
  machinery and signs the signal with the absence claim as the
  kind (never-advertised / advertised-but-missing / revoked).
* gov/revocation.py additive hook — RevocationList(audit=None,
  signal_issuer=None, signal_sink=None): revoke() emits a signed
  revocation signal when signal_issuer=(issuer_id, seed, scope)
  is configured and hands it to signal_sink; without both
  configured, legacy behavior byte-identical.

Attack shapes: tampered sub, forged issuer key, signal laundered
as an authorization grant, signal with a field stripped (fragment
evasion), cross-scope replay, unknown event vocabulary, unknown
kind, silent signal drop (no audit entry).

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-222 HEAD
d7f377aaf1a9ccf095cc4e0535eb9f74fa8f7fc9.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP — only
the no-hook legacy revocation pin is verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g223s
  TMPDIR=/var/tmp/g223s ~/workspace/.gov-venv/bin/python evals/w223_set_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g223s-u \\
      ~/workspace/.gov-venv/bin/python evals/w223_set_probes.py
"""

import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w223-set-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g223s-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import posture as po  # noqa: E402
    _POSTURE_OK = True
except Exception as exc:  # noqa: BLE001 - import probe records it
    _POSTURE_OK = False
    po = None

try:
    from gov import revocation as rv  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    _CORE_OK = True
    _CORE_ERR = None
except Exception as exc:  # noqa: BLE001 - import probe records it
    _CORE_OK = False
    _CORE_ERR = exc
    rv = _ed = None

_IMPORT_OK = _POSTURE_OK and _CORE_OK
_IMPORT_ERR = None if _POSTURE_OK else "gov.posture absent (pristine)"

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _gap(name, detail="absent on base"):
    _record(name, "GAP", detail)


def _break(name, detail):
    _record(name, "BREAK", detail)


def _code_of(exc):
    return getattr(exc, "code", exc.__class__.__name__)


def _expect_refusal(name, code, fn):
    """BREAK unless fn raises an exception carrying ``code``."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        if _code_of(exc) == code:
            _held(name, "refused %s" % code)
            return True
        _break(name, "wrong code: %r, expected %r" % (_code_of(exc), code))
        return False
    _break(name, "no refusal raised for %s" % code)
    return False


def _keypair():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _emit(now=1700000000.0, event="revocation", sub=_DIGEST_A,
          scope="permit", issuer_id="posture-issuer", kind=None):
    seed, pub = _keypair()
    audit = []
    sig = po.emit_signal(event, sub, scope, seed,
                         issuer_id=issuer_id,
                         audit=audit.append, now=now, kind=kind)
    return sig, pub, seed, audit


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------


@_probe("signal-verifies")
def _p_verify():
    if not _IMPORT_OK:
        return _gap("signal-verifies")
    sig, pub, _seed, _audit = _emit()
    rec = po.verify_signal(sig, {"posture-issuer": pub})
    if rec["sub"] != _DIGEST_A or rec["scope"] != "permit":
        return _break("signal-verifies",
                      "verified record lost sub/scope: %r" % (rec,))
    if "urn:sasanam:posture:v1:revocation" not in rec["events"]:
        return _break("signal-verifies",
                      "event URI missing from events map")
    _held("signal-verifies", "round-trip OK, event URI present")


@_probe("tampered-signal-fails")
def _p_tamper():
    if not _IMPORT_OK:
        return _gap("tampered-signal-fails")
    sig, pub, _seed, _audit = _emit()
    sig["sub"] = _DIGEST_B
    _expect_refusal("tampered-signal-fails", "signal-unverifiable",
                    lambda: po.verify_signal(
                        sig, {"posture-issuer": pub}))


@_probe("forged-issuer-fails")
def _p_forge():
    if not _IMPORT_OK:
        return _gap("forged-issuer-fails")
    sig, _pub, _seed, _audit = _emit()
    _wrong_seed, wrong_pub = _keypair()
    _expect_refusal("forged-issuer-fails", "signal-unverifiable",
                    lambda: po.verify_signal(
                        sig, {"posture-issuer": wrong_pub}))


@_probe("signal-not-authorization")
def _p_no_authority():
    if not _IMPORT_OK:
        return _gap("signal-not-authorization")
    sig, pub, _seed, _audit = _emit()
    # The signal is verified first — it is a GOOD signal — and must
    # still be refused when offered where authorization is required.
    # The spec-named guard is the contract; the alias behaves the same.
    rec = po.verify_signal(sig, {"posture-issuer": pub})
    _expect_refusal("signal-not-authorization", "signal-not-authorization",
                    lambda: po.signal_carries_no_authority(rec))
    _expect_refusal("signal-not-authorization", "signal-not-authorization",
                    lambda: po.require_authorization(rec))


@_probe("fragment-guard")
def _p_fragment():
    if not _IMPORT_OK:
        return _gap("fragment-guard")
    sig, _pub, _seed, _audit = _emit()
    # Strip one field: no longer a full signal, but unmistakably a
    # signal fragment — ambiguity fails closed.
    frag = {k: v for k, v in sig.items() if k != "events"}
    _expect_refusal("fragment-guard", "signal-not-authorization",
                    lambda: po.signal_carries_no_authority(frag))


@_probe("non-signal-passes-guard")
def _p_guard_passthrough():
    if not _IMPORT_OK:
        return _gap("non-signal-passes-guard")
    # The guard is surgical: plain records are not signals and pass
    # through unchanged.
    plain = {"permit_id": "p1", "grant": True}
    if po.require_authorization(plain) is not plain:
        return _break("non-signal-passes-guard",
                      "guard mutated or refused a non-signal record")
    _held("non-signal-passes-guard", "plain record passes through")


@_probe("scope-bound")
def _p_scope():
    if not _IMPORT_OK:
        return _gap("scope-bound")
    sig, pub, _seed, _audit = _emit(scope="permit")
    # Right scope: verifies.
    po.verify_signal(sig, {"posture-issuer": pub},
                     require_scope="permit")
    # Cross-scope replay: refuses with the scope code, not silence.
    _expect_refusal("scope-bound", "signal-scope-mismatch",
                    lambda: po.verify_signal(
                        sig, {"posture-issuer": pub},
                        require_scope="admission"))


@_probe("revocation-emits-signal")
def _p_revoke_signal():
    if not _IMPORT_OK:
        return _gap("revocation-emits-signal")
    seed, pub = _keypair()
    emitted = []
    rl = rv.RevocationList(signal_issuer=("rev-issuer", seed, "permit"),
                           signal_sink=emitted.append)
    rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=seed)
    if not emitted:
        return _break("revocation-emits-signal",
                      "revoke() emitted no signal")
    rec = po.verify_signal(emitted[0], {"rev-issuer": pub},
                           require_scope="permit")
    if rec["sub"] != _DIGEST_A:
        return _break("revocation-emits-signal",
                      "signal sub is not the revoked digest")
    _held("revocation-emits-signal", "revoke emitted verifiable signal")


@_probe("signals-ride-audit-trail")
def _p_audit():
    if not _IMPORT_OK:
        return _gap("signals-ride-audit-trail")
    _sig, _pub, _seed, audit = _emit(event="admission-refusal",
                                    kind="admission-digest-mismatch")
    entries = [e for e in audit if e.get("event") == "posture_signal"]
    if not entries:
        return _break("signals-ride-audit-trail",
                      "no posture_signal entry in the audit trail")
    if entries[0].get("scope") != "permit" or not entries[0].get("jti"):
        return _break("signals-ride-audit-trail",
                      "audit entry missing scope/jti: %r" % (entries[0],))
    _held("signals-ride-audit-trail", "in-band audit entry present")


@_probe("absence-signal-composes")
def _p_absence_composes():
    if not _IMPORT_OK:
        return _gap("absence-signal-composes")
    try:
        from gov import absence as _ab
    except Exception:  # noqa: BLE001
        return _gap("absence-signal-composes", "gov.absence absent")
    seed, pub = _keypair()
    issuer = _ab.AbsenceIssuer("abs-issuer", seed)
    # Case 1: never advertised.
    sig1 = po.emit_absence_signal(issuer, _DIGEST_A, "admission",
                                  now=1700000000.0)
    rec1 = po.verify_signal(sig1, {"abs-issuer": pub},
                            require_scope="admission")
    kinds1 = [p.get("kind") for p in rec1["events"].values()]
    # Case 2: advertised, then missing.
    issuer.advertise(_DIGEST_B)
    sig2 = po.emit_absence_signal(issuer, _DIGEST_B, "admission",
                                  now=1700000000.0)
    rec2 = po.verify_signal(sig2, {"abs-issuer": pub})
    kinds2 = [p.get("kind") for p in rec2["events"].values()]
    # Case 3: revoked.
    rl = rv.RevocationList()
    rl.revoke(_DIGEST_A, issuer_id="rev", seed=seed)
    sig3 = po.emit_absence_signal(issuer, _DIGEST_A, "admission",
                                  revocation=rl, now=1700000000.0)
    rec3 = po.verify_signal(sig3, {"abs-issuer": pub})
    kinds3 = [p.get("kind") for p in rec3["events"].values()]
    if (kinds1, kinds2, kinds3) != (["never-advertised"],
                                    ["advertised-but-missing"],
                                    ["revoked"]):
        return _break("absence-signal-composes",
                      "claims not discriminated: %r %r %r"
                      % (kinds1, kinds2, kinds3))
    _held("absence-signal-composes",
          "absence claims ride the signal as kinds")


@_probe("permit-refusal-kinds")
def _p_kinds():
    if not _IMPORT_OK:
        return _gap("permit-refusal-kinds")
    sig_a, pub_a, _s, _a = _emit(event="permit-refusal",
                                kind="permit-revoked")
    sig_b, _pb, _sb, _ab2 = _emit(event="permit-refusal",
                                  kind="approval-digest-diverged")
    ka = [p.get("kind") for p in sig_a["events"].values()]
    kb = [p.get("kind") for p in sig_b["events"].values()]
    if ka != ["permit-revoked"] or kb != ["approval-digest-diverged"]:
        return _break("permit-refusal-kinds",
                      "refusal causes not discriminated: %r %r"
                      % (ka, kb))
    po.verify_signal(sig_a, {"posture-issuer": pub_a})
    _held("permit-refusal-kinds",
          "permit-revoked vs approval-digest-diverged discriminated")


@_probe("kind-required")
def _p_kind_required():
    if not _IMPORT_OK:
        return _gap("kind-required")
    _expect_refusal("kind-required", "signal-kind-required",
                    lambda: _emit(event="permit-refusal"))


@_probe("unknown-kind-refused")
def _p_unknown_kind():
    if not _IMPORT_OK:
        return _gap("unknown-kind-refused")
    _expect_refusal("unknown-kind-refused", "signal-unknown-kind",
                    lambda: _emit(event="permit-refusal",
                                 kind="launch-the-missiles"))


@_probe("attestation-statement-passes-guard")
def _p_statement_passthrough():
    if not _IMPORT_OK:
        return _gap("attestation-statement-passes-guard")
    # A real attestation-release statement carries iss/jti/sub/iat
    # but is NOT a posture signal — the guard must not touch it.
    statement = {"format": "sasanam-attestation/v1",
                 "sub": _DIGEST_A, "iss": "attester", "aud": "ops",
                 "status": "affirming", "iat": "2023-11-14T22:13:20Z",
                 "exp": "2023-11-14T23:13:20Z",
                 "jti": "stmt-1", "agent_scope": "deploy",
                 "session": {"agent_id": "a", "run_id": "r"}}
    if po.signal_carries_no_authority(statement) is not statement:
        return _break("attestation-statement-passes-guard",
                      "guard refused a non-signal attestation record")
    # A record with a non-posture events LIST is also not a signal.
    sweep = {"events": [{"gap": "x"}]}
    if po.signal_carries_no_authority(sweep) is not sweep:
        return _break("attestation-statement-passes-guard",
                      "guard refused a non-posture events record")
    _held("attestation-statement-passes-guard",
          "non-signal records pass through")


@_probe("legacy-revoke-identical")
def _p_legacy():
    # Verifiable on pristine base: revoking without the hook must
    # behave exactly as before — no signal, same entry shape.
    if not _CORE_OK:
        return _gap("legacy-revoke-identical",
                    "revocation module not importable in this harness")
    seed = _ed.generate_seed()
    audit = []
    rl = rv.RevocationList(audit=audit.append)
    entry = rl.revoke(_DIGEST_A, issuer_id="legacy-issuer", seed=seed)
    if rl.check(_DIGEST_A) != "revoked":
        return _break("legacy-revoke-identical", "check lost revocation")
    if set(entry) != {"v", "target_digest", "issuer_id", "revoked_at",
                      "signature"}:
        return _break("legacy-revoke-identical",
                      "entry shape changed: %r" % sorted(entry))
    if [e for e in audit if e.get("event") != "revoked"]:
        return _break("legacy-revoke-identical",
                      "audit gained non-legacy entries")
    _held("legacy-revoke-identical", "no-hook revoke unchanged")


@_probe("unknown-event-refused")
def _p_unknown_event():
    if not _IMPORT_OK:
        return _gap("unknown-event-refused")
    _expect_refusal("unknown-event-refused", "signal-unknown-event",
                    lambda: _emit(event="launch-the-missiles"))


@_probe("determinism")
def _p_determinism():
    if not _IMPORT_OK:
        return _gap("determinism")
    seed, _pub = _keypair()  # FIXED seed: determinism is same inputs
    audit1, audit2 = [], []
    sig1 = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                         issuer_id="posture-issuer",
                         audit=audit1.append, now=1700000000.0)
    sig2 = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                         issuer_id="posture-issuer",
                         audit=audit2.append, now=1700000000.0)
    if sig1["signature"] != sig2["signature"]:
        return _break("determinism", "emit nondeterministic under fixed clock")
    if sig1["jti"] != sig2["jti"]:
        return _break("determinism", "jti nondeterministic under fixed clock")
    _held("determinism", "signatures deterministic under fixed clock")


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
    # GOV_SKIP_GREEN=1 so the nesting never compounds. Adjacent
    # regression coverage for the revocation.py change rides the
    # battery's own green check so it cannot be silently dropped.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_absence_revocation.py",
                 "tests/test_permit_leases.py",
                 "tests/test_admission.py",
                 "tests/test_digest_link.py",
                 "tests/test_attestation_release.py",
                 "tests/test_posture.py"):
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
    print("w223 posture probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in _RESULTS:
        print("  %-32s %s %s" % (name, verdict, detail))
    for name, status, detail in green:
        print("  %-32s %s %s" % (name, status, detail))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
