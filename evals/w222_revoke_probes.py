#!/usr/bin/env python3
"""Wave-222 lane C: signed absence-attribution + exact-target revocation.

ADAPT of the SEP-0000 absence-attribution pattern and the EMILIA
PIP-011 EP-REVOCATION-v1 pattern (both re-derived; no EMILIA text
copied). Silence is never an acceptable answer: a missing credential
must arrive as a SIGNED negative outcome whose claim distinguishes
"never advertised by this issuer" from "advertised but missing".
Revocation pins EXACT digests only — a prefix or a class can never be
revoked.

Seams under test:
* gov/absence.py — AbsenceIssuer.attest_absence(subject_digest) ->
  SignedNegative {subject_digest, claim, revocation_target, issued_at,
  issuer_id, signature}; verify_negative(negative, pubkey);
  evaluate_negative(negative, pubkey) raises the claim-specific code:
  absence-never-advertised / absence-advertised-but-missing /
  absence-revoked; unsigned or forged negatives refuse
  absence-unverifiable.
* gov/revocation.py — RevocationList.revoke(target_digest, issuer_id,
  seed) signs an exact-target entry (domain sasanam-revocation/v1:);
  revoke() refuses revocation-inexact-target-refused for anything but
  a full 64-hex digest; check(target_digest) -> "revoked" | "active";
  export()/import_entries(entries, issuer_pubkeys) verifies signatures
  against the pinned keyset (bad entry ->
  revocation-entry-unverifiable).
* gov/permit_leases.py wiring — PermitRegistry(..., revocation_registry)
  and PermitLease.redeem(..., revocation_registry): a revoked lease
  digest refuses permit-revoked even when the digest is otherwise
  valid; no registry -> legacy behavior byte-identical.

Attack shapes: forged issuer signature, unsigned negative, tampered
claim, prefix/class revocation, revoked-lease redemption with the
correct digest, unrevoked-lease unaffected, wrong-keyset import.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-221 HEAD
194588b78321b7d8b9bc454799c55a32ca2756e3.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (modules absent) is expected GAP — the
no-registry legacy pin is verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g222r
  TMPDIR=/var/tmp/g222r ~/workspace/.gov-venv/bin/python evals/w222_revoke_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g222r-u \\
      ~/workspace/.gov-venv/bin/python evals/w222_revoke_probes.py
"""

import os
import secrets
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w222-revoke-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g222r-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import absence as ab  # noqa: E402
    from gov import revocation as rv  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no modules
    ab = rv = _ed = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

from gov import permit_leases as pl  # noqa: E402 - present on base

_RESULTS = []


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md): this battery
# records HELD/GAP/BREAK/ERROR on probes and PASS/SKIP/FAIL on its
# depth-1 green checks; the canonical emission vocabulary is
# BREAK/HELD/ERROR/SKIP, mapped red-first (PASS->HELD, GAP/FAIL->BREAK).
# Probe logic, verdict computation and count code are untouched -- only
# the print loop below maps.
_VERDICT_MAP = {
    "PASS": "HELD", "HELD": "HELD", "GREEN": "HELD",
    "FAIL": "BREAK", "BROKEN": "BREAK", "GAP": "BREAK",
    "RED": "BREAK", "BREAK": "BREAK",
    "ERROR": "ERROR", "SKIP": "SKIP", "SKIPPED": "SKIP",
}
_PROBE_FNS = {}

_DIGEST_A = "aa" * 32  # 64-hex stand-in digests
_DIGEST_B = "bb" * 32
_DIGEST_C = "cc" * 32


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


def _issuer():
    seed = _ed.generate_seed()
    return ab.AbsenceIssuer("issuer-1", seed), seed


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("never-vs-advertised-distinguished")
def _p_distinguish():
    if not _IMPORT_OK:
        return _gap("never-vs-advertised-distinguished")
    issuer, _seed = _issuer()
    pub = _ed.publickey(issuer.seed)
    never = issuer.attest_absence(_DIGEST_A)
    issuer.advertise(_DIGEST_B)
    missing = issuer.attest_absence(_DIGEST_B)
    # The claims must differ, and the consumer must distinguish them.
    if never["claim"] == missing["claim"]:
        return _break("never-vs-advertised-distinguished",
                      "claims identical: %r" % (never["claim"],))
    try:
        ab.evaluate_negative(never, pub)
    except Exception as exc:
        code_never = _code_of(exc)
    else:
        return _break("never-vs-advertised-distinguished",
                      "never-advertised evaluated without refusal")
    try:
        ab.evaluate_negative(missing, pub)
    except Exception as exc:
        code_missing = _code_of(exc)
    else:
        return _break("never-vs-advertised-distinguished",
                      "advertised-but-missing evaluated without refusal")
    if code_never != "absence-never-advertised":
        return _break("never-vs-advertised-distinguished",
                      "wrong code for never-advertised: %s" % code_never)
    if code_missing != "absence-advertised-but-missing":
        return _break("never-vs-advertised-distinguished",
                      "wrong code for advertised-but-missing: %s"
                      % code_missing)
    _held("never-vs-advertised-distinguished",
          "never-advertised vs advertised-but-missing distinguished")


@_probe("unsigned-negative-refused")
def _p_unsigned():
    if not _IMPORT_OK:
        return _gap("unsigned-negative-refused")
    issuer, _seed = _issuer()
    pub = _ed.publickey(issuer.seed)
    neg = issuer.attest_absence(_DIGEST_A)
    tampered = dict(neg)
    tampered["signature"] = "00" * 64  # 64 zero bytes, valid length
    _expect_refusal("unsigned-negative-refused", "absence-unverifiable",
                    lambda: ab.evaluate_negative(tampered, pub))
    missing_sig = dict(neg)
    del missing_sig["signature"]
    _expect_refusal("unsigned-negative-refused", "absence-unverifiable",
                    lambda: ab.evaluate_negative(missing_sig, pub))


@_probe("forged-issuer-refused")
def _p_forged():
    if not _IMPORT_OK:
        return _gap("forged-issuer-refused")
    issuer, _seed = _issuer()
    other_seed = _ed.generate_seed()
    other_issuer = ab.AbsenceIssuer("issuer-1", other_seed)
    pub = _ed.publickey(issuer.seed)
    forged = other_issuer.attest_absence(_DIGEST_A)
    # Same issuer_id label, wrong key: the signature must not verify.
    _expect_refusal("forged-issuer-refused", "absence-unverifiable",
                    lambda: ab.evaluate_negative(forged, pub))


@_probe("revoked-claim-signed")
def _p_revoked_claim():
    if not _IMPORT_OK:
        return _gap("revoked-claim-signed")
    issuer, _seed = _issuer()
    pub = _ed.publickey(issuer.seed)
    rl = rv.RevocationList()
    rl.revoke(_DIGEST_C, issuer_id="issuer-1", seed=issuer.seed)
    neg = issuer.attest_absence(_DIGEST_C, revocation=rl)
    if neg["claim"] != "revoked":
        return _break("revoked-claim-signed",
                      "expected claim revoked, got %r" % (neg["claim"],))
    if neg["revocation_target"] != _DIGEST_C:
        return _break("revoked-claim-signed",
                      "revocation_target not the exact digest")
    _expect_refusal("revoked-claim-signed", "absence-revoked",
                    lambda: ab.evaluate_negative(neg, pub))


@_probe("exact-digest-revokes")
def _p_exact():
    if not _IMPORT_OK:
        return _gap("exact-digest-revokes")
    seed = _ed.generate_seed()
    rl = rv.RevocationList()
    rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=seed)
    if rl.check(_DIGEST_A) != "revoked":
        return _break("exact-digest-revokes",
                      "check() did not return revoked for pinned digest")
    if rl.check(_DIGEST_B) != "active":
        return _break("exact-digest-revokes",
                      "check() did not return active for unknown digest")
    _held("exact-digest-revokes", "revoked/active correct")


@_probe("prefix-and-class-refused")
def _p_inexact():
    if not _IMPORT_OK:
        return _gap("prefix-and-class-refused")
    seed = _ed.generate_seed()
    rl = rv.RevocationList()
    bad_targets = [
        "aa",                       # prefix
        _DIGEST_A[:32],             # half digest
        "*",                        # class wildcard
        "tool:*",                   # class shape
        "sha256:",                  # bare scheme
        "sha256:" + "aa",           # short with scheme
        _DIGEST_A.upper(),          # wrong case (not the canonical form)
        "",                         # empty
        "not-a-digest-at-all",      # garbage
    ]
    for target in bad_targets:
        try:
            rl.revoke(target, issuer_id="rev-issuer", seed=seed)
        except Exception as exc:
            if _code_of(exc) != "revocation-inexact-target-refused":
                return _break("prefix-and-class-refused",
                              "target %r refused with %s, expected "
                              "revocation-inexact-target-refused"
                              % (target, _code_of(exc)))
        else:
            return _break("prefix-and-class-refused",
                          "target %r was NOT refused" % (target,))
    _held("prefix-and-class-refused", "all 9 inexact targets refused")


@_probe("revoked-lease-refused")
def _p_revoked_lease():
    if not _IMPORT_OK:
        return _gap("revoked-lease-refused")
    seed = _ed.generate_seed()
    rl = rv.RevocationList()
    try:
        registry = pl.PermitRegistry(revocation_registry=rl)
    except TypeError:
        return _gap("revoked-lease-refused")  # wiring absent on pristine
    lease = registry.issue("p1", params_digest="sha256:" + _DIGEST_A,
                           grant_scope={"action": {"read"}})
    rl.revoke("sha256:" + _DIGEST_A, issuer_id="rev-issuer", seed=seed)
    # Correct digest, unused, unexpired — revocation alone must refuse.
    _expect_refusal("revoked-lease-refused", "permit-revoked",
                    lambda: registry.redeem("p1",
                                            "sha256:" + _DIGEST_A))
    # The lease must NOT be consumed by the refused redeem.
    if lease.used:
        _break("revoked-lease-refused",
               "refused redeem consumed the lease")
    else:
        _held("revoked-lease-refused", "permit-revoked; lease not consumed")


@_probe("non-revoked-lease-unaffected")
def _p_nonrevoked():
    if not _IMPORT_OK:
        return _gap("non-revoked-lease-unaffected")
    seed = _ed.generate_seed()
    rl = rv.RevocationList()
    rl.revoke("sha256:" + _DIGEST_C, issuer_id="rev-issuer", seed=seed)
    try:
        registry = pl.PermitRegistry(revocation_registry=rl)
    except TypeError:
        return _gap("non-revoked-lease-unaffected")
    registry.issue("p2", params_digest="sha256:" + _DIGEST_A,
                   grant_scope={"action": {"read"}})
    try:
        grant = registry.redeem("p2", "sha256:" + _DIGEST_A)
    except Exception as exc:
        return _break("non-revoked-lease-unaffected",
                      "non-revoked lease refused: %s" % _code_of(exc))
    if grant["permit_id"] != "p2":
        return _break("non-revoked-lease-unaffected", "bad grant record")
    _held("non-revoked-lease-unaffected", "redeem succeeded")


@_probe("no-registry-legacy-identical")
def _p_legacy():
    # Legacy pin, verifiable on the pristine base: redeem with no
    # revocation registry must behave exactly as before.
    registry = pl.PermitRegistry()
    registry.issue("p3", params_digest="sha256:" + _DIGEST_A,
                   grant_scope={"action": {"read"}})
    try:
        grant = registry.redeem("p3", "sha256:" + _DIGEST_A)
    except Exception as exc:
        return _break("no-registry-legacy-identical",
                      "legacy redeem refused: %s" % _code_of(exc))
    if set(grant) != {"permit_id", "parameter_digest", "granted_at"}:
        return _break("no-registry-legacy-identical",
                      "grant record shape changed: %s" % sorted(grant))
    _held("no-registry-legacy-identical", "legacy grant record identical")


@_probe("import-verifies-signatures")
def _p_import():
    if not _IMPORT_OK:
        return _gap("import-verifies-signatures")
    seed = _ed.generate_seed()
    pub = _ed.publickey(seed)
    wrong_seed = _ed.generate_seed()
    wrong_pub = _ed.publickey(wrong_seed)
    rl = rv.RevocationList()
    rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=seed)
    exported = rl.export()
    rl2 = rv.RevocationList()
    rl2.import_entries(exported, {"rev-issuer": pub})
    if rl2.check(_DIGEST_A) != "revoked":
        return _break("import-verifies-signatures",
                      "round-trip import lost the revocation")
    # Wrong keyset: the entry must not be trusted.
    rl3 = rv.RevocationList()
    _expect_refusal("import-verifies-signatures",
                    "revocation-entry-unverifiable",
                    lambda: rl3.import_entries(exported,
                                               {"rev-issuer": wrong_pub}))
    if rl3.check(_DIGEST_A) == "revoked":
        _break("import-verifies-signatures",
               "bad-keyset import still revoked")
    else:
        _held("import-verifies-signatures",
              "round-trip OK; wrong keyset refused")


@_probe("revocation-idempotent")
def _p_idempotent():
    if not _IMPORT_OK:
        return _gap("revocation-idempotent")
    seed = _ed.generate_seed()
    rl = rv.RevocationList()
    rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=seed)
    first = rl.export()[0]["revoked_at"]
    rl.revoke(_DIGEST_A, issuer_id="rev-issuer", seed=seed)
    if rl.export()[0]["revoked_at"] != first:
        return _break("revocation-idempotent",
                      "second revoke rewrote the entry")
    _held("revocation-idempotent", "append-only, no rewrite")


@_probe("determinism")
def _p_determinism():
    if not _IMPORT_OK:
        return _gap("determinism")
    issuer, _seed = _issuer()
    pub = _ed.publickey(issuer.seed)
    neg1 = issuer.attest_absence(_DIGEST_A, now=1000.0)
    neg2 = issuer.attest_absence(_DIGEST_A, now=1000.0)
    if neg1["signature"] != neg2["signature"]:
        return _break("determinism", "absence signatures nondeterministic")
    seed = _ed.generate_seed()
    rl1, rl2 = rv.RevocationList(), rv.RevocationList()
    rl1.revoke(_DIGEST_A, issuer_id="r", seed=seed, now=2000.0)
    rl2.revoke(_DIGEST_A, issuer_id="r", seed=seed, now=2000.0)
    if rl1.export() != rl2.export():
        return _break("determinism", "revocation entries nondeterministic")
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
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green/permit-leases-adjacent", "SKIP", "nested run")]
    return [("green/permit-leases-adjacent", "SKIP",
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
    final = [(n, _VERDICT_MAP[v], d) for n, v, d in _RESULTS]
    # Green-check pids are renamed value-only ("/" -> "_") so every
    # emitted pid stays inside [A-Za-z0-9_.-] (D7).
    final += [(n.replace("/", "_"), _VERDICT_MAP[s], d)
              for n, s, d in green]
    probe_lines.emit(final)
    brk_c = sum(1 for _, v, _ in final if v == "BREAK")
    held_c = sum(1 for _, v, _ in final if v == "HELD")
    err_c = sum(1 for _, v, _ in final if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        final, brk_c, held_c, err_c)
    if not _coh_ok:
        print("coherence-WARNING: %s" % ("; ".join(_coh_diags)))
    print("%d BREAK / %d HELD / %d ERROR"
          % (brk_c, held_c, err_c))
    print("w222 revoke probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    if not _IMPORT_OK:
        print("import failed (pristine): %r" % (_IMPORT_ERR,))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
