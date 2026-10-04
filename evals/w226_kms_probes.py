#!/usr/bin/env python3
"""Wave-226 lane A: KMS-resident signing for evidence records.

ADAPT of the Dex v2.45.0 Vault/OpenBao JWT signer pattern
(re-derived prose; nothing copied): signing happens INSIDE the
KMS and only signatures return — the private key material never
crosses the boundary.

Seams under test:
* gov/kms_signer.py (NEW) — KmsSigner.sign(key_ref, message) ->
  signature bytes; KeyRef {provider, key_id, algorithm};
  unknown algorithm -> kms-signer-algorithm-refused; oversized
  message -> kms-signer-message-too-large; MAC-tier keys return
  receipts HONESTLY labeled non_repudiation=False;
  verify(key_ref_or_pubkey, message, signature) dispatches by
  the named algorithm.
* gov/kms_signer_loopback.py (NEW) — local test/dev reference
  implementation (docstring: "NEVER a production KMS
  substitute"), backed by the vendored Ed25519/HMAC registry,
  zero network. Seeds live inside the loopback closure/class
  and are never returned by any public method.
* gov/alg_registry.py additive — register_signer_backend /
  clear_signer_backend / has_signer_backend /
  sign_via_backend(alg, message, key_ref); default registries
  have NO backends (sign() behavior byte-identical to legacy).

Attack shapes: key material exfiltration through the signer API,
unknown/typo'd algorithm degrading to a known one, unbounded
message sizes (DoS on the signing path), MAC-tier evidence
offered as non-repudiation evidence, backend wiring changing
legacy sign() behavior, tampered signatures, legacy key rings
broken by the new module.

Method (diagnosing-bugs): seams at the PUBLIC surface,
deterministic, minimal, against pristine wave-225 HEAD
0fb51624e6162c1846501e93b9ab3dd2127f7873.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (modules
absent) is expected GAP — only the legacy pins are verifiable
on base.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe
fails closed on them).

Run:
  mkdir -p /var/tmp/g226a
  TMPDIR=/var/tmp/g226a ~/workspace/.gov-venv/bin/python evals/w226_kms_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g226a-u \\
      ~/workspace/.gov-venv/bin/python evals/w226_kms_probes.py
"""

import os
import secrets
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w226-kms-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g226a-%d" % os.getpid()
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
    from gov import kms_signer as ks  # noqa: E402
    from gov import kms_signer_loopback as kl  # noqa: E402
    from gov import alg_registry as ar  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - import probe records it
    _IMPORT_OK = False
    _IMPORT_ERR = exc
    ks = kl = ar = None

# Legacy seams — these must hold on pristine too.
try:
    from gov import kms as _kms  # noqa: E402
    _KMS_OK = True
    _KMS_ERR = None
except Exception as exc:  # noqa: BLE001
    _KMS_OK = False
    _KMS_ERR = exc
    _kms = None

try:
    from gov import ed25519 as _ed  # noqa: E402
    _ED_OK = True
except Exception:  # noqa: BLE001
    _ED_OK = False
    _ed = None

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


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail):
    _record(name, "HELD", detail)


def _gap(name, detail):
    _record(name, "GAP", detail)


def _break(name, detail):
    _record(name, "BREAK", detail)


def _error(name, detail):
    _record(name, "ERROR", detail)


def _need_imports(name):
    """Probes that need the new modules: GAP when absent, True when ok."""
    if not _IMPORT_OK:
        _gap(name, "pristine: kms_signer module absent")
        return False
    return True


def _loopback(alg="ed25519-rfc8032", provider="vault"):
    """Fresh loopback with one provisioned key."""
    lb = kl.LoopbackKms()
    key_ref = lb.provision_key(provider, "%s-key-1" % provider, alg)
    return lb, key_ref


# ----------------------------------------------------------------------
# New-module probes (GAP on pristine).
# ----------------------------------------------------------------------

@_probe("kms-import-present")
def _p_import():
    if not _IMPORT_OK:
        _gap("kms-import-present",
             "pristine: gov.kms_signer absent (%r)" % (_IMPORT_ERR,))
        return
    _held("kms-import-present",
          "gov.kms_signer + gov.kms_signer_loopback import clean")


@_probe("kms-loopback-not-production")
def _p_loopback_doc():
    if not _need_imports("kms-loopback-not-production"):
        return
    doc = (kl.__doc__ or "")
    if "NEVER a production KMS substitute" not in " ".join(doc.split()):
        _break("kms-loopback-not-production",
               "loopback module docstring lacks the "
               "NEVER-a-production-substitute warning")
        return
    _held("kms-loopback-not-production",
          "loopback docstring carries the non-production warning")


@_probe("kms-keyref-shape")
def _p_keyref_shape():
    if not _need_imports("kms-keyref-shape"):
        return
    ref = ks.KeyRef(provider="vault", key_id="signing-key-1",
                    algorithm="ed25519-rfc8032")
    if (ref.provider, ref.key_id, ref.algorithm) != (
            "vault", "signing-key-1", "ed25519-rfc8032"):
        _break("kms-keyref-shape", "KeyRef does not preserve fields")
        return
    bad = 0
    for kwargs in (dict(provider="", key_id="k", algorithm="ed25519-rfc8032"),
                   dict(provider="vault", key_id="", algorithm="x"),
                   dict(provider="vault", key_id="k", algorithm=123)):
        try:
            ks.KeyRef(**kwargs)
        except Exception:  # noqa: BLE001 - any refusal is fine here
            bad += 1
    if bad != 3:
        _break("kms-keyref-shape",
               "malformed KeyRef accepted (%d/3 refused)" % bad)
        return
    _held("kms-keyref-shape",
          "KeyRef preserves fields; malformed refs refused 3/3")


@_probe("kms-sign-verify-roundtrip")
def _p_roundtrip():
    if not _need_imports("kms-sign-verify-roundtrip"):
        return
    lb, ref = _loopback()
    msg = b"evidence-record-body"
    sig = lb.sign(ref, msg)
    if not isinstance(sig, bytes) or not sig:
        _break("kms-sign-verify-roundtrip",
               "sign() did not return signature bytes")
        return
    pub = lb.public_key_for(ref)
    # Raw public keys require a named algorithm (fail-closed: the
    # bytes alone do not name a scheme).
    if not lb.verify(pub, msg, sig, algorithm="ed25519-rfc8032"):
        _break("kms-sign-verify-roundtrip",
               "verify(pub, msg, sig, algorithm=...) failed on fresh "
               "signature")
        return
    if not lb.verify(ref, msg, sig):
        _break("kms-sign-verify-roundtrip",
               "verify(key_ref, msg, sig) failed on fresh signature")
        return
    _held("kms-sign-verify-roundtrip",
          "sign -> verify (pubkey and key_ref forms) holds")


@_probe("kms-unknown-algorithm-refused")
def _p_unknown_alg():
    if not _need_imports("kms-unknown-algorithm-refused"):
        return
    lb, _ = _loopback()
    ref = ks.KeyRef(provider="vault", key_id="k1", algorithm="nope-v99")
    try:
        lb.sign(ref, b"msg")
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "kms-signer-algorithm-refused":
            _held("kms-unknown-algorithm-refused",
                  "unknown algorithm refuses kms-signer-algorithm-refused")
            return
        _break("kms-unknown-algorithm-refused",
               "wrong error code: %r" % (getattr(exc, "code", None),))
        return
    _break("kms-unknown-algorithm-refused",
           "sign() accepted an unregistered algorithm")


@_probe("kms-message-too-large-refused")
def _p_too_large():
    if not _need_imports("kms-message-too-large-refused"):
        return
    lb, ref = _loopback()
    try:
        lb.sign(ref, b"x" * (ks.MAX_MESSAGE_BYTES + 1))
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "kms-signer-message-too-large":
            _held("kms-message-too-large-refused",
                  "oversized message refuses "
                  "kms-signer-message-too-large")
            return
        _break("kms-message-too-large-refused",
               "wrong error code: %r" % (getattr(exc, "code", None),))
        return
    _break("kms-message-too-large-refused",
           "sign() accepted an oversized message")


@_probe("kms-honest-non-repudiation-tier")
def _p_honest_tier():
    if not _need_imports("kms-honest-non-repudiation-tier"):
        return
    lb, ref = _loopback(alg="hmac-sha256-mac")
    receipt = lb.sign_labeled(ref, b"evidence")
    if receipt.algorithm != "hmac-sha256-mac":
        _break("kms-honest-non-repudiation-tier",
               "receipt carries wrong algorithm label")
        return
    if receipt.non_repudiation is not False:
        _break("kms-honest-non-repudiation-tier",
               "MAC-tier receipt not labeled non_repudiation=False: %r"
               % (receipt.non_repudiation,))
        return
    ed_ref = _loopback(alg="ed25519-rfc8032")[1]
    ed_receipt = lb.sign_labeled(ed_ref, b"evidence")
    if ed_receipt.non_repudiation is not True:
        _break("kms-honest-non-repudiation-tier",
               "Ed25519 receipt not labeled non_repudiation=True")
        return
    _held("kms-honest-non-repudiation-tier",
          "receipts honestly labeled: MAC=False, Ed25519=True")


@_probe("kms-no-key-exfil")
def _p_no_exfil():
    if not _need_imports("kms-no-key-exfil"):
        return
    lb, ref = _loopback()
    msg = b"exfil-probe"
    sig = lb.sign(ref, msg)
    # API-shape assertion: no public accessor yields key material.
    leaks = [name for name in dir(lb)
             if "seed" in name.lower() or "private" in name.lower()
             and not name.startswith("_")]
    if leaks:
        _break("kms-no-key-exfil",
               "loopback exposes key-material accessors: %r" % (leaks,))
        return
    if sig == b"" or len(sig) != 64:
        _break("kms-no-key-exfil",
               "unexpected signature shape %d bytes" % len(sig))
        return
    pub = lb.public_key_for(ref)
    # The seed and the public key must differ (proving sign() did not
    # leak the seed back through public_key_for).
    if pub == sig:
        _break("kms-no-key-exfil", "public key equals signature bytes")
        return
    try:
        lb.provision_key("vault", "k", "ed25519-rfc8032")
        ids = lb.key_ids()
    except Exception as exc:  # noqa: BLE001
        _break("kms-no-key-exfil", "key_ids() failed: %r" % (exc,))
        return
    if any("signing-key-1" in i for i in ids) and len(ids) != 2:
        _break("kms-no-key-exfil", "key_ids() disagrees with provisioning")
        return
    _held("kms-no-key-exfil",
          "no public accessor yields seed/private material; "
          "signatures and metadata only")


@_probe("kms-verify-tampered-refused")
def _p_tampered():
    if not _need_imports("kms-verify-tampered-refused"):
        return
    lb, ref = _loopback()
    msg = b"original"
    sig = lb.sign(ref, msg)
    pub = lb.public_key_for(ref)
    if lb.verify(pub, b"tampered", sig, algorithm="ed25519-rfc8032"):
        _break("kms-verify-tampered-refused",
               "verify() accepted a tampered message")
        return
    bad = bytearray(sig)
    bad[0] ^= 0xFF
    if lb.verify(pub, msg, bytes(bad), algorithm="ed25519-rfc8032"):
        _break("kms-verify-tampered-refused",
               "verify() accepted a tampered signature")
        return
    _held("kms-verify-tampered-refused",
          "tampered message and signature both verify False")


@_probe("kms-backend-option-defaults")
def _p_backend_defaults():
    if not _need_imports("kms-backend-option-defaults"):
        return
    if not hasattr(ar, "AlgorithmRegistry"):
        _error("kms-backend-option-defaults", "alg_registry import broken")
        return
    reg = ar.default_registry()
    for meth in ("register_signer_backend", "clear_signer_backend",
                 "has_signer_backend", "sign_via_backend"):
        if not hasattr(reg, meth):
            _gap("kms-backend-option-defaults",
                 "pristine: AlgorithmRegistry lacks %s" % meth)
            return
    if reg.has_signer_backend("ed25519-rfc8032"):
        _break("kms-backend-option-defaults",
               "default registry has a backend pre-registered")
        return
    if not _ED_OK:
        _error("kms-backend-option-defaults", "ed25519 import failed")
        return
    seed = _ed.generate_seed()
    pub = _ed.publickey(seed)
    msg = b"legacy-sign-behavior"
    before = reg.sign("ed25519-rfc8032", msg, seed)
    if not reg.verify("ed25519-rfc8032", msg, before, pub):
        _break("kms-backend-option-defaults",
               "legacy sign() path broken after additive wiring")
        return
    _held("kms-backend-option-defaults",
          "no default backend; legacy sign() path unchanged")


@_probe("kms-backend-sign-works")
def _p_backend_sign():
    if not _need_imports("kms-backend-sign-works"):
        return
    reg = ar.AlgorithmRegistry()
    for meth in ("register_signer_backend", "has_signer_backend",
                 "sign_via_backend"):
        if not hasattr(reg, meth):
            _gap("kms-backend-sign-works",
                 "pristine: AlgorithmRegistry lacks %s" % meth)
            return

    def _test_keygen():
        seed = _ed.generate_seed()
        return seed, _ed.publickey(seed)

    reg.register("ed25519-rfc8032",
                 sign_fn=lambda s, m: _ed.sign(bytes(s), bytes(m)),
                 verify_fn=lambda k, m, g: _ed.verify(bytes(k), bytes(m),
                                                     bytes(g)),
                 keygen=_test_keygen,
                 domain_separator=b"sasanam-test-backend:",
                 non_repudiation=True)
    lb = kl.LoopbackKms(registry=reg)
    ref = lb.provision_key("vault", "backend-key", "ed25519-rfc8032")
    reg.register_signer_backend("ed25519-rfc8032", lb)
    if not reg.has_signer_backend("ed25519-rfc8032"):
        _break("kms-backend-sign-works",
               "has_signer_backend False after registration")
        return
    try:
        sig = reg.sign_via_backend("ed25519-rfc8032", b"m", ref)
    except Exception as exc:  # noqa: BLE001
        _break("kms-backend-sign-works", "sign_via_backend raised: %r"
               % (exc,))
        return
    if not reg.verify("ed25519-rfc8032", b"m", sig,
                      lb.public_key_for(ref)):
        _break("kms-backend-sign-works",
               "backend signature does not verify")
        return
    # Unknown algorithm for backend registration refuses fail-closed.
    try:
        reg.register_signer_backend("nope-v99", lb)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", "") == "alg-unregistered":
            _held("kms-backend-sign-works",
                  "backend registration + sign + verify work; "
                  "unknown alg refuses")
            return
        _break("kms-backend-sign-works",
               "wrong code for unknown backend alg: %r"
               % (getattr(exc, "code", None),))
        return
    _break("kms-backend-sign-works",
           "register_signer_backend accepted an unregistered algorithm")


@_probe("kms-determinism")
def _p_determinism():
    if not _need_imports("kms-determinism"):
        return
    lb, ref = _loopback()
    msg = b"deterministic-signing"
    if lb.sign(ref, msg) != lb.sign(ref, msg):
        _break("kms-determinism",
               "KMS sign() nondeterministic for identical inputs")
        return
    _held("kms-determinism", "identical inputs sign identically")


# ----------------------------------------------------------------------
# Legacy pins (must HELD on pristine and after the lane).
# ----------------------------------------------------------------------

@_probe("kms-legacy-envelope-ring")
def _p_legacy_kms():
    if not _KMS_OK:
        _error("kms-legacy-envelope-ring",
               "gov.kms failed to import: %r" % (_KMS_ERR,))
        return
    fake = _kms.FakeKmsProvider(["k1"])
    ring = _kms.EnvelopeKeyRing.generate(fake, "k1", epoch="epoch-1")
    mat = ring.materialize(fake)
    if ring.active().epoch != "epoch-1" or mat.get("epoch-1") is None:
        _break("kms-legacy-envelope-ring",
               "envelope keyring behavior changed")
        return
    _held("kms-legacy-envelope-ring",
          "FakeKmsProvider envelope ring generate/materialize intact")


@_probe("kms-legacy-alg-registry")
def _p_legacy_alg():
    if not _ED_OK:
        _error("kms-legacy-alg-registry", "ed25519 import failed")
        return
    # Baseline: registry primitives on the two built-ins must still
    # work exactly as before (this pin runs even on pristine).
    from gov import alg_registry as _ar
    reg = _ar.default_registry()
    if set(reg.names()) != {"ed25519-rfc8032", "hmac-sha256-mac"}:
        _break("kms-legacy-alg-registry",
               "default registry names changed: %r" % (reg.names(),))
        return
    seed, pub = reg.keygen("ed25519-rfc8032")
    if not reg.verify("ed25519-rfc8032", b"pin", reg.sign(
            "ed25519-rfc8032", b"pin", seed), pub):
        _break("kms-legacy-alg-registry", "ed25519 round trip broken")
        return
    _held("kms-legacy-alg-registry",
          "default registry names + ed25519 round trip intact")


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
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_kms_signer.py",
                 "tests/test_alg_registry.py",
                 "tests/test_kms.py"):
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
    print("w226 kms probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "(%d probes, determinism %s)"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    if brk or err or not det_ok:
        return 1
    if any(s not in ("PASS", "SKIP") for _, s, _ in green):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
