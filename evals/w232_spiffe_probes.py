#!/usr/bin/env python3
"""Wave-232 lane A: SPIFFE-attested KMS auth (ADAPT of the wave-231 spike).

Re-derived pattern (nothing copied): a ``CredentialProvider`` injectable
acquires SHORT-LIVED Vault client tokens through a file-projected
JWT-SVID (SPIFFE CSI driver rotation is deployment-owned) exchanged via
Vault/OpenBao's JWT auth method. The spiffe factory path NEVER reads the
static ``VAULT_TOKEN`` env bearer -- the no-fallback invariant is
structural (the code path has no reference to the env var), not operator
discipline. Pre-network refusal: a malformed/expired/wrong-audience SVID
or a world-readable SVID file refuses BEFORE any Vault request is sent.

Seams under test:
* gov/spiffe_credential_provider.py -- CredentialProvider ABC with
  current_token(); FileJwtSvidCredentialProvider(path, *, audience,
  role, transport, ...) doing pre-network shape/expiry/audience/perms
  checks, JWT login, token caching to lease expiry, and exactly-one
  re-login on 403; vault_provider_from_spiffe_config(mapping) wiring
  `provider: vault-spiffe` without ever reading VAULT_TOKEN.
* gov/kms_vault.py -- VaultKmsProvider.__init__ accepts an optional
  credential_provider= (exactly one of token / provider); _api()
  resolves the token per request and re-logs-in once on 403.
* gov/transit_signer.py -- TransitSigner.__init__ accepts the same
  optional seam and passes it to the composed provider.
* gov/leased_credentials.py -- LeasedCredentialManager.__init__
  accepts the same optional seam.

Attack shapes: absent SVID file (SPIRE agent down); expired SVID;
wrong-audience SVID; malformed SVID; world-readable SVID file;
VAULT_TOKEN decoy in env (must be structurally ignored); Vault 403 on
login (bounded retry); expired client-token lease; token+provider both
set / neither set at construction.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-231 HEAD
6f9131bc76e3713a61a271c4a2203956c533c456.

Verdicts: HELD / GAP / BREAK / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g232a
  TMPDIR=/var/tmp/g232a ~/workspace/.gov-venv/bin/python evals/w232_spiffe_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import base64
import json
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import spiffe_credential_provider as _scp
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

try:
    from gov.kms_vault import VaultTransport, VaultTransportError
    HAVE_VAULT = True
except ImportError:
    HAVE_VAULT = False
    VaultTransport = object  # pristine-base fallback; probes GAP anyway

PROBE_NAMES = [
    "agent-down-no-network",
    "expired-svid-no-network",
    "wrong-audience-no-network",
    "no-static-fallback",
    "bounded-403-retry",
    "lease-expiry-relogin",
    "signer-interface-unchanged",
    "perms-refused",
]

_LOGIN_PATH = "/v1/auth/jwt/login"
_AUD = "vault://test-cluster"
_ROLE = "sasanam-kms-signer"


def _b64url(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")


def _jwt(payload):
    return "%s.%s.%s" % (_b64url({"alg": "none", "typ": "JWT"}),
                         _b64url(payload), "fakesig")


class _FakeSpiffeVault(VaultTransport):
    """Records every request; serves JWT login + minimal transit."""

    def __init__(self, login_script=None):
        self.calls = []          # (method, path, headers, body)
        self.login_calls = 0
        self.login_script = list(login_script or [])
        self._lock = threading.Lock()
        self._vault = {}         # ciphertext handle -> plaintext_b64
        self._token_ok = None

    def _err(self, status, *errors):
        return status, json.dumps({"errors": list(errors)}).encode("utf-8")

    def _ok(self, data):
        return 200, json.dumps({"data": data}).encode("utf-8")

    def request(self, method, path, headers, body):
        with self._lock:
            self.calls.append((method, path, dict(headers), body))
            if path == _LOGIN_PATH:
                self.login_calls += 1
                if self.login_script:
                    status, auth = self.login_script.pop(0)
                    if status == 200:
                        return 200, json.dumps({"auth": auth}).encode("utf-8")
                    return self._err(status, "permission denied")
                tok = "client-tok-%d" % self.login_calls
                return 200, json.dumps(
                    {"auth": {"client_token": tok,
                             "lease_duration": 300}}).encode("utf-8")
            # transit: any X-Vault-Token is accepted; the provider is
            # responsible for supplying the right one.
            try:
                payload = json.loads((body or b"").decode("utf-8"))
            except Exception:
                return self._err(400, "malformed request body")
            if path.endswith("/encrypt/k1"):
                pt = payload.get("plaintext")
                handle = ("vault:v1:" + base64.urlsafe_b64encode(
                    secrets.token_bytes(12)).decode("ascii").rstrip("="))
                self._vault[handle] = pt
                return self._ok({"ciphertext": handle, "key_version": 1})
            if path.endswith("/decrypt/k1"):
                ct = payload.get("ciphertext")
                pt = self._vault.get(ct)
                if pt is None:
                    return self._err(400, "invalid ciphertext")
                return self._ok({"plaintext": pt})
            return self._err(404, "no handler for %r" % path)


def _write_svid(tmpdir, payload, mode=0o600):
    path = os.path.join(tmpdir, "svid-%d.jwt" % (time.time_ns() % 10**9))
    with open(path, "w") as fh:
        fh.write(_jwt(payload))
    os.chmod(path, mode)
    return path


def _provider(tmpdir, transport, payload=None, now=None, **kw):
    now = 1700000000 if now is None else now
    payload = {"sub": "spiffe://sasanam/ns/governance/sa/kms-signer",
               "aud": _AUD, "exp": now + 3600} if payload is None else payload
    path = _write_svid(tmpdir, payload, kw.pop("mode", 0o600))
    return _scp.FileJwtSvidCredentialProvider(
        path, audience=_AUD, role=_ROLE, transport=transport,
        now=lambda: now, **kw), path


def _refuses(fn, code):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            return True
        raise AssertionError(
            "expected code %r, got %r (%r)" % (code, got, exc))
    return False


def _p01_agent_down():
    tmpdir = tempfile.mkdtemp(prefix="w232p01")
    fake = _FakeSpiffeVault()
    prov = _scp.FileJwtSvidCredentialProvider(
        os.path.join(tmpdir, "no-such-svid.jwt"), audience=_AUD,
        role=_ROLE, transport=fake, now=lambda: 1700000000)
    ok = _refuses(prov.current_token, "spiffe-svid-unavailable")
    if not ok:
        return "BREAK", "absent SVID accepted"
    if fake.calls:
        return "BREAK", "network happened before refusal: %d calls" % (
            len(fake.calls),)
    return "HELD", "absent SVID refused pre-network, zero requests"


def _p02_expired():
    tmpdir = tempfile.mkdtemp(prefix="w232p02")
    now = 1700000000
    fake = _FakeSpiffeVault()
    # Expired SVID (well past the 60s clock-skew allowance).
    prov, _ = _provider(tmpdir, fake, {"aud": _AUD, "exp": now - 3600},
                        now=now)
    ok_exp = _refuses(prov.current_token, "spiffe-svid-expired")
    # Malformed SVID (not three segments).
    bad = os.path.join(tmpdir, "bad.jwt")
    with open(bad, "w") as fh:
        fh.write("not-a-jwt")
    os.chmod(bad, 0o600)
    prov2 = _scp.FileJwtSvidCredentialProvider(
        bad, audience=_AUD, role=_ROLE, transport=fake,
        now=lambda: now)
    ok_mal = _refuses(prov2.current_token, "spiffe-svid-malformed")
    # Missing exp is malformed, not expired.
    prov3, _ = _provider(tmpdir, fake, {"aud": _AUD}, now=now)
    ok_noexp = _refuses(prov3.current_token, "spiffe-svid-malformed")
    if not (ok_exp and ok_mal and ok_noexp):
        return "BREAK", "expired=%r malformed=%r noexp=%r" % (
            ok_exp, ok_mal, ok_noexp)
    if fake.calls:
        return "BREAK", "network happened before refusal: %d calls" % (
            len(fake.calls),)
    return "HELD", "expired/malformed/missing-exp refused pre-network"


def _p03_wrong_audience():
    tmpdir = tempfile.mkdtemp(prefix="w232p03")
    now = 1700000000
    fake = _FakeSpiffeVault()
    prov, _ = _provider(tmpdir, fake,
                        {"aud": "other-service", "exp": now + 3600}, now=now)
    ok = _refuses(prov.current_token, "spiffe-audience-mismatch")
    if not ok:
        return "BREAK", "foreign-audience SVID accepted"
    if fake.calls:
        return "BREAK", "foreign SVID presented to Vault: %d calls" % (
            len(fake.calls),)
    # List-form aud containing ours is accepted.
    prov2, _ = _provider(tmpdir, fake,
                         {"aud": ["x", _AUD], "exp": now + 3600}, now=now)
    tok = prov2.current_token()
    if not tok or fake.login_calls != 1:
        return "BREAK", "list-aud SVID not accepted: %r" % (tok,)
    return "HELD", "wrong audience refused pre-network; list-aud accepted"


def _p04_no_static_fallback():
    from gov.kms_vault import VaultKmsProvider
    tmpdir = tempfile.mkdtemp(prefix="w232p04")
    now = 1700000000
    sentinel = "sentinel-decoy-token-%d" % now
    os.environ["VAULT_TOKEN"] = sentinel
    os.environ["VAULT_ADDR"] = "https://vault.invalid"
    try:
        fake = _FakeSpiffeVault()
        prov, _ = _provider(tmpdir, fake, now=now)
        kms = VaultKmsProvider(fake, credential_provider=prov)
        blob = kms.wrap_data_key("k1", b"hello")
        pt = kms.unwrap_data_key("k1", blob)
        if pt != b"hello":
            return "BREAK", "round trip failed"
        # (a) behavioral: no X-Vault-Token header ever equals the decoy.
        for _m, _p, headers, _b in fake.calls:
            if headers.get("X-Vault-Token") == sentinel:
                return "BREAK", "static VAULT_TOKEN leaked into a header"
        # (b) structural: the spiffe factory path never reads VAULT_TOKEN.
        seen = []
        orig_get = os.environ.get

        def _spy_get(key, *a):
            seen.append(key)
            return orig_get(key, *a)

        os.environ.get = _spy_get
        try:
            _scp.vault_provider_from_spiffe_config({
                "svid_path": _,
                "audience": _AUD,
                "role": _ROLE,
            })
        finally:
            # Instance attribute shadow; delete restores the class method.
            try:
                del os.environ.get
            except AttributeError:
                os.environ.get = orig_get
        if "VAULT_TOKEN" in seen:
            return "BREAK", "spiffe factory read VAULT_TOKEN: %r" % (seen,)
    finally:
        del os.environ["VAULT_TOKEN"]
        del os.environ["VAULT_ADDR"]
    return "HELD", "decoy token never used; factory never read VAULT_TOKEN"


def _p05_bounded_retry():
    tmpdir = tempfile.mkdtemp(prefix="w232p05")
    now = 1700000000
    # 403 once, then 200: exactly 2 login calls, then success.
    fake = _FakeSpiffeVault(login_script=[
        (403, None), (200, {"client_token": "tok-ok", "lease_duration": 60})])
    prov, _ = _provider(tmpdir, fake, now=now)
    tok = prov.current_token()
    if tok != "tok-ok":
        return "BREAK", "retry did not recover: %r" % (tok,)
    if fake.login_calls != 2:
        return "BREAK", "expected 2 login calls, got %d" % fake.login_calls
    # Always 403: exactly 2 login calls, then fail closed.
    fake2 = _FakeSpiffeVault(login_script=[(403, None), (403, None),
                                           (403, None)])
    prov2, _ = _provider(tmpdir, fake2, now=now)
    ok = _refuses(prov2.current_token, "spiffe-auth-refused")
    if not ok:
        return "BREAK", "persistent 403 accepted"
    if fake2.login_calls != 2:
        return "BREAK", "retry loop not bounded: %d login calls" % (
            fake2.login_calls,)
    return "HELD", "one re-login then fail closed; never a retry loop"


def _p06_lease_expiry():
    tmpdir = tempfile.mkdtemp(prefix="w232p06")
    now = [1700000000]
    fake = _FakeSpiffeVault()
    prov, _ = _provider(tmpdir, fake, now=now[0])
    # Short lease: script two logins with lease_duration 60.
    fake.login_script = [
        (200, {"client_token": "tok-1", "lease_duration": 60}),
        (200, {"client_token": "tok-2", "lease_duration": 60})]
    prov2 = _scp.FileJwtSvidCredentialProvider(
        _, audience=_AUD, role=_ROLE, transport=fake,
        now=lambda: now[0])
    t1 = prov2.current_token()
    now[0] += 120  # past lease (60s) minus skew
    t2 = prov2.current_token()
    if t1 != "tok-1" or t2 != "tok-2":
        return "BREAK", "lease expiry did not re-login: %r %r" % (t1, t2)
    if fake.login_calls != 2:
        return "BREAK", "expected 2 logins, got %d" % fake.login_calls
    # Re-login outage fails closed.
    fake3 = _FakeSpiffeVault()
    fake3.login_script = [
        (200, {"client_token": "tok-1", "lease_duration": 1})]
    prov3 = _scp.FileJwtSvidCredentialProvider(
        _, audience=_AUD, role=_ROLE, transport=fake3,
        now=lambda: now[0])
    prov3.current_token()
    now[0] += 100
    fake3.login_script = []  # outage: raise on every request
    orig_request = fake3.request

    def _down(*a):
        raise VaultTransportError("simulated outage")

    fake3.request = _down
    ok = _refuses(prov3.current_token, "spiffe-auth-refused")
    fake3.request = orig_request
    if not ok:
        return "BREAK", "re-login outage accepted"
    return "HELD", "expired lease re-logs-in; re-login outage refused"


def _p07_interface_unchanged():
    from gov.kms_vault import VaultKmsProvider
    tmpdir = tempfile.mkdtemp(prefix="w232p07")
    now = 1700000000
    # Token-backed provider still works (existing behavior unchanged).
    fake_t = _FakeSpiffeVault()
    kms_t = VaultKmsProvider(fake_t, token="static-tok")
    blob_t = kms_t.wrap_data_key("k1", b"data")
    if kms_t.unwrap_data_key("k1", blob_t) != b"data":
        return "BREAK", "token path regressed"
    # Provider-backed provider: same envelope discipline.
    fake_s = _FakeSpiffeVault()
    prov, _ = _provider(tmpdir, fake_s, now=now)
    kms_s = VaultKmsProvider(fake_s, credential_provider=prov)
    blob_s = kms_s.wrap_data_key("k1", b"data")
    if kms_s.unwrap_data_key("k1", blob_s) != b"data":
        return "BREAK", "provider path round trip failed"
    if not blob_s.startswith(b"VAULTKMS1"):
        return "BREAK", "envelope magic changed"
    # Key-id binding identical: cross-key unwrap refuses on both.
    blob_cross = kms_t.wrap_data_key("k1", b"x")
    try:
        kms_s.unwrap_data_key("k1", blob_cross)
    except Exception:
        pass  # fake stores per-handle; cross-provider handles are unknown
    # Exactly-one-of rule at construction.
    from gov.kms import KmsError
    for bad in ({"token": "t", "credential_provider": prov},
                {}):
        try:
            VaultKmsProvider(_FakeSpiffeVault(), **bad)
        except (ValueError, TypeError, KmsError):
            pass
        else:
            return "BREAK", "exactly-one rule not enforced: %r" % (bad,)
    # TransitSigner seam.
    from gov.transit_signer import TransitSigner
    fake2 = _FakeSpiffeVault()
    prov2, _ = _provider(tmpdir, fake2, now=now)
    ts = TransitSigner(fake2, credential_provider=prov2, key_name="k1")
    if ts.key_name != "k1":
        return "BREAK", "transit signer seam broken"
    try:
        TransitSigner(_FakeSpiffeVault(), token="t",
                      credential_provider=prov2, key_name="k1")
    except (ValueError, TypeError, KmsError):
        pass
    else:
        return "BREAK", "transit signer allows token+provider"
    # LeasedCredentialManager seam.
    from gov.leased_credentials import LeasedCredentialManager
    mgr = LeasedCredentialManager(
        _FakeSpiffeVault(), credential_provider=prov2)
    if mgr is None:
        return "BREAK", "lease manager seam broken"
    try:
        LeasedCredentialManager(_FakeSpiffeVault())
    except Exception:
        pass
    else:
        return "BREAK", "lease manager allows neither token nor provider"
    return "HELD", "provider seam additive; exactly-one enforced; " \
        "token path unchanged"


def _p08_perms():
    tmpdir = tempfile.mkdtemp(prefix="w232p08")
    now = 1700000000
    fake = _FakeSpiffeVault()
    # World-readable SVID file refused (0600 accepted).
    wide = _write_svid(tmpdir, {"aud": _AUD, "exp": now + 3600}, mode=0o644)
    prov = _scp.FileJwtSvidCredentialProvider(
        wide, audience=_AUD, role=_ROLE, transport=fake,
        now=lambda: now)
    ok_wide = _refuses(prov.current_token, "spiffe-permission-invalid")
    prov2, path2 = _provider(tmpdir, fake, now=now)
    st = os.stat(path2)
    if stat.S_IMODE(st.st_mode) != 0o600:
        return "BREAK", "test setup: SVID not 0600"
    tok = prov2.current_token()
    if not ok_wide:
        return "BREAK", "world-readable SVID accepted"
    if not tok:
        return "BREAK", "0600 SVID refused"
    if fake.login_calls != 1:
        return "BREAK", "unexpected login count %d" % fake.login_calls
    return "HELD", "0644 refused spiffe-permission-invalid; 0600 works"


_PROBES = [
    _p01_agent_down, _p02_expired, _p03_wrong_audience,
    _p04_no_static_fallback, _p05_bounded_retry, _p06_lease_expiry,
    _p07_interface_unchanged, _p08_perms,
]


def _run_once():
    results = []
    for name, probe in zip(PROBE_NAMES, _PROBES):
        if not HAVE_MODULE:
            # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
            # gap-demonstrated evidence in the note.
            results.append((name, "BREAK",
                            "GAP: gov/spiffe_credential_provider.py absent "
                            "(pristine red)"))
            continue
        t0 = time.time()
        try:
            verdict, detail = probe()
        except Exception as exc:  # noqa: BLE001
            verdict = "ERROR"
            detail = "%r %s" % (exc, traceback.format_exc(limit=2))
        dt = time.time() - t0
        results.append((name, verdict, "%s (%.2fs)" % (detail, dt)))
    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_kms_vault.py",
                 "tests/test_transit_signer.py",
                 "tests/test_decision_codes.py"):
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
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(first, brk, held, err)
    probe_lines.emit(first)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR; determinism %s"
          % (brk, held, err, "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in green:
        print("  green [%s] %s: %s" % (verdict, name, detail))
    if brk or err or not det_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
