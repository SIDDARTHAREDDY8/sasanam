#!/usr/bin/env python3
"""Wave-188 red-team probes: transit-managed Ed25519 audit signing.

Break-first battery per the diagnosing-bugs skill. Threat model: the
audit-entry signing key is a long-lived secret; the KMS seam
(``gov/kms.py`` / ``gov/kms_vault.py``) covers envelope encryption only,
so the audit-*signing* path has no KMS story -- operators either keep
the seed in process memory (``Ed25519Signer``) or cannot sign at all.
The wave-186 OpenBao spike proved ``gov/kms_vault.py`` works unmodified
against OpenBao v2.7.0's transit engine (sign/verify/export endpoints
live) but mapped the missing adapter as product work.

Each probe attacks the gap / the adapter's contract:

  S1 CAPABILITY   a ``Signer``-ABC adapter backed by transit exists
  S2 ROUND-TRIP   sign via transit, verify LOCALLY against the exported
                  public key (the server's /verify endpoint is never
                  consulted)
  S3 FORGED       a forged signature fails local verification even
                  though the server's (lying) /verify endpoint claims
                  ``{"valid": true}``
  S4 CONFUSION    a v1 signature does not verify under the v2 public
                  key; a v2 version claim on a v1 signature fails closed
  S5 STRIPPED     a signature with no bound version is refused (never
                  verified against a silently-picked key)
  S6 OUTAGE       server unavailable -> sign raises KmsError; no
                  signature, no unsigned fallback, no local-key fallback
  S7 AUTH         wrong token -> KmsError (fail-closed, no retry storm)
  S8 LYING-SERVER a sign response whose ``key_version`` disagrees with
                  the ``vault:vN:`` prefix in the signature is rejected
  S9 BAD-EXPORT   a malformed exported public key fails closed

On the pristine tree ``gov.transit_signer`` does not exist: every probe
reports BREAK ("capability absent" -- the gap is real and demonstrated).

After the fix: every probe must flip to HELD.

Verdicts: BREAK (gap demonstrated), HELD (defense held), HELD* (held
with a documented residual). ERROR only on harness failure (a verdict
changing between the two deterministic runs, an unexpected exception).

Pattern lineage: HashiCorp Vault / OpenBao transit secrets engine
(OpenBao MPL-2.0 -- API-shape knowledge only, no vendored code; stdlib
only, $0 spend). The fake transit server below is a faithful emulation:
real Ed25519 keys per version (deterministic seeds), real local
signing, versioned ``vault:vN:`` signature strings, a deliberately
lying /verify endpoint (always ``{"valid": true}``) that the adapter
must never call.

Deterministic: all key material derives from SHA256(probe tags); every
probe runs twice and a verdict change is an ERROR. Synthetic/local
only. ``GOV_SKIP_GREEN=1`` is honored (green check records a skip
instead of spawning sub-batteries).
"""

import base64
import hashlib
import json
import os
import re
import sys
import threading
import urllib.parse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import transit_signer as _ts
    HAVE_TS = True
except ImportError:
    HAVE_TS = False
    _ts = None

from gov import ed25519 as _ed
from gov.kms import KmsError
from gov.kms_vault import VaultTransport, VaultTransportError


# ---------------------------------------------------------------------------
# Fake transit server (faithful emulation, deterministic key material)
# ---------------------------------------------------------------------------

def _seed(tag):
    return hashlib.sha256(b"transit-signer-probe:" + tag.encode()).digest()


def _spki_pem(pub):
    der = bytes.fromhex("302a300506032b6570032100") + bytes(pub)
    b64 = base64.encodebytes(der).decode("ascii")
    return ("-----BEGIN PUBLIC KEY-----\n" + b64 +
            "-----END PUBLIC KEY-----\n")


class FakeTransitTransport(VaultTransport):
    """In-memory transit engine with REAL Ed25519 keys per version.

    Emulates the OpenBao/Vault transit HTTP surface the adapter uses:
    ``POST sign/<name>``, ``GET keys/<name>``,
    ``GET export/public-key/<name>[/<version>]``. The ``POST
    verify/<name>`` endpoint exists but ALWAYS answers
    ``{"valid": true}`` -- the compromised-server threat model; the
    adapter must never call it (every probe asserts this via
    :attr:`calls`).
    """

    def __init__(self, token="test-transit-token", mount="transit"):
        self._token = token
        self._mount = mount
        self._keys = {}   # name -> {"versions": {v: (seed, pub)}}
        self._lock = threading.Lock()
        self.outage = False
        self.lie_about_version = False
        self.bad_export = False
        self.calls = []

    # -- test controls ------------------------------------------------

    def create_signing_key(self, name):
        with self._lock:
            if name in self._keys:
                raise ValueError("key %r exists" % (name,))
            seed = _seed("key:" + name + ":v1")
            self._keys[name] = {"versions": {1: (seed,
                                                 _ed.publickey(seed))}}

    def rotate(self, name):
        with self._lock:
            info = self._keys[name]
            v = max(info["versions"]) + 1
            seed = _seed("key:" + name + ":v%d" % v)
            info["versions"][v] = (seed, _ed.publickey(seed))
            return v

    # -- transport -----------------------------------------------------

    def _err(self, status, *errors):
        return status, json.dumps({"errors": list(errors)}).encode()

    def _ok(self, data):
        return 200, json.dumps({"data": data}).encode()

    def request(self, method, path, headers, body):
        if self.outage:
            raise VaultTransportError("simulated outage")
        with self._lock:
            self.calls.append((method, path))
            if headers.get("X-Vault-Token") != self._token:
                return self._err(403, "permission denied")
            prefix = "/v1/%s/" % self._mount
            if not path.startswith(prefix):
                return self._err(404, "no handler")
            rest = path[len(prefix):]
            if method == "GET" and rest.startswith("export/public-key/"):
                return self._export(rest[len("export/public-key/"):])
            if method == "GET" and rest.startswith("keys/"):
                return self._read_key(rest[len("keys/"):])
            try:
                payload = json.loads((body or b"").decode("utf-8"))
            except Exception:
                return self._err(400, "malformed body")
            if not isinstance(payload, dict):
                return self._err(400, "malformed body")
            if method == "POST" and rest.startswith("sign/"):
                return self._sign(rest[len("sign/"):], payload)
            if method == "POST" and rest.startswith("verify/"):
                # THE LYING ENDPOINT: always claims valid.
                return self._ok({"valid": True})
            return self._err(404, "no handler")

    def _name(self, raw):
        return urllib.parse.unquote(raw)

    def _read_key(self, raw):
        info = self._keys.get(self._name(raw))
        if info is None:
            return self._err(404, "no such key")
        latest = max(info["versions"])
        return self._ok({"name": self._name(raw), "type": "ed25519",
                         "latest_version": latest,
                         "min_decryption_version": 1,
                         "export_private_key": False,
                         "keys": {str(v): {} for v in info["versions"]}})

    def _sign(self, raw, payload):
        info = self._keys.get(self._name(raw))
        if info is None:
            return self._err(404, "no such key")
        raw_input = payload.get("input")
        if not isinstance(raw_input, str) or not raw_input:
            return self._err(400, "missing input")
        try:
            data = base64.b64decode(raw_input, validate=True)
        except Exception:
            return self._err(400, "invalid base64 input")
        if not data:
            return self._err(400, "missing input")
        want = payload.get("key_version", 0)
        if want in (None, 0):
            v = max(info["versions"])
        else:
            v = want
            if not isinstance(v, int) or v not in info["versions"]:
                return self._err(400, "invalid key_version")
        seed, _pub = info["versions"][v]
        sig = _ed.sign(seed, data)
        sig_b64 = base64.b64encode(sig).decode("ascii")
        reported = 999 if self.lie_about_version else v
        return self._ok({"signature": "vault:v%d:%s" % (v, sig_b64),
                         "key_version": reported})

    def _export(self, raw):
        parts = self._name(raw).split("/")
        name, ver = (parts[0], None) if len(parts) == 1 else (
            parts[0], parts[1])
        if self.bad_export:
            return self._ok({"public_key": "NOT-A-PEM", "name": name})
        info = self._keys.get(name)
        if info is None:
            return self._err(404, "no such key")
        if ver is None:
            v = max(info["versions"])
        else:
            try:
                v = int(ver)
            except ValueError:
                return self._err(400, "invalid version")
            if v not in info["versions"]:
                return self._err(404, "no such version")
        _seed_v, pub = info["versions"][v]
        return self._ok({"name": name, "public_key": _spki_pem(pub)})


def _mk(name="audit-sign"):
    """Build (adapter, fake) pair; asserts adapter constructor works."""
    fake = FakeTransitTransport()
    fake.create_signing_key(name)
    signer = _ts.TransitSigner(fake, token="test-transit-token",
                               key_name=name)
    return signer, fake


def _server_verify_called(fake):
    return any(p.startswith("/v1/transit/verify/") for _m, p in fake.calls)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def p_s1_capability():
    """S1: the transit-backed Signer exists and satisfies the ABC."""
    if not HAVE_TS:
        return "BREAK", "gov.transit_signer absent: no KMS seam for audit signing"
    from gov.signing import Signer
    if not (hasattr(_ts, "TransitSigner") and hasattr(_ts, "TransitVerifier")):
        return "BREAK", "adapter classes missing"
    if not issubclass(_ts.TransitSigner, Signer):
        return "BREAK", "TransitSigner is not a Signer"
    signer, _fake = _mk()
    if not isinstance(signer.key_id, str) or not signer.key_id:
        return "BREAK", "key_id not resolved"
    if len(signer.public_key) != 32:
        return "BREAK", "public_key not 32 bytes"
    return "HELD", "TransitSigner present, ABC satisfied, identity resolves"


def p_s2_roundtrip():
    """S2: sign via transit, verify locally against the exported key."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    signer, fake = _mk()
    sig, ver = signer.sign_versioned(b"audit entry bytes")
    if len(sig) != 64 or ver != 1:
        return "BREAK", "sign_versioned returned bad shape"
    verifier = signer.verifier_for(ver)
    if not verifier.verify(b"audit entry bytes", sig):
        return "BREAK", "local verification of honest signature failed"
    if _server_verify_called(fake):
        return "BREAK", "adapter consulted the server /verify endpoint"
    return "HELD", "transit-signed bytes verify locally; /verify never called"


def p_s3_forged():
    """S3: forged signature fails local verify despite lying /verify."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    signer, fake = _mk()
    forged = _ed.sign(_seed("attacker-key"), b"audit entry bytes")
    verifier = signer.verifier_for(1)
    if verifier.verify(b"audit entry bytes", forged):
        return "BREAK", "forged signature verified"
    # The lying endpoint would claim valid; the adapter must not ask it.
    if _server_verify_called(fake):
        return "BREAK", "adapter trusted the server /verify endpoint"
    return "HELD", "forgery rejected locally; lying /verify never consulted"


def p_s4_confusion():
    """S4: v1 signature under the v2 key (and vice versa) fails."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    signer, fake = _mk()
    sig_v1, v1 = signer.sign_versioned(b"entry")
    assert v1 == 1
    fake.rotate("audit-sign")
    signer.refresh()
    sig_v2, v2 = signer.sign_versioned(b"entry")
    assert v2 == 2
    if signer.verifier_for(2).verify(b"entry", sig_v1):
        return "BREAK", "v1 sig verified under v2 key"
    if signer.verifier_for(1).verify(b"entry", sig_v2):
        return "BREAK", "v2 sig verified under v1 key"
    # Envelope claims v2 for a v1 signature -> must NOT verify.
    if _ts.verify_versioned(b"entry", sig_v1, 2, signer.verifier_for):
        return "BREAK", "cross-version envelope verified"
    if not _ts.verify_versioned(b"entry", sig_v2, 2, signer.verifier_for):
        return "BREAK", "honest v2 envelope failed"
    return "HELD", "cross-version confusion fails closed at both seams"


def p_s5_stripped():
    """S5: a signature with no bound version is refused outright."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    signer, _fake = _mk()
    sig, _ver = signer.sign_versioned(b"entry")
    try:
        _ts.verify_versioned(b"entry", sig, None, signer.verifier_for)
    except KmsError as e:
        return "HELD", "version-stripped refused: %s" % (e,)
    return "BREAK", "version-stripped signature verified without a version"


def p_s6_outage():
    """S6: server down -> KmsError; no signature, no fallback."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    signer, fake = _mk()
    fake.outage = True
    # Every network-touching seam must fail closed. refresh() is a
    # local cache clear by design -- it must NOT fail on outage.
    for fn in (lambda: signer.sign(b"entry"),
               lambda: signer.sign_versioned(b"entry"),
               lambda: signer.verifier_for(1),
               lambda: signer.key_id,
               lambda: signer.public_key):
        try:
            fn()
        except KmsError:
            continue
        except Exception as e:
            return "BREAK", "outage raised %s, not KmsError" % type(e).__name__
        return "BREAK", "outage did not fail closed"
    return "HELD", "outage fails closed on every seam; no unsigned fallback"


def p_s7_auth():
    """S7: wrong token -> KmsError at first use."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    fake = FakeTransitTransport()
    fake.create_signing_key("audit-sign")
    bad = _ts.TransitSigner(fake, token="wrong-token",
                            key_name="audit-sign")
    try:
        bad.sign(b"entry")
    except KmsError:
        return "HELD", "bad token fails closed"
    except Exception as e:
        return "BREAK", "bad token raised %s" % type(e).__name__
    return "BREAK", "bad token signed anyway"


def p_s8_lying_server():
    """S8: sign response with key_version != vault:vN: prefix rejected."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    signer, fake = _mk()
    fake.lie_about_version = True  # reports key_version=999, prefix says v1
    try:
        signer.sign_versioned(b"entry")
    except KmsError:
        return "HELD", "version/prefix disagreement rejected"
    except Exception as e:
        return "BREAK", "lying server raised %s" % type(e).__name__
    return "BREAK", "lying key_version accepted"


def p_s9_bad_export():
    """S9: malformed exported public key fails closed."""
    if not HAVE_TS:
        return "BREAK", "capability absent"
    signer, fake = _mk()
    fake.bad_export = True
    try:
        signer.verifier_for(1)
    except KmsError:
        return "HELD", "malformed export fails closed"
    except Exception as e:
        return "BREAK", "bad export raised %s" % type(e).__name__
    return "BREAK", "malformed export produced a verifier"


_PROBES = [
    ("S1", p_s1_capability),
    ("S2", p_s2_roundtrip),
    ("S3", p_s3_forged),
    ("S4", p_s4_confusion),
    ("S5", p_s5_stripped),
    ("S6", p_s6_outage),
    ("S7", p_s7_auth),
    ("S8", p_s8_lying_server),
    ("S9", p_s9_bad_export),
]


def _run_once():
    out = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:
            verdict, detail = ("ERROR",
                               "%s: %s" % (type(e).__name__, e))
        if verdict not in ("BREAK", "HELD", "HELD*"):
            verdict, detail = "ERROR", "bad verdict %r" % (verdict,)
        out.append((name, verdict, detail))
    return out


def main():
    first = _run_once()
    second = _run_once()
    errors = 0
    for (n1, v1, d1), (n2, v2, _d2) in zip(first, second):
        assert n1 == n2
        if v1 != v2:
            errors += 1
            print("ERROR %s: verdict changed %s -> %s" % (n1, v1, v2))
    brk = sum(1 for _n, v, _d in first if v == "BREAK")
    held = sum(1 for _n, v, _d in first if v in ("HELD", "HELD*"))
    errs = sum(1 for _n, v, _d in first if v == "ERROR") + errors
    for n, v, d in first:
        print("%s %s: %s" % (v, n, d))
    print("---")
    print("transit_signer_probes: %d BREAK / %d HELD / %d errors"
          % (brk, held, errs))
    if brk:
        print("BREAK: %s" % ", ".join(n for n, v, _ in first
                                      if v == "BREAK"))
    return 1 if errs else 0


def _green_check():
    """Depth-1 green check: adjacent unit suites only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip."""
    import subprocess
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for suite in ("tests.test_transit_signer", "tests.test_kms_vault"):
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite, "-v"],
            cwd=REPO, env=env, capture_output=True, text=True,
            timeout=600)
        tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
        print("GREEN CHECK %s: rc=%d %s" % (suite, r.returncode,
                                            " | ".join(tail)))
        if r.returncode != 0:
            return False
    return True


if __name__ == "__main__":
    rc = main()
    print("---")
    ok = _green_check()
    sys.exit(rc if ok else 2)
