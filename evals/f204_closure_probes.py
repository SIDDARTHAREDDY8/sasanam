#!/usr/bin/env python3
"""F204 closure battery: byte-capped response reads on the anchoring path.

F204 (LOW, filed 2026-09-29, wave-206 lane B): unbounded ``resp.read()``
in ``gov/rekor_anchor.py`` (``SelfHostedRekor._urllib_transport``) and
``gov/anchor_backend.py`` (``RekorBackend._urllib_transport``) -- a
malicious or compromised transparency log could serve an unbounded
response body and the client would buffer it all (download DoS).

Close-when: every response body read on both transports is byte-capped;
an oversized body is refused LOUDLY (a named error, never a silent
truncation); truncation can never produce a verifiable receipt; normal
bodies anchor exactly as before.

Red-first method: a REAL local HTTP server (stdlib http.server on
127.0.0.1, ephemeral port) and the REAL urllib client -- no fake
transport, no monkeypatching of urlopen. The vulnerable code under test
is the default ``_urllib_transport`` in both modules, driven through the
public ``submit`` seam and, for the exact cap boundary, through the
transport callable itself.

Probe map:
  p_oversized_refused_rekor_anchor:   2 MiB entry body -> submit raises
                                      loudly (names the cap). Pre-fix this
                                      probe BREAKS (the body is accepted).
  p_normal_still_anchors_rekor_anchor: small valid entry -> receipt with
                                      the uuid (unchanged behavior).
  p_truncated_never_verifies:         truncated JSON body -> loud
                                      refusal, never a receipt.
  p_cap_boundary_rekor_anchor:        exactly MAX bytes accepted,
                                      MAX+1 bytes refused. Pre-fix the
                                      MAX+1 case BREAKS (accepted).
  p_oversized_refused_anchor_backend: same as the first probe against
                                      RekorBackend.submit.
  p_normal_still_anchors_anchor_backend: small valid entry -> receipt.
  p_cap_boundary_anchor_backend:      boundary through its transport.
  p_deterministic_x2:                 verdicts byte-identical across 2 runs.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.rekor_anchor, gov.anchor_backend); the only network use is
localhost loopback.

Run (fresh UNIQUE /var/tmp TMPDIR per run -- never reuse one across
runs, and always mkdir -p first: Python 3.12 silently ignores a
nonexistent TMPDIR):
  T=/var/tmp/g206f-$$; mkdir -p $T
  TMPDIR=$T ~/workspace/.gov-venv/bin/python evals/f204_closure_probes.py
Also standalone (must be identical -- deployment mode is pinned at
module level):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=$T ~/workspace/.gov-venv/bin/python \
      evals/f204_closure_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

from gov import anchor_backend as ab  # noqa: E402
from gov import rekor_anchor as ra  # noqa: E402

_RESULTS = []

# 2 MiB of JSON -- far beyond any legitimate Rekor v1 response.
OVERSIZED = 2 * 1024 * 1024


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("%-42s %s %s" % (name, verdict, detail))


def _entry_body(uuid, pad_len=0):
    entry = {
        "logIndex": 42,
        "logID": "f204-test-log-id",
        "integratedTime": 1750000000,
        "verification": {
            "inclusionProof": {
                "hashes": [],
                "rootHash": "00" * 32,
                "treeSize": 1,
                "logIndex": 42,
            },
            "signedEntryTimestamp": "c2ln",
            "body": "Ym9keQ==",
        },
        "body": "Ym9keQ==",
    }
    body = {uuid: entry}
    if pad_len:
        body["pad"] = "x" * pad_len
    return json.dumps(body).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    """Serves one configured response body per request."""

    mode = "normal"
    body = b"{}"
    status = 200

    def _drain(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)

    def _send(self):
        payload = _Handler.body
        self.send_response(_Handler.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        self._drain()
        self._send()

    def do_GET(self):
        self._send()

    def log_message(self, *args):
        pass


def _serve(mode, body, status=200):
    _Handler.mode = mode
    _Handler.body = body
    _Handler.status = status
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _anchor_client(mod):
    if mod is ra:
        return ra.SelfHostedRekor(
            url="http://127.0.0.1:%d" % _PORT[0], log_id="f204-test-log")
    seed = bytes(range(32))
    pub = bytes([(i * 7) % 256 for i in range(32)])
    return ab.RekorBackend(
        url="http://127.0.0.1:%d" % _PORT[0],
        anchor_seed=seed, anchor_pubkey=pub)


_PORT = [0]

_AHASH = hashlib.sha256(b"f204-anchor").hexdigest()
_FAKE_PEM = ("-----BEGIN PUBLIC KEY-----\n"
             "MCowBQYDK2VwAyEA7v7v7v7v7v7v7v7v7v7v7v7v7v7v7v7v7v7v7v7v7v8=\n"
             "-----END PUBLIC KEY-----\n")
_SIG_B64 = base64.b64encode(b"\x01" * 64).decode("ascii")


def _submit_ra(client):
    return client.submit(_AHASH, signature_b64=_SIG_B64, pubkey_pem=_FAKE_PEM)


def _submit_ab(client):
    return client.submit(_AHASH)


def p_oversized_refused_rekor_anchor():
    name = "p_oversized_refused_rekor_anchor"
    body = _entry_body("uuid-over", pad_len=OVERSIZED)
    assert len(body) > OVERSIZED
    srv = _serve("oversized", body)
    _PORT[0] = srv.server_address[1]
    try:
        client = _anchor_client(ra)
        try:
            client.submit(_AHASH, signature_b64=_SIG_B64,
                          pubkey_pem=_FAKE_PEM)
        except Exception as e:
            msg = str(e)
            if "exceed" in msg and ("byte" in msg or "download" in msg):
                _record(name, "HELD",
                        "oversized body refused loudly: %s" % msg[:80])
            else:
                _record(name, "BREAK",
                        "refused but not LOUDLY about the cap: %r"
                        % (msg[:80],))
            return
        _record(name, "BREAK",
                "2 MiB response body accepted without refusal (unbounded read)")
    finally:
        srv.shutdown()


def p_normal_still_anchors_rekor_anchor():
    name = "p_normal_still_anchors_rekor_anchor"
    srv = _serve("normal", _entry_body("uuid-normal"))
    _PORT[0] = srv.server_address[1]
    try:
        client = _anchor_client(ra)
        try:
            receipt = _submit_ra(client)
        except Exception as e:
            _record(name, "ERROR", "normal submit raised: %r" % (e,))
            return
        if receipt.get("uuid") == "uuid-normal" \
                and receipt.get("anchor_hash") == _AHASH:
            _record(name, "HELD", "receipt carries uuid + anchor hash")
        else:
            _record(name, "BREAK", "receipt malformed: %r" % (receipt,))
    finally:
        srv.shutdown()


def p_truncated_never_verifies():
    name = "p_truncated_never_verifies"
    full = _entry_body("uuid-trunc")
    truncated = full[: len(full) // 2]
    srv = _serve("truncated", truncated)
    _PORT[0] = srv.server_address[1]
    try:
        client = _anchor_client(ra)
        try:
            receipt = _submit_ra(client)
        except Exception as e:
            _record(name, "HELD",
                    "truncated body refused loudly: %s" % (str(e)[:70],))
            return
        _record(name, "BREAK",
                "truncated body produced a receipt: %r" % (receipt,))
    finally:
        srv.shutdown()


def _cap_limit(mod):
    return getattr(mod, "MAX_RESPONSE_BODY_BYTES", None)


def p_cap_boundary_rekor_anchor():
    name = "p_cap_boundary_rekor_anchor"
    limit = _cap_limit(ra)
    if limit is None:
        _record(name, "BREAK",
                "no MAX_RESPONSE_BODY_BYTES on gov.rekor_anchor (no cap)")
        return
    ok_exact, ok_over = False, False
    srv = _serve("exact", b"x" * limit)
    _PORT[0] = srv.server_address[1]
    try:
        try:
            r = ra.SelfHostedRekor._urllib_transport(
                {"method": "GET",
                 "url": "http://127.0.0.1:%d/api/v1/log" % _PORT[0],
                 "headers": {}, "body": ""})
            ok_exact = (len(r["body"].encode("utf-8")) == limit)
        except Exception:
            ok_exact = False
        _Handler.body = b"x" * (limit + 1)
        try:
            ra.SelfHostedRekor._urllib_transport(
                {"method": "GET",
                 "url": "http://127.0.0.1:%d/api/v1/log" % _PORT[0],
                 "headers": {}, "body": ""})
            ok_over = False
        except Exception as e:
            ok_over = "exceed" in str(e)
    finally:
        srv.shutdown()
    if ok_exact and ok_over:
        _record(name, "HELD",
                "exactly-MAX accepted, MAX+1 refused loudly")
    else:
        _record(name, "BREAK",
                "exact-MAX accepted=%s, MAX+1 refused=%s"
                % (ok_exact, ok_over))


def p_oversized_refused_anchor_backend():
    name = "p_oversized_refused_anchor_backend"
    body = _entry_body("uuid-over-ab", pad_len=OVERSIZED)
    assert len(body) > OVERSIZED
    srv = _serve("oversized", body)
    _PORT[0] = srv.server_address[1]
    try:
        client = _anchor_client(ab)
        try:
            client.submit(_AHASH)
        except Exception as e:
            msg = str(e)
            if "exceed" in msg and ("byte" in msg or "download" in msg):
                _record(name, "HELD",
                        "oversized body refused loudly: %s" % msg[:80])
            else:
                _record(name, "BREAK",
                        "refused but not LOUDLY about the cap: %r"
                        % (msg[:80],))
            return
        _record(name, "BREAK",
                "2 MiB response body accepted without refusal (unbounded read)")
    finally:
        srv.shutdown()


def p_normal_still_anchors_anchor_backend():
    name = "p_normal_still_anchors_anchor_backend"
    srv = _serve("normal", _entry_body("uuid-normal-ab"))
    _PORT[0] = srv.server_address[1]
    try:
        client = _anchor_client(ab)
        try:
            receipt = _submit_ab(client)
        except Exception as e:
            _record(name, "ERROR", "normal submit raised: %r" % (e,))
            return
        if receipt.get("uuid") == "uuid-normal-ab" \
                and receipt.get("anchor_hash") == _AHASH:
            _record(name, "HELD", "receipt carries uuid + anchor hash")
        else:
            _record(name, "BREAK", "receipt malformed: %r" % (receipt,))
    finally:
        srv.shutdown()


def p_cap_boundary_anchor_backend():
    name = "p_cap_boundary_anchor_backend"
    limit = _cap_limit(ab)
    if limit is None:
        _record(name, "BREAK",
                "no MAX_RESPONSE_BODY_BYTES on gov.anchor_backend (no cap)")
        return
    ok_exact, ok_over = False, False
    srv = _serve("exact", b"x" * limit)
    _PORT[0] = srv.server_address[1]
    try:
        try:
            r = ab.RekorBackend._urllib_transport(
                {"method": "GET",
                 "url": "http://127.0.0.1:%d/api/v1/log" % _PORT[0],
                 "headers": {}, "body": ""})
            ok_exact = (len(r["body"].encode("utf-8")) == limit)
        except Exception:
            ok_exact = False
        _Handler.body = b"x" * (limit + 1)
        try:
            ab.RekorBackend._urllib_transport(
                {"method": "GET",
                 "url": "http://127.0.0.1:%d/api/v1/log" % _PORT[0],
                 "headers": {}, "body": ""})
            ok_over = False
        except Exception as e:
            ok_over = "exceed" in str(e)
    finally:
        srv.shutdown()
    if ok_exact and ok_over:
        _record(name, "HELD",
                "exactly-MAX accepted, MAX+1 refused loudly")
    else:
        _record(name, "BREAK",
                "exact-MAX accepted=%s, MAX+1 refused=%s"
                % (ok_exact, ok_over))


def p_deterministic_x2():
    name = "p_deterministic_x2"
    first = [(n, v) for n, v, _ in _RESULTS]
    _RESULTS.clear()
    p_oversized_refused_rekor_anchor()
    p_normal_still_anchors_rekor_anchor()
    p_truncated_never_verifies()
    p_cap_boundary_rekor_anchor()
    p_oversized_refused_anchor_backend()
    p_normal_still_anchors_anchor_backend()
    p_cap_boundary_anchor_backend()
    second = [(n, v) for n, v, _ in _RESULTS]
    _RESULTS.clear()
    if first == second:
        _record(name, "HELD", "verdicts byte-identical across 2 runs")
    else:
        _record(name, "BREAK", "run-to-run verdict drift: %r vs %r"
                % (first, second))


def _run_all():
    p_oversized_refused_rekor_anchor()
    p_normal_still_anchors_rekor_anchor()
    p_truncated_never_verifies()
    p_cap_boundary_rekor_anchor()
    p_oversized_refused_anchor_backend()
    p_normal_still_anchors_anchor_backend()
    p_cap_boundary_anchor_backend()


def green_check():
    """Adjacent anchoring suites, depth-1 (honors GOV_SKIP_GREEN)."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green_check: skipped (GOV_SKIP_GREEN set)")
        return True
    suites = ["tests.test_rekor_anchor", "tests.test_anchoring",
              "tests.test_w72_anchor"]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for suite in suites:
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite],
            cwd=REPO_ROOT, env=env,
            capture_output=True, text=True, timeout=600)
        tail = (r.stderr.strip().splitlines() or [""]) [-1]
        print("green_check %-28s %s" % (suite, tail))
        if r.returncode != 0:
            print(r.stderr[-2000:])
            return False
    return True


def main():
    _run_all()
    p_deterministic_x2()
    ok = green_check()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("f204_closure_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR / green=%s"
          % (held, brk, exp, err, ok))
    return 1 if (brk or err or not ok) else 0


if __name__ == "__main__":
    sys.exit(main())
