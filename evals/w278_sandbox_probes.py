#!/usr/bin/env python3
"""Wave-278 sandbox-containment battery: the e2b steal, break-first.

Target (wave-277 prospecting, child A): e2b's deny-by-default,
runtime-mutable per-sandbox egress policy + lifecycle audit hooks
(Apache-2.0), ADAPTED to our wall topology. Three gaps, all red on the
wave-277 base:

  se01/se02/se08: the sim wall proxy forwards plaintext-HTTP GET
      path+query with only a host:port allowlist check. A 4x-encoded
      sensitive token in the query (the F296 shape) sails through --
      the L7 decode-to-stability leg from gov/egress_refs.py is never
      consulted at the sandbox egress seam.
  se05/se06: no runtime-mutable per-sandbox network policy exists
      (e2b's updateNetwork analog). Policy is launch-time/file-bound;
      it cannot be narrowed mid-run.
  se07: no lifecycle/policy audit chain exists -- the wall blocks but
      does not log what crossed the boundary (the industry hole E2B
      itself has; our differentiator is the chained attempt log).

After the fix (gov/sandbox_egress.py: SandboxNetworkPolicy +
SandboxEgressController + SandboxEgressAuditor; L7 screening wired into
the wall proxy's GET path; Sandbox.update_network_policy), all probes
must be HELD.

Honest limit (pinned, not filed): CONNECT tunnels are destination-wall
only -- the TLS bytes tunnel opaquely by design, so no L7 leg can see
the path (se09 documents this).

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic; fresh unique
/var/tmp/g278-sandbox TMPDIR (`mkdir -p` first); depth-1 green checks
honoring GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib only.
"""

import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g278-sandbox-%d-" % os.getpid(),
                         dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import probe_lines  # noqa: E402  (canonical probe-line form)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []

# Synthetic test token only -- never a real credential. Shaped like the
# F296 token: '/' chars force percent-encoding; the decoded form survives
# _payload_tokens as a digest-eligible (>=8 char) token.
SECRET = "zx/qw/er_ty-99"


def _encode_n(text, n):
    enc = text
    for _ in range(n):
        enc = urllib.parse.quote(enc, safe="")
    return enc


def _digest(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


# ------------------------------------------------------------------
# Fixture: origin server + confined DNS + wall proxy (localhost only).
# ------------------------------------------------------------------

class _Fixture(object):
    def __init__(self, with_policy=True):
        self.root = tempfile.mkdtemp(prefix="se-fix-", dir=_TMP)
        self.origin = self._start_origin()
        zone = os.path.join(self.root, "zone.txt")
        with open(zone, "w", encoding="utf-8") as f:
            f.write("victim.example 127.0.0.1\n")
        allowlist = os.path.join(self.root, "allowlist.txt")
        with open(allowlist, "w", encoding="utf-8") as f:
            f.write("victim.example:%d\n" % self.origin_port)
        from gov.egress_launcher import StubDnsServer, StubProxyServer
        self.dns = StubDnsServer(zone)
        self.dns.start()
        self.controller = None
        self.auditor = None
        self.deny_log = os.path.join(self.root, "deny.log")
        self.seam_error = None
        kwargs = {}
        if with_policy:
            try:
                # Raises ImportError/TypeError on the wave-277 base
                # (the seam does not exist there) -- the probe records
                # BREAK, not ERROR.
                from gov import sandbox_egress as se
                self.auditor = se.SandboxEgressAuditor()
                pol = se.SandboxNetworkPolicy({
                    "version": "v1",
                    "allow_out": ["victim.example:%d" % self.origin_port],
                    "sensitive_digests": [_digest(SECRET)],
                })
                self.controller = se.SandboxEgressController(
                    pol, auditor=self.auditor)
                kwargs["network_policy"] = self.controller
                kwargs["auditor"] = self.auditor
            except (ImportError, TypeError) as exc:
                self.seam_error = exc
        # The stub proxy only accepts the new kwargs post-fix; on the
        # base the TypeError below records BREAK via seam_error.
        try:
            self.proxy = StubProxyServer(
                allowlist, "127.0.0.1", self.dns.port,
                deny_log_path=self.deny_log, **kwargs)
        except TypeError as exc:
            if not kwargs:
                raise
            self.seam_error = exc
            self.controller = None
            self.auditor = None
            self.proxy = StubProxyServer(
                allowlist, "127.0.0.1", self.dns.port,
                deny_log_path=self.deny_log)
        self.proxy.start()
        time.sleep(0.2)

    def deny_log_text(self):
        try:
            with open(self.deny_log, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    def _start_origin(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        self.origin_port = srv.getsockname()[1]
        stop = threading.Event()

        def _serve():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    conn.settimeout(3.0)
                    try:
                        conn.recv(65536)
                    except OSError:
                        pass
                    conn.sendall(b"HTTP/1.0 200 OK\r\n"
                                 b"Content-Length: 2\r\n\r\nok")
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        self._origin_stop = stop
        self._origin_sock = srv
        return srv

    def close(self):
        try:
            self.proxy.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.dns.stop()
        except Exception:  # noqa: BLE001
            pass
        self._origin_stop.set()
        try:
            self._origin_sock.close()
        except OSError:
            pass

    def get(self, path):
        url = "http://victim.example:%d%s" % (self.origin_port, path)
        s = socket.create_connection(
            ("127.0.0.1", self.proxy.port), timeout=8)
        try:
            s.sendall(("GET %s HTTP/1.0\r\n\r\n" % url).encode("ascii"))
            data = b""
            s.settimeout(8)
            while True:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            s.close()
        return data.split(b"\r\n", 1)[0] if data else b""

    def connect_host(self, hostport):
        s = socket.create_connection(
            ("127.0.0.1", self.proxy.port), timeout=8)
        try:
            s.sendall(("CONNECT %s HTTP/1.1\r\n\r\n"
                        % hostport).encode("ascii"))
            s.settimeout(8)
            data = s.recv(1024)
        finally:
            s.close()
        return data.split(b"\r\n", 1)[0] if data else b""


# ------------------------------------------------------------------
# Probes.
# ------------------------------------------------------------------

def se01_quad_encoded_exfil_refused():
    """4x-encoded sensitive token in a GET query must be refused at the
    sandbox egress seam (the F296 shape, now at the wall proxy)."""
    fix = _Fixture()
    try:
        if fix.seam_error is not None:
            return ("BREAK", "no per-sandbox L7 policy seam on base")
        enc = _encode_n(SECRET, 4)
        status = fix.get("/x?d=" + enc)
        if status.startswith(b"HTTP/1.1 403") \
                and "egress-ref-data-exfil" in fix.deny_log_text():
            return ("HELD", "4x-encoded token refused at wall proxy")
        return ("BREAK", "4x exfil passed the wall: %r" % status)
    finally:
        fix.close()


def se02_plaintext_digest_refused():
    """1x-encoded sensitive token in a GET query must be refused."""
    fix = _Fixture()
    try:
        if fix.seam_error is not None:
            return ("BREAK", "no per-sandbox L7 policy seam on base")
        enc = _encode_n(SECRET, 1)
        status = fix.get("/x?d=" + enc)
        if status.startswith(b"HTTP/1.1 403"):
            return ("HELD", "1x-encoded token refused at wall proxy")
        return ("BREAK", "1x exfil passed the wall: %r" % status)
    finally:
        fix.close()


def se03_benign_get_allowed():
    """Control: clean GET to an allowlisted host still flows (anti-FP)."""
    fix = _Fixture(with_policy=False)
    try:
        status = fix.get("/search?q=hello%20world&n=42")
        if b"200" in status:
            return ("HELD", "benign GET allowed: %r" % status)
        return ("BREAK", "benign GET blocked: %r" % status)
    finally:
        fix.close()


def se04_connect_nonallowlisted_denied():
    """Control: CONNECT to a non-allowlisted host stays denied."""
    fix = _Fixture(with_policy=False)
    try:
        status = fix.connect_host("evil.example:443")
        if b"403" in status:
            return ("HELD", "non-allowlisted CONNECT denied")
        return ("BREAK", "non-allowlisted CONNECT passed: %r" % status)
    finally:
        fix.close()


def se05_runtime_policy_update_narrows():
    """e2b updateNetwork analog: narrowing the policy mid-run denies
    previously-allowed egress."""
    fix = _Fixture()
    try:
        if fix.seam_error is not None:
            return ("BREAK", "no per-sandbox L7 policy seam on base")
        from gov.sandbox import Sandbox
        auditor = fix.auditor
        sb = Sandbox(network_policy=fix.controller,
                     audit=auditor.event,
                     use_netns=False, use_pidns=False,
                     use_seccomp=False)
        if not hasattr(sb, "update_network_policy"):
            return ("BREAK", "Sandbox.update_network_policy absent")
        before = fix.get("/ok")
        if b"200" not in before:
            return ("ERROR", "pre-update baseline not 200: %r" % before)
        sb.update_network_policy({
            "version": "v2-narrowed",
            "allow_out": [],
            "sensitive_digests": [_digest(SECRET)],
        })
        after = fix.get("/ok")
        if b"403" in after:
            kinds = [e["kind"] for e in auditor.events]
            if "policy-updated" in kinds:
                return ("HELD", "mid-run narrowing denied; "
                                "policy-updated chained")
            return ("BREAK", "denied but no policy-updated event")
        return ("BREAK", "narrowed policy still allowed: %r" % after)
    finally:
        fix.close()


def se06_malformed_update_refused_loud():
    """Malformed policy update refuses loudly; the old policy keeps
    serving (fail-closed, never half-parsed)."""
    fix = _Fixture()
    try:
        if fix.seam_error is not None:
            return ("BREAK", "no per-sandbox L7 policy seam on base")
        from gov.sandbox import Sandbox
        from gov import sandbox_egress as se
        sb = Sandbox(network_policy=fix.controller,
                     audit=fix.auditor.event,
                     use_netns=False, use_pidns=False,
                     use_seccomp=False)
        try:
            sb.update_network_policy({"version": "",
                                      "allow_out": "not-a-list"})
        except se.PolicyRefusedError:
            pass
        except AttributeError:
            return ("BREAK", "Sandbox.update_network_policy absent")
        except Exception as exc:  # noqa: BLE001
            return ("BREAK", "wrong exception: %r" % exc)
        else:
            return ("BREAK", "malformed update silently accepted")
        status = fix.get("/still-ok")
        if b"200" in status:
            return ("HELD", "malformed refused loudly; old policy serves")
        return ("BREAK", "old policy stopped serving: %r" % status)
    finally:
        fix.close()


def se07_lifecycle_chain_verifies():
    """Lifecycle + policy events are hash-chained and verify: what
    crossed the boundary is evidence, not just enforcement."""
    fix = _Fixture()
    try:
        if fix.seam_error is not None:
            return ("BREAK", "no per-sandbox L7 policy seam on base")
        from gov.sandbox import Sandbox
        auditor = fix.auditor
        sb = Sandbox(network_policy=fix.controller,
                     audit=auditor.event,
                     use_netns=False, use_pidns=False,
                     use_seccomp=False)
        if not hasattr(sb, "update_network_policy"):
            return ("BREAK", "Sandbox.update_network_policy absent")
        fix.get("/ev1")
        sb.update_network_policy({
            "version": "v2",
            "allow_out": ["victim.example:%d" % fix.origin_port],
            "sensitive_digests": [_digest(SECRET)],
        })
        kinds = [e["kind"] for e in auditor.events]
        need = {"sandbox-created", "policy-updated", "egress-attempt"}
        if not need.issubset(set(kinds)):
            return ("BREAK", "missing lifecycle kinds: %r" % kinds)
        if auditor.verify():
            return ("HELD", "chain verifies: %d events" % len(kinds))
        return ("BREAK", "audit chain failed verification")
    finally:
        fix.close()


def se08_oversized_query_refused():
    """Query over the payload budget is refused at the seam."""
    fix = _Fixture()
    try:
        if fix.seam_error is not None:
            return ("BREAK", "no per-sandbox L7 policy seam on base")
        status = fix.get("/x?d=" + "A" * 600)
        if status.startswith(b"HTTP/1.1 403"):
            return ("HELD", "oversized query refused")
        return ("BREAK", "oversized query passed: %r" % status)
    finally:
        fix.close()


def se09_connect_path_is_destination_only():
    """Pinned honest limit: CONNECT carries no path, so the L7 leg
    cannot apply -- the destination wall is the whole decision there.
    Documents the limit; must not regress into a bypass claim."""
    fix = _Fixture()
    try:
        if fix.seam_error is not None:
            return ("BREAK", "no per-sandbox L7 policy seam on base")
        # Allowlisted CONNECT still tunnels (destination decision);
        # the probe only pins that no L7 refusal is *claimed* for it.
        status = fix.connect_host(
            "victim.example:%d" % fix.origin_port)
        if b"200" in status or b"403" in status:
            return ("HELD", "CONNECT decision is destination-only "
                            "(documented limit): %r" % status)
        return ("BREAK", "unexpected CONNECT outcome: %r" % status)
    finally:
        fix.close()


_PROBES = [
    ("se01-quad-encoded-exfil-refused", "HELD", se01_quad_encoded_exfil_refused),
    ("se02-plaintext-digest-refused", "HELD", se02_plaintext_digest_refused),
    ("se03-benign-get-allowed", "HELD", se03_benign_get_allowed),
    ("se04-connect-nonallowlisted-denied", "HELD",
     se04_connect_nonallowlisted_denied),
    ("se05-runtime-policy-update-narrows", "HELD",
     se05_runtime_policy_update_narrows),
    ("se06-malformed-update-refused-loud", "HELD",
     se06_malformed_update_refused_loud),
    ("se07-lifecycle-chain-verifies", "HELD", se07_lifecycle_chain_verifies),
    ("se08-oversized-query-refused", "HELD", se08_oversized_query_refused),
    ("se09-connect-path-destination-only", "HELD",
     se09_connect_path_is_destination_only),
]


def green_check():
    """Depth-1: adjacent sim-battery + egress-ref unit tests, with
    GOV_SKIP_GREEN=1 so they do not recurse."""
    if GREEN_SKIP:
        return [("green-check",
                 "GOV_SKIP_GREEN=1: recorded, not recursing")]
    out = []
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    py = sys.executable
    for label, cmd in (
        ("s7egress_break", [py, "evals/s7egress_break.py"]),
        ("test_egress_refs",
         [py, "-m", "unittest", "tests.test_egress_refs", "-v"]),
    ):
        try:
            cp = subprocess.run(
                cmd, cwd=REPO, env=env, capture_output=True,
                timeout=600, text=True)
            ok = cp.returncode == 0
            out.append((label, "green rc=0" if ok else
                        "NOT GREEN rc=%d: %s" % (
                            cp.returncode,
                            (cp.stdout + cp.stderr)[-800:])))
        except Exception as exc:  # noqa: BLE001
            out.append((label, "ERROR: %s" % exc))
    return out


def main():
    print("wave-278 sandbox-containment battery "
          "(base-red expected pre-fix)")
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    # Wave-316 lane-3 decision (D1 PASS/FAIL rationale): ok -> HELD,
    # MISMATCH -> BREAK. Exit-equivalence: every probe expects HELD,
    # so an actual BREAK/ERROR verdict always implies ok=False; the
    # old `n_break or n_err or mism` reduces to `mism`, and folding
    # the green checks into brk preserves `or not green_ok`.
    mapped = []
    for pid, expected, verdict, ok, note in _RESULTS:
        mapped.append((pid, "HELD" if ok else "BREAK",
                       "expected=%s got=%s :: %s" % (expected, verdict,
                                                     note)))
    probe_lines.emit(mapped)
    print("--- green checks (depth-1) ---")
    gc_mapped = []
    for label, note in green_check():
        bad = note.startswith("NOT GREEN") or note.startswith("ERROR")
        if "GOV_SKIP_GREEN=1" in note:
            gc_mapped.append((label, "SKIP", note))
        elif bad:
            gc_mapped.append((label, "BREAK", note))
        else:
            gc_mapped.append((label, "HELD", note))
    probe_lines.emit(gc_mapped)
    mapped.extend(gc_mapped)
    brk = sum(1 for _, v, _ in mapped if v == "BREAK")
    hld = sum(1 for _, v, _ in mapped if v == "HELD")
    err = 0
    _coh_ok, _coh_diags = probe_lines.check_coherence(mapped, brk, hld, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, hld, err))
    n_break = sum(1 for _, _, v, _, _ in _RESULTS if v == "BREAK")
    n_err = sum(1 for _, _, v, _, _ in _RESULTS if v == "ERROR")
    green_ok = all(v != "BREAK" for _, v, _ in gc_mapped)
    print("probes: %d BREAK / %d ERROR; green checks %s"
          % (n_break, n_err, "GREEN" if green_ok else "NOT GREEN"))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
