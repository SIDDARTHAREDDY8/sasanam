"""Wave-244 MCP-surface secure-defaults audit probes (W244-7, red-first).

Incident shapes (prose re-derived, no upstream code, no incident text):
* ContextForge CVE-2026-78573 (9.8): a default-credentials MCP gateway
  reached unauthenticated admin. A surface that ships with placeholder
  or empty credentials must refuse to go live, never silently serve.
* Langflow CVE-2026-85025 (CWE-863, 9.8): public MCP endpoints skipped
  the anonymous-execution guard. A public endpoint without an
  execution guard / per-call authorization must be refused before it
  goes live.
* Langflow CVE-2026-81941 (8.8): stdio bypass of the auth path. A
  transport that carries agent traffic outside the mediated auth path
  must be refused unless explicitly mediated.

Common shape: insecure-by-default surfaces that only become safe when
the operator opts in. ``gov.surface_defaults.audit_surface`` fails
closed on every insecure default; it NEVER auto-remediates (a silent
fix hides operator error) and names the exact default violated.

Probes:
  default-credentials-refused -- placeholder/default credential
      values -> refused surface-default-credentials.
  empty-credentials-refused -- missing/empty credentials ->
      refused surface-default-credentials.
  admin-unauthenticated-refused -- admin endpoint with no auth ->
      refused surface-admin-unauthenticated.
  public-unguarded-refused -- public endpoint without an execution
      guard -> refused surface-public-unguarded.
  stdio-bypass-refused -- stdio transport bypassing auth mediation ->
      refused surface-transport-bypass.
  secure-config-attested -- an explicitly secure config passes and
      yields an attestation binding the config digest.
  attestation-detects-drift -- post-attestation config change makes
      verify_attestation fail.
  no-auto-remediate -- the audit never mutates its input config, and
      the refusal names the exact violated default.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import copy
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_SD = False
try:
    from gov import surface_defaults as _sd
    HAVE_SD = all(hasattr(_sd, n) for n in (
        "audit_surface", "verify_attestation", "SurfaceDefaultsError"))
except ImportError:
    _sd = None

_ISSUER_KEY = b"\x07" * 32  # test-only issuer key, never production


def _base_config(**over):
    cfg = {
        "surface": "test-gateway",
        "gateway": {
            "credentials": {"username": "ops", "password": "x9K#mQ2$vL7n"},
        },
        "endpoints": [
            {"name": "admin-api", "admin": True, "auth": "token",
             "transport": "https"},
            {"name": "public-tools", "public": True,
             "execution_guard": True, "auth": "token",
             "transport": "https"},
        ],
    }
    cfg.update(over)
    return cfg


def _expect_refusal(fn, code):
    try:
        fn()
    except _sd.SurfaceDefaultsError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        assert exc.detail, "refusal must name the violated default"
        return True
    return False


def p_default_credentials():
    cfg = _base_config()
    cfg["gateway"]["credentials"] = {"username": "admin",
                                     "password": "admin"}
    return _expect_refusal(
        lambda: _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY),
        "surface-default-credentials")


def p_empty_credentials():
    cfg = _base_config()
    cfg["gateway"]["credentials"] = {"username": "ops", "password": ""}
    return _expect_refusal(
        lambda: _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY),
        "surface-default-credentials")


def p_admin_unauthenticated():
    cfg = _base_config()
    cfg["endpoints"][0]["auth"] = "none"
    return _expect_refusal(
        lambda: _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY),
        "surface-admin-unauthenticated")


def p_public_unguarded():
    cfg = _base_config()
    cfg["endpoints"][1]["execution_guard"] = False
    return _expect_refusal(
        lambda: _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY),
        "surface-public-unguarded")


def p_stdio_bypass():
    cfg = _base_config()
    cfg["endpoints"].append({"name": "local-stdio", "transport": "stdio",
                            "auth": "none"})
    return _expect_refusal(
        lambda: _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY),
        "surface-transport-bypass")


def p_secure_config_attested():
    cfg = _base_config()
    att = _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY)
    assert att["verdict"] == "attested", att
    assert att["surface"] == "test-gateway", att
    assert att.get("config_digest"), "attestation must bind config digest"
    # The bound digest must be the digest of the exact config audited.
    assert att["config_digest"] == _sd.config_digest(cfg), "digest mismatch"
    return _sd.verify_attestation(att, cfg, issuer_key=_ISSUER_KEY)


def p_attestation_detects_drift():
    cfg = _base_config()
    att = _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY)
    drifted = _base_config()
    drifted["endpoints"][1]["execution_guard"] = True
    drifted["gateway"]["credentials"]["password"] = "other-secret-1!"
    assert not _sd.verify_attestation(att, drifted,
                                      issuer_key=_ISSUER_KEY), \
        "drifted config must not verify"
    # And a wrong issuer key must not verify either.
    assert not _sd.verify_attestation(att, cfg,
                                      issuer_key=b"\x09" * 32), \
        "wrong issuer key must not verify"
    return True


def p_no_auto_remediate():
    cfg = _base_config()
    cfg["gateway"]["credentials"] = {"username": "admin",
                                     "password": "changeme"}
    before = copy.deepcopy(cfg)
    try:
        _sd.audit_surface(cfg, issuer_key=_ISSUER_KEY)
    except _sd.SurfaceDefaultsError as exc:
        # The refusal names the exact violated default, not a generic
        # message; the input is returned untouched.
        assert "changeme" in exc.detail or "default" in exc.detail.lower(), \
            "detail must name the violated default: %r" % exc.detail
    assert cfg == before, "audit_surface must never mutate its input"
    return True


PROBES = {
    "default-credentials-refused": p_default_credentials,
    "empty-credentials-refused": p_empty_credentials,
    "admin-unauthenticated-refused": p_admin_unauthenticated,
    "public-unguarded-refused": p_public_unguarded,
    "stdio-bypass-refused": p_stdio_bypass,
    "secure-config-attested": p_secure_config_attested,
    "attestation-detects-drift": p_attestation_detects_drift,
    "no-auto-remediate": p_no_auto_remediate,
}

PROBE_NAMES = sorted(PROBES)


def _run_probe(name):
    fn = PROBES[name]
    if not HAVE_SD:
        return name, "GAP", "capability absent on pristine base"
    try:
        held = fn()
    except Exception:
        return name, "ERROR", traceback.format_exc(limit=3)
    return name, ("HELD" if held else "FAIL"), \
        ("held" if held else "probe condition not met")


def main():
    results = [_run_probe(n) for n in PROBE_NAMES]
    held = sum(1 for _, s, _ in results if s == "HELD")
    gap = sum(1 for _, s, _ in results if s == "GAP")
    for name, status, note in results:
        print("%-32s %-5s %s" % (name, status, note))
    print("%d/%d HELD  GAP %d/%d" % (held, len(results), gap,
                                    len(results)))
    if gap:
        print("GENUINE RED: %d probes have no implementation on this base"
              % gap)
    bad = [r for r in results if r[1] in ("FAIL", "ERROR")]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
