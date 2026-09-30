"""Wave-246 MCP DNS-discovery trust probes (W246-9, red-first).

Threat model from draft-morrison-mcp-dns-discovery -07 (posted
2026-09-30, "Discovery of Model Context Protocol Servers via DNS TXT
Records" -- MCP server discovery + operator identity via DNS): DNS is
an UNTRUSTED discovery plane. A DNS-discovered server must not be
trusted without explicit deployment pinning, and a forged DNS record
claiming a pinned server's identity must be refused loudly -- never
silently trusted, never silently ignored.

The product has no DNS client (by design; none is built here). The
seam under test is the trust decision where discovery results ENTER:
gov/mcp_discovery_trust.check_discovery(discovery, pins).

Probes:
  dns-unattested-not-in-registry (PIN) -- a discovery-shaped but
      unattested statement never enters the attested tool registry
      (gov.mcp_annotations.build_tool_registry refuses it).
  dns-unpinned-mapping-refused (PIN) -- invocation authz without a
      pinned mapping digest refuses mapping-unpinned
      (gov.mcp_invocation_authz).
  dns-discovered-unpinned-refused (GAP->HELD) -- a DNS-discovered
      server with no deployment pin refuses discovery-unpinned.
  dns-claimed-identity-mismatch (GAP->HELD) -- a discovery result
      claiming a pinned name with a non-matching identity refuses
      discovery-identity-mismatch.
  dns-forged-record-not-trusted (GAP->HELD) -- a forged DNS TXT
      record (attacker endpoint + attacker key, pinned name)
      refuses discovery-identity-mismatch; never accepted.
  dns-pinned-identity-accepted (GAP->HELD) -- pinned name + matching
      identity accepts, with the pin verified (not merely asserted).
  dns-source-never-trusted (GAP->HELD) -- the source label ("dns"
      vs "manual") never changes the verdict; trust comes from pins.
      A changed endpoint with a matching identity still accepts
      (endpoint is a locator, identity is the trust anchor).
  dns-discovery-malformed (GAP->HELD) -- malformed discovery or pin
      inputs refuse discovery-result-malformed, never silently.

Stdlib only. Deterministic: no network, no DNS lookups, no clock,
no in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import mcp_annotations as _ma
from gov import mcp_invocation_authz as _mia

HAVE_DISCOVERY_TRUST = False
try:
    from gov import mcp_discovery_trust as _mdt
    HAVE_DISCOVERY_TRUST = all(hasattr(_mdt, n) for n in (
        "check_discovery", "McpDiscoveryTrustError",
        "DISCOVERY_UNPINNED", "DISCOVERY_IDENTITY_MISMATCH",
        "DISCOVERY_RESULT_MALFORMED"))
except ImportError:
    _mdt = None


def _run_probe(name, fn, have, pin=False):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, ("PIN" if pin else "HELD"), note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    try:
        fn()
    except _mdt.McpDiscoveryTrustError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# PIN probes: existing wiring already holds these; they document the boundary
# the new gate composes with. They PASS on the pristine base.
# ---------------------------------------------------------------------------

def _probe_unattested_not_in_registry():
    # A discovery-shaped input with no keyset attestation must never
    # enter the attested tool registry.
    registry, refused = _ma.build_tool_registry(
        [{"server": "dns-found.example", "note": "no attestation"}], {})
    assert registry == {}, "unattested input entered the registry: %r" % (
        registry,)
    assert len(refused) == 1, "expected exactly one refusal, got %r" % (
        refused,)
    return "unattested discovery input refused; registry empty"


def _probe_unpinned_mapping_refused():
    policy = _mia.build_policy({"subject_id": "agent-1"})
    result = _mia.authorize(
        policy,
        {"method": "tools/call", "params": {}, "id": 1},
        {"subject": {"id": "agent-1"},
         "server_mapping": {"server::tool": {"type": "object"}}})
    assert result.verdict == "refuse", "verdict %r" % (result.verdict,)
    assert result.code == "mapping-unpinned", "code %r" % (result.code,)
    return "unpinned mapping refuses mapping-unpinned"


# ---------------------------------------------------------------------------
# GAP probes: the explicit discovery-trust decision. They FAIL (GAP) on the
# pristine base, where no such gate exists, and HOLD once the gate lands.
# ---------------------------------------------------------------------------

_PINNED = {"trusted-server": "key-fp-9f2a44c1"}


def _dns_discovery(name="trusted-server",
                   endpoint="https://trusted.example/mcp",
                   identity="key-fp-9f2a44c1",
                   source="dns"):
    return {"name": name, "endpoint": endpoint, "identity": identity,
            "source": source}


def _probe_discovered_unpinned_refused():
    note = _expect_refusal(
        lambda: _mdt.check_discovery(
            _dns_discovery(name="unknown-server",
                           identity="key-fp-deadbeef"),
            _PINNED),
        "discovery-unpinned")
    # Empty pin set: everything is unpinned, fail closed.
    note2 = _expect_refusal(
        lambda: _mdt.check_discovery(_dns_discovery(), {}),
        "discovery-unpinned")
    return "%s; %s" % (note, note2)


def _probe_claimed_identity_mismatch():
    note = _expect_refusal(
        lambda: _mdt.check_discovery(
            _dns_discovery(identity="key-fp-ATTACKER"),
            _PINNED),
        "discovery-identity-mismatch")
    return note


def _probe_forged_record_not_trusted():
    # Forged DNS TXT record: attacker endpoint + attacker key, but the
    # PINNED name. Must refuse loudly, never accept.
    forged = {"name": "trusted-server",
              "endpoint": "https://attacker.invalid/mcp",
              "identity": "key-fp-ATTACKER",
              "source": "dns"}
    note = _expect_refusal(
        lambda: _mdt.check_discovery(forged, _PINNED),
        "discovery-identity-mismatch")
    return "%s; forged record never accepted" % note


def _probe_pinned_identity_accepted():
    record = _mdt.check_discovery(_dns_discovery(), _PINNED)
    assert record["verdict"] == "accept", "verdict %r" % (record,)
    assert record["name"] == "trusted-server", "name %r" % (record,)
    assert record["identity"] == "key-fp-9f2a44c1", "identity %r" % (record,)
    return "pinned identity accepted; pin verified"


def _probe_source_never_trusted():
    # The source label must not change the verdict: trust comes from
    # pins, never from the discovery plane.
    via_dns = _mdt.check_discovery(_dns_discovery(source="dns"), _PINNED)
    via_manual = _mdt.check_discovery(_dns_discovery(source="manual"),
                                      _PINNED)
    assert via_dns["verdict"] == via_manual["verdict"] == "accept"
    # Unpinned stays refused regardless of source label.
    for source in ("dns", "manual", "operator-ui"):
        try:
            _mdt.check_discovery(
                _dns_discovery(name="unknown", identity="x", source=source),
                _PINNED)
        except _mdt.McpDiscoveryTrustError as exc:
            assert exc.code == "discovery-unpinned", exc.code
        else:
            raise AssertionError("source %r bypassed pin requirement" % (
                source,))
    # Endpoint is a locator, not identity: same pinned identity at a
    # new endpoint still accepts.
    moved = _mdt.check_discovery(
        _dns_discovery(endpoint="https://trusted-new.example/mcp"), _PINNED)
    assert moved["verdict"] == "accept", "verdict %r" % (moved,)
    return "source label never confers trust; endpoint is a locator"


def _probe_discovery_malformed():
    cases = [
        (None, _PINNED, "discovery None"),
        ("not-a-mapping", _PINNED, "discovery str"),
        ({}, _PINNED, "discovery empty"),
        ({"name": "", "endpoint": "https://x.example",
          "identity": "k"}, _PINNED, "empty name"),
        ({"name": "trusted-server", "endpoint": "https://x.example"},
         _PINNED, "missing identity"),
        (_dns_discovery(), None, "pins None"),
        (_dns_discovery(), {"trusted-server": ""}, "empty pin value"),
        (_dns_discovery(), {"trusted-server": 42}, "non-str pin value"),
    ]
    for discovery, pins, label in cases:
        try:
            _mdt.check_discovery(discovery, pins)
        except _mdt.McpDiscoveryTrustError as exc:
            assert exc.code == "discovery-result-malformed", \
                "%s: code %r" % (label, exc.code)
        else:
            raise AssertionError("%s: no refusal" % label)
    return "8 malformed shapes refuse discovery-result-malformed"


_PROBES = [
    ("dns-unattested-not-in-registry", _probe_unattested_not_in_registry,
     "PIN_WIRING", True),
    ("dns-unpinned-mapping-refused", _probe_unpinned_mapping_refused,
     "PIN_WIRING", True),
    ("dns-discovered-unpinned-refused", _probe_discovered_unpinned_refused,
     "HAVE_DISCOVERY_TRUST", False),
    ("dns-claimed-identity-mismatch", _probe_claimed_identity_mismatch,
     "HAVE_DISCOVERY_TRUST", False),
    ("dns-forged-record-not-trusted", _probe_forged_record_not_trusted,
     "HAVE_DISCOVERY_TRUST", False),
    ("dns-pinned-identity-accepted", _probe_pinned_identity_accepted,
     "HAVE_DISCOVERY_TRUST", False),
    ("dns-source-never-trusted", _probe_source_never_trusted,
     "HAVE_DISCOVERY_TRUST", False),
    ("dns-discovery-malformed", _probe_discovery_malformed,
     "HAVE_DISCOVERY_TRUST", False),
]


def main():
    # This battery spawns no nested green-check subprocesses, so the
    # probes must always run -- a GOV_SKIP_GREEN early return would make
    # the battery a vacuous pass depth-1 (wave-244 merge lesson).
    flags = {"HAVE_DISCOVERY_TRUST": HAVE_DISCOVERY_TRUST,
             "PIN_WIRING": True}
    results = []
    for name, fn, flag, pin in _PROBES:
        results.append(_run_probe(name, fn, flags[flag], pin=pin))
    held = sum(1 for _, s, _ in results if s in ("HELD", "PIN"))
    total = len(results)
    for name, status, note in results:
        print("%-36s %-6s %s" % (name, status, note.split("\n")[0]))
    print("w246_mcp_dns_discovery: %d/%d HELD-or-PIN" % (held, total))
    return 0 if held == total else 2


if __name__ == "__main__":
    sys.exit(main())
