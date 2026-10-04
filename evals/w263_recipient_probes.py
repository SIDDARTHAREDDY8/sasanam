"""Break-first battery for wave-263 lane 1: pluggable envelope recipients.

Age-plugin-protocol ADAPT (str4d/age-plugin-yubikey, MIT OR Apache-2.0;
pattern only -- no age code vendored): recipient-namespace routing,
recipient-v1/identity-v1 stanza state machines over spawned binaries,
framework-enforced label consistency. Recombined here as an in-process
recipient-plugin protocol for gov/encrypted_envelopes.py with a
documented out-of-process seam.

Two modes x every probe (the x2):
- legacy: the pre-existing public API (EnvelopeVault.seal/open,
  Recipient, KeyWrap) -- the ONLY API that existed pre-fix. Its GAPs
  are structural: the property is inexpressible through that API, and
  they remain true post-fix by design (backward compatibility is a
  feature, not a regression).
- plugin: the new gov/recipient_plugins.py protocol. Every probe must
  HELD here; anything else is a BREAK.

Targets (base 82c84934027be71083d260520c3b7fb3eab89ffa, taxonomy pin
1129 + 7 recipient-plugin-* codes = 1136):
- gov/recipient_plugins.py -- namespace registration conflicts,
  label routing (longest-prefix, legacy fallback, unknown-label),
  framework label-consistency + wrap-size enforcement, Shamir k-of-n
  quorum plugin, subprocess seam stub.
- gov/encrypted_envelopes.py integration -- seal_plugin/open_plugin,
  legacy seal/open byte-compatibility, open-time error conversion to
  the single envelope-open-refused code, journal digest-only.

Deterministic across runs (staging + `env -u GOV_DEPLOYMENT_MODE`).
No in-repo git subprocesses (wave-36 supply-chain probe: fail closed).
Stdlib only.
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

from gov import decision_codes  # noqa: E402
from gov import encrypted_envelopes as ee  # noqa: E402

try:
    from gov import recipient_plugins as rp  # noqa: E402
    _HAVE_RP = True
except ImportError:
    rp = None
    _HAVE_RP = False

TAXONOMY_PIN = 2020 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*)



_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _gap(detail):
    return ("GAP", detail)


def _held(detail):
    return ("HELD", detail)


def _break(detail):
    return ("BREAK", detail)


def _na(detail):
    return ("N/A", detail)


def _tmp_vault(**kw):
    d = tempfile.mkdtemp(prefix="w263-")
    return ee.EnvelopeVault(os.path.join(d, "j.jsonl"), **kw)


def _km(seed):
    return hashlib.sha256(b"w263-%s" % seed.encode()).digest()


# ---------------------------------------------------------------------------
# 1. Namespace hijack: a plugin claiming another plugin's label namespace
# ---------------------------------------------------------------------------

@probe("namespace-hijack")
def _p_hijack(mode):
    if mode == "legacy":
        # Pre-fix API: recipient ids are opaque strings. There is no
        # namespace, no registry, no claim check -- a label shaped like
        # another recipient type's namespace is silently accepted.
        v = _tmp_vault()
        env = v.seal(b"data", [ee.Recipient("gov1quorum1rogue", _km("a"))])
        out, _meta = v.open(env, _km("a"))
        assert out == b"data"
        return _gap(
            "legacy vault has no recipient namespaces: id "
            "'gov1quorum1rogue' sealed/opened as an opaque symmetric "
            "recipient; a plugin claiming another's namespace is "
            "undetectable")
    # plugin mode
    reg = rp.default_registry()
    d = tempfile.mkdtemp(prefix="w263-")
    v = ee.EnvelopeVault(os.path.join(d, "j.jsonl"), plugins=reg)

    class Rogue(rp.RecipientPlugin):
        NAME = "rogue/v1"
        LABEL_NAMESPACE = "gov1sym"  # already claimed by the default

        def wrap(self, envelope_key, label, identity):
            return [(label, b"\x00" * 48)]

        def unwrap(self, entries, identity):
            return [(label, b"\x00" * 32) for label, _w in entries]

    for plugin, why in (
            (Rogue(), "exact namespace claim"),
    ):
        try:
            reg.register(plugin)
        except rp.RecipientPluginError as e:
            assert e.code == "recipient-plugin-namespace-conflict", e.code
            continue
        return _break("rogue plugin registered despite %s" % why)

    class Rogue2(Rogue):
        NAME = "rogue2/v1"
        LABEL_NAMESPACE = "gov1symx"  # prefix-overlaps gov1sym

    try:
        reg.register(Rogue2())
    except rp.RecipientPluginError as e:
        assert e.code == "recipient-plugin-namespace-conflict", e.code
    else:
        return _break("prefix-overlapping namespace 'gov1symx' registered")

    class Rogue3(Rogue):
        NAME = "symmetric-hmac/v1"  # duplicate plugin name
        LABEL_NAMESPACE = "gov1rogue"

    try:
        reg.register(Rogue3())
    except rp.RecipientPluginError as e:
        assert e.code == "recipient-plugin-namespace-conflict", e.code
    else:
        return _break("duplicate plugin name registered")

    class BadShape(Rogue):
        NAME = "badshape/v1"
        LABEL_NAMESPACE = "NOT-A-NAMESPACE"

    try:
        reg.register(BadShape())
    except rp.RecipientPluginError as e:
        assert e.code == "recipient-plugin-namespace-conflict", e.code
    else:
        return _break("malformed namespace registered")

    assert "gov1sym" in reg.namespaces() and "gov1quorum" in reg.namespaces()
    return _held(
        "namespace hijack refused at registration "
        "(recipient-plugin-namespace-conflict): exact claim, "
        "prefix overlap, duplicate name, malformed shape")


# ---------------------------------------------------------------------------
# 2. Unknown recipient label -> machine-coded refusal
# ---------------------------------------------------------------------------

@probe("unknown-recipient-label")
def _p_unknown(mode):
    if mode == "legacy":
        v = _tmp_vault()
        env = v.seal(b"data", [ee.Recipient("gov1nosuch1x", _km("a"))])
        try:
            v.open(env, _km("wrong"))
        except ee.EnvelopeRefusal as e:
            assert e.code == "envelope-open-refused", e.code
            return _gap(
                "legacy open cannot name an unknown recipient type: "
                "unregistered namespace 'gov1nosuch1' collapses into the "
                "generic envelope-open-refused")
        return _break("legacy open with wrong key did not refuse")
    # plugin mode: seal under a now-unregistered namespace, open with
    # the default registry.
    reg = rp.default_registry()

    class Tmp(rp.RecipientPlugin):
        NAME = "tmp/v1"
        LABEL_NAMESPACE = "gov1tmp"

        def wrap(self, envelope_key, label, identity):
            return [(label, b"\x01" * 48)]

        def unwrap(self, entries, identity):
            return [(label, b"\x02" * 32) for label, _w in entries]

    reg.register(Tmp())
    d = tempfile.mkdtemp(prefix="w263-")
    v = ee.EnvelopeVault(os.path.join(d, "j.jsonl"), plugins=reg)
    env = v.seal_plugin(b"data", [rp.PluginRecipient(
        "gov1tmp1x", "tmp/v1", {})])
    d2 = tempfile.mkdtemp(prefix="w263-")
    v2 = ee.EnvelopeVault(os.path.join(d2, "j.jsonl"))  # default registry
    try:
        v2.open_plugin(env, {"gov1tmp1x": {}})
    except rp.RecipientPluginError as e:
        assert e.code == "recipient-plugin-unknown-label", e.code
    else:
        return _break("open with unregistered namespace did not refuse")
    try:
        v2.open(env, _km("a"))
    except ee.EnvelopeRefusal as e:
        assert e.code == "envelope-open-refused", e.code
    else:
        return _break("legacy open of unknown-namespace envelope "
                      "did not refuse")
    try:
        rp.default_registry().route("gov1nosuch1x")
    except rp.RecipientPluginError as e:
        assert e.code == "recipient-plugin-unknown-label", e.code
    else:
        return _break("route() of unknown namespace did not refuse")
    return _held(
        "unknown recipient label refused with machine code "
        "recipient-plugin-unknown-label (direct route, open_plugin, "
        "and legacy-open conversion)")


# ---------------------------------------------------------------------------
# 3. Plugin error during unwrap -> refusal, never partial plaintext
# ---------------------------------------------------------------------------

@probe("plugin-error-unwrap")
def _p_unwrap_err(mode):
    if mode == "legacy":
        # Pre-fix API: open() takes raw key bytes; there is no
        # component boundary, so a component failure during unwrap has
        # no machine-coded contract -- it collapses into the generic
        # code and the caller cannot tell which component failed.
        v = _tmp_vault()
        env = v.seal(b"data", [ee.Recipient("r0", _km("a"))])
        try:
            v.open(env, {"not": "bytes"})
        except ee.EnvelopeRefusal as e:
            assert e.code == "envelope-open-refused", e.code
            return _gap(
                "legacy open has no component error contract: a "
                "per-recipient unwrap failure is inexpressible, "
                "collapsing into generic envelope-open-refused")
        return _break("legacy open with dict key material did not refuse")
    # plugin mode: a plugin whose unwrap raises -> machine-coded
    # refusal, no plaintext, journaled.
    reg = rp.default_registry()

    class Boom(rp.RecipientPlugin):
        NAME = "boom/v1"
        LABEL_NAMESPACE = "gov1boom"

        def wrap(self, envelope_key, label, identity):
            return [(label, b"\x03" * 48)]

        def unwrap(self, entries, identity):
            raise rp.RecipientPluginError(
                "recipient-plugin-unwrap-refused", "boom: fault injected")

    reg.register(Boom())
    d = tempfile.mkdtemp(prefix="w263-")
    v = ee.EnvelopeVault(os.path.join(d, "j.jsonl"), plugins=reg)
    env = v.seal_plugin(b"top-secret", [rp.PluginRecipient(
        "gov1boom1x", "boom/v1", {})])
    journal = os.path.join(d, "j.jsonl")
    try:
        v.open_plugin(env, {"gov1boom1x": {}})
    except ee.EnvelopeRefusal as e:
        assert e.code == "envelope-open-refused", e.code
    else:
        return _break("faulty plugin unwrap did not refuse")
    # No partial plaintext anywhere: the journal carries digests only.
    with open(journal, "rb") as f:
        journal_bytes = f.read()
    assert b"top-secret" not in journal_bytes, "plaintext in journal!"
    # A non-protocol exception from a plugin is also converted, never
    # propagated raw.
    class RawBoom(Boom):
        NAME = "rawboom/v1"
        LABEL_NAMESPACE = "gov1rawboom"

        def unwrap(self, entries, identity):
            raise RuntimeError("raw bug, not a protocol error")

    reg.register(RawBoom())
    env2 = v.seal_plugin(b"top-secret-2", [rp.PluginRecipient(
        "gov1rawboom1x", "rawboom/v1", {})])
    try:
        v.open_plugin(env2, {"gov1rawboom1x": {}})
    except ee.EnvelopeRefusal as e:
        assert e.code == "envelope-open-refused", e.code
    except RuntimeError:
        return _break("raw plugin exception propagated uncaught")
    else:
        return _break("raw-fault plugin unwrap did not refuse")
    return _held(
        "plugin unwrap errors -> envelope-open-refused (protocol and "
        "raw exceptions); no plaintext returned, journal digest-only")


# ---------------------------------------------------------------------------
# 4/5/6. Quorum recipient: k-1 refused, k opens, wrong share refused
# ---------------------------------------------------------------------------

def _quorum_vault():
    d = tempfile.mkdtemp(prefix="w263-")
    return ee.EnvelopeVault(os.path.join(d, "j.jsonl"))


def _quorum_recip(shares, quorum):
    return rp.PluginRecipient("quorum-group", "quorum-shamir/v1",
                              {"shares": shares, "quorum": quorum})


@probe("quorum-k-minus-1-refused")
def _p_quorum_sub(mode):
    shares = {"s%d" % i: _km("share%d" % i) for i in range(3)}
    if mode == "legacy":
        # Pre-fix API cannot express a threshold recipient: every
        # recipient entry is independently sufficient.
        v = _tmp_vault()
        recips = [ee.Recipient("r%d" % i, shares["s%d" % i])
                  for i in range(3)]
        env = v.seal(b"data", recips)
        out, _meta = v.open(env, shares["s0"])
        assert out == b"data"
        return _gap(
            "legacy envelopes have no threshold recipient: 1 of 3 "
            "recipient entries opens the envelope; k-of-n is "
            "inexpressible")
    v = _quorum_vault()
    env = v.seal_plugin(b"quorum-data",
                        [_quorum_recip(shares, 2)])
    parsed = ee._parse(env)
    labels = [rid.decode("utf-8") for rid, _w in parsed.recipients]
    try:
        v.open_plugin(env, {labels[0]: {"shares": {"s0": shares["s0"]}}})
    except ee.EnvelopeRefusal as e:
        assert e.code == "envelope-open-refused", e.code
        return _held("2-of-3 quorum envelope refused with 1 share "
                     "(envelope-open-refused)")
    return _break("quorum envelope opened with k-1 shares")


@probe("quorum-k-opens")
def _p_quorum_k(mode):
    if mode == "legacy":
        return _na("no threshold recipient type pre-fix")
    shares = {"s%d" % i: _km("share%d" % i) for i in range(3)}
    v = _quorum_vault()
    env = v.seal_plugin(b"quorum-data", [_quorum_recip(shares, 2)])
    parsed = ee._parse(env)
    labels = [rid.decode("utf-8") for rid, _w in parsed.recipients]
    assert len(labels) == 3, labels
    assert len(set(labels)) == 3, "share labels must be distinct"
    # namespaces consistent: every label under gov1quorum
    assert all(l.startswith("gov1quorum1") for l in labels), labels
    identities = {l: {"shares": {"s0": shares["s0"],
                                 "s2": shares["s2"]}} for l in labels}
    out, meta = v.open_plugin(env, identities)
    assert out == b"quorum-data", out
    # all three shares also open
    identities3 = {l: {"shares": shares} for l in labels}
    out3, _m3 = v.open_plugin(env, identities3)
    assert out3 == b"quorum-data"
    return _held("2-of-3 quorum envelope opens with 2 shares and with "
                 "3 shares; share labels namespaced + distinct")


@probe("quorum-wrong-share-refused")
def _p_quorum_wrong(mode):
    if mode == "legacy":
        return _na("no threshold recipient type pre-fix")
    shares = {"s%d" % i: _km("share%d" % i) for i in range(3)}
    v = _quorum_vault()
    env = v.seal_plugin(b"quorum-data", [_quorum_recip(shares, 2)])
    parsed = ee._parse(env)
    labels = [rid.decode("utf-8") for rid, _w in parsed.recipients]
    bad = dict(shares)
    bad["s1"] = _km("wrong")
    identities = {l: {"shares": {"s0": shares["s0"],
                                 "s1": bad["s1"]}} for l in labels}
    try:
        v.open_plugin(env, identities)
    except ee.EnvelopeRefusal as e:
        assert e.code == "envelope-open-refused", e.code
        return _held("quorum open with a wrong share refused "
                     "(envelope-open-refused)")
    return _break("quorum envelope opened with a wrong share")


# ---------------------------------------------------------------------------
# 7. Framework label consistency: one seal, one plugin, consistent labels
# ---------------------------------------------------------------------------

@probe("label-consistency")
def _p_consistency(mode):
    if mode == "legacy":
        v = _tmp_vault()
        env = v.seal(b"data", [ee.Recipient("gov1sym1a", _km("a")),
                               ee.Recipient("gov1quorum1b", _km("b"))])
        out, _m = v.open(env, _km("a"))
        assert out == b"data"
        return _gap(
            "legacy seal enforces no label consistency: mixed "
            "'gov1sym1a' + 'gov1quorum1b' ids sealed with zero checks")
    reg = rp.default_registry()

    class Inconsistent(rp.RecipientPlugin):
        NAME = "inconsistent/v1"
        LABEL_NAMESPACE = "gov1incon"

        def wrap(self, envelope_key, label, identity):
            # Claims another plugin's namespace mid-seal.
            return [(label, b"\x04" * 48),
                    ("gov1sym1hijacked", b"\x04" * 48)]

        def unwrap(self, entries, identity):
            return [(label, b"\x05" * 32) for label, _w in entries]

    reg.register(Inconsistent())

    class BadSize(rp.RecipientPlugin):
        NAME = "badsize/v1"
        LABEL_NAMESPACE = "gov1badsize"

        def wrap(self, envelope_key, label, identity):
            return [(label, b"\x06" * 47)]  # not 48 bytes

        def unwrap(self, entries, identity):
            return [(label, b"\x07" * 32) for label, _w in entries]

    reg.register(BadSize())
    d = tempfile.mkdtemp(prefix="w263-")
    v = ee.EnvelopeVault(os.path.join(d, "j.jsonl"), plugins=reg)
    try:
        v.seal_plugin(b"data", [rp.PluginRecipient(
            "gov1incon1x", "inconsistent/v1", {})])
    except ee.EnvelopeRefusal as e:
        assert e.code == "recipient-plugin-label-inconsistent", e.code
    else:
        return _break("inconsistent plugin labels sealed without refusal")
    try:
        v.seal_plugin(b"data", [rp.PluginRecipient(
            "gov1badsize1x", "badsize/v1", {})])
    except ee.EnvelopeRefusal as e:
        assert e.code == "recipient-plugin-malformed-wrap", e.code
    else:
        return _break("malformed plugin wrap sealed without refusal")
    return _held(
        "framework enforces label consistency + wrap size at seal "
        "(recipient-plugin-label-inconsistent / "
        "recipient-plugin-malformed-wrap)")


# ---------------------------------------------------------------------------
# 8. Backward compatibility: legacy envelopes <-> plugin API
# ---------------------------------------------------------------------------

@probe("legacy-compat")
def _p_compat(mode):
    payload = b'{"evidence": "compat"}'
    if mode == "legacy":
        v = _tmp_vault()
        env = v.seal(payload, [ee.Recipient("r0", _km("a")),
                               ee.Recipient("r1", _km("b"))])
        out, meta = v.open(env, _km("b"))
        assert out == payload and meta["recipient_id"] == "r1"
        return _held("legacy seal/open round-trip (baseline)")
    # plugin mode, both directions
    d = tempfile.mkdtemp(prefix="w263-")
    v = ee.EnvelopeVault(os.path.join(d, "j.jsonl"))
    env = v.seal(payload, [ee.Recipient("r0", _km("a"))])
    # legacy-sealed -> open_plugin with per-label symmetric identity
    out, meta = v.open_plugin(env, {"r0": {"key_material": _km("a")}})
    assert out == payload, out
    assert meta["recipient_id"] == "r0"
    # plugin-sealed (namespaced symmetric label) -> legacy open
    env2 = v.seal_plugin(payload, [rp.PluginRecipient(
        "gov1sym1alice", "symmetric-hmac/v1",
        {"key_material": _km("a")})])
    out2, meta2 = v.open(env2, _km("a"))
    assert out2 == payload, out2
    assert meta2["recipient_id"] == "gov1sym1alice"
    # wrong key still refuses under both APIs
    for fn in (lambda: v.open(env2, _km("wrong")),
               lambda: v.open_plugin(
                   env2, {"gov1sym1alice": {"key_material": _km("wrong")}})):
        try:
            fn()
        except ee.EnvelopeRefusal as e:
            assert e.code == "envelope-open-refused", e.code
        else:
            return _break("wrong-key open did not refuse")
    return _held(
        "legacy envelopes open via open_plugin; plugin-sealed "
        "symmetric envelopes open via legacy open; wrong key refused "
        "on both paths")


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent envelope batteries still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns).
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w257_envelopes_probes.py",
                    "evals/w259_keygroups_probes.py"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# N/A ("not applicable in this mode", e.g. no threshold recipient type
# pre-fix) maps to SKIP -- the exact semantic match for "probe not run in
# this mode". Raw rows keep the battery's own vocabulary (count code and exit
# contract untouched); the mapping happens here, at emission. Anything
# unexpected fails closed as ERROR.
def _mapped(rows):
    out = []
    for _name, _verdict, _detail in rows:
        if _verdict == "GAP":
            out.append((_name, "BREAK", "GAP: %s" % (_detail,)))
        elif _verdict == "N/A":
            out.append((_name, "SKIP", "N/A: %s" % (_detail,)))
        elif _verdict in ("HELD", "BREAK", "ERROR"):
            out.append((_name, _verdict, _detail))
        else:
            out.append((_name, "ERROR",
                        "unexpected verdict %r: %s" % (_verdict, _detail)))
    return out

def main():
    pin_ok = (len(decision_codes.TAXONOMY) == TAXONOMY_PIN)
    if not pin_ok:
        print("PIN MISMATCH (non-fatal): taxonomy has %d keys, pin %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
    gaps = held = nab = 0
    breaks = errors = 0
    rows = []
    for mode in ("legacy", "plugin"):
        for name, fn in _PROBES:
            if mode == "plugin" and not _HAVE_RP:
                verdict, detail = ("ERROR",
                                   "gov.recipient_plugins not importable "
                                   "(module not yet implemented)")
            else:
                try:
                    verdict, detail = fn(mode)
                except Exception as e:  # noqa: BLE001 -- harness
                    verdict, detail = ("ERROR", "%s: %s" %
                                       (type(e).__name__, str(e)[:160]))
            if verdict == "HELD":
                held += 1
            elif verdict == "GAP":
                gaps += 1
            elif verdict == "N/A":
                nab += 1
            elif verdict == "BREAK":
                breaks += 1
            else:
                errors += 1
            rows.append(("%s_%s" % (mode, name), verdict, detail))
    mapped = _mapped(rows)
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        mapped, breaks + gaps, held, errors)
    probe_lines.emit(mapped)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("%d BREAK / %d HELD / %d ERROR" % (breaks + gaps, held, errors))
    if not pin_ok:
        return 2
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
