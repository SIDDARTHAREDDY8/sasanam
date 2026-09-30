#!/usr/bin/env python3
"""Wave-223 lane B: per-request attenuation binding.

RE-DERIVED pattern (fora-protocol ADR-001, no foreign source copied):
the cryptographic embodiment of tighten-only/no-downgrade. Every
permit-lease redeem SHOULD carry a fresh REQUESTER-SIGNED ATTENUATION
BLOCK with a <=10-minute TTL; the block may only tighten the lease's
scope (narrower parameters, shorter TTL), never widen it.

Seams under test:
* gov/attenuation.py — issue(lease_digest, narrowed_scope, requester_id,
  seed, *, ttl_s, now) -> AttenuationBlock {v, lease_digest,
  narrowed_scope, issued_at, expires_at, requester_id, requester_pubkey,
  signature} (domain sasanam-attenuation/v1:); ttl_s > 600 refused at
  issuance with attenuation-ttl-refused; bind(block, lease, now) checks
  signature (attenuation-unverifiable) -> lease digest match
  (attenuation-lease-mismatch) -> TTL span (attenuation-ttl-refused) ->
  expiry (attenuation-expired) -> tighten-only via
  PermitLease.check_scope (attenuation-widening-refused). The block
  carries NO authority by itself.
* gov/permit_leases.py wiring — PermitLease.redeem(..., attenuation=None,
  require_attenuation=False): missing block with required policy
  refuses attenuation-missing; forged/widened/stale blocks refuse at
  bind time; absent policy -> legacy behavior byte-identical; a bound
  block constrains request_scope to narrowed_scope
  (attenuation-widening-refused) in addition to the grant envelope.

Attack shapes: stale block, TTL>600 at issuance, widened scope, forged
signature, block for another lease, missing block under required
policy, block-as-grant misuse, widened request_scope past the narrowed
scope while inside the grant.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-222 HEAD
d7f377aaf1a9ccf095cc4e0535eb9f74fa8f7fc9.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP — the
legacy no-attenuation pin is verifiable on base.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g223a
  TMPDIR=/var/tmp/g223a ~/workspace/.gov-venv/bin/python evals/w223_atten_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g223a-u \\
      ~/workspace/.gov-venv/bin/python evals/w223_atten_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g223a-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import attenuation as at  # noqa: E402
    from gov import ed25519 as _ed  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    at = _ed = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

from gov import permit_leases as pl  # noqa: E402 - present on base

_RESULTS = []
_PROBE_FNS = {}

_DIGEST_A = "aa" * 32  # 64-hex stand-in parameter digests
_DIGEST_B = "bb" * 32

_GRANT = {"action": {"read", "write"}, "resource": {"toolbox"}}


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


def _fixed_clock(now):
    return lambda: float(now)


def _issue_lease(now=1000.0):
    return pl.PermitLease.issue(
        "permit-1", params_digest=_DIGEST_A, grant_scope=_GRANT,
        ttl_s=3600, now=_fixed_clock(now))


def _issue_block(lease, narrowed, ttl_s=300, now=1000.0, seed=None):
    seed = seed if seed is not None else _ed.generate_seed()
    return at.issue(lease.parameter_digest, narrowed, "req-1", seed,
                    ttl_s=ttl_s, now=now), seed


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------


@_probe("fresh-block-redeems")
def _p_fresh():
    if not _IMPORT_OK:
        return _gap("fresh-block-redeems")
    lease = _issue_lease()
    block, _seed = _issue_block(lease, {"action": {"read"}})
    grant = lease.redeem(_DIGEST_A, request_scope={"action": {"read"}},
                         now=_fixed_clock(1100.0), attenuation=block)
    if grant["permit_id"] != "permit-1":
        return _break("fresh-block-redeems", "grant for wrong permit")
    _held("fresh-block-redeems", "valid attenuation bound and redeemed")


@_probe("expired-block-refused")
def _p_expired():
    if not _IMPORT_OK:
        return _gap("expired-block-refused")
    lease = _issue_lease()
    # Span 300s (<=600) but the window closed before redeem time.
    block, _seed = _issue_block(lease, {"action": {"read"}}, ttl_s=300,
                                now=1000.0)
    _expect_refusal(
        "expired-block-refused", "attenuation-expired",
        lambda: lease.redeem(_DIGEST_A, now=_fixed_clock(1400.0),
                             attenuation=block))


@_probe("long-ttl-issuance-refused")
def _p_long_ttl():
    if not _IMPORT_OK:
        return _gap("long-ttl-issuance-refused")
    lease = _issue_lease()
    _expect_refusal(
        "long-ttl-issuance-refused", "attenuation-ttl-refused",
        lambda: at.issue(lease.parameter_digest, {"action": {"read"}},
                         "req-1", _ed.generate_seed(), ttl_s=900,
                         now=1000.0))


@_probe("widened-scope-refuses")
def _p_widened():
    if not _IMPORT_OK:
        return _gap("widened-scope-refuses")
    lease = _issue_lease()
    block, _seed = _issue_block(
        lease, {"action": {"read", "write", "admin"}}, ttl_s=300,
        now=1000.0)
    _expect_refusal(
        "widened-scope-refuses", "attenuation-widening-refused",
        lambda: lease.redeem(_DIGEST_A, now=_fixed_clock(1100.0),
                             attenuation=block))


@_probe("forged-block-refuses")
def _p_forged():
    if not _IMPORT_OK:
        return _gap("forged-block-refuses")
    lease = _issue_lease()
    block, _seed = _issue_block(lease, {"action": {"read"}})
    forged = dict(block)
    forged["narrowed_scope"] = {"action": {"read", "write", "admin"}}
    _expect_refusal(
        "forged-block-refuses", "attenuation-unverifiable",
        lambda: lease.redeem(_DIGEST_A, now=_fixed_clock(1100.0),
                             attenuation=forged))


@_probe("wrong-lease-block-refuses")
def _p_wrong_lease():
    if not _IMPORT_OK:
        return _gap("wrong-lease-block-refuses")
    lease = _issue_lease()
    block, _seed = _issue_block(lease, {"action": {"read"}})
    other = pl.PermitLease.issue(
        "permit-2", params_digest=_DIGEST_B, grant_scope=_GRANT,
        ttl_s=3600, now=_fixed_clock(1000.0))
    _expect_refusal(
        "wrong-lease-block-refuses", "attenuation-lease-mismatch",
        lambda: other.redeem(_DIGEST_B, now=_fixed_clock(1100.0),
                             attenuation=block))


@_probe("missing-block-required-refuses")
def _p_missing():
    if not _IMPORT_OK:
        return _gap("missing-block-required-refuses")
    lease = _issue_lease()
    _expect_refusal(
        "missing-block-required-refuses", "attenuation-missing",
        lambda: lease.redeem(_DIGEST_A, now=_fixed_clock(1100.0),
                             attenuation=None, require_attenuation=True))


@_probe("legacy-no-block-identical")
def _p_legacy():
    # Verifiable on the pristine base: redeem without attenuation must
    # behave exactly as before (grant keys unchanged).
    lease = _issue_lease()
    grant = lease.redeem(_DIGEST_A, now=_fixed_clock(1100.0))
    if set(grant) != {"permit_id", "parameter_digest", "granted_at"}:
        return _break("legacy-no-block-identical",
                      "grant record shape changed: %s" % sorted(grant))
    # Legacy refusal codes unchanged with no attenuation args.
    lease2 = _issue_lease()
    _expect_refusal("legacy-no-block-identical", "permit-digest-mismatch",
                    lambda: lease2.redeem("cc" * 32,
                                          now=_fixed_clock(1100.0)))
    _held("legacy-no-block-identical",
          "no-attenuation path unchanged (grant keys + codes)")


@_probe("block-grants-nothing")
def _p_no_authority():
    if not _IMPORT_OK:
        return _gap("block-grants-nothing")
    lease = _issue_lease()
    block, _seed = _issue_block(lease, {"action": {"read"}})
    # A valid block does not upgrade authority: a wrong digest still
    # refuses, and the block itself is not a digest.
    _expect_refusal(
        "block-grants-nothing", "permit-digest-mismatch",
        lambda: lease.redeem("cc" * 32, now=_fixed_clock(1100.0),
                             attenuation=block))
    _held("block-grants-nothing",
          "block alone never authorizes; digest still required")


@_probe("no-digest-oracle-via-block")
def _p_oracle():
    if not _IMPORT_OK:
        return _gap("no-digest-oracle-via-block")
    lease = _issue_lease()
    # Attacker self-signs a block with a GUESSED lease digest and
    # presents a wrong digest: bind must run only AFTER the digest
    # check, so the refusal must be permit-digest-mismatch — the
    # block may never confirm or deny the recorded digest.
    guessed = at.issue("dd" * 32, {"action": {"read"}}, "req-1",
                       _ed.generate_seed(), ttl_s=300, now=1000.0)
    _expect_refusal(
        "no-digest-oracle-via-block", "permit-digest-mismatch",
        lambda: lease.redeem("cc" * 32, now=_fixed_clock(1100.0),
                             attenuation=guessed))


@_probe("narrowed-scope-constrains")
def _p_constrains():
    if not _IMPORT_OK:
        return _gap("narrowed-scope-constrains")
    lease = _issue_lease()
    block, _seed = _issue_block(lease, {"action": {"read"}})
    # Inside the grant but outside the narrowed scope -> refused.
    _expect_refusal(
        "narrowed-scope-constrains", "attenuation-widening-refused",
        lambda: lease.redeem(
            _DIGEST_A, request_scope={"action": {"write"}},
            now=_fixed_clock(1100.0), attenuation=block))


@_probe("determinism")
def _p_determinism():
    if not _IMPORT_OK:
        return _gap("determinism")
    seed = _ed.generate_seed()
    b1 = at.issue(_DIGEST_A, {"action": {"read"}}, "req-1", seed,
                  ttl_s=300, now=1000.0)
    b2 = at.issue(_DIGEST_A, {"action": {"read"}}, "req-1", seed,
                  ttl_s=300, now=1000.0)
    if b1["requester_signature"] != b2["requester_signature"]:
        return _break("determinism", "block signatures nondeterministic")
    if b1 != b2:
        return _break("determinism", "block bytes differ under fixed clock")
    _held("determinism", "blocks deterministic under fixed clock")


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
    print("w223 attenuation probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
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
