"""Witness config auto-load + intermediate-CA completeness invariants
(witness GHSA-ggg4 / GHSA-6xq9 / GHSA-88v8 steal, pattern-only).

GHSA-ggg4 (in-toto/go-witness, CRITICAL): ``.witness.yaml`` auto-loaded
from the current working directory lets a repo under attestation ship
its own verifier configuration -- a CI secret-exfil vector. The
suggested fix: never auto-load config from CWD in CI contexts.

GHSA-6xq9 / GHSA-88v8 (in-toto/go-witness): chain-verify entry points
that never load the intermediate CA set silently treat chains as
verifiable while they are not. The fix: every chain-verify entry
point must actually load intermediates before verifying.

Re-derived here as Sasanam invariants, in prose (no witness code is
reused):

1. A config discovered by CWD auto-load is never honored in a CI or
   untrusted-repo context (``witness-config-cwd-autoload``). An
   explicit config path in a trusted context loads normally.
2. A change to the upload destination applies only with explicit
   confirmation (``witness-config-upload-ungated``); an unchanged
   destination is a no-op.
3. The sensitive-values filter can only be tightened, never
   downgraded (``witness-config-filter-downgrade``).
4. Every chain-verify entry point asserts intermediate-CA
   completeness: a chain whose issuers are not all resolvable
   in-chain, with no intermediate set loaded, refuses
   (``witness-intermediates-missing``).

Honest boundaries: this module is a policy guard, not a verifier.
The actual signature/crypto chain verification is deployment-owned;
``verify_chain_entry`` performs the completeness assertion (the
invariant we stole) and returns a completeness verdict, never a
cryptographic trust verdict. Config parsing itself (YAML) is the
caller's: ``load_config`` takes the parsed mapping.
"""

CONTEXT_CI = "ci"
CONTEXT_TRUSTED = "trusted"
CONTEXT_UNTRUSTED = "untrusted"

_ENTRY_POINTS = ("leaf", "intermediate", "timestamp")


class WitnessConfigError(Exception):
    """Refusal raised by this module. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def chain_entry_points():
    """Names of the chain-verify entry points the completeness
    invariant must be asserted at (stdlib model of GHSA-6xq9/88v8)."""
    return list(_ENTRY_POINTS)


def load_config(config, source, *, context, auto_discovered=False):
    """Honor a parsed config mapping, enforcing the auto-load rule.

    ``source`` is where the config came from (a path or descriptor).
    ``auto_discovered`` must be True when the config was found by
    scanning the current working directory rather than given as an
    explicit path. In ``ci`` or ``untrusted`` contexts, an
    auto-discovered config refuses with ``witness-config-cwd-autoload``.
    """
    if context not in (CONTEXT_CI, CONTEXT_TRUSTED, CONTEXT_UNTRUSTED):
        raise WitnessConfigError(
            "witness-config-cwd-autoload",
            "unknown context %r; failing closed" % (context,))
    if auto_discovered and context in (CONTEXT_CI, CONTEXT_UNTRUSTED):
        raise WitnessConfigError(
            "witness-config-cwd-autoload",
            "refusing auto-discovered config %r in %r context" % (
                source, context))
    if not isinstance(config, dict):
        raise WitnessConfigError(
            "witness-config-cwd-autoload",
            "config from %r is not a mapping; failing closed" % (source,))
    return dict(config)


def apply_upload_destination(existing, proposed, *, confirmed=False):
    """Apply a change to the upload destination (GHSA-ggg4 hardening).

    The destination changes only with explicit confirmation; an
    unconfirmed change refuses ``witness-config-upload-ungated``.
    Re-applying the current destination is a no-op and needs no
    confirmation.
    """
    if proposed == existing:
        return existing
    if not confirmed:
        raise WitnessConfigError(
            "witness-config-upload-ungated",
            "upload destination change %r -> %r requires explicit "
            "confirmation" % (existing, proposed))
    return proposed


def set_sensitive_filter(current, proposed):
    """Update the sensitive-values filter (GHSA-ggg4 hardening).

    The filter can only be tightened: ``proposed`` must contain every
    pattern in ``current``. Removing a pattern (or disabling the
    filter entirely) refuses ``witness-config-filter-downgrade``.
    """
    current = list(current)
    proposed = list(proposed)
    missing = [p for p in current if p not in proposed]
    if missing:
        raise WitnessConfigError(
            "witness-config-filter-downgrade",
            "sensitive filter may not drop patterns %r; filters are "
            "tighten-only" % (missing,))
    return proposed


def _needs_intermediates(chain):
    """True when the chain names issuers not resolvable in-chain.

    A chain of plain dicts ``{"subject", "issuer"}``. Any cert whose
    issuer is neither itself (a root) nor the subject of another cert
    in the chain requires loaded intermediates to resolve.
    """
    subjects = {c.get("subject") for c in chain}
    for cert in chain:
        issuer = cert.get("issuer")
        if issuer != cert.get("subject") and issuer not in subjects:
            return True
    return False


def assert_intermediates_loaded(chain, *, intermediates):
    """Assert intermediate-CA completeness before chain verification.

    Every chain-verify entry point must call this first (GHSA-6xq9 /
    GHSA-88v8). When the chain needs intermediates (an issuer not
    resolvable in-chain) and none were loaded (None or empty), the
    verification refuses ``witness-intermediates-missing`` -- a
    verifier that never loaded intermediates cannot treat the chain
    as verifiable. Returns True when completeness holds.
    """
    if not isinstance(chain, list) or not chain:
        raise WitnessConfigError(
            "witness-intermediates-missing",
            "completeness cannot be asserted for an empty chain; "
            "refusing closed")
    if _needs_intermediates(chain) and not intermediates:
        raise WitnessConfigError(
            "witness-intermediates-missing",
            "chain needs intermediate CAs but none were loaded; "
            "intermediate-CA completeness not established")
    return True


def verify_chain_entry(chain, *, intermediates, entry_point):
    """Model of a chain-verify entry point with the completeness
    invariant enforced.

    Asserts intermediate-CA completeness (the GHSA-6xq9/88v8
    invariant), then returns a completeness verdict. This is NOT a
    cryptographic chain verification: signature and EKU checks are
    deployment-owned. The verdict records exactly what was checked.
    """
    if entry_point not in _ENTRY_POINTS:
        raise WitnessConfigError(
            "witness-intermediates-missing",
            "unknown chain-verify entry point %r; failing closed" % (
                entry_point,))
    assert_intermediates_loaded(chain, intermediates=intermediates)
    return {"ok": True, "entry_point": entry_point,
            "chain_length": len(chain),
            "completeness": "intermediates-loaded",
            "note": "completeness asserted; cryptographic verification "
                    "is deployment-owned"}
