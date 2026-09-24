"""S7-stream (wave-90): filtered-egress launcher — productizing the F81 lab wall.

F136: the GCP lab validated the wall (netns ``agent0`` + default-deny
nftables + confined dnsmasq + CONNECT proxy + seccomp-BPF: 17 STOPPED /
0 BREAK across 11 attack classes), but there was no launcher, no
component pinning, and no residual threat model. This module is the
product layer on top of that validated mechanism:

1. ``WallComponentInventory`` — install-time digest pinning of the
   wall's own components (nft ruleset, proxy allowlist, DNS filter
   config, DNS zone, proxy implementation artifact, seccomp config).
   Same primitive shape as the S5 tool-definition digest inventory
   (``gov/tool_continuity.py``): canonical bytes -> sha256/sha512
   digests -> install manifest + operator-held receipt. The launcher
   re-verifies every digest at startup under an interprocess lock and
   refuses to launch on ANY mismatch. Tamper = no launch.
2. ``FilteredEgressLauncher`` — every launch (a) verifies the receipt
   -> manifest -> components chain, (b) verifies the wall reports UP
   via a ``WallStateProvider``, (c) spawns the child through the
   provider with a child-side preexec re-assertion (shrinking the
   check->spawn TOCTOU to the preexec->exec window), (d) scrubs
   proxy-env trust-wideners from the child (the F81 Wiki lesson:
   ``NO_PROXY`` suffix trust), and (e) chains audit events. Any
   failure refuses: fail-closed, never degraded.
3. Localhost fixtures — ``SimulatedWallProvider`` + ``FakePacketFilter``
   + ``StubProxyServer`` + ``StubDnsServer`` model the lab wall on
   loopback so the break battery runs at $0 with no real network and
   no privileges.

Honest boundaries (full text: ``docs/egress_wall_threat_model.md``):
the localhost fixtures model the wall's *mechanism* (allowlist
enforcement, digest pinning, fail-closed startup); they do NOT re-prove
the netns/nftables topology — the GCP lab did that (``evals/FINDINGS.md``
F81). Host root, TCB compromise (proxy/DNS), covert channels through
allowlisted destinations, and DNS answers inside the allowlist remain
documented residuals. A green battery here closes the *launcher* gap
(F136), not the universe.
"""

import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import threading
import time

from .delegation_tokens import DelegationTrust
from .ed25519 import generate_seed as _ed_generate_seed
from .ed25519 import verify as _ed_verify
from .signing import Ed25519Signer

# ---------------------------------------------------------------------------
# Errors — every refusal names itself (fail-closed, never degraded).
# ---------------------------------------------------------------------------


class EgressLaunchRefused(RuntimeError):
    """The launcher refused to spawn. ``reason`` is one of:

    - ``receipt_unverifiable``  — receipt missing/unparseable, or the
      manifest's digest does not match the receipt (manifest tampered).
    - ``component_tampered``    — a pinned wall component's digest (or
      symlink target) drifted since install. ``component`` names it.
    - ``no_common_algorithm``   — manifest and verifier share no digest
      algorithm; refusing is safer than downgrading silently.
    - ``wall_not_up`` / ``wall_degraded`` — the wall provider does not
      report UP (wall down, partial wall, running-ruleset drift).
    - ``lock_unavailable``      — could not take the verify+spawn lock;
      launching unlocked would reopen the check->spawn race.
    - ``preexec_recheck_failed`` — the wall flapped between the parent
      check and the child preexec; the child aborted before exec
      (exit 99) and nothing ungoverned ran.
    - ``preexec_chain_failed`` — the embedder preexec_chain entry
      failed AFTER the wall re-check passed (F149); the child aborted
      before exec (exit 98) and nothing ungoverned ran. The re-check
      itself passed — this is never a wall flap.
    - ``pin_authorship_invalid`` — the manifest's pin record is missing,
      not bound to the manifest payload it ships with, or lacks valid
      roster-human Ed25519 authorship (F138); legacy manifests without
      pin records are refused — re-pin under human authorship.
    - ``pin_chain_broken``      — the operator-held pin ledger is
      missing/empty, a pin record fails its self-hash, prev-linkage is
      broken, or the ledger tip does not match the manifest's pin
      record (pin history rewritten).
    """


# ---------------------------------------------------------------------------
# Digest agility — pins may carry several algorithms; the verifier uses
# the strongest algorithm present in BOTH the manifest and its own
# supported set. All listed digests must match (a mismatch in a weaker
# algorithm is still evidence of tamper, not a downgrade signal).
# ---------------------------------------------------------------------------

_ALGO_STRENGTH = {"sha256": 1, "sha512": 2}
DEFAULT_ALGOS = ("sha256", "sha512")


def _digest_bytes(data, algo):
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def component_digests(data, algos=DEFAULT_ALGOS):
    """Digest map for raw component bytes (follows symlinks: caller
    reads the bytes; what matters is content, plus recorded realpath)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return {a: _digest_bytes(data, a) for a in algos}


def negotiate_algo(manifest_algos, supported_algos=DEFAULT_ALGOS):
    """Strongest algorithm in both sets, or None."""
    common = set(manifest_algos or ()) & set(supported_algos or ())
    if not common:
        return None
    return max(common, key=lambda a: _ALGO_STRENGTH.get(a, 0))


MANIFEST_FORMAT = "egress-wall-pins/2"  # /2: pins carry authorship (F138)
PIN_RECORD_FORMAT = "egress-wall-pin-record/1"
RECEIPT_FORMAT = "egress-wall-receipt/1"  # unchanged: sha256(manifest bytes)

# The wall's pinned components. A deployment maps each name to the real
# artifact path (e.g. /etc/agent-wall/agent0.nft); the localhost
# fixtures map them into the sim dir (see install_simulated_wall).
WALL_COMPONENTS = (
    "nft_ruleset",      # default-deny ruleset (desired state)
    "proxy_allowlist",  # the entire outside world, host:port per line
    "dns_config",       # confined-resolver config (no-rebind etc.)
    "dns_zone",         # authoritative zone data for allowlisted names
    "proxy_impl",       # proxy implementation artifact / policy descriptor
    "seccomp_config",   # seccomp-BPF policy (blocked calls)
    "seccomp_helper",   # the seccomp launcher artifact itself
                        # (vendored gov/data/run_seccomp.py copied into
                        # the conf dir at install; F81 launcher wave)
)


# ---------------------------------------------------------------------------
# Pin authorship + chained pin history (F138).
#
# F136's R10 residual, filed as F138: install() re-pinned through a bare
# function call — the receipt (sha256 over the manifest bytes) is
# self-consistent, not operator-anchored, and no pin carried human
# authorship evidence or history. The fix mirrors the wave-75/78
# load-gate construction (gov/load_gate.py):
#
# * every pin (including the first) requires a roster-human Ed25519
#   authorship token: a signature by a DelegationTrust human key over a
#   domain-separated canonical body binding (tier, pin payload digest,
#   previous pin-record digest, timestamp). The signature cannot be
#   transplanted to different content, a different chain position, or a
#   different tier — the tier is committed in the body, and production
#   tier needs TWO distinct roster humans (the wave-75 nuclear rule).
# * every pin appends a pin record to an operator-held JSONL ledger.
#   Each record carries prev_pin_record_sha256, so history cannot be
#   rewritten silently: dropping/rewriting records breaks the linkage
#   and verify() refuses (pin_chain_broken). The tip record's prev
#   transitively commits the whole history; the tip's authorship is
#   verified live at every launch, while historical records are checked
#   structurally (self-hash + linkage) so roster rotation cannot brick
#   the wall.
#
# Reuses gov/ed25519 (sign/verify), gov/signing.Ed25519Signer
# (operator-side signing), and gov/delegation_tokens.DelegationTrust
# (the human roster). No new crypto: the chaining is the same
# prev-hash-link construction as the audit log (gov/log.py).
#
# Operational notes: the ledger is operator-held custody alongside the
# receipt (a missing ledger refuses launches — recovery is a human
# re-pin, which starts a new genesis record). Concurrent installs must
# be serialized by the operator; the ledger append is not interlocked.
# ---------------------------------------------------------------------------


class WallPinRefused(Exception):
    """Install-time fail-closed refusal. The message carries a
    machine-readable reason code:

    - ``pin_authorship_invalid`` — no authorship token, unknown author
      key, bad signature, tier-rule violation, or the pin record is not
      bound to the manifest payload it ships with.
    - ``pin_chain_broken`` — the pin ledger is missing/empty, a record
      fails its self-hash, prev-linkage is broken, or the ledger tip
      does not match the manifest's pin record.
    """


_PIN_RECORD_DOMAIN = b"gov-egress-wall-pin-record/v1\x00"
_PIN_RECORD_ARTIFACT_ID = "egress-wall-pins"
_PIN_TIERS = ("dev", "test", "staging", "production")
_GENESIS_PREV = "genesis"


def _canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, indent=2,
                      ensure_ascii=True).encode("utf-8")


def _canonical_pin_record_body(tier, pin_payload_sha256,
                              prev_pin_record_sha256, ts):
    """Domain-separated body the roster human signs. Binds the tier, the
    exact pin payload digest, the chain position (prev record digest),
    and the timestamp — a signature cannot move across content, history
    position, or tier."""
    return b"|".join([
        _PIN_RECORD_DOMAIN,
        tier.encode("utf-8"),
        _PIN_RECORD_ARTIFACT_ID.encode("utf-8"),
        pin_payload_sha256.encode("utf-8"),
        (prev_pin_record_sha256 or _GENESIS_PREV).encode("utf-8"),
        ts.encode("utf-8"),
    ])


def _default_ledger_path(manifest_path):
    return str(manifest_path) + ".pinlog"


def _verify_pin_approval(trust, body, author_key_id, authorship_sig_hex):
    pub = trust.human_keys.get(author_key_id)
    if pub is None:
        raise WallPinRefused(
            "pin_authorship_invalid: unknown author key %r "
            "(not in the roster)" % (author_key_id,))
    try:
        sig = bytes.fromhex(authorship_sig_hex)
    except (TypeError, ValueError):
        raise WallPinRefused(
            "pin_authorship_invalid: malformed authorship signature")
    if not _ed_verify(pub, body, sig):
        raise WallPinRefused(
            "pin_authorship_invalid: bad authorship signature for %r"
            % (author_key_id,))
    return author_key_id


def _require_pin_approvals(trust, body, tier, author_key_id,
                           authorship_sig_hex, second_author_key_id,
                           second_authorship_sig_hex):
    """The load-gate wave-75 tier rule, applied to wall pins: production
    needs two DISTINCT roster-human approvals over the identical body;
    dev/test/staging take single-human."""
    approvals = [_verify_pin_approval(trust, body, author_key_id,
                                      authorship_sig_hex)]
    if tier == "production":
        if not second_author_key_id or not second_authorship_sig_hex:
            raise WallPinRefused(
                "pin_authorship_invalid: production tier requires two "
                "distinct human approvals (wave-75 nuclear rule)")
        if second_author_key_id == author_key_id:
            raise WallPinRefused(
                "pin_authorship_invalid: production approvals must come "
                "from two DISTINCT keys (same key twice refused)")
        approvals.append(_verify_pin_approval(
            trust, body, second_author_key_id, second_authorship_sig_hex))
    return approvals


def _read_pin_ledger(ledger_path):
    """Pin records (list of dicts). A missing file reads as [] — the
    caller decides whether that is genesis or a broken chain."""
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    records = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            raise WallPinRefused(
                "pin_chain_broken: ledger line %d is not JSON" % lineno)
        if not isinstance(rec, dict):
            raise WallPinRefused(
                "pin_chain_broken: ledger line %d is not a record" % lineno)
        records.append(rec)
    return records


def _record_sha256(pin_record):
    """Self-hash of a pin record (the record_sha256 field itself is
    excluded — it is the head pointer, not part of the hashed body)."""
    body = {k: v for k, v in pin_record.items() if k != "record_sha256"}
    return _digest_bytes(_canonical_json_bytes(body), "sha256")


def _check_pin_ledger_structure(records):
    """Structural chain check: every record's self-hash verifies and
    every prev-link matches the previous record's digest. Returns the
    tip digest (None for an empty ledger)."""
    prev = None
    for i, rec in enumerate(records):
        if rec.get("format") != PIN_RECORD_FORMAT:
            raise WallPinRefused(
                "pin_chain_broken: record %d has bad format" % i)
        if _record_sha256(rec) != rec.get("record_sha256"):
            raise WallPinRefused(
                "pin_chain_broken: record %d self-hash mismatch "
                "(record edited)" % i)
        if rec.get("prev_pin_record_sha256") != prev:
            raise WallPinRefused(
                "pin_chain_broken: record %d prev-linkage broken "
                "(history rewritten)" % i)
        prev = rec["record_sha256"]
    return prev


def _operator_roster(trust, operator_signers, tier):
    """Test/sim operator roster. Generates ephemeral human keys unless
    the caller supplies signers/trust. Production deployments pass
    their real DelegationTrust and NEVER rely on generated keys."""
    n = 2 if tier == "production" else 1
    if operator_signers is None:
        operator_signers = [Ed25519Signer(_ed_generate_seed())
                            for _ in range(n)]
    signers = list(operator_signers)
    if len(signers) < n:
        raise ValueError("tier %r needs %d operator signers, got %d"
                         % (tier, n, len(signers)))
    if trust is None:
        filler = [Ed25519Signer(_ed_generate_seed()) for _ in range(2)]
        trust = DelegationTrust(
            human_keys={s.key_id: s.public_key for s in signers},
            # authority/user-issuer slots are unused by pin verification;
            # DelegationTrust requires non-empty mappings, so fill with
            # throwaway keys (same shape as the load-gate tests).
            authority_keys={filler[0].key_id: filler[0].public_key},
            user_issuer_keys={filler[1].key_id: filler[1].public_key})
    elif not isinstance(trust, DelegationTrust):
        raise TypeError("trust must be a DelegationTrust")
    return trust, signers


class WallComponentInventory:
    """Install-time pinning + startup verification of wall components.

    Install (operator, privileged, reviewed): ``install()`` digests each
    component file, requires a roster-human Ed25519 authorship token
    bound to the new pin digest (F138 — no bare re-pinning), writes the
    manifest (with the pin record embedded), writes the receipt — the
    operator-held trust anchor binding the manifest bytes — and appends
    the pin record to the operator-held pin ledger (each record links
    to the previous, so history cannot be rewritten silently).
    Verify (launcher, every launch): receipt -> manifest -> pin record
    authorship + ledger chain -> components.
    """

    def __init__(self, manifest_path, receipt_path,
                 supported_algos=DEFAULT_ALGOS, trust=None,
                 ledger_path=None):
        self.manifest_path = str(manifest_path)
        self.receipt_path = str(receipt_path)
        self.supported_algos = tuple(supported_algos)
        if trust is not None and not isinstance(trust, DelegationTrust):
            raise TypeError("trust must be a DelegationTrust")
        # The roster is required to verify pin authorship; a launcher
        # without it fails closed at verify() time.
        self.trust = trust
        self.ledger_path = (str(ledger_path) if ledger_path is not None
                            else _default_ledger_path(self.manifest_path))

    # -- pin payload --------------------------------------------------
    @staticmethod
    def _build_pin_payload(component_paths, algos, installed_at,
                           *, live_digests=None):
        algos = tuple(algos)
        if not algos:
            raise ValueError("install requires at least one digest algo")
        if live_digests:
            unknown = set(live_digests) - set(component_paths)
            if unknown:
                raise EgressLaunchRefused(
                    "live_digests for unknown components: %s"
                    % sorted(unknown))
        entries = []
        for name in WALL_COMPONENTS:
            path = component_paths.get(name)
            if not path:
                raise ValueError("missing component path: %s" % name)
            st = os.lstat(path)
            is_link = os.path.islink(path)
            with open(path, "rb") as f:
                data = f.read()
            entry = {
                "name": name,
                "path": os.path.abspath(path),
                "realpath": os.path.realpath(path),
                "is_symlink": bool(is_link),
                "size": len(data),
                "digests": component_digests(data, algos),
            }
            if live_digests and name in live_digests:
                # Install-time live-state baseline (fog decision 1):
                # e.g. the sha256 of the normalized deployed nftables
                # ruleset. Part of the pin payload, so roster-human
                # authorship binds the baseline too — drift detection
                # cannot be silently re-based.
                entry["live_sha256"] = live_digests[name]
            entries.append(entry)
        return {
            "format": MANIFEST_FORMAT,
            "installed_at": installed_at,
            "algos": list(algos),
            "components": entries,
        }

    @staticmethod
    def _prepare_pin(component_paths, manifest_path, *, algos=DEFAULT_ALGOS,
                     tier="production", ts=None, ledger_path=None,
                     live_digests=None):
        """Shared pre-computation for proposal() and install(): build the
        payload, hash it, and locate the chain tip. Refuses to build on a
        broken ledger (fail closed — never extend rewritten history).

        The timestamp is fixed ONCE here and stamps both the payload's
        installed_at and the signed body: proposal() and install() called
        with the same ts build byte-identical payloads, while a ts skew
        (or any content change) between signing and install invalidates
        the signature instead of pinning unauthenticated bytes.
        """
        if tier not in _PIN_TIERS:
            raise WallPinRefused(
                "pin_authorship_invalid: unknown tier %r" % (tier,))
        ts = ts or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = WallComponentInventory._build_pin_payload(
            component_paths, algos, ts, live_digests=live_digests)
        payload_sha = _digest_bytes(_canonical_json_bytes(payload), "sha256")
        ledger_path = (ledger_path if ledger_path is not None
                       else _default_ledger_path(manifest_path))
        tip = _check_pin_ledger_structure(_read_pin_ledger(ledger_path))
        body = _canonical_pin_record_body(tier, payload_sha, tip, ts)
        return {"payload": payload, "pin_payload_sha256": payload_sha,
                "prev_pin_record_sha256": tip, "ts": ts, "body": body,
                "ledger_path": ledger_path}

    # -- proposal (operator signing side) -------------------------------
    @staticmethod
    def proposal(component_paths, manifest_path, *, algos=DEFAULT_ALGOS,
                 tier="production", ts=None, ledger_path=None,
                 live_digests=None):
        """The exact canonical body a roster human must sign to authorize
        a pin — computed WITHOUT writing anything.

        Returns ``{"tier", "pin_payload_sha256",
        "prev_pin_record_sha256", "ts", "body"}``. The operator signs
        ``body`` with their Ed25519 seed and passes ``ts``/``tier`` and
        the resulting signature back into :meth:`install` unchanged: a
        signature over different content, chain position, timestamp, or
        tier is refused.

        ``live_digests`` optionally pins install-time live-state
        baselines (e.g. the normalized nftables ruleset digest) on the
        named components; it is part of the signed payload, so the
        baseline cannot be re-based without new authorship. Pass the
        identical mapping to install().
        """
        prep = WallComponentInventory._prepare_pin(
            component_paths, manifest_path, algos=algos, tier=tier, ts=ts,
            ledger_path=ledger_path, live_digests=live_digests)
        out = {k: prep[k] for k in ("pin_payload_sha256",
                                   "prev_pin_record_sha256", "ts", "body")}
        out["tier"] = tier
        return out

    # -- install ------------------------------------------------------
    @staticmethod
    def install(component_paths, manifest_path, receipt_path,
                algos=DEFAULT_ALGOS, *, trust=None,
                author_key_id=None, authorship_sig_hex=None,
                ts=None, tier="production",
                second_author_key_id=None, second_authorship_sig_hex=None,
                ledger_path=None, live_digests=None):
        """Pin components under roster-human authorship.

        ``trust`` is a DelegationTrust whose human_keys roster authorizes
        the pin. ``authorship_sig_hex`` is the Ed25519 signature (by the
        private key for ``author_key_id``) over the canonical pin body
        from :meth:`proposal` — i.e. bound to the newly pinned digest,
        the chain position, the tier, and the timestamp. ``tier`` commits
        the deployment tier in the signed body: ``"production"`` (the
        default) requires a SECOND approval from a DISTINCT roster human
        key (the wave-75 nuclear rule); dev/test/staging take
        single-human.

        There is no bare install: missing trust or authorship is refused
        with WallPinRefused (``pin_authorship_invalid``), never a
        silent re-pin. ``live_digests`` must be the identical mapping
        passed to :meth:`proposal` (the signed body covers it; a skew
        invalidates the signature). Returns the manifest dict. Writes
        the manifest JSON (with the pin record embedded), then the
        receipt (sha256 over the exact manifest bytes), then appends
        the pin record to the ledger.
        """
        if tier not in _PIN_TIERS:
            raise WallPinRefused(
                "pin_authorship_invalid: unknown tier %r" % (tier,))
        if trust is None or not isinstance(trust, DelegationTrust):
            raise WallPinRefused(
                "pin_authorship_invalid: re-pinning requires a "
                "DelegationTrust roster (no bare install)")
        if not author_key_id or not authorship_sig_hex:
            raise WallPinRefused(
                "pin_authorship_invalid: re-pinning requires a "
                "roster-human Ed25519 authorship token bound to the new "
                "pin digest (no bare install)")
        prep = WallComponentInventory._prepare_pin(
            component_paths, manifest_path, algos=algos, tier=tier, ts=ts,
            ledger_path=ledger_path, live_digests=live_digests)
        approvals = _require_pin_approvals(
            trust, prep["body"], tier, author_key_id, authorship_sig_hex,
            second_author_key_id, second_authorship_sig_hex)
        pin_record = {
            "format": PIN_RECORD_FORMAT,
            "tier": tier,
            "artifact_id": _PIN_RECORD_ARTIFACT_ID,
            "pin_payload_sha256": prep["pin_payload_sha256"],
            "prev_pin_record_sha256": prep["prev_pin_record_sha256"],
            "author_key_ids": approvals,
            "authorship_sigs": {
                approvals[0]: authorship_sig_hex,
                **({approvals[1]: second_authorship_sig_hex}
                   if len(approvals) > 1 else {}),
            },
            "pinned_at": prep["ts"],
        }
        pin_record["record_sha256"] = _record_sha256(pin_record)
        manifest = dict(prep["payload"])
        manifest["pin_record"] = pin_record
        blob = _canonical_json_bytes(manifest)
        with open(manifest_path, "wb") as f:
            f.write(blob)
        receipt = {
            "format": RECEIPT_FORMAT,
            "manifest_sha256": _digest_bytes(blob, "sha256"),
            "installed_at": manifest["installed_at"],
        }
        with open(receipt_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, sort_keys=True, indent=2)
        with open(prep["ledger_path"], "a", encoding="utf-8") as f:
            f.write(json.dumps(pin_record, sort_keys=True) + "\n")
        return manifest

    # -- verify -------------------------------------------------------
    def _load_receipt(self):
        try:
            with open(self.receipt_path, "r", encoding="utf-8") as f:
                receipt = json.load(f)
        except (OSError, ValueError) as e:
            raise EgressLaunchRefused(
                "receipt_unverifiable: %s" % e)
        if not isinstance(receipt, dict) or \
                receipt.get("format") != RECEIPT_FORMAT:
            raise EgressLaunchRefused("receipt_unverifiable: bad format")
        return receipt

    def _load_manifest(self, receipt):
        try:
            with open(self.manifest_path, "rb") as f:
                blob = f.read()
        except OSError as e:
            raise EgressLaunchRefused(
                "receipt_unverifiable: manifest unreadable: %s" % e)
        if _digest_bytes(blob, "sha256") != receipt.get("manifest_sha256"):
            raise EgressLaunchRefused(
                "receipt_unverifiable: manifest digest != receipt "
                "(manifest tampered or replaced)")
        try:
            manifest = json.loads(blob.decode("utf-8"))
        except ValueError as e:
            raise EgressLaunchRefused(
                "receipt_unverifiable: manifest not JSON: %s" % e)
        if not isinstance(manifest, dict) or \
                not isinstance(manifest.get("format"), str):
            raise EgressLaunchRefused(
                "receipt_unverifiable: bad manifest format")
        # NOTE: the manifest FORMAT version itself is authorized by
        # _verify_pin_record: a legacy format without pin authorship is
        # refused there with an actionable pin_authorship_invalid
        # reason, not here.
        return manifest

    def _verify_pin_record(self, manifest):
        """F138: pin authorship + history. Every manifest must carry a
        roster-human-authorized pin record bound to its payload, and the
        operator-held pin ledger must hash-chain to that exact record.
        WallPinRefused from the shared checks is surfaced as
        EgressLaunchRefused (the launcher's fail-closed vocabulary)."""
        try:
            self._check_pin_record(manifest)
        except WallPinRefused as e:
            raise EgressLaunchRefused(str(e))

    def _check_pin_record(self, manifest):
        if manifest.get("format") != MANIFEST_FORMAT:
            raise WallPinRefused(
                "pin_authorship_invalid: legacy manifest format %r "
                "carries no pin authorship (re-pin under human "
                "authorship required)" % (manifest.get("format"),))
        pin_record = manifest.get("pin_record")
        if not isinstance(pin_record, dict) or \
                pin_record.get("format") != PIN_RECORD_FORMAT:
            raise WallPinRefused(
                "pin_authorship_invalid: manifest has no pin record")
        tier = pin_record.get("tier")
        if tier not in _PIN_TIERS:
            raise WallPinRefused(
                "pin_authorship_invalid: unknown pin tier %r" % (tier,))
        # 1. the pin record must bind the payload it ships with — a
        #    manifest edited after pinning fails here even if the
        #    receipt was re-minted.
        payload = {k: v for k, v in manifest.items() if k != "pin_record"}
        payload_sha = _digest_bytes(_canonical_json_bytes(payload), "sha256")
        if pin_record.get("pin_payload_sha256") != payload_sha:
            raise WallPinRefused(
                "pin_authorship_invalid: pin record not bound to manifest "
                "payload (manifest edited after pinning)")
        # 2. the operator-held ledger must hash-chain to this exact pin
        #    record — a missing/rewritten history refuses.
        records = _read_pin_ledger(self.ledger_path)
        if not records:
            raise WallPinRefused(
                "pin_chain_broken: pin ledger missing or empty "
                "(operator-held pin history required)")
        tip = _check_pin_ledger_structure(records)
        if tip != pin_record.get("record_sha256"):
            raise WallPinRefused(
                "pin_chain_broken: ledger tip != manifest pin record "
                "(history rewritten or manifest swapped)")
        # 3. live authorship check on the tip record: the signature is
        #    verified over the RECOMPUTED body, so a signature can never
        #    be valid for tampered content.
        if self.trust is None:
            raise WallPinRefused(
                "pin_authorship_invalid: no trust roster configured; "
                "cannot verify pin authorship")
        if _record_sha256(pin_record) != pin_record.get("record_sha256"):
            raise WallPinRefused(
                "pin_authorship_invalid: pin record self-hash mismatch "
                "(record edited)")
        body = _canonical_pin_record_body(
            tier, payload_sha, pin_record.get("prev_pin_record_sha256"),
            pin_record.get("pinned_at"))
        key_ids = pin_record.get("author_key_ids") or []
        sigs = pin_record.get("authorship_sigs") or {}
        if not isinstance(key_ids, list) or \
                not all(isinstance(k, str) for k in key_ids):
            raise WallPinRefused(
                "pin_authorship_invalid: malformed author_key_ids")
        if tier == "production":
            if len(key_ids) < 2:
                raise WallPinRefused(
                    "pin_authorship_invalid: production pin record "
                    "carries fewer than two approvals")
            first, second = key_ids[0], key_ids[1]
        else:
            if not key_ids:
                raise WallPinRefused(
                    "pin_authorship_invalid: pin record carries no "
                    "approvals")
            first, second = key_ids[0], None
        _require_pin_approvals(
            self.trust, body, tier, first, sigs.get(first), second,
            sigs.get(second) if second else None)

    def verify(self):
        """Full chain verification. Returns (manifest, per-component
        digests). Raises EgressLaunchRefused on ANY failure."""
        receipt = self._load_receipt()
        manifest = self._load_manifest(receipt)
        self._verify_pin_record(manifest)
        algos = manifest.get("algos") or []
        if negotiate_algo(algos, self.supported_algos) is None:
            raise EgressLaunchRefused(
                "no_common_algorithm: manifest=%r supported=%r"
                % (algos, list(self.supported_algos)))
        checked = {}
        for entry in manifest.get("components", []):
            name = entry.get("name")
            path = entry.get("path")
            if not name or not path:
                raise EgressLaunchRefused(
                    "component_tampered: manifest entry malformed")
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError:
                raise EgressLaunchRefused(
                    "component_tampered: %s absent (%s)" % (name, path))
            # Symlink-shape check: a symlink swapped to a different
            # target with identical bytes is still a deployment change
            # worth refusing on (defense in depth; the digest is the
            # primary signal).
            if os.path.realpath(path) != entry.get("realpath"):
                raise EgressLaunchRefused(
                    "component_tampered: %s symlink target changed "
                    "(%s -> %s)" % (name, entry.get("realpath"),
                                    os.path.realpath(path)))
            if os.path.islink(path) != bool(entry.get("is_symlink")):
                raise EgressLaunchRefused(
                    "component_tampered: %s symlink shape changed" % name)
            want = entry.get("digests") or {}
            for algo in algos:
                if algo not in self.supported_algos:
                    continue
                got = _digest_bytes(data, algo)
                if want.get(algo) != got:
                    raise EgressLaunchRefused(
                        "component_tampered: %s digest mismatch (%s)"
                        % (name, algo))
            checked[name] = {a: want.get(a) for a in algos
                             if a in self.supported_algos}
        return manifest, checked


# ---------------------------------------------------------------------------
# Wall state — UP / DOWN / DEGRADED, and the provider interface.
# ---------------------------------------------------------------------------

WALL_UP = "UP"
WALL_DOWN = "DOWN"
WALL_DEGRADED = "DEGRADED"


class WallStateReport:
    def __init__(self, state, detail=None):
        self.state = state
        self.detail = dict(detail or {})

    def ok(self):
        return self.state == WALL_UP

    def __repr__(self):
        return "WallStateReport(%s, %r)" % (self.state, self.detail)


class WallStateProvider:
    """How the launcher observes the wall. Production: netns/nftables/
    listener checks. Tests: the simulated provider below."""

    def check(self):
        """Return a WallStateReport. Must be cheap and side-effect free."""
        raise NotImplementedError

    def child_recheck(self):
        """Re-run inside the child preexec (after fork, before exec).
        Raise EgressLaunchRefused (or return False) to abort the child."""
        report = self.check()
        if not report.ok():
            raise EgressLaunchRefused(
                "preexec_recheck_failed: wall %s (%r)"
                % (report.state, report.detail))
        return True

    def describe(self):
        return {"provider": type(self).__name__}

    def wrap_argv(self, argv):
        """Return the argv prefix that places the child in the wall.

        The default is identity: providers that do not move the child
        into a namespace (e.g. the simulated provider) spawn argv
        unchanged. NetnsWallProvider overrides this to return
        ``["ip", "netns", "exec", <netns>, <seccomp helper>, *argv]``.
        FilteredEgressLauncher.launch() applies this at spawn time,
        after verify + check and before Popen.
        """
        return list(argv)

    def child_env_extra(self):
        """Extra env vars injected into every launched child (e.g. the
        in-wall proxy endpoint). Production returns the well-known
        in-netns addresses; the sim reads endpoints.json."""
        return {}


# ---------------------------------------------------------------------------
# Localhost fixtures: the simulated wall.
#
# The sim models the LAB wall's mechanism on 127.0.0.1 with ephemeral
# ports (no privileges, no real netns):
#   - nft_state.txt        "running ruleset" (fake iptables state);
#                          symbolic ALLOW lines resolved via endpoints.json
#   - wall_up.flag         operator-set liveness marker
#   - StubDnsServer        confined resolver: authoritative for the
#                          pinned zone only, NXDOMAIN otherwise
#   - StubProxyServer      CONNECT + absolute-form proxy enforcing the
#                          pinned allowlist, resolving ONLY via the stub
#                          DNS (the lab's A5 bug fix, reproduced here)
# The sim does NOT model the IP-layer drop with real packets — the
# FakePacketFilter parses the pinned ruleset and answers would_drop()
# for any tuple; the real IP-layer enforcement was lab-validated.
# ---------------------------------------------------------------------------

SIM_PROXY_HOST = "127.0.0.1"
SIM_DNS_HOST = "127.0.0.1"

# Child-visible marker: the sim cannot put the child in a real netns,
# so the marker + scrubbed env + proxy-only routing is the sim's
# "inside the wall" notion. The battery asserts the marker is set and
# the env is scrubbed.
WALL_ACTIVE_ENV = "EGRESS_WALL_ACTIVE"
WALL_ID_ENV = "EGRESS_WALL_ID"

# Proxy-env names the launcher scrubs from the child (F81 Wiki lesson:
# a child-controlled NO_PROXY must never widen operator trust).
_PROXY_ENV_NAMES = ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")

# Distinctive child exit code when the preexec re-assert aborts the
# child before exec: observable by the parent, never a real exit code
# of a launched workload.
PREEXEC_ABORT_CODE = 99

# F149: distinctive child exit code when an embedder preexec_chain
# entry fails AFTER the wall re-check passed (i.e. after the F148 ack
# was written). Distinct from PREEXEC_ABORT_CODE (99, re-check abort,
# pre-ack) so the parent can tell "the wall flapped" from "the chain
# broke" -- the audit refusal must name the true cause.
PREEXEC_CHAIN_ABORT_CODE = 98

# F149: post-ack chain-failure check. The F148 ack attests the wall
# re-check, not the embedder chain (which runs after the ack; a
# post-chain ack is impossible on pidns paths whose intermediate
# _exits by design). Chain entries are synchronous pre-exec setup.
# Popen.__init__ blocks on its preexec error pipe until the child's
# preexec_fn completes, but returns on error-pipe EOF which can race
# the child's actual exit -- so launch() does a brief (0.5s) wait for
# a PREEXEC_CHAIN_ABORT_CODE (98) exit. A 98 means a chain entry
# failed: refuse truthfully with no launch event (fail-closed,
# mirroring the pre-ack EOF path). A child that survives the 0.5s --
# or exits any other code (it exec'd) -- gets the witnessed launch
# event. No 2-second grace: Popen already blocks through the chain.
#
# Explicit non-coverage (spec review): the sandbox's chain entry
# (gov/sandbox.py) calls os._exit(127) -- not raise -- on hardening
# failure, so the 98 path never engages there; a sandbox-layer failure
# yields an unpaired egress_wall_launch (the sandbox's own 5-byte
# status marker and _refuse_loud receipt remain that layer's audit
# responsibility, per the F148 docstring carve-out). Only chain
# entries that RAISE get the 98 treatment.

# F148: deadline for the child's preexec ack byte. The ack follows
# the provider's child_recheck(); the production provider's check
# does an `nft list` (15s subprocess timeout) plus a TCP proxy
# connect and a DNS query (3s each), so 30s is generous while still
# bounding a hung child. Expiry kills the child and refuses (fail
# closed) -- a launch event is never emitted without the ack.
_PREEXEC_ACK_TIMEOUT_S = 30.0

# F148: grace for reaping a child that died in preexec. EOF on the
# status pipe means the child's write end is closed, but on Linux
# fds are closed before the task becomes a zombie -- a single
# poll() in that window returns None and would misreport a clean
# preexec abort as a hang. wait() with this grace reaps it
# deterministically; expiry (the process will not die) falls back
# to kill + "preexec_child_died".
_PREEXEC_REAP_GRACE_S = 5.0


def install_simulated_wall(sim_dir, *, algos=DEFAULT_ALGOS,
                           wall_id="sim-wall-1", trust=None,
                           operator_signers=None, tier="dev",
                           live_digests=None):
    """Create a simulated wall install: components + manifest + receipt +
    pin ledger.

    The pin is authorized by roster-human Ed25519 authorship (F138). The
    caller may pass their own ``trust`` (DelegationTrust) and
    ``operator_signers`` (list of Ed25519Signer); when omitted, an
    ephemeral sim operator keypair is generated — honest for a localhost
    fixture, never for production. ``tier`` defaults to ``"dev"``
    (single-human); pass ``"production"`` for the two-human rule.

    ``live_digests`` (optional) maps component names to their
    install-time *live* digests (e.g. {"nft_ruleset": <sha256 of the
    normalized deployed ruleset>}); they are recorded on the manifest
    entry for drift detection by live-state providers. The sim
    provider ignores them; NetnsWallProvider requires them.

    Returns (inventory, paths dict). The inventory is wired with the
    trust + ledger so verify() checks authorship and chain. paths also
    carries "ledger" and "trust" (public roster only).
    """
    sim_dir = os.path.abspath(sim_dir)
    conf_dir = os.path.join(sim_dir, "conf")
    run_dir = os.path.join(sim_dir, "run")
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(run_dir, exist_ok=True)

    def w(name, text):
        p = os.path.join(conf_dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    # The "running ruleset" is a separate file from the pinned desired
    # state: the launcher checks that the RUNNING wall matches the PIN.
    # Symbolic service names (wall:proxy / wall:dns) are resolved via
    # endpoints.json so ephemeral ports do not churn the digest.
    # Transport note: the lab wall allowed UDP+TCP/53; this fixture's
    # confined DNS speaks DNS-over-TCP (RFC 7766) because the build
    # environment's seccomp blocks the sendto() syscall. The modeled
    # mechanism (allowlisted answers only) is transport-independent.
    nft_ruleset = w("agent0.nft.sim",
                    "# simulated default-deny egress wall (desired state)\n"
                    "# production: nftables inside netns agent0; here the\n"
                    "# FakePacketFilter enforces the same semantics.\n"
                    "ALLOW tcp wall:dns   # confined DNS only (sim: TCP)\n"
                    "ALLOW tcp wall:proxy # egress proxy only\n"
                    "DROP  *              # everything else\n")
    with open(nft_ruleset, encoding="utf-8") as src:
        desired = src.read()
    with open(os.path.join(run_dir, "nft_state.txt"), "w",
              encoding="utf-8") as f:
        f.write(desired)

    allowlist = w("allowlist.txt",
                  "# the entire outside world (sim)\n"
                  "example.com:443\n"
                  "example.com:80\n")
    dns_config = w("dns_config.txt",
                   "# confined-resolver config (simulates dnsmasq.conf)\n"
                   "stop-dns-rebind\n"
                   "cache-size=0\n"
                   "forward-only-allowlisted\n")
    dns_zone = w("dns_hosts.txt",
                 "# authoritative zone: allowlisted names only.\n"
                 "# Everything else -> NXDOMAIN (no answer = no connect).\n"
                 "example.com 127.0.0.1\n")
    proxy_impl = w("proxy_impl.txt",
                   "# proxy enforcement-policy descriptor.\n"
                   "# PRODUCTION: pin the deployed proxy artifact bytes.\n"
                   "mode=CONNECT-and-absolute-form-only\n"
                   "resolver=confined-only\n"
                   "default=deny-with-log\n")
    seccomp_config = w("seccomp_config.txt",
                       "# seccomp-BPF policy descriptor (sim).\n"
                       "# PRODUCTION: pin the deployed BPF/profile bytes.\n"
                       "deny=socket(AF_PACKET) socket(SOCK_RAW) "
                       "unshare(CLONE_NEWNET) setns\n")
    # The sim's stand-in for the vendored run_seccomp.py artifact: the
    # real deployment pins the vendored bytes (gov/data/run_seccomp.py)
    # copied into the conf dir. The sim provider never executes it
    # (wrap_argv is identity there); what matters here is that the pin
    # covers the helper's bytes, so tamper refuses.
    seccomp_helper = w("run_seccomp.py",
                       "# simulated seccomp-helper stand-in.\n"
                       "# PRODUCTION: copy gov/data/run_seccomp.py here;\n"
                       "# its bytes are what the pin binds.\n"
                       "raise SystemExit('sim stand-in: never executed')\n")

    manifest_path = os.path.join(sim_dir, "wall_pins.json")
    receipt_path = os.path.join(sim_dir, "wall_receipt.json")
    ledger_path = _default_ledger_path(manifest_path)
    trust, signers = _operator_roster(trust, operator_signers, tier)
    component_paths = {"nft_ruleset": nft_ruleset,
                       "proxy_allowlist": allowlist,
                       "dns_config": dns_config,
                       "dns_zone": dns_zone,
                       "proxy_impl": proxy_impl,
                       "seccomp_config": seccomp_config,
                       "seccomp_helper": seccomp_helper}
    prop = WallComponentInventory.proposal(
        component_paths, manifest_path, algos=algos, tier=tier,
        ledger_path=ledger_path, live_digests=live_digests)
    sigs = [s.sign(prop["body"]).hex() for s in signers]
    kids = [s.key_id for s in signers]
    WallComponentInventory.install(
        component_paths, manifest_path, receipt_path, algos=algos,
        trust=trust, author_key_id=kids[0], authorship_sig_hex=sigs[0],
        ts=prop["ts"], tier=tier,
        second_author_key_id=kids[1] if len(kids) > 1 else None,
        second_authorship_sig_hex=sigs[1] if len(sigs) > 1 else None,
        ledger_path=ledger_path, live_digests=live_digests)
    with open(os.path.join(sim_dir, "wall_id.txt"), "w",
              encoding="utf-8") as f:
        f.write(wall_id + "\n")
    paths = {"manifest": manifest_path, "receipt": receipt_path,
             "ledger": ledger_path, "trust": trust,
             "conf_dir": conf_dir, "run_dir": run_dir,
             "allowlist": allowlist, "nft_ruleset": nft_ruleset,
             "dns_zone": dns_zone, "wall_id": wall_id}
    return (WallComponentInventory(manifest_path, receipt_path,
                                  trust=trust, ledger_path=ledger_path),
            paths)


# ---------------------------------------------------------------------------
# FakePacketFilter — parses the pinned ruleset; answers would_drop().
# ---------------------------------------------------------------------------

class FakePacketFilter:
    """The sim's IP-layer model, parsed from the pinned ruleset text.

    In production this layer is nftables inside the netns (lab
    validated). Here the battery asserts the *model* drops exfil tuples;
    the proxy stub (real sockets) refuses them for real.
    """

    def __init__(self, ruleset_text, endpoints):
        self.rules = []  # (proto, host, port)
        eps = endpoints or {}
        sym = {"wall:proxy": (SIM_PROXY_HOST,
                              eps.get("proxy", [None, None])[1]),
               "wall:dns": (SIM_DNS_HOST,
                            eps.get("dns", [None, None])[1])}
        for line in ruleset_text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line.startswith("ALLOW"):
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            _, proto, target = parts
            if target in sym:
                host, port = sym[target]
            elif ":" in target:
                host, _, port = target.rpartition(":")
                port = int(port)
            else:
                continue
            self.rules.append((proto.lower(), host, port))

    def would_drop(self, host, port, proto="tcp"):
        for rproto, rhost, rport in self.rules:
            if rproto == proto.lower() and rhost == host \
                    and rport == port:
                return False
        return True


# ---------------------------------------------------------------------------
# StubDnsServer — confined resolver: pinned zone only, NXDOMAIN otherwise.
# ---------------------------------------------------------------------------

def _dns_encode_name(name):
    out = b""
    for part in name.rstrip(".").split("."):
        out += bytes([len(part)]) + part.encode("ascii")
    return out + b"\x00"


def _dns_decode_name(buf, off):
    parts = []
    while True:
        ln = buf[off]
        off += 1
        if ln == 0:
            break
        parts.append(buf[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(parts), off


def dns_query(host, port, name, timeout=3.0):
    """Minimal DNS client: A query, returns IPv4 string or None.

    Transport note: DNS-over-TCP (RFC 7766) with the 2-byte length
    prefix. The lab used real dnsmasq over UDP; this environment's
    seccomp blocks the sendto() syscall, so the localhost fixture
    speaks TCP. The modeled mechanism — authoritative answers for the
    pinned zone only, NXDOMAIN otherwise, no-answer-means-no-connect —
    is transport-independent.
    """
    txid = os.urandom(2)
    q = (txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         + _dns_encode_name(name) + b"\x00\x01\x00\x01")
    pkt = struct.pack(">H", len(q)) + q
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(pkt)
        hdr = b""
        while len(hdr) < 2:
            chunk = s.recv(2 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        (rlen,) = struct.unpack(">H", hdr)
        data = b""
        while len(data) < rlen:
            chunk = s.recv(rlen - len(data))
            if not chunk:
                return None
            data += chunk
    except OSError:
        return None
    finally:
        s.close()
    if len(data) < 12 or data[0:2] != txid:
        return None
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return None
    try:
        _, off = _dns_decode_name(data, 12)
    except (IndexError, struct.error):
        return None
    off += 4  # qtype+qclass
    try:
        while off + 10 <= len(data):
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                _, off = _dns_decode_name(data, off)
            atype, aclass, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if atype == 1 and aclass == 1 and rdlen == 4:
                return socket.inet_ntoa(rdata)
    except (IndexError, struct.error):
        return None
    return None


class StubDnsServer(threading.Thread):
    """Authoritative DNS for the pinned zone file only (TCP transport;
    see dns_query for why the fixture uses DNS-over-TCP)."""

    def __init__(self, zone_path, log_path=None):
        super().__init__(daemon=True)
        self.zone_path = zone_path
        self.log_path = log_path
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((SIM_DNS_HOST, 0))
        self._sock.listen(32)
        self.port = self._sock.getsockname()[1]
        self._stop_event = threading.Event()

    def _zone(self):
        zone = {}
        try:
            with open(self.zone_path, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) == 2:
                        zone[parts[0].lower().rstrip(".")] = parts[1]
        except OSError:
            pass
        return zone

    def _log(self, line):
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def run(self):
        self._sock.settimeout(0.2)
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._answer, args=(conn,),
                                 daemon=True)
            t.start()

    def _answer(self, conn):
        try:
            conn.settimeout(3.0)
            hdr = b""
            while len(hdr) < 2:
                chunk = conn.recv(2 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            (qlen,) = struct.unpack(">H", hdr)
            data = b""
            while len(data) < qlen:
                chunk = conn.recv(qlen - len(data))
                if not chunk:
                    return
                data += chunk
            if len(data) < 12:
                return
            txid = data[0:2]
            try:
                qname, _ = _dns_decode_name(data, 12)
            except (IndexError, struct.error):
                return
            ip = self._zone().get(qname.lower())
            if ip:
                flags = b"\x81\x80"
                ancount = b"\x00\x01"
                answer = (b"\xc0\x0c" + b"\x00\x01\x00\x01"
                          + b"\x00\x00\x00\x00" + b"\x00\x04"
                          + socket.inet_aton(ip))
                self._log("ALLOW-DNS %s -> %s" % (qname, ip))
            else:
                flags = b"\x81\x83"  # NXDOMAIN
                ancount = b"\x00\x00"
                answer = b""
                self._log("DENY-DNS %s NXDOMAIN" % qname)
            resp = (txid + flags + b"\x00\x01" + ancount
                    + b"\x00\x00\x00\x00" + data[12:] + answer)
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass
        # Join the accept loop: a thread blocked in accept() holds a
        # reference to the file description, so the port is only freed
        # once the thread observes the close/event and exits. Without
        # the join, an immediate rebind races the 0.2s accept timeout
        # and fails with EADDRINUSE (observed in the battery).
        self.join(timeout=5)


# ---------------------------------------------------------------------------
# StubProxyServer — CONNECT + absolute-form, pinned allowlist, confined
# resolver ONLY (the lab's A5 fix: never the host resolver).
# ---------------------------------------------------------------------------

class StubProxyServer(threading.Thread):
    def __init__(self, allowlist_path, dns_host, dns_port,
                 deny_log_path=None):
        super().__init__(daemon=True)
        self.allowlist_path = allowlist_path
        self.dns_host = dns_host
        self.dns_port = dns_port
        self.deny_log_path = deny_log_path
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((SIM_PROXY_HOST, 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(64)
        self._stop_event = threading.Event()

    def _allowlist(self):
        allowed = set()
        try:
            with open(self.allowlist_path, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip().lower()
                    if line:
                        allowed.add(line)
        except OSError:
            pass
        return allowed

    def _deny(self, line):
        if self.deny_log_path:
            with open(self.deny_log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _relay(self, a, b):
        a.setblocking(False)
        b.setblocking(False)
        pair = {a: b, b: a}
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 10.0)
                if not r:
                    break
                for s in r:
                    try:
                        data = s.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    try:
                        pair[s].sendall(data)
                    except OSError:
                        return
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def _handle(self, conn):
        try:
            conn.settimeout(5.0)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            try:
                request_line = head.split(b"\r\n", 1)[0].decode(
                    "ascii", "replace")
                method, target, _ = request_line.split(" ", 2)
            except ValueError:
                return
            method = method.upper()
            if method == "CONNECT":
                hostport = target
                path_suffix = b""
            elif target.startswith("http://"):
                rest = target[len("http://"):]
                hostport, _, suffix = rest.partition("/")
                path_suffix = b"/" + suffix.encode("ascii", "replace")
            else:
                conn.sendall(b"HTTP/1.1 400 bad request\r\n\r\n")
                self._deny("DENY-PROXY malformed %r" % target)
                return
            if ":" in hostport:
                host, _, port_s = hostport.rpartition(":")
            else:
                host, port_s = hostport, "80"
            try:
                port = int(port_s)
            except ValueError:
                port = -1
            key = "%s:%d" % (host.lower(), port)
            if key not in self._allowlist():
                conn.sendall(b"HTTP/1.1 403 denied by egress wall\r\n\r\n")
                self._deny("DENY-CONNECT %s" % key)
                return
            # Confined resolution ONLY — never the host resolver.
            ip = dns_query(self.dns_host, self.dns_port, host.lower())
            if not ip:
                conn.sendall(b"HTTP/1.1 502 no confined answer\r\n\r\n")
                self._deny("DENY-NOANSWER %s" % key)
                return
            try:
                up = socket.create_connection((ip, port), timeout=5.0)
            except OSError:
                conn.sendall(b"HTTP/1.1 502 upstream refused\r\n\r\n")
                self._deny("DENY-UPSTREAM %s" % key)
                return
            if method == "CONNECT":
                conn.sendall(b"HTTP/1.1 200 established\r\n\r\n")
                self._relay(conn, up)
            else:
                up.sendall(b"GET " + path_suffix + b" HTTP/1.0\r\n"
                            b"Host: " + host.encode("ascii", "replace")
                            + b"\r\n\r\n")
                self._relay(up, conn)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def run(self):
        self._sock.settimeout(0.2)
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn,),
                                 daemon=True)
            t.start()

    def stop(self):
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass
        # Join the accept loop: a thread blocked in accept() holds a
        # reference to the file description, so the port is only freed
        # once the thread observes the close/event and exits. Without
        # the join, an immediate rebind races the 0.2s accept timeout
        # and fails with EADDRINUSE (observed in the battery).
        self.join(timeout=5)


# ---------------------------------------------------------------------------
# SimulatedWallProvider — the launcher's view of the sim wall.
# ---------------------------------------------------------------------------

class SimulatedWallProvider(WallStateProvider):
    """Wall-state checks against the localhost fixture.

    UP requires ALL of: the operator liveness flag, the RUNNING ruleset
    digest matching the PINNED digest (live-wall drift detection), a TCP
    handshake to the proxy stub, and a confined-DNS probe answer.
    Anything less is DOWN/DEGRADED — and the launcher refuses either
    way (fail-closed); the distinction is diagnostic only.
    """

    def __init__(self, sim_dir, inventory, probe_name="example.com"):
        self.sim_dir = os.path.abspath(sim_dir)
        self.inventory = inventory
        self.probe_name = probe_name

    def _endpoints(self):
        p = os.path.join(self.sim_dir, "endpoints.json")
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _pinned_ruleset_digest(self, algo="sha256"):
        manifest, _ = self.inventory.verify()
        for e in manifest["components"]:
            if e["name"] == "nft_ruleset":
                return e["digests"][algo]
        return None

    def check(self):
        eps = self._endpoints()
        proxy_ep = eps.get("proxy")
        dns_ep = eps.get("dns")
        if not os.path.exists(os.path.join(self.sim_dir, "run",
                                            "wall_up.flag")):
            return WallStateReport(WALL_DOWN,
                                   {"missing": "wall_up.flag"})
        try:
            with open(os.path.join(self.sim_dir, "run",
                                   "nft_state.txt"), "rb") as f:
                running = f.read()
        except OSError:
            return WallStateReport(WALL_DOWN,
                                   {"missing": "run/nft_state.txt"})
        try:
            pinned = self._pinned_ruleset_digest()
        except EgressLaunchRefused as e:
            return WallStateReport(WALL_DOWN, {"pin_verify": str(e)})
        if pinned is None or _digest_bytes(running, "sha256") != pinned:
            return WallStateReport(WALL_DEGRADED,
                                   {"running_ruleset_drift": True})
        missing = []
        if not proxy_ep:
            missing.append("proxy endpoint")
        else:
            try:
                s = socket.create_connection(tuple(proxy_ep), timeout=2.0)
                s.close()
            except OSError:
                missing.append("proxy unreachable")
        if not dns_ep:
            missing.append("dns endpoint")
        else:
            ans = dns_query(dns_ep[0], dns_ep[1], self.probe_name,
                            timeout=2.0)
            if ans is None:
                missing.append("dns probe failed")
        if missing:
            return WallStateReport(WALL_DEGRADED, {"missing": missing})
        return WallStateReport(WALL_UP, {"proxy": proxy_ep, "dns": dns_ep})

    def describe(self):
        return {"provider": "SimulatedWallProvider",
                "sim_dir": self.sim_dir}

    def child_env_extra(self):
        eps = self._endpoints()
        extra = {}
        if eps.get("proxy"):
            extra["EGRESS_PROXY_ADDR"] = "%s:%d" % tuple(eps["proxy"])
        if eps.get("dns"):
            extra["EGRESS_DNS_ADDR"] = "%s:%d" % tuple(eps["dns"])
        return extra


class FlappingWallProvider(SimulatedWallProvider):
    """Test hook: first check() is UP, every later check is DOWN.

    Models the wall dying in the check->spawn window; the child-side
    preexec re-assert must catch it (exit 99, nothing exec'd).
    """

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._checks = 0

    def check(self):
        self._checks += 1
        if self._checks == 1:
            return WallStateReport(WALL_UP, {"flap": "first-check"})
        return WallStateReport(WALL_DOWN, {"flap": "wall died mid-launch"})


# ---------------------------------------------------------------------------
# Production provider: the real netns/nftables/seccomp topology (F81
# launcher wave).
#
# NetnsWallProvider(WallStateProvider) observes the LAB-validated wall:
# netns agent0, in-namespace nftables, the proxy + confined DNS on
# 10.200.0.1, and the pinned run_seccomp helper. check() runs the D5
# ordered fail-closed sequence; wrap_argv() returns the spawn prefix
# (D2/D3: ip netns exec agent0 <helper> … — netns entry, then the
# seccomp filter, then the agent argv). child_recheck() is inherited
# from WallStateProvider: the preexec child re-runs exactly these
# host-visible D5 checks (still in the host netns, before it execs
# `ip`) — D6 needs no override.
#
# The launcher REQUIRES privilege; it never grants it (D4): without
# CAP_SYS_ADMIN the netns is invisible and check() reports WALL_DOWN
# (netns_missing_or_unprivileged) — fail closed, never un-isolated.
# The `ip` / `ip netns` host binary is host TCB (threat-model
# non-goal): it is resolved once at construction and reported by
# describe(), never re-resolved per launch.
# ---------------------------------------------------------------------------

# Well-known in-namespace endpoints (the lab topology, build.sh).
WALL_NETNS = "agent0"
WALL_PROXY_ADDR = ("10.200.0.1", 8080)
WALL_DNS_ADDR = ("10.200.0.1", 53)


def _normalize_nft_ruleset(text):
    """Canonicalize `nft list ruleset` output for drift comparison.

    Strips `#` comments, `handle N` tokens (kernel-assigned, churn
    across loads), and whitespace runs; drops blank lines. This is
    what makes the live-vs-pinned digest comparison robust to
    nftables version formatting (fog decision 1): anything the
    normalizer cannot bridge fails closed as ruleset_drift and the
    operator re-pins. Deterministic: same semantic ruleset yields
    the same bytes.
    """
    out = []
    for line in text.splitlines():
        line = re.sub(r"#.*$", "", line)
        line = re.sub(r"\bhandle\s+\d+", "", line)
        line = " ".join(line.split())
        if line:
            out.append(line)
    return "\n".join(out) + "\n"


class NetnsWallProvider(WallStateProvider):
    """Wall-state checks against the production netns topology.

    UP requires ALL of (D5, in order): the netns exists (bind-mount
    or `ip netns list`), the installed seccomp-helper bytes match the
    pinned `seccomp_helper` digests, the live in-namespace nftables
    ruleset matches the install-time baseline digest, and the
    proxy + confined-DNS listeners answer. Anything less is
    DOWN/DEGRADED — and the launcher refuses either way
    (fail-closed); the distinction is diagnostic only.
    """

    def __init__(self, inventory, *, netns_name=WALL_NETNS,
                 netns_dir="/run/netns", ip_path=None, helper_path=None,
                 proxy_addr=WALL_PROXY_ADDR, dns_addr=WALL_DNS_ADDR,
                 probe_name="example.com"):
        self.inventory = inventory
        self.netns_name = netns_name
        self.netns_dir = netns_dir
        # Fog decision 3: the `ip` binary path is resolved ONCE at
        # construction (shutil.which) and pinned-observable via
        # describe(). A per-launch PATH lookup could silently swap
        # the binary mid-deployment; construction-time resolution
        # keeps the spawn prefix stable for the provider's lifetime.
        self.ip_path = ip_path or shutil.which("ip")
        if not self.ip_path:
            raise EgressLaunchRefused(
                "ip_not_found: no `ip` binary on PATH and no ip_path "
                "given (netns entry is host-privileged; the launcher "
                "requires the operator to provide it — refusing "
                "fail-closed)")
        self.helper_path = helper_path
        self.proxy_addr = tuple(proxy_addr)
        self.dns_addr = tuple(dns_addr)
        self.probe_name = probe_name

    # -- ip plumbing -------------------------------------------------
    def _run_ip(self, *args, timeout=10.0):
        """Run the pinned `ip` binary. Returns (rc, stdout, stderr);
        (None, "", err) when the binary cannot run at all."""
        try:
            cp = subprocess.run(
                [self.ip_path] + [str(a) for a in args],
                capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as e:
            return None, "", str(e)
        return (cp.returncode, cp.stdout.decode("utf-8", "replace"),
                cp.stderr.decode("utf-8", "replace"))

    def _netns_present(self):
        if os.path.exists(os.path.join(self.netns_dir,
                                       self.netns_name)):
            return True
        rc, out, _ = self._run_ip("netns", "list")
        if rc != 0:
            return False
        return any(line.split()[:1] == [self.netns_name]
                   for line in out.splitlines())

    # -- WallStateProvider -------------------------------------------
    def check(self):
        # D5 step 1: netns existence (bind-mount or ip listing).
        if not self._netns_present():
            return WallStateReport(
                WALL_DOWN, {"reason": "netns_missing_or_unprivileged"})
        # D5 step 2: the installed helper's bytes still match the pin.
        try:
            manifest, _ = self.inventory.verify()
        except EgressLaunchRefused as e:
            return WallStateReport(WALL_DOWN, {"pin_verify": str(e)})
        helper_entry = nft_entry = None
        for e in manifest.get("components", []):
            if e.get("name") == "seccomp_helper":
                helper_entry = e
            elif e.get("name") == "nft_ruleset":
                nft_entry = e
        if helper_entry is None:
            # D7: a v2 manifest without the helper is a
            # pre-productization manifest — refused for the real
            # provider, never a silent partial wall.
            return WallStateReport(
                WALL_DEGRADED, {"reason": "helper_not_pinned"})
        if not self.helper_path:
            return WallStateReport(
                WALL_DEGRADED, {"reason": "helper_not_configured"})
        try:
            with open(self.helper_path, "rb") as f:
                helper_bytes = f.read()
        except OSError:
            return WallStateReport(
                WALL_DEGRADED, {"reason": "component_tampered",
                                "component": "seccomp_helper",
                                "detail": "helper unreadable"})
        want = (helper_entry.get("digests") or {}).get("sha256")
        if want != _digest_bytes(helper_bytes, "sha256"):
            return WallStateReport(
                WALL_DEGRADED, {"reason": "component_tampered",
                                "component": "seccomp_helper"})
        # D5 step 3: live ruleset vs pinned desired state (fog 1:
        # normalized `nft list ruleset` digest vs the install-time
        # baseline pinned in the manifest entry).
        baseline = (nft_entry or {}).get("live_sha256")
        if not baseline:
            return WallStateReport(
                WALL_DEGRADED, {"reason": "ruleset_baseline_missing"})
        rc, out, err = self._run_ip("netns", "exec", self.netns_name,
                                   "nft", "list", "ruleset", timeout=15.0)
        if rc != 0:
            return WallStateReport(
                WALL_DEGRADED, {"reason": "ruleset_unreadable",
                                "detail": err[:200]})
        live = _digest_bytes(
            _normalize_nft_ruleset(out).encode("utf-8"), "sha256")
        if live != baseline:
            return WallStateReport(
                WALL_DEGRADED, {"reason": "ruleset_drift"})
        # D5 step 4: listener liveness (the sim's probe pattern,
        # pointed at the real in-ns addresses).
        missing = []
        try:
            s = socket.create_connection(self.proxy_addr, timeout=3.0)
            s.close()
        except OSError:
            missing.append("proxy unreachable %s:%d" % self.proxy_addr)
        if dns_query(self.dns_addr[0], self.dns_addr[1],
                     self.probe_name, timeout=3.0) is None:
            missing.append("dns probe failed %s:%d" % self.dns_addr)
        if missing:
            return WallStateReport(WALL_DEGRADED, {"missing": missing})
        return WallStateReport(
            WALL_UP, {"netns": self.netns_name,
                      "proxy": "%s:%d" % self.proxy_addr,
                      "dns": "%s:%d" % self.dns_addr})

    def wrap_argv(self, argv):
        # D2/D3: netns entry (host-privileged `ip`), then the pinned
        # seccomp helper installs the BPF filter, then execs the agent
        # argv — the filter lands after namespace entry (the child
        # cannot unshare/setns its way out) and before exec (the agent
        # runs filtered from its first instruction).
        if not self.helper_path:
            raise EgressLaunchRefused(
                "helper_not_configured: NetnsWallProvider needs the "
                "installed seccomp-helper path (refusing fail-closed)")
        return ([self.ip_path, "netns", "exec", self.netns_name,
                 self.helper_path] + [str(a) for a in argv])

    def describe(self):
        return {"provider": "NetnsWallProvider",
                "netns": self.netns_name,
                "ip": self.ip_path,
                "helper": self.helper_path}

    def child_env_extra(self):
        # Story 13: the child sees the in-namespace proxy endpoint.
        return {"EGRESS_PROXY_ADDR": "%s:%d" % self.proxy_addr,
                "EGRESS_DNS_ADDR": "%s:%d" % self.dns_addr}


class SimulatedWallFixture:
    """Context manager: starts stub DNS + proxy + origin, writes
    endpoints.json and wall_up.flag. Yields self."""

    def __init__(self, sim_dir, inventory=None, origin_body=b"ok\n"):
        self.sim_dir = os.path.abspath(sim_dir)
        self.inventory = inventory
        self.origin_body = origin_body
        self.dns = None
        self.proxy = None
        self._origin_sock = None
        self._origin_thread = None
        self._origin_stop = threading.Event()
        self.proxy_port = None
        self.dns_port = None

    def __enter__(self):
        return self.start_fixed()

    def __exit__(self, *exc):
        self._origin_stop.set()
        for srv in (self.dns, self.proxy):
            if srv is not None:
                srv.stop()
        if self._origin_sock is not None:
            try:
                self._origin_sock.close()
            except OSError:
                pass
        # Same accept()-holds-the-port reason as StubDnsServer.stop:
        # join the origin thread so the port is deterministically free.
        if self._origin_thread is not None:
            self._origin_thread.join(timeout=5)
            self._origin_thread = None
        flag = os.path.join(self.sim_dir, "run", "wall_up.flag")
        try:
            os.remove(flag)
        except OSError:
            pass
        return False

    # -- the port problem, solved honestly ---------------------------
    # DNS maps names -> IPs, not ports; the allowlist pins host:port.
    # For the sim the origin MUST listen on the allowlisted port, so the
    # fixture binds fixed loopback ports chosen from a private range and
    # retries on collision. The pinned nft_state uses symbolic
    # wall:proxy / wall:dns names resolved via endpoints.json, so fixed
    # ports do not churn digests.

    FIXED_PROXY_PORT = 18443
    FIXED_DNS_PORT = 15353
    FIXED_ORIGIN_PORT = 18080

    def start_fixed(self):
        """Bind stubs on fixed ports; write endpoints.json + flag."""
        zone_path = os.path.join(self.sim_dir, "conf", "dns_hosts.txt")
        allow_path = os.path.join(self.sim_dir, "conf", "allowlist.txt")

        # DNS (TCP) fixed bind.
        dns = StubDnsServer.__new__(StubDnsServer)
        threading.Thread.__init__(dns, daemon=True)
        dns.zone_path = zone_path
        dns.log_path = os.path.join(self.sim_dir, "dns.log")
        dns._stop_event = threading.Event()
        for p in range(self.FIXED_DNS_PORT, self.FIXED_DNS_PORT + 50):
            try:
                dns._sock = socket.socket(socket.AF_INET,
                                          socket.SOCK_STREAM)
                dns._sock.setsockopt(socket.SOL_SOCKET,
                                     socket.SO_REUSEADDR, 1)
                dns._sock.bind((SIM_DNS_HOST, p))
                dns._sock.listen(32)
                dns.port = p
                break
            except OSError:
                continue
        else:
            raise RuntimeError("no free DNS port")
        dns.start()
        self.dns = dns

        # Origin on the allowlisted port (example.com:443 -> here is
        # impossible unprivileged; the sim allowlist uses :18080).
        allow_path_fixed = allow_path
        with open(allow_path_fixed, "w", encoding="utf-8") as f:
            f.write("# the entire outside world (sim)\n"
                    "example.com:%d\n" % self.FIXED_ORIGIN_PORT)
        # NOTE: rewriting the allowlist AFTER install changes its
        # digest -> the fixture re-pins (install-time action, operator).
        # See SimulatedWallFixture.repin_allowlist.
        self._origin_stop = threading.Event()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((SIM_PROXY_HOST, self.FIXED_ORIGIN_PORT))
        srv.listen(16)
        self._origin_sock = srv

        def serve():
            srv.settimeout(0.2)
            body = self.origin_body
            while not self._origin_stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    c.settimeout(3.0)
                    c.recv(65536)
                    c.sendall(b"HTTP/1.0 200 ok\r\nContent-Length: "
                              + str(len(body)).encode("ascii") + b"\r\n\r\n"
                              + body)
                except OSError:
                    pass
                finally:
                    c.close()

        self._origin_thread = threading.Thread(target=serve, daemon=True)
        self._origin_thread.start()

        # Proxy on a fixed port.
        proxy = StubProxyServer.__new__(StubProxyServer)
        threading.Thread.__init__(proxy, daemon=True)
        proxy.allowlist_path = allow_path
        proxy.dns_host = SIM_DNS_HOST
        proxy.dns_port = dns.port
        proxy.deny_log_path = os.path.join(self.sim_dir,
                                           "proxy_deny.log")
        proxy._stop_event = threading.Event()
        for p in range(self.FIXED_PROXY_PORT, self.FIXED_PROXY_PORT + 50):
            try:
                proxy._sock = socket.socket(socket.AF_INET,
                                            socket.SOCK_STREAM)
                proxy._sock.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_REUSEADDR, 1)
                proxy._sock.bind((SIM_PROXY_HOST, p))
                proxy.port = p
                proxy._sock.listen(64)
                break
            except OSError:
                continue
        else:
            raise RuntimeError("no free proxy port")
        proxy.start()
        self.proxy = proxy

        with open(os.path.join(self.sim_dir, "endpoints.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"proxy": [SIM_PROXY_HOST, proxy.port],
                       "dns": [SIM_DNS_HOST, dns.port],
                       "origin": [SIM_PROXY_HOST,
                                  self.FIXED_ORIGIN_PORT]}, f)
        with open(os.path.join(self.sim_dir, "run", "wall_up.flag"),
                  "w", encoding="utf-8") as f:
            f.write("up\n")
        self.proxy_port = proxy.port
        self.dns_port = dns.port
        return self

    def provider(self):
        return SimulatedWallProvider(self.sim_dir, self.inventory)

    def packet_filter(self):
        with open(os.path.join(self.sim_dir, "run", "nft_state.txt"),
                  encoding="utf-8") as f:
            rules = f.read()
        with open(os.path.join(self.sim_dir, "endpoints.json"),
                  encoding="utf-8") as f:
            eps = json.load(f)
        return FakePacketFilter(rules, eps)


def repin_after_fixture_fixup(sim_dir, *, algos=DEFAULT_ALGOS, trust=None,
                              operator_signers=None, tier="dev"):
    """Re-pin the manifest after the fixture rewrites the allowlist to
    the bound origin port. This is an INSTALL-TIME operator action (the
    allowlist content is deployment data); the battery calls it once
    per fresh sim dir before any launch, so digest verification still
    covers every later tamper.

    F138: the re-pin is authorized by a roster-human Ed25519 authorship
    token and appended to the chained pin ledger — same operator-signing
    flow as install_simulated_wall (ephemeral sim operator unless the
    caller supplies trust/signers)."""
    sim_dir = os.path.abspath(sim_dir)
    conf = os.path.join(sim_dir, "conf")
    manifest_path = os.path.join(sim_dir, "wall_pins.json")
    receipt_path = os.path.join(sim_dir, "wall_receipt.json")
    ledger_path = _default_ledger_path(manifest_path)
    trust, signers = _operator_roster(trust, operator_signers, tier)
    component_paths = {
        "nft_ruleset": os.path.join(conf, "agent0.nft.sim"),
        "proxy_allowlist": os.path.join(conf, "allowlist.txt"),
        "dns_config": os.path.join(conf, "dns_config.txt"),
        "dns_zone": os.path.join(conf, "dns_hosts.txt"),
        "proxy_impl": os.path.join(conf, "proxy_impl.txt"),
        "seccomp_config": os.path.join(conf, "seccomp_config.txt"),
        "seccomp_helper": os.path.join(conf, "run_seccomp.py")}
    prop = WallComponentInventory.proposal(
        component_paths, manifest_path, algos=algos, tier=tier,
        ledger_path=ledger_path)
    sigs = [s.sign(prop["body"]).hex() for s in signers]
    kids = [s.key_id for s in signers]
    WallComponentInventory.install(
        component_paths, manifest_path, receipt_path, algos=algos,
        trust=trust, author_key_id=kids[0], authorship_sig_hex=sigs[0],
        ts=prop["ts"], tier=tier,
        second_author_key_id=kids[1] if len(kids) > 1 else None,
        second_authorship_sig_hex=sigs[1] if len(sigs) > 1 else None,
        ledger_path=ledger_path)
    return WallComponentInventory(manifest_path, receipt_path,
                                  trust=trust, ledger_path=ledger_path)


# ---------------------------------------------------------------------------
# The launcher.
# ---------------------------------------------------------------------------

class FilteredEgressLauncher:
    """Spawn processes behind the filtered-egress wall, fail-closed.

    Every launch: take the interprocess lock -> verify receipt ->
    manifest -> components -> wall state UP -> spawn with child-side
    preexec re-assert + scrubbed env. Any step failing raises
    EgressLaunchRefused and (when audit is set) chains a refusal event.
    """

    def __init__(self, *, manifest_path, receipt_path, wall_provider,
                 audit=None, lock_path=None,
                 supported_algos=DEFAULT_ALGOS, trust=None,
                 ledger_path=None):
        self.inventory = WallComponentInventory(
            manifest_path, receipt_path,
            supported_algos=supported_algos, trust=trust,
            ledger_path=ledger_path)
        self.wall = wall_provider
        self.audit = audit
        self.lock_path = (lock_path or str(manifest_path) + ".lock")
        self._wall_id = self._read_wall_id(manifest_path)

    @staticmethod
    def _read_wall_id(manifest_path):
        try:
            sib = os.path.join(os.path.dirname(os.path.abspath(
                manifest_path)), "wall_id.txt")
            with open(sib, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return "unknown"

    # -- audit -------------------------------------------------------
    def _emit(self, event):
        if self.audit is None:
            return
        try:
            self.audit(event)
        except Exception:
            pass  # audit failure must not open the wall; the
            # refusal/launch already happened — fail-closed stands.

    # -- verify (no spawn) -------------------------------------------
    def verify(self):
        """Run the receipt->manifest->components chain. Returns
        (manifest, checked). Raises EgressLaunchRefused."""
        return self.inventory.verify()

    # -- launch ------------------------------------------------------
    def _child_env(self, extra):
        env = {}
        if extra:
            env.update(extra)
        for name in _PROXY_ENV_NAMES:
            env.pop(name, None)
        env.update(self.wall.child_env_extra())
        env[WALL_ACTIVE_ENV] = "1"
        env[WALL_ID_ENV] = self._wall_id
        return env

    def _preexec(self, chain=(), _status_w=None):
        """Child preexec: wall re-check first, then the embedder chain.

        The re-check runs before the chain so a fault-injected wall
        death aborts before any embedder hardening; the chain (e.g. a
        sandbox's rlimit/pivot/pidns setup) runs after, still before
        exec. Chain entries are nullary callables; a chain failure
        aborts the child loudly (exit 98, PREEXEC_CHAIN_ABORT_CODE --
        distinct from the re-check abort's 99, F149) -- nothing
        ungoverned runs. Embedders whose chain execs (rather
        than returning) must place their exec inside the chain: the
        re-check cannot run after a chain entry that never returns.

        ``_status_w`` (F148): when the launcher spawns via launch(),
        this is the write end of a status pipe. The child writes a
        single ack byte here immediately AFTER the re-check passes
        (before the chain), so the parent's ``egress_wall_launch``
        audit event is a WITNESSED fact -- the child really was
        placed behind a live wall -- not a prediction made at fork
        time. The ack is placed before the chain deliberately: some
        embedder chains never return (the sandbox pidns intermediate
        waitpids and _exits by design), so a post-chain ack could
        never be written on those paths; the chain's own status
        reporting (e.g. the sandbox's 5-byte marker) remains the
        chain's audit responsibility. Best-effort: a failed write
        never aborts the launch -- the parent treats a missing ack
        as a refusal (fail closed on the parent's side).
        """
        provider = self.wall
        chain = tuple(chain)

        def _child():
            try:
                provider.child_recheck()
            except Exception as e:  # noqa: BLE001 - child must die
                # loud, on any re-assert failure, before exec.
                try:
                    os.write(2, ("EGRESS-WALL preexec abort: %s\n"
                                 % e).encode("utf-8", "replace"))
                except OSError:
                    pass
                os._exit(PREEXEC_ABORT_CODE)
            if _status_w is not None:
                # F148: witness the re-check for the parent's audit.
                # Written BEFORE the chain (see docstring). Best
                # effort -- never aborts the launch; close the fd so
                # it cannot leak into the exec'd program.
                try:
                    os.write(_status_w, b"\x01")
                except OSError:
                    pass
                try:
                    os.close(_status_w)
                except OSError:
                    pass
            for fn in chain:
                try:
                    fn()
                except Exception as e:  # noqa: BLE001 - child must die
                    # F149: chain failure exits 98 (PREEXEC_CHAIN_ABORT_CODE),
                    # distinct from the re-check abort (99): the re-check
                    # passed (the ack was already written); the embedder
                    # chain broke. Nothing ungoverned runs.
                    try:
                        os.write(2, ("EGRESS-WALL preexec chain abort: "
                                     "%s\n"
                                     % e).encode("utf-8", "replace"))
                    except OSError:
                        pass
                    os._exit(PREEXEC_CHAIN_ABORT_CODE)
        return _child

    @staticmethod
    def _read_preexec_ack(status_r):
        """Read the child's preexec ack byte (F148), deadline-bounded.

        Returns True iff the child wrote the ack (its wall re-check
        passed). EOF means the child died in preexec before
        reporting; timeout means it hung. Both are "not witnessed".
        """
        deadline = time.monotonic() + _PREEXEC_ACK_TIMEOUT_S
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None  # hung: distinct from EOF
            rlist, _, _ = select.select([status_r], [], [], remaining)
            if not rlist:
                return None  # hung: distinct from EOF
            try:
                chunk = os.read(status_r, 1)
            except OSError:
                return False
            if not chunk:
                return False  # EOF: child died before the ack
            if chunk == b"\x01":
                return True
            # Any other byte is not the ack; keep waiting for EOF or
            # the deadline rather than misreading it.

    def _wall_proof(self):
        """(manifest_sha256, receipt_sha256, pin_record_sha256) over
        the install
        verify() just checked. Reads the exact bytes the receipt pins,
        so the launch audit binds the wall proof an auditor can
        re-verify offline. Unreadable proof -> fail closed."""
        try:
            with open(self.inventory.manifest_path, "rb") as f:
                manifest_blob = f.read()
            with open(self.inventory.receipt_path, "rb") as f:
                receipt_blob = f.read()
        except OSError as e:
            raise EgressLaunchRefused(
                "wall_proof_unreadable: %s" % e)
        manifest = json.loads(manifest_blob.decode("utf-8"))
        pin_record_sha256 = (manifest.get("pin_record") or {}).get(
            "record_sha256")
        return (_digest_bytes(manifest_blob, "sha256"),
                _digest_bytes(receipt_blob, "sha256"),
                pin_record_sha256)

    def launch(self, argv, *, env=None, agent_id=None, principal=None,
               run_id=None, preexec_chain=(), **popen_kw):
        """Spawn argv behind the wall. Returns the Popen object.

        Raises EgressLaunchRefused (fail-closed) instead of spawning
        whenever the wall cannot be verified.

        F148: the ``egress_wall_launch`` audit event is witnessed, not
        predicted -- it is emitted only after the child's preexec ack
        byte arrives (the child-side wall re-check passed). A child
        that dies or hangs in preexec is refused (and killed) with no
        launch event; the refusal carries a named reason
        (``preexec_recheck_failed`` / ``preexec_recheck_timeout`` /
        ``preexec_child_died``).

        F149: the ack attests the re-check, not the embedder chain.
        After the ack, launch() observes the child for a short grace
        (``_POST_ACK_CHAIN_GRACE_S``): a chain-entry failure (child
        exit 98, ``PREEXEC_CHAIN_ABORT_CODE``) refuses truthfully with
        ``preexec_chain_failed`` -- no launch event, fail-closed. A
        chain that fails after the grace still yields a launch event
        (the parent cannot distinguish a slow chain from an exec'd
        child); ``run_child()`` then reports the truthful
        ``preexec_chain_failed`` refusal when it reaps the 98.

        The provider's wrap_argv() places the child in the wall
        (identity for the sim; ``ip netns exec agent0 <helper>``
        for the production provider). agent_id / principal / run_id
        are optional identity bindings recorded on the launch audit
        event (nulls stay visible, never omitted). ``preexec_chain``
        is a tuple of nullary callables an embedder (e.g.
        gov/sandbox.py) wants run in the child after the wall
        re-check, before exec; a chain failure aborts the child (exit
        98, ``PREEXEC_CHAIN_ABORT_CODE``) -- F149: launch() refuses
        truthfully (``preexec_chain_failed``) with no launch event if
        the failure lands within the post-ack grace, and
        ``run_child()`` reports it truthfully if it lands later.
        Remaining ``popen_kw`` go to
        Popen (env and preexec_fn are owned by the launcher).
        """
        lock_fh = open(self.lock_path, "a+b")
        try:
            try:
                fcntl.flock(lock_fh.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": "lock_unavailable",
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused("lock_unavailable: another "
                                          "launch holds the wall lock")
            # 1. component chain, under the lock.
            try:
                manifest, checked = self.inventory.verify()
            except EgressLaunchRefused as e:
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": str(e).split(":")[0],
                            "detail": str(e),
                            "wall_id": self._wall_id})
                raise
            # 1b. wall proof for the audit event (fail-closed: the
            # launch is only auditable if the proof is readable).
            try:
                manifest_sha256, receipt_sha256, pin_record_sha256 = \
                    self._wall_proof()
            except EgressLaunchRefused as e:
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": str(e).split(":")[0],
                            "detail": str(e),
                            "wall_id": self._wall_id})
                raise
            # 2. wall state.
            report = self.wall.check()
            if not report.ok():
                reason = ("wall_not_up" if report.state == WALL_DOWN
                          else "wall_degraded")
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": reason,
                            "wall_state": report.state,
                            "wall_detail": report.detail,
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused(
                    "%s: %r" % (reason, report.detail))
            # 2b. provider spawn prefix (fail-closed: a provider that
            # cannot place the child in the wall refuses here, before
            # any spawn).
            try:
                spawn_argv = self.wall.wrap_argv(argv)
            except EgressLaunchRefused as e:
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": str(e).split(":")[0],
                            "detail": str(e),
                            "wall_id": self._wall_id})
                raise
            # 3. spawn with child-side re-assert. F148: the
            # egress_wall_launch event is WITNESSED, not predicted --
            # it is emitted only after the child's preexec ack byte
            # arrives (the child's wall re-check passed). A child
            # that dies in preexec (wall flapped between the parent
            # check and fork) yields EOF -> refusal, never a launch
            # event; a hung child is killed and refused (fail closed).
            status_r, status_w = os.pipe()
            popen_kw = dict(popen_kw)
            popen_kw["env"] = self._child_env(env)
            popen_kw["preexec_fn"] = self._preexec(
                chain=preexec_chain, _status_w=status_w)
            popen_kw["pass_fds"] = (tuple(popen_kw.get("pass_fds", ()))
                                    + (status_w,))
            try:
                proc = subprocess.Popen(spawn_argv, **popen_kw)
            except OSError as e:
                os.close(status_r)
                os.close(status_w)
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": "spawn_failed",
                            "detail": str(e),
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused("spawn_failed: %s" % e)
            # Parent never writes: with our copy closed, the child's
            # death closes the last write end and the read sees EOF.
            os.close(status_w)
            try:
                witnessed = self._read_preexec_ack(status_r)
            finally:
                os.close(status_r)
            if witnessed:
                # Ack received: the child's wall re-check passed. F149:
                # the ack attests the re-check, NOT the embedder chain
                # (which runs after the ack). Popen.__init__ blocks
                # until preexec completes, but returns on error-pipe
                # EOF which can race the child's actual exit: wait
                # briefly for a 98 (chain-failed) exit. A 98 means a
                # chain entry failed -- refuse truthfully with no
                # launch event (fail-closed, mirroring the pre-ack EOF
                # path). Timeout (child alive: it exec'd) or any other
                # exit code gets the witnessed launch event below.
                try:
                    chain_rc = proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    chain_rc = None  # alive: chain done, exec'd
                if chain_rc == PREEXEC_CHAIN_ABORT_CODE:
                    self._emit({"event": "egress_wall_launch_refused",
                                "reason": "preexec_chain_failed",
                                "detail": ("embedder preexec_chain entry "
                                           "failed after the wall "
                                           "re-check passed; child "
                                           "aborted before exec "
                                           "(exit 98)"),
                                "wall_id": self._wall_id})
                    raise EgressLaunchRefused(
                        "preexec_chain_failed: embedder preexec_chain "
                        "entry failed after the wall re-check passed; "
                        "child aborted before exec")
                # Fall through to the witnessed launch event below.
            elif witnessed is None:
                # Truly hung in preexec: no ack and no EOF within the
                # deadline. Kill it; nothing was exec'd (the ack is
                # written before the chain, so the chain never ran
                # without the re-check passing first).
                try:
                    proc.kill()
                except OSError:
                    pass
                proc.wait()
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": "preexec_recheck_timeout",
                            "detail": ("no preexec ack within %ss; child "
                                       "killed before exec"
                                       % _PREEXEC_ACK_TIMEOUT_S),
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused(
                    "preexec_recheck_timeout: no preexec ack within %ss; "
                    "child killed before exec" % _PREEXEC_ACK_TIMEOUT_S)
            else:
                # EOF before the ack: the child died in preexec. Reap
                # with a grace -- a single poll() can return None
                # while the child is mid-_exit (fds already closed,
                # not yet a zombie) and would misreport a clean abort
                # as a hang.
                try:
                    rc = proc.wait(timeout=_PREEXEC_REAP_GRACE_S)
                except subprocess.TimeoutExpired:
                    # Fds closed but the process will not die: kill
                    # it and record the anomaly.
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    rc = proc.wait()
                if rc == PREEXEC_ABORT_CODE:
                    reason = "preexec_recheck_failed"
                    detail = ("wall died between check and spawn; child "
                              "aborted before exec")
                else:
                    reason = "preexec_child_died"
                    detail = ("child died in preexec (exit %r) before "
                              "the ack; wall re-check not witnessed"
                              % (rc,))
                self._emit({"event": "egress_wall_launch_refused",
                            "reason": reason,
                            "detail": detail,
                            "wall_id": self._wall_id})
                raise EgressLaunchRefused("%s: %s" % (reason, detail))
            self._emit({"event": "egress_wall_launch",
                        "argv0": os.path.basename(str(argv[0])),
                        "spawn_argv0": os.path.basename(
                            str(spawn_argv[0])),
                        "provider": self.wall.describe(),
                        "wall_state": report.state,
                        "components": sorted(checked),
                        "wall_id": self._wall_id,
                        "agent_id": agent_id,
                        "principal": principal,
                        "run_id": run_id,
                        "manifest_sha256": manifest_sha256,
                        "receipt_sha256": receipt_sha256,
                        "pin_record_sha256": pin_record_sha256})
            return proc
        finally:
            try:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            lock_fh.close()

    def run_child(self, argv, *, env=None, agent_id=None, principal=None,
                  run_id=None, **popen_kw):
        """launch() then wait; maps preexec-abort exits to
        EgressLaunchRefused so callers can treat a mid-launch wall
        death or chain failure as a refusal, not a crash.
        ``capture_output=True`` is honored (translated to pipes for
        Popen).

        F149: launch() only returns a proc after the child's preexec
        ack (the wall re-check passed), so any preexec abort observed
        here is a CHAIN failure, never a re-check failure. Exit 98
        (``PREEXEC_CHAIN_ABORT_CODE``) maps to the truthful
        ``preexec_chain_failed`` -- run_child() never mislabels it
        ``preexec_recheck_failed``. (Exit 99 here is unreachable via
        launch(), which raises on pre-ack re-check failure; it is
        still mapped defensively.)
        """
        popen_kw = dict(popen_kw)
        capture = popen_kw.pop("capture_output", False)
        text = popen_kw.pop("text", False)
        if capture:
            popen_kw["stdout"] = subprocess.PIPE
            popen_kw["stderr"] = subprocess.PIPE
        if text:
            popen_kw["text"] = True
        proc = self.launch(argv, env=env, agent_id=agent_id,
                           principal=principal, run_id=run_id,
                           **popen_kw)
        if capture:
            out, err = proc.communicate(timeout=30)
            rc = proc.returncode
        else:
            rc = proc.wait()
            out = err = None
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:
                pass
        if rc == PREEXEC_CHAIN_ABORT_CODE:
            self._emit({"event": "egress_wall_launch_refused",
                        "reason": "preexec_chain_failed",
                        "detail": ("embedder preexec_chain entry failed; "
                                   "child aborted before exec (exit 98)"),
                        "wall_id": self._wall_id})
            raise EgressLaunchRefused(
                "preexec_chain_failed: embedder preexec_chain entry "
                "failed; child aborted before exec")
        if rc == PREEXEC_ABORT_CODE:
            # Unreachable via launch() (pre-ack re-check failure
            # raises there); kept so a 99 observed by any other path
            # still refuses fail-closed.
            self._emit({"event": "egress_wall_launch_refused",
                        "reason": "preexec_recheck_failed",
                        "wall_id": self._wall_id})
            raise EgressLaunchRefused(
                "preexec_recheck_failed: wall died between check and "
                "spawn; child aborted before exec")
        cp = subprocess.CompletedProcess(argv, rc, out, err)
        return cp

    # -- integration helper ------------------------------------------
    def popen_kwargs(self, env=None):
        """Env + preexec for embedding in another spawner (e.g.
        gov/sandbox.py's Popen call). The caller MUST still run
        verify()+check() first — this helper does not verify."""
        return {"env": self._child_env(env),
                "preexec_fn": self._preexec()}
