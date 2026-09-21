"""Per-principal egress ledger: tamper-evident cross-run record of outbound
``api_call`` shapes (F10).

Per-run guards cannot see a low-and-slow campaign: three fresh runs, each
sending one innocent-looking credential fragment, are each individually
clean. This ledger gives the engine content-aware cross-run memory: every
``api_call`` attempt that passes DLP is recorded (endpoint, param
count/size/entropy bucket, timestamp, principal, run) in a hash-chained
JSONL file — the same tamper-evidence pattern as the action log
(``gov/log.py``), minus the HMAC key (the ledger is a heuristic signal,
not an authorization artifact; a forged ledger entry can only cause a
spurious approval QUEUE, never an execution).

The ledger lives NEXT TO the runs directory (e.g. ``runs/``), shared by
all runs of a deployment; the path is configurable and tests point it at
temp dirs. A deployment that wants no cross-run memory can point it at a
per-run path (the test harness default).

The campaign rule itself is heuristic and FAIL-SAFE: K small
high-entropy-ish fragments to the SAME registered domain from the SAME
principal across >= 2 distinct runs within a time window ->
``require_approval`` (flag ``cross_run_campaign``). It never denies. See
``ToolExecutor._check_cross_run_campaign`` for the thresholds.

F13: the campaign KEY normalizes the endpoint to its registered domain
(last two hostname labels), so subdomain rotation
(shard0/shard1/shard2.collector.example) lands in ONE bucket. The exact
endpoint string stays in the ledger record for forensics.

F14: a STRUCTURAL campaign signal sits alongside the fragment-shape
signal: same principal + same registered domain + same param KEY SET
across >= K distinct runs inside the window -> ``require_approval``
(flag ``structural_campaign``), regardless of payload size or entropy.
Thin-spread only: a run that repeats the structure K+ times in one run
is bursty repetition (the loop guard's territory), not low-and-slow.

F15: principal-scoped sensitive-read taint. A ``sensitive_read`` entry
records that a principal's run ingested DLP-sensitive content; a fresh
executor for the SAME principal inherits the taint while the mark is
unexpired (24h TTL). Different principals never share taint.

F17 (Round 5): the ledger is now a first-class authenticated record, not
an unkeyed chain. Every entry carries an HMAC computed with the SAME
key epochs as the action log (``GOV_LOG_KEY`` / ``GOV_LOG_KEY_ARCHIVE`` /
the dev key; see ``gov/log.py``), plus a sequence number, and every
append writes an HMAC'd checkpoint to a sidecar file
(``<ledger>.checkpoints``). All reads verify before trusting: a tampered
or truncated ledger raises ``LedgerUnverifiableError`` instead of
silently dropping taint — the old behavior failed open, so trimming the
last taint mark defeated the cross-run control. The executor verifies
the ledger at the top of every ``call()`` and refuses to proceed when
it cannot verify. Residuals: (a) if the checkpoint sidecar AND the
ledger are both replaced with a self-consistent forgery the verifier
cannot tell — same trust boundary as the action log; (b) entries written
by pre-Round-5 builds have no MAC and do not verify (fail-closed:
start a fresh ledger); (c) fresh-principal rotation remains a deployment
trust boundary — see ``gov/identity.py`` ``PrincipalRegistry``.

F20 (Round 5): ``registered_domain`` no longer uses the naive
last-two-labels heuristic. IP literals are returned unchanged (never
bucketed), and a built-in common multi-label public-suffix table keeps
one registrable label above known suffixes (``evil.co.uk`` and
``good.co.uk`` are different tenants again). The table is intentionally
small — not a full public-suffix list — and rotating the registered
domain itself still evades (F13 residual).
"""

import hashlib
import hmac
import ipaddress
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from . import log as _logmod

_LEDGER_VERSION = 1
_GENESIS_HASH = "0" * 64

# Campaign thresholds (see _check_cross_run_campaign in gov/executor.py).
# A "fragment" is a small, information-dense payload: total string param
# bytes <= _FRAGMENT_MAX_BYTES with at least one string value at
# _FRAGMENT_MIN_ENTROPY bits/char. K fragments from >= 2 distinct runs to
# the same registered domain within the window queue the K-th attempt.
FRAGMENT_MAX_BYTES = 64
FRAGMENT_MIN_ENTROPY = 1.8
CAMPAIGN_K = 3
CAMPAIGN_WINDOW_SECS = 24 * 3600

# F15: how long a principal-scoped sensitive-read mark keeps fresh runs
# of the same principal tainted. Documented, not tuned: long enough to
# cover a confederate two-hop inside one operator session, short enough
# that a stale mark cannot taint the principal forever. Out-of-band
# exfil the engine never sees is still out of scope.
SENSITIVE_TAINT_TTL_SECS = 24 * 3600

# Common multi-label public suffixes (F20). Intentionally small — a
# deployment that needs full coverage should vendor the public suffix
# list; this table only stops the naive last-two-labels heuristic from
# merging unrelated tenants (evil.co.uk vs good.co.uk -> co.uk). IP
# literals are handled separately in registered_domain (never bucketed).
_PUBLIC_SUFFIXES = frozenset(
    """
    co.uk org.uk me.uk net.uk sch.uk ac.uk gov.uk nhs.uk police.uk
    com.au net.au org.au asn.au id.au edu.au gov.au
    co.jp or.jp ne.jp ac.jp go.jp ad.jp
    co.in net.in org.in firm.in gen.in ind.in gov.in ac.in edu.in nic.in
    com.br net.br org.br gov.br edu.br
    co.kr or.kr ne.kr go.kr ac.kr
    co.nz net.nz org.nz govt.nz ac.nz
    com.cn net.cn org.cn gov.cn edu.cn
    com.sg net.sg org.sg edu.sg gov.sg
    com.hk net.hk org.hk edu.hk gov.hk idv.hk
    com.tw net.tw org.tw idv.tw
    co.za net.za org.za gov.za ac.za
    com.mx net.mx org.mx edu.mx gob.mx
    com.ar net.ar org.ar gov.ar edu.ar int.ar
    com.tr net.tr org.tr gov.tr edu.tr
    com.pl net.pl org.pl edu.pl gov.pl
    co.il org.il net.il ac.il gov.il
    com.ph net.ph org.ph edu.ph gov.ph
    com.my net.my org.my edu.my gov.my
    com.vn net.vn org.vn edu.vn gov.vn
    co.th or.th go.th ac.th net.th in.th
    com.eg net.eg org.eg edu.eg gov.eg
    """.split()
)


def registered_domain(endpoint):
    """Registered domain of an endpoint URL (F13/F20 campaign key).

    F20 hardened: IP literals are returned unchanged (``10.0.0.1`` stays
    ``10.0.0.1`` — never bucketed with anything else), and hosts under a
    known multi-label public suffix keep one registrable label above the
    suffix (``a.example.co.uk`` -> ``example.co.uk``; ``evil.co.uk`` and
    ``good.co.uk`` are different tenants). Anything else falls back to
    the last two labels, so ``shard0.collector.example`` and
    ``shard1.collector.example`` both key as ``collector.example``. A bare
    public suffix (or a host with fewer than two labels) passes through
    unchanged. Only the campaign KEY normalizes; the exact endpoint
    string stays in the ledger record for forensics. Residual: the
    built-in suffix table is small, not a full public-suffix list.
    """
    try:
        host = (urlparse(endpoint or "").hostname or "")
    except Exception:
        host = ""
    host = host.strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host  # IP literal: its own bucket, never merged.
    except ValueError:
        pass
    labels = host.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in _PUBLIC_SUFFIXES:
            if i == 0:
                return host  # the host IS a public suffix
            return ".".join(labels[i - 1 :])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


class LedgerUnverifiableError(Exception):
    """Raised when the egress ledger cannot be authenticated.

    F17 fail-closed: callers must treat an unverifiable ledger as taint
    ACTIVE (or refuse the action), never as "no taint". The executor
    raises this from ``call()`` before any policy evaluation when the
    ledger is corrupt, forged, or truncated past its newest checkpoint.
    """


def _ledger_keyring():
    """{key_epoch: key_bytes}: active key plus archived epochs.

    F17: the SAME key epochs as the action log (``gov/log.py``) —
    ``GOV_LOG_KEY`` / ``GOV_LOG_KEY_ARCHIVE``, falling back to the public
    dev key. Verification therefore survives the same rotations the
    action log does.
    """
    key, epoch = _logmod._active_key()
    keys = {epoch: key}
    archive = os.environ.get("GOV_LOG_KEY_ARCHIVE")
    if archive:
        try:
            mapping = json.loads(archive)
        except ValueError:
            mapping = {}
        if isinstance(mapping, dict):
            for ep, kval in mapping.items():
                keys.setdefault(ep, str(kval).encode("utf-8"))
    return keys


def _ledger_mac(key, key_epoch, prev_hash, canonical):
    """HMAC over one ledger entry (domain-separated from the action log)."""
    return hmac.new(
        key,
        ("ledger|%s|%s|%s" % (key_epoch, prev_hash, canonical)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _checkpoint_mac(key, key_epoch, seq, entry_hash):
    """HMAC over one checkpoint record."""
    return hmac.new(
        key,
        ("ledger-checkpoint|%s|%d|%s" % (key_epoch, seq, entry_hash)).encode(
            "utf-8"
        ),
        hashlib.sha256,
    ).hexdigest()


class EgressLedger:
    """Append-only HMAC-authenticated JSONL of outbound api_call shapes.

    F17: every entry is HMAC'd with the active ledger key epoch and
    carries a sequence number; every append writes an HMAC'd checkpoint
    to the ``<ledger>.checkpoints`` sidecar. All reads verify before
    trusting (``require_verified``): tampering or tail truncation raises
    ``LedgerUnverifiableError`` instead of silently dropping taint.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.checkpoint_path = Path(str(self.path) + ".checkpoints")
        self._seq, self._prev = self._tail_state()
        self._verified_sig = None  # (size, mtime_ns) of last good verify

    def _sig(self):
        """Stat signature of the ledger *and* its checkpoint sidecar.

        The trust unit is both files: deleting or replacing the
        sidecar without touching the data file must still invalidate
        the verification cache.
        """
        try:
            st = self.path.stat()
            data = (st.st_size, st.st_mtime_ns)
        except OSError:
            data = None
        try:
            cst = self.checkpoint_path.stat()
            sidecar = (cst.st_size, cst.st_mtime_ns)
        except OSError:
            sidecar = None
        return (data, sidecar)

    def _sig_valid(self):
        return self._sig() == self._verified_sig

    # -- authenticated chaining (F17) ----------------------------------

    def _tail_state(self):
        """(seq, entry_hash) of the last ledger entry, O(tail).

        Reads at most the last 8 KiB: ledger entries are bounded shape
        records (no payload values), so one entry always fits. A missing
        file is (0, genesis); an unparseable tail yields (0, genesis) but
        ``require_verified`` refuses the file before any append can fork
        the chain, so this fallback is unreachable for corrupt files.
        """
        seq, prev = 0, _GENESIS_HASH
        if not self.path.exists():
            return seq, prev
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 8192))
                tail = f.read().decode("utf-8", "replace")
        except OSError:
            return seq, prev
        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return seq, prev
        try:
            entry = json.loads(lines[-1])
            seq = int(entry.get("seq", 0))
            prev = entry.get("entry_hash") or prev
        except (ValueError, TypeError):
            pass
        return seq, prev

    def _read_checkpoints(self):
        """All parseable checkpoint records, oldest first."""
        out = []
        if not self.checkpoint_path.exists():
            return out
        try:
            text = self.checkpoint_path.read_text(encoding="utf-8")
        except OSError:
            return out
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                cp = json.loads(line)
            except ValueError:
                continue
            if isinstance(cp, dict) and isinstance(cp.get("seq"), int):
                out.append(cp)
        return out

    def _write_checkpoint(self, seq, entry_hash, key_epoch, end_offset, key):
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        cp = {
            "v": _LEDGER_VERSION,
            "seq": seq,
            "hash": entry_hash,
            "key_epoch": key_epoch,
            "end_offset": end_offset,
            "mac": _checkpoint_mac(key, key_epoch, seq, entry_hash),
        }
        with open(self.checkpoint_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(cp, sort_keys=True) + "\n")

    def append(self, shape):
        """Record one api_call shape; returns the chained record.

        F17: verifies the ledger BEFORE appending — a tampered ledger
        refuses new writes (fail-closed) — then HMACs the entry with the
        active key epoch and writes an HMAC'd checkpoint.
        """
        self.require_verified()
        key, epoch = _logmod._active_key()
        self._seq, self._prev = self._tail_state()
        seq = self._seq + 1
        body = dict(shape)
        body["v"] = _LEDGER_VERSION
        body["seq"] = seq
        body["key_epoch"] = epoch
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        mac = _ledger_mac(key, epoch, self._prev, canonical)
        entry_hash = hashlib.sha256(
            (self._prev + canonical).encode("utf-8")
        ).hexdigest()
        record = dict(body)
        record["prev_hash"] = self._prev
        record["entry_hash"] = entry_hash
        record["mac"] = mac
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
            f.flush()
            end_offset = f.tell()
        self._write_checkpoint(seq, entry_hash, epoch, end_offset, key)
        self._seq, self._prev = seq, entry_hash
        # We verified before writing and know exactly the bytes we
        # appended, so the new stat signature is known-good: the next
        # require_verified() stays O(1) without re-reading.
        self._verified_sig = self._sig()
        return record

    def require_verified(self):
        """Raise ``LedgerUnverifiableError`` unless the ledger verifies.

        F17 fail-closed reads. The executor calls this at the top of
        every ``call()``; the ledger's own readers (``taint_active``,
        ``fragments``, ``structural_campaign_hit``, ``append``) call it
        too. A missing ledger is vacuously fine (nothing to trust yet).
        Corruption, forgery, or truncation past the newest checkpoint all
        raise — the caller must then treat taint as ACTIVE or refuse the
        action, never as "no taint".

        Soundness: whenever the file's stat signature changed since the
        last successful verification, the ledger is re-verified from
        genesis (O(n)) — a checkpoint alone never vouches for bytes it
        did not re-read, so same-size modifications before the newest
        checkpoint cannot slip through. Unchanged files skip the
        re-read (O(1) stat). An attacker who can rewrite bytes AND
        restore the exact mtime_ns evades the cache; that is the
        documented residual of any mtime-based check.
        """
        if not self.path.exists():
            return
        sig = self._sig()
        if sig[0] is None:
            raise LedgerUnverifiableError("cannot stat ledger: %s"
                                          % (self.path,))
        if sig == self._verified_sig:
            return
        if not self._verify_full(_ledger_keyring()):
            raise LedgerUnverifiableError(
                "ledger verification failed for %s: the ledger was "
                "tampered with, forged, or truncated — treating taint "
                "as ACTIVE" % (self.path,)
            )
        self._verified_sig = sig

    def _verify_full(self, keys):
        """Full from-genesis authentication, O(n)."""
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return False
        prev = _GENESIS_HASH
        seq = 0
        hash_at_seq = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False
            seq += 1
            if entry.get("seq") != seq or entry.get("prev_hash") != prev:
                return False
            epoch = entry.get("key_epoch")
            key = keys.get(epoch)
            if key is None:
                return False
            body = {
                k: v
                for k, v in entry.items()
                if k not in ("prev_hash", "entry_hash", "mac")
            }
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            if not hmac.compare_digest(
                str(entry.get("mac") or ""), _ledger_mac(key, epoch, prev, canonical)
            ):
                return False
            # Unkeyed chain kept as defense-in-depth (as before F17).
            unkeyed = hashlib.sha256((prev + canonical).encode("utf-8")).hexdigest()
            if unkeyed != entry.get("entry_hash"):
                return False
            prev = entry["entry_hash"]
            hash_at_seq[seq] = prev
        # Checkpoints on disk must agree with the file they anchor:
        # a checkpoint ahead of the file, or disagreeing on the hash at
        # its seq, means the tail was trimmed.  The checkpoint sidecar is
        # the tail-truncation anchor: a non-empty ledger with NO sidecar
        # fails closed (deleted sidecar, or a crash between the entry
        # write and the checkpoint write in append()).
        cps = self._read_checkpoints()
        if seq > 0 and not cps:
            return False
        for cp in cps:
            epoch = cp.get("key_epoch")
            key = keys.get(epoch)
            if key is None:
                return False
            try:
                cseq = int(cp.get("seq"))
            except (TypeError, ValueError):
                return False
            if not hmac.compare_digest(
                str(cp.get("mac") or ""),
                _checkpoint_mac(key, epoch, cseq, str(cp.get("hash") or "")),
            ):
                return False
            if cseq > seq:
                return False
            if hash_at_seq.get(cseq) != cp.get("hash"):
                return False
        return True

    def verify(self):
        """True iff the whole ledger authenticates (O(n), from genesis).

        F17: checks every entry's HMAC (under its recorded key epoch),
        the unkeyed chain linkage, and the sequence numbers, then
        requires every checkpoint on disk to agree with the file. A
        missing ledger verifies True (nothing to distrust). Entries
        without a MAC (pre-Round-5 builds) do NOT verify — fail-closed;
        start a fresh ledger. A non-empty ledger whose checkpoint
        sidecar is missing also does NOT verify: the sidecar is the
        tail-truncation anchor, and its absence is treated as tampering.
        """
        if not self.path.exists():
            return True
        return self._verify_full(_ledger_keyring())

    # -- campaign query --------------------------------------------------

    @staticmethod
    def _entry_domain(entry):
        """Registered domain for one ledger entry (F13).

        New entries carry ``campaign_domain`` (written by
        ``ToolExecutor._api_call_shape``); older entries fall back to
        normalizing their exact ``endpoint`` string, so the rotation fix
        applies to history already on disk.
        """
        domain = entry.get("campaign_domain")
        if domain:
            return domain
        return registered_domain(entry.get("endpoint") or "")

    def fragments(self, principal, endpoint, window_secs=CAMPAIGN_WINDOW_SECS,
                  now=None):
        """Fragment-shaped entries for principal+endpoint inside the window.

        F13: the endpoint is normalized to its registered domain before
        keying, so ``shard0.collector.example`` and
        ``shard1.collector.example`` land in the SAME campaign bucket.
        """
        self.require_verified()  # F17: verify before trusting any read
        if not self.path.exists():
            return []
        now = time.time() if now is None else now
        domain = registered_domain(endpoint)
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if (entry.get("principal") == principal
                    and self._entry_domain(entry) == domain
                    and entry.get("fragment") is True
                    and now - float(entry.get("ts", 0)) <= window_secs):
                out.append(entry)
        return out

    def campaign_hit(self, principal, endpoint,
                     window_secs=CAMPAIGN_WINDOW_SECS, now=None,
                     k=CAMPAIGN_K):
        """True when >= k fragments from >= 2 distinct runs are in window.

        The K-th fragment (counting the just-recorded current attempt) is
        what queues. Requiring >= 2 distinct runs keeps single-run
        identical-call bursts (the loop guard's territory) out of this
        rule's reach. F13: keying is on the registered domain, not the
        exact endpoint string.
        """
        frags = self.fragments(principal, endpoint, window_secs, now)
        if len(frags) < k:
            return False
        return len({f.get("run_id") for f in frags}) >= 2

    def structural_campaign_hit(self, principal, domain, param_keys,
                                window_secs=CAMPAIGN_WINDOW_SECS, now=None,
                                k=CAMPAIGN_K):
        """F14: True when >= k api_call entries share (principal, domain,
        param_keys) across >= k distinct runs inside the window.

        The STRUCTURAL campaign signal: it does not look at payload size
        or entropy at all, so oversize padding and sub-entropy encodings
        (unary) still trip it — the attacks it was built for repeat the
        same call structure thinly across runs. A run counts only when
        it contributed FEWER than k matching calls: a single run that
        repeats the structure k+ times is bursty repetition (the loop
        guard's territory), not low-and-slow. Empty key sets never match
        (a param-less call carries no exfil payload). Heuristic,
        queue-only, fail-safe — same contract as campaign_hit.
        """
        self.require_verified()  # F17: verify before trusting any read
        if not self.path.exists():
            return False
        if not principal or not domain or not param_keys:
            return False
        now = time.time() if now is None else now
        wanted = sorted(param_keys)
        per_run = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("tool") != "api_call":
                continue
            if entry.get("principal") != principal:
                continue
            if self._entry_domain(entry) != domain:
                continue
            keys = entry.get("param_keys")
            if not keys or sorted(keys) != wanted:
                continue
            try:
                ts = float(entry.get("ts", 0))
            except (TypeError, ValueError):
                continue
            if now - ts > window_secs:
                continue
            run_id = entry.get("run_id")
            per_run.setdefault(run_id, 0)
            per_run[run_id] += 1
        thin_runs = [r for r, n in per_run.items() if n < k]
        return len(thin_runs) >= k

    # -- principal-scoped sensitive-read taint (F15) ------------------------

    def taint_mark(self, principal, run_id, now=None):
        """Persist a sensitive-read mark for *principal* (F15).

        Records that this principal's run ingested DLP-sensitive
        content. A fresh executor for the SAME principal inherits the
        taint while the mark is unexpired (see ``taint_active``);
        different principals never share taint. F17: the mark rides the
        HMAC-authenticated chain, so a forged mark is rejected by
        ``require_verified`` instead of being trusted.
        """
        if not principal:
            return None
        return self.append({
            "kind": "sensitive_read",
            "ts": time.time() if now is None else now,
            "principal": principal,
            "run_id": run_id,
        })

    def taint_active(self, principal, ttl_secs=SENSITIVE_TAINT_TTL_SECS,
                     now=None):
        """True when *principal* has an unexpired sensitive-read mark.

        F17: verifies the ledger first — a tampered ledger raises
        ``LedgerUnverifiableError`` instead of returning False, so a
        trimmed taint mark fails CLOSED, never open.
        """
        self.require_verified()  # F17: verify before trusting any read
        if not self.path.exists() or not principal:
            return False
        now = time.time() if now is None else now
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if (entry.get("kind") == "sensitive_read"
                    and entry.get("principal") == principal):
                try:
                    ts = float(entry.get("ts", 0))
                except (TypeError, ValueError):
                    continue
                if now - ts <= ttl_secs:
                    return True
        return False
