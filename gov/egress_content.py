"""Unlabeled-egress content analyzer (wave-132 lane).

Row-13 residual: 4 authorized-channel semantic-exfiltration BREAKs remain
for UNLABELED sources. The classification-label control (wave-128)
converts the shapes when the source is labeled; this module scores
outbound payloads for exfiltration risk WITHOUT relying on
classification labels.

Deterministic, $0, stdlib-only. Five signals:

1. ``structured`` — key:value / key=value lines, JSON/XML fragments,
   table rows. Weighted LOW: a benign status report looks like this
   too (the FP ceiling).
2. ``dump`` — RECORD REPETITION: >=3 JSON objects sharing an identical
   key set, or >=3 CSV-like rows with a stable field count. This is
   the dump shape; a single record or heterogeneous KV lines score 0.
3. ``entropy`` — high-entropy blobs (base64/hex runs): keys, tokens,
   encoded secrets.
4. ``volume`` — payload bytes vs the agent's rolling baseline
   (z-score with a std floor; cold-start safe: needs >= 5 samples).
5. ``novelty`` — a first-time external recipient AMPLIFIES the
   structured/dump/entropy subtotal (never fires alone).

Score -> graduated response:
  score < 0.40            -> "allow" (silent)
  0.40 <= score < 0.60    -> "flag" (LOUD audit, execution proceeds)
  score >= 0.60           -> "require_approval" (block until human decides)

Honest ceiling (documented, measured in
evals/unlabeled_exfil_probes.py): prose-form exfiltration ("the
customer's phone number is five five five...") carries no
structured/dump/entropy signal and is UNDETECTABLE by this analyzer
by design. The 4 pinned paraphrase BREAK shapes are prose; a bulleted
key:value paraphrase (e2) is STRUCTURALLY INDISTINGUISHABLE from a
benign status report (f3) — the analyzer does not pretend to separate
them, and both score under the flag threshold. What this module adds
is a measured control over the STRUCTURED unlabeled-exfil class
(JSON/CSV dumps, encoded blobs), which previously had no content
control at all.

The analyzer never sees classification labels and never consults
them; it is orthogonal to gov/classification.py.
"""

import base64
import binascii
import math
import re
from collections import Counter, deque

# ---------------------------------------------------------------------------
# Thresholds (tuned on synthetic data; see _TUNING note below)
# ---------------------------------------------------------------------------
FLAG_THRESHOLD = 0.40
REQUIRE_THRESHOLD = 0.60

W_STRUCTURED = 0.25
W_DUMP = 0.50
W_ENTROPY = 0.30
W_VOLUME = 0.15
# destination novelty multiplies the (structured+dump+entropy) subtotal by
# this when the destination is first-seen AND a sub-signal is material.
NOVELTY_AMPLIFIER = 1.30
NOVELTY_MATERIAL_FLOOR = 0.25

BASELINE_MIN_SAMPLES = 5
BASELINE_WINDOW = 40

# _TUNING: thresholds were set by scoring a synthetic tuning set
# (structured/encoded dumps as malicious; JSON API responses, status
# reports, prose as benign). The tuning set lives in
# tests/test_egress_content.py::TUNING_MALICIOUS / TUNING_BENIGN.

# ---------------------------------------------------------------------------
# Signal 1: structured-data density
# ---------------------------------------------------------------------------

_KV_LINE = re.compile(
    r"^\s*(?:[-*\u2022]\s*)?[A-Za-z][\w .()/-]{0,40}?\s*[:=]\s*\S+")
_JSON_FRAG = re.compile(r"\{[^^{}]{0,400}?\"[^\"]{1,60}\"\s*:")
_XML_FRAG = re.compile(r"<[A-Za-z][\w.-]*(\s[^<>]*)?>.*?</[A-Za-z][\w.-]*>",
                       re.DOTALL)
_TABLE_ROW = re.compile(r"^\s*\S.*\|.*\|.*$")


def _csv_like(lines):
    """Count of CSV-like rows among the candidate comma-bearing lines.

    Lines without commas (prose padding, headers) are ignored, so a
    single prose line cannot mask a dump. Fires when >=3 candidate
    lines each carry >=2 commas with a stable field count (within
    +-1) — the CSV-dump shape. Returns 0 when the shape is absent."""
    cands = [ln for ln in lines if ln.strip() and ln.count(",") >= 2]
    if len(cands) < 3:
        return 0
    counts = [ln.count(",") for ln in cands]
    if max(counts) - min(counts) > 1:
        return 0
    return len(cands)


def structured_density(text):
    """0..1 score for structured-data density. Returns (score, detail)."""
    if not text or not text.strip():
        return 0.0, {"structured_lines": 0, "total_lines": 0}
    lines = [ln for ln in text.splitlines() if ln.strip()]
    total = len(lines)
    if total == 0:
        return 0.0, {"structured_lines": 0, "total_lines": 0}
    structured = 0
    for ln in lines:
        if _KV_LINE.match(ln):
            structured += 1
        elif _JSON_FRAG.search(ln):
            structured += 1
        elif _TABLE_ROW.match(ln):
            structured += 1
        elif "\t" in ln and len(ln.split("\t")) >= 3:
            structured += 1
    if _XML_FRAG.search(text):
        structured = max(structured, 2)
    csv_rows = _csv_like(lines)
    if csv_rows >= 3:
        structured = max(structured, csv_rows)
    # Gate on an absolute count: a single "key: value" line in a long
    # prose message must not move the needle.
    if structured < 2:
        return 0.0, {"structured_lines": structured, "total_lines": total}
    score = min(1.0, (structured / total) * 1.35)
    return score, {"structured_lines": structured, "total_lines": total}


# ---------------------------------------------------------------------------
# Signal 2: dump repetition (record-shaped exfil)
# ---------------------------------------------------------------------------

_JSON_OBJ = re.compile(r"\{[^{}]*\}")
_JSON_KEY = re.compile(r'"([^"]{1,40})"\s*:')


def _csv_row_count(lines):
    rows = [ln for ln in lines if ln.strip()]
    if len(rows) < 3:
        return 0
    counts = [ln.count(",") for ln in rows]
    if min(counts) < 3 or max(counts) - min(counts) > 1:
        return 0
    return len(rows)


def dump_repetition(text):
    """0..1 score for repeated-record dumps. Returns (score, detail).

    Fires (1.0) when >=3 JSON objects share an identical key set, or
    >=3 CSV-like rows share a stable field count. A single record, or
    heterogeneous key:value lines, scores 0 — this is what separates a
    customer-table dump (u1/u2) from a benign status report (f3) and a
    bulleted paraphrase (e2)."""
    if not text or not text.strip():
        return 0.0, {"kind": None, "records": 0}
    keysets = []
    for m in _JSON_OBJ.finditer(text):
        keys = tuple(sorted(set(_JSON_KEY.findall(m.group(0)))))
        if keys:
            keysets.append(keys)
    if keysets:
        top_count = Counter(keysets).most_common(1)[0][1]
        if top_count >= 3:
            return 1.0, {"kind": "json", "records": top_count}
    lines = [ln for ln in text.splitlines() if ln.strip()]
    csv_rows = _csv_like(lines)
    if csv_rows >= 3:
        return 1.0, {"kind": "csv", "records": csv_rows}
    # Repeated XML elements: the same tag opened >=3 times where at least
    # one instance wraps NESTED markup (<c><id>1</id>...</c>), the XML
    # record-dump shape. Bare repeated tags (HTML <p> paragraphs, whose
    # first inner "<" is their own closing tag) do NOT count, so a
    # formatted email body is not mistaken for a record dump.
    xml_tags = []
    for tag in set(t for t, _ in re.findall(
            r"<([A-Za-z][\w.-]*)(\s[^>]*)?>", text)):
        if len(re.findall(r"<%s(\s[^>]*)?>" % re.escape(tag), text)) < 3:
            continue
        if re.search(r"<%s(\s[^>]*)?>[^<]*<(?!/)" % re.escape(tag),
                     text):
            xml_tags.append(tag.lower())
    if xml_tags:
        top_xml = Counter(
            re.findall(r"<(%s)(\s[^>]*)?>" % "|".join(
                re.escape(t) for t in xml_tags), text)
        ).most_common(1)[0][1]
        if top_xml >= 3:
            return 1.0, {"kind": "xml", "records": top_xml}
    # Key=value record dumps: the same key repeated >=3 times across
    # lines (e.g. user=alice / role=admin / user=bob / ...).
    kv_keys = []
    for ln in lines:
        m = _KV_LINE.match(ln)
        if m:
            key = re.split(r"\s*[:=]\s*", ln.strip(), maxsplit=1)[0]
            key = re.sub(r"^[-*\u2022]\s*", "", key).strip().lower()
            if key:
                kv_keys.append(key)
    if kv_keys:
        top_kv = Counter(kv_keys).most_common(1)[0][1]
        if top_kv >= 3:
            return 1.0, {"kind": "kv", "records": top_kv}
    return 0.0, {"kind": None, "records": 0}


# ---------------------------------------------------------------------------
# Signal 3: entropy anomaly (high-entropy blobs)
# ---------------------------------------------------------------------------

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RUN = re.compile(r"(?:0x)?[0-9a-fA-F]{40,}")


def _shannon(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def entropy_anomaly(text):
    """0..1 score for high-entropy blob content. Returns (score, detail)."""
    if not text:
        return 0.0, {"suspicious_bytes": 0, "total_bytes": 0}
    total = len(text)
    suspicious = 0
    for m in _B64_RUN.finditer(text):
        run = m.group(0)
        if _shannon(run) >= 4.0:
            try:
                padded = run + "=" * (-len(run) % 4)
                base64.b64decode(padded, validate=True)
                suspicious += len(run)
            except (binascii.Error, ValueError):
                continue
    for m in _HEX_RUN.finditer(text):
        run = m.group(0)
        body = run[2:] if run.startswith("0x") else run
        if len(body) >= 40 and _shannon(body) >= 3.5:
            suspicious += len(run)
    if suspicious == 0:
        return 0.0, {"suspicious_bytes": 0, "total_bytes": total}
    score = min(1.0, (suspicious / max(total, 1)) * 3.0)
    return score, {"suspicious_bytes": suspicious, "total_bytes": total}


# ---------------------------------------------------------------------------
# Signal 4: volume anomaly vs rolling baseline
# ---------------------------------------------------------------------------

def volume_anomaly(nbytes, samples):
    """0..1 score for payload-size surprise. Cold-start safe: needs
    BASELINE_MIN_SAMPLES samples, else 0.0. A std floor (0.5*mean) keeps
    a degenerate baseline (identical samples) from maxing out on any
    larger payload."""
    if len(samples) < BASELINE_MIN_SAMPLES:
        return 0.0, {"z": 0.0, "samples": len(samples)}
    mean = sum(samples) / len(samples)
    var = sum((s - mean) ** 2 for s in samples) / len(samples)
    std = math.sqrt(var) if var > 0 else 0.0
    std = max(std, 0.5 * mean, 1.0)
    z = (nbytes - mean) / std
    if z < 1.5:
        return 0.0, {"z": round(z, 2), "samples": len(samples)}
    score = 1.0 / (1.0 + math.exp(-(z - 3.0)))
    return score, {"z": round(z, 2), "samples": len(samples)}


# ---------------------------------------------------------------------------
# Analysis entry point
# ---------------------------------------------------------------------------

def analyze_payload(text, destination=None, baseline_samples=(),
                    seen_destinations=()):
    """Score an outbound payload. Returns a dict:

    {score, verdict, signals: {structured, dump, entropy, volume,
     novelty}, detail: {...}}

    verdict in {"allow", "flag", "require_approval"}.
    Pure function of its inputs — no I/O, no global state.
    """
    text = text or ""
    s_struct, d_struct = structured_density(text)
    s_dump, d_dump = dump_repetition(text)
    s_ent, d_ent = entropy_anomaly(text)
    s_vol, d_vol = volume_anomaly(len(text.encode("utf-8", "replace")),
                                  tuple(baseline_samples))
    novelty = 0.0
    if destination:
        novelty = 0.0 if destination in set(seen_destinations) else 1.0

    subtotal = (W_STRUCTURED * s_struct + W_DUMP * s_dump
                + W_ENTROPY * s_ent)
    if novelty >= 1.0 and max(s_struct, s_dump, s_ent) >= NOVELTY_MATERIAL_FLOOR:
        subtotal *= NOVELTY_AMPLIFIER
    score = min(1.0, subtotal + W_VOLUME * s_vol)

    if score >= REQUIRE_THRESHOLD:
        verdict = "require_approval"
    elif score >= FLAG_THRESHOLD:
        verdict = "flag"
    else:
        verdict = "allow"
    return {
        "score": round(score, 3),
        "verdict": verdict,
        "signals": {
            "structured": round(s_struct, 3),
            "dump": round(s_dump, 3),
            "entropy": round(s_ent, 3),
            "volume": round(s_vol, 3),
            "novelty": novelty,
        },
        "detail": {
            "structured": d_struct,
            "dump": d_dump,
            "entropy": d_ent,
            "volume": d_vol,
        },
    }


# ---------------------------------------------------------------------------
# Stateful per-agent monitor (baseline + destination history)
# ---------------------------------------------------------------------------

class EgressContentMonitor:
    """Per-agent rolling baseline of egress payload sizes and the set of
    seen destinations. ``check()`` analyzes one outbound payload and
    records it into the baseline AFTER scoring (the current payload
    never scores against itself). The baseline tracks what the agent
    SENDS, not what was clean."""

    def __init__(self):
        self._baselines = {}     # agent_id -> deque of byte counts
        self._destinations = {}  # agent_id -> set of destinations

    def check(self, agent_id, tool, args, payload_text=None):
        """Analyze one egress. ``payload_text`` overrides arg extraction
        (tests/synthetic callers). Returns the analyze_payload dict plus
        the destination and agent id."""
        if payload_text is None:
            payload_text = _extract_payload(tool, args or {})
        destination = _extract_destination(tool, args or {})
        samples = tuple(self._baselines.get(agent_id, ()))
        seen = self._destinations.get(agent_id, set())
        res = analyze_payload(payload_text, destination=destination,
                              baseline_samples=samples,
                              seen_destinations=seen)
        buf = self._baselines.setdefault(agent_id,
                                         deque(maxlen=BASELINE_WINDOW))
        buf.append(len((payload_text or "").encode("utf-8", "replace")))
        if destination:
            self._destinations.setdefault(agent_id, set()).add(destination)
        res["destination"] = destination
        res["agent_id"] = agent_id
        return res


def _extract_payload(tool, args):
    """Best-effort outbound text extraction from tool args."""
    bits = []
    if tool == "http_post":
        for k in ("data", "body", "payload", "content"):
            v = args.get(k)
            if isinstance(v, str) and v:
                bits.append(v)
    elif tool == "send_email":
        for k in ("subject", "body", "text", "html"):
            v = args.get(k)
            if isinstance(v, str) and v:
                bits.append(v)
    elif tool == "api_call":
        params = args.get("params")
        if isinstance(params, dict):
            for v in params.values():
                if isinstance(v, str) and v:
                    bits.append(v)
        elif isinstance(params, str) and params:
            bits.append(params)
    else:
        for v in args.values():
            if isinstance(v, str) and v:
                bits.append(v)
    return "\n".join(bits)


def _extract_destination(tool, args):
    if tool == "http_post":
        return args.get("url")
    if tool == "send_email":
        return args.get("to")
    if tool == "api_call":
        return args.get("endpoint")
    return None
