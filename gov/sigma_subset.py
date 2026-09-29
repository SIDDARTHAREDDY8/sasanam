"""Sigma-subset detection-rule evaluator -- stdlib only, product code.

Auditor-side detection (see ``gov/audit_detect.py``): evaluates
Sigma-shaped rules (public-domain format; pySigma is LGPL-2.1 and is
NOT vendored or depended on) with Falco-style composition (named
macros / lists / exceptions) folded in. Never on the enforcement hot
path: this module is consumed only by the offline auditor.

Supported subset (documented limits, not a full Sigma implementation):
  - YAML-subset rule documents: nested maps (2-space indent), "- " lists,
    inline "[a, b]" flow lists, scalars (quoted/unquoted strings, ints,
    floats, booleans, null). NOT supported: anchors, multi-doc, block
    scalars, flow maps, tabs. The parser refuses anything outside this.
  - detection: named selections; each selection is field -> predicate.
    Predicates: scalar (exact equality), list (OR), or dict with ONE of:
      {"$list": name}      field value in named list (Falco-style)
      {"$re": pattern}     regex search
      {"$contains": s} / {"$startswith": s} / {"$endswith": s}
      {"$gt"/"$gte"/"$lt"/"$lte": n}   numeric comparison
      {"$in": [..]}        explicit OR list
      {"$null": true}      field missing or null
      {"$gtf": other}      val > event[other] (numeric, else ISO-8601
                           string compare) -- spike extension for
                           field-to-field comparison (ceremony windows).
    Field-name modifiers are ALSO accepted in Sigma spelling:
      "field|startswith": "x", "field|endswith", "field|contains",
      "field|re", "field|gt", "field|gte", "field|lt", "field|lte".
    A bare null value matches a missing/null field.
  - condition: boolean algebra over selection names:
      selection | (a and b) | (a or b) | not a |
      1 of sel_* | all of sel_* | 1 of them | all of them
    Aggregation form (Sigma-style):
      selection | count() by field > N
      selection | count() by field1, field2 > N
    with an optional rule-level `timeframe: 10m|1h|30s` sliding window.
  - macros (Falco-style): top-level `macros:` maps names to field-predicate
    dicts; a selection may pull one in via "$macro": name.
  - lists (Falco-style): top-level `lists:` maps names to value lists.
  - exceptions (Falco-style): per-rule list of field-predicate dicts; if ANY
    exception selection matches the event, the alert is suppressed.
  - logsource: product/service recorded on the alert (scoping only).
  - level: informational/low/medium/high/critical recorded on the alert.

NOT in scope: Sigma correlations (temporal "near"),
`cidr`/`windash` modifiers, value modifiers on lists, rule `status`
filtering, deduplication across rules. Pairwise temporal correlation
(impossible travel) is deliberately out of the selection subset; the
rule YAML carries the parameters under a `correlation:` block and
`gov/audit_detect.py` enforces them with a stateful correlator --
documented, not quiet.

$0 spend, synthetic/local deterministic only. No network.
"""

import re
from datetime import datetime, timedelta, timezone

__all__ = [
    "SigmaSubsetError", "RuleError",
    "parse_yaml_subset", "parse_timeframe", "parse_rule_text",
    "compile_rule", "CompiledRule", "StreamEngine", "event_time",
]


class SigmaSubsetError(Exception):
    pass


class RuleError(SigmaSubsetError):
    pass


# --------------------------------------------------------------------------
# Minimal YAML-subset parser.
# --------------------------------------------------------------------------

def _split_flow(s):
    parts, cur, q = [], "", None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
            cur += ch
        elif ch == ",":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def _parse_scalar(tok):
    tok = tok.strip()
    if tok in ("null", "Null", "NULL", "~", ""):
        return None
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return tok[1:-1]
    low = tok.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if re.fullmatch(r"[+-]?\d+", tok):
        return int(tok)
    if re.fullmatch(r"[+-]?\d*\.\d+([eE][+-]?\d+)?", tok):
        return float(tok)
    if tok.startswith("[") and tok.endswith("]"):
        inner = tok[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(p) for p in _split_flow(inner)]
    return tok


def _hash_is_comment(raw):
    q = None
    for ch in raw:
        if q:
            if ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
        elif ch == "#":
            return True
    return False


def parse_yaml_subset(text):
    """Parse the supported YAML subset into Python objects."""
    lines = []
    for raw in text.splitlines():
        if "\t" in raw:
            raise SigmaSubsetError("tabs are not supported in the YAML subset")
        code = raw.split("#", 1)[0] if _hash_is_comment(raw) else raw
        if not code.strip():
            continue
        indent = len(code) - len(code.lstrip(" "))
        lines.append((indent, code.strip()))
    if not lines:
        return {}
    pos = [0]
    doc = _parse_block(lines, pos, 0)
    if pos[0] < len(lines):
        raise SigmaSubsetError(
            "unsupported construct (only simple scalars, nested maps and "
            "dash/flow lists are supported) at: %s" % (lines[pos[0]][1],))
    return doc


def _parse_block(lines, pos, indent):
    if pos[0] >= len(lines):
        return None
    cur_indent, cur_text = lines[pos[0]]
    if cur_indent != indent:
        raise SigmaSubsetError(
            "unexpected indent %d (expected %d) at: %s" % (cur_indent, indent, cur_text))
    if cur_text.startswith("- ") or cur_text == "-":
        return _parse_list(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_list(lines, pos, indent):
    out = []
    while pos[0] < len(lines):
        cur_indent, cur_text = lines[pos[0]]
        if cur_indent != indent or not (cur_text.startswith("- ") or cur_text == "-"):
            break
        pos[0] += 1
        rest = cur_text[1:].strip()
        if rest == "":
            # Nested block on following lines (deeper indent).
            if pos[0] < len(lines) and lines[pos[0]][0] > indent:
                out.append(_parse_block(lines, pos, lines[pos[0]][0]))
            else:
                out.append(None)
        elif ":" in rest and not _looks_like_scalar(rest):
            # "- key: value" inline map start.
            key, _, val = rest.partition(":")
            item = {}
            k = key.strip()
            v = val.strip()
            item[k] = _parse_scalar(v) if v else None
            # Continuation lines of this map at deeper indent.
            while pos[0] < len(lines) and lines[pos[0]][0] > indent:
                sub = _parse_block(lines, pos, lines[pos[0]][0])
                if isinstance(sub, dict):
                    item.update(sub)
                else:
                    raise SigmaSubsetError(
                        "mixed content in dash-map item: %r" % (sub,))
                # only consume one nested block per iteration guard
                break
            # Handle possible further sibling keys written as "- k2: v2"
            # (already handled) -- map continuation lines deeper than the
            # dash are consumed above; plain "k2: v2" lines at deeper
            # indent are also maps and were consumed.
            if v == "" and pos[0] < len(lines) and lines[pos[0]][0] > indent:
                sub = _parse_block(lines, pos, lines[pos[0]][0])
                if isinstance(sub, dict):
                    item.update(sub)
            out.append(item)
        else:
            out.append(_parse_scalar(rest))
    return out


def _looks_like_scalar(rest):
    # Heuristic: "key: value" where value contains ": " is a map; a plain
    # scalar with a colon inside quotes or a URL is not a map. We treat
    # `key: <anything with ': '>` as a map only when the key has no spaces
    # and the value part after the first colon is non-empty... simpler:
    # if it parses as key + ": " + value, it's a map.
    key, _, val = rest.partition(":")
    return not (val.startswith(" ") and re.fullmatch(r"[A-Za-z0-9_.\-|$]+", key.strip()))


def _parse_map(lines, pos, indent):
    out = {}
    while pos[0] < len(lines):
        cur_indent, cur_text = lines[pos[0]]
        if cur_indent != indent:
            break
        if cur_text.startswith("- "):
            break
        pos[0] += 1
        if ":" not in cur_text:
            raise SigmaSubsetError("map line without ':': %s" % cur_text)
        key, _, val = cur_text.partition(":")
        key = key.strip()
        val = val.strip()
        if not key:
            raise SigmaSubsetError("empty key in: %s" % cur_text)
        if val == "":
            if pos[0] < len(lines) and lines[pos[0]][0] > indent:
                out[key] = _parse_block(lines, pos, lines[pos[0]][0])
            else:
                out[key] = None
        else:
            out[key] = _parse_scalar(val)
    return out


# --------------------------------------------------------------------------
# Timeframes: "30s" / "10m" / "1h" / "2d".
# --------------------------------------------------------------------------

def parse_timeframe(text):
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(text))
    if not m:
        raise RuleError("bad timeframe: %r (want like 10m, 1h, 30s)" % (text,))
    n, unit = int(m.group(1)), m.group(2)
    return {"s": timedelta(seconds=n), "m": timedelta(minutes=n),
            "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]


# --------------------------------------------------------------------------
# Predicate compilation.
# --------------------------------------------------------------------------

_MODIFIERS = ("startswith", "endswith", "contains", "re",
              "gt", "gte", "lt", "lte", "gtf")


def _match_predicate(field, pred, event, lists):
    val = event.get(field, None)
    return _apply_pred(val, pred, event, lists)


def _apply_pred(val, pred, event, lists):
    if isinstance(pred, dict):
        if len(pred) != 1:
            raise RuleError("predicate dict must have exactly one op: %r" % (pred,))
        op, arg = next(iter(pred.items()))
        if op == "$list":
            if arg not in lists:
                raise RuleError("unknown list: %r" % (arg,))
            return val in lists[arg]
        if op == "$in":
            return val in arg
        if op == "$null":
            return (val is None) == bool(arg)
        if op == "$re":
            return val is not None and re.search(arg, str(val)) is not None
        if op == "$contains":
            return val is not None and str(arg) in str(val)
        if op == "$startswith":
            return val is not None and str(val).startswith(str(arg))
        if op == "$endswith":
            return val is not None and str(val).endswith(str(arg))
        if op in ("$gt", "$gte", "$lt", "$lte"):
            # Numeric when both sides parse; otherwise ISO-8601/string
            # ordering (timestamps compare correctly in Z-normalized form).
            try:
                lnum, rnum = float(val), float(arg)
                numeric = True
            except (TypeError, ValueError):
                numeric = False
            if numeric:
                return {"$gt": lnum > rnum, "$gte": lnum >= rnum,
                        "$lt": lnum < rnum, "$lte": lnum <= rnum}[op]
            if val is None:
                return False
            l, r = str(val), str(arg)
            return {"$gt": l > r, "$gte": l >= r,
                    "$lt": l < r, "$lte": l <= r}[op]
        if op == "$gtf":
            other = event.get(arg)
            if val is None or other is None:
                return False
            try:
                return float(val) > float(other)
            except (TypeError, ValueError):
                return str(val) > str(other)
        raise RuleError("unknown predicate op: %r" % (op,))
    if isinstance(pred, list):
        return any(_apply_pred(val, p, event, lists) for p in pred)
    if pred is None:
        return val is None
    return val == pred


def _build_matcher(sel_fields, lists):
    """Compile a field->predicate map into an event->bool matcher."""
    compiled = []
    for raw_field, pred in sel_fields.items():
        if "|" in raw_field:
            field, _, mod = raw_field.partition("|")
            field, mod = field.strip(), mod.strip()
            if mod not in _MODIFIERS:
                raise RuleError("unknown field modifier: %r" % (mod,))
            pred = {"$" + mod: pred}
        else:
            field = raw_field
        compiled.append((field, pred))

    def matcher(event):
        return all(_match_predicate(f, p, event, lists) for f, p in compiled)

    return matcher


def _expand_macros(sel_fields, macros):
    out = {}
    macro_names = []
    for k, v in sel_fields.items():
        if k == "$macro":
            macro_names.append(v)
        else:
            out[k] = v
    # Macros expand after explicit fields so collision detection is
    # order-independent: a macro fragment must never shadow or repeat
    # an explicit field, whichever comes first in the mapping.
    for name in macro_names:
        if name not in macros:
            raise RuleError("unknown macro: %r" % (name,))
        frag = macros[name]
        if not isinstance(frag, dict):
            raise RuleError("macro %r must be a field map" % (name,))
        for fk, fv in frag.items():
            if fk in out:
                raise RuleError("macro %r collides on field %r" % (name, fk))
            out[fk] = fv
    return out


# --------------------------------------------------------------------------
# Condition algebra.
# --------------------------------------------------------------------------

_COND_TOK = re.compile(r"\(|\)|\b(?:and|or|not)\b|1 of [A-Za-z0-9_.*]+|"
                       r"all of [A-Za-z0-9_.*]+|[A-Za-z0-9_]+|\S")


def _cond_to_fn(cond_text, sel_matchers):
    tokens = [t for t in _COND_TOK.findall(cond_text) if t.strip()]
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def next_tok():
        t = peek()
        pos[0] += 1
        return t

    def parse_expr():
        return parse_or()

    def parse_or():
        left = parse_and()
        while peek() == "or":
            next_tok()
            right = parse_and()
            left = (lambda l, r: lambda m: l(m) or r(m))(left, right)
        return left

    def parse_and():
        left = parse_not()
        while peek() == "and":
            next_tok()
            right = parse_not()
            left = (lambda l, r: lambda m: l(m) and r(m))(left, right)
        return left

    def parse_not():
        if peek() == "not":
            next_tok()
            inner = parse_not()
            return lambda m: not inner(m)
        return parse_atom()

    def parse_atom():
        t = next_tok()
        if t == "(":
            inner = parse_expr()
            if next_tok() != ")":
                raise RuleError("unbalanced parens in condition: %r" % cond_text)
            return inner
        if t is None:
            raise RuleError("truncated condition: %r" % cond_text)
        low = t.lower()
        if low.startswith("1 of "):
            names = _resolve_group(t[5:].strip(), sel_matchers, cond_text)
            return lambda m: sum(1 for f in names if f(m)) >= 1
        if low.startswith("all of "):
            names = _resolve_group(t[7:].strip(), sel_matchers, cond_text)
            return lambda m: all(f(m) for f in names)
        if t in sel_matchers:
            fn = sel_matchers[t]
            return lambda m: fn(m)
        raise RuleError("unknown selection %r in condition: %r" % (t, cond_text))

    fn = parse_expr()
    if peek() is not None:
        raise RuleError("trailing tokens in condition: %r" % cond_text)
    return fn


def _resolve_group(pattern, sel_matchers, cond_text):
    if pattern == "them":
        names = list(sel_matchers)
    elif pattern.endswith("*"):
        prefix = pattern[:-1]
        names = [n for n in sel_matchers if n.startswith(prefix)]
    else:
        raise RuleError("bad group pattern %r in condition: %r" % (pattern, cond_text))
    if not names:
        raise RuleError("group %r matches no selections in: %r" % (pattern, cond_text))
    return [sel_matchers[n] for n in names]


_AGG_RE = re.compile(
    r"^\s*([A-Za-z0-9_]+)\s*\|\s*count\(\)\s*by\s+([A-Za-z0-9_, ]+?)\s*"
    r"(?:near\s+(\S+))?\s*>\s*(\d+)\s*$")


def _compile_agg(cond_text, sel_matchers):
    m = _AGG_RE.match(cond_text)
    if not m:
        return None
    sel_name, by_fields, near, threshold = m.groups()
    if sel_name not in sel_matchers:
        raise RuleError("unknown selection %r in aggregation: %r" % (sel_name, cond_text))
    by_fields = [f.strip() for f in by_fields.split(",") if f.strip()]
    if not by_fields:
        raise RuleError("count() by needs at least one field: %r" % cond_text)
    near_td = parse_timeframe(near) if near else None
    return {
        "matcher": sel_matchers[sel_name],
        "by": by_fields,
        "near": near_td,
        "threshold": int(threshold),
    }


# --------------------------------------------------------------------------
# Rule compilation.
# --------------------------------------------------------------------------

def parse_rule_text(text):
    doc = parse_yaml_subset(text)
    if not isinstance(doc, dict):
        raise RuleError("rule document must be a mapping")
    return doc


REQUIRED = ("title", "id", "detection")


def compile_rule(doc, macros=None, lists=None):
    for req in REQUIRED:
        if req not in doc:
            raise RuleError("rule missing required key: %s" % req)
    macros = dict(macros or {})
    lists = dict(lists or {})
    doc_macros = doc.get("macros") or {}
    doc_lists = doc.get("lists") or {}
    if not isinstance(doc_macros, dict) or not isinstance(doc_lists, dict):
        raise RuleError("macros/lists must be mappings")
    macros = {**macros, **doc_macros}
    lists = {**lists, **doc_lists}

    detection = doc["detection"]
    if not isinstance(detection, dict):
        raise RuleError("detection must be a mapping")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise RuleError("detection.condition must be a string")

    sel_matchers = {}
    for name, sel in detection.items():
        if name in ("condition", "timeframe"):
            continue
        if not isinstance(sel, dict):
            raise RuleError("selection %r must be a field map" % name)
        sel_matchers[name] = _build_matcher(_expand_macros(sel, macros), lists)

    agg = _compile_agg(condition, sel_matchers)
    cond_fn = None if agg else _cond_to_fn(condition, sel_matchers)

    timeframe = None
    if "timeframe" in detection:
        timeframe = parse_timeframe(detection["timeframe"])

    exceptions = []
    for exc in doc.get("exceptions") or []:
        if not isinstance(exc, dict):
            raise RuleError("each exception must be a field map")
        fields = dict(exc)
        fields.pop("name", None)
        fields.pop("desc", None)
        exceptions.append(_build_matcher(_expand_macros(fields, macros), lists))

    logsource = doc.get("logsource") or {}
    rule = CompiledRule(
        rule_id=str(doc["id"]),
        title=str(doc["title"]),
        level=str(doc.get("level", "medium")),
        logsource={"product": logsource.get("product"),
                   "service": logsource.get("service")},
        agg=agg, cond_fn=cond_fn, timeframe=timeframe,
        exceptions=exceptions,
        raw_condition=condition,
        falsepositives=list(doc.get("falsepositives") or []),
    )
    # The raw document stays attached so consumers (correlators,
    # assumption checks) read rule-authored parameters -- notably the
    # `correlation:` block -- from the YAML itself, never from a
    # shadow copy.
    rule.raw_doc = doc
    return rule


class CompiledRule:
    def __init__(self, rule_id, title, level, logsource, agg, cond_fn,
                 timeframe, exceptions, raw_condition, falsepositives):
        self.rule_id = rule_id
        self.title = title
        self.level = level
        self.logsource = logsource
        self.agg = agg
        self.cond_fn = cond_fn
        self.timeframe = timeframe
        self.exceptions = exceptions
        self.raw_condition = raw_condition
        self.falsepositives = falsepositives
        #: The parsed rule document (set by compile_rule); carries
        #: rule-authored blocks the selection subset does not compile
        #: (e.g. `correlation:`, `assumptions:`).
        self.raw_doc = {}

    @property
    def is_aggregation(self):
        return self.agg is not None

    def matches(self, event):
        """Stateless match (also the per-event leg of aggregation rules)."""
        if self.agg:
            hit = self.agg["matcher"](event)
        else:
            hit = self.cond_fn(event)
        if hit and self.exceptions:
            for exc in self.exceptions:
                if exc(event):
                    return False
        return hit


def _event_time(event):
    ts = event.get("ts")
    if isinstance(ts, datetime):
        dt = ts
    else:
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            raise SigmaSubsetError("event ts not ISO-8601: %r" % (ts,))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


#: Public alias: auditors and correlators order events by this.
event_time = _event_time


class StreamEngine:
    """Feeds timestamp-ordered events through compiled rules.

    Stateless rules alert per matching event. Aggregation rules keep a
    sliding window (rule `timeframe`, default 10m) of per-group timestamps
    and alert once per group when the count first exceeds the threshold
    (re-arming when the group falls back under).
    """

    def __init__(self, rules):
        self.rules = list(rules)
        self.alerts = []
        self._windows = {}   # (rule_id, group_key) -> deque[timestamps]
        self._armed = {}     # (rule_id, group_key) -> bool (already alerted)

    def feed(self, events):
        ordered = sorted(events, key=_event_time)
        for ev in ordered:
            self._feed_one(ev)
        return self.alerts

    def _feed_one(self, event):
        for rule in self.rules:
            if not rule.is_aggregation:
                if rule.matches(event):
                    self._alert(rule, [event], None)
                continue
            if not rule.matches(event):
                continue
            key = tuple(event.get(f) for f in rule.agg["by"])
            now = _event_time(event)
            window = rule.timeframe or timedelta(minutes=10)
            near = rule.agg["near"] or window
            slot = self._windows.setdefault((rule.rule_id, key), [])
            # Evict outside the sliding window.
            cutoff = now - window
            while slot and slot[0] < cutoff:
                slot.pop(0)
            slot.append(now)
            # `near`: require the threshold count to also fall inside the
            # tighter near-window ending at this event.
            near_cutoff = now - near
            near_count = sum(1 for t in slot if t >= near_cutoff)
            gkey = (rule.rule_id, key)
            if near_count > rule.agg["threshold"]:
                if not self._armed.get(gkey):
                    self._armed[gkey] = True
                    self._alert(rule, [event],
                                {"group": dict(zip(rule.agg["by"], key)),
                                 "count": near_count,
                                 "threshold": rule.agg["threshold"]})
            elif len(slot) <= rule.agg["threshold"]:
                # Fell back under: re-arm for the next burst.
                self._armed[gkey] = False

    def _alert(self, rule, events, detail):
        self.alerts.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "level": rule.level,
            "logsource": dict(rule.logsource),
            "events": list(events),
            "detail": detail,
        })
