"""A minimal YAML-subset parser (standard library only).

Supports exactly the subset used by policies/*.yaml:
  - nested mappings via indentation (spaces only)
  - block sequences using "- "
  - flow sequences like [a, b, c]
  - scalars: single/double-quoted strings, integers, floats, booleans, null
  - mapping keys: bare ([A-Za-z_][A-Za-z0-9_-]*) or single/double-quoted
    (quoted keys exist for section keys the bare grammar cannot spell,
    e.g. fnmatch families like "db.*" -- wave-337)
Blank lines and "#" comments are ignored.

This is intentionally small: it exists so policy files stay human-readable
YAML without adding a third-party dependency.
"""

import re

_MAP_KEY = re.compile(
    r"^(?:([A-Za-z_][A-Za-z0-9_\-]*)|\"([^\"]*)\"|'([^']*)')"
    r"\s*:(?:\s+(.*)|\s*)$")


def _map_key(m):
    """The mapping key from a _MAP_KEY match: bare, double-quoted, or
    single-quoted. Quoted keys exist so policy sections can name keys
    the bare grammar cannot spell -- e.g. fnmatch families like
    "db.*" in tool_rate_limits:/tool_budgets: (wave-337, R8/R12).
    An empty quoted key ("") is returned as "" and refused
    downstream by the section normalizers (fail closed)."""
    key = m.group(1)
    if key is None:
        key = m.group(2) if m.group(2) is not None else m.group(3)
    return key


def _strip_comment(line):
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                return line[:i].rstrip()
    return line


def _split_flow(inner):
    parts, buf = [], ""
    in_single = in_double = False
    depth = 0  # bracket nesting: commas inside [...] do not split
    for ch in inner:
        if ch == "'" and not in_double:
            in_single = not in_single
            buf += ch
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf += ch
        elif in_single or in_double:
            buf += ch
        elif ch in "[{":
            depth += 1
            buf += ch
        elif ch in "]}":
            depth = max(0, depth - 1)
            buf += ch
        elif ch == "," and depth == 0:
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return parts


def _scalar(token):
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    low = token.lower()
    if low in ("", "null", "~", "none"):
        return None
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p) for p in _split_flow(inner)]
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _parse_map(items, pos, indent):
    out = {}
    while pos < len(items):
        ind, content = items[pos]
        if ind < indent:
            break
        if ind > indent:
            raise ValueError("unexpected indentation at: %r" % content)
        m = _MAP_KEY.match(content)
        if not m:
            raise ValueError("expected 'key: value', got: %r" % content)
        key, rest = _map_key(m), (m.group(4) or "").strip()
        pos += 1
        if rest:
            out[key] = _scalar(rest)
        elif pos < len(items) and items[pos][0] > indent:
            val, pos = _parse_block(items, pos, items[pos][0])
            out[key] = val
        else:
            out[key] = None
    return out, pos


def _parse_seq(items, pos, indent):
    out = []
    while pos < len(items):
        ind, content = items[pos]
        if ind < indent:
            break
        if ind > indent:
            raise ValueError("unexpected indentation at: %r" % content)
        if not (content.startswith("- ") or content == "-"):
            raise ValueError("expected '- ' item, got: %r" % content)
        rest = content[1:].strip()
        pos += 1
        if not rest:
            if pos >= len(items) or items[pos][0] <= indent:
                raise ValueError("'-' with no value and no nested block")
            val, pos = _parse_block(items, pos, items[pos][0])
            out.append(val)
            continue
        if ":" in rest and _MAP_KEY.match(rest):
            # "- key: value" starts an inline mapping; gather its continuation lines.
            cont = []
            while pos < len(items) and items[pos][0] > indent:
                cont.append(items[pos])
                pos += 1
            if not cont:
                m = _MAP_KEY.match(rest)
                out.append({_map_key(m): _scalar((m.group(4) or "").strip())})
                continue
            base = cont[0][0]
            sub = [(base, rest)] + cont
            val, _ = _parse_map(sub, 0, base)
            out.append(val)
            continue
        out.append(_scalar(rest))
    return out, pos


def _parse_block(items, pos, indent):
    first = items[pos][1]
    if first.startswith("- ") or first == "-":
        return _parse_seq(items, pos, indent)
    return _parse_map(items, pos, indent)


def parse(text):
    """Parse the supported YAML subset into plain Python objects."""
    items = []
    for raw in text.splitlines():
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ValueError("tabs are not allowed for indentation")
        if not raw.strip():
            continue
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        items.append((indent, line.strip()))
    if not items:
        return {}
    val, pos = _parse_block(items, 0, items[0][0])
    if pos != len(items):
        raise ValueError("trailing unparsed content at: %r" % (items[pos],))
    return val


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return parse(f.read())
