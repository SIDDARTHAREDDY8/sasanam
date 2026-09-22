"""P13 (wave-36): renderer-side output-filter REFERENCE implementation.

EchoLeak-class exfiltration (I6) happens in the RENDERER, not in the
governed tool layer: an attacker who gets a URL into agent output
exfiltrates by getting the *renderer* (markdown with image autoload,
HTML email, chat link previews) to fetch it. The payload side is
covered by the P1/P4 close-outs (DLP/taint/budget keep sensitive
bytes out of output); this module is the renderer-side reference
implementation of the deployment guidance in ``docs/DEPLOYMENT.md``
§5.6 -- a deterministic, stdlib-only sanitizer a deployment runs on
agent-controlled text BEFORE it reaches any active renderer.

What it neutralizes (EchoLeak primitives):
  * markdown inline/reference images whose host is not on the
    deployer's image allowlist (the exfil fetch primitive);
  * raw HTML active tags (img/script/iframe/object/embed/link/meta/
    base/form/video/audio/source/track/style/svg/image + comments) --
    wave-40 (F116): ``svg``/``image`` added -- ``<svg><image
    href="...">`` is an auto-fetch exfil primitive in any renderer
    that allows inline SVG, and the ``\b`` boundary meant ``<image``
    never matched the ``img`` alternative. Trade-off, documented:
    legitimate inline SVG diagrams in agent output are escaped too
    (fail-closed); deployments that need SVG diagrams should render
    them from trusted templates, not agent output;
  * dangerous schemes (javascript:/data:/vbscript:/file:) in any URL
    position, including whitespace/control-char and HTML-entity
    obfuscation -- wave-40 (F116): raw-HTML ``<a href="...">`` with a
    dangerous scheme is now neutralized (entity-aware); previously
    only markdown links/autolinks were checked, so
    ``<a href="javascript:...">`` passed through despite the "any URL
    position" claim;
  * autolinks carrying dangerous schemes.

What it deliberately does NOT do (documented, not gaps):
  * bare ``https://`` URLs are left as text -- link-preview fetches
    are a renderer setting (``linkify: false``, server-side unfurl
    proxying); see §5.6 item 3. The filter cannot configure the
    renderer.
  * fenced code blocks and inline code spans are skipped -- their
    content is already inert in CommonMark renderers, and rewriting
    them would corrupt displayed code.
  * allowlist membership is the deployer's call (pass
    ``image_host_allowlist=`` / ``link_host_allowlist=``); the empty
    default denies every image host (fail-closed).

HONEST BOUNDARY: this module pins the filter's BEHAVIOR in the
repo's gates (unit tests + a registered probe). It cannot verify
that a deployment actually routes agent output through it --
adoption is deployment-verified via the EchoLeak canary checklist
(§5.6). That is why P13 remains PARTIAL: the renderer side is a
reference control, not a verified deployment.
"""

import html as _html
import re
from urllib.parse import urlsplit

__all__ = [
    "DANGEROUS_SCHEMES",
    "ACTIVE_HTML_TAGS",
    "CSP_AGENT_OUTPUT",
    "contains_active_content",
    "sanitize",
]

#: Schemes that must never appear in any URL position of rendered
#: agent output (checked after whitespace/control-char stripping and
#: HTML-entity unescaping, so ``java\\tscript:`` and
#: ``&#106;avascript:`` are caught).
DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:", "file:")

#: Raw-HTML tags treated as active content in agent output.
#: Wave-40 (F116): ``svg``/``image`` included -- an SVG ``<image>``
#: element fetches its ``href`` in renderers that allow inline SVG,
#: which is exactly the auto-fetch exfil primitive this module
#: exists to neutralize. Fail-closed trade-off: legitimate inline
#: SVG diagrams in agent output are escaped as well.
ACTIVE_HTML_TAGS = (
    "img", "script", "iframe", "object", "embed", "link", "meta",
    "base", "form", "video", "audio", "source", "track", "style",
    "svg", "image",
)

#: Reference Content-Security-Policy for pages rendering agent
#: output (adapt host lists; mirrors docs/DEPLOYMENT.md §5.6).
CSP_AGENT_OUTPUT = (
    "default-src 'self'; img-src 'self' data:; "
    "script-src 'self'; object-src 'none'; base-uri 'self'; "
    "frame-src 'none'; form-action 'self'"
)

_WS_CONTROL = re.compile(r"[\x00-\x20]+")


def _normalize_scheme(url):
    """Scheme of ``url`` after unescape + whitespace/control strip."""
    u = _WS_CONTROL.sub("", _html.unescape(url)).lower()
    return u.split(":", 1)[0] + ":" if ":" in u else ""


def _is_dangerous_scheme(url):
    return _normalize_scheme(url) in DANGEROUS_SCHEMES


def _host_of(url):
    try:
        return (urlsplit(_html.unescape(url)).hostname or "").lower()
    except Exception:
        return ""


_FENCE_RE = re.compile(r"(```.*?```|`[^`\n]+`)", re.DOTALL)


def _segments(text):
    """Split into (is_code, segment) pairs; code spans are inert."""
    parts = _FENCE_RE.split(text)
    return [(i % 2 == 1, part) for i, part in enumerate(parts) if part]


_MD_IMAGE_INLINE_RE = re.compile(
    r"!\[([^\]\n]*)\]\(\s*(<[^>\n]*>|[^)\s\n]+)(?:\s+[^)]*)?\)")
_MD_IMAGE_REF_RE = re.compile(r"!\[([^\]\n]*)\]\[([^\]\n]*)\]")
_REF_DEF_RE = re.compile(r"(?m)^\s{0,3}\[([^\]\n]+)\]:\s*(\S+)")
_HTML_ACTIVE_RE = re.compile(
    r"<\s*/?\s*(%s)\b[^>]*>" % "|".join(ACTIVE_HTML_TAGS), re.IGNORECASE)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
#: Wave-40 (F116): raw-HTML ``<a href="...">`` carrying a dangerous
#: scheme. ``<a>`` itself is not an active tag (plain https links are
#: left as text by design -- click-through is a user action, and
#: link-preview fetching is a renderer setting), but a dangerous
#: scheme in its href is never legitimate output. Entity-aware and
#: quote-tolerant; only a dangerous normalized scheme triggers.
_HTML_A_HREF_RE = re.compile(
    r"<\s*a\b(?:[^>\"']|\"[^\"]*\"|'[^']*')*?\bhref\s*=\s*"
    r"(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
    re.IGNORECASE)
_MD_LINK_RE = re.compile(
    r"(?<!!)\[([^\]\n]*)\]\(\s*(<[^>\n]*>|[^)\s\n]+)(?:\s+[^)]*)?\)")
_AUTOLINK_RE = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^<>\s]*)>")
#: Fallback for whitespace/control-char-obfuscated URL positions
#: (e.g. ``[x](java\\tscript:...)``): strict CommonMark would not form
#: a link here, but sloppy renderers strip the whitespace before
#: interpreting the scheme -- so a dangerous scheme in such a
#: position is still neutralized. Scoped narrowly: only a dangerous
#: normalized scheme triggers; anything else passes through
#: untouched.
_WS_OBFUSCATED_RE = re.compile(
    r"(!?)\[([^\]\n]*)\]\(\s*([^)\n]*[\x00-\x20]+[^)\n]*)\)")


def _ref_targets(text):
    return {m.group(1).strip().lower(): m.group(2).strip()
            for m in _REF_DEF_RE.finditer(text)}


def contains_active_content(text, *, image_host_allowlist=(),
                            link_host_allowlist=()):
    """Detect EchoLeak-class active content. Returns a list of
    ``(kind, snippet)`` hits; empty means clean. Pure function."""
    img_allow = {h.lower() for h in image_host_allowlist}
    hits = []
    refs = _ref_targets(text)
    for is_code, seg in _segments(text):
        if is_code:
            continue
        for m in _MD_IMAGE_INLINE_RE.finditer(seg):
            url = m.group(2).strip()
            if url.startswith("<") and url.endswith(">"):
                url = url[1:-1]
            if _is_dangerous_scheme(url):
                hits.append(("dangerous-scheme-image", m.group(0)[:80]))
            elif _host_of(url) not in img_allow:
                hits.append(("nonallowlisted-image", m.group(0)[:80]))
        for m in _MD_IMAGE_REF_RE.finditer(seg):
            ref = (m.group(2) or m.group(1)).strip().lower()
            url = refs.get(ref, "")
            if _is_dangerous_scheme(url):
                hits.append(("dangerous-scheme-image", m.group(0)[:80]))
            elif _host_of(url) not in img_allow:
                hits.append(("nonallowlisted-image", m.group(0)[:80]))
        for m in _MD_LINK_RE.finditer(seg):
            url = m.group(2).strip()
            if url.startswith("<") and url.endswith(">"):
                url = url[1:-1]
            if _is_dangerous_scheme(url):
                hits.append(("dangerous-scheme-link", m.group(0)[:80]))
        for m in _AUTOLINK_RE.finditer(seg):
            if _is_dangerous_scheme(m.group(1)):
                hits.append(("dangerous-scheme-autolink",
                             m.group(0)[:80]))
        for m in _WS_OBFUSCATED_RE.finditer(seg):
            if _is_dangerous_scheme(m.group(3)):
                hits.append(("obfuscated-dangerous-scheme",
                             m.group(0)[:80]))
        for m in _HTML_ACTIVE_RE.finditer(seg):
            hits.append(("active-html-tag", m.group(0)[:80]))
        for m in _HTML_A_HREF_RE.finditer(seg):
            url = m.group(1) or m.group(2) or m.group(3) or ""
            if _is_dangerous_scheme(url):
                hits.append(("dangerous-scheme-a-href",
                             m.group(0)[:80]))
        for m in _HTML_COMMENT_RE.finditer(seg):
            hits.append(("html-comment", m.group(0)[:80]))
    return hits


def _neutralize_bracket(text):
    return text.replace("![", "!&#91;", 1).replace("[", "&#91;", 1)


def _sanitize_segment(seg, img_allow):
    refs = _ref_targets(seg)

    def _img_inline(m):
        url = m.group(2).strip()
        if url.startswith("<") and url.endswith(">"):
            url = url[1:-1]
        if _is_dangerous_scheme(url) or _host_of(url) not in img_allow:
            return _neutralize_bracket(m.group(0))
        return m.group(0)

    def _img_ref(m):
        ref = (m.group(2) or m.group(1)).strip().lower()
        url = refs.get(ref, "")
        if _is_dangerous_scheme(url) or _host_of(url) not in img_allow:
            return _neutralize_bracket(m.group(0))
        return m.group(0)

    def _link(m):
        url = m.group(2).strip()
        if url.startswith("<") and url.endswith(">"):
            url = url[1:-1]
        if _is_dangerous_scheme(url):
            return m.group(0).replace("[", "&#91;", 1)
        return m.group(0)

    def _autolink(m):
        if _is_dangerous_scheme(m.group(1)):
            return m.group(0).replace("<", "&lt;", 1)
        return m.group(0)

    def _ws_obfuscated(m):
        # Narrow: only a dangerous normalized scheme triggers.
        if _is_dangerous_scheme(m.group(3)):
            if m.group(1) == "!":
                return m.group(0).replace("![", "!&#91;", 1)
            return m.group(0).replace("[", "&#91;", 1)
        return m.group(0)

    def _a_href(m):
        url = m.group(1) or m.group(2) or m.group(3) or ""
        if _is_dangerous_scheme(url):
            return m.group(0).replace("<", "&lt;", 1)
        return m.group(0)

    seg = _MD_IMAGE_INLINE_RE.sub(_img_inline, seg)
    seg = _MD_IMAGE_REF_RE.sub(_img_ref, seg)
    seg = _MD_LINK_RE.sub(_link, seg)
    seg = _WS_OBFUSCATED_RE.sub(_ws_obfuscated, seg)
    seg = _AUTOLINK_RE.sub(_autolink, seg)
    seg = _HTML_A_HREF_RE.sub(_a_href, seg)
    seg = _HTML_ACTIVE_RE.sub(
        lambda m: m.group(0).replace("<", "&lt;", 1), seg)
    seg = _HTML_COMMENT_RE.sub(
        lambda m: m.group(0).replace("<", "&lt;", 1), seg)
    return seg


def sanitize(text, *, image_host_allowlist=(),
             link_host_allowlist=()):
    """Neutralize EchoLeak-class active content in agent output.

    Markdown images with non-allowlisted hosts (or dangerous
    schemes), dangerous-scheme links/autolinks, raw-HTML active tags
    and comments are escaped so they render as inert text. Benign
    markdown (links, formatting, tables) and fenced/inline code pass
    through unchanged. Deterministic, stdlib-only, pure function.
    """
    img_allow = {h.lower() for h in image_host_allowlist}
    return "".join(seg if is_code else _sanitize_segment(seg, img_allow)
                   for is_code, seg in _segments(text))
