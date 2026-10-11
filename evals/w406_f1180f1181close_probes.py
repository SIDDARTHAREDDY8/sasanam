#!/usr/bin/env python3
"""Wave-406 lane 4 close battery: F1180 + F1181 CLOSED.

F1180: plain `<meta name="keywords" content="...">` carrier --
prose-shaped text in the keywords content attribute is not rendered in
the consuming view (page metadata), but the seam returned QUIET.
F1064 covers only og:/twitter: meta variants; F1151 covers plain
name="description"; the keywords variant was not modeled.
Closed by _has_hidden_meta_keywords in gov/instruction_provenance.py
wired into instruction_shaped (F1180/F1181 block): prose-shaped content
is instruction-shaped by construction (the F1024 rationale); machine
tokens (whitespace-free keyword lists) and empty carriers stay quiet.
Disjoint from F1064's og:/twitter: variants and F1151's
name="description" (documented per detector).

F1181: other unmodeled meta content carriers -- prose-shaped text in
`<meta name="author" content="...">` and `<meta
property="article:tag" content="...">` is not rendered in the
consuming view, but the seam returned QUIET. Closed by
_has_hidden_meta_author_and_article_tags wired into instruction_shaped
(F1180/F1181 block). Machine tokens stay quiet. Disjoint from
F1064's variants, F1151's name="description", and F1180's
name="keywords" (documented per detector).

Neutralized framing throughout (round-67 lesson): carriers described
purely as HTML content shapes with expected routing outcomes.
Green checks ON. $0-spend-by-construction.
"""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143
VERIFIER_TAXONOMY_PIN = 33
RECOMPILE_PIN = 28  # gov/dlp.py untouched by this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402
from gov.instruction_provenance import instruction_shaped  # noqa: E402

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _misses(payload):
    return dlp.find_credential(payload) is None


def _flags(payload):
    return bool(instruction_shaped(payload))


def _quiet(payload):
    return not instruction_shaped(payload)


def _redfirst_shapes(prefix, num):
    """Import a red-first module's SHAPES (import is side-effect free)."""
    path = os.path.join(REPO_ROOT, "evals", "%s_f%d_redfirst.py" % (prefix, num))
    spec = importlib.util.spec_from_file_location(
        "%s_f%d_rf" % (prefix, num), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHAPES


POLITE = ("the quarterly financial summary shows revenue growth across "
          "all regional divisions and market segments")
VISIBLE = "Hi team, please see the quarterly report summary below. Best, Alice"


@_t
def test_p0_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_taxonomy_pin (%d)" % len(TAXONOMY))
    return ok


@_t
def test_p0_verifier_pin():
    ok = VERIFIER_TAXONOMY_PIN == 33
    print(("HELD " if ok else "BREAK") + " test_p0_verifier_pin (%d)" % VERIFIER_TAXONOMY_PIN)
    return ok


@_t
def test_p0_recompile_pin():
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == RECOMPILE_PIN
    print(("HELD " if ok else "BREAK") + " test_p0_recompile_pin (%d)" % n)
    return ok


@_t
def test_p0_footer_state():
    """Lane-local footer: base footer's open F1159-F1181 minus this
    lane's F1180/F1181 closures."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    ok = ("# Wave-406 lane 4: F1180-F1181 CLOSED (2); "
          "F1159-F1179 OPEN (21); next free F1182" in text)
    print(("HELD " if ok else "BREAK") + " test_p0_footer_state")
    return ok


@_t
def test_p0_base_footer_preserved():
    """Base wave-405 footer lineage intact (wave-393 rule)."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    ok = ("# Wave-405: F1142-F1158 CLOSED (17); F1159-F1181 OPEN (23); "
          "next free F1182" in text)
    print(("HELD " if ok else "BREAK") + " test_p0_base_footer_preserved")
    return ok


@_t
def test_f1180_filed_shapes_flagged():
    shapes = _redfirst_shapes("w405", 1180)
    bad = [n for n, p in shapes if not _flags(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1180_filed_shapes_flagged (%d%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1181_filed_shapes_flagged():
    shapes = _redfirst_shapes("w405", 1181)
    bad = [n for n, p in shapes if not _flags(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1181_filed_shapes_flagged (%d%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1180_generalizations():
    cases = [
        # Case-insensitive tags and attribute names.
        ("upper", VISIBLE + '\n<META NAME="keywords" CONTENT="' + POLITE + '">', True),
        ("mixed-name", VISIBLE + '\n<meta Name="Keywords" content="' + POLITE + '">', True),
        # Attribute order swapped (content before name).
        ("swapped-order", VISIBLE + '\n<meta content="' + POLITE + '" name="keywords">', True),
        # Unquoted name value.
        ("unquoted-name", VISIBLE + '\n<meta name=keywords content="' + POLITE + '">', True),
        # Sibling: name="description" still flags via F1151.
        ("description-sibling", VISIBLE + '\n<meta name="description" content="' + POLITE + '">', True),
        # Sibling: og:description still flags via F1064.
        ("og-sibling", VISIBLE + '\n<meta property="og:description" content="' + POLITE + '">', True),
        # Machine tokens / honest keyword lists stay quiet.
        ("keyword-list", VISIBLE + '\n<meta name="keywords" content="news,finance,quarterly">', False),
        ("machine-token", VISIBLE + '\n<meta name="keywords" content="ABC-123">', False),
        ("empty-content", VISIBLE + '\n<meta name="keywords" content="">', False),
        ("no-content-attr", VISIBLE + '\n<meta name="keywords">', False),
        ("no-name-attr", VISIBLE + '\n<meta content="' + POLITE + '">', False),
        # Whitespace-only content stays quiet.
        ("ws-only", VISIBLE + '\n<meta name="keywords" content="   ">', False),
    ]
    bad = [n for n, p, want in cases if _flags(p) != want]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1180_generalizations (%d%s)" %
          (len(cases), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1181_generalizations():
    cases = [
        # <meta name="author"> variants.
        ("author-dq", VISIBLE + '\n<meta name="author" content="' + POLITE + '">', True),
        ("author-sq", VISIBLE + "\n<meta name='author' content='" + POLITE + "'>", True),
        ("author-upper", VISIBLE + '\n<META NAME="AUTHOR" CONTENT="' + POLITE + '">', True),
        ("author-swapped", VISIBLE + '\n<meta content="' + POLITE + '" name="author">', True),
        # <meta property="article:tag"> variants.
        ("articletag-dq", VISIBLE + '\n<meta property="article:tag" content="' + POLITE + '">', True),
        ("articletag-sq", VISIBLE + "\n<meta property='article:tag' content='" + POLITE + "'>", True),
        ("articletag-upper", VISIBLE + '\n<META PROPERTY="ARTICLE:TAG" CONTENT="' + POLITE + '">', True),
        # article:section is NOT modeled (different property).
        ("articlesection-quiet", VISIBLE + '\n<meta property="article:section" content="' + POLITE + '">', False),
        # Machine tokens / honest bylines stay quiet.
        ("author-token", VISIBLE + '\n<meta name="author" content="jsmith">', False),
        ("author-empty", VISIBLE + '\n<meta name="author" content="">', False),
        ("articletag-token", VISIBLE + '\n<meta property="article:tag" content="Tech">', False),
        ("no-content", VISIBLE + '\n<meta name="author">', False),
        # Sibling: og:description still flags via F1064.
        ("og-sibling", VISIBLE + '\n<meta property="og:description" content="' + POLITE + '">', True),
    ]
    bad = [n for n, p, want in cases if _flags(p) != want]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1181_generalizations (%d%s)" %
          (len(cases), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1180f1181_disjointness():
    """Each detector fires only on its own carrier (documented
    disjointness), both directions."""
    from gov.instruction_provenance import (
        _has_hidden_meta_keywords, _has_hidden_meta_author_and_article_tags,
        _has_hidden_meta_descriptions, _has_hidden_meta_plain_description)
    kw = '<meta name="keywords" content="' + POLITE + '">'
    author = '<meta name="author" content="' + POLITE + '">'
    atag = '<meta property="article:tag" content="' + POLITE + '">'
    og = '<meta property="og:description" content="' + POLITE + '">'
    desc = '<meta name="description" content="' + POLITE + '">'
    cases = [
        ("kw-fires-kw", _has_hidden_meta_keywords(kw), True),
        ("kw-misses-author", _has_hidden_meta_keywords(author), False),
        ("kw-misses-atag", _has_hidden_meta_keywords(atag), False),
        ("kw-misses-desc", _has_hidden_meta_keywords(desc), False),
        ("kw-misses-og", _has_hidden_meta_keywords(og), False),
        ("author-fires-author", _has_hidden_meta_author_and_article_tags(author), True),
        ("author-fires-atag", _has_hidden_meta_author_and_article_tags(atag), True),
        ("author-misses-kw", _has_hidden_meta_author_and_article_tags(kw), False),
        ("author-misses-desc", _has_hidden_meta_author_and_article_tags(desc), False),
        ("author-misses-og", _has_hidden_meta_author_and_article_tags(og), False),
        ("og-fires-og", _has_hidden_meta_descriptions(og), True),
        ("og-misses-kw", _has_hidden_meta_descriptions(kw), False),
        ("og-misses-author", _has_hidden_meta_descriptions(author), False),
        ("desc-fires-desc", _has_hidden_meta_plain_description(desc), True),
        ("desc-misses-kw", _has_hidden_meta_plain_description(kw), False),
        ("desc-misses-author", _has_hidden_meta_plain_description(author), False),
    ]
    bad = [n for n, got, want in cases if got != want]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1180f1181_disjointness (%d%s)" %
          (len(cases), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_sibling_provenance_pins():
    """Prior carriers still route; honest provenance controls quiet."""
    must_route = [
        ("f1024-comment", VISIBLE + '\n<!-- ' + POLITE + ' -->'),
        ("f1064-og", VISIBLE + '\n<meta property="og:description" content="' + POLITE + '">'),
        ("f1064-imgalt", VISIBLE + '\n<img src="x.png" alt="' + POLITE + '">'),
        ("f1064-htmltitle", VISIBLE + '\n<title>' + POLITE + '</title>'),
        ("f1047-dataattr", VISIBLE + '\n<div data-info="' + POLITE + '">x</div>'),
        ("f1047-arialabel", VISIBLE + '\n<button aria-label="' + POLITE + '">x</button>'),
        ("f1073-textplain", VISIBLE + '\n<script type="text/plain">' + POLITE + '</scr' + 'ipt>'),
        ("f1085-vttcue", "WEBVTT\n\n00:00.000 --> 00:01.000\n" + POLITE + "\n"),
        ("f1098-optgrouplabel", VISIBLE + '\n<select><optgroup label="' + POLITE + '"><option>x</option></optgroup></select>'),
        ("f1109-rubyrt", VISIBLE + '\n<ruby>x<rt>' + POLITE + '</rt></ruby>'),
        ("f1151-description", VISIBLE + '\n<meta name="description" content="' + POLITE + '">'),
        ("f1152-tracklabel", VISIBLE + '\n<video><track kind="captions" label="' + POLITE + '"></video>'),
    ]
    must_quiet = [
        ("visible", VISIBLE),
        ("meta-viewport", VISIBLE + '\n<meta name="viewport" content="width=device-width">'),
        ("meta-charset", VISIBLE + '\n<meta charset="utf-8">'),
        ("f1047-ldjson", '<script type="application/ld+json">{"a": 1}</scr' + 'ipt>'),
    ]
    bad = [n for n, p in must_route if not _flags(p)]
    bad += [n for n, p in must_quiet if not _quiet(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_sibling_provenance_pins (%d%s)" %
          (len(must_route) + len(must_quiet), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_still_open_dlps():
    """Round-73 DLP findings F1159-F1179 stay OPEN (untouched by this
    lane): their filed shapes still MISS at the decoder seam."""
    nums = list(range(1159, 1180))
    bad = []
    total = 0
    for num in nums:
        shapes = _redfirst_shapes("w405", num)
        total += len(shapes)
        for name, payload in shapes:
            if not _misses(payload):
                bad.append(name)
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_still_open_dlps (%d shapes%s)" %
          (total, "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_perf_200_sites():
    texts = []
    for i in range(200):
        if i % 4 == 0:
            texts.append(VISIBLE + '\n<meta name="keywords" content="' + POLITE + '">')
        elif i % 4 == 1:
            texts.append(VISIBLE + '\n<meta name="author" content="' + POLITE + '">')
        elif i % 4 == 2:
            texts.append("var x = %d; // honest text %d" % (i, i))
        else:
            texts.append("<p>honest paragraph number %d with words</p>" % i)
    t0 = time.time()
    for t in texts:
        instruction_shaped(t)
        dlp.find_credential(t)
    dt = time.time() - t0
    ok = dt < 60
    print(("HELD " if ok else "BREAK") + " test_perf_200_sites (%.2fs)" % dt)
    return ok


@_t
def test_green_w405():
    """Depth-1 green check on w405's attack battery (carries the
    F1180/F1181 OPEN provenance pins). Honor GOV_SKIP_GREEN. The two
    OPEN provenance pins are EXPECTED to flip (now closed); anything
    else breaking is real."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w405 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g406l4-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    child = os.path.join(REPO_ROOT, "evals", "w405_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, child],
                           capture_output=True, text=True, env=env,
                           timeout=600, cwd=os.path.join(REPO_ROOT, "evals"))
        broke, held = [], []
        for line in (r.stdout or "").split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (broke if parts[0] == "BREAK" else held).append(parts[1])
        expected_flips = {"test_open_prov_w405_f1180", "test_open_prov_w405_f1181"}
        ok = (set(broke) == expected_flips)
        print(("HELD " if ok else "BREAK") +
              " test_green_w405 (flips=%s broke=%s)" %
              (sorted(set(broke) & expected_flips), sorted(broke)))
        return ok
    except Exception as e:
        print("BREAK test_green_w405 (exec failed: %s)" % e)
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    fails = []
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            if not fn():
                fails.append(fn.__name__)
        except Exception as e:
            print("BREAK " + fn.__name__ + " (exception: %s)" % e)
            fails.append(fn.__name__)
    print("%d/%d HELD" % (len(TESTS) - len(fails), len(TESTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
