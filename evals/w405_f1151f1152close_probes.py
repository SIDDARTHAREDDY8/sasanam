#!/usr/bin/env python3
"""Wave-405 lane 3 close battery: F1151 + F1152 CLOSED.

F1151: plain `<meta name="description" content="...">` carrier --
prose-shaped text in the plain meta description is not rendered in
the consuming view (page metadata), but the seam returned QUIET.
F1064's _has_hidden_meta_descriptions covers only og:/twitter: meta
variants; the plain name="description" variant was not modeled.
Closed by _has_hidden_meta_plain_description in
gov/instruction_provenance.py wired into instruction_shaped
(F1151/F1152 block): prose-shaped content is instruction-shaped by
construction (the F1024 rationale); machine tokens and empty carriers
stay quiet. Disjoint from F1064's og:/twitter: variants (documented
per detector).

F1152: `<track>` label attribute carrier -- prose-shaped text in the
label attribute of a track element (captions/subtitles) is not
rendered inline (the label surfaces only in a player captions
menu), but the seam returned QUIET. No detector modeled the track
label attribute (round-68's triage-out covered the `kind`
attribute, not `label` -- different shape). Closed by
_has_hidden_track_label wired into instruction_shaped (F1151/F1152
block). Machine tokens stay quiet.

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
    """Lane-local footer: base footer's open F1142-F1157 minus this
    lane's F1151/F1152 closures."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    ok = ("# Wave-405 lane 3: F1151-F1152 CLOSED (2); "
          "F1142-F1150, F1153-F1157 OPEN (14); next free F1158" in text)
    print(("HELD " if ok else "BREAK") + " test_p0_footer_state")
    return ok


@_t
def test_p0_base_footer_preserved():
    """Base wave-404 footer lineage intact (wave-393 rule)."""
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        text = f.read()
    ok = ("# Wave-404: F1123-F1141 CLOSED (19); F1142-F1157 OPEN (16); "
          "next free F1158" in text)
    print(("HELD " if ok else "BREAK") + " test_p0_base_footer_preserved")
    return ok


@_t
def test_f1151_filed_shapes_flagged():
    shapes = _redfirst_shapes("w404", 1151)
    bad = [n for n, p in shapes if not _flags(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1151_filed_shapes_flagged (%d%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1152_filed_shapes_flagged():
    shapes = _redfirst_shapes("w404", 1152)
    bad = [n for n, p in shapes if not _flags(p)]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1152_filed_shapes_flagged (%d%s)" %
          (len(shapes), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1151_generalizations():
    cases = [
        # Case-insensitive tags and attribute names.
        ("upper", VISIBLE + '\n<META NAME="description" CONTENT="' + POLITE + '">', True),
        ("mixed-name", VISIBLE + '\n<meta Name="Description" content="' + POLITE + '">', True),
        # Attribute order swapped (content before name).
        ("swapped-order", VISIBLE + '\n<meta content="' + POLITE + '" name="description">', True),
        # Unquoted name value.
        ("unquoted-name", VISIBLE + '\n<meta name=description content="' + POLITE + '">', True),
        # Sibling: og:description still flags via F1064.
        ("og-sibling", VISIBLE + '\n<meta property="og:description" content="' + POLITE + '">', True),
        # twitter:description still flags via F1064.
        ("twitter-sibling", VISIBLE + '\n<meta name="twitter:description" content="' + POLITE + '">', True),
        # Different meta names stay quiet.
        ("keywords-quiet", VISIBLE + '\n<meta name="keywords" content="' + POLITE + '">', False),
        ("viewport-quiet", VISIBLE + '\n<meta name="viewport" content="width=device-width">', False),
        # Machine tokens / empty carriers stay quiet.
        ("machine-token", VISIBLE + '\n<meta name="description" content="ABC-123">', False),
        ("empty-content", VISIBLE + '\n<meta name="description" content="">', False),
        ("no-content-attr", VISIBLE + '\n<meta name="description">', False),
        ("no-name-attr", VISIBLE + '\n<meta content="' + POLITE + '">', False),
        # Whitespace-only content stays quiet.
        ("ws-only", VISIBLE + '\n<meta name="description" content="   ">', False),
    ]
    bad = [n for n, p, want in cases if _flags(p) != want]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1151_generalizations (%d%s)" %
          (len(cases), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1152_generalizations():
    cases = [
        # Single-quoted label.
        ("squote", VISIBLE + "\n<video><track kind='captions' label='" + POLITE + "'></video>", True),
        # Uppercase tag/attribute.
        ("upper", VISIBLE + '\n<video><TRACK KIND="subtitles" LABEL="' + POLITE + '"></TRACK></video>', True),
        # Track outside a video element.
        ("no-video", VISIBLE + '\n<track kind="captions" label="' + POLITE + '">', True),
        # kind=descriptions WITH a prose label still flags on the label.
        ("descriptions-with-label", VISIBLE + '\n<track kind="descriptions" label="' + POLITE + '">', True),
        # Round-68 triage-out shape: kind=descriptions WITHOUT a label stays quiet.
        ("kind-only-quiet", VISIBLE + '\n<track kind="descriptions" src="d.vtt">', False),
        # Machine tokens / short labels stay quiet.
        ("short-label", VISIBLE + '\n<video><track kind="captions" label="English"></video>', False),
        ("token-label", VISIBLE + '\n<video><track kind="subtitles" label="EN-01"></video>', False),
        # No label attribute stays quiet.
        ("no-label", VISIBLE + '\n<video><track kind="captions" srclang="en"></video>', False),
        # Empty label stays quiet.
        ("empty-label", VISIBLE + '\n<video><track kind="captions" label=""></video>', False),
    ]
    bad = [n for n, p, want in cases if _flags(p) != want]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1152_generalizations (%d%s)" %
          (len(cases), "" if ok else ": " + ",".join(bad)))
    return ok


@_t
def test_f1151f1152_disjointness():
    """Each detector fires only on its own carrier (documented
    disjointness), both directions."""
    from gov.instruction_provenance import (
        _has_hidden_meta_plain_description, _has_hidden_track_label,
        _has_hidden_meta_descriptions)
    meta = '<meta name="description" content="' + POLITE + '">'
    track = '<track kind="captions" label="' + POLITE + '">'
    og = '<meta property="og:description" content="' + POLITE + '">'
    cases = [
        ("meta-fires-meta", _has_hidden_meta_plain_description(meta), True),
        ("meta-misses-track", _has_hidden_meta_plain_description(track), False),
        ("meta-misses-og", _has_hidden_meta_plain_description(og), False),
        ("track-fires-track", _has_hidden_track_label(track), True),
        ("track-misses-meta", _has_hidden_track_label(meta), False),
        ("og-fires-og", _has_hidden_meta_descriptions(og), True),
        ("og-misses-plain", _has_hidden_meta_descriptions(meta), False),
    ]
    bad = [n for n, got, want in cases if got != want]
    ok = not bad
    print(("HELD " if ok else "BREAK") +
          " test_f1151f1152_disjointness (%d%s)" %
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
        ("f1073-canvas", VISIBLE + '\n<canvas>' + POLITE + '</canvas>'),
        ("f1085-vttcue", "WEBVTT\n\n00:00.000 --> 00:01.000\n" + POLITE + "\n"),
        ("f1085-imglongdesc", VISIBLE + '\n<img src="x.png" longdesc="' + POLITE + '">'),
        ("f1098-optgrouplabel", VISIBLE + '\n<select><optgroup label="' + POLITE + '"><option>x</option></optgroup></select>'),
        ("f1098-tablesummary", VISIBLE + '\n<table summary="' + POLITE + '"><tr><td>x</td></tr></table>'),
        ("f1109-rubyrt", VISIBLE + '\n<ruby>x<rt>' + POLITE + '</rt></ruby>'),
    ]
    must_quiet = [
        ("visible", VISIBLE),
        ("meta-keywords", VISIBLE + '\n<meta name="keywords" content="news, finance">'),
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
    """Round-72 DLP findings F1142-F1150, F1153-F1157 stay OPEN
    (untouched by this lane): their filed shapes still MISS at the
    decoder seam."""
    nums = list(range(1142, 1151)) + [1153, 1154, 1155, 1156, 1157]
    bad = []
    total = 0
    for num in nums:
        shapes = _redfirst_shapes("w404", num)
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
            texts.append(VISIBLE + '\n<meta name="description" content="' + POLITE + '">')
        elif i % 4 == 1:
            texts.append(VISIBLE + '\n<track kind="captions" label="' + POLITE + '">')
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
def test_green_w404():
    """Depth-1 green check on w404's attack battery (carries the
    F1151/F1152 OPEN pins). Honor GOV_SKIP_GREEN. The two OPEN
    provenance pins are EXPECTED to flip (now closed); anything else
    breaking is real."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("HELD  test_green_w404 (skipped: GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g405l3-green-", dir="/var/tmp")
    env["TMPDIR"] = tmpd
    child = os.path.join(REPO_ROOT, "evals", "w404_attack_probes.py")
    try:
        r = subprocess.run([sys.executable, child],
                           capture_output=True, text=True, env=env,
                           timeout=600, cwd=os.path.join(REPO_ROOT, "evals"))
        broke, held = [], []
        for line in (r.stdout or "").split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("BREAK", "HELD"):
                (broke if parts[0] == "BREAK" else held).append(parts[1])
        expected_flips = {"test_open_w404_f1151", "test_open_w404_f1152"}
        ok = (set(broke) == expected_flips)
        print(("HELD " if ok else "BREAK") +
              " test_green_w404 (flips=%s broke=%s)" %
              (sorted(set(broke) & expected_flips), sorted(broke)))
        return ok
    except Exception as e:
        print("BREAK test_green_w404 (exec failed: %s)" % e)
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
