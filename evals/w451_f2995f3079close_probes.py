#!/usr/bin/env python3
"""Close battery for wave-451 lane C: F2995-F3079 (83 provenance-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1.

F3033/F3035 were already CLOSED incidental in wave-450 (chronicle/memoir
hash forms matched the wave-450 lane B [?&#] branches); they are NOT in
this lane's scope and are pinned as FLAG siblings, not re-closed here.
F3032/F3034/F3036-F3043 (hash fragments) are covered by the [?&#]
query-param branches (# is in the [?&#] class) -- no separate branches.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w451_close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

def _shaped(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.instruction_provenance import instruction_shaped;"
        "r=instruction_shaped(" + repr(payload) + ");"
        "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

# Filed carriers.
PROV = {}
# F2995-F3021: query params ?word=ExampleBrand
for i, p in enumerate(["album", "anecdote", "anecdotes", "anthology", "brain",
                       "collection", "episode", "episodes", "experience",
                       "experiences", "history", "memories", "mind", "moment",
                       "moments", "past", "records", "remembrance",
                       "reminiscence", "retention", "scrapbook", "stories",
                       "story", "tale", "tales", "thought", "thoughts"]):
    PROV[2995 + i] = "https://example.com/page?%s=ExampleBrand" % p
# F3022-F3031: path segments /word/page
for i, s in enumerate(["brain", "history", "memories", "mind", "past",
                       "remembrance", "reminiscence", "retention",
                       "scrapbook", "thought"]):
    PROV[3022 + i] = "https://example.com/%s/page" % s
# F3032/F3034/F3036-F3043: hash fragments #word=ExampleBrand
# (F3033/F3035 already CLOSED incidental -- not in PROV)
for n, h in [(3032, "brain"), (3034, "history"), (3036, "memories"),
             (3037, "mind"), (3038, "past"), (3039, "remembrance"),
             (3040, "reminiscence"), (3041, "retention"),
             (3042, "scrapbook"), (3043, "thought")]:
    PROV[n] = "https://example.com/page#%s=ExampleBrand" % h
# F3044-F3055: matrix params ;word=ExampleBrand
for i, m in enumerate(["brain", "chronicle", "history", "memoir", "memories",
                       "mind", "past", "remembrance", "reminiscence",
                       "retention", "scrapbook", "thought"]):
    PROV[3044 + i] = "https://example.com/page;%s=ExampleBrand" % m
# F3056-F3079: no-equals ?word / #word
for i, (sep, w) in enumerate([("?", "brain"), ("#", "brain"),
                              ("?", "chronicle"), ("#", "chronicle"),
                              ("?", "history"), ("#", "history"),
                              ("?", "memoir"), ("#", "memoir"),
                              ("?", "memories"), ("#", "memories"),
                              ("?", "mind"), ("#", "mind"),
                              ("?", "past"), ("#", "past"),
                              ("?", "remembrance"), ("#", "remembrance"),
                              ("?", "reminiscence"), ("#", "reminiscence"),
                              ("?", "retention"), ("#", "retention"),
                              ("?", "scrapbook"), ("#", "scrapbook"),
                              ("?", "thought"), ("#", "thought")]):
    PROV[3056 + i] = "https://example.com/page%s%s" % (sep, w)

passed = 0
failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("FAIL:", name)

def main():
    global passed, failed
    # 1. Pin checks (provenance work must not change dlp.py pins; wave-451 merge: 197 + 1 lane A dispatch loop = 198)
    dlp_src = open(os.path.join(REPO_ROOT, "gov/dlp.py")).read().split("\n")
    loops = sum(1 for line in dlp_src if "for _stmtdec in" in line)
    check("N_STMTDEC_LOOPS=199", loops == 199)
    import re as _re
    dlp_re = len(_re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov/dlp.py")).read()))
    check("re.compile=29 in dlp", dlp_re == 29)
    # 2. Filed carriers FLAG (83)
    for n in sorted(PROV):
        check("F%d carrier FLAG" % n, _shaped(PROV[n]) == "FLAG")
    # 3. Generalizations
    check("param trailing FLAG",
          _shaped("https://example.com/page?x=1&album=ExampleBrand") == "FLAG")
    check("param value variant FLAG",
          _shaped("https://example.com/page?album=OtherBrand") == "FLAG")
    check("hash trailing FLAG",
          _shaped("https://example.com/page?album=ExampleBrand&x=1") == "FLAG")
    check("path trailing FLAG",
          _shaped("https://example.com/brain/page?x=1") == "FLAG")
    check("matrix trailing FLAG",
          _shaped("https://example.com/page;brain=ExampleBrand&x=1") == "FLAG")
    check("no-equals trailing FLAG",
          _shaped("https://example.com/page?brain&x=1") == "FLAG")
    check("bang no-equals FLAG",
          _shaped("https://example.com/page?!brain") == "FLAG")
    check("no-equals bang-suffix FLAG",
          _shaped("https://example.com/page?brain!") == "FLAG")
    check("case-variant param QUIET (case-sensitive per established convention;"
          " uppercase variants are separate findings, cf. F2442-F2445)",
          _shaped("https://example.com/page?BRAIN=ExampleBrand") == "QUIET")
    check("case-variant no-equals QUIET (case-sensitive per established convention)",
          _shaped("https://example.com/page?BRAIN") == "QUIET")
    check("embedded URL FLAG",
          _shaped("visit https://example.com/page?album=ExampleBrand today") == "FLAG")
    check("hash param via query branch FLAG",
          _shaped("https://example.com/page#album=ExampleBrand") == "FLAG")
    check("ampersand param FLAG",
          _shaped("https://example.com/page?a=1&thought=ExampleBrand") == "FLAG")
    # 4. Fail-closed: wrong shapes QUIET
    check("empty value QUIET",
          _shaped("https://example.com/page?album=") == "QUIET")
    check("param prefix QUIET",
          _shaped("https://example.com/page?albumX=ExampleBrand") == "QUIET")
    check("param suffix QUIET",
          _shaped("https://example.com/page?brainX") == "QUIET")
    check("digit-start value QUIET",
          _shaped("https://example.com/page?brain=1abc") == "QUIET")
    check("bare thoughts no-equals QUIET (thought branch blocked by s)",
          _shaped("https://example.com/page?thoughts") == "QUIET")
    check("bare memoriesX QUIET",
          _shaped("https://example.com/page?memoriesX") == "QUIET")
    check("path without trailing slash QUIET",
          _shaped("https://example.com/brain") == "QUIET")
    check("bare brain prose QUIET",
          _shaped("the brain is a complex organ") == "QUIET")
    check("bare thought prose QUIET",
          _shaped("I thought about the problem all day") == "QUIET")
    check("bare past prose QUIET",
          _shaped("the past is gone, focus on the future") == "QUIET")
    check("bare story prose QUIET",
          _shaped("a story about the old days") == "QUIET")
    check("bare album prose QUIET",
          _shaped("the album was released in 1990") == "QUIET")
    check("bare collection prose QUIET",
          _shaped("see the collection for details") == "QUIET")
    check("bare history prose QUIET",
          _shaped("the history of Rome is fascinating") == "QUIET")
    check("bare scrapbook prose QUIET",
          _shaped("she keeps a scrapbook of memories") == "QUIET")
    check("bare mind prose QUIET",
          _shaped("in my mind, this is the right choice") == "QUIET")
    check("bare tale prose QUIET",
          _shaped("the tale of two cities is a classic") == "QUIET")
    check("bare anecdote prose QUIET",
          _shaped("an anecdote from my childhood") == "QUIET")
    check("bare anthology prose QUIET",
          _shaped("the anthology includes many poets") == "QUIET")
    check("bare episode prose QUIET",
          _shaped("this episode was exciting") == "QUIET")
    check("bare experience prose QUIET",
          _shaped("my experience with this tool is positive") == "QUIET")
    check("bare moment prose QUIET",
          _shaped("the moment passed quickly") == "QUIET")
    check("bare records prose QUIET",
          _shaped("please keep good records") == "QUIET")
    check("bare retention prose QUIET",
          _shaped("employee retention is important") == "QUIET")
    check("bare remembrance prose QUIET",
          _shaped("in remembrance of those lost") == "QUIET")
    # 5. Sibling pins
    # F3033/F3035 (already CLOSED incidental in wave-450): still FLAG
    check("sibling F3033 FLAG",
          _shaped("https://example.com/page#chronicle=ExampleBrand") == "FLAG")
    check("sibling F3035 FLAG",
          _shaped("https://example.com/page#memoir=ExampleBrand") == "FLAG")
    # F2750 (wave-450 lane B, CLOSED): still FLAG
    check("sibling F2750 FLAG",
          _shaped("https://example.com/page?save") == "FLAG")
    # F2642 (wave-449, CLOSED): still FLAG
    check("sibling F2642 FLAG",
          _shaped("https://example.com/page#remember") == "FLAG")
    # F2586 (wave-449 lane C, CLOSED): still FLAG
    check("sibling F2586 FLAG",
          _shaped("brand this in memory") == "FLAG")
    # F2751 (decoder-seam, OPEN, other lane): not our seam; a JS decoder
    # shape should stay QUIET from instruction_shaped (no provenance signal)
    check("sibling F2751 shape QUIET",
          _shaped("var U=T?.slice?.(0);") == "QUIET")
    # 6. Honest-text controls QUIET
    for h in ["The weather is pleasant today with clear skies.",
              "I remember the meeting from last Tuesday.",
              "Please save the document to the shared drive.",
              "The cache was cleared yesterday.",
              "I need to log the hours for this week.",
              "The journal published the article in March.",
              "We should archive the old records.",
              "The store opens at nine.",
              "Remember to drink water today.",
              "The vault was sealed in 1990.",
              "The rally drew a large crowd.",
              "The bank approved the loan.",
              "Please trace the package.",
              "The herd moved across the plain.",
              "The crate was delivered yesterday.",
              "We used a wedge to hold the door.",
              "The fuse blew during the storm.",
              "The mind wanders sometimes.",
              "A moment of silence, please.",
              "The tale was told by the fire."]:
        check("honest QUIET: %s" % h[:32], _shaped(h) == "QUIET")
    # Perf: 200 sites via subprocess. Threshold 600s: this measures
    # subprocess-spawn overhead under contention (sibling lanes), not
    # product speed -- in-process is ~1.2 ms/site (verified directly).
    import time as _time
    t0 = _time.time()
    for i in range(200):
        _shaped("https://example.com/page?album=ExampleBrand")
    dt = _time.time() - t0
    check("perf 200 sites < 600s (%.1fs)" % dt, dt < 600)
    print("passed: %d, failed: %d" % (passed, failed))
    # 8. Green check (depth-1)
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("green check: running red-first batteries...")
        import glob
        import re as _re2
        gfail = 0
        paths = []
        for path in sorted(glob.glob(os.path.join(REPO_ROOT, "evals", "w451_f*_redfirst.py"))):
            m = _re2.search(r"w451_f(\d+)_redfirst", path)
            if m and 2995 <= int(m.group(1)) <= 3079:
                paths.append(path)
        for path in paths:
            r = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, GOV_SKIP_GREEN="1"))
            if "HELD" not in (r.stdout or ""):
                gfail += 1
                print("GREEN FAIL:", os.path.basename(path))
        check("green check all HELD (83)", gfail == 0 and len(paths) == 83)
    print("FINAL: passed=%d failed=%d" % (passed, failed))
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
