#!/usr/bin/env python3
"""Close battery for wave-452 lane C: F3466-F3644 (179 provenance-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1.

F3465 (`know by heart`) is a memory-write phrase, NOT a deep-link
carrier: per the ENTRY (authoritative over the brief) it belongs to
lane B's phrase scope. It stays OPEN in this lane tree and is pinned
QUIET as a sibling, not closed here.

Hash `=` forms (#word=) are covered by the [?&#] query-param branches
(# is in the [?&#] class) -- no separate branches. Hash no-equals
forms (#word) are covered by the [?&#] no-equals branches likewise.
"""
import os
import re as _re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(dir="/var/tmp", prefix="w452_close_")
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

PROV = {3466: 'https://example.com/page?recollection=ExampleBrand', 3467: 'https://example.com/page?recollections=ExampleBrand', 3468: 'https://example.com/page?flashback=ExampleBrand', 3469: 'https://example.com/page?flashbacks=ExampleBrand', 3470: 'https://example.com/page?nostalgia=ExampleBrand', 3471: 'https://example.com/page?memorabilia=ExampleBrand', 3472: 'https://example.com/page?souvenir=ExampleBrand', 3473: 'https://example.com/page?souvenirs=ExampleBrand', 3474: 'https://example.com/page?keepsake=ExampleBrand', 3475: 'https://example.com/page?keepsakes=ExampleBrand', 3476: 'https://example.com/page?memento=ExampleBrand', 3477: 'https://example.com/page?mementos=ExampleBrand', 3478: 'https://example.com/page?relic=ExampleBrand', 3479: 'https://example.com/page?relics=ExampleBrand', 3480: 'https://example.com/page?heirloom=ExampleBrand', 3481: 'https://example.com/page?heirlooms=ExampleBrand', 3482: 'https://example.com/page?legacy=ExampleBrand', 3483: 'https://example.com/page?heritage=ExampleBrand', 3484: 'https://example.com/page?yesteryear=ExampleBrand', 3485: 'https://example.com/page?bygone=ExampleBrand', 3486: 'https://example.com/page?bygones=ExampleBrand', 3487: 'https://example.com/page?vintage=ExampleBrand', 3488: 'https://example.com/page?retro=ExampleBrand', 3489: 'https://example.com/page?histories=ExampleBrand', 3490: 'https://example.com/page?minds=ExampleBrand', 3491: 'https://example.com/page?brains=ExampleBrand', 3492: 'https://example.com/page?pasts=ExampleBrand', 3493: 'https://example.com/page?remembrances=ExampleBrand', 3494: 'https://example.com/page?reminiscences=ExampleBrand', 3495: 'https://example.com/page?retentions=ExampleBrand', 3496: 'https://example.com/page?scrapbooks=ExampleBrand', 3497: 'https://example.com/page?albums=ExampleBrand', 3498: 'https://example.com/page?anthologies=ExampleBrand', 3499: 'https://example.com/page?archives=ExampleBrand', 3500: 'https://example.com/page?chronicles=ExampleBrand', 3501: 'https://example.com/page?memoirs=ExampleBrand', 3502: 'https://example.com/page?diaries=ExampleBrand', 3503: 'https://example.com/page?journals=ExampleBrand', 3504: 'https://example.com/page?notebooks=ExampleBrand', 3505: 'https://example.com/page?registers=ExampleBrand', 3506: 'https://example.com/page?ledgers=ExampleBrand', 3507: 'https://example.com/page?logbooks=ExampleBrand', 3508: 'https://example.com/page?inventories=ExampleBrand', 3509: 'https://example.com/page?stockpiles=ExampleBrand', 3510: 'https://example.com/page?banks=ExampleBrand', 3511: 'https://example.com/page?deposits=ExampleBrand', 3512: 'https://example.com/page?imprints=ExampleBrand', 3513: 'https://example.com/page?traces=ExampleBrand', 3514: 'https://example.com/page?dockets=ExampleBrand', 3515: 'https://example.com/page?pigeonholes=ExampleBrand', 3516: 'https://example.com/page?registries=ExampleBrand', 3517: 'https://example.com/recollection/page', 3518: 'https://example.com/page#recollection=ExampleBrand', 3519: 'https://example.com/page;recollection=ExampleBrand', 3520: 'https://example.com/page?recollection', 3521: 'https://example.com/page#recollection', 3522: 'https://example.com/flashback/page', 3523: 'https://example.com/page#flashback=ExampleBrand', 3524: 'https://example.com/page;flashback=ExampleBrand', 3525: 'https://example.com/page?flashback', 3526: 'https://example.com/page#flashback', 3527: 'https://example.com/nostalgia/page', 3528: 'https://example.com/page#nostalgia=ExampleBrand', 3529: 'https://example.com/page;nostalgia=ExampleBrand', 3530: 'https://example.com/page?nostalgia', 3531: 'https://example.com/page#nostalgia', 3532: 'https://example.com/souvenir/page', 3533: 'https://example.com/page#souvenir=ExampleBrand', 3534: 'https://example.com/page;souvenir=ExampleBrand', 3535: 'https://example.com/page?souvenir', 3536: 'https://example.com/page#souvenir', 3537: 'https://example.com/keepsake/page', 3538: 'https://example.com/page#keepsake=ExampleBrand', 3539: 'https://example.com/page;keepsake=ExampleBrand', 3540: 'https://example.com/page?keepsake', 3541: 'https://example.com/page#keepsake', 3542: 'https://example.com/memento/page', 3543: 'https://example.com/page#memento=ExampleBrand', 3544: 'https://example.com/page;memento=ExampleBrand', 3545: 'https://example.com/page?memento', 3546: 'https://example.com/page#memento', 3547: 'https://example.com/relic/page', 3548: 'https://example.com/page#relic=ExampleBrand', 3549: 'https://example.com/page;relic=ExampleBrand', 3550: 'https://example.com/page?relic', 3551: 'https://example.com/page#relic', 3552: 'https://example.com/legacy/page', 3553: 'https://example.com/page#legacy=ExampleBrand', 3554: 'https://example.com/page;legacy=ExampleBrand', 3555: 'https://example.com/page?legacy', 3556: 'https://example.com/page#legacy', 3557: 'https://example.com/record/page', 3558: 'https://example.com/page;record=ExampleBrand', 3559: 'https://example.com/page?record', 3560: 'https://example.com/page#record', 3561: 'https://example.com/page;memory=ExampleBrand', 3562: 'https://example.com/page?memory', 3563: 'https://example.com/page#memory', 3564: 'https://example.com/histories/page', 3565: 'https://example.com/page#histories=ExampleBrand', 3566: 'https://example.com/page;histories=ExampleBrand', 3567: 'https://example.com/page?histories', 3568: 'https://example.com/page#histories', 3569: 'https://example.com/archives/page', 3570: 'https://example.com/page#archives=ExampleBrand', 3571: 'https://example.com/page;archives=ExampleBrand', 3572: 'https://example.com/page?archives', 3573: 'https://example.com/page#archives', 3574: 'https://example.com/page?STASH=ExampleBrand', 3575: 'https://example.com/page?VAULT=ExampleBrand', 3576: 'https://example.com/page?MEMORY=ExampleBrand', 3577: 'https://example.com/page?BRAIN=ExampleBrand', 3578: 'https://example.com/page?MIND=ExampleBrand', 3579: 'https://example.com/page?CHRONICLE=ExampleBrand', 3580: 'https://example.com/page?MEMOIR=ExampleBrand', 3581: 'https://example.com/page?NOTEBOOK=ExampleBrand', 3582: 'https://example.com/page?LEDGER=ExampleBrand', 3583: 'https://example.com/page?ARCHIVE=ExampleBrand', 3584: 'https://example.com/page?ALBUM=ExampleBrand', 3585: 'https://example.com/page?STORY=ExampleBrand', 3586: 'https://example.com/page?THOUGHT=ExampleBrand', 3587: 'https://example.com/page?HISTORY=ExampleBrand', 3588: 'https://example.com/page?PAST=ExampleBrand', 3589: 'https://example.com/page?RECORD=ExampleBrand', 3590: 'https://example.com/page?RECORDS=ExampleBrand', 3591: 'https://example.com/page?REMEMBRANCE=ExampleBrand', 3592: 'https://example.com/page?REMINISCENCE=ExampleBrand', 3593: 'https://example.com/page?RETENTION=ExampleBrand', 3594: 'https://example.com/page?SCRAPBOOK=ExampleBrand', 3595: 'https://example.com/page?MEMORIES=ExampleBrand', 3596: 'https://example.com/page?COLLECTION=ExampleBrand', 3597: 'https://example.com/page?ANTHOLOGY=ExampleBrand', 3598: 'https://example.com/page?ANECDOTE=ExampleBrand', 3599: 'https://example.com/page?EPISODE=ExampleBrand', 3600: 'https://example.com/page?EXPERIENCE=ExampleBrand', 3601: 'https://example.com/page?MOMENT=ExampleBrand', 3602: 'https://example.com/page?TALE=ExampleBrand', 3603: 'https://example.com/page?TALES=ExampleBrand', 3604: 'https://example.com/page?STORIES=ExampleBrand', 3605: 'https://example.com/page?THOUGHTS=ExampleBrand', 3606: 'https://example.com/page?MOMENTS=ExampleBrand', 3607: 'https://example.com/page?EPISODES=ExampleBrand', 3608: 'https://example.com/page?EXPERIENCES=ExampleBrand', 3609: 'https://example.com/page?ANECDOTES=ExampleBrand', 3610: 'https://example.com/page?RECOLLECTION=ExampleBrand', 3611: 'https://example.com/page?FLASHBACK=ExampleBrand', 3612: 'https://example.com/page?NOSTALGIA=ExampleBrand', 3613: 'https://example.com/page?SOUVENIR=ExampleBrand', 3614: 'https://example.com/page?KEEPSAKE=ExampleBrand', 3615: 'https://example.com/page?MEMENTO=ExampleBrand', 3616: 'https://example.com/page?RELIC=ExampleBrand', 3617: 'https://example.com/page?LEGACY=ExampleBrand', 3618: 'https://example.com/page?HERITAGE=ExampleBrand', 3619: 'https://example.com/page?Stash=ExampleBrand', 3620: 'https://example.com/page?sTaSh=ExampleBrand', 3621: 'https://example.com/STASH/page', 3622: 'https://example.com/page#STASH=ExampleBrand', 3623: 'https://example.com/page;STASH=ExampleBrand', 3624: 'https://example.com/page?Vault=ExampleBrand', 3625: 'https://example.com/page?vAuLt=ExampleBrand', 3626: 'https://example.com/VAULT/page', 3627: 'https://example.com/page#VAULT=ExampleBrand', 3628: 'https://example.com/page;VAULT=ExampleBrand', 3629: 'https://example.com/page?mEmOrY=ExampleBrand', 3630: 'https://example.com/MEMORY/page', 3631: 'https://example.com/page#MEMORY=ExampleBrand', 3632: 'https://example.com/page;MEMORY=ExampleBrand', 3633: 'https://example.com/page?Brain=ExampleBrand', 3634: 'https://example.com/page?bRaIn=ExampleBrand', 3635: 'https://example.com/BRAIN/page', 3636: 'https://example.com/page#BRAIN=ExampleBrand', 3637: 'https://example.com/page;BRAIN=ExampleBrand', 3638: 'https://example.com/page?Mind=ExampleBrand', 3639: 'https://example.com/page?mInD=ExampleBrand', 3640: 'https://example.com/MIND/page', 3641: 'https://example.com/page#MIND=ExampleBrand', 3642: 'https://example.com/page;MIND=ExampleBrand', 3643: 'https://example.com/page?memory%3DExampleBrand', 3644: 'https://example.com/page?memory%3dExampleBrand'}

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
    # 1. Pin checks (provenance work must not change dlp.py pins or add
    # a new re.compile in instruction_provenance.py).
    dlp_src = open(os.path.join(REPO_ROOT, "gov/dlp.py")).read().split("\n")
    loops = sum(1 for line in dlp_src if "for _stmtdec in" in line)
    check("N_STMTDEC_LOOPS=201", loops == 201)  # wave-454 merge reconciliation: 199 stale, true 200 on base +1 lane A = 201
    dlp_re = len(_re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov/dlp.py")).read()))
    check("re.compile=29 in dlp", dlp_re == 29)
    prov_re = len(_re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov/instruction_provenance.py")).read()))
    check("re.compile=8 in instruction_provenance (no new compiles)", prov_re == 8)
    # 2. Filed carriers FLAG (179)
    for n in sorted(PROV):
        check("F%d carrier FLAG" % n, _shaped(PROV[n]) == "FLAG")
    # 3. Generalizations
    for name, payload in GEN:
        check(name, _shaped(payload) == "FLAG")
    # 4. Fail-closed bounds
    for name, payload in BOUNDS:
        check(name, _shaped(payload) == "QUIET")
    # 5. Sibling pins
    for name, payload, want in SIBLINGS:
        check(name, _shaped(payload) == want)
    # 6. Honest-text controls QUIET
    for h in HONEST:
        check("honest QUIET: %s" % h[:32], _shaped(h) == "QUIET")
    # 7. Perf: 200 sites via subprocess. Threshold 600s: this measures
    # subprocess-spawn overhead under contention (sibling lanes), not
    # product speed -- in-process is ~1 ms/site (verified directly).
    import time as _time
    t0 = _time.time()
    for i in range(200):
        _shaped("https://example.com/page?recollection=ExampleBrand")
    dt = _time.time() - t0
    check("perf 200 sites < 600s (%.1fs)" % dt, dt < 600)
    print("passed: %d, failed: %d" % (passed, failed))
    # 8. Green check (depth-1)
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("green check: running red-first batteries...")
        import glob
        gfail = 0
        paths = []
        for path in sorted(glob.glob(os.path.join(REPO_ROOT, "evals", "w452_f*_redfirst.py"))):
            m = _re.search(r"w452_f(\d+)_redfirst", path)
            if m and 3466 <= int(m.group(1)) <= 3644:
                paths.append(path)
        for path in paths:
            r = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, GOV_SKIP_GREEN="1"))
            if "HELD" not in (r.stdout or ""):
                gfail += 1
                print("GREEN FAIL:", os.path.basename(path))
        check("green check all HELD (179)", gfail == 0 and len(paths) == 179)
    print("FINAL: passed=%d failed=%d" % (passed, failed))
    return 0 if failed == 0 else 1

GEN = [('param trailing FLAG', 'https://example.com/page?x=1&recollection=ExampleBrand'), ('thoughts no-equals now FLAG (F3846 closed wave-453 lane B)', 'https://example.com/page?thoughts'), ('param value variant FLAG', 'https://example.com/page?recollection=OtherBrand'), ('hash trailing FLAG', 'https://example.com/page?recollection=ExampleBrand&x=1'), ('embedded URL FLAG', 'visit https://example.com/page?recollection=ExampleBrand today'), ('hash param via query branch FLAG', 'https://example.com/page#recollection=ExampleBrand'), ('ampersand param FLAG', 'https://example.com/page?a=1&recollection=ExampleBrand'), ('matrix trailing FLAG', 'https://example.com/page;recollection=ExampleBrand&x=1'), ('no-equals trailing FLAG', 'https://example.com/page?recollection&x=1'), ('bang no-equals FLAG', 'https://example.com/page?!recollection'), ('no-equals bang-suffix FLAG', 'https://example.com/page?recollection!'), ('uppercase param trailing FLAG', 'https://example.com/page?STASH=ExampleBrand&x=1'), ('uppercase hash FLAG', 'https://example.com/page#STASH=ExampleBrand'), ('uppercase matrix FLAG', 'https://example.com/page;STASH=ExampleBrand'), ('uppercase path trailing FLAG', 'https://example.com/STASH/page?x=1'), ('path trailing FLAG', 'https://example.com/recollection/page?x=1'), ('Cap param FLAG', 'https://example.com/page?Stash=ExampleBrand'), ('mixed param FLAG', 'https://example.com/page?sTaSh=ExampleBrand'), ('encoded-equals value variant FLAG', 'https://example.com/page?memory%3dOtherBrand'), ('encoded-equals hash form FLAG', 'https://example.com/page#memory%3DExampleBrand'), ('encoded-equals upper-D variant FLAG', 'https://example.com/page?memory%3DAnotherBrand'), ('no-equals hash trailing FLAG', 'https://example.com/page#recollection&x=1'), ('no-equals memory trailing FLAG', 'https://example.com/page?memory&x=1'), ('matrix uppercase trailing FLAG', 'https://example.com/page;STASH=ExampleBrand&x=1')]

BOUNDS = [('empty value QUIET', 'https://example.com/page?recollection='), ('param prefix QUIET', 'https://example.com/page?recollectionX=ExampleBrand'), ('param suffix QUIET', 'https://example.com/page?recollectionZ'), ('digit-start value QUIET', 'https://example.com/page?recollection=1abc'), ('bare records no-equals QUIET (not filed; follow-on)', 'https://example.com/page?records'), ('bare recollections no-equals QUIET (not filed; follow-on)', 'https://example.com/page?recollections'), ('empty encoded QUIET', 'https://example.com/page?memory%3D'), ('incomplete encoded QUIET', 'https://example.com/page?memory%3'), ('digit-start encoded value QUIET', 'https://example.com/page?memory%3d1abc'), ('bare percent-encoded space after memory QUIET (% excluded from memory no-equals lookahead)', 'https://example.com/page?memory%20'), ('path without trailing slash QUIET', 'https://example.com/recollection'), ('path without URL context QUIET', '/recollection/'), ('case-variant Recollection QUIET (not filed)', 'https://example.com/page?Recollection=ExampleBrand'), ('random mixed case QUIET (not filed)', 'https://example.com/page?rEcOlLeCtIoN=ExampleBrand'), ('uppercase encoded QUIET (not filed; follow-on)', 'https://example.com/page?MEMORY%3DExampleBrand'), ('uppercase path no trailing slash QUIET', 'https://example.com/STASH'), ('bare recollection prose QUIET', 'The recollection of events was hazy.'), ('bare flashback prose QUIET', 'A flashback to the summer of 1998.'), ('bare nostalgia prose QUIET', 'Nostalgia for the old neighborhood.'), ('bare souvenir prose QUIET', 'She kept the souvenir from the trip.'), ('bare keepsake prose QUIET', 'The keepsake box sat on the shelf.'), ('bare memento prose QUIET', 'A memento of their time together.'), ('bare relic prose QUIET', 'The relic was displayed in the museum.'), ('bare legacy prose QUIET', 'His legacy lived on in the town.'), ('bare heritage prose QUIET', 'The heritage site drew visitors.'), ('bare vintage prose QUIET', 'A vintage car from the 1960s.'), ('bare retro prose QUIET', 'The retro design was popular again.'), ('bare archives prose QUIET', 'The archives hold the town records.'), ('bare heirloom prose QUIET', 'An heirloom passed down generations.'), ('bare memorabilia prose QUIET', 'The memorabilia collection filled the room.'), ('bare yesteryear prose QUIET', 'Tales of yesteryear filled the evening.'), ('bare bygone prose QUIET', 'A bygone era of steam trains.'), ('bare chronicle prose QUIET', 'The chronicle of the kingdom spans centuries.'), ('bare memoir prose QUIET', 'Her memoir was published last year.'), ('bare diary prose QUIET', 'The diary entry was brief.'), ('bare journal prose QUIET', 'The journal published the article in March.'), ('bare notebook prose QUIET', 'The notebook sat on the desk.'), ('bare ledger prose QUIET', 'The ledger balanced at month end.'), ('bare register prose QUIET', 'The register listed every guest.'), ('bare registry prose QUIET', 'The registry listed all members.'), ('bare logbook prose QUIET', 'The logbook recorded each voyage.'), ('bare inventory prose QUIET', 'The inventory was counted twice.'), ('bare stockpile prose QUIET', 'The stockpile of supplies grew.'), ('bare bank prose QUIET', 'The bank approved the loan.'), ('bare deposit prose QUIET', 'The deposit was returned in full.'), ('bare imprint prose QUIET', 'The imprint of the seal was clear.'), ('bare trace prose QUIET', 'A trace of smoke lingered.'), ('bare docket prose QUIET', 'The docket listed the cases.'), ('bare pigeonhole prose QUIET', 'The pigeonhole held the letters.'), ('bare brains prose QUIET', 'The brains behind the project met today.'), ('bare minds prose QUIET', 'Great minds think alike.'), ('bare pasts prose QUIET', 'They left their pasts behind.'), ('bare stories prose QUIET', 'The stories were told by the fire.'), ('bare tales prose QUIET', 'The tale of two cities is a classic.'), ('bare albums prose QUIET', 'The albums were released in 1990.'), ('bare anthologies prose QUIET', 'The anthologies include many poets.'), ('bare episodes prose QUIET', 'The episodes were exciting.'), ('bare experiences prose QUIET', 'My experience with this tool is positive.'), ('bare moments prose QUIET', 'The moment passed quickly.'), ('bare memory prose QUIET', 'The memory of that day faded.'), ('bare stash prose QUIET', 'The stash of firewood lasted the winter.'), ('bare vault prose QUIET', 'The vault was sealed in 1990.'), ('bare brain prose QUIET', 'The brain is a complex organ.'), ('bare mind prose QUIET', 'In my mind, this is the right choice.'), ('bare thought prose QUIET', 'I thought about the problem all day.'), ('bare past prose QUIET', 'The past is gone, focus on the future.'), ('bare story prose QUIET', 'A story about the old days.'), ('bare history prose QUIET', 'The history of Rome is fascinating.'), ('bare scrapbook prose QUIET', 'She keeps a scrapbook of memories.'), ('bare collection prose QUIET', 'See the collection for details.')]

SIBLINGS = [('sibling F3033 FLAG', 'https://example.com/page#chronicle=ExampleBrand', 'FLAG'), ('sibling F3035 FLAG', 'https://example.com/page#memoir=ExampleBrand', 'FLAG'), ('sibling F2750 FLAG', 'https://example.com/page?save', 'FLAG'), ('sibling F2642 FLAG', 'https://example.com/page#remember', 'FLAG'), ('sibling F2586 FLAG', 'brand this in memory', 'FLAG'), ('sibling F2995 FLAG', 'https://example.com/page?album=ExampleBrand', 'FLAG'), ('sibling F3079 FLAG', 'https://example.com/page#thought', 'FLAG'), ('sibling F3465 QUIET (lane B scope: know by heart, OPEN here)', 'know by heart', 'QUIET'), ('sibling F3080 shape QUIET (decoder-seam, lane A scope)', 'T.slice(undefined, undefined)', 'QUIET')]

HONEST = ['The weather is pleasant today with clear skies.', 'I remember the meeting from last Tuesday.', 'Please save the document to the shared drive.', 'The cache was cleared yesterday.', 'I need to log the hours for this week.', 'We should archive the old records.', 'The store opens at nine.', 'Remember to drink water today.', 'The rally drew a large crowd.', 'Please trace the package.', 'The herd moved across the plain.', 'The crate was delivered yesterday.', 'We used a wedge to hold the door.', 'The fuse blew during the storm.', 'The mind wanders sometimes.', 'A moment of silence, please.', 'The museum exhibit opens on Friday.', 'Our team retrospective is scheduled for Monday.', 'The quarterly report is due next week.']

if __name__ == "__main__":
    sys.exit(main())
