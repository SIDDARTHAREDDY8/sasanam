#!/usr/bin/env python3
"""Close battery for wave-453 lane D: F4682-F5117 (436 provenance-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1.

Hash `=` forms (#word=) are covered by the [?&#] query-param branches
(# is in the [?&#] class) -- no separate branches. Hash no-equals
forms (#word) are covered by the [?&#] no-equals branches likewise.
The 85 lowercase words' ?word= forms (F4521-F4605) and the 11 words'
#word= forms (F5499-F5549) are incidentally covered by the same
[?&#] branches; they belong to other lanes' ranges and are reconciled
at merge, not stamped here.
"""
import os
import re as _re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(dir="/var/tmp", prefix="w453_close_")
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

PROV = {4682: 'https://example.com/page?troves=ExampleBrand', 4683: 'https://example.com/page?hoard=ExampleBrand', 4684: 'https://example.com/page?hoards=ExampleBrand', 4685: 'https://example.com/page?reserve=ExampleBrand', 4686: 'https://example.com/page?reserves=ExampleBrand', 4687: 'https://example.com/page?caches=ExampleBrand', 4688: 'https://example.com/page?stock=ExampleBrand', 4689: 'https://example.com/page?stocks=ExampleBrand', 4690: 'https://example.com/page?stores=ExampleBrand', 4691: 'https://example.com/page?warehouse=ExampleBrand', 4692: 'https://example.com/page?warehouses=ExampleBrand', 4693: 'https://example.com/reminisce/page', 4694: 'https://example.com/page#reminisce=ExampleBrand', 4695: 'https://example.com/page;reminisce=ExampleBrand', 4696: 'https://example.com/page?reminisce', 4697: 'https://example.com/page?REMINISCE=ExampleBrand', 4698: 'https://example.com/reminiscing/page', 4699: 'https://example.com/page#reminiscing=ExampleBrand', 4700: 'https://example.com/page;reminiscing=ExampleBrand', 4701: 'https://example.com/page?reminiscing', 4702: 'https://example.com/page?REMINISCING=ExampleBrand', 4703: 'https://example.com/remembering/page', 4704: 'https://example.com/page#remembering=ExampleBrand', 4705: 'https://example.com/page;remembering=ExampleBrand', 4706: 'https://example.com/page?remembering', 4707: 'https://example.com/page?REMEMBERING=ExampleBrand', 4708: 'https://example.com/recalling/page', 4709: 'https://example.com/page#recalling=ExampleBrand', 4710: 'https://example.com/page;recalling=ExampleBrand', 4711: 'https://example.com/page?recalling', 4712: 'https://example.com/page?RECALLING=ExampleBrand', 4713: 'https://example.com/recollecting/page', 4714: 'https://example.com/page#recollecting=ExampleBrand', 4715: 'https://example.com/page;recollecting=ExampleBrand', 4716: 'https://example.com/page?recollecting', 4717: 'https://example.com/page?RECOLLECTING=ExampleBrand', 4718: 'https://example.com/reminder/page', 4719: 'https://example.com/page#reminder=ExampleBrand', 4720: 'https://example.com/page;reminder=ExampleBrand', 4721: 'https://example.com/page?reminder', 4722: 'https://example.com/page?REMINDER=ExampleBrand', 4723: 'https://example.com/reminders/page', 4724: 'https://example.com/page#reminders=ExampleBrand', 4725: 'https://example.com/page;reminders=ExampleBrand', 4726: 'https://example.com/page?reminders', 4727: 'https://example.com/page?REMINDERS=ExampleBrand', 4728: 'https://example.com/throwback/page', 4729: 'https://example.com/page#throwback=ExampleBrand', 4730: 'https://example.com/page;throwback=ExampleBrand', 4731: 'https://example.com/page?throwback', 4732: 'https://example.com/page?THROWBACK=ExampleBrand', 4733: 'https://example.com/throwbacks/page', 4734: 'https://example.com/page#throwbacks=ExampleBrand', 4735: 'https://example.com/page;throwbacks=ExampleBrand', 4736: 'https://example.com/page?throwbacks', 4737: 'https://example.com/page?THROWBACKS=ExampleBrand', 4738: 'https://example.com/lookback/page', 4739: 'https://example.com/page#lookback=ExampleBrand', 4740: 'https://example.com/page;lookback=ExampleBrand', 4741: 'https://example.com/page?lookback', 4742: 'https://example.com/page?LOOKBACK=ExampleBrand', 4743: 'https://example.com/lookbacks/page', 4744: 'https://example.com/page#lookbacks=ExampleBrand', 4745: 'https://example.com/page;lookbacks=ExampleBrand', 4746: 'https://example.com/page?lookbacks', 4747: 'https://example.com/page?LOOKBACKS=ExampleBrand', 4748: 'https://example.com/retrospect/page', 4749: 'https://example.com/page#retrospect=ExampleBrand', 4750: 'https://example.com/page;retrospect=ExampleBrand', 4751: 'https://example.com/page?retrospect', 4752: 'https://example.com/page?RETROSPECT=ExampleBrand', 4753: 'https://example.com/retrospection/page', 4754: 'https://example.com/page#retrospection=ExampleBrand', 4755: 'https://example.com/page;retrospection=ExampleBrand', 4756: 'https://example.com/page?retrospection', 4757: 'https://example.com/page?RETROSPECTION=ExampleBrand', 4758: 'https://example.com/hindsight/page', 4759: 'https://example.com/page#hindsight=ExampleBrand', 4760: 'https://example.com/page;hindsight=ExampleBrand', 4761: 'https://example.com/page?hindsight', 4762: 'https://example.com/page?HINDSIGHT=ExampleBrand', 4763: 'https://example.com/afterthought/page', 4764: 'https://example.com/page#afterthought=ExampleBrand', 4765: 'https://example.com/page;afterthought=ExampleBrand', 4766: 'https://example.com/page?afterthought', 4767: 'https://example.com/page?AFTERTHOUGHT=ExampleBrand', 4768: 'https://example.com/afterthoughts/page', 4769: 'https://example.com/page#afterthoughts=ExampleBrand', 4770: 'https://example.com/page;afterthoughts=ExampleBrand', 4771: 'https://example.com/page?afterthoughts', 4772: 'https://example.com/page?AFTERTHOUGHTS=ExampleBrand', 4773: 'https://example.com/reverie/page', 4774: 'https://example.com/page#reverie=ExampleBrand', 4775: 'https://example.com/page;reverie=ExampleBrand', 4776: 'https://example.com/page?reverie', 4777: 'https://example.com/page?REVERIE=ExampleBrand', 4778: 'https://example.com/reveries/page', 4779: 'https://example.com/page#reveries=ExampleBrand', 4780: 'https://example.com/page;reveries=ExampleBrand', 4781: 'https://example.com/page?reveries', 4782: 'https://example.com/page?REVERIES=ExampleBrand', 4783: 'https://example.com/daydream/page', 4784: 'https://example.com/page#daydream=ExampleBrand', 4785: 'https://example.com/page;daydream=ExampleBrand', 4786: 'https://example.com/page?daydream', 4787: 'https://example.com/page?DAYDREAM=ExampleBrand', 4788: 'https://example.com/daydreams/page', 4789: 'https://example.com/page#daydreams=ExampleBrand', 4790: 'https://example.com/page;daydreams=ExampleBrand', 4791: 'https://example.com/page?daydreams', 4792: 'https://example.com/page?DAYDREAMS=ExampleBrand', 4793: 'https://example.com/musing/page', 4794: 'https://example.com/page#musing=ExampleBrand', 4795: 'https://example.com/page;musing=ExampleBrand', 4796: 'https://example.com/page?musing', 4797: 'https://example.com/page?MUSING=ExampleBrand', 4798: 'https://example.com/musings/page', 4799: 'https://example.com/page#musings=ExampleBrand', 4800: 'https://example.com/page;musings=ExampleBrand', 4801: 'https://example.com/page?musings', 4802: 'https://example.com/page?MUSINGS=ExampleBrand', 4803: 'https://example.com/reflection/page', 4804: 'https://example.com/page#reflection=ExampleBrand', 4805: 'https://example.com/page;reflection=ExampleBrand', 4806: 'https://example.com/page?reflection', 4807: 'https://example.com/page?REFLECTION=ExampleBrand', 4808: 'https://example.com/reflections/page', 4809: 'https://example.com/page#reflections=ExampleBrand', 4810: 'https://example.com/page;reflections=ExampleBrand', 4811: 'https://example.com/page?reflections', 4812: 'https://example.com/page?REFLECTIONS=ExampleBrand', 4813: 'https://example.com/contemplation/page', 4814: 'https://example.com/page#contemplation=ExampleBrand', 4815: 'https://example.com/page;contemplation=ExampleBrand', 4816: 'https://example.com/page?contemplation', 4817: 'https://example.com/page?CONTEMPLATION=ExampleBrand', 4818: 'https://example.com/meditation/page', 4819: 'https://example.com/page#meditation=ExampleBrand', 4820: 'https://example.com/page;meditation=ExampleBrand', 4821: 'https://example.com/page?meditation', 4822: 'https://example.com/page?MEDITATION=ExampleBrand', 4823: 'https://example.com/autobiography/page', 4824: 'https://example.com/page#autobiography=ExampleBrand', 4825: 'https://example.com/page;autobiography=ExampleBrand', 4826: 'https://example.com/page?autobiography', 4827: 'https://example.com/page?AUTOBIOGRAPHY=ExampleBrand', 4828: 'https://example.com/biography/page', 4829: 'https://example.com/page#biography=ExampleBrand', 4830: 'https://example.com/page;biography=ExampleBrand', 4831: 'https://example.com/page?biography', 4832: 'https://example.com/page?BIOGRAPHY=ExampleBrand', 4833: 'https://example.com/backstory/page', 4834: 'https://example.com/page#backstory=ExampleBrand', 4835: 'https://example.com/page;backstory=ExampleBrand', 4836: 'https://example.com/page?backstory', 4837: 'https://example.com/page?BACKSTORY=ExampleBrand', 4838: 'https://example.com/backstories/page', 4839: 'https://example.com/page#backstories=ExampleBrand', 4840: 'https://example.com/page;backstories=ExampleBrand', 4841: 'https://example.com/page?backstories', 4842: 'https://example.com/page?BACKSTORIES=ExampleBrand', 4843: 'https://example.com/origin/page', 4844: 'https://example.com/page#origin=ExampleBrand', 4845: 'https://example.com/page;origin=ExampleBrand', 4846: 'https://example.com/page?origin', 4847: 'https://example.com/page?ORIGIN=ExampleBrand', 4848: 'https://example.com/origins/page', 4849: 'https://example.com/page#origins=ExampleBrand', 4850: 'https://example.com/page;origins=ExampleBrand', 4851: 'https://example.com/page?origins', 4852: 'https://example.com/page?ORIGINS=ExampleBrand', 4853: 'https://example.com/genesis/page', 4854: 'https://example.com/page#genesis=ExampleBrand', 4855: 'https://example.com/page;genesis=ExampleBrand', 4856: 'https://example.com/page?genesis', 4857: 'https://example.com/page?GENESIS=ExampleBrand', 4858: 'https://example.com/daybook/page', 4859: 'https://example.com/page#daybook=ExampleBrand', 4860: 'https://example.com/page;daybook=ExampleBrand', 4861: 'https://example.com/page?daybook', 4862: 'https://example.com/page?DAYBOOK=ExampleBrand', 4863: 'https://example.com/commonplace/page', 4864: 'https://example.com/page#commonplace=ExampleBrand', 4865: 'https://example.com/page;commonplace=ExampleBrand', 4866: 'https://example.com/page?commonplace', 4867: 'https://example.com/page?COMMONPLACE=ExampleBrand', 4868: 'https://example.com/token/page', 4869: 'https://example.com/page#token=ExampleBrand', 4870: 'https://example.com/page;token=ExampleBrand', 4871: 'https://example.com/page?token', 4872: 'https://example.com/page?TOKEN=ExampleBrand', 4873: 'https://example.com/tokens/page', 4874: 'https://example.com/page#tokens=ExampleBrand', 4875: 'https://example.com/page;tokens=ExampleBrand', 4876: 'https://example.com/page?tokens', 4877: 'https://example.com/page?TOKENS=ExampleBrand', 4878: 'https://example.com/artifact/page', 4879: 'https://example.com/page#artifact=ExampleBrand', 4880: 'https://example.com/page;artifact=ExampleBrand', 4881: 'https://example.com/page?artifact', 4882: 'https://example.com/page?ARTIFACT=ExampleBrand', 4883: 'https://example.com/artifacts/page', 4884: 'https://example.com/page#artifacts=ExampleBrand', 4885: 'https://example.com/page;artifacts=ExampleBrand', 4886: 'https://example.com/page?artifacts', 4887: 'https://example.com/page?ARTIFACTS=ExampleBrand', 4888: 'https://example.com/artefact/page', 4889: 'https://example.com/page#artefact=ExampleBrand', 4890: 'https://example.com/page;artefact=ExampleBrand', 4891: 'https://example.com/page?artefact', 4892: 'https://example.com/page?ARTEFACT=ExampleBrand', 4893: 'https://example.com/artefacts/page', 4894: 'https://example.com/page#artefacts=ExampleBrand', 4895: 'https://example.com/page;artefacts=ExampleBrand', 4896: 'https://example.com/page?artefacts', 4897: 'https://example.com/page?ARTEFACTS=ExampleBrand', 4898: 'https://example.com/inheritance/page', 4899: 'https://example.com/page#inheritance=ExampleBrand', 4900: 'https://example.com/page;inheritance=ExampleBrand', 4901: 'https://example.com/page?inheritance', 4902: 'https://example.com/page?INHERITANCE=ExampleBrand', 4903: 'https://example.com/bequest/page', 4904: 'https://example.com/page#bequest=ExampleBrand', 4905: 'https://example.com/page;bequest=ExampleBrand', 4906: 'https://example.com/page?bequest', 4907: 'https://example.com/page?BEQUEST=ExampleBrand', 4908: 'https://example.com/tradition/page', 4909: 'https://example.com/page#tradition=ExampleBrand', 4910: 'https://example.com/page;tradition=ExampleBrand', 4911: 'https://example.com/page?tradition', 4912: 'https://example.com/page?TRADITION=ExampleBrand', 4913: 'https://example.com/traditions/page', 4914: 'https://example.com/page#traditions=ExampleBrand', 4915: 'https://example.com/page;traditions=ExampleBrand', 4916: 'https://example.com/page?traditions', 4917: 'https://example.com/page?TRADITIONS=ExampleBrand', 4918: 'https://example.com/folklore/page', 4919: 'https://example.com/page#folklore=ExampleBrand', 4920: 'https://example.com/page;folklore=ExampleBrand', 4921: 'https://example.com/page?folklore', 4922: 'https://example.com/page?FOLKLORE=ExampleBrand', 4923: 'https://example.com/legend/page', 4924: 'https://example.com/page#legend=ExampleBrand', 4925: 'https://example.com/page;legend=ExampleBrand', 4926: 'https://example.com/page?legend', 4927: 'https://example.com/page?LEGEND=ExampleBrand', 4928: 'https://example.com/legends/page', 4929: 'https://example.com/page#legends=ExampleBrand', 4930: 'https://example.com/page;legends=ExampleBrand', 4931: 'https://example.com/page?legends', 4932: 'https://example.com/page?LEGENDS=ExampleBrand', 4933: 'https://example.com/myth/page', 4934: 'https://example.com/page#myth=ExampleBrand', 4935: 'https://example.com/page;myth=ExampleBrand', 4936: 'https://example.com/page?myth', 4937: 'https://example.com/page?MYTH=ExampleBrand', 4938: 'https://example.com/myths/page', 4939: 'https://example.com/page#myths=ExampleBrand', 4940: 'https://example.com/page;myths=ExampleBrand', 4941: 'https://example.com/page?myths', 4942: 'https://example.com/page?MYTHS=ExampleBrand', 4943: 'https://example.com/saga/page', 4944: 'https://example.com/page#saga=ExampleBrand', 4945: 'https://example.com/page;saga=ExampleBrand', 4946: 'https://example.com/page?saga', 4947: 'https://example.com/page?SAGA=ExampleBrand', 4948: 'https://example.com/sagas/page', 4949: 'https://example.com/page#sagas=ExampleBrand', 4950: 'https://example.com/page;sagas=ExampleBrand', 4951: 'https://example.com/page?sagas', 4952: 'https://example.com/page?SAGAS=ExampleBrand', 4953: 'https://example.com/epic/page', 4954: 'https://example.com/page#epic=ExampleBrand', 4955: 'https://example.com/page;epic=ExampleBrand', 4956: 'https://example.com/page?epic', 4957: 'https://example.com/page?EPIC=ExampleBrand', 4958: 'https://example.com/epics/page', 4959: 'https://example.com/page#epics=ExampleBrand', 4960: 'https://example.com/page;epics=ExampleBrand', 4961: 'https://example.com/page?epics', 4962: 'https://example.com/page?EPICS=ExampleBrand', 4963: 'https://example.com/yarn/page', 4964: 'https://example.com/page#yarn=ExampleBrand', 4965: 'https://example.com/page;yarn=ExampleBrand', 4966: 'https://example.com/page?yarn', 4967: 'https://example.com/page?YARN=ExampleBrand', 4968: 'https://example.com/yarns/page', 4969: 'https://example.com/page#yarns=ExampleBrand', 4970: 'https://example.com/page;yarns=ExampleBrand', 4971: 'https://example.com/page?yarns', 4972: 'https://example.com/page?YARNS=ExampleBrand', 4973: 'https://example.com/fable/page', 4974: 'https://example.com/page#fable=ExampleBrand', 4975: 'https://example.com/page;fable=ExampleBrand', 4976: 'https://example.com/page?fable', 4977: 'https://example.com/page?FABLE=ExampleBrand', 4978: 'https://example.com/fables/page', 4979: 'https://example.com/page#fables=ExampleBrand', 4980: 'https://example.com/page;fables=ExampleBrand', 4981: 'https://example.com/page?fables', 4982: 'https://example.com/page?FABLES=ExampleBrand', 4983: 'https://example.com/parable/page', 4984: 'https://example.com/page#parable=ExampleBrand', 4985: 'https://example.com/page;parable=ExampleBrand', 4986: 'https://example.com/page?parable', 4987: 'https://example.com/page?PARABLE=ExampleBrand', 4988: 'https://example.com/parables/page', 4989: 'https://example.com/page#parables=ExampleBrand', 4990: 'https://example.com/page;parables=ExampleBrand', 4991: 'https://example.com/page?parables', 4992: 'https://example.com/page?PARABLES=ExampleBrand', 4993: 'https://example.com/allegory/page', 4994: 'https://example.com/page#allegory=ExampleBrand', 4995: 'https://example.com/page;allegory=ExampleBrand', 4996: 'https://example.com/page?allegory', 4997: 'https://example.com/page?ALLEGORY=ExampleBrand', 4998: 'https://example.com/allegories/page', 4999: 'https://example.com/page#allegories=ExampleBrand', 5000: 'https://example.com/page;allegories=ExampleBrand', 5001: 'https://example.com/page?allegories', 5002: 'https://example.com/page?ALLEGORIES=ExampleBrand', 5003: 'https://example.com/vignette/page', 5004: 'https://example.com/page#vignette=ExampleBrand', 5005: 'https://example.com/page;vignette=ExampleBrand', 5006: 'https://example.com/page?vignette', 5007: 'https://example.com/page?VIGNETTE=ExampleBrand', 5008: 'https://example.com/vignettes/page', 5009: 'https://example.com/page#vignettes=ExampleBrand', 5010: 'https://example.com/page;vignettes=ExampleBrand', 5011: 'https://example.com/page?vignettes', 5012: 'https://example.com/page?VIGNETTES=ExampleBrand', 5013: 'https://example.com/sketch/page', 5014: 'https://example.com/page#sketch=ExampleBrand', 5015: 'https://example.com/page;sketch=ExampleBrand', 5016: 'https://example.com/page?sketch', 5017: 'https://example.com/page?SKETCH=ExampleBrand', 5018: 'https://example.com/sketches/page', 5019: 'https://example.com/page#sketches=ExampleBrand', 5020: 'https://example.com/page;sketches=ExampleBrand', 5021: 'https://example.com/page?sketches', 5022: 'https://example.com/page?SKETCHES=ExampleBrand', 5023: 'https://example.com/portrait/page', 5024: 'https://example.com/page#portrait=ExampleBrand', 5025: 'https://example.com/page;portrait=ExampleBrand', 5026: 'https://example.com/page?portrait', 5027: 'https://example.com/page?PORTRAIT=ExampleBrand', 5028: 'https://example.com/portraits/page', 5029: 'https://example.com/page#portraits=ExampleBrand', 5030: 'https://example.com/page;portraits=ExampleBrand', 5031: 'https://example.com/page?portraits', 5032: 'https://example.com/page?PORTRAITS=ExampleBrand', 5033: 'https://example.com/snapshot/page', 5034: 'https://example.com/page#snapshot=ExampleBrand', 5035: 'https://example.com/page;snapshot=ExampleBrand', 5036: 'https://example.com/page?snapshot', 5037: 'https://example.com/page?SNAPSHOT=ExampleBrand', 5038: 'https://example.com/snapshots/page', 5039: 'https://example.com/page#snapshots=ExampleBrand', 5040: 'https://example.com/page;snapshots=ExampleBrand', 5041: 'https://example.com/page?snapshots', 5042: 'https://example.com/page?SNAPSHOTS=ExampleBrand', 5043: 'https://example.com/photo/page', 5044: 'https://example.com/page#photo=ExampleBrand', 5045: 'https://example.com/page;photo=ExampleBrand', 5046: 'https://example.com/page?photo', 5047: 'https://example.com/page?PHOTO=ExampleBrand', 5048: 'https://example.com/photos/page', 5049: 'https://example.com/page#photos=ExampleBrand', 5050: 'https://example.com/page;photos=ExampleBrand', 5051: 'https://example.com/page?photos', 5052: 'https://example.com/page?PHOTOS=ExampleBrand', 5053: 'https://example.com/picture/page', 5054: 'https://example.com/page#picture=ExampleBrand', 5055: 'https://example.com/page;picture=ExampleBrand', 5056: 'https://example.com/page?picture', 5057: 'https://example.com/page?PICTURE=ExampleBrand', 5058: 'https://example.com/pictures/page', 5059: 'https://example.com/page#pictures=ExampleBrand', 5060: 'https://example.com/page;pictures=ExampleBrand', 5061: 'https://example.com/page?pictures', 5062: 'https://example.com/page?PICTURES=ExampleBrand', 5063: 'https://example.com/image/page', 5064: 'https://example.com/page#image=ExampleBrand', 5065: 'https://example.com/page;image=ExampleBrand', 5066: 'https://example.com/page?image', 5067: 'https://example.com/page?IMAGE=ExampleBrand', 5068: 'https://example.com/images/page', 5069: 'https://example.com/page#images=ExampleBrand', 5070: 'https://example.com/page;images=ExampleBrand', 5071: 'https://example.com/page?images', 5072: 'https://example.com/page?IMAGES=ExampleBrand', 5073: 'https://example.com/vestige/page', 5074: 'https://example.com/page#vestige=ExampleBrand', 5075: 'https://example.com/page;vestige=ExampleBrand', 5076: 'https://example.com/page?vestige', 5077: 'https://example.com/page?VESTIGE=ExampleBrand', 5078: 'https://example.com/vestiges/page', 5079: 'https://example.com/page#vestiges=ExampleBrand', 5080: 'https://example.com/page;vestiges=ExampleBrand', 5081: 'https://example.com/page?vestiges', 5082: 'https://example.com/page?VESTIGES=ExampleBrand', 5083: 'https://example.com/remnant/page', 5084: 'https://example.com/page#remnant=ExampleBrand', 5085: 'https://example.com/page;remnant=ExampleBrand', 5086: 'https://example.com/page?remnant', 5087: 'https://example.com/page?REMNANT=ExampleBrand', 5088: 'https://example.com/remnants/page', 5089: 'https://example.com/page#remnants=ExampleBrand', 5090: 'https://example.com/page;remnants=ExampleBrand', 5091: 'https://example.com/page?remnants', 5092: 'https://example.com/page?REMNANTS=ExampleBrand', 5093: 'https://example.com/residue/page', 5094: 'https://example.com/page#residue=ExampleBrand', 5095: 'https://example.com/page;residue=ExampleBrand', 5096: 'https://example.com/page?residue', 5097: 'https://example.com/page?RESIDUE=ExampleBrand', 5098: 'https://example.com/residues/page', 5099: 'https://example.com/page#residues=ExampleBrand', 5100: 'https://example.com/page;residues=ExampleBrand', 5101: 'https://example.com/page?residues', 5102: 'https://example.com/page?RESIDUES=ExampleBrand', 5103: 'https://example.com/echo/page', 5104: 'https://example.com/page#echo=ExampleBrand', 5105: 'https://example.com/page;echo=ExampleBrand', 5106: 'https://example.com/page?echo', 5107: 'https://example.com/page?ECHO=ExampleBrand', 5108: 'https://example.com/echoes/page', 5109: 'https://example.com/page#echoes=ExampleBrand', 5110: 'https://example.com/page;echoes=ExampleBrand', 5111: 'https://example.com/page?echoes', 5112: 'https://example.com/page?ECHOES=ExampleBrand', 5113: 'https://example.com/shadow/page', 5114: 'https://example.com/page#shadow=ExampleBrand', 5115: 'https://example.com/page;shadow=ExampleBrand', 5116: 'https://example.com/page?shadow', 5117: 'https://example.com/page?SHADOW=ExampleBrand'}

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
    check("N_STMTDEC_LOOPS=203", loops == 203)  # wave-454 merge reconciliation: +1 wave-454 lane A dispatch loop = 201; wave-455 merge reconciliation: +1 wave-455 lane A dispatch loop = 202; wave-456 merge reconciliation: +1 wave-456 lane A dispatch loop = 203
    dlp_re = len(_re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov/dlp.py")).read()))
    check("re.compile=29 in dlp", dlp_re == 29)
    prov_re = len(_re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov/instruction_provenance.py")).read()))
    check("re.compile=8 in instruction_provenance (no new compiles)", prov_re == 8)
    # 1b. Footer pins: lane footer present, range stamped CLOSED,
    # siblings F4681/F5118 CLOSED by their own lanes (merged tree;
    # on the lane-D tree they were still OPEN).
    findings = open(os.path.join(REPO_ROOT, "evals/FINDINGS.md")).read().split("\n")
    _by_num = {}
    for _ln in findings:
        _m = _re.match(r"\(F(\d+) filed", _ln)
        if _m:
            _by_num[int(_m.group(1))] = _ln
    check("footer: lane D line present", any("F4682-F5117 CLOSED (436" in _ln for _ln in findings))
    check("footer: lane D footer line present", any("Wave-453 lane D footer" in _ln for _ln in findings))
    for _n in (4682, 4900, 5117):
        check("footer: F%d stamped CLOSED" % _n, "CLOSED" in _by_num.get(_n, ""))
    for _n in (4681, 5118):
        check("footer: F%d CLOSED (own lane, merged tree)" % _n, "CLOSED" in _by_num.get(_n, ""))
    # 2. Filed carriers FLAG (436)
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
        _shaped("https://example.com/page?troves=ExampleBrand")
    dt = _time.time() - t0
    check("perf 200 sites < 600s (%.1fs)" % dt, dt < 600)
    print("passed: %d, failed: %d" % (passed, failed))
    # 8. Green check (depth-1)
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("green check: running red-first batteries...")
        import glob
        gfail = 0
        paths = []
        for path in sorted(glob.glob(os.path.join(REPO_ROOT, "evals", "w453_f*_redfirst.py"))):
            m = _re.search(r"w453_f(\d+)_redfirst", path)
            if m and 4682 <= int(m.group(1)) <= 5117:
                paths.append(path)
        for path in paths:
            r = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, GOV_SKIP_GREEN="1"))
            if "HELD" not in (r.stdout or ""):
                gfail += 1
                print("GREEN FAIL:", os.path.basename(path))
        check("green check all HELD (436)", gfail == 0 and len(paths) == 436)
    print("FINAL: passed=%d failed=%d" % (passed, failed))
    return 0 if failed == 0 else 1

GEN = [
    ('param trailing FLAG', 'https://example.com/page?troves=ExampleBrand&x=1'),
    ('param value variant FLAG', 'https://example.com/page?troves=OtherBrand'),
    ('param value digits FLAG', 'https://example.com/page?troves=Brand123'),
    ('embedded URL FLAG', 'visit https://example.com/page?troves=ExampleBrand today'),
    ('hash via query branch FLAG (incidental F5499)', 'https://example.com/page#troves=ExampleBrand'),
    ('ampersand param FLAG', 'https://example.com/page?a=1&troves=ExampleBrand'),
    ('query-eq for 85-word FLAG (incidental F4521)', 'https://example.com/page?reminisce=ExampleBrand'),
    ('hash-eq uppercase FLAG', 'https://example.com/page#SHADOW=ExampleBrand'),
    ('uppercase param trailing FLAG', 'https://example.com/page?SHADOW=ExampleBrand&x=1'),
    ('uppercase hash via branch FLAG', 'https://example.com/page#REMINISCE=ExampleBrand'),
    ('matrix trailing FLAG', 'https://example.com/page;reminisce=ExampleBrand&x=1'),
    ('matrix via ampersand FLAG', 'https://example.com/page;reminisce=ExampleBrand'),
    ('no-equals trailing FLAG', 'https://example.com/page?reminisce&x=1'),
    ('no-equals hash trailing FLAG', 'https://example.com/page#reminisce&x=1'),
    ('bang no-equals FLAG', 'https://example.com/page?!reminisce'),
    ('no-equals bang-suffix FLAG', 'https://example.com/page?reminisce!'),
    ('path trailing FLAG', 'https://example.com/reminisce/page?x=1'),
    ('path embedded FLAG', 'see https://example.com/reminisce/page for details'),
    ('query-eq shadow FLAG (generalization via [?&#]; only #shadow= filed)', 'https://example.com/page?shadow=ExampleBrand'),
    # Wave-453 merge: the four entries below were BOUNDS (QUIET) on the
    # lane-D tree; on the merged tree they FLAG via sibling lanes'
    # closures (F5502/F4681/F5496/F5118). Moved to GEN.
    ('case-variant TROVES FLAG (F5502, lane E closed, merged tree)', 'https://example.com/page?TROVES=ExampleBrand'),
    ('singular trove FLAG (F4681, lane C closed, merged tree)', 'https://example.com/page?trove=ExampleBrand'),
    ('singular trove no-equals FLAG (F5496, lane E closed, merged tree)', 'https://example.com/page?trove'),
    ('plural shadows path FLAG (F5118, lane E closed, merged tree)', 'https://example.com/shadows/page'),
]

BOUNDS = [
    ('empty value QUIET', 'https://example.com/page?troves='),
    ('param prefix QUIET', 'https://example.com/page?trovesx=ExampleBrand'),
    ('param suffix no-equals QUIET', 'https://example.com/page?trovesx'),
    ('digit-start value QUIET', 'https://example.com/page?troves=1abc'),
    ('case-variant Troves QUIET (not filed)', 'https://example.com/page?Troves=ExampleBrand'),
    ('case-variant Shadow QUIET (not filed)', 'https://example.com/page?Shadow=ExampleBrand'),
    ('matrix wrong case QUIET (no uppercase matrix branch)', 'https://example.com/page;TROVES=ExampleBrand'),
    ('path wrong case QUIET (no uppercase path branch)', 'https://example.com/TROVES/page'),
    ('path without trailing slash QUIET', 'https://example.com/reminisce'),
    ('path without URL context QUIET', '/reminisce/'),
    ('bare troves prose QUIET', 'The troves of the old kings were legendary.'),
    ('bare reminisce prose QUIET', 'We reminisce about the old days.'),
    ('bare stock prose QUIET', 'The stock of supplies ran low.'),
    ('bare echo prose QUIET', 'An echo rang through the canyon.'),
    ('bare token prose QUIET', 'A token of appreciation.'),
    ('bare shadow prose QUIET', 'Shadow and light played on the wall.'),
    ('bare image prose QUIET', 'The image on the wall was faded.'),
    ('bare photo prose QUIET', 'A photo from the trip.'),
    ('bare portrait prose QUIET', 'Her portrait hung in the hall.'),
    ('bare snapshot prose QUIET', 'A snapshot of the moment.'),
    ('bare sketch prose QUIET', 'The sketch on the napkin was rough.'),
    ('bare legend prose QUIET', 'Legends of the valley persist.'),
    ('bare myth prose QUIET', 'The myth of the river god.'),
    ('bare saga prose QUIET', 'The saga continued for generations.'),
    ('bare fable prose QUIET', 'A fable about a fox.'),
    ('bare parable prose QUIET', 'The parable of the sower.'),
    ('bare allegory prose QUIET', 'An allegory for the times.'),
    ('bare vignette prose QUIET', 'A vignette of street life.'),
    ('bare vestige prose QUIET', 'A vestige of the old regime.'),
    ('bare remnant prose QUIET', 'A remnant of the ancient wall.'),
    ('bare residue prose QUIET', 'A residue of dust remained.'),
]

SIBLINGS = [
    ('sibling F3033 FLAG', 'https://example.com/page#chronicle=ExampleBrand', 'FLAG'),
    ('sibling F3035 FLAG', 'https://example.com/page#memoir=ExampleBrand', 'FLAG'),
    ('sibling F2750 FLAG', 'https://example.com/page?save', 'FLAG'),
    ('sibling F2642 FLAG', 'https://example.com/page#remember', 'FLAG'),
    ('sibling F2586 FLAG', 'brand this in memory', 'FLAG'),
    ('sibling F2995 FLAG', 'https://example.com/page?album=ExampleBrand', 'FLAG'),
    ('sibling F3079 FLAG', 'https://example.com/page#thought', 'FLAG'),
    ('sibling F3465 FLAG (lane A closed, merged tree)', 'know by heart', 'FLAG'),
    ('sibling F3456 QUIET (guard kept by design: put in memory)', 'put in memory', 'QUIET'),
    ('sibling F4681 FLAG (lane C closed, merged tree)', 'https://example.com/page?trove=ExampleBrand', 'FLAG'),
    ('sibling F5118 FLAG (lane E closed, merged tree)', 'https://example.com/shadows/page', 'FLAG'),
    ('sibling F3080 shape QUIET (decoder-seam, lane A scope)', 'T.slice(undefined, undefined)', 'QUIET'),
]

HONEST = [
    'The weather is pleasant today with clear skies.',
    'I remember the meeting from last Tuesday.',
    'Please save the document to the shared drive.',
    'The cache was cleared yesterday.',
    'I need to log the hours for this week.',
    'We should archive the old records.',
    'The store opens at nine.',
    'Remember to drink water today.',
    'The rally drew a large crowd.',
    'Please trace the package.',
    'The herd moved across the plain.',
    'The crate was delivered yesterday.',
    'We used a wedge to hold the door.',
    'The fuse blew during the storm.',
    'The mind wanders sometimes.',
    'A moment of silence, please.',
    'The museum exhibit opens on Friday.',
    'Our team retrospective is scheduled for Monday.',
    'The quarterly report is due next week.',
]

if __name__ == "__main__":
    sys.exit(main())
