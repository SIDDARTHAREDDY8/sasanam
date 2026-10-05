import json, os, sys
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
REPO = os.getcwd()
for _p in (REPO, os.path.join(REPO,"tests"), os.path.join(REPO,"evals")):
    if _p not in sys.path: sys.path.insert(0,_p)
from gov.adapters.openai_agents import UncoveredSurfaceError, audit_agent_coverage, make_tool_input_guardrail
from gov.adapters.core import GovernedBinding
from tests.keyfixture import provision_test_key
provision_test_key()
from tests.harness import make_run
class _Ctx:
    def __init__(s,t,a): s.tool_name=t; s.tool_arguments=a
class _Data:
    def __init__(s,c): s.context=c
class _Tool:
    def __init__(s,n,g): s.name=n; s.tool_input_guardrails=g
class _Agent:
    def __init__(s,t): s.name="x"; s.tools=t; s.handoffs=[]
ctx = make_run()
support = GovernedBinding(ctx["executor"], ctx["mint_identity"]("support-1","support","dev-org"))

# CANDIDATE: guardrail built for framework_tool "read_file" but DECLARES
# expect_sdk_tool_name="delete_file", attached to SDK tool "delete_file".
g = make_tool_input_guardrail(support, "read_file", expect_sdk_tool_name="delete_file")
agent = _Agent([_Tool("delete_file", [g])])
try:
    audit_agent_coverage(agent); certified=True
except UncoveredSurfaceError as e:
    certified=False; print("refused:", str(e)[:120])
print("candidate shape audit certified:", certified)
if certified:
    out = g(_Data(_Ctx("delete_file", json.dumps({"path":"victim.txt"}))))
    info = out.output_info or {}
    print("via guardrail:", out.behavior.get("type"), "framework_tool=", info.get("framework_tool"))
    direct = support.call("delete_file", on_denied="return", on_queued="return", path="victim.txt")
    print("direct delete_file:", direct.get("status"), str(direct.get("reason"))[:60])
