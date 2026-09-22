# Red-team test package for the agent-governance product (threats T1-T4, T11).

# R6c dev-key opt-in for the test harness: the suite runs against the
# public development key with zero configuration. BOTH factors are set
# here explicitly in code — env vars alone, or the in-code call alone,
# never enable dev keys. Production entry points never do this.
import os
os.environ.setdefault("GOV_DEV_KEYS", "1")
# Wave-37: the TEST-ONLY demonstration_cipher in gov/platform_egress.py
# requires GOV_DEMO_CIPHER_OK=1 on top of the explicit pass, so a
# production copy-paste of the test call fails loud. The suite is a
# synthetic context -- opt in here, explicitly in code (production
# entry points never do this).
os.environ.setdefault("GOV_DEMO_CIPHER_OK", "1")
from gov.log import enable_dev_keys
enable_dev_keys()
