# Red-team test package for the agent-governance product (threats T1-T4, T11).

# Wave-81: the dev key and every dev-key opt-in are DELETED from gov/
# (``gov.log.enable_dev_keys()`` no longer exists). The suite
# provisions an EXPLICIT key through the same env backend production
# uses (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH -> EnvKeyProvider), with fresh
# random key material per suite process: nothing shared, nothing
# public, no fallback. Test convenience lives only in tests/
# (tests/keyfixture.py); production code cannot reach it.
import os
try:
    from tests.keyfixture import provision_test_key
except ImportError:  # executed with tests/ directly on sys.path
    from keyfixture import provision_test_key
provision_test_key()
# Wave-69: the synthetic suite is not production -- declare it explicitly
# (wave-61 deployment_mode discipline). Wave-81: the key resolver
# validates the mode but no longer selects a key story from it --
# provisioning is explicit in every mode. Kept because gov/sandbox.py
# still reads GOV_DEPLOYMENT_MODE for its seccomp-tier selection.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Wave-37: the TEST-ONLY demonstration_cipher in gov/platform_egress.py
# requires GOV_DEMO_CIPHER_OK=1 on top of the explicit pass, so a
# production copy-paste of the test call fails loud. The suite is a
# synthetic context -- opt in here, explicitly in code (production
# entry points never do this).
os.environ.setdefault("GOV_DEMO_CIPHER_OK", "1")
