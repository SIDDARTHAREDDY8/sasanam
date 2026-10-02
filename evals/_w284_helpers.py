"""Helper: real atomic specs for emission probes (executor needs source)."""

SECRET = "AKIAIOSFODNN7EXAMPLE"  # synthetic shape-only canary


def _run_leak(ctx):
    return "BREAK", "saw %s in response" % SECRET


def _run_held(ctx):
    return "HELD", "clean"


def leak_spec():
    return {
        "name": "probe", "description": "emission probe atomic",
        "input_arguments": {},
        "dependencies": [],
        "executor": {"run": _run_leak, "cleanup": None,
                     "elevation_required": False},
    }


def held_spec(name="okprobe"):
    return {
        "name": name, "description": "held probe atomic",
        "input_arguments": {},
        "dependencies": [],
        "executor": {"run": _run_held, "cleanup": None,
                     "elevation_required": False},
    }


def raising_spec(name="raiseprobe"):
    def _run(ctx):
        raise RuntimeError("executor blew up: %s" % SECRET)

    return {
        "name": name, "description": "raising probe atomic",
        "input_arguments": {},
        "dependencies": [],
        "executor": {"run": _run, "cleanup": None,
                     "elevation_required": False},
    }
