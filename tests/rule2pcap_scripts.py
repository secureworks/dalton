"""Load the rule2pcap skill's scripts, which live outside any package."""

import importlib.util
import pathlib
import sys

SCRIPTS = (
    pathlib.Path(__file__).resolve().parent.parent
    / ".agents"
    / "skills"
    / "rule2pcap"
    / "scripts"
)


def load(name):
    module_name = f"rule2pcap_{name}"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
