"""Shared test fixtures.

The tool ships as a single hyphenated script (``rednb-verify.py``) which is not
a valid module name for ``import``, so we load it from its file path and expose
it as a fixture/helper for the test suite.
"""
import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "rednb-verify.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("rednb_verify", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def tool():
    return load_tool()
