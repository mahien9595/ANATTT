"""Nạp module công cụ (tên file có dấu chấm nên không import trực tiếp được)."""
import importlib.util
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "auto_fill_bien_ban_V1.6.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("anattt_tool", _SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def m():
    return _load_module()


@pytest.fixture(scope="session")
def root():
    return _ROOT
