from __future__ import annotations

import importlib
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_distribution_uses_gway_wire_name() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert data["project"]["name"] == "gway-wire"


def test_gway_project_uses_wire_with_compatibility_alias() -> None:
    data = tomllib.loads((ROOT / "gway.toml").read_text())
    assert data["project"]["name"] == "wire"
    assert data["project"]["aliases"] == ["wireguard"]
    assert data["adapter"]["module"] == "gway_wire.gway"


def test_canonical_python_namespace_imports() -> None:
    module = importlib.import_module("gway_wire.gway")
    assert callable(module.status)
