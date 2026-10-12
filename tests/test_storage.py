"""Atomic JSON state files: missing -> default, corrupt -> stop (never silently reset)."""

import json

import pytest

from agent_guardrails.errors import StateCorrupt
from agent_guardrails.storage import JsonFile


def test_missing_file_reads_as_default(tmp_path):
    assert JsonFile(tmp_path / "state.json").read({"items": []}) == {"items": []}


def test_write_then_read_round_trips_and_creates_parent_dirs(tmp_path):
    state = JsonFile(tmp_path / "nested" / "state.json")
    state.write({"a": 1, "b": ["x"]})
    assert state.read(None) == {"a": 1, "b": ["x"]}


def test_write_replaces_atomically_without_leaving_temp_files(tmp_path):
    state = JsonFile(tmp_path / "state.json")
    state.write({"v": 1})
    state.write({"v": 2})
    assert json.loads((tmp_path / "state.json").read_text(encoding="utf-8")) == {"v": 2}
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_corrupt_state_raises_instead_of_resetting(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{ truncated", encoding="utf-8")
    with pytest.raises(StateCorrupt):
        JsonFile(path).read({})
    assert path.read_text(encoding="utf-8") == "{ truncated"   # evidence left in place
