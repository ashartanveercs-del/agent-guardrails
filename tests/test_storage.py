"""Atomic JSON state files: missing -> default, corrupt -> stop (never silently reset).
File locks: one holder at a time across processes, and never left behind by a crash."""

import json
import subprocess
import sys

import pytest

from agent_guardrails.errors import StateCorrupt
from agent_guardrails.storage import FileLock, JsonFile


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


def test_a_file_lock_keeps_other_holders_out_until_released(tmp_path):
    path = tmp_path / "state.lock"
    holder, other = FileLock(path), FileLock(path, timeout=0.2)   # e.g. two worker processes
    with holder, pytest.raises(TimeoutError):
        other.__enter__()
    with other:
        pass


def test_a_file_lock_is_reentrant_for_its_holder(tmp_path):
    lock = FileLock(tmp_path / "state.lock")
    with lock, lock:
        pass
    with FileLock(tmp_path / "state.lock", timeout=0.2):          # fully released after
        pass


def test_a_crashed_holder_never_leaves_a_stale_lock(tmp_path):
    path = tmp_path / "state.lock"
    crash = ("import os, sys; from agent_guardrails.storage import FileLock; "
             "FileLock(sys.argv[1]).__enter__(); os._exit(0)")
    proc = subprocess.run([sys.executable, "-c", crash, str(path)], timeout=60, check=False)
    assert proc.returncode == 0
    with FileLock(path, timeout=5):
        pass
