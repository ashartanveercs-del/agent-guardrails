"""A broken pytest runner must never count as evidence that a safety guard was caught."""

import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mutation_check.py"


def harness(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("guardrails_mutation_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "guard.py"
    original = b"guard = True\r\n"
    source.write_bytes(original)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "MUTATIONS", [
        ("test guard", "guard.py", "guard = True\n", "guard = False\n")])
    return module, source, original


@pytest.mark.parametrize(("code", "output", "expected"), [
    (1, "FAILED tests/test_guard.py::test_denies - AssertionError\n", 0),
    (1, "runner failed without a test result\n", 1),
    (2, "ERROR collecting tests/test_guard.py\n", 1),
    (4, "ERROR: invalid pytest arguments\n", 1),
    (5, "no tests ran\n", 1),
])
def test_only_a_test_failure_counts_as_a_caught_mutation(tmp_path, monkeypatch,
                                                       code, output, expected):
    module, source, original = harness(tmp_path, monkeypatch)
    calls = []

    def runner(*args, **kwargs):
        calls.append(source.read_bytes())
        if source.read_bytes() == original:
            return SimpleNamespace(returncode=0, stdout="1 passed\n", stderr="")
        return SimpleNamespace(returncode=code, stdout=output, stderr="")

    monkeypatch.setattr(module.subprocess, "run", runner)
    assert module.main() == expected
    assert calls == [original, b"guard = False\r\n"]
    assert source.read_bytes() == original


def test_a_failing_baseline_stops_before_mutating_source(tmp_path, monkeypatch):
    module, source, original = harness(tmp_path, monkeypatch)
    calls = []

    def runner(*args, **kwargs):
        calls.append(source.read_bytes())
        return SimpleNamespace(returncode=2, stdout="ERROR collecting tests\n", stderr="")

    monkeypatch.setattr(module.subprocess, "run", runner)
    assert module.main() == 1
    assert calls == [original]
    assert source.read_bytes() == original


def test_source_is_restored_when_pytest_times_out(tmp_path, monkeypatch):
    module, source, original = harness(tmp_path, monkeypatch)

    def runner(*args, **kwargs):
        if source.read_bytes() == original:
            return SimpleNamespace(returncode=0, stdout="1 passed\n", stderr="")
        raise subprocess.TimeoutExpired("pytest", 600)

    monkeypatch.setattr(module.subprocess, "run", runner)
    with pytest.raises(subprocess.TimeoutExpired):
        module.main()
    assert source.read_bytes() == original
