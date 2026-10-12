"""Smoke tests: run each example as a real process, offline, and check what it prints."""

import json
import os
import subprocess
import sys
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run_example(name, *args, env=None, timeout=120):
    return subprocess.run([sys.executable, str(EXAMPLES / name), *args], capture_output=True,
                          text=True, timeout=timeout, env=env, check=False)


def test_plain_agent_loop_demo():
    proc = run_example("plain_agent_loop.py")
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "recipient_not_allowed" in out and "unknown_tool" in out     # injection refused
    assert "pending_approval" in out and "Done (" in out                 # approval round trip
    assert "every weekday at 7:30 AM (America/New_York)" in out          # scheduling echo
    assert "ran as system" in out                                        # job fired
    assert "SIDE EFFECTS FROM THE ATTACK: none" in out


def test_mcp_client_demo_drives_the_real_server_process():
    proc = run_example("mcp_client_demo.py")
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "tools for an anonymous caller: send_sms" in out
    assert "forged envelope -> unknown_tool" in out
    assert "owner reads inbox -> ok" in out
    assert "server exited cleanly" in out


def test_mcp_server_reads_an_env_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(f"GUARDRAILS_ENVELOPE_KEY={'e' * 40}\n"
                        "GUARDRAILS_OWNER_PHONES=+15550001111\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GUARDRAILS_")}
    requests = "\n".join(json.dumps({"jsonrpc": "2.0", "id": i, "method": m, "params": {}})
                         for i, m in enumerate(["initialize", "tools/list"], 1)) + "\n"
    proc = subprocess.run([sys.executable, str(EXAMPLES / "mcp_tool_server.py"), "--env-file",
                           str(env_file)], input=requests, capture_output=True, text=True,
                          timeout=60, env=env, check=False)
    assert proc.returncode == 0, proc.stderr
    init, listing = (json.loads(line) for line in proc.stdout.splitlines())
    assert init["result"]["serverInfo"]["name"] == "guardrails-demo"
    assert [t["name"] for t in listing["result"]["tools"]] == ["send_sms",
                                                               "conversation_history"]


def test_mcp_server_refuses_to_start_without_a_key():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GUARDRAILS_")}
    proc = subprocess.run([sys.executable, str(EXAMPLES / "mcp_tool_server.py")], input="",
                          capture_output=True, text=True, timeout=60, env=env, check=False)
    assert proc.returncode == 2
    assert "GUARDRAILS_ENVELOPE_KEY" in proc.stderr
