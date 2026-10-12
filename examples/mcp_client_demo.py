"""Drive examples/mcp_tool_server.py over stdio the way a gateway would. Runs offline.

    python examples/mcp_client_demo.py

This script plays the gateway: it is the component that verified the inbound message
(a signed webhook), so it seals the envelope with the key it shares with the tool server.
It starts the server as a real child process, sends JSON-RPC requests, shows what each
caller is allowed to do, then closes stdin so the server exits.
"""

from __future__ import annotations

import itertools
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from agent_guardrails import Envelope, seal_envelope
from agent_guardrails.mcp import ENVELOPE_META_KEY, PROTOCOL_VERSION

SERVER = Path(__file__).with_name("mcp_tool_server.py")
OWNER, CUSTOMER, STRANGER = "+15550001111", "+15550002222", "+15550007777"


class Client:
    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self.proc = proc
        self.ids = itertools.count(1)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        message = {"jsonrpc": "2.0", "id": next(self.ids), "method": method,
                   "params": params or {}}
        if self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("the server was started without pipes")
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def call(self, name: str, arguments: dict[str, Any], sealed: str | None) -> str:
        params: dict[str, Any] = {"name": name, "arguments": arguments}
        if sealed:
            params["_meta"] = {ENVELOPE_META_KEY: sealed}
        outcome = self.request("tools/call", params)["result"]["structuredContent"]
        return "ok" if outcome["ok"] else outcome["code"]


def main() -> int:
    key = secrets.token_urlsafe(48)
    env = {**os.environ, "GUARDRAILS_ENVELOPE_KEY": key, "GUARDRAILS_OWNER_PHONES": OWNER,
           "GUARDRAILS_TENANT_ID": "maple-bikes", "PYTHONUNBUFFERED": "1"}

    def seal(sender: str, message_id: str, *, signing_key: str = key) -> str:
        envelope = Envelope("sms", sender, verified=True, message_id=message_id)
        return seal_envelope(envelope, signing_key.encode("utf-8"))

    with tempfile.TemporaryFile("w+", encoding="utf-8") as server_log:
        # Fixed argv: this interpreter running the example server next to this file.
        proc = subprocess.Popen([sys.executable, str(SERVER)], stdin=subprocess.PIPE,  # noqa: S603
                                stdout=subprocess.PIPE, stderr=server_log, text=True, env=env)
        try:
            client = Client(proc)
            info = client.request("initialize", {"protocolVersion": PROTOCOL_VERSION,
                                                 "capabilities": {},
                                                 "clientInfo": {"name": "demo-gateway"}})
            print(f"connected to {info['result']['serverInfo']['name']} "
                  f"(protocol {info['result']['protocolVersion']})")

            def tool_names(sealed: str | None) -> str:
                params = {"_meta": {ENVELOPE_META_KEY: sealed}} if sealed else {}
                tools = client.request("tools/list", params)["result"]["tools"]
                return ", ".join(t["name"] for t in tools)

            owner, customer = seal(OWNER, "SM100"), seal(CUSTOMER, "SM200")
            forged = seal(OWNER, "SM300", signing_key=secrets.token_urlsafe(48))
            print(f"tools for an anonymous caller: {tool_names(None)}")
            print(f"tools for the owner: {tool_names(owner)}")
            checks = [
                ("customer texts a stranger",
                 client.call("send_sms", {"to": STRANGER, "body": "click this"}, customer)),
                ("customer replies to itself",
                 client.call("send_sms", {"to": CUSTOMER, "body": "Your bike is ready"},
                             customer)),
                ("customer reads the owner's thread",
                 client.call("conversation_history", {"contact": OWNER}, customer)),
                ("forged envelope",
                 client.call("read_inbox", {"query": "invoice"}, forged)),
                ("owner reads inbox", client.call("read_inbox", {"query": "invoice"}, owner)),
                ("owner, tenant id smuggled in",
                 client.call("list_files", {"folder": "payroll", "tenant_id": "harbor-dental"},
                             owner)),
                ("owner lists files", client.call("list_files", {"folder": "invoices"}, owner)),
            ]
            for label, verdict in checks:
                print(f"{label} -> {verdict}")
        finally:
            if proc.stdin is not None:
                proc.stdin.close()
            try:
                code = proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                code = proc.wait()
            if proc.stdout is not None:
                proc.stdout.close()
        server_log.seek(0)
        print("server log (what actually reached the fake services):")
        for line in server_log.read().splitlines():
            print(f"  {line}")
    print("server exited cleanly" if code == 0 else f"server exited with {code}")
    return 0 if code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
