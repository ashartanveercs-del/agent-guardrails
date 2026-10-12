"""An MCP-style tool server over stdio (one JSON-RPC message per line).

    python examples/mcp_tool_server.py --env-file .env      # see .env.example
    # or: GUARDRAILS_ENVELOPE_KEY=... GUARDRAILS_OWNER_PHONES=+15550001111 python ...

The server refuses to start without an envelope key: without one it could never verify a
caller, and every tool call would be anonymous. Callers (your gateway) attach a sealed
envelope to each request in ``params._meta["agent-guardrails/envelope"]``; see
``examples/mcp_client_demo.py``. The backing services are in-memory stand-ins that log to
stderr - nothing is really sent.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

from agent_guardrails import (
    ConfigError,
    McpToolServer,
    Role,
    Settings,
    Toolbox,
    own_records_only,
    owner_only,
    send_gate,
    tenant_scoped,
    untrusted_output,
)
from agent_guardrails.config import read_env_file


def log(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}), file=sys.stderr, flush=True)


def build_toolbox(settings: Settings) -> Toolbox:
    box = Toolbox()
    inbox = [{"from": "supplier@example.com", "subject": "Invoice 2231", "body": "Due Friday"}]
    threads = {"+15550002222": ["Is my bike ready?"], "+15550001111": ["(owner notes)"]}

    @box.tool(description="Send a text message.", roles=(Role.OWNER, Role.THIRD_PARTY),
              parameters={"type": "object", "required": ["to", "body"],
                          "properties": {"to": {"type": "string"},
                                         "body": {"type": "string", "maxLength": 480}}})
    @send_gate(recipient="to", channel="sms")
    def send_sms(to: str, body: str) -> dict[str, str]:
        log("sms_sent", to=to, chars=len(body))
        return {"sent_to": to}

    @box.tool(description="Search the owner's inbox.",
              parameters={"type": "object", "properties": {"query": {"type": "string"}}})
    @owner_only
    @untrusted_output("email")
    def read_inbox(query: str = "") -> list[dict[str, str]]:
        log("inbox_read", query=query)
        return [m for m in inbox if query.lower() in json.dumps(m).lower()]

    @box.tool(description="Conversation history with a contact.",
              roles=(Role.OWNER, Role.THIRD_PARTY),
              parameters={"type": "object", "properties": {"contact": {"type": "string"}}})
    @own_records_only(param="contact")
    def conversation_history(contact: str | None = None) -> list[str]:
        return threads.get(contact or "", [])

    @box.tool(description="List files in the shared drive.",
              parameters={"type": "object", "required": ["folder"],
                          "properties": {"folder": {"type": "string"}}})
    @tenant_scoped(settings.tenant)
    def list_files(folder: str, tenant_id: str | None = None) -> list[str]:
        log("files_listed", tenant=tenant_id, folder=folder)
        return [f"{folder}/2026-q3.pdf"]

    return box


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP-style guarded tool server over stdio")
    parser.add_argument("--env-file", help="KEY=value file; real environment variables win")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    try:
        environ = {**read_env_file(args.env_file), **os.environ} if args.env_file else None
        settings = Settings.from_env(environ)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    if settings.envelope_key is None:
        print("GUARDRAILS_ENVELOPE_KEY is not set; refusing to start a server that could "
              "never verify its callers", file=sys.stderr)
        return 2
    if not settings.owners.configured:
        log("warning", message="no owner configured: every caller is a third party")
    server = McpToolServer(build_toolbox(settings), settings.owners,
                           envelope_key=settings.envelope_key, name="guardrails-demo")
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response: dict[str, Any] | None = {"jsonrpc": "2.0", "id": None,
                                               "error": {"code": -32700, "message": "Parse error"}}
        else:
            response = server.handle(message)
        if response is not None:
            print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
