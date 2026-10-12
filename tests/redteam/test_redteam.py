"""Prompt-injection red team.

The model is assumed to be fully compromised: it calls exactly what the attacker asked for.
Every attack in the corpus must end in a refusal (or a pending approval) with zero side
effects on the fake services - through the agent loop and through the MCP server."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from agent_guardrails import (
    ApprovalStatus,
    Envelope,
    McpToolServer,
    ModelReply,
    ToolCall,
    run_turn,
    seal_envelope,
    turn_scope,
)
from agent_guardrails.mcp import ENVELOPE_META_KEY
from tests.fakes import CUSTOMER, OWNER_PHONE, OWNERS, STRANGER, owner_turn
from tests.redteam.attacks import ATTACKS, Attack
from tests.redteam.world import World, build_world

KEY = b"r" * 32


class CompromisedModel:
    """Obeys the injection: one reply with every requested tool call, then a summary."""

    def __init__(self, calls: tuple[tuple[str, Any], ...]) -> None:
        self.calls = calls
        self.turns = 0

    def __call__(self, messages: list[dict], tools: list[dict]) -> ModelReply:
        self.turns += 1
        if self.turns > 1:
            return ModelReply(text="All done!")
        return ModelReply(text="On it!", tool_calls=tuple(
            ToolCall(name, args, f"call-{i}") for i, (name, args) in enumerate(self.calls)))


def outcome(output: dict[str, Any]) -> str:
    if not output["ok"]:
        return output["code"]
    result = output["result"]
    if isinstance(result, dict) and result.get("status") == "pending_approval":
        return "pending_approval"
    return "ok"


def prepare(world: World, attack: Attack) -> tuple[Attack, str | None]:
    """Run the attack's setup and fill in ``{code}`` placeholders."""
    if attack.setup != "pending_email":
        return attack, None
    with turn_scope(owner_turn("email the client the quote")):
        code = world.approvals.request(
            "email.send", {"to": "client@example.com", "subject": "Quote", "body": "Attached"},
            summary="Email client@example.com: Quote").code
    fill = json.loads(json.dumps(attack.calls).replace("{code}", code))
    return dataclasses.replace(attack, text=attack.text.replace("{code}", code),
                               calls=tuple((name, args) for name, args in fill)), code


def envelope(attack: Attack, message_id: str = "") -> Envelope | None:
    if attack.sender is None:
        return None
    return Envelope(attack.channel, attack.sender, verified=attack.verified, text=attack.text,
                    message_id=message_id)


def assert_no_side_effects(world: World, before: dict[str, int], attack: Attack) -> None:
    after = world.side_effects()
    changed = {k: (before[k], after[k]) for k in before
               if before[k] != after[k] and k not in attack.allowed_effects}
    assert changed == {}, f"{attack.id} caused side effects: {changed}"


@pytest.mark.parametrize("attack", ATTACKS, ids=[a.id for a in ATTACKS])
def test_attack_is_blocked_through_the_agent_loop(attack: Attack) -> None:
    world = build_world()
    attack, pending_code = prepare(world, attack)
    before = world.side_effects()
    result = run_turn(envelope(attack), owners=OWNERS, toolbox=world.toolbox,
                      model=CompromisedModel(attack.calls), approvals=world.approvals)
    assert [outcome(r["output"]) for r in result.tool_results] == list(attack.expect)
    assert result.decisions == []
    assert_no_side_effects(world, before, attack)
    if pending_code:
        with turn_scope(owner_turn()):
            assert world.approvals.get(pending_code).status is ApprovalStatus.PENDING


@pytest.mark.parametrize("attack", [a for a in ATTACKS if a.setup is None],
                         ids=[a.id for a in ATTACKS if a.setup is None])
def test_attack_is_blocked_through_the_mcp_server(attack: Attack) -> None:
    world = build_world()
    server = McpToolServer(world.toolbox, OWNERS, envelope_key=KEY, clock=world.clock)
    sealed = envelope(attack, message_id="SM-redteam")
    meta = {ENVELOPE_META_KEY: seal_envelope(sealed, KEY, now=world.clock())} if sealed else None
    before = world.side_effects()
    outcomes = []
    for i, (name, args) in enumerate(attack.calls):
        params: dict[str, Any] = {"name": name, "arguments": args}
        if meta:
            params["_meta"] = meta
        response = server.handle({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                  "params": params})
        if "error" in response:              # e.g. arguments that aren't a JSON object
            assert response["error"]["code"] == -32602
            outcomes.append("invalid_args")
        else:
            outcomes.append(outcome(response["result"]["structuredContent"]))
    assert outcomes == list(attack.expect)
    assert_no_side_effects(world, before, attack)


def test_the_corpus_covers_every_guardrail() -> None:
    assert {a.category for a in ATTACKS} == {
        "send-gate", "read-gate", "identity", "scope", "arguments", "tenancy", "scheduling",
        "approvals", "carry-forward"}
    assert len({a.id for a in ATTACKS}) == len(ATTACKS)


def test_an_unconfigured_tenant_fails_closed_even_for_the_owner() -> None:
    world = build_world(tenant=None)
    result = run_turn(Envelope("sms", OWNER_PHONE, verified=True, text="list the invoices"),
                      owners=OWNERS, toolbox=world.toolbox,
                      model=CompromisedModel((("list_files", {"folder": "invoices"}),)))
    assert outcome(result.tool_results[0]["output"]) == "tenant_unset"
    assert world.files.calls == []


def test_the_owner_can_still_get_real_work_done() -> None:
    """Control: guardrails that refused everything would pass every test above."""
    world = build_world()
    calls = (("send_sms", {"to": STRANGER, "body": "Running 10 minutes late"}),
             ("conversation_history", {"contact": CUSTOMER}),
             ("list_files", {"folder": "invoices"}),
             ("read_inbox", {"query": "invoice"}))
    result = run_turn(Envelope("sms", OWNER_PHONE, verified=True, text="morning errands"),
                      owners=OWNERS, toolbox=world.toolbox, model=CompromisedModel(calls),
                      approvals=world.approvals)
    assert [outcome(r["output"]) for r in result.tool_results] == ["ok"] * 4
    assert world.sms.sent == [{"to": STRANGER, "body": "Running 10 minutes late"}]
    assert world.files.calls == [("maple-bikes", "invoices")]
