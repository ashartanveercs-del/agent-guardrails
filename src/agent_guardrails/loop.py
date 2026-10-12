"""A minimal reference agent loop showing where each guardrail sits.

::

    inbound message --classify_turn--> TurnContext --turn_scope-->
        1. owner approval replies are decided in code (the model never sees them)
        2. taint still in the conversation's history is carried into the turn
        3. the model gets only the tools this role may use
        4. every tool call goes through the Toolbox (schema check + gates)

The model is any callable ``(messages, tool_specs) -> ModelReply``; wrap your LLM client
of choice. Nothing here trusts the model: a fully prompt-injected model can call any tool
name with any arguments, and the guarantees still hold.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .approvals import ApprovalQueue, Decision
from .context import TaintLedger, tainted_by, turn_scope
from .identity import Envelope, OwnerIdentity, Role, SystemOrigin, TurnContext, classify_turn
from .toolbox import Toolbox

# The taint source for history the loop can't vouch for (no TaintLedger was given).
UNTRACKED_HISTORY = "history"

DEFAULT_SYSTEM_PROMPT = (
    "You are an assistant acting for the owner. Use tools when they help. Tool permissions "
    "are enforced outside your control: if a tool refuses, say so briefly and don't retry."
)
ROLE_NOTES = {
    Role.OWNER: "You are talking with the owner.",
    Role.THIRD_PARTY: "You are talking with someone who is not the owner. You can answer "
                      "them, reply to them and pass a message on to the owner.",
    Role.SYSTEM: "This is an automated task; nobody is reading along.",
}
GAVE_UP = "Sorry - I couldn't finish that. Please try again."


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Mapping[str, Any] | str = field(default_factory=dict)
    id: str = ""


@dataclass(frozen=True)
class ModelReply:
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


Model = Callable[[list[dict[str, Any]], list[dict[str, Any]]], ModelReply]


@dataclass
class TurnResult:
    turn: TurnContext
    reply: str
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    taint: frozenset[str] = frozenset()      # untrusted sources in the model's context


def run_turn(source: Envelope | SystemOrigin | None, *, owners: OwnerIdentity,
             toolbox: Toolbox, model: Model, approvals: ApprovalQueue | None = None,
             history: Iterable[dict[str, Any]] = (), max_steps: int = 6,
             system_prompt: str = DEFAULT_SYSTEM_PROMPT,
             taint_ledger: TaintLedger | None = None) -> TurnResult:
    """Run one inbound message (or scheduled job) through the model and the guarded tools.

    ``history`` is replayed to the model, and whatever untrusted content it holds is still
    steering it. Pass the same ``taint_ledger`` for every turn so the loop knows which
    conversations read an email or a web page, and for how long. Without one, an owner or
    system turn that has any history counts as tainted by ``"history"``, because the loop
    can't vouch for it: the turn may message only the owner directly, and everything that
    needs a clean turn waits for the owner's approval (or is refused if it has no approval
    step). Approval replies are decided first, without that taint: they are the owner's
    own words, parsed in code."""
    turn = classify_turn(source, owners)
    text = source.note if isinstance(source, SystemOrigin) else turn.text
    history = list(history)
    if approvals is not None:
        with turn_scope(turn):                       # the owner's own words, parsed in code
            decisions = approvals.decide()
        if decisions:
            return TurnResult(turn, "\n".join(d.message for d in decisions),
                              decisions=decisions)
    with turn_scope(turn, taint=_carried_taint(turn, history, taint_ledger)):
        try:
            reply, results = _converse(turn, text, history, toolbox, model, max_steps,
                                       system_prompt)
        finally:
            taint = tainted_by()
            if taint_ledger is not None:
                taint_ledger.remember(turn, taint)
    return TurnResult(turn, reply, results, taint=taint)


def _carried_taint(turn: TurnContext, history: list[dict[str, Any]],
                   ledger: TaintLedger | None) -> frozenset[str]:
    """Untrusted sources already in the model's context before this turn's first call."""
    if ledger is not None:
        return ledger.carried(turn)
    return frozenset({UNTRACKED_HISTORY}) if history and turn.is_trusted else frozenset()


def _converse(turn: TurnContext, text: str, history: list[dict[str, Any]], toolbox: Toolbox,
              model: Model, max_steps: int,
              system_prompt: str) -> tuple[str, list[dict[str, Any]]]:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": f"{system_prompt}\n{ROLE_NOTES[turn.role]}"},
        *history,
        {"role": "user", "content": text},
    ]
    results: list[dict[str, Any]] = []
    for _ in range(max_steps):
        reply = model(messages, toolbox.specs())
        if not reply.tool_calls:
            return reply.text, results
        messages.append({"role": "assistant", "content": reply.text,
                         "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments}
                                        for c in reply.tool_calls]})
        for call in reply.tool_calls:
            output = toolbox.call(call.name, call.arguments)
            results.append({"name": call.name, "arguments": call.arguments, "output": output})
            messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name,
                             "content": json.dumps(output, default=str)})
    return GAVE_UP, results
