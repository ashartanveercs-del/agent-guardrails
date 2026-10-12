"""Framework-agnostic tool middleware.

A :class:`Toolbox` sits between whatever produces tool calls (an LLM API, an MCP server, a
test script) and the tool functions. Per call it:

1. reads the active turn (refusing outside :func:`~agent_guardrails.context.turn_scope`),
2. hides tools the turn's role may not use - a hidden tool answers exactly like a missing
   one, so a third party can't even probe which owner tools exist,
3. parses and strictly validates the arguments against the tool's JSON schema,
4. runs the tool (whose own gates run again inside - defence in depth), and
5. turns every failure into ``{"ok": False, "code", "error"}`` with a safe sentence.
   Exception text never reaches the model; it may contain keys, paths or customer data.

Roles default to owner + system: a tool is invisible to third parties unless you say so.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .context import current_turn
from .errors import Refused
from .identity import Role, TurnContext
from .schema import strict_schema, validate

log = logging.getLogger(__name__)

_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]{0,63}")
TOOL_ERROR = {"ok": False, "code": "tool_error",
              "error": "That didn't work right now. Please try again later."}
AuditHook = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    roles: frozenset[Role]
    fn: Callable[..., Any]

    @property
    def is_async(self) -> bool:
        return inspect.iscoroutinefunction(self.fn)

    def spec(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "parameters": self.parameters}


class Toolbox:
    def __init__(self, *, audit: AuditHook | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        self.audit = audit

    # -- registration ---------------------------------------------------------------------

    def tool(self, *, description: str, parameters: dict[str, Any] | None = None,
             roles: Iterable[Role | str] = (Role.OWNER, Role.SYSTEM),
             name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def register(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            if not _NAME_RE.fullmatch(tool_name):
                raise ValueError(f"invalid tool name {tool_name!r}")
            if tool_name in self._tools:
                raise ValueError(f"tool {tool_name!r} is already registered")
            self._tools[tool_name] = Tool(tool_name, description, strict_schema(parameters),
                                          frozenset(Role(r) for r in roles), fn)
            return fn
        return register

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    # -- model-facing ---------------------------------------------------------------------

    def specs(self) -> list[dict[str, Any]]:
        """Tool definitions visible to the active turn's role."""
        role = current_turn().role
        return [t.spec() for t in self._tools.values() if role in t.roles]

    def call(self, name: str, arguments: str | Mapping[str, Any] | None = None) -> dict[str, Any]:
        turn = current_turn()
        prepared = self._prepare(turn, name, arguments)
        if isinstance(prepared, dict):
            return prepared
        tool, args = prepared
        if tool.is_async:
            raise TypeError(f"tool {name!r} is async; use Toolbox.acall()")
        try:
            result = tool.fn(**args)
        except Refused as refusal:
            return self._refused(turn, name, args, refusal)
        except Exception:
            return self._crashed(turn, name, args)
        return self._ok(turn, name, args, result)

    async def acall(self, name: str,
                    arguments: str | Mapping[str, Any] | None = None) -> dict[str, Any]:
        turn = current_turn()
        prepared = self._prepare(turn, name, arguments)
        if isinstance(prepared, dict):
            return prepared
        tool, args = prepared
        try:
            result = tool.fn(**args)
            if inspect.isawaitable(result):
                result = await result
        except Refused as refusal:
            return self._refused(turn, name, args, refusal)
        except Exception:
            return self._crashed(turn, name, args)
        return self._ok(turn, name, args, result)

    # -- internals ------------------------------------------------------------------------

    def _prepare(self, turn: TurnContext, name: str,
                 arguments: str | Mapping[str, Any] | None) -> tuple[Tool, dict[str, Any]] | dict:
        tool = self._tools.get(name)
        if tool is None or turn.role not in tool.roles:
            return self._refused(turn, name, {}, Refused("unknown_tool"))
        if arguments is None:
            args: Any = {}
        elif isinstance(arguments, str):
            try:
                args = json.loads(arguments)
            except ValueError:
                return self._refused(turn, name, {}, Refused("invalid_args", detail="bad JSON"))
        elif isinstance(arguments, Mapping):
            args = dict(arguments)
        else:
            args = None
        if not isinstance(args, dict):
            return self._refused(turn, name, {}, Refused("invalid_args", detail="not an object"))
        problems = validate(args, tool.parameters)
        if problems:
            return self._refused(turn, name, args,
                                 Refused("invalid_args", detail="; ".join(problems)))
        return tool, args

    def _emit(self, turn: TurnContext, name: str, args: Mapping[str, Any], outcome: str,
              detail: str = "") -> None:
        if self.audit is None:
            return
        event = {"tool": name, "role": str(turn.role), "sender": turn.sender,
                 "turn_id": turn.turn_id, "args": dict(args), "outcome": outcome,
                 "detail": detail}
        try:
            self.audit(event)
        except Exception:
            log.exception("audit hook failed")

    def _ok(self, turn: TurnContext, name: str, args: Mapping[str, Any],
            result: Any) -> dict[str, Any]:
        self._emit(turn, name, args, "ok")
        return {"ok": True, "result": result}

    def _refused(self, turn: TurnContext, name: str, args: Mapping[str, Any],
                 refusal: Refused) -> dict[str, Any]:
        log.info("refused %s for %s: %s %s", name, turn.role, refusal.code, refusal.detail)
        self._emit(turn, name, args, refusal.code, refusal.detail)
        return refusal.to_dict()

    def _crashed(self, turn: TurnContext, name: str, args: Mapping[str, Any]) -> dict[str, Any]:
        log.exception("tool %s failed", name)
        self._emit(turn, name, args, "tool_error")
        return dict(TOOL_ERROR)
