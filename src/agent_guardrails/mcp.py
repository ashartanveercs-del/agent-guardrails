"""An MCP-style JSON-RPC 2.0 tool server around a :class:`~agent_guardrails.toolbox.Toolbox`.

Transport-agnostic: :meth:`McpToolServer.handle` maps one decoded JSON-RPC message to one
response (or ``None`` for notifications), so it can sit behind stdio, HTTP or a test.

Identity never comes from the tool arguments. The gateway that verified the inbound
message seals its :class:`~agent_guardrails.identity.Envelope`
(:func:`~agent_guardrails.sealing.seal_envelope`) and passes the token in the request's
``params._meta["agent-guardrails/envelope"]``. A missing, forged, expired or unverified
envelope classifies as a third party, so the worst a broken integration can do is make
the server *more* restrictive.

Every ``tools/call`` is a separate request, but the calls made while handling one inbound
message belong to one turn, and the gateway replays that turn as history for the sender's
next message. Taint is therefore remembered per turn id (built from the sealed platform
message id, so gateways should always set ``message_id``) and, for owner and system
conversations, in a :class:`~agent_guardrails.context.TaintLedger`: reading an email in one
call still counts when a later call, or a later message, tries to send.

Implemented methods: ``initialize``, ``ping``, ``tools/list``, ``tools/call``.
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from ._version import __version__
from .context import TaintLedger, tainted_by, turn_scope
from .errors import ConfigError
from .identity import OwnerIdentity, TurnContext, classify_turn
from .sealing import MIN_KEY_BYTES, open_envelope
from .toolbox import TOOL_ERROR, Toolbox

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-06-18"
ENVELOPE_META_KEY = "agent-guardrails/envelope"
MAX_TRACKED_TURNS = 1024


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _result(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


class McpToolServer:
    def __init__(self, toolbox: Toolbox, owners: OwnerIdentity, *, envelope_key: bytes,
                 clock: Callable[[], datetime] | None = None,
                 max_envelope_age: timedelta = timedelta(minutes=5),
                 name: str = "agent-guardrails",
                 taint_ledger: TaintLedger | None = None) -> None:
        """``taint_ledger`` defaults to a fresh in-memory :class:`TaintLedger` (24 h ttl);
        pass your own to match how long your gateway keeps conversation history."""
        if not isinstance(envelope_key, bytes | bytearray) or len(envelope_key) < MIN_KEY_BYTES:
            raise ConfigError(f"the envelope key must be at least {MIN_KEY_BYTES} bytes")
        self.toolbox = toolbox
        self.owners = owners
        self.name = name
        self._key = bytes(envelope_key)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_age = max_envelope_age
        self.taint_ledger = (taint_ledger if taint_ledger is not None
                             else TaintLedger(clock=self._clock))
        # Taint per turn, for every role: separate tools/call requests from one inbound
        # message share it. The ledger carries owner and system taint into later messages.
        self._taint: OrderedDict[str, frozenset[str]] = OrderedDict()

    def turn_for(self, params: object) -> TurnContext:
        """Classify the caller from the sealed envelope in ``params._meta``."""
        meta = params.get("_meta") if isinstance(params, Mapping) else None
        token = meta.get(ENVELOPE_META_KEY) if isinstance(meta, Mapping) else None
        envelope = None
        if token is not None:
            envelope = open_envelope(token, self._key, now=self._clock(), max_age=self._max_age)
            if envelope is None:
                log.warning("tool call carried an envelope that did not verify")
        return classify_turn(envelope, self.owners)

    def handle(self, message: object) -> dict[str, Any] | None:
        if not isinstance(message, Mapping):
            return _error(None, -32600, "Invalid Request")
        msg_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _error(msg_id, -32600, "Invalid Request")
        params = message.get("params") or {}
        if "id" not in message:                          # a notification: never answered
            return None
        if not isinstance(params, Mapping):
            return _error(msg_id, -32602, "Invalid params")
        try:
            if method == "initialize":
                return _result(msg_id, self._initialize())
            if method == "ping":
                return _result(msg_id, {})
            if method == "tools/list":
                return _result(msg_id, self._list(params))
            if method == "tools/call":
                name, arguments = params.get("name"), params.get("arguments", {})
                if not isinstance(name, str) or not isinstance(arguments, Mapping):
                    return _error(msg_id, -32602, "Invalid params")
                return _result(msg_id, self._call(params, name, arguments))
        except Exception:
            log.exception("internal error handling %s", method)
            return _error(msg_id, -32603, "Internal error")
        return _error(msg_id, -32601, "Method not found")

    def _initialize(self) -> dict[str, Any]:
        return {"protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": __version__},
                "instructions": "Tool visibility and permissions depend on the verified "
                                "caller; pass the gateway's sealed envelope in _meta."}

    def _list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        with turn_scope(self.turn_for(params)):
            specs = self.toolbox.specs()
        return {"tools": [{"name": s["name"], "description": s["description"],
                           "inputSchema": s["parameters"]} for s in specs]}

    def _call(self, params: Mapping[str, Any], name: str,
              arguments: Mapping[str, Any]) -> dict[str, Any]:
        turn = self.turn_for(params)
        with turn_scope(turn, taint=self._carried_taint(turn)):
            try:
                outcome = self.toolbox.call(name, dict(arguments))
            except Exception:
                log.exception("tool %s could not be called", name)
                outcome = dict(TOOL_ERROR)
            self._remember_taint(turn, tainted_by())
        return {"content": [{"type": "text", "text": json.dumps(outcome, default=str)}],
                "structuredContent": outcome, "isError": not outcome.get("ok", False)}

    def _carried_taint(self, turn: TurnContext) -> frozenset[str]:
        """What earlier calls of this turn, and earlier turns of this conversation, read."""
        return self._taint.get(turn.turn_id, frozenset()) | self.taint_ledger.carried(turn)

    def _remember_taint(self, turn: TurnContext, taint: frozenset[str]) -> None:
        """Turn ids come from the sealed platform message id, so every call made while
        handling one inbound message shares its taint. Bounded, oldest evicted first."""
        if not taint:
            return
        self.taint_ledger.remember(turn, taint)
        self._taint[turn.turn_id] = taint
        self._taint.move_to_end(turn.turn_id)
        while len(self._taint) > MAX_TRACKED_TURNS:
            self._taint.popitem(last=False)
