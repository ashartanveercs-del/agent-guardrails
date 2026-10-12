"""The active turn, held in a :mod:`contextvars` variable.

Gates look the turn up here instead of taking it as an argument, so there is no parameter
a model could fill in to change who it is acting for. Context variables follow asyncio
tasks automatically; a bare ``threading.Thread`` starts with no turn at all, which makes
gated calls from it fail closed (use ``contextvars.copy_context().run`` to hand a turn
to a worker thread on purpose).

Each scope also tracks *taint*: the names of untrusted sources (an email body, a web page)
whose content entered the model's context. Gates and approval policies use it to stop an
owner's turn from acting on instructions hidden in data the agent read. That content stays
in the conversation history after the turn ends, so :class:`TaintLedger` carries the taint
into the conversation's later turns.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .errors import Refused, StateCorrupt
from .identity import TurnContext
from .storage import FileLock, JsonFile


@dataclass
class _ActiveTurn:
    turn: TurnContext
    taint: set[str] = field(default_factory=set)


_ACTIVE: ContextVar[_ActiveTurn | None] = ContextVar("agent_guardrails_turn", default=None)


def _sources(taint: Iterable[str] | str) -> frozenset[str]:
    names = (taint,) if isinstance(taint, str) else tuple(taint)
    for name in names:
        if not isinstance(name, str) or not name:
            raise TypeError(f"taint sources are non-empty strings, got {name!r}")
    return frozenset(names)


@contextmanager
def turn_scope(turn: TurnContext, *, taint: Iterable[str] | str = ()) -> Iterator[TurnContext]:
    """Make ``turn`` the active turn for the duration of the ``with`` block.

    ``taint`` names untrusted sources that are already in the model's context when the turn
    starts, typically :meth:`TaintLedger.carried` for this conversation: an email read two
    turns ago is still in the history the model is reading now."""
    if not isinstance(turn, TurnContext):
        raise TypeError("turn_scope() needs a TurnContext from classify_turn()")
    token = _ACTIVE.set(_ActiveTurn(turn, set(_sources(taint))))
    try:
        yield turn
    finally:
        _ACTIVE.reset(token)


def _active() -> _ActiveTurn:
    active = _ACTIVE.get()
    if active is None:
        raise Refused("no_active_turn", detail="gated call made outside turn_scope()")
    return active


def current_turn() -> TurnContext:
    """The active turn. Outside a scope this refuses rather than guessing a role."""
    return _active().turn


def mark_untrusted(source: str) -> None:
    """Record that content from ``source`` entered the model's context this turn."""
    _active().taint.add(source)


def tainted_by() -> frozenset[str]:
    """Untrusted sources in the model's context so far in the active turn."""
    return frozenset(_active().taint)


class TaintLedger:
    """Which conversations still have untrusted content in the model's history.

    Taint is tracked per turn, but the email that caused it isn't gone when the turn ends:
    the next turn replays it as history, injected instructions included. Record each turn's
    taint with :meth:`remember` and seed the conversation's next turn from :meth:`carried`
    (:func:`~agent_guardrails.loop.run_turn` and
    :class:`~agent_guardrails.mcp.McpToolServer` do both).

    A conversation is one sender on one channel. Only owner and system conversations are
    kept: taint is what limits *their* extra privileges (a third party can only reply or
    relay anyway), and it means strangers can't grow the ledger. Entries last ``ttl`` from
    the latest untrusted read; set it to at least how long content stays in the model's
    history, and call :meth:`forget` when you start a conversation afresh.

    By default the ledger lives in memory, in one process. Give it a ``path`` when several
    worker processes on one machine handle the same conversations: a JSON file, read and
    written under an OS lock, so a turn sees the taint wherever the last one ran.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None, *,
                 ttl: timedelta = timedelta(hours=24),
                 clock: Callable[[], datetime] | None = None) -> None:
        if ttl <= timedelta(0):
            raise ValueError("a taint ledger needs a positive ttl")
        self.ttl = ttl
        self._clock = clock or (lambda: datetime.now(UTC))
        self._file = JsonFile(path) if path is not None else None
        self._lock: AbstractContextManager[Any] = (
            FileLock(self._file.path.with_name(self._file.path.name + ".lock"))
            if self._file is not None else threading.RLock())
        self._memory: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _conversation(turn: TurnContext) -> str | None:
        if not turn.is_trusted or not turn.sender:
            return None
        return f"{turn.channel} {turn.sender}"      # channel names never contain a space

    def _load(self) -> dict[str, dict[str, Any]]:
        if self._file is None:
            return self._memory
        data = self._file.read({"version": 1, "conversations": {}})
        conversations = data.get("conversations") if isinstance(data, dict) else None
        if not isinstance(conversations, dict):
            raise StateCorrupt(f"{self._file.path} is not a taint ledger")
        return conversations

    def _save(self, conversations: dict[str, dict[str, Any]], now: datetime) -> None:
        live = {key: entry for key, entry in conversations.items()
                if datetime.fromisoformat(entry["expires"]) > now}
        if self._file is None:
            self._memory = live
        else:
            self._file.write({"version": 1, "conversations": live})

    @staticmethod
    def _live(entry: dict[str, Any] | None, now: datetime) -> frozenset[str]:
        if entry is None or datetime.fromisoformat(entry["expires"]) <= now:
            return frozenset()
        return frozenset(entry["sources"])

    def carried(self, turn: TurnContext) -> frozenset[str]:
        """Untrusted sources still in the history of ``turn``'s conversation."""
        key = self._conversation(turn)
        if key is None:
            return frozenset()
        with self._lock:
            return self._live(self._load().get(key), self._clock())

    def remember(self, turn: TurnContext, sources: Iterable[str] | str) -> None:
        """Add ``sources`` to ``turn``'s conversation and restart its ttl. Recording a turn
        that read nothing untrusted changes nothing."""
        key, new = self._conversation(turn), _sources(sources)
        if key is None or not new:
            return
        now = self._clock()
        with self._lock:
            conversations = dict(self._load())
            merged = self._live(conversations.get(key), now) | new
            conversations[key] = {"expires": (now + self.ttl).isoformat(),
                                  "sources": sorted(merged)}
            self._save(conversations, now)

    def forget(self, turn: TurnContext) -> None:
        """Clear ``turn``'s conversation, e.g. when its history is reset."""
        key = self._conversation(turn)
        if key is None:
            return
        with self._lock:
            conversations = dict(self._load())
            if conversations.pop(key, None) is not None:
                self._save(conversations, self._clock())
