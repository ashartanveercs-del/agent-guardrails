"""The active turn, held in a :mod:`contextvars` variable.

Gates look the turn up here instead of taking it as an argument, so there is no parameter
a model could fill in to change who it is acting for. Context variables follow asyncio
tasks automatically; a bare ``threading.Thread`` starts with no turn at all, which makes
gated calls from it fail closed (use ``contextvars.copy_context().run`` to hand a turn
to a worker thread on purpose).

Each scope also tracks *taint*: the names of untrusted sources (an email body, a web page)
whose content entered the model's context during this turn. Approval policies use it to
stop an owner's turn from acting on instructions hidden in data the agent just read.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from .errors import Refused
from .identity import TurnContext


@dataclass
class _ActiveTurn:
    turn: TurnContext
    taint: set[str] = field(default_factory=set)


_ACTIVE: ContextVar[_ActiveTurn | None] = ContextVar("agent_guardrails_turn", default=None)


@contextmanager
def turn_scope(turn: TurnContext) -> Iterator[TurnContext]:
    """Make ``turn`` the active turn for the duration of the ``with`` block."""
    if not isinstance(turn, TurnContext):
        raise TypeError("turn_scope() needs a TurnContext from classify_turn()")
    token = _ACTIVE.set(_ActiveTurn(turn))
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
    """Untrusted sources read so far in the active turn."""
    return frozenset(_active().taint)
