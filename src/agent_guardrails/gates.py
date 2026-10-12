"""Decorators that enforce who may do what, in code, before a tool body runs.

Every gate follows the same shape: bind the call's arguments, look up the active turn
(:func:`~agent_guardrails.context.current_turn`), decide, and only then call the wrapped
function. A refusal raises :class:`~agent_guardrails.errors.Refused` before any I/O, so a
gated tool can't half-run. Gates work on sync and async functions, keep the original
name, docstring and signature, and stack freely::

    @owner_only
    @untrusted_output("email")
    def read_inbox(query: str = "") -> list[dict]: ...

    @send_gate(recipient="to", channel="sms")
    def send_sms(to: str, body: str) -> dict: ...
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterable
from typing import Any, TypeVar, overload

from .context import current_turn, mark_untrusted
from .errors import Refused
from .identity import TurnContext, canonical_address, canonical_sender, channel_kind

F = TypeVar("F", bound=Callable[..., Any])
Check = Callable[[inspect.BoundArguments], None]


def bind_arguments(sig: inspect.Signature, args: tuple[Any, ...],
          kwargs: dict[str, Any]) -> inspect.BoundArguments:
    try:
        bound = sig.bind(*args, **kwargs)
    except TypeError as exc:
        raise Refused("invalid_args", detail=str(exc)) from None
    bound.apply_defaults()
    return bound


def guarded(fn: F, check: Check) -> F:
    """Wrap ``fn`` so ``check(bound_arguments)`` runs first. ``check`` may raise
    :class:`Refused` or rewrite ``bound.arguments`` (e.g. to pass a canonical value)."""
    sig = inspect.signature(fn)
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = bind_arguments(sig, args, kwargs)
            check(bound)
            return await fn(*bound.args, **bound.kwargs)
        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        bound = bind_arguments(sig, args, kwargs)
        check(bound)
        return fn(*bound.args, **bound.kwargs)
    return wrapper  # type: ignore[return-value]


# -- read gate --------------------------------------------------------------------------------

@overload
def owner_only(fn: F) -> F: ...
@overload
def owner_only(*, allow_system: bool = True) -> Callable[[F], F]: ...


def owner_only(fn: F | None = None, *, allow_system: bool = True) -> Any:
    """Refuse unless the active turn is the verified owner (or, by default, trusted
    in-process automation). Use it on anything that reads the owner's private data."""

    def decorate(func: F) -> F:
        def check(_bound: inspect.BoundArguments) -> None:
            turn = current_turn()
            if turn.is_owner or (allow_system and turn.is_trusted):
                return
            raise Refused("owner_only",
                          detail=f"{func.__name__} refused for {turn.role} ({turn.reason})")
        return guarded(func, check)

    return decorate(fn) if fn is not None else decorate


# -- send gate --------------------------------------------------------------------------------

def _is_self(turn: TurnContext, channel: str, target: str) -> bool:
    """Is ``target`` (canonical for ``channel``) the sender of this turn?"""
    if not turn.sender:
        return False
    if channel_kind(channel) == "account" and channel != turn.channel:
        return False
    if channel_kind(channel) != channel_kind(turn.channel):
        return False
    return canonical_sender(channel, target) == turn.sender


def send_gate(*, recipient: str = "to", channel: str | None = None,
              channel_param: str | None = None, channels: Iterable[str] | None = None,
              normalize: bool = True) -> Callable[[F], F]:
    """Gate an outbound message.

    * Every caller needs a recipient that canonicalises for the channel (an E.164 number,
      a plain email address, a platform id). Anything ambiguous is refused, because a
      provider may "helpfully" reinterpret it as someone else.
    * Owner and system turns may then send anywhere.
    * A third party may only message itself (a reply) or the owner (a relay).

    The channel is fixed with ``channel=`` or read from the call with ``channel_param=``
    (then it must be in ``channels``). With ``normalize`` the function receives the
    canonical recipient, so the API gets exactly the value that was checked.
    """
    if (channel is None) == (channel_param is None):
        raise TypeError("send_gate() needs exactly one of channel= or channel_param=")
    if channel_param is not None and not channels:
        raise TypeError("send_gate(channel_param=...) needs a channels= allowlist")
    allowed = frozenset(c.lower() for c in channels) if channels is not None else None

    def decorate(func: F) -> F:
        params = inspect.signature(func).parameters
        if recipient not in params:
            raise TypeError(f"{func.__name__}() has no recipient parameter {recipient!r}")
        if channel_param is not None and channel_param not in params:
            raise TypeError(f"{func.__name__}() has no channel parameter {channel_param!r}")

        def check(bound: inspect.BoundArguments) -> None:
            turn = current_turn()
            if channel is not None:
                chosen = channel.lower()
            else:
                chosen = str(bound.arguments.get(channel_param) or "").strip().lower()
                if allowed is not None and chosen not in allowed:
                    raise Refused("invalid_recipient", detail=f"channel {chosen!r} not allowed")
            raw = bound.arguments.get(recipient)
            target = canonical_address(chosen, raw)
            if target is None:
                raise Refused("invalid_recipient", detail=f"{raw!r} is not a valid {chosen} "
                                                          "address")
            if normalize:
                bound.arguments[recipient] = target
            if turn.is_trusted:
                return
            if _is_self(turn, chosen, target) or turn.owners.owns(chosen, target):
                return
            raise Refused("recipient_not_allowed",
                          detail=f"{turn.role} {turn.sender or '?'} tried {chosen}:{target}")

        return guarded(func, check)

    return decorate


# -- own records only -------------------------------------------------------------------------

def own_records_only(*, param: str = "contact") -> Callable[[F], F]:
    """Pin a lookup to the current sender on third-party turns.

    The owner (and system) may look up anyone. A third party may only look up itself: an
    omitted ``param`` is filled with its own canonical id, the same id in another format
    is accepted, and any other value is refused before the store is queried.
    """

    def decorate(func: F) -> F:
        if param not in inspect.signature(func).parameters:
            raise TypeError(f"{func.__name__}() has no parameter {param!r}")

        def check(bound: inspect.BoundArguments) -> None:
            turn = current_turn()
            if turn.is_trusted:
                return
            if not turn.sender:
                raise Refused("scope_violation", detail="sender has no usable identity")
            raw = bound.arguments.get(param)
            if raw not in (None, "") and canonical_sender(turn.channel, raw) != turn.sender:
                raise Refused("scope_violation",
                              detail=f"{turn.sender} tried to read records of {raw!r}")
            bound.arguments[param] = turn.sender

        return guarded(func, check)

    return decorate


# -- taint ------------------------------------------------------------------------------------

def untrusted_output(source: str) -> Callable[[F], F]:
    """Record that the active turn read untrusted content from ``source`` (an email
    body, a web page, a document) once the wrapped function returns successfully."""

    def decorate(func: F) -> F:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                current_turn()
                result = await func(*args, **kwargs)
                mark_untrusted(source)
                return result
            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_turn()
            result = func(*args, **kwargs)
            mark_untrusted(source)
            return result
        return wrapper  # type: ignore[return-value]

    return decorate
