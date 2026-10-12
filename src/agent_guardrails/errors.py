"""Error types. A :class:`Refused` carries two messages on purpose: a bland
``public_message`` that is safe to hand back to the model (and therefore to whoever is
talking to it), and a ``detail`` string that only goes to logs."""

from __future__ import annotations

from typing import Any

PUBLIC_MESSAGES: dict[str, str] = {
    "no_active_turn": "That isn't available right now.",
    "owner_only": "That isn't available on this conversation.",
    "recipient_not_allowed": "I can only send messages to you or to the owner.",
    "tainted_recipient": "This conversation includes outside content (such as an email), so "
                         "for now I can only send messages to the owner.",
    "invalid_recipient": "That recipient doesn't look valid. Use a full international "
                         "number (+country code) or a plain email address.",
    "scope_violation": "I can only look up your own conversation.",
    "invalid_args": "The request was malformed.",
    "unknown_tool": "That tool isn't available.",
    "tenant_unset": "This feature isn't configured yet.",
    "tenant_invalid": "This feature isn't configured correctly.",
    "cross_tenant": "That account isn't available here.",
    "approval_not_allowed": "That approval can't be processed here.",
    "too_many_pending": "There are already requests waiting for the owner. Please wait.",
    "not_allowlisted": "That kind of job can't be scheduled.",
    "interval_too_short": "That would run too often.",
    "schedule_unclear": "I couldn't work out when that should run.",
    "schedule_conflict": "That schedule can't be created.",
}

DEFAULT_PUBLIC_MESSAGE = "That isn't available right now."


class GuardrailError(Exception):
    """Base class for everything this library raises on purpose."""


class Refused(GuardrailError):
    """A guardrail said no. Raised *before* any side effect happens."""

    def __init__(self, code: str, public_message: str | None = None, *, detail: str = ""):
        self.code = code
        self.public_message = public_message or PUBLIC_MESSAGES.get(code, DEFAULT_PUBLIC_MESSAGE)
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)

    def to_dict(self) -> dict[str, Any]:
        """The shape handed back to a model: no internals, just a code and a safe sentence."""
        return {"ok": False, "code": self.code, "error": self.public_message}


class ConfigError(GuardrailError, ValueError):
    """Invalid configuration, detected at startup rather than at the first tool call."""


class StateCorrupt(GuardrailError):
    """A state file exists but can't be read. We stop instead of silently starting empty."""
