"""Fail-closed tenant isolation for multi-tenant backends.

Many SaaS APIs give you one project-level key that can address *any* tenant: the tenant
(or "user", or "entity") id is just a request parameter, not an authentication boundary.
Two failure modes then leak data silently:

1. **Unset id.** A deployment without its tenant id quietly falls back to a default like
   ``"default"`` - and every misconfigured deployment lands in the same tenant.
2. **Foreign id.** The model (or a skill it wrote) passes some other tenant's id.

:func:`tenant_scoped` closes both. The tenant comes from configuration only; an unset,
blank or shared placeholder id refuses the call; a model-supplied id that isn't exactly the
bound one refuses the call; and the backend always receives the bound id.
"""

from __future__ import annotations

import inspect
import logging
import re
from collections.abc import Callable
from typing import Any, TypeVar

from .errors import ConfigError, Refused
from .gates import guarded

log = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])

SHARED_TENANT_IDS = frozenset({"default", "owner", "admin", "root", "public", "shared", "test",
                               "demo", "none", "null", "undefined", "all", "any", "*"})
_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,127}")


class TenantBinding:
    """The one tenant this deployment may address."""

    def __init__(self, tenant_id: str | None, *, source: str = "config") -> None:
        value = (tenant_id or "").strip()
        if value and (not _TENANT_RE.fullmatch(value) or ".." in value):
            raise ConfigError(f"invalid tenant id from {source}: {tenant_id!r}")
        self._tenant = value or None
        self.source = source
        if self._tenant is None:
            log.warning("no tenant id configured: tenant-scoped tools will refuse every call")
        elif self._tenant.lower() in SHARED_TENANT_IDS:
            log.warning("tenant id %r is a shared placeholder: tenant-scoped tools will refuse",
                        self._tenant)

    @classmethod
    def from_sources(cls, **sources: str | None) -> TenantBinding:
        """Resolve from several places (``env=..., config_file=...``). Blank sources are
        ignored; two sources that disagree are a configuration error, not a coin toss."""
        found = {name: value.strip() for name, value in sources.items()
                 if value and value.strip()}
        if len(set(found.values())) > 1:
            listed = ", ".join(f"{name}={value!r}" for name, value in found.items())
            raise ConfigError(f"conflicting tenant ids ({listed}); refusing to guess")
        if not found:
            return cls(None, source="unset")
        name, value = next(iter(found.items()))
        return cls(value, source=name)

    @property
    def tenant_id(self) -> str | None:
        return self._tenant

    def require(self) -> str:
        """The bound tenant id, or a refusal if there isn't a usable one."""
        if self._tenant is None:
            raise Refused("tenant_unset",
                          detail="no tenant id configured; refusing to call a shared backend")
        if self._tenant.lower() in SHARED_TENANT_IDS:
            raise Refused("tenant_invalid",
                          detail=f"tenant id {self._tenant!r} is a shared placeholder")
        return self._tenant

    def check(self, requested: object) -> str:
        """Accept ``None``/``""`` (meaning "mine") or exactly the bound id."""
        own = self.require()
        if requested in (None, ""):
            return own
        if requested != own:
            raise Refused("cross_tenant",
                          detail=f"requested tenant {requested!r}; this deployment is {own!r}")
        return own


def tenant_scoped(binding: TenantBinding, *, param: str = "tenant_id") -> Callable[[F], F]:
    """Inject the bound tenant into ``param`` and refuse anything else, before the call.
    Keep ``param`` out of the tool's model-facing schema; the toolbox then rejects it as an
    unexpected property and this decorator is the second line of defence."""

    def decorate(fn: F) -> F:
        if param not in inspect.signature(fn).parameters:
            raise TypeError(f"{fn.__name__}() has no tenant parameter {param!r}")

        def check(bound: inspect.BoundArguments) -> None:
            bound.arguments[param] = binding.check(bound.arguments.get(param))

        return guarded(fn, check)

    return decorate
