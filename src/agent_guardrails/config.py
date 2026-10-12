"""Settings from environment variables, validated once at startup.

Every problem raises :class:`~agent_guardrails.errors.ConfigError` naming the variable
(never echoing a secret's value). Defaults are the conservative ones: no owner until one
is configured, no tenant (so tenant-scoped tools refuse), a five-minute scheduling floor.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from .errors import ConfigError
from .identity import OwnerIdentity
from .sealing import MIN_KEY_BYTES
from .tenancy import TenantBinding

PREFIX = "GUARDRAILS_"


_ENV_LINE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*")


def read_env_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Read ``KEY=value`` lines (``#`` comments, blank lines and one level of matching
    quotes allowed). Anything else is an error naming the line, never a silent skip."""
    values: dict[str, str] = {}
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ENV_LINE.fullmatch(line)
        if match is None:
            raise ConfigError(f"{path}: line {number} is not a KEY=value assignment")
        key, value = match.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def _list(value: str | None) -> list[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _int(environ: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number") from None
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}")
    return value


@dataclass(frozen=True)
class Settings:
    owners: OwnerIdentity
    timezone: str
    tenant: TenantBinding
    min_schedule_interval: timedelta
    approval_ttl: timedelta
    envelope_key: bytes | None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if environ is None else environ
        accounts: dict[str, list[str]] = {}
        for entry in _list(env.get(f"{PREFIX}OWNER_ACCOUNTS")):
            channel, sep, account = entry.partition(":")
            if not sep or not channel.strip() or not account.strip():
                raise ConfigError(f"{PREFIX}OWNER_ACCOUNTS entries look like 'slack:U123'")
            accounts.setdefault(channel.strip(), []).append(account.strip())
        parts = {"OWNER_PHONES": {"phones": _list(env.get(f"{PREFIX}OWNER_PHONES"))},
                 "OWNER_EMAILS": {"emails": _list(env.get(f"{PREFIX}OWNER_EMAILS"))},
                 "OWNER_ACCOUNTS": {"accounts": accounts}}
        for variable, kwargs in parts.items():        # validate each one on its own
            try:
                OwnerIdentity(**kwargs)
            except ValueError as exc:
                raise ConfigError(f"{PREFIX}{variable}: {exc}") from None
        owners = OwnerIdentity(**{k: v for part in parts.values() for k, v in part.items()})

        timezone = env.get(f"{PREFIX}TIMEZONE", "").strip() or "UTC"
        try:
            ZoneInfo(timezone)
        except Exception:
            raise ConfigError(f"{PREFIX}TIMEZONE: unknown time zone {timezone!r}") from None

        try:
            tenant = TenantBinding(env.get(f"{PREFIX}TENANT_ID"), source=f"{PREFIX}TENANT_ID")
        except ConfigError as exc:
            raise ConfigError(f"{PREFIX}TENANT_ID: {exc}") from None

        minutes = _int(env, f"{PREFIX}MIN_INTERVAL_MINUTES", 5, 5, 24 * 60)
        hours = _int(env, f"{PREFIX}APPROVAL_TTL_HOURS", 24, 1, 168)

        key = env.get(f"{PREFIX}ENVELOPE_KEY", "")
        if key and len(key.encode("utf-8")) < MIN_KEY_BYTES:
            raise ConfigError(f"{PREFIX}ENVELOPE_KEY must be at least {MIN_KEY_BYTES} bytes")

        return cls(owners=owners, timezone=timezone, tenant=tenant,
                   min_schedule_interval=timedelta(minutes=minutes),
                   approval_ttl=timedelta(hours=hours),
                   envelope_key=key.encode("utf-8") if key else None)
