"""Carry-forward hygiene for recurring briefings ("here's what's still open").

Two ways a daily briefing goes wrong: it keeps repeating something that was dealt with
days ago (yesterday's summary said "invoice unpaid", so today's does too), and it nags
about the same item every single day until the owner tunes it out. This module makes
both structurally impossible:

* **Re-checked or not shown.** An item from a previous briefing is shown again only if a
  collector found it again in *this* run, or its kind's verifier re-checked it against
  the source of truth and said it is still open. A verifier that fails, times out or
  doesn't exist yields ``UNKNOWN``, and unknown is never shown as open. After a few
  unknown runs in a row the item is dropped.
* **Age-based backoff.** Reminders fire on fixed ages (days 0, 1, 3 and 7 by default,
  counted in the owner's local days), the last one is flagged ``final``, and after the
  give-up age the item is dropped. A missed briefing catches up once; it never nags twice
  in a day.
* **Spent only when delivered.** :meth:`CarryForward.plan` computes the briefing without
  writing anything; :meth:`CarryForward.commit` records it after delivery succeeded. A
  stale plan (state changed in between) is refused.
* **Instance-scoped resolution.** The owner resolving ``invoice:INV-1042`` archives that
  item for a while; it never blacklists invoices. A new invoice is a new key and shows up
  immediately; archives expire so a genuine recurrence resurfaces. Permanent muting is a
  separate, owner-only, reversible action.
"""

from __future__ import annotations

import copy
import logging
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .context import current_turn
from .errors import ConfigError, GuardrailError, Refused
from .identity import Role
from .storage import JsonFile

log = logging.getLogger(__name__)
_KIND_RE = re.compile(r"[a-z0-9_\-]{1,40}")


class Status(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class StalePlan(GuardrailError):
    """The ledger changed after the plan was made; plan again."""


def item_key(kind: str, text: str) -> str:
    """A stable key for collectors without natural ids. Case, punctuation and spacing are
    ignored; numbers are kept, so invoice 1042 and invoice 1043 are different items."""
    words = re.sub(r"[^a-z0-9]+", " ", text.lower()).split()
    return f"{kind}:{' '.join(words)}"


@dataclass(frozen=True)
class Backoff:
    remind_on_days: tuple[int, ...] = (0, 1, 3, 7)
    give_up_after_days: int = 14

    def __post_init__(self) -> None:
        days = self.remind_on_days
        if not days or days[0] != 0:
            raise ValueError("reminders must start on day 0")
        if any(b <= a for a, b in zip(days, days[1:], strict=False)):
            raise ValueError("reminder days must be strictly increasing")
        if self.give_up_after_days <= days[-1]:
            raise ValueError("give_up_after_days must come after the last reminder")


@dataclass(frozen=True)
class Candidate:
    """An open item a collector found in this run, from a source of truth."""

    key: str
    kind: str
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key.strip() or len(self.key) > 200:
            raise ValueError("candidate keys must be 1-200 characters")
        if not _KIND_RE.fullmatch(self.kind):
            raise ValueError(f"invalid item kind {self.kind!r}")


@dataclass(frozen=True)
class TrackedItem:
    """What a verifier is given to re-check."""

    key: str
    kind: str
    text: str
    first_seen: date


@dataclass(frozen=True)
class PlannedItem:
    key: str
    kind: str
    text: str
    age_days: int
    reminder: int        # 1-based
    final: bool          # the last scheduled reminder


@dataclass
class BriefingPlan:
    today: date
    revision: int
    show: list[PlannedItem] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)   # open, but not due a reminder
    closed: list[str] = field(default_factory=list)       # verified closed this run
    unverified: list[str] = field(default_factory=list)   # couldn't re-check: not shown
    dropped: list[str] = field(default_factory=list)      # aged out or unverifiable
    next_state: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class _Tracked:
    key: str
    kind: str
    text: str
    first_seen: date
    reminders: int = 0
    last_shown: date | None = None
    unverified_runs: int = 0
    closed_on: date | None = None

    def to_json(self) -> dict[str, Any]:
        return {"key": self.key, "kind": self.kind, "text": self.text,
                "first_seen": self.first_seen.isoformat(), "reminders": self.reminders,
                "last_shown": self.last_shown.isoformat() if self.last_shown else None,
                "unverified_runs": self.unverified_runs,
                "closed_on": self.closed_on.isoformat() if self.closed_on else None}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> _Tracked:
        def day(value: str | None) -> date | None:
            return date.fromisoformat(value) if value else None
        return cls(key=data["key"], kind=data["kind"], text=data["text"],
                   first_seen=date.fromisoformat(data["first_seen"]),
                   reminders=data.get("reminders", 0), last_shown=day(data.get("last_shown")),
                   unverified_runs=data.get("unverified_runs", 0),
                   closed_on=day(data.get("closed_on")))


class _MemoryState:
    def __init__(self) -> None:
        self._data: Any = None

    def read(self, default: Any) -> Any:
        return copy.deepcopy(self._data if self._data is not None else default)

    def write(self, data: Any) -> None:
        self._data = copy.deepcopy(data)


_EMPTY = {"version": 1, "revision": 0, "items": {}, "archived": {}, "muted": []}
Verifier = Callable[[TrackedItem], Any]


class CarryForward:
    def __init__(self, path: str | Path | None = None, *, verifiers: Mapping[str, Verifier],
                 backoff: Backoff | None = None, timezone: str = "UTC",
                 clock: Callable[[], datetime] | None = None, archive_days: int = 45,
                 max_unverified_runs: int = 3) -> None:
        try:
            self._zone = ZoneInfo(timezone)
        except Exception:
            raise ConfigError(f"unknown time zone {timezone!r}") from None
        self._state = JsonFile(path) if path is not None else _MemoryState()
        self.verifiers = dict(verifiers)
        self.backoff = backoff or Backoff()
        self.archive_days = archive_days
        self.max_unverified_runs = max_unverified_runs
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()

    # -- briefing ------------------------------------------------------------------------

    def plan(self, fresh: Iterable[Candidate] = ()) -> BriefingPlan:
        """Decide what today's briefing shows. Writes nothing."""
        today = self._today()
        with self._lock:
            state = self._state.read(_EMPTY)
        items = {k: _Tracked.from_json(v) for k, v in state["items"].items()}
        archived = {k: v for k, v in state["archived"].items()
                    if (today - date.fromisoformat(v)).days <= self.archive_days}
        muted = list(state["muted"])
        found: dict[str, Candidate] = {}
        for candidate in fresh:
            found.setdefault(candidate.key, candidate)

        plan = BriefingPlan(today=today, revision=state["revision"])
        keep: dict[str, _Tracked] = {}
        for key in sorted(items):
            item = items[key]
            if self._is_muted(key, muted) or key in archived:
                continue
            candidate = found.pop(key, None)
            if candidate is not None:              # seen again in the source of truth
                item.text, item.kind = candidate.text, candidate.kind
                item.closed_on, item.unverified_runs = None, 0
                status = Status.OPEN
            elif item.closed_on is not None:       # closed earlier; remembered, not shown
                if (today - item.closed_on).days <= self.archive_days:
                    keep[key] = item
                continue
            else:
                status = self._verify(item)
            if status is Status.CLOSED:
                item.closed_on = today
                keep[key] = item
                plan.closed.append(key)
            elif status is Status.UNKNOWN:
                item.unverified_runs += 1
                if item.unverified_runs >= self.max_unverified_runs:
                    plan.dropped.append(key)
                else:
                    keep[key] = item
                    plan.unverified.append(key)
            else:
                item.unverified_runs = 0
                self._ladder(item, today, plan, keep)
        for key in sorted(found):
            candidate = found[key]
            if self._is_muted(key, muted) or key in archived:
                continue
            self._ladder(_Tracked(key, candidate.kind, candidate.text, today), today, plan, keep)

        plan.show.sort(key=lambda p: (-p.age_days, p.key))
        plan.next_state = {"version": 1, "revision": state["revision"],
                           "items": {k: v.to_json() for k, v in keep.items()},
                           "archived": archived, "muted": muted}
        return plan

    def commit(self, plan: BriefingPlan) -> None:
        """Record a briefing that was actually delivered."""
        with self._lock:
            current = self._state.read(_EMPTY)
            if current["revision"] != plan.revision:
                raise StalePlan("the briefing ledger changed since this plan was made")
            state = copy.deepcopy(plan.next_state)
            state["revision"] = current["revision"] + 1
            self._state.write(state)

    # -- owner actions ---------------------------------------------------------------------

    def resolve(self, key: str) -> bool:
        """Owner or system: archive this item instance. Returns whether it was tracked."""
        turn = current_turn()
        if not turn.is_trusted:
            raise Refused("owner_only", detail="only the owner can close briefing items")
        with self._lock:
            state = self._state.read(_EMPTY)
            existed = state["items"].pop(key, None) is not None
            state["archived"][key] = self._today().isoformat()
            state["revision"] += 1
            self._state.write(state)
        return existed

    def mute(self, prefix: str) -> None:
        """Owner only: never show items whose key starts with ``prefix`` (until unmuted)."""
        self._require_owner()
        if not isinstance(prefix, str) or len(prefix.strip()) < 3:
            raise ValueError("mute prefixes must be at least 3 characters")
        with self._lock:
            state = self._state.read(_EMPTY)
            if prefix not in state["muted"]:
                state["muted"].append(prefix)
            state["items"] = {k: v for k, v in state["items"].items()
                              if not k.startswith(prefix)}
            state["revision"] += 1
            self._state.write(state)

    def unmute(self, prefix: str) -> None:
        self._require_owner()
        with self._lock:
            state = self._state.read(_EMPTY)
            state["muted"] = [m for m in state["muted"] if m != prefix]
            state["revision"] += 1
            self._state.write(state)

    # -- internals ---------------------------------------------------------------------------

    @staticmethod
    def _require_owner() -> None:
        turn = current_turn()
        if turn.role is not Role.OWNER:
            raise Refused("owner_only", detail="only the owner can mute briefing items")

    @staticmethod
    def _is_muted(key: str, muted: list[str]) -> bool:
        return any(key.startswith(prefix) for prefix in muted)

    def _today(self) -> date:
        return self._clock().astimezone(self._zone).date()

    def _verify(self, item: _Tracked) -> Status:
        verifier = self.verifiers.get(item.kind)
        if verifier is None:
            return Status.UNKNOWN
        try:
            result = verifier(TrackedItem(item.key, item.kind, item.text, item.first_seen))
        except Exception:
            log.warning("verifier for %s failed; treating %s as unknown", item.kind, item.key,
                        exc_info=True)
            return Status.UNKNOWN
        if result is True or result is Status.OPEN:
            return Status.OPEN
        if result is False or result is Status.CLOSED:
            return Status.CLOSED
        return Status.UNKNOWN

    def _ladder(self, item: _Tracked, today: date, plan: BriefingPlan,
                keep: dict[str, _Tracked]) -> None:
        age = (today - item.first_seen).days
        days = self.backoff.remind_on_days
        if age > self.backoff.give_up_after_days:
            plan.dropped.append(item.key)
            return
        keep[item.key] = item
        if item.last_shown == today:
            plan.suppressed.append(item.key)
        elif item.reminders < len(days) and age >= days[item.reminders]:
            item.reminders += 1
            item.last_shown = today
            plan.show.append(PlannedItem(item.key, item.kind, item.text, age, item.reminders,
                                         item.reminders == len(days)))
        else:
            plan.suppressed.append(item.key)
