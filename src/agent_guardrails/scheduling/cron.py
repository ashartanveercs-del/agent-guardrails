"""A deliberately strict 5-field cron parser.

Only syntax whose meaning is unambiguous is accepted: numbers, ``*``, ranges, lists, steps,
3-letter month/day names and the common ``@`` macros. Quartz extras (``?``, ``L``, ``W``,
``#``), a seconds field and ``@reboot`` are refused, as are dates that never exist
(``0 0 30 2 *``). A guardrail can't reason about a schedule it can't read.

:meth:`CronSchedule.min_gap` computes the *real* shortest interval between two runs from
the expanded minute and hour sets, including the wrap across the hour and midnight. Prefix
checks like "starts with ``*/``" miss ``0-59 * * * *`` (every minute) and
``*/7 * * * *`` (a 4-minute gap at :56 -> :00).

:meth:`CronSchedule.next_after` evaluates the schedule in the owner's time zone. A wall time
inside a spring-forward gap fires once, shifted forward by the gap; a wall time in the
repeated fall-back hour fires once, on its first occurrence.
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

MACROS = {
    "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}
_MONTHS = {name.lower(): i for i, name in enumerate(calendar.month_abbr) if name}
_DAYS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
_FIELD_RE = re.compile(r"[0-9A-Za-z*/,\-]+")
_NUMBER_RE = re.compile(r"[0-9]{1,2}")
_SEARCH_DAYS = 366 * 5 + 2


class CronError(ValueError):
    """The expression is invalid, unsupported or can never fire."""


def _value(token: str, lo: int, hi: int, names: dict[str, int] | None, label: str) -> int:
    lowered = token.lower()
    if names and lowered in names:
        return names[lowered]
    if not _NUMBER_RE.fullmatch(token):
        raise CronError(f"{label}: {token!r} is not a number")
    number = int(token)
    if not lo <= number <= hi:
        raise CronError(f"{label}: {number} is outside {lo}-{hi}")
    return number


def _field(text: str, lo: int, hi: int, names: dict[str, int] | None,
           label: str) -> frozenset[int]:
    if not _FIELD_RE.fullmatch(text):
        raise CronError(f"{label}: unsupported syntax {text!r}")
    values: set[int] = set()
    for item in text.split(","):
        if not item:
            raise CronError(f"{label}: empty list item in {text!r}")
        base, slash, step_text = item.partition("/")
        step = 1
        if slash:
            if not _NUMBER_RE.fullmatch(step_text) or not 1 <= int(step_text) <= hi - lo + 1:
                raise CronError(f"{label}: bad step {step_text!r}")
            step = int(step_text)
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            first, _, last = base.partition("-")
            start = _value(first, lo, hi, names, label)
            end = _value(last, lo, hi, names, label)
            if start > end:
                raise CronError(f"{label}: range {base!r} runs backwards")
        else:
            start = _value(base, lo, hi, names, label)
            end = hi if slash else start
        values.update(range(start, end + 1, step))
    return frozenset(values)


@dataclass(frozen=True)
class CronSchedule:
    expr: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]          # 0 = Sunday
    days_restricted: bool
    weekdays_restricted: bool

    @classmethod
    def parse(cls, expr: str) -> CronSchedule:
        text = (expr or "").strip()
        if text.startswith("@"):
            if text.lower() not in MACROS:
                raise CronError(f"unsupported macro {text!r} (@reboot and friends have no "
                                "time to check)")
            text = MACROS[text.lower()]
        parts = text.split()
        if len(parts) != 5:
            raise CronError(f"expected 5 fields (minute hour day month weekday), got {len(parts)}")
        minute, hour, day, month, weekday = parts
        dows = _field(weekday, 0, 7, _DAYS, "day of week")
        schedule = cls(
            expr=text,
            minutes=_field(minute, 0, 59, None, "minute"),
            hours=_field(hour, 0, 23, None, "hour"),
            days=_field(day, 1, 31, None, "day of month"),
            months=_field(month, 1, 12, _MONTHS, "month"),
            weekdays=frozenset(0 if d == 7 else d for d in dows),
            days_restricted=day != "*",
            weekdays_restricted=weekday != "*",
        )
        if schedule.days_restricted and not schedule.weekdays_restricted:
            longest = {m: 29 if m == 2 else calendar.monthrange(2026, m)[1]
                       for m in schedule.months}
            if not any(d <= longest[m] for m in schedule.months for d in schedule.days):
                raise CronError(f"{expr!r} never fires: those days don't exist in those months")
        return schedule

    def min_gap(self) -> timedelta:
        """Shortest possible interval between two consecutive runs (a lower bound: the
        wrap past midnight is always counted, even if the next day doesn't match)."""
        times = sorted(h * 60 + m for h in self.hours for m in self.minutes)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        gaps.append(times[0] + 1440 - times[-1])
        return timedelta(minutes=min(gaps))

    def matches_date(self, day: date) -> bool:
        if day.month not in self.months:
            return False
        dom = day.day in self.days
        dow = (day.weekday() + 1) % 7 in self.weekdays
        if self.days_restricted and self.weekdays_restricted:
            return dom or dow
        if self.days_restricted:
            return dom
        if self.weekdays_restricted:
            return dow
        return True

    def next_after(self, after: datetime, tz: ZoneInfo | str) -> datetime:
        """The first run strictly after ``after``, as an aware UTC datetime."""
        if after.tzinfo is None:
            raise ValueError("next_after() needs a timezone-aware datetime")
        zone = ZoneInfo(tz) if isinstance(tz, str) else tz
        start = after.astimezone(zone).date()
        clock = sorted((h, m) for h in self.hours for m in self.minutes)
        for offset in range(_SEARCH_DAYS):
            day = start + timedelta(days=offset)
            if not self.matches_date(day):
                continue
            # fold=0: a gap time maps forward by the gap, a repeated time to its first pass
            runs = [datetime(day.year, day.month, day.day, h, m, tzinfo=zone).astimezone(UTC)
                    for h, m in clock]
            later = [run for run in runs if run > after]
            if later:
                return min(later)
        raise CronError(f"{self.expr!r} does not fire within five years")
