"""Resolve natural-language times ("tomorrow at 9", "every weekday at 7:30am") in code.

The model should never do date arithmetic. It forwards the owner's words; this module
resolves them against the owner's clock and time zone, and returns a human echo
("Tue Oct 13, 2026 at 9:00 AM EDT") for the owner to confirm before anything is scheduled.

Rules worth knowing:

* "Tomorrow" is the owner's tomorrow. At 21:30 in Los Angeles it is already Tuesday in UTC;
  computing from the UTC date would land a day late.
* A bare hour with no day ("at 9") means the next time the clock shows it (9 PM if 9 AM
  has passed). With a day ("tomorrow at 5") 7-11 read as morning and 12-6 as afternoon.
  "morning", "tonight" and friends override both.
* An explicit day in the past is refused, never silently moved forward.
* Things cron can't express faithfully are refused instead of approximated: "every 7
  minutes" (the hour wrap breaks it), "every other day" (the month wrap breaks it), the
  31st of every month (most months don't have one).
* Ambiguous input is refused: "10/11" (October 11 or November 10?), two different times,
  a relative time combined with a day, digits that weren't understood.
* A wall time inside a spring-forward gap is refused; a repeated fall-back time resolves to
  its first occurrence and the echo shows which (EDT vs EST).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

MAX_PHRASE = 200
MAX_AHEAD = timedelta(days=366)
_DAY_ABBR = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")   # not %a: locale-independent
_MONTH_ABBR = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
               "Nov", "Dec"]

_ONES = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
         "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
         "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
         "nineteen": 19}
_TENS = {"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50}
_HOUR_WORD = "(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)"
_HOUR = rf"(?:\d{{1,2}}|{_HOUR_WORD})"
_UNIT_DIGIT = "(?:one|two|three|four|five|six|seven|eight|nine)"

_WEEKDAYS = {"monday": 0, "mon": 0, "tuesday": 1, "tues": 1, "tue": 1, "wednesday": 2,
             "wed": 2, "thursday": 3, "thurs": 3, "thur": 3, "thu": 3, "friday": 4, "fri": 4,
             "saturday": 5, "sat": 5, "sunday": 6, "sun": 6}
_MONTHS = {"january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3, "april": 4,
           "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7, "august": 8,
           "aug": 8, "september": 9, "sept": 9, "sep": 9, "october": 10, "oct": 10,
           "november": 11, "nov": 11, "december": 12, "dec": 12}


def _alternation(words: dict[str, int]) -> str:
    return "|".join(sorted(words, key=len, reverse=True))


_MONTH_NAMES = _alternation(_MONTHS)
_WEEKDAY_RE = re.compile(rf"\b(next\s+|this\s+)?({_alternation(_WEEKDAYS)})(s)?\b")
_MONTH_DAY_RE = re.compile(rf"\b({_MONTH_NAMES})\.?\s+(\d{{1,2}})(?:st|nd|rd|th)?\b")
_DAY_MONTH_RE = re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?({_MONTH_NAMES})\b")
_ISO_RE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
_UNITS = r"(?:minutes?|mins?|hours?|hrs?|days?|weeks?)"

_UNSUPPORTED = [
    r"\bevery\s+other\b",
    r"\bevery\s+\d+\s*(?:days?|weeks?|months?|years?)\b",
    r"\b(?:bi-?weekly|fortnight(?:ly)?|semi-?monthly)\b",
    r"\b(?:yearly|annually|every\s+year|each\s+year)\b",
    r"\bevery\s+(?:second|third|fourth|last)\b",
    r"\bevery\s+\d+\s*(?:seconds?|secs?)\b",
]

# name, default time, meridiem hint
_DAY_PARTS = [
    (r"\b(?:this\s+morning|in\s+the\s+morning|mornings?)\b", "morning", (9, 0), "am"),
    (r"\b(?:this\s+afternoon|in\s+the\s+afternoon|afternoons?)\b", "afternoon", (15, 0), "pm"),
    (r"\b(?:this\s+evening|in\s+the\s+evening|evenings?)\b", "evening", (18, 0), "pm"),
    (r"\btonight\b", "tonight", (20, 0), "pm"),
    (r"\b(?:at\s+night|nights?)\b", "night", (21, 0), "pm"),
]
_DAY_WORDS = (r"(?:tonight|tomorrow|today|this\s+(?:morning|afternoon|evening)|"
              r"in\s+the\s+(?:morning|afternoon|evening)|at\s+night)")


class WhenError(ValueError):
    """The phrase is unclear, unsupported, ambiguous or in the past."""


@dataclass(frozen=True)
class Resolved:
    """``run_at`` is an aware **UTC** instant. Local wall times in a repeated DST hour are
    fold-ambiguous, and PEP 495 makes ``==`` between such a time and any other zone's
    datetime return False, so instants are kept in UTC and localised only for display."""

    kind: str                       # "once" or "recurring"
    timezone: str
    human: str                      # what to read back to the owner before scheduling
    cron: str | None = None         # recurring only; evaluated in `timezone`
    run_at: datetime | None = None  # once only; aware UTC

    @property
    def recurring(self) -> bool:
        return self.kind == "recurring"

    def to_dict(self) -> dict[str, Any]:
        local = self.run_at.astimezone(ZoneInfo(self.timezone)) if self.run_at else None
        return {"kind": self.kind, "timezone": self.timezone, "human": self.human,
                "cron": self.cron, "run_at": local.isoformat() if local else None}


@dataclass(frozen=True)
class _Clock:
    hour: int
    minute: int
    exact: bool          # False: a 1-12 hour with no am/pm


# -- text helpers ------------------------------------------------------------------------------

def _num(token: str) -> int:
    return int(token) if token.isdigit() else _ONES[token]


def _spell_out(text: str) -> str:
    """Rewrite spoken clock times and number words into digits."""
    def fraction(m: re.Match[str]) -> str:
        hour = _num(m.group(2))
        if not 1 <= hour <= 12:
            return m.group(0)
        if m.group(1) == "half past":
            return f"{hour}:30"
        if m.group(1) == "quarter past":
            return f"{hour}:15"
        return f"{12 if hour == 1 else hour - 1}:45"

    def hour_and_minutes(m: re.Match[str]) -> str:
        words = m.group(2)
        mins = 45 if words.startswith("forty") else 30 if words == "thirty" else 15
        return f"{_num(m.group(1))}:{mins:02d}"

    text = re.sub(rf"\b(half past|quarter past|quarter to)\s+({_HOUR})\b", fraction, text)
    text = re.sub(rf"\b({_HOUR})\s*o'?\s?clock\b", lambda m: f"{_num(m.group(1))}:00", text)
    text = re.sub(rf"\b({_HOUR_WORD})\s+(fifteen|thirty|forty[\s-]?five)\b",
                  hour_and_minutes, text)
    text = re.sub(rf"\b(twenty|thirty|forty|fifty)[\s-]({_UNIT_DIGIT})\b",
                  lambda m: str(_TENS[m.group(1)] + _ONES[m.group(2)]), text)
    text = re.sub(r"\b(twenty|thirty|forty|fifty)\b", lambda m: str(_TENS[m.group(1)]), text)
    return re.sub(rf"\b({'|'.join(_ONES)})\b", lambda m: str(_ONES[m.group(1)]), text)


def _normalise(phrase: str) -> str:
    text = phrase.strip().lower().replace("’", "'")
    text = re.sub(r"(\d)\s*([ap])\.?\s*m\b\.?", r"\1\2m", text)     # 9 a.m. -> 9am
    text = re.sub(r"[,;!]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return _spell_out(text).strip()


def _take(pattern: str | re.Pattern[str], text: str) -> tuple[list[re.Match[str]], str]:
    """All matches of ``pattern`` plus ``text`` with them blanked out."""
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    return list(regex.finditer(text)), regex.sub(" ", text)


def _clock_text(hour: int, minute: int) -> str:
    return f"{(hour % 12) or 12}:{minute:02d} {'AM' if hour < 12 else 'PM'}"


def _human_once(moment: datetime) -> str:
    return (f"{_DAY_ABBR[moment.weekday()]} {_MONTH_ABBR[moment.month]} {moment.day}, "
            f"{moment.year} at {_clock_text(moment.hour, moment.minute)} {moment.tzname()}")


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except Exception:
        raise WhenError(f"unknown time zone {name!r}") from None


# -- extraction -------------------------------------------------------------------------------

def _interval(text: str) -> tuple[tuple[str, str] | None, str]:
    found, rest = _take(r"\bhourly\b", text)
    if found:
        return ("0 * * * *", "every hour"), rest
    found, rest = _take(r"\bevery\s+(?:(\d+)\s*)?(minutes?|mins?|hours?|hrs?)\b", text)
    if not found:
        return None, text
    count = int(found[0].group(1) or 1)
    if found[0].group(2).startswith("m"):
        if count == 1:
            return ("* * * * *", "every minute"), rest
        if count >= 60 or 60 % count:
            raise WhenError(f"every {count} minutes can't be expressed as a cron schedule; "
                            "use a number that divides 60 (5, 10, 15, 20 or 30)")
        return (f"*/{count} * * * *", f"every {count} minutes"), rest
    if count == 1:
        return ("0 * * * *", "every hour"), rest
    if count >= 24 or 24 % count:
        raise WhenError(f"every {count} hours can't be expressed as a cron schedule; "
                        "use 2, 3, 4, 6, 8 or 12")
    return (f"0 */{count} * * *", f"every {count} hours"), rest


def _relative(text: str) -> tuple[tuple[int, timedelta] | None, str]:
    """``in ...`` as (calendar days, elapsed time). Days keep the wall-clock time ("in 3
    days" is the same time of day even across a DST change); minutes and hours are real
    elapsed time ("in 2 hours" is two hours from now, not two hours of wall clock)."""
    pattern = (rf"\bin\s+((?:(?:\d+|half\s+an?|an?)\s*{_UNITS}\s*(?:and\s+)?)+)")
    found, rest = _take(pattern, text)
    if not found:
        return None, text
    if len(found) > 1:
        raise WhenError("more than one relative time")
    days, elapsed = 0, timedelta()
    for qty, unit in re.findall(rf"(\d+|half\s+an?|an?)\s*({_UNITS})", found[0].group(1)):
        amount = 0.5 if qty.startswith("half") else 1 if qty in ("a", "an") else int(qty)
        if unit.startswith("m"):
            elapsed += timedelta(minutes=amount)
        elif unit.startswith("h"):
            elapsed += timedelta(hours=amount)
        elif amount != int(amount):
            raise WhenError("use hours for part of a day")
        else:
            days += int(amount) * (7 if unit.startswith("w") else 1)
    if days * timedelta(days=1) + elapsed <= timedelta(0) or \
            days * timedelta(days=1) + elapsed > MAX_AHEAD:
        raise WhenError("relative times must be between 1 minute and a year ahead")
    return (days, elapsed), rest


def _month_day(text: str, today: date) -> tuple[date | None, str]:
    found: list[date] = []
    matches, text = _take(_ISO_RE, text)
    for m in matches:
        try:
            found.append(date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
        except ValueError:
            raise WhenError(f"{m.group(0)} is not a real date") from None
    for regex, month_group, day_group in ((_MONTH_DAY_RE, 1, 2), (_DAY_MONTH_RE, 2, 1)):
        matches, text = _take(regex, text)
        for m in matches:
            month, day = _MONTHS[m.group(month_group)], int(m.group(day_group))
            try:
                candidate = date(today.year, month, day)
            except ValueError:
                raise WhenError(f"{m.group(0).strip()} is not a real date") from None
            if candidate < today:
                candidate = date(today.year + 1, month, day)
            found.append(candidate)
    if len(set(found)) > 1:
        raise WhenError("more than one date")
    return (found[0] if found else None), text


def _clocks(text: str) -> tuple[list[_Clock], bool, str]:
    """Times of day, a midnight flag, and the text with both removed."""
    clocks: list[_Clock] = []
    midnight, text = _take(r"\bmidnight\b", text)
    noon, text = _take(r"\b(?:noon|midday)\b", text)
    clocks += [_Clock(12, 0, True) for _ in noon]

    matches, text = _take(r"\b(\d{1,2}):(\d{2})\s*(am|pm)?(?![\w:])", text)
    for m in matches:
        hour, minute, meridiem = int(m.group(1)), int(m.group(2)), m.group(3)
        if minute > 59:
            raise WhenError(f"{m.group(0)} is not a time")
        if meridiem:
            clocks.append(_meridiem_clock(hour, minute, meridiem))
        elif hour > 23:
            raise WhenError(f"{m.group(0)} is not a time")
        else:
            exact = hour == 0 or hour >= 13 or m.group(1).startswith("0")
            clocks.append(_Clock(hour, minute, exact))

    matches, text = _take(r"\b(\d{1,2})(am|pm)\b", text)
    clocks += [_meridiem_clock(int(m.group(1)), 0, m.group(2)) for m in matches]

    hours: list[int] = []
    for pattern in (rf"\b(?:at|by|@|around)\s+(\d{{1,2}})\b(?!\s*(?:{_UNITS}|st|nd|rd|th)\b)",
                    rf"\b(\d{{1,2}})\s+(?={_DAY_WORDS}\b)"):
        matches, text = _take(pattern, text)
        hours += [int(m.group(1)) for m in matches]
    # "tomorrow 9": keep the day word, take the hour
    after_day = re.compile(rf"\b(today|tomorrow|tonight)\s+(\d{{1,2}})\b(?!\s*(?:{_UNITS})\b)")
    hours += [int(m.group(2)) for m in after_day.finditer(text)]
    text = after_day.sub(lambda m: m.group(1) + " ", text)
    for hour in hours:
        if hour > 23:
            raise WhenError(f"{hour} is not an hour")
        clocks.append(_Clock(hour, 0, hour == 0 or hour >= 13))
    return clocks, bool(midnight), text


def _meridiem_clock(hour: int, minute: int, meridiem: str) -> _Clock:
    if not 1 <= hour <= 12:
        raise WhenError(f"{hour}{meridiem} is not a time")
    hour = hour % 12 + (12 if meridiem == "pm" else 0)
    return _Clock(hour, minute, True)


def _day_part(text: str) -> tuple[tuple[str, tuple[int, int], str] | None, str]:
    found = []
    for pattern, name, default, hint in _DAY_PARTS:
        matches, text = _take(pattern, text)
        if matches:
            found.append((name, default, hint))
    if len({name for name, _, _ in found}) > 1:
        raise WhenError("more than one part of the day")
    return (found[0] if found else None), text


def _candidates(clock: _Clock, hint: str | None, anchored: bool) -> list[tuple[int, int]]:
    """Possible (hour, minute) readings of a clock time."""
    if clock.exact:
        return [(clock.hour, clock.minute)]
    morning = (0 if clock.hour == 12 else clock.hour, clock.minute)
    afternoon = (12 if clock.hour == 12 else clock.hour + 12, clock.minute)
    if hint == "am":
        return [morning]
    if hint == "pm":
        return [afternoon]
    if anchored:
        return [morning] if 7 <= clock.hour <= 11 else [afternoon]
    return [morning, afternoon]


def _localize(day: date, hour: int, minute: int, zone: ZoneInfo) -> datetime:
    wall = datetime.combine(day, time(hour, minute))
    aware = wall.replace(tzinfo=zone)                    # fold=0: first of a repeated hour
    if aware.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != wall:
        raise WhenError(f"{_clock_text(hour, minute)} doesn't exist on "
                        f"{_DAY_ABBR[day.weekday()]} {_MONTH_ABBR[day.month]} {day.day} in "
                        f"{zone.key} (the clocks jump forward); pick another time")
    return aware


# -- the resolver ------------------------------------------------------------------------------

_FILLER = frozenset({"at", "around", "by", "@", "about"})


def time_of_day(phrase: str) -> tuple[int, int]:
    """``(hour, minute)`` for a phrase that names *only* a time of day ("8am", "half past
    six", "noon"). Anything that also names a day, an interval or a repeat raises
    :class:`WhenError`. A bare hour reads 7-11 as morning and 12-6 as afternoon."""
    if not isinstance(phrase, str) or not phrase.strip() or len(phrase) > MAX_PHRASE:
        raise WhenError("no time given")
    text = _normalise(phrase)
    if re.fullmatch(r"\d{1,2}", text):          # "move it to 5": the whole phrase is an hour
        text = f"at {text}"
    clocks, midnight, rest = _clocks(text)
    part, rest = _day_part(rest)
    if set(rest.split()) - _FILLER:
        raise WhenError(f"{phrase.strip()!r} is more than a time of day")
    if len(clocks) + midnight > 1:
        raise WhenError("that names more than one time")
    if clocks:
        [(hour, minute)] = _candidates(clocks[0], part[2] if part else None, anchored=True)
        return hour, minute
    if midnight:
        return 0, 0
    if part:
        return part[1]
    raise WhenError("no time of day found")


def resolve_when(phrase: str, timezone: str, *, now: datetime | None = None) -> Resolved:
    """Resolve ``phrase`` in ``timezone``. Raises :class:`WhenError` when unsure."""
    zone = _zone(timezone)
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not isinstance(phrase, str) or not phrase.strip():
        raise WhenError("no time given")
    if len(phrase) > MAX_PHRASE:
        raise WhenError("that description is too long")
    local_now = now.astimezone(zone)
    today = local_now.date()
    text = _normalise(phrase)

    for pattern in _UNSUPPORTED:
        if re.search(pattern, text):
            raise WhenError("I can schedule one-off times, every N minutes or hours, daily, "
                            "weekdays, weekends, specific weekdays or a day of the month - "
                            f"not {phrase.strip()!r}")
    if re.search(r"\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b", text):
        raise WhenError("numeric dates like 10/11 are ambiguous; say 'Oct 11' or '11 Nov'")

    interval, text = _interval(text)
    delta, text = _relative(text)
    monthly, text = _take(r"\b(?:monthly|every\s+month|each\s+month)\b", text)
    month_day: int | None = None
    if monthly:
        doms, text = _take(r"\b(?:on\s+)?(?:the\s+)?(\d{1,2})(?:st|nd|rd|th)\b", text)
        if len(doms) != 1:
            raise WhenError("which day of the month? e.g. 'monthly on the 1st at 9am'")
        month_day = int(doms[0].group(1))
        if not 1 <= month_day <= 28:
            raise WhenError("not every month has that day; pick the 1st to the 28th")
    explicit_date, text = _month_day(text, today)

    anchors: list[date] = [explicit_date] if explicit_date else []
    found, text_wo = _take(r"\bday after tomorrow\b", text)
    if found:
        anchors.append(today + timedelta(days=2))
        text = text_wo
    if re.search(r"\b(?:tomorrow|tmrw|tmr)\b", text):
        anchors.append(today + timedelta(days=1))
    if re.search(r"\b(?:today|tonight|this\s+(?:morning|afternoon|evening))\b", text):
        anchors.append(today)
    if len(set(anchors)) > 1:
        raise WhenError("that names more than one day")
    anchor = anchors[0] if anchors else None

    clocks, midnight, text = _clocks(text)
    if len(clocks) + midnight > 1:
        raise WhenError("that names more than one time; schedule them separately")
    part, text = _day_part(text)
    weekdays = list(_WEEKDAY_RE.finditer(text))
    text = _WEEKDAY_RE.sub(" ", text)
    text = re.sub(r"\b(?:day after tomorrow|tomorrow|tmrw|tmr|today)\b", " ", text)

    recurring_words = re.search(r"\b(?:every|each|daily|weekly|weekdays?|weekends?)\b", text)
    plural_days = any(m.group(3) for m in weekdays)
    if re.search(r"\d", text):
        raise WhenError(f"I couldn't understand all of {phrase.strip()!r}")

    hint = part[2] if part else None
    if interval is not None:
        if clocks or midnight or part or weekdays or anchor or delta or month_day:
            raise WhenError("a repeating interval can't be combined with a time or a day")
        cron, human = interval
        return Resolved("recurring", timezone, human, cron=cron)

    if delta is not None:
        if clocks or midnight or part or weekdays or anchor or recurring_words or month_day:
            raise WhenError("'in ...' can't be combined with another time or day")
        days, elapsed = delta
        base = local_now
        if days:
            wall = local_now.replace(tzinfo=None) + timedelta(days=days)
            base = _localize(wall.date(), wall.hour, wall.minute, zone)
        run_at = (base.astimezone(UTC) + elapsed).replace(second=0, microsecond=0)
        return Resolved("once", timezone, _human_once(run_at.astimezone(zone)), run_at=run_at)

    if recurring_words or plural_days or month_day is not None:
        return _recurring(text, timezone, weekdays, month_day, clocks, midnight, part, hint,
                          anchor)
    return _once(local_now, zone, timezone, anchor, weekdays, clocks, midnight, part, hint)


def _recurring(text: str, timezone: str, weekdays: list[re.Match[str]], month_day: int | None,
               clocks: list[_Clock], midnight: bool, part: Any, hint: str | None,
               anchor: date | None) -> Resolved:
    if anchor is not None:
        raise WhenError("a repeating schedule can't also name a specific day")
    if clocks:
        [(hour, minute)] = _candidates(clocks[0], hint, anchored=True)
    elif midnight:
        hour, minute = 0, 0
    elif part:
        hour, minute = part[1]
    else:
        raise WhenError("a repeating schedule needs a time of day, e.g. 'every day at 8am'")
    days = sorted({_WEEKDAYS[m.group(2)] for m in weekdays})
    at = f"at {_clock_text(hour, minute)} ({timezone})"
    if month_day is not None:
        if days:
            raise WhenError("pick either a day of the month or days of the week")
        return Resolved("recurring", timezone, f"on day {month_day} of every month {at}",
                        cron=f"{minute} {hour} {month_day} * *")
    if re.search(r"\bweekdays?\b", text):
        dow, label = "1-5", "every weekday"
    elif re.search(r"\bweekends?\b", text):
        dow, label = "0,6", "every weekend day"
    elif days:
        dow = ",".join(str(c) for c in sorted((d + 1) % 7 for d in days))
        names = [_DAY_ABBR[d] for d in days]
        joined = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
        label = f"every {joined}"
    elif re.search(r"\bweekly\b", text):
        raise WhenError("which day of the week? e.g. 'weekly on Friday at 9am'")
    else:
        dow, label = "*", "every day"
    return Resolved("recurring", timezone, f"{label} {at}", cron=f"{minute} {hour} * * {dow}")


def _once(local_now: datetime, zone: ZoneInfo, timezone: str, anchor: date | None,
          weekdays: list[re.Match[str]], clocks: list[_Clock], midnight: bool, part: Any,
          hint: str | None) -> Resolved:
    today = local_now.date()
    if len({_WEEKDAYS[m.group(2)] for m in weekdays}) > 1:
        raise WhenError("that names more than one day")
    days: list[date]
    strict = anchor is not None
    if anchor is not None:
        if weekdays and _WEEKDAYS[weekdays[0].group(2)] != anchor.weekday():
            raise WhenError("that weekday doesn't match the date")
        days = [anchor]
    elif weekdays:
        target = _WEEKDAYS[weekdays[0].group(2)]
        first = today + timedelta(days=(target - today.weekday()) % 7)
        if (weekdays[0].group(1) or "").strip() == "next" and first == today:
            first += timedelta(days=7)
        days = [first, first + timedelta(days=7)]
    else:
        days = [today, today + timedelta(days=1)]

    if midnight:
        times = [(0, 0)]
        days = [d + timedelta(days=1) for d in days]   # midnight ends the named day
    elif clocks:
        times = _candidates(clocks[0], hint, anchored=bool(anchor or weekdays))
    elif part:
        times = [part[1]]
    else:
        raise WhenError("I couldn't find a time of day; try e.g. 'tomorrow at 9am'")

    now_wall = local_now.replace(tzinfo=None)
    walls = sorted(datetime.combine(d, time(h, m)) for d in days for h, m in times)
    upcoming = [w for w in walls if w > now_wall]
    if not upcoming:
        when = _clock_text(walls[0].hour, walls[0].minute)
        raise WhenError(f"{_DAY_ABBR[walls[0].weekday()]} {_MONTH_ABBR[walls[0].month]} "
                        f"{walls[0].day} at {when} has already passed")
    if strict and upcoming[0] != walls[0]:
        raise WhenError("that time has already passed")
    chosen = upcoming[0]
    local = _localize(chosen.date(), chosen.hour, chosen.minute, zone)
    if local - local_now > MAX_AHEAD:
        raise WhenError("that is more than a year away")
    return Resolved("once", timezone, _human_once(local), run_at=local.astimezone(UTC))
