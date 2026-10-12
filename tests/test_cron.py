"""Cron parsing, the real minimum gap between runs, and DST-aware next-run times."""

from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from agent_guardrails.scheduling.cron import CronError, CronSchedule

NY = ZoneInfo("America/New_York")


def minutes(expr):
    return CronSchedule.parse(expr).min_gap() // timedelta(minutes=1)


def test_parses_steps_ranges_lists_and_names():
    s = CronSchedule.parse("*/15 9-17 * jan-mar mon-fri")
    assert s.minutes == {0, 15, 30, 45}
    assert s.hours == set(range(9, 18))
    assert s.months == {1, 2, 3}
    assert s.weekdays == {1, 2, 3, 4, 5}


def test_seven_is_also_sunday_and_offsets_with_steps_work():
    assert CronSchedule.parse("0 0 * * 7").weekdays == {0}
    assert CronSchedule.parse("5/20 * * * *").minutes == {5, 25, 45}


@pytest.mark.parametrize("macro,gap", [("@hourly", 60), ("@daily", 1440), ("@weekly", 1440),
                                       ("@MIDNIGHT", 1440)])
def test_macros(macro, gap):
    assert minutes(macro) == gap


@pytest.mark.parametrize("expr", [
    "", "* * * *", "0 0 * * * *",               # wrong field count (no seconds field)
    "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8",
    "5-1 * * * *", "*/0 * * * *", "1,,2 * * * *", "*/61 * * * *",
    "0 0 ? * MON", "0 0 L * *", "0 0 * * MON#2",  # Quartz-only syntax
    "@reboot", "@every 5m",
    "0 0 30 2 *", "0 0 31 4,6,9,11 *",          # dates that never exist
    "0 9 * * * ; rm -rf /",
])
def test_rejects_anything_it_cannot_reason_about(expr):
    with pytest.raises(CronError):
        CronSchedule.parse(expr)


@pytest.mark.parametrize("expr,gap", [
    ("* * * * *", 1),
    ("*/2 * * * *", 2),
    ("*/5 * * * *", 5),
    ("*/7 * * * *", 4),          # 0,7,...,56 then 0 again: the hour wrap is only 4 minutes
    ("0-59 * * * *", 1),         # a range is "every minute" in disguise
    ("0,1 * * * *", 1),
    ("0,30 * * * *", 30),
    ("0 * * * *", 60),
    ("55 0,23 * * *", 60),       # 23:55 -> 00:55 crosses midnight
    ("30 9 * * 1-5", 1440),
])
def test_min_gap_is_the_true_shortest_interval(expr, gap):
    assert minutes(expr) == gap


def test_dom_and_dow_combine_with_or_like_classic_cron():
    s = CronSchedule.parse("0 9 13 * 5")              # the 13th, or any Friday
    assert s.matches_date(date(2026, 10, 13))         # a Tuesday the 13th
    assert s.matches_date(date(2026, 10, 16))         # a Friday
    assert not s.matches_date(date(2026, 10, 14))


def test_next_after_in_the_owners_timezone():
    s = CronSchedule.parse("30 9 * * 1-5")
    after = datetime(2026, 10, 16, 10, 0, tzinfo=NY)  # Friday after the run
    assert s.next_after(after, NY) == datetime(2026, 10, 19, 9, 30, tzinfo=NY)


def test_next_after_returns_strictly_later_times():
    s = CronSchedule.parse("0 * * * *")
    at_run = datetime(2026, 10, 12, 15, 0, tzinfo=UTC)
    assert s.next_after(at_run, "UTC") == datetime(2026, 10, 12, 16, 0, tzinfo=UTC)


def test_a_time_inside_the_spring_forward_gap_fires_once_shifted_by_the_gap():
    s = CronSchedule.parse("30 2 * * *")
    after = datetime(2026, 3, 8, 0, 0, tzinfo=NY)     # US clocks jump 02:00 -> 03:00
    run = s.next_after(after, NY)
    assert run == datetime(2026, 3, 8, 7, 30, tzinfo=UTC)   # 03:30 EDT
    assert s.next_after(run, NY).astimezone(NY) == datetime(2026, 3, 9, 2, 30, tzinfo=NY)


def test_the_repeated_fall_back_hour_runs_only_once():
    s = CronSchedule.parse("30 1 * * *")
    first = s.next_after(datetime(2026, 11, 1, 0, 0, tzinfo=NY), NY)
    assert first == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)          # 01:30 EDT
    assert s.next_after(first, NY) == datetime(2026, 11, 2, 6, 30, tzinfo=UTC)  # next day EST


def test_next_after_needs_an_aware_datetime():
    with pytest.raises(ValueError):
        CronSchedule.parse("0 9 * * *").next_after(datetime(2026, 10, 12, 9, 0), "UTC")
