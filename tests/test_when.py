"""Natural-language times resolve in the OWNER's time zone, in code, never by the model.

Fixed clock: Monday 2026-10-12 15:00 UTC = 11:00 EDT in New York."""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from agent_guardrails.scheduling.when import WhenError, resolve_when, time_of_day

NY = ZoneInfo("America/New_York")
NOW = datetime(2026, 10, 12, 15, 0, tzinfo=UTC)


def at(phrase, tz="America/New_York", now=NOW):
    return resolve_when(phrase, tz, now=now)


def local(*args, tz=NY):
    return datetime(*args, tzinfo=tz)


# -- one-off ------------------------------------------------------------------------------------

@pytest.mark.parametrize("phrase,expected", [
    ("tomorrow at 9am", local(2026, 10, 13, 9, 0)),
    ("tomorrow at 9:30 a.m.", local(2026, 10, 13, 9, 30)),
    ("tomorrow at 5", local(2026, 10, 13, 17, 0)),          # bare 1-6 -> afternoon
    ("tomorrow at 7", local(2026, 10, 13, 7, 0)),           # bare 7-11 -> morning
    ("nine o'clock tomorrow", local(2026, 10, 13, 9, 0)),
    ("tomorrow morning", local(2026, 10, 13, 9, 0)),
    ("day after tomorrow at 14:15", local(2026, 10, 14, 14, 15)),
    ("noon tomorrow", local(2026, 10, 13, 12, 0)),
    ("tomorrow at midnight", local(2026, 10, 14, 0, 0)),    # the end of tomorrow
    ("at midnight", local(2026, 10, 13, 0, 0)),
    ("tonight at 9", local(2026, 10, 12, 21, 0)),
    ("9 tonight", local(2026, 10, 12, 21, 0)),
    ("half past nine tonight", local(2026, 10, 12, 21, 30)),
    ("this evening", local(2026, 10, 12, 18, 0)),
])
def test_day_anchored_times(phrase, expected):
    resolved = at(phrase)
    assert resolved.kind == "once" and resolved.cron is None
    assert resolved.run_at == expected


@pytest.mark.parametrize("phrase,expected", [
    ("at 9", local(2026, 10, 12, 21, 0)),        # 9 AM already passed -> 9 PM today
    ("at 2", local(2026, 10, 12, 14, 0)),
    ("at 11:30", local(2026, 10, 12, 11, 30)),   # still ahead this morning
    ("quarter to five", local(2026, 10, 12, 16, 45)),
    ("5:45pm", local(2026, 10, 12, 17, 45)),
    ("at 10am", local(2026, 10, 13, 10, 0)),     # explicit and already past -> tomorrow
])
def test_time_only_means_the_next_time_the_clock_shows_it(phrase, expected):
    assert at(phrase).run_at == expected


@pytest.mark.parametrize("phrase,expected", [
    ("in 2 hours", local(2026, 10, 12, 13, 0)),
    ("in 45 minutes", local(2026, 10, 12, 11, 45)),
    ("in five minutes", local(2026, 10, 12, 11, 5)),
    ("in half an hour", local(2026, 10, 12, 11, 30)),
    ("in an hour", local(2026, 10, 12, 12, 0)),
    ("in 1 hour and 30 minutes", local(2026, 10, 12, 12, 30)),
    ("in 3 days", local(2026, 10, 15, 11, 0)),
])
def test_relative_times(phrase, expected):
    assert at(phrase).run_at == expected


@pytest.mark.parametrize("phrase,expected", [
    ("friday at 3pm", local(2026, 10, 16, 15, 0)),
    ("monday at 3pm", local(2026, 10, 12, 15, 0)),      # today, still ahead
    ("monday at 10am", local(2026, 10, 19, 10, 0)),     # today but passed -> next week
    ("next monday at 3pm", local(2026, 10, 19, 15, 0)),  # "next" never means today
    ("oct 20 at 10am", local(2026, 10, 20, 10, 0)),
    ("20 october at 10am", local(2026, 10, 20, 10, 0)),
    ("october 20th 10am", local(2026, 10, 20, 10, 0)),
    ("jan 5 at 9am", local(2027, 1, 5, 9, 0)),          # already past this year -> next year
    ("2026-12-01 08:00", local(2026, 12, 1, 8, 0)),
])
def test_weekdays_and_dates(phrase, expected):
    assert at(phrase).run_at == expected


def test_in_n_hours_is_elapsed_time_even_across_a_dst_change():
    now = datetime(2026, 11, 1, 4, 30, tzinfo=UTC)      # 00:30 EDT, clocks fall back at 2:00
    assert at("in 2 hours", now=now).run_at == datetime(2026, 11, 1, 6, 30, tzinfo=UTC)


def test_in_n_days_keeps_the_wall_clock_time_across_a_dst_change():
    now = datetime(2026, 10, 31, 15, 0, tzinfo=UTC)     # Sat 11:00 EDT
    resolved = at("in 3 days", now=now)
    assert resolved.human == "Tue Nov 3, 2026 at 11:00 AM EST"
    assert resolved.run_at == datetime(2026, 11, 3, 16, 0, tzinfo=UTC)


def test_tomorrow_is_computed_from_the_owners_date_not_utcs():
    # 21:30 Monday in Los Angeles is already 04:30 Tuesday in UTC
    now = datetime(2026, 10, 13, 4, 30, tzinfo=UTC)
    resolved = at("tomorrow at 9am", "America/Los_Angeles", now)
    la = ZoneInfo("America/Los_Angeles")
    assert resolved.run_at == datetime(2026, 10, 13, 9, 0, tzinfo=la)


def test_human_echo_names_the_day_date_and_zone():
    assert at("tomorrow at 9am").human == "Tue Oct 13, 2026 at 9:00 AM EDT"
    assert at("tomorrow at 9am", "Europe/London").human == "Tue Oct 13, 2026 at 9:00 AM BST"


@pytest.mark.parametrize("phrase", ["today at 9am", "2026-10-01 at 9am",
                                    "monday 9am this morning"])
def test_explicit_times_in_the_past_are_refused_not_rolled_forward(phrase):
    with pytest.raises(WhenError):
        at(phrase)


def test_a_time_that_does_not_exist_because_of_dst_is_refused():
    now = datetime(2026, 3, 7, 15, 0, tzinfo=UTC)      # Saturday before spring-forward
    with pytest.raises(WhenError, match="doesn't exist"):
        at("tomorrow at 2:30am", now=now)


def test_a_repeated_dst_time_resolves_to_its_first_occurrence_and_says_so():
    now = datetime(2026, 10, 31, 15, 0, tzinfo=UTC)     # Saturday before fall-back
    resolved = at("tomorrow at 1:30am", now=now)
    assert resolved.run_at == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
    assert resolved.human.endswith("EDT")


# -- recurring ----------------------------------------------------------------------------------

@pytest.mark.parametrize("phrase,cron,human", [
    ("every weekday at 7:30am", "30 7 * * 1-5",
     "every weekday at 7:30 AM (America/New_York)"),
    ("every monday and thursday at 6pm", "0 18 * * 1,4",
     "every Mon and Thu at 6:00 PM (America/New_York)"),
    ("weekends at 10am", "0 10 * * 0,6", "every weekend day at 10:00 AM (America/New_York)"),
    ("daily at 9", "0 9 * * *", "every day at 9:00 AM (America/New_York)"),
    ("every day at 5", "0 17 * * *", "every day at 5:00 PM (America/New_York)"),
    ("every morning", "0 9 * * *", "every day at 9:00 AM (America/New_York)"),
    ("mondays at 8:15", "15 8 * * 1", "every Mon at 8:15 AM (America/New_York)"),
    ("monthly on the 1st at 8am", "0 8 1 * *",
     "on day 1 of every month at 8:00 AM (America/New_York)"),
])
def test_recurring_schedules(phrase, cron, human):
    resolved = at(phrase)
    assert resolved.kind == "recurring" and resolved.run_at is None
    assert (resolved.cron, resolved.human) == (cron, human)


@pytest.mark.parametrize("phrase,cron", [
    ("every 15 minutes", "*/15 * * * *"),
    ("every hour", "0 * * * *"),
    ("hourly", "0 * * * *"),
    ("every 2 hours", "0 */2 * * *"),
    ("every minute", "* * * * *"),     # resolvable; the scheduler's policy refuses it
])
def test_intervals(phrase, cron):
    assert at(phrase).cron == cron


@pytest.mark.parametrize("phrase", [
    "every 7 minutes",               # cron can't repeat every 7 minutes across the hour
    "every 5 hours",                 # nor every 5 hours across midnight
    "every 90 minutes",
    "every other day at 9am",        # must not silently become "every day"
    "every 2 days at 9am",
    "every 2 weeks on friday at 9am",
    "biweekly on friday at 9",
    "every year on oct 20 at 9am",
    "monthly on the 31st at 9am",    # most months don't have one
    "every weekday",                 # no time of day
    "every 15 minutes at 9am",       # contradictory
    "at 9am and 5pm",                # two times
    "tomorrow in 2 hours",
    "10/11 at 9am",                  # Oct 11 or Nov 10?
    "in 400 days",
    "sometime soon",
    "",
])
def test_unclear_or_unsupported_phrases_are_refused(phrase):
    with pytest.raises(WhenError):
        at(phrase)


@pytest.mark.parametrize("phrase,expected", [
    ("8am", (8, 0)), ("at 8", (8, 0)), ("5", (17, 0)), ("half past six", (18, 30)),
    ("noon", (12, 0)), ("midnight", (0, 0)), ("9 in the evening", (21, 0)), ("21:15", (21, 15)),
])
def test_time_of_day_only(phrase, expected):
    assert time_of_day(phrase) == expected


@pytest.mark.parametrize("phrase", ["tomorrow at 8", "every day at 8", "in 2 hours",
                                    "8am and 9am", "monday 8am", "soon", ""])
def test_time_of_day_rejects_anything_more(phrase):
    with pytest.raises(WhenError):
        time_of_day(phrase)


def test_unknown_timezone_is_refused():
    with pytest.raises(WhenError, match="time zone"):
        at("tomorrow at 9am", "Mars/Olympus_Mons")


def test_now_must_be_timezone_aware():
    with pytest.raises(ValueError):
        resolve_when("tomorrow at 9am", "UTC", now=datetime(2026, 10, 12, 15, 0))


def test_to_dict_is_json_friendly():
    data = at("tomorrow at 9am").to_dict()
    assert data == {"kind": "once", "timezone": "America/New_York",
                    "human": "Tue Oct 13, 2026 at 9:00 AM EDT", "cron": None,
                    "run_at": "2026-10-13T09:00:00-04:00"}
