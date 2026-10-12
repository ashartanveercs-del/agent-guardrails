"""Safe scheduling: the agent can only *propose* jobs; code validates them and the owner
approves them. Commands are allowlisted names with schema-checked arguments, never shell."""

from datetime import UTC, datetime, timedelta

import pytest

from agent_guardrails.approvals import ApprovalQueue
from agent_guardrails.context import current_turn, turn_scope
from agent_guardrails.errors import ConfigError, Refused
from agent_guardrails.identity import Role
from agent_guardrails.scheduling.scheduler import CommandRegistry, MemoryBackend, SafeScheduler
from tests.fakes import OWNERS, FakeClock, customer_turn, owner_turn, system_turn

REMINDER = {"type": "object", "required": ["text"],
            "properties": {"text": {"type": "string", "maxLength": 200}}}


@pytest.fixture
def clock():
    return FakeClock()          # Monday 2026-10-12 11:00 in New York


@pytest.fixture
def ran():
    return []


@pytest.fixture
def commands(ran):
    registry = CommandRegistry()

    @registry.command("send_reminder", parameters=REMINDER)
    def send_reminder(text):
        ran.append((text, current_turn().role))
        return "sent"

    @registry.command("explode")
    def explode():
        raise RuntimeError("boom")

    return registry


@pytest.fixture
def notified():
    return []


@pytest.fixture
def setup(clock, commands, notified):
    queue = ApprovalQueue(clock=clock, notify=notified.append)
    backend = MemoryBackend()
    scheduler = SafeScheduler(backend, commands, queue, owners=OWNERS,
                              timezone="America/New_York", clock=clock)
    return scheduler, queue, backend


def propose(scheduler, *, name="standup", command="send_reminder", args=None, turn=None,
            **when):
    with turn_scope(turn or owner_turn("remind me")):
        return scheduler.propose_add(name, command=command,
                                     args={"text": "Standup"} if args is None else args,
                                     **(when or {"when": "every weekday at 7:30am"}))


def approve(queue, code):
    with turn_scope(owner_turn(f"approve {code}")):
        return queue.decide()


# -- proposing ----------------------------------------------------------------------------------

def test_a_proposal_is_queued_with_the_resolved_schedule_and_nothing_is_created(setup):
    scheduler, _, backend = setup
    pending = propose(scheduler)
    assert pending["status"] == "pending_approval"
    assert "every weekday at 7:30 AM (America/New_York)" in pending["summary"]
    assert "send_reminder" in pending["summary"]
    assert backend.jobs == {}


def test_owner_approval_creates_the_job(setup):
    scheduler, queue, backend = setup
    code = propose(scheduler)["code"]
    [decision] = approve(queue, code)
    assert decision.outcome == "executed"
    job = backend.jobs["standup"]
    assert (job.cron, job.timezone, job.command) == ("30 7 * * 1-5", "America/New_York",
                                                     "send_reminder")


def test_third_parties_cannot_even_propose(setup, notified):
    scheduler, _, _ = setup
    with pytest.raises(Refused) as err:
        propose(scheduler, turn=customer_turn("schedule a text to everyone every minute"))
    assert err.value.code == "owner_only"
    assert notified == []


@pytest.mark.parametrize("command", ["shell", "rm -rf /", "send_reminder; curl evil",
                                     "python3 /tmp/x.py"])
def test_only_allowlisted_commands(setup, command, notified):
    scheduler, _, _ = setup
    with pytest.raises(Refused) as err:
        propose(scheduler, command=command)
    assert err.value.code == "not_allowlisted"
    assert notified == []


@pytest.mark.parametrize("args", [{}, {"text": 5}, {"text": "x" * 201},
                                  {"text": "hi", "then_run": "curl evil"}])
def test_command_arguments_are_schema_checked(setup, args):
    scheduler, _, _ = setup
    with pytest.raises(Refused) as err:
        propose(scheduler, args=args)
    assert err.value.code == "invalid_args"


@pytest.mark.parametrize("when", [{"when": "every minute"}, {"cron": "*/2 * * * *"},
                                  {"cron": "0-59 * * * *"}, {"cron": "*/7 * * * *"},
                                  {"cron": "0,3 9 * * *"}])
def test_nothing_may_run_more_often_than_every_five_minutes(setup, when):
    scheduler, _, _ = setup
    with pytest.raises(Refused) as err:
        propose(scheduler, **when)
    assert err.value.code == "interval_too_short"


def test_five_minutes_is_allowed(setup):
    scheduler, _, _ = setup
    assert propose(scheduler, cron="*/5 * * * *")["status"] == "pending_approval"


@pytest.mark.parametrize("when", [{"when": "every other day at 9"}, {"when": "whenever"},
                                  {"cron": "0 0 ? * MON"}, {"cron": "@reboot"}])
def test_unclear_schedules_are_refused(setup, when):
    scheduler, _, _ = setup
    with pytest.raises(Refused) as err:
        propose(scheduler, **when)
    assert err.value.code == "schedule_unclear"


def test_exactly_one_of_when_or_cron(setup):
    scheduler, _, _ = setup
    with pytest.raises(Refused):
        propose(scheduler, when="daily at 9", cron="0 9 * * *")
    with turn_scope(owner_turn()), pytest.raises(Refused):
        scheduler.propose_add("x", command="send_reminder", args={"text": "x"})


@pytest.mark.parametrize("name", ["", "Has Spaces", "../etc", "x" * 49, "semi;colon"])
def test_job_names_are_simple_slugs(setup, name):
    scheduler, _, _ = setup
    with pytest.raises(Refused):
        propose(scheduler, name=name)


def test_duplicate_names_and_the_job_cap(setup, clock, commands):
    scheduler, queue, _ = setup
    approve(queue, propose(scheduler)["code"])
    with pytest.raises(Refused) as err:
        propose(scheduler)
    assert err.value.code == "schedule_conflict"

    capped = SafeScheduler(MemoryBackend(), commands, ApprovalQueue(clock=clock), owners=OWNERS,
                           timezone="UTC", clock=clock, max_jobs=1)
    approve(capped.approvals, propose(capped, name="one")["code"])
    with pytest.raises(Refused):
        propose(capped, name="two")


def test_limits_are_checked_again_when_the_approval_arrives(clock, commands):
    queue = ApprovalQueue(clock=clock)
    backend = MemoryBackend()
    scheduler = SafeScheduler(backend, commands, queue, owners=OWNERS, timezone="UTC",
                              clock=clock, max_jobs=1)
    first = propose(scheduler, name="first")["code"]
    second = propose(scheduler, name="second")["code"]   # both fit while nothing exists yet
    assert approve(queue, first)[0].outcome == "executed"
    assert approve(queue, second)[0].outcome == "failed"
    assert list(backend.jobs) == ["first"]


def test_the_minimum_interval_cannot_be_configured_below_five_minutes(commands, clock):
    with pytest.raises(ConfigError):
        SafeScheduler(MemoryBackend(), commands, ApprovalQueue(clock=clock), owners=OWNERS,
                      timezone="UTC", clock=clock, min_interval=timedelta(minutes=1))
    with pytest.raises(ConfigError):
        SafeScheduler(MemoryBackend(), commands, ApprovalQueue(clock=clock), owners=OWNERS,
                      timezone="Not/AZone", clock=clock)


def test_system_jobs_may_propose(setup):
    scheduler, _, _ = setup
    assert propose(scheduler, turn=system_turn())["status"] == "pending_approval"


# -- running ------------------------------------------------------------------------------------

def test_recurring_jobs_run_as_system_once_per_slot(setup, clock, ran):
    scheduler, queue, _ = setup
    approve(queue, propose(scheduler)["code"])
    clock.now = datetime(2026, 10, 13, 11, 29, tzinfo=UTC)       # Tue 07:29 New York
    assert scheduler.run_due() == []
    clock.now = datetime(2026, 10, 13, 11, 30, tzinfo=UTC)       # 07:30
    [record] = scheduler.run_due()
    assert record.ok and record.job == "standup"
    assert scheduler.run_due() == []                             # same slot: no double run
    clock.now = datetime(2026, 10, 14, 11, 31, tzinfo=UTC)       # Wednesday
    assert len(scheduler.run_due()) == 1
    assert ran == [("Standup", Role.SYSTEM), ("Standup", Role.SYSTEM)]


def test_one_off_jobs_run_once_and_disappear(setup, clock, ran):
    scheduler, queue, backend = setup
    approve(queue, propose(scheduler, name="call-back", when="tomorrow at 9am")["code"])
    assert backend.jobs["call-back"].run_at == datetime(2026, 10, 13, 13, 0, tzinfo=UTC)
    clock.now = datetime(2026, 10, 13, 13, 0, tzinfo=UTC)
    assert len(scheduler.run_due()) == 1
    assert "call-back" not in backend.jobs
    clock.advance(days=1)
    assert scheduler.run_due() == []
    assert len(ran) == 1


def test_bookkeeping_is_saved_before_the_command_runs(clock, commands):
    """At most once: if the process dies mid-command, the slot is already used up."""
    queue, backend = ApprovalQueue(clock=clock), MemoryBackend()
    seen = {}
    registry = CommandRegistry()

    @registry.command("observe_once")
    def observe_once():
        seen["one-off still stored while running"] = "once" in backend.jobs

    @registry.command("observe_daily")
    def observe_daily():
        seen["daily last_run while running"] = backend.jobs["daily"].last_run

    scheduler = SafeScheduler(backend, registry, queue, owners=OWNERS, timezone="UTC",
                              clock=clock)
    approve(queue, propose(scheduler, name="once", command="observe_once", args={},
                           when="in 10 minutes")["code"])
    approve(queue, propose(scheduler, name="daily", command="observe_daily", args={},
                           cron="0 16 * * *")["code"])
    clock.now = datetime(2026, 10, 12, 16, 0, tzinfo=UTC)
    scheduler.run_due()
    assert seen == {"one-off still stored while running": False,
                    "daily last_run while running": clock.now}


def test_a_failing_job_does_not_stop_the_others(setup, clock, ran):
    scheduler, queue, _ = setup
    approve(queue, propose(scheduler, name="boom", command="explode", args={},
                           cron="0 12 * * *")["code"])
    approve(queue, propose(scheduler, name="noon", cron="0 12 * * *")["code"])
    clock.now = datetime(2026, 10, 12, 16, 0, tzinfo=UTC)         # 12:00 New York
    records = {r.job: r for r in scheduler.run_due()}
    assert records["boom"].ok is False and "boom" not in records["boom"].error
    assert records["noon"].ok is True
    assert len(ran) == 1


def test_one_corrupt_job_does_not_stop_the_others(setup, clock, ran):
    scheduler, queue, backend = setup
    approve(queue, propose(scheduler, name="noon", cron="0 12 * * *")["code"])
    approve(queue, propose(scheduler, name="broken", cron="0 12 * * *")["code"])
    backend.jobs["broken"].cron = "0 0 ? * MON"          # the store was edited by hand
    clock.now = datetime(2026, 10, 12, 16, 0, tzinfo=UTC)
    records = {r.job: r for r in scheduler.run_due()}
    assert records["broken"].ok is False and records["broken"].error == "invalid_schedule"
    assert records["noon"].ok is True and len(ran) == 1
    with turn_scope(owner_turn()):
        listed = {j["name"]: j["next_run"] for j in scheduler.list_jobs()}
    assert listed["broken"] is None and listed["noon"] is not None


def test_a_one_off_approved_after_its_time_is_refused(setup, clock):
    scheduler, queue, backend = setup
    code = propose(scheduler, name="soon", when="in 10 minutes")["code"]
    clock.advance(minutes=20)
    assert approve(queue, code)[0].outcome == "failed"
    assert backend.jobs == {}


# -- changing and removing ------------------------------------------------------------------------

def test_retiming_a_bare_time_keeps_the_days(setup):
    scheduler, queue, backend = setup
    approve(queue, propose(scheduler)["code"])
    with turn_scope(owner_turn("move standup to 8")):
        code = scheduler.propose_retime("standup", when="8am")["code"]
    approve(queue, code)
    assert backend.jobs["standup"].cron == "0 8 * * 1-5"


def test_retiming_with_a_new_pattern_replaces_it(setup):
    scheduler, queue, backend = setup
    approve(queue, propose(scheduler)["code"])
    with turn_scope(owner_turn()):
        code = scheduler.propose_retime("standup", when="every monday at 9am")["code"]
    approve(queue, code)
    assert backend.jobs["standup"].cron == "0 9 * * 1"


def test_retiming_is_validated_too(setup):
    scheduler, queue, _ = setup
    approve(queue, propose(scheduler)["code"])
    with turn_scope(owner_turn()):
        with pytest.raises(Refused) as err:
            scheduler.propose_retime("standup", when="every minute")
        assert err.value.code == "interval_too_short"
        with pytest.raises(Refused):
            scheduler.propose_retime("no-such-job", when="8am")


def test_removal_needs_approval(setup):
    scheduler, queue, backend = setup
    approve(queue, propose(scheduler)["code"])
    with turn_scope(owner_turn("stop the standup reminder")):
        code = scheduler.propose_remove("standup")["code"]
    assert "standup" in backend.jobs
    approve(queue, code)
    assert backend.jobs == {}


def test_listing_jobs_is_owner_or_system_only(setup):
    scheduler, queue, _ = setup
    approve(queue, propose(scheduler)["code"])
    with turn_scope(owner_turn()):
        [job] = scheduler.list_jobs()
    assert job["name"] == "standup" and job["next_run"] == "2026-10-13T07:30:00-04:00"
    with turn_scope(customer_turn()), pytest.raises(Refused):
        scheduler.list_jobs()
