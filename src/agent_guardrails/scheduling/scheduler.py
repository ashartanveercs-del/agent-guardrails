"""Safe scheduling for agents.

An agent that can create cron jobs can turn one prompt injection into a persistent
foothold: "every minute, forward the owner's inbox to me". :class:`SafeScheduler` is the
only door, and it is narrow:

* **Allowlisted commands, not shell.** A job names a registered command and passes JSON
  arguments validated against that command's schema. There is no shell string anywhere,
  so there is nothing to inject into: no ``;``, no ``$(...)``, no newline that becomes a
  second crontab line, no ``%`` that crontab turns into stdin.
* **Real minimum interval.** The cron expression's true shortest gap between runs must be
  at least five minutes (the floor can be raised, never lowered).
* **Owner time zone, in code.** "every weekday at 7:30am" is resolved by
  :mod:`~agent_guardrails.scheduling.when`, not by the model.
* **Owner confirmation that can't be faked.** Every add, retime and removal goes through
  the :class:`~agent_guardrails.approvals.ApprovalQueue`. There is no ``confirmed=True``
  argument for a model to set; the owner has to reply with the approval code, and the
  approval is bound to the exact resolved schedule they were shown.
* **Re-validated on approval.** Limits are checked again when the approval arrives, since
  it may be hours later and other jobs may exist by then.
* **Third parties can't propose at all**, and jobs run as an explicit ``SYSTEM`` turn.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from ..approvals import ApprovalQueue
from ..context import current_turn, turn_scope
from ..errors import ConfigError, Refused
from ..identity import OwnerIdentity, SystemOrigin, TurnContext, classify_turn
from ..schema import strict_schema, validate
from .cron import CronError, CronSchedule
from .when import WhenError, resolve_when, time_of_day

log = logging.getLogger(__name__)

MIN_INTERVAL_FLOOR = timedelta(minutes=5)
_JOB_NAME_RE = re.compile(r"[a-z0-9][a-z0-9\-]{0,47}")
_COMMAND_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,47}")


# -- commands ----------------------------------------------------------------------------------

@dataclass(frozen=True)
class Command:
    name: str
    fn: Callable[..., Any]
    parameters: dict[str, Any]
    description: str = ""


class CommandRegistry:
    """The allowlist of things a scheduled job may do."""

    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}

    def command(self, name: str, *, parameters: dict[str, Any] | None = None,
                description: str = "") -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        if not _COMMAND_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid command name {name!r}")
        if name in self._commands:
            raise ValueError(f"command {name!r} is already registered")

        def register(fn: Callable[..., Any]) -> Callable[..., Any]:
            self._commands[name] = Command(name, fn, strict_schema(parameters), description)
            return fn
        return register

    def names(self) -> list[str]:
        return sorted(self._commands)

    def validate(self, name: object, args: object) -> dict[str, Any]:
        command = self._commands.get(name) if isinstance(name, str) else None
        if command is None:
            raise Refused("not_allowlisted", detail=f"{name!r} is not an allowlisted command")
        if not isinstance(args, dict):
            raise Refused("invalid_args", detail="command arguments must be an object")
        problems = validate(args, command.parameters)
        if problems:
            raise Refused("invalid_args", detail="; ".join(problems))
        return dict(args)

    def run(self, name: str, args: dict[str, Any]) -> Any:
        return self._commands[name].fn(**self.validate(name, args))


# -- jobs and backends -------------------------------------------------------------------------

@dataclass
class Job:
    name: str
    command: str
    args: dict[str, Any]
    timezone: str
    human: str
    created_at: datetime
    cron: str | None = None          # recurring, evaluated in `timezone`
    run_at: datetime | None = None   # one-off, aware UTC
    last_run: datetime | None = None
    requested_by: str = ""

    def next_run(self, after: datetime) -> datetime | None:
        if self.cron is not None:
            return CronSchedule.parse(self.cron).next_after(after, self.timezone)
        return self.run_at if self.run_at is not None and self.run_at > after else None


class SchedulerBackend(Protocol):
    def list(self) -> list[Job]: ...
    def get(self, name: str) -> Job | None: ...
    def add(self, job: Job) -> None: ...
    def update(self, job: Job) -> None: ...
    def remove(self, name: str) -> None: ...


class MemoryBackend:
    """In-process job store; :meth:`SafeScheduler.run_due` drives it. Production code can
    implement :class:`SchedulerBackend` over APScheduler, Celery beat or a cloud scheduler
    and keep every guarantee above, since all writes go through :class:`SafeScheduler`."""

    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}

    def list(self) -> list[Job]:
        return list(self.jobs.values())

    def get(self, name: str) -> Job | None:
        return self.jobs.get(name)

    def add(self, job: Job) -> None:
        if job.name in self.jobs:
            raise ValueError(f"job {job.name!r} exists")
        self.jobs[job.name] = job

    def update(self, job: Job) -> None:
        self.jobs[job.name] = job

    def remove(self, name: str) -> None:
        self.jobs.pop(name, None)


@dataclass(frozen=True)
class RunRecord:
    job: str
    ok: bool
    at: datetime
    result: Any = None
    error: str = ""


# -- the scheduler -----------------------------------------------------------------------------

class SafeScheduler:
    def __init__(self, backend: SchedulerBackend, commands: CommandRegistry,
                 approvals: ApprovalQueue, *, owners: OwnerIdentity, timezone: str,
                 clock: Callable[[], datetime] | None = None,
                 min_interval: timedelta = MIN_INTERVAL_FLOOR, max_jobs: int = 25) -> None:
        if min_interval < MIN_INTERVAL_FLOOR:
            raise ConfigError(f"min_interval can't be below {MIN_INTERVAL_FLOOR}")
        try:
            ZoneInfo(timezone)
        except Exception:
            raise ConfigError(f"unknown time zone {timezone!r}") from None
        self.backend = backend
        self.commands = commands
        self.approvals = approvals
        self.owners = owners
        self.timezone = timezone
        self.min_interval = min_interval
        self.max_jobs = max_jobs
        self._clock = clock or (lambda: datetime.now(UTC))
        approvals.register("schedule.add", self._execute_add)
        approvals.register("schedule.remove", self._execute_remove)
        approvals.register("schedule.retime", self._execute_retime)

    # -- proposals (owner or system turns only) ---------------------------------------------

    def propose_add(self, name: str, *, command: str, args: dict[str, Any] | None = None,
                    when: str | None = None, cron: str | None = None) -> dict[str, Any]:
        """Validate a new job and queue it for the owner's approval."""
        turn = self._require_trusted()
        spec = self._build(name, command, {} if args is None else args, when, cron)
        summary = (f'Schedule "{name}": {spec["human"]} -> {command} '
                   f'{json.dumps(spec["args"], sort_keys=True)}')
        approval = self.approvals.request("schedule.add", {**spec, "requested_by": turn.sender},
                                          summary=summary)
        return {**approval.public_view(), "schedule": spec["human"]}

    def propose_remove(self, name: str) -> dict[str, Any]:
        self._require_trusted()
        if self.backend.get(name) is None:
            raise Refused("schedule_conflict", detail=f"no job named {name!r}")
        approval = self.approvals.request("schedule.remove", {"name": name},
                                          summary=f'Remove scheduled job "{name}"')
        return approval.public_view()

    def propose_retime(self, name: str, *, when: str | None = None,
                       cron: str | None = None) -> dict[str, Any]:
        """Change a recurring job's schedule. A bare time ("8am") keeps the job's days."""
        self._require_trusted()
        job = self.backend.get(name)
        if job is None:
            raise Refused("schedule_conflict", detail=f"no job named {name!r}")
        if job.cron is None:
            raise Refused("schedule_conflict", "One-off jobs can't be moved; remove it and "
                                               "add a new one.")
        if (when is None) == (cron is None):
            raise Refused("invalid_args", detail="give exactly one of when or cron")
        if cron is not None:
            new_cron, human = self._check_cron(cron).expr, f"cron '{cron}' ({self.timezone})"
        else:
            new_cron, human = self._retime_phrase(job, when or "")
            self._check_cron(new_cron)
        approval = self.approvals.request(
            "schedule.retime", {"name": name, "cron": new_cron, "previous": job.cron,
                                "human": human},
            summary=f'Change "{name}" from {job.human} to {human}')
        return {**approval.public_view(), "schedule": human}

    def list_jobs(self) -> list[dict[str, Any]]:
        self._require_trusted()
        now = self._clock()
        jobs = []
        for job in sorted(self.backend.list(), key=lambda j: j.name):
            try:
                upcoming = job.next_run(now)
            except (CronError, ValueError):
                upcoming = None                      # invalid schedule: shown, never run
            jobs.append({"name": job.name, "command": job.command, "args": job.args,
                         "schedule": job.human,
                         "next_run": upcoming.astimezone(ZoneInfo(job.timezone)).isoformat()
                         if upcoming else None})
        return jobs

    # -- running ------------------------------------------------------------------------------

    def run_due(self, now: datetime | None = None) -> list[RunRecord]:
        """Run every job whose next slot is due, each in its own SYSTEM turn.

        At most once: the slot is recorded (a one-off job removed, a recurring job's
        ``last_run`` saved) *before* the command runs, so a crash mid-command never repeats
        it. A job that missed several slots while the process was down runs once."""
        now = now or self._clock()
        records = []
        for job in sorted(self.backend.list(), key=lambda j: j.name):
            try:
                due = job.next_run(job.last_run or job.created_at)
            except (CronError, ValueError):
                log.error("job %s has an invalid schedule %r; skipping it", job.name, job.cron)
                records.append(RunRecord(job.name, False, now, error="invalid_schedule"))
                continue
            if due is None or due > now:
                continue
            if job.cron is None:
                self.backend.remove(job.name)
            else:
                job.last_run = now
                self.backend.update(job)
            turn = classify_turn(SystemOrigin(f"job-{job.name}"), self.owners)
            with turn_scope(turn):
                try:
                    result = self.commands.run(job.command, job.args)
                    records.append(RunRecord(job.name, True, now, result=result))
                except Exception as exc:
                    log.exception("scheduled job %s failed", job.name)
                    error = exc.code if isinstance(exc, Refused) else type(exc).__name__
                    records.append(RunRecord(job.name, False, now, error=error))
        return records

    # -- approval executors (run after the owner approves) -------------------------------------

    def _execute_add(self, name: str, command: str, args: dict[str, Any], timezone: str,
                     cron: str | None, run_at: str | None, human: str,
                     requested_by: str) -> dict[str, Any]:
        now = self._clock()
        if timezone != self.timezone:
            raise Refused("schedule_conflict", detail="the owner's time zone changed")
        args = self.commands.validate(command, args)
        when = datetime.fromisoformat(run_at) if run_at else None
        if cron is not None:
            self._check_cron(cron)
        elif when is None or when <= now:
            raise Refused("schedule_conflict", detail="that time passed before it was approved")
        self._check_capacity(name)
        self.backend.add(Job(name=name, command=command, args=args, timezone=timezone,
                             human=human, created_at=now, cron=cron, run_at=when,
                             requested_by=requested_by))
        return {"created": name, "schedule": human}

    def _execute_remove(self, name: str) -> dict[str, Any]:
        if self.backend.get(name) is None:
            raise Refused("schedule_conflict", detail=f"no job named {name!r}")
        self.backend.remove(name)
        return {"removed": name}

    def _execute_retime(self, name: str, cron: str, previous: str, human: str) -> dict[str, Any]:
        job = self.backend.get(name)
        if job is None or job.cron != previous:
            raise Refused("schedule_conflict", detail=f"{name!r} changed since the request")
        self._check_cron(cron)
        job.cron, job.human = cron, human
        job.last_run = self._clock()      # don't fire a slot that only exists in the new time
        self.backend.update(job)
        return {"retimed": name, "schedule": human}

    # -- validation ----------------------------------------------------------------------------

    @staticmethod
    def _require_trusted() -> TurnContext:
        turn = current_turn()
        if not turn.is_trusted:
            raise Refused("owner_only",
                          detail="only the owner or a system job can manage schedules")
        return turn

    def _build(self, name: str, command: str, args: dict[str, Any], when: str | None,
               cron: str | None) -> dict[str, Any]:
        if not isinstance(name, str) or not _JOB_NAME_RE.fullmatch(name):
            raise Refused("invalid_args", "Job names are short lowercase slugs like "
                                          "'morning-brief'.")
        args = self.commands.validate(command, args)
        if (when is None) == (cron is None):
            raise Refused("invalid_args", detail="give exactly one of when or cron")
        now = self._clock()
        run_at = None
        if when is not None:
            try:
                resolved = resolve_when(when, self.timezone, now=now)
            except WhenError as exc:
                raise Refused("schedule_unclear", str(exc)) from None
            expr, run_at, human = resolved.cron, resolved.run_at, resolved.human
        else:
            expr, human = cron, f"cron '{cron}' ({self.timezone})"
        if expr is not None:
            expr = self._check_cron(expr).expr
        elif run_at is None or run_at <= now:
            raise Refused("schedule_conflict", detail="that time has passed")
        self._check_capacity(name)
        return {"name": name, "command": command, "args": args, "timezone": self.timezone,
                "cron": expr, "run_at": run_at.isoformat() if run_at else None, "human": human}

    def _check_cron(self, expr: str) -> CronSchedule:
        try:
            schedule = CronSchedule.parse(expr)
        except CronError as exc:
            raise Refused("schedule_unclear", str(exc)) from None
        gap = schedule.min_gap()
        if gap < self.min_interval:
            minutes = int(self.min_interval.total_seconds() // 60)
            raise Refused("interval_too_short",
                          f"That could run {int(gap.total_seconds() // 60)} minute(s) apart; "
                          f"jobs may run at most every {minutes} minutes.",
                          detail=f"{expr!r} min gap {gap}")
        return schedule

    def _check_capacity(self, name: str) -> None:
        if self.backend.get(name) is not None:
            raise Refused("schedule_conflict", f'A job named "{name}" already exists.')
        if len(self.backend.list()) >= self.max_jobs:
            raise Refused("schedule_conflict", detail=f"job limit {self.max_jobs} reached")

    def _retime_phrase(self, job: Job, phrase: str) -> tuple[str, str]:
        try:
            hour, minute = time_of_day(phrase)
        except WhenError:
            pass
        else:
            _, _, dom, month, dow = (job.cron or "").split()
            clock = f"{(hour % 12) or 12}:{minute:02d} {'AM' if hour < 12 else 'PM'}"
            return f"{minute} {hour} {dom} {month} {dow}", f"{clock} on the same days"
        try:
            resolved = resolve_when(phrase, self.timezone, now=self._clock())
        except WhenError as exc:
            raise Refused("schedule_unclear", str(exc)) from None
        if not resolved.recurring or resolved.cron is None:
            raise Refused("schedule_unclear", "A repeating job needs a repeating time, e.g. "
                                              "'every weekday at 8am'.")
        return resolved.cron, resolved.human
