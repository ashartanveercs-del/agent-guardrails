"""An approval queue for consequential actions.

The design rule: **the model can ask, but it can never decide.** There is no "approve" tool.
A request gets a short code (``7KQ2``); the owner approves by replying ``approve 7KQ2``, and
that reply is parsed *in code* from the verified owner message on the turn
(:attr:`TurnContext.text`), before or instead of any model call. A prompt-injected model,
or a third party who has seen the code, has no path to approval.

Further guarantees:

* **Bound to content.** Each request stores a SHA-256 digest of its action and payload.
  The digest is re-checked before execution, so a payload edited in the store is never
  run. An owner edit issues a *new* code, so an approval can't apply to text the owner
  hasn't seen.
* **A separate turn.** A request can't be decided in the turn that created it.
* **At most once.** A request is marked ``executing`` and saved *before* the side effect.
  A crash mid-send leaves it ``executing`` and it is never retried automatically -
  re-sending a message is worse than asking again.
* **Bounded.** Requests expire (24 h by default); a third party may only have a few
  pending at once; identical pending requests are de-duplicated.
* **Unambiguous.** "do not approve 7KQ2", "approve 7KQ2?" or "yes 7KQ2 no wait" do nothing.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import inspect
import json
import logging
import re
import secrets
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from .context import current_turn, tainted_by
from .errors import Refused
from .gates import bind_arguments
from .identity import Role, TurnContext
from .storage import JsonFile

log = logging.getLogger(__name__)

CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"   # no 0/O, 1/I/L
_CODE_RE = re.compile(r"[2-9A-HJKMNP-Z]{4}")
_ACTION_RE = re.compile(r"[a-z0-9][a-z0-9._\-]{0,63}")
MAX_PAYLOAD_BYTES = 16_384
MAX_SUMMARY_CHARS = 300

APPROVE_WORDS = frozenset({"approve", "approved", "yes", "y", "ok", "okay", "confirm",
                           "confirmed", "send", "go", "do"})
REJECT_WORDS = frozenset({"reject", "rejected", "no", "n", "deny", "denied", "cancel",
                          "decline", "stop", "dont", "don't"})
HEDGE_WORDS = frozenset({"not", "wait", "hold", "maybe", "later", "unsure", "unless", "but",
                         "if"})


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_digest(action: str, payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of the action and its payload."""
    blob = _canonical_json({"action": action, "payload": payload}).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _clean_summary(text: str) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()
    return text if len(text) <= MAX_SUMMARY_CHARS else text[: MAX_SUMMARY_CHARS - 3] + "..."


def _jsonable(value: Any) -> Any:
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = json.dumps(repr(value))
    if len(text) > 4096:
        return {"truncated": text[:4000]}
    return json.loads(text)


def _random_code() -> str:
    while True:
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(4))
        if any(c.isdigit() for c in code) and any(c.isalpha() for c in code):
            return code


def parse_decision(text: str, known_codes: Iterable[str]) -> tuple[str | None, list[str]]:
    """Read an owner's reply. Returns ``(verb, codes)`` where verb is ``"approve"``,
    ``"reject"`` or ``None`` (no clear instruction). Only known codes are returned."""
    known = set(known_codes)
    tokens = re.findall(r"[A-Za-z0-9']+", text or "")
    codes: list[str] = []
    for token in tokens:
        upper = token.upper()
        if upper in known and upper not in codes:
            codes.append(upper)
    if not codes:
        return None, []
    words = {t.lower() for t in tokens}
    approve, reject = bool(words & APPROVE_WORDS), bool(words & REJECT_WORDS)
    hedged = bool(words & HEDGE_WORDS) or "?" in (text or "")
    if hedged or approve == reject:
        return None, codes
    return ("approve" if approve else "reject"), codes


@dataclass
class Approval:
    code: str
    action: str
    payload: dict[str, Any]
    digest: str
    summary: str
    status: ApprovalStatus
    requester_role: str
    requester: str
    bound_turn: str
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    result: Any = None
    error: str = ""

    def public_view(self) -> dict[str, Any]:
        """What the model (and so the requester) is told while it waits."""
        return {"status": "pending_approval", "code": self.code, "summary": self.summary,
                "expires_at": self.expires_at.isoformat(),
                "note": f"Nothing has happened yet. The owner must reply 'approve {self.code}' "
                        f"to go ahead or 'reject {self.code}' to cancel."}

    def to_json(self) -> dict[str, Any]:
        return {"code": self.code, "action": self.action, "payload": self.payload,
                "digest": self.digest, "summary": self.summary, "status": str(self.status),
                "requester_role": self.requester_role, "requester": self.requester,
                "bound_turn": self.bound_turn, "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
                "decided_at": self.decided_at.isoformat() if self.decided_at else None,
                "result": self.result, "error": self.error}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Approval:
        decided = data.get("decided_at")
        return cls(code=data["code"], action=data["action"], payload=dict(data["payload"]),
                   digest=data["digest"], summary=data["summary"],
                   status=ApprovalStatus(data["status"]),
                   requester_role=data["requester_role"], requester=data["requester"],
                   bound_turn=data["bound_turn"],
                   created_at=datetime.fromisoformat(data["created_at"]),
                   expires_at=datetime.fromisoformat(data["expires_at"]),
                   decided_at=datetime.fromisoformat(decided) if decided else None,
                   result=data.get("result"), error=data.get("error", ""))


@dataclass(frozen=True)
class Decision:
    code: str
    verb: str | None
    outcome: str
    message: str


# -- stores ------------------------------------------------------------------------------------

class ApprovalStore(Protocol):
    def load(self) -> dict[str, Approval]: ...
    def save(self, approvals: Mapping[str, Approval]) -> None: ...


class MemoryApprovalStore:
    """Keeps serialised copies, so code that mutates a loaded object without saving it
    behaves exactly as it would against a file."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}

    def load(self) -> dict[str, Approval]:
        return {code: Approval.from_json(copy.deepcopy(d)) for code, d in self._data.items()}

    def save(self, approvals: Mapping[str, Approval]) -> None:
        self._data = {code: copy.deepcopy(a.to_json()) for code, a in approvals.items()}


class JsonApprovalStore:
    def __init__(self, path: str) -> None:
        self._file = JsonFile(path)

    def load(self) -> dict[str, Approval]:
        data = self._file.read({"version": 1, "approvals": []})
        return {d["code"]: Approval.from_json(d) for d in data.get("approvals", [])}

    def save(self, approvals: Mapping[str, Approval]) -> None:
        self._file.write({"version": 1,
                          "approvals": [a.to_json() for a in approvals.values()]})


# -- the queue ---------------------------------------------------------------------------------

class ApprovalQueue:
    def __init__(self, store: ApprovalStore | None = None, *,
                 ttl: timedelta = timedelta(hours=24),
                 clock: Callable[[], datetime] | None = None,
                 notify: Callable[[Approval], None] | None = None,
                 max_pending_per_requester: int = 3,
                 retention: timedelta = timedelta(days=30),
                 code_factory: Callable[[], str] | None = None) -> None:
        self.store: ApprovalStore = store if store is not None else MemoryApprovalStore()
        self.ttl = ttl
        self.notify = notify
        self.max_pending_per_requester = max_pending_per_requester
        self.retention = retention
        self._clock = clock or (lambda: datetime.now(UTC))
        self._code_factory = code_factory or _random_code
        self._executors: dict[str, Callable[..., Any]] = {}
        self._lock = threading.RLock()

    # -- setup ----------------------------------------------------------------------------

    def register(self, action: str, executor: Callable[..., Any]) -> None:
        """Declare what runs when a request for ``action`` is approved. Requests for
        actions without an executor are refused up front."""
        if not _ACTION_RE.fullmatch(action):
            raise ValueError(f"invalid action name {action!r}")
        if action in self._executors:
            raise ValueError(f"action {action!r} already has an executor")
        self._executors[action] = executor

    # -- asking ---------------------------------------------------------------------------

    def request(self, action: str, payload: Mapping[str, Any], *, summary: str) -> Approval:
        """Queue ``action(**payload)`` for the owner. Allowed on any turn."""
        turn = current_turn()
        payload = dict(payload)
        digest = payload_digest(action, payload)          # TypeError if not plain JSON
        if len(_canonical_json(payload).encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise Refused("invalid_args", detail="approval payload too large")
        if action not in self._executors:
            raise Refused("approval_not_allowed", detail=f"no executor for {action!r}")
        now = self._clock()
        with self._lock:
            approvals = self.store.load()
            self._expire(approvals, now)
            for existing in approvals.values():
                if existing.status is ApprovalStatus.PENDING and existing.digest == digest:
                    self.store.save(approvals)
                    return existing
            if turn.role is Role.THIRD_PARTY:
                waiting = sum(1 for a in approvals.values()
                              if a.status is ApprovalStatus.PENDING
                              and a.requester_role == Role.THIRD_PARTY
                              and a.requester == turn.sender)
                if waiting >= self.max_pending_per_requester:
                    raise Refused("too_many_pending", detail=f"{turn.sender} has {waiting}")
            approval = Approval(
                code=self._new_code(approvals), action=action, payload=copy.deepcopy(payload),
                digest=digest, summary=_clean_summary(summary), status=ApprovalStatus.PENDING,
                requester_role=str(turn.role), requester=turn.sender, bound_turn=turn.turn_id,
                created_at=now, expires_at=now + self.ttl)
            approvals[approval.code] = approval
            self._prune(approvals, now)
            self.store.save(approvals)
        if self.notify is not None:
            try:
                self.notify(approval)
            except Exception:
                log.exception("approval notify hook failed for %s", approval.code)
        return approval

    # -- deciding -------------------------------------------------------------------------

    def decide(self) -> list[Decision]:
        """Apply the decisions in the active owner turn's verified text. Returns one
        :class:`Decision` per code mentioned; ``[]`` when there is nothing to decide or
        the turn isn't the verified owner."""
        to_run, decided, order = self._plan(allow_async=False)
        for approval in to_run:
            try:
                result = self._executors[approval.action](**approval.payload)
            except Exception as exc:
                decided[approval.code] = self._failed(approval, exc)
            else:
                decided[approval.code] = self._done(approval, result)
        return [decided[c] for c in order]

    async def adecide(self) -> list[Decision]:
        """:meth:`decide` for queues whose executors may be coroutines."""
        to_run, decided, order = self._plan(allow_async=True)
        for approval in to_run:
            try:
                result = self._executors[approval.action](**approval.payload)
                if inspect.isawaitable(result):
                    result = await result
            except Exception as exc:
                decided[approval.code] = self._failed(approval, exc)
            else:
                decided[approval.code] = self._done(approval, result)
        return [decided[c] for c in order]

    def _plan(self, *, allow_async: bool) -> tuple[list[Approval], dict[str, Decision], list[str]]:
        turn = current_turn()
        if turn.role is not Role.OWNER:
            return [], {}, []
        now = self._clock()
        with self._lock:
            approvals = self.store.load()
            expired = self._expire(approvals, now)
            verb, codes = parse_decision(turn.text, approvals.keys())
            decided: dict[str, Decision] = {}
            to_run: list[Approval] = []
            for code in codes:
                approval = approvals[code]
                outcome = self._judge(approval, verb, turn, now, allow_async)
                if outcome is None:
                    to_run.append(approval)
                else:
                    decided[code] = outcome
            if expired or codes:          # most owner messages mention no code: no write
                self.store.save(approvals)
        return to_run, decided, codes

    def _judge(self, approval: Approval, verb: str | None, turn: TurnContext, now: datetime,
               allow_async: bool) -> Decision | None:
        """Decide one code under the lock. ``None`` means "approved, run it now"."""
        code, summary = approval.code, approval.summary
        if verb is None:
            return Decision(code, None, "ambiguous", f"Not sure what to do with {code} "
                            f"({summary}). Reply 'approve {code}' or 'reject {code}'.")
        if approval.status is ApprovalStatus.EXPIRED:
            return Decision(code, verb, "expired",
                            f"{code} expired before it was approved. Ask again if needed.")
        if approval.status is not ApprovalStatus.PENDING:
            return Decision(code, verb, f"already_{approval.status}",
                            f"{code} was already {approval.status}.")
        if turn.turn_id == approval.bound_turn:
            return Decision(code, verb, "refused",
                            f"{code} has to be approved in a separate message.")
        approval.decided_at = now
        if verb == "reject":
            approval.status = ApprovalStatus.REJECTED
            return Decision(code, verb, "rejected", f"Cancelled ({code}): {summary}")
        executor = self._executors.get(approval.action)
        if executor is not None and not allow_async and inspect.iscoroutinefunction(executor):
            raise TypeError(f"executor for {approval.action!r} is async; use adecide()")
        problem = ""
        if executor is None:
            problem = f"no executor registered for {approval.action!r}"
        elif payload_digest(approval.action, approval.payload) != approval.digest:
            problem = "stored payload does not match the digest that was requested"
        if problem:
            log.warning("approval %s not executed: %s", code, problem)
            approval.status = ApprovalStatus.FAILED
            approval.error = problem
            return Decision(code, verb, "failed", f"That didn't go through ({code}): {summary}")
        approval.status = ApprovalStatus.EXECUTING   # saved before the side effect
        return None

    def _done(self, approval: Approval, result: Any) -> Decision:
        self._finish(approval.code, ApprovalStatus.EXECUTED, result=_jsonable(result))
        return Decision(approval.code, "approve", "executed",
                        f"Done ({approval.code}): {approval.summary}")

    def _failed(self, approval: Approval, exc: Exception) -> Decision:
        if isinstance(exc, Refused):
            error = f"{exc.code}: {exc.detail}"
        else:
            log.exception("executor for %s failed", approval.code)
            error = type(exc).__name__
        self._finish(approval.code, ApprovalStatus.FAILED, error=error)
        return Decision(approval.code, "approve", "failed",
                        f"That didn't go through ({approval.code}): {approval.summary}")

    def _finish(self, code: str, status: ApprovalStatus, *, result: Any = None,
                error: str = "") -> None:
        with self._lock:
            approvals = self.store.load()
            current = approvals.get(code)
            if current is None:
                return
            current.status, current.result, current.error = status, result, error
            self.store.save(approvals)

    # -- owner tools ------------------------------------------------------------------------

    def edit(self, code: str, payload: Mapping[str, Any], *,
             summary: str | None = None) -> Approval:
        """Owner-only: replace a pending request's payload. Issues a new code."""
        turn = current_turn()
        if turn.role is not Role.OWNER:
            raise Refused("owner_only", detail="only the owner can edit a request")
        payload = dict(payload)
        now = self._clock()
        with self._lock:
            approvals = self.store.load()
            self._expire(approvals, now)
            approval = approvals.get(code.upper())
            if approval is None or approval.status is not ApprovalStatus.PENDING:
                raise Refused("approval_not_allowed", detail=f"{code} is not pending")
            del approvals[approval.code]
            approval.code = self._new_code(approvals)
            approval.payload = copy.deepcopy(payload)
            approval.digest = payload_digest(approval.action, payload)
            if summary is not None:
                approval.summary = _clean_summary(summary)
            approval.bound_turn = turn.turn_id
            approval.expires_at = now + self.ttl
            approvals[approval.code] = approval
            self.store.save(approvals)
        return approval

    def pending(self) -> list[Approval]:
        """Owner/system only: requests waiting for a decision, oldest first."""
        self._require_trusted()
        with self._lock:
            approvals = self.store.load()
            if self._expire(approvals, self._clock()):
                self.store.save(approvals)
        waiting = [a for a in approvals.values() if a.status is ApprovalStatus.PENDING]
        return sorted(waiting, key=lambda a: a.created_at)

    def get(self, code: str) -> Approval | None:
        """Owner/system only."""
        self._require_trusted()
        with self._lock:
            return self.store.load().get(code.upper())

    # -- internals --------------------------------------------------------------------------

    @staticmethod
    def _require_trusted() -> None:
        turn = current_turn()
        if not turn.is_trusted:
            raise Refused("owner_only", detail="approval queue is owner/system only")

    def _new_code(self, approvals: Mapping[str, Approval]) -> str:
        for _ in range(100):
            code = self._code_factory()
            if not (_CODE_RE.fullmatch(code) and any(c.isdigit() for c in code)
                    and any(c.isalpha() for c in code)):
                raise ValueError(f"code factory produced an invalid code {code!r}")
            if code not in approvals:
                return code
        raise RuntimeError("could not allocate a unique approval code")

    @staticmethod
    def _expire(approvals: Mapping[str, Approval], now: datetime) -> bool:
        changed = False
        for approval in approvals.values():
            if approval.status is ApprovalStatus.PENDING and now >= approval.expires_at:
                approval.status = ApprovalStatus.EXPIRED
                changed = True
        return changed

    def _prune(self, approvals: dict[str, Approval], now: datetime) -> None:
        live = (ApprovalStatus.PENDING, ApprovalStatus.EXECUTING)
        for code in [c for c, a in approvals.items()
                     if a.status not in live
                     and now - (a.decided_at or a.expires_at) > self.retention]:
            del approvals[code]


# -- decorator ---------------------------------------------------------------------------------

Policy = Callable[[TurnContext, frozenset[str]], bool]


def always(turn: TurnContext, taint: frozenset[str]) -> bool:
    """Every call needs the owner's approval."""
    return True


def unless_clean_owner(turn: TurnContext, taint: frozenset[str]) -> bool:
    """Run directly only when the owner (or system) asked and nothing untrusted was read
    this turn; otherwise queue for approval."""
    return not (turn.is_trusted and not taint)


def requires_approval(queue: ApprovalQueue, action: str, *,
                      summary: str | Callable[[dict[str, Any]], str],
                      when: Policy = always) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Route calls through ``queue`` when ``when(turn, taint)`` says so. The undecorated
    function is registered as the executor, so an approval runs exactly the call that was
    shown to the owner. Put role gates *outside* this decorator so refusals happen before
    anything is queued."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)
        for param in sig.parameters.values():
            if param.kind not in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY):
                raise TypeError(f"{fn.__name__}(): approval payloads need named parameters")
        queue.register(action, fn)

        def maybe_queue(bound: inspect.BoundArguments) -> dict[str, Any] | None:
            if not when(current_turn(), tainted_by()):
                return None
            payload = dict(bound.arguments)
            text = summary(payload) if callable(summary) else summary
            return queue.request(action, payload, summary=text).public_view()

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = bind_arguments(sig, args, kwargs)
                pending = maybe_queue(bound)
                return pending if pending is not None else await fn(*bound.args, **bound.kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = bind_arguments(sig, args, kwargs)
            pending = maybe_queue(bound)
            return pending if pending is not None else fn(*bound.args, **bound.kwargs)
        return wrapper

    return decorate
