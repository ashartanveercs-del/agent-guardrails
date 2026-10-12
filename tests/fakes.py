"""In-memory stand-ins for the services an agent's tools call: an SMS provider, a mailbox, a
conversation-history store and a clock. Every fake records each call, so a test can prove
that a refused request never reached the "API" at all."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from agent_guardrails.identity import (
    Envelope,
    OwnerIdentity,
    SystemOrigin,
    TurnContext,
    classify_turn,
)

OWNER_PHONE = "+15550001111"
OWNER_EMAIL = "owner@example.com"
CUSTOMER = "+15550002222"      # a third party who is texting the agent
STRANGER = "+15550007777"      # neither the owner nor the current sender
OWNERS = OwnerIdentity(phones=[OWNER_PHONE], emails=[OWNER_EMAIL])


def owner_turn(text: str = "", *, message_id: str = "") -> TurnContext:
    return classify_turn(Envelope("sms", OWNER_PHONE, verified=True, text=text,
                                  message_id=message_id), OWNERS)


def customer_turn(text: str = "", *, sender: str = CUSTOMER) -> TurnContext:
    return classify_turn(Envelope("sms", sender, verified=True, text=text), OWNERS)


def system_turn(job: str = "test-job") -> TurnContext:
    return classify_turn(SystemOrigin(job), OWNERS)


class FakeSmsApi:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []

    def send(self, to: str, body: str) -> dict[str, str]:
        self.sent.append({"to": to, "body": body})
        return {"id": f"msg-{len(self.sent):04d}", "to": to}


class FakeMailbox:
    def __init__(self, messages: list[dict[str, str]] | None = None) -> None:
        self.messages = list(messages or [])
        self.reads = 0
        self.sent: list[dict[str, str]] = []

    def search(self, query: str = "") -> list[dict[str, str]]:
        self.reads += 1
        q = query.lower()
        return [m for m in self.messages if q in (m["subject"] + " " + m["body"]).lower()]

    def send(self, to: str, subject: str, body: str) -> dict[str, str]:
        self.sent.append({"to": to, "subject": subject, "body": body})
        return {"id": f"mail-{len(self.sent):04d}"}


class FakeHistory:
    def __init__(self, threads: dict[str, list[str]] | None = None) -> None:
        self.threads = threads or {}
        self.reads: list[str] = []

    def thread(self, contact: str) -> list[str]:
        self.reads.append(contact)
        return list(self.threads.get(contact, []))


class FakeClock:
    """Callable clock returning an aware UTC datetime that tests move by hand."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 10, 12, 15, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: Any) -> None:
        self.now += timedelta(**delta)
