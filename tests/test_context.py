"""The active turn lives in a context variable: gates read it, the model can't pass it."""

import asyncio
import threading

import pytest

from agent_guardrails.context import current_turn, mark_untrusted, tainted_by, turn_scope
from agent_guardrails.errors import Refused
from agent_guardrails.identity import Envelope, OwnerIdentity, Role, SystemOrigin, classify_turn

OWNERS = OwnerIdentity(phones=["+15550001111"])


def owner_turn():
    return classify_turn(Envelope("sms", "+15550001111", verified=True), OWNERS)


def stranger_turn():
    return classify_turn(Envelope("sms", "+15550002222", verified=True), OWNERS)


def test_there_is_no_turn_outside_a_scope():
    with pytest.raises(Refused) as err:
        current_turn()
    assert err.value.code == "no_active_turn"


def test_scopes_nest_and_restore():
    a, b = owner_turn(), stranger_turn()
    with turn_scope(a):
        assert current_turn() is a
        with turn_scope(b):
            assert current_turn() is b
        assert current_turn() is a
    with pytest.raises(Refused):
        current_turn()


def test_turn_scope_rejects_anything_but_a_turn_context():
    with pytest.raises(TypeError), turn_scope(Role.OWNER):  # type: ignore[arg-type]
        pass


def test_taint_starts_clean_accumulates_and_is_per_scope():
    with turn_scope(owner_turn()):
        assert tainted_by() == frozenset()
        mark_untrusted("email")
        mark_untrusted("web")
        assert tainted_by() == {"email", "web"}
    with turn_scope(owner_turn()):
        assert tainted_by() == frozenset()


def test_marking_taint_outside_a_turn_is_refused():
    with pytest.raises(Refused):
        mark_untrusted("email")


async def test_the_turn_and_its_taint_flow_into_child_tasks():
    turn = classify_turn(SystemOrigin("digest"), OWNERS)
    with turn_scope(turn):
        async def child():
            mark_untrusted("rss")
            return current_turn()

        assert await asyncio.create_task(child()) is turn
        assert tainted_by() == {"rss"}   # same turn, same taint set


async def test_concurrent_turns_do_not_see_each_other():
    seen = {}

    async def handle(turn, key):
        with turn_scope(turn):
            await asyncio.sleep(0)
            seen[key] = current_turn().role

    await asyncio.gather(handle(owner_turn(), "a"), handle(stranger_turn(), "b"))
    assert seen == {"a": Role.OWNER, "b": Role.THIRD_PARTY}


def test_a_bare_thread_does_not_inherit_the_turn():
    """Fail closed: work handed to a plain thread has no turn, so gates refuse it."""
    outcome = []

    def worker():
        try:
            current_turn()
            outcome.append("had a turn")
        except Refused:
            outcome.append("refused")

    with turn_scope(owner_turn()):
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
    assert outcome == ["refused"]
