"""The active turn lives in a context variable: gates read it, the model can't pass it."""

import asyncio
import threading
from datetime import timedelta

import pytest

from agent_guardrails.context import (
    TaintLedger,
    current_turn,
    mark_untrusted,
    tainted_by,
    turn_scope,
)
from agent_guardrails.errors import Refused, StateCorrupt
from agent_guardrails.identity import Envelope, OwnerIdentity, Role, SystemOrigin, classify_turn
from tests.fakes import FakeClock

OWNERS = OwnerIdentity(phones=["+15550001111"])


def owner_turn(channel="sms"):
    return classify_turn(Envelope(channel, "+15550001111", verified=True), OWNERS)


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


def test_a_scope_can_start_with_taint_carried_over_from_earlier_turns():
    with turn_scope(owner_turn(), taint={"email"}):
        assert tainted_by() == {"email"}
        mark_untrusted("web")
        assert tainted_by() == {"email", "web"}
    with turn_scope(owner_turn(), taint="email"):           # one name, not five letters
        assert tainted_by() == {"email"}


# -- the taint ledger ------------------------------------------------------------------------

def make_ledger(hours=2):
    clock = FakeClock()
    return TaintLedger(ttl=timedelta(hours=hours), clock=clock), clock


def test_the_ledger_carries_taint_into_later_turns_of_the_same_conversation():
    ledger, clock = make_ledger()
    assert ledger.carried(owner_turn()) == frozenset()
    ledger.remember(owner_turn(), {"email"})
    assert ledger.carried(owner_turn()) == {"email"}                # a later message
    assert ledger.carried(owner_turn("whatsapp")) == frozenset()     # another conversation
    clock.advance(hours=2)
    assert ledger.carried(owner_turn()) == frozenset()              # aged out of the history


def test_new_taint_merges_and_restarts_the_clock():
    ledger, clock = make_ledger()
    ledger.remember(owner_turn(), {"email"})
    clock.advance(hours=1)
    ledger.remember(owner_turn(), {"web"})
    clock.advance(hours=1, minutes=30)
    assert ledger.carried(owner_turn()) == {"email", "web"}
    ledger.remember(owner_turn(), ())                               # a clean turn changes nothing
    assert ledger.carried(owner_turn()) == {"email", "web"}


def test_forgetting_a_conversation_clears_it():
    ledger, _ = make_ledger()
    ledger.remember(owner_turn(), {"email"})
    ledger.forget(owner_turn())
    assert ledger.carried(owner_turn()) == frozenset()


def test_system_jobs_are_conversations_and_third_parties_are_not_kept():
    ledger, _ = make_ledger()
    digest = classify_turn(SystemOrigin("digest"), OWNERS)
    ledger.remember(digest, {"rss"})
    ledger.remember(stranger_turn(), {"web"})
    assert ledger.carried(classify_turn(SystemOrigin("digest"), OWNERS)) == {"rss"}
    assert ledger.carried(classify_turn(SystemOrigin("backup"), OWNERS)) == frozenset()
    assert ledger.carried(stranger_turn()) == frozenset()


def test_the_ledger_needs_a_positive_ttl():
    with pytest.raises(ValueError):
        make_ledger(hours=0)


def test_a_file_backed_ledger_is_shared_by_every_worker(tmp_path):
    """Consecutive messages may land on different gateway processes; the taint must too."""
    clock = FakeClock()
    path = tmp_path / "taint.json"
    first = TaintLedger(path, ttl=timedelta(hours=2), clock=clock)
    second = TaintLedger(path, ttl=timedelta(hours=2), clock=clock)
    first.remember(owner_turn(), {"email"})
    assert second.carried(owner_turn()) == {"email"}
    second.remember(owner_turn(), {"web"})
    assert first.carried(owner_turn()) == {"email", "web"}
    first.forget(owner_turn())
    assert second.carried(owner_turn()) == frozenset()


@pytest.mark.parametrize("content", ["{ truncated", "[]", '{"conversations": 3}'])
def test_a_corrupt_ledger_file_fails_loudly(tmp_path, content):
    """Starting empty would quietly declare every conversation clean."""
    path = tmp_path / "taint.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(StateCorrupt):
        TaintLedger(path).carried(owner_turn())


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
