"""Approval queue: anyone may ask, only the verified owner can decide, and only in code."""

from datetime import timedelta

import pytest

from agent_guardrails.approvals import (
    ApprovalQueue,
    ApprovalStatus,
    JsonApprovalStore,
    MemoryApprovalStore,
    always,
    parse_decision,
    requires_approval,
    unless_clean_owner,
)
from agent_guardrails.context import mark_untrusted, turn_scope
from agent_guardrails.errors import Refused
from agent_guardrails.gates import send_gate
from tests.fakes import (
    CUSTOMER,
    OWNER_PHONE,
    STRANGER,
    FakeClock,
    FakeSmsApi,
    customer_turn,
    owner_turn,
    system_turn,
)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def sms():
    return FakeSmsApi()


@pytest.fixture
def notified():
    return []


@pytest.fixture
def queue(clock, sms, notified):
    q = ApprovalQueue(MemoryApprovalStore(), clock=clock, ttl=timedelta(hours=24),
                      notify=notified.append)
    q.register("sms.send", lambda to, body: sms.send(to, body))
    return q


def ask(queue, turn=None, to=STRANGER, body="Invoice attached"):
    with turn_scope(turn or owner_turn("text the client")):
        return queue.request("sms.send", {"to": to, "body": body}, summary=f"Text {to}: {body}")


def owner_says(queue, text):
    with turn_scope(owner_turn(text)):
        return queue.decide()


# -- requesting -------------------------------------------------------------------------------

def test_a_request_is_pending_with_a_short_code_and_the_owner_is_notified(queue, notified, sms):
    approval = ask(queue)
    assert approval.status is ApprovalStatus.PENDING
    assert len(approval.code) == 4 and any(c.isdigit() for c in approval.code)
    assert notified == [approval]
    assert sms.sent == []


def test_identical_pending_requests_are_deduplicated(queue, notified):
    first, second = ask(queue), ask(queue)
    assert first.code == second.code
    assert len(notified) == 1


def test_requests_for_unregistered_actions_are_refused(queue):
    with turn_scope(owner_turn()), pytest.raises(Refused) as err:
        queue.request("wire.transfer", {"amount": 10_000}, summary="Wire money")
    assert err.value.code == "approval_not_allowed"


def test_a_third_party_cannot_flood_the_owner(queue):
    for i in range(3):
        ask(queue, customer_turn(), to=OWNER_PHONE, body=f"callback please #{i}")
    with pytest.raises(Refused) as err:
        ask(queue, customer_turn(), to=OWNER_PHONE, body="one more")
    assert err.value.code == "too_many_pending"
    for i in range(5):  # the owner is not capped
        ask(queue, body=f"owner request {i}")


def test_payloads_must_be_plain_json(queue):
    with turn_scope(owner_turn()), pytest.raises(TypeError):
        queue.request("sms.send", {"to": STRANGER, "body": object()}, summary="x")


# -- deciding ---------------------------------------------------------------------------------

def test_owner_approval_executes_exactly_once(queue, sms):
    code = ask(queue).code
    [decision] = owner_says(queue, f"approve {code}")
    assert decision.outcome == "executed"
    again = owner_says(queue, f"yes {code}")
    assert again[0].outcome == "already_executed"
    assert sms.sent == [{"to": STRANGER, "body": "Invoice attached"}]


def test_codes_are_case_insensitive_and_position_free(queue, sms):
    code = ask(queue).code
    owner_says(queue, f"{code.lower()} ok, go ahead")
    assert len(sms.sent) == 1


def test_a_third_party_typing_a_valid_code_decides_nothing(queue, sms):
    code = ask(queue).code
    with turn_scope(customer_turn(f"approve {code}")):
        assert queue.decide() == []
    with turn_scope(owner_turn()):
        assert queue.get(code).status is ApprovalStatus.PENDING
    assert sms.sent == []


def test_rejection_is_final(queue, sms):
    code = ask(queue).code
    assert owner_says(queue, f"no {code}")[0].outcome == "rejected"
    assert owner_says(queue, f"approve {code}")[0].outcome == "already_rejected"
    assert sms.sent == []


@pytest.mark.parametrize("text", ["do not approve {code}", "approve {code}? not sure",
                                  "yes {code} no wait"])
def test_hedged_or_contradictory_replies_do_nothing(queue, sms, text):
    code = ask(queue).code
    [decision] = owner_says(queue, text.format(code=code))
    assert decision.outcome == "ambiguous"
    assert sms.sent == []


def test_a_bare_yes_without_a_code_decides_nothing(queue, sms):
    ask(queue)
    assert owner_says(queue, "yes") == []
    assert sms.sent == []


def test_approval_cannot_come_from_the_turn_that_made_the_request(queue, sms):
    with turn_scope(owner_turn("send it", message_id="SM42")):
        code = queue.request("sms.send", {"to": STRANGER, "body": "x"}, summary="x").code
    with turn_scope(owner_turn(f"approve {code}", message_id="SM42")):  # replayed turn id
        [decision] = queue.decide()
    assert decision.outcome == "refused"
    assert sms.sent == []


def test_expired_requests_cannot_be_approved(queue, clock, sms):
    code = ask(queue).code
    clock.advance(hours=25)
    assert owner_says(queue, f"approve {code}")[0].outcome == "expired"
    assert sms.sent == []


def test_a_failing_executor_is_not_retried(queue, sms):
    queue.register("explode", lambda: (_ for _ in ()).throw(RuntimeError("secret detail")))
    with turn_scope(owner_turn()):
        code = queue.request("explode", {}, summary="Explode").code
    [decision] = owner_says(queue, f"approve {code}")
    assert decision.outcome == "failed" and "secret" not in decision.message
    assert owner_says(queue, f"approve {code}")[0].outcome == "already_failed"


def test_execution_is_marked_in_progress_before_the_side_effect(queue):
    """At-most-once: if the process dies mid-send the request stays 'executing' and is
    never re-run automatically."""
    seen = []

    def executor(note):
        with turn_scope(owner_turn()):
            seen.append(queue.get(code).status)

    queue.register("note", executor)
    with turn_scope(owner_turn()):
        code = queue.request("note", {"note": "x"}, summary="Note").code
    owner_says(queue, f"approve {code}")
    assert seen == [ApprovalStatus.EXECUTING]


def test_a_tampered_payload_is_never_executed(queue, sms):
    code = ask(queue).code
    stored = queue.store.load()
    stored[code].payload["to"] = "+15550009999"          # someone edits the store file
    queue.store.save(stored)
    [decision] = owner_says(queue, f"approve {code}")
    assert decision.outcome == "failed"
    assert sms.sent == []


def test_editing_rotates_the_code_so_old_approvals_cannot_apply(queue, sms):
    old = ask(queue).code
    with turn_scope(owner_turn("change the wording")):
        new = queue.edit(old, {"to": STRANGER, "body": "Invoice attached (corrected)"}).code
    assert new != old
    assert owner_says(queue, f"approve {old}") == []
    assert owner_says(queue, f"approve {new}")[0].outcome == "executed"
    assert sms.sent[0]["body"] == "Invoice attached (corrected)"


def test_only_the_owner_can_edit_or_list(queue):
    code = ask(queue).code
    with turn_scope(customer_turn()):
        with pytest.raises(Refused):
            queue.edit(code, {"to": CUSTOMER, "body": "x"})
        with pytest.raises(Refused):
            queue.pending()
    with turn_scope(system_turn()):
        assert [a.code for a in queue.pending()] == [code]


def test_new_codes_never_collide_with_existing_ones(clock, sms):
    codes = iter(["AB23", "AB23", "CD34"])
    q = ApprovalQueue(MemoryApprovalStore(), clock=clock, code_factory=lambda: next(codes))
    q.register("sms.send", lambda to, body: sms.send(to, body))
    assert ask(q, body="one").code == "AB23"
    assert ask(q, body="two").code == "CD34"


def test_requests_survive_a_restart(tmp_path, clock, sms):
    path = tmp_path / "approvals.json"
    first = ApprovalQueue(JsonApprovalStore(path), clock=clock)
    first.register("sms.send", lambda to, body: sms.send(to, body))
    code = ask(first).code

    restarted = ApprovalQueue(JsonApprovalStore(path), clock=clock)
    restarted.register("sms.send", lambda to, body: sms.send(to, body))
    assert owner_says(restarted, f"approve {code}")[0].outcome == "executed"
    assert len(sms.sent) == 1


async def test_async_executors_run_through_adecide(clock, sms):
    q = ApprovalQueue(MemoryApprovalStore(), clock=clock)

    async def send(to, body):
        return sms.send(to, body)

    q.register("sms.send", send)
    code = ask(q).code
    with turn_scope(owner_turn(f"approve {code}")):
        [decision] = await q.adecide()
    assert decision.outcome == "executed" and len(sms.sent) == 1


# -- decision grammar ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("approve AB23", ("approve", ["AB23"])),
    ("AB23 yes please", ("approve", ["AB23"])),
    ("reject ab23 and CD34", ("reject", ["AB23", "CD34"])),
    ("don't AB23", ("reject", ["AB23"])),
    ("approve AB23, reject CD34", (None, ["AB23", "CD34"])),
    ("hmm AB23", (None, ["AB23"])),
    ("approve ZZ99", (None, [])),
])
def test_parse_decision(text, expected):
    assert parse_decision(text, {"AB23", "CD34"}) == expected


# -- the decorator ------------------------------------------------------------------------------

def make_send(queue, sms, when=always):
    @send_gate(recipient="to", channel="sms")
    @requires_approval(queue, "sms.decorated", summary=lambda a: f"Text {a['to']}", when=when)
    def send_sms(to: str, body: str):
        return sms.send(to, body)
    return send_sms


def test_decorated_tool_queues_instead_of_running(queue, sms):
    send_sms = make_send(queue, sms)
    with turn_scope(owner_turn()):
        out = send_sms(STRANGER, "Quote attached")
    assert out["status"] == "pending_approval" and out["summary"] == f"Text {STRANGER}"
    assert sms.sent == []
    owner_says(queue, f"approve {out['code']}")
    assert sms.sent == [{"to": STRANGER, "body": "Quote attached"}]


def test_unless_clean_owner_runs_directly_only_for_a_clean_owner_turn(queue, sms):
    send_sms = make_send(queue, sms, when=unless_clean_owner)
    with turn_scope(owner_turn()):
        assert send_sms(STRANGER, "direct")["to"] == STRANGER
    with turn_scope(owner_turn()):
        mark_untrusted("email")                       # the agent read an inbound email
        assert send_sms(STRANGER, "from email")["status"] == "pending_approval"
    with turn_scope(customer_turn()):
        assert send_sms(OWNER_PHONE, "relay")["status"] == "pending_approval"
    assert [m["body"] for m in sms.sent] == ["direct"]


def test_role_gates_still_run_before_anything_is_queued(queue, sms, notified):
    send_sms = make_send(queue, sms)
    with turn_scope(customer_turn()), pytest.raises(Refused):
        send_sms(STRANGER, "spam")
    assert notified == [] and sms.sent == []
