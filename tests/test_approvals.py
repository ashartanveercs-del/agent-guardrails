"""Approval queue: anyone may ask, only the verified owner can decide, and only in code."""

import contextlib
import hashlib
import json
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

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
    when_tainted,
)
from agent_guardrails.context import mark_untrusted, turn_scope
from agent_guardrails.errors import ConfigError, Refused
from agent_guardrails.gates import send_gate
from agent_guardrails.identity import Envelope, classify_turn
from tests.fakes import (
    CUSTOMER,
    OWNER_PHONE,
    OWNERS,
    STRANGER,
    FakeClock,
    FakeSmsApi,
    customer_turn,
    owner_turn,
    system_turn,
)

KEY = b"k" * 32          # the queue's signing secret; never stored with the requests
WORKER = Path(__file__).with_name("approval_worker.py")


def unverified_turn(sender):
    return classify_turn(Envelope("sms", sender, verified=False, text="call me"), OWNERS)


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


def test_unverified_senders_share_one_pending_cap(queue, notified):
    """Rotating the claimed (spoofable) number must not buy a fresh quota of owner alerts."""
    for i in range(3):
        ask(queue, unverified_turn(f"+1555000{3000 + i}"), to=OWNER_PHONE, body=f"call me #{i}")
    with pytest.raises(Refused) as err:
        ask(queue, unverified_turn("+15550003999"), to=OWNER_PHONE, body="call me #4")
    assert err.value.code == "too_many_pending"
    assert len(notified) == 3


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


def test_codes_are_case_insensitive_and_may_come_before_the_verb(queue, sms):
    code = ask(queue).code
    owner_says(queue, f"{code.lower()} ok!")
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


@pytest.mark.parametrize("text", [
    "never send {code}",
    "don’t send {code}",           # the apostrophe iOS and macOS type by default
    "Please don’t do {code}",
    "don't send {code}",
    "dont go ahead with {code}",
    "send {code} to the trash",
    "nope, don't send {code}",
    "nah {code} can wait",
    "hold off on {code}",
    "wait on {code}",
    "approve {code} tomorrow",
    "ok but not {code}",
    "{code}: no way",
])
def test_a_refusal_is_never_read_as_an_approval(queue, sms, text):
    """Negation can't be listed exhaustively ("never", "nope", "send it to the trash"), so
    only an exact verb + code approves, and everything else does nothing."""
    code = ask(queue).code
    [decision] = owner_says(queue, text.format(code=code))
    assert decision.outcome in ("ambiguous", "rejected")
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


def unkeyed_digest(action, payload):
    """What anyone can compute from the stored request with the published format."""
    blob = json.dumps({"action": action, "payload": payload}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def test_a_payload_rewritten_with_a_recomputed_digest_is_never_executed(queue, sms):
    """Someone who can edit the store can also recompute any digest that doesn't need a
    secret, so the digest has to be keyed."""
    code = ask(queue).code
    stored = queue.store.load()
    stored[code].payload["to"] = "+15550009999"
    stored[code].digest = unkeyed_digest(stored[code].action, stored[code].payload)
    queue.store.save(stored)
    [decision] = owner_says(queue, f"approve {code}")
    assert decision.outcome == "failed"
    assert sms.sent == []


def test_a_payload_cannot_be_moved_onto_another_code(queue, sms):
    """The owner approves the request they were shown under that code, never another one."""
    shown = ask(queue, body="Quote attached").code
    other = ask(queue, to="+15550009999", body="Gift card numbers").code
    stored = queue.store.load()
    stored[shown].payload, stored[shown].digest = stored[other].payload, stored[other].digest
    queue.store.save(stored)
    [decision] = owner_says(queue, f"approve {shown}")
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
    first = ApprovalQueue(JsonApprovalStore(path), key=KEY, clock=clock)
    first.register("sms.send", lambda to, body: sms.send(to, body))
    code = ask(first).code

    restarted = ApprovalQueue(JsonApprovalStore(path), key=KEY, clock=clock)
    restarted.register("sms.send", lambda to, body: sms.send(to, body))
    assert owner_says(restarted, f"approve {code}")[0].outcome == "executed"
    assert len(sms.sent) == 1


def test_a_persistent_store_needs_a_long_secret_key(tmp_path):
    with pytest.raises(ConfigError, match="key"):
        ApprovalQueue(JsonApprovalStore(tmp_path / "approvals.json"))
    with pytest.raises(ConfigError, match="32 bytes"):
        ApprovalQueue(JsonApprovalStore(tmp_path / "approvals.json"), key=b"short")


def test_editing_the_approvals_file_cannot_change_what_runs(tmp_path, clock, sms):
    """The reported attack: rewrite the recipient in approvals.json and recompute the digest.
    Without the queue's key the new digest can't be right, so nothing runs."""
    path = tmp_path / "approvals.json"
    queue = ApprovalQueue(JsonApprovalStore(path), key=KEY, clock=clock)
    queue.register("sms.send", lambda to, body: sms.send(to, body))
    code = ask(queue, to="+15550004444", body="Quote attached").code
    data = json.loads(path.read_text(encoding="utf-8"))
    [stored] = data["approvals"]
    stored["payload"]["to"] = "+15550009999"
    stored["digest"] = unkeyed_digest(stored["action"], stored["payload"])
    path.write_text(json.dumps(data), encoding="utf-8")
    [decision] = owner_says(queue, f"approve {code}")
    assert decision.outcome == "failed"
    assert sms.sent == []


def test_requests_signed_with_another_key_never_run(tmp_path, clock, sms):
    path = tmp_path / "approvals.json"
    first = ApprovalQueue(JsonApprovalStore(path), key=KEY, clock=clock)
    first.register("sms.send", lambda to, body: sms.send(to, body))
    code = ask(first).code
    rotated = ApprovalQueue(JsonApprovalStore(path), key=b"r" * 32, clock=clock)
    rotated.register("sms.send", lambda to, body: sms.send(to, body))
    assert owner_says(rotated, f"approve {code}")[0].outcome == "failed"
    assert sms.sent == []


def test_two_workers_sharing_a_store_run_an_approval_at_most_once(tmp_path, clock,
                                                                  monkeypatch):
    """At most once has to hold across worker processes, not just across one queue's threads.
    Two queues over one file stand in for two workers: each has its own store object and file
    handle. A barrier makes both hold what they read before either saves - unless the store
    keeps the whole read-modify-write to one worker at a time."""
    path = tmp_path / "approvals.json"
    executed, errors = [], []

    def worker_queue():
        q = ApprovalQueue(JsonApprovalStore(path), key=KEY, clock=clock)
        q.register("sms.send", lambda to, body: executed.append(to))
        return q

    first, second = worker_queue(), worker_queue()
    code = ask(first).code
    barrier, original_load = threading.Barrier(2, timeout=1), JsonApprovalStore.load

    def racing_load(self):
        approvals = original_load(self)
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait()
        return approvals

    monkeypatch.setattr(JsonApprovalStore, "load", racing_load)

    def decide(queue):
        try:
            owner_says(queue, f"approve {code}")
        except Exception as exc:          # e.g. PermissionError from a concurrent replace
            errors.append(exc)

    threads = [threading.Thread(target=decide, args=(q,)) for q in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == []
    assert executed == [STRANGER]


def test_worker_processes_sharing_a_store_run_an_approval_once(tmp_path):
    """The same guarantee with real processes, all deciding at the same moment."""
    store, log = tmp_path / "approvals.json", tmp_path / "executions.log"
    queue = ApprovalQueue(JsonApprovalStore(store), key=KEY)
    queue.register("sms.send", lambda to, body: None)
    code = ask(queue).code
    start_at = time.time() + 2
    argv = [sys.executable, str(WORKER), str(store), str(log), code, str(start_at)]
    workers = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
               for _ in range(3)]
    outcomes = []
    for worker in workers:
        out, err = worker.communicate(timeout=60)
        assert worker.returncode == 0, err
        outcomes.append(out.strip())
    assert sorted(outcomes)[-1] == "executed"
    assert all(o.startswith("already_") for o in sorted(outcomes)[:-1]), outcomes
    assert log.read_text(encoding="utf-8").splitlines() == [STRANGER]


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
    ("  Approve ab23. ", ("approve", ["AB23"])),
    ("yes AB23!", ("approve", ["AB23"])),
    ("AB23 ok", ("approve", ["AB23"])),                     # the code may come first
    ("'approve AB23'", ("approve", ["AB23"])),              # pasted with the prompt's quotes
    ("approve AB23 and CD34", ("approve", ["AB23", "CD34"])),
    ("approve: AB23, CD34", ("approve", ["AB23", "CD34"])),
    ("reject ab23 and CD34", ("reject", ["AB23", "CD34"])),
    ("no AB23", ("reject", ["AB23"])),
    ("never AB23", ("reject", ["AB23"])),
    ("don't AB23", ("reject", ["AB23"])),
    ("don’t AB23", ("reject", ["AB23"])),              # smart apostrophe
    ("AB23 yes please", (None, ["AB23"])),                  # anything beyond verb + codes
    ("never send AB23", (None, ["AB23"])),
    ("don’t send AB23", (None, ["AB23"])),
    ("send AB23 to the trash", (None, ["AB23"])),
    ("approve AB23, reject CD34", (None, ["AB23", "CD34"])),
    ("approve AB23 approve", (None, ["AB23"])),
    ("AB23 approve CD34", (None, ["AB23", "CD34"])),         # the verb leads or trails
    ("approve and AB23", (None, ["AB23"])),
    ("approve AB23?", (None, ["AB23"])),
    ("approve AB23 \U0001f44d", (None, ["AB23"])),
    ("approve AB23 ZZ99", (None, ["AB23"])),                 # an unknown code is an extra word
    ("hmm AB23", (None, ["AB23"])),
    ("approve ZZ99", (None, [])),
    ("", (None, [])),
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


def test_when_tainted_queues_only_what_a_tainted_turn_asks_for(queue, sms):
    send_sms = make_send(queue, sms, when=when_tainted)
    with turn_scope(customer_turn()):
        assert send_sms(CUSTOMER, "See you Saturday")["to"] == CUSTOMER     # a plain reply
    with turn_scope(owner_turn()):
        assert send_sms(STRANGER, "Running late")["to"] == STRANGER
    with turn_scope(owner_turn()):
        mark_untrusted("email")
        assert send_sms(STRANGER, "fwd: the invoice")["status"] == "pending_approval"
    assert [m["body"] for m in sms.sent] == ["See you Saturday", "Running late"]


def test_role_gates_still_run_before_anything_is_queued(queue, sms, notified):
    send_sms = make_send(queue, sms)
    with turn_scope(customer_turn()), pytest.raises(Refused):
        send_sms(STRANGER, "spam")
    assert notified == [] and sms.sent == []
