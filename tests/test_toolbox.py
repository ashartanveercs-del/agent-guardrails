"""Toolbox: per-role tool visibility, strict argument validation, safe error shapes."""

import json

import pytest

from agent_guardrails.context import turn_scope
from agent_guardrails.errors import Refused
from agent_guardrails.gates import owner_only, send_gate
from agent_guardrails.identity import Role
from agent_guardrails.schema import validate
from agent_guardrails.toolbox import Toolbox
from tests.fakes import (
    CUSTOMER,
    STRANGER,
    FakeMailbox,
    FakeSmsApi,
    customer_turn,
    owner_turn,
    system_turn,
)

SEND_SCHEMA = {
    "type": "object",
    "required": ["to", "body"],
    "properties": {"to": {"type": "string", "maxLength": 32},
                   "body": {"type": "string", "maxLength": 320}},
}


@pytest.fixture
def services():
    return {"sms": FakeSmsApi(), "mail": FakeMailbox([{"subject": "Hi", "body": "x"}])}


@pytest.fixture
def toolbox(services):
    box = Toolbox()

    @box.tool(description="Search the owner's inbox.",
              parameters={"type": "object",
                          "properties": {"query": {"type": "string", "maxLength": 200}}})
    @owner_only
    def read_inbox(query: str = ""):
        return services["mail"].search(query)

    @box.tool(description="Send an SMS.", parameters=SEND_SCHEMA,
              roles=(Role.OWNER, Role.THIRD_PARTY, Role.SYSTEM))
    @send_gate(recipient="to", channel="sms")
    def send_sms(to: str, body: str):
        return services["sms"].send(to, body)

    @box.tool(description="Always breaks.", roles=(Role.OWNER,))
    def flaky():
        raise RuntimeError("upstream said: invalid api key sk-test-123 for /srv/secrets")

    return box


def names(specs):
    return sorted(s["name"] for s in specs)


def test_each_role_only_sees_its_own_tools(toolbox):
    with turn_scope(owner_turn()):
        assert names(toolbox.specs()) == ["flaky", "read_inbox", "send_sms"]
    with turn_scope(customer_turn()):
        assert names(toolbox.specs()) == ["send_sms"]


def test_tools_are_owner_and_system_only_unless_roles_say_otherwise(services):
    box = Toolbox()

    @box.tool(description="Default roles.")
    def internal():
        return "ok"

    with turn_scope(system_turn()):
        assert names(box.specs()) == ["internal"]
    with turn_scope(customer_turn()):
        assert box.specs() == []


def test_specs_are_strict_json_schemas(toolbox):
    with turn_scope(owner_turn()):
        spec = next(s for s in toolbox.specs() if s["name"] == "read_inbox")
    assert spec["description"] == "Search the owner's inbox."
    assert spec["parameters"]["additionalProperties"] is False


def test_listing_or_calling_outside_a_turn_is_refused(toolbox):
    with pytest.raises(Refused):
        toolbox.specs()
    with pytest.raises(Refused):
        toolbox.call("send_sms", {"to": CUSTOMER, "body": "x"})


def test_successful_call(toolbox, services):
    with turn_scope(owner_turn()):
        out = toolbox.call("send_sms", '{"to": "+15550007777", "body": "On my way"}')
    assert out["ok"] is True and out["result"]["to"] == STRANGER
    assert services["sms"].sent[0]["body"] == "On my way"


def test_hidden_tools_look_exactly_like_missing_ones(toolbox, services):
    with turn_scope(customer_turn()):
        hidden = toolbox.call("read_inbox", {"query": "password"})
        missing = toolbox.call("delete_everything", {})
    assert hidden == missing == {"ok": False, "code": "unknown_tool",
                                 "error": "That tool isn't available."}
    assert services["mail"].reads == 0


@pytest.mark.parametrize("arguments", [
    "{not json",
    "[1, 2]",
    [["to", CUSTOMER], ["body", "hi"]],                       # not an object at all
    42,
    {"to": CUSTOMER},                                         # missing body
    {"to": CUSTOMER, "body": "hi", "role": "owner"},          # smuggled extra field
    {"to": 15550002222, "body": "hi"},                        # wrong type
    {"to": CUSTOMER, "body": "x" * 321},                      # too long
])
def test_malformed_arguments_never_reach_the_tool(toolbox, services, arguments):
    with turn_scope(owner_turn()):
        out = toolbox.call("send_sms", arguments)
    assert out["ok"] is False and out["code"] == "invalid_args"
    assert services["sms"].sent == []


def test_gate_refusals_come_back_as_safe_messages(toolbox, services):
    with turn_scope(customer_turn()):
        out = toolbox.call("send_sms", {"to": STRANGER, "body": "click this link"})
    assert out == {"ok": False, "code": "recipient_not_allowed",
                   "error": "I can only send messages to you or to the owner."}
    assert services["sms"].sent == []


def test_unexpected_errors_never_leak_internals(toolbox):
    events = []
    toolbox.audit = events.append
    with turn_scope(owner_turn()):
        out = toolbox.call("flaky", {})
    assert out["ok"] is False and out["code"] == "tool_error"
    assert "sk-test" not in json.dumps(out) and "/srv" not in json.dumps(out)
    assert events[-1]["outcome"] == "tool_error"


def test_every_call_is_audited_with_role_and_outcome(toolbox):
    events = []
    toolbox.audit = events.append
    with turn_scope(customer_turn()):
        toolbox.call("send_sms", {"to": STRANGER, "body": "x"})
        toolbox.call("read_inbox", {})
    assert [(e["tool"], e["role"], e["outcome"]) for e in events] == [
        ("send_sms", "third_party", "recipient_not_allowed"),
        ("read_inbox", "third_party", "unknown_tool"),
    ]


async def test_async_tools_run_through_acall(services):
    box = Toolbox()

    @box.tool(description="Async send.", parameters=SEND_SCHEMA,
              roles=(Role.OWNER, Role.THIRD_PARTY))
    @send_gate(recipient="to", channel="sms")
    async def send_async(to: str, body: str):
        return services["sms"].send(to, body)

    with turn_scope(customer_turn()):
        refused = await box.acall("send_async", {"to": STRANGER, "body": "x"})
        allowed = await box.acall("send_async", {"to": CUSTOMER, "body": "thanks"})
        with pytest.raises(TypeError, match="acall"):
            box.call("send_async", {"to": CUSTOMER, "body": "x"})
    assert refused["code"] == "recipient_not_allowed" and allowed["ok"] is True
    assert [m["to"] for m in services["sms"].sent] == [CUSTOMER]


def test_duplicate_names_are_rejected():
    box = Toolbox()

    @box.tool(description="a")
    def thing():
        pass

    with pytest.raises(ValueError):
        @box.tool(description="b", name="thing")
        def other():
            pass


# -- schema subset ----------------------------------------------------------------------------

def test_schema_booleans_are_not_integers():
    schema = {"type": "object", "properties": {"count": {"type": "integer"}}}
    assert validate({"count": 3}, schema) == []
    assert validate({"count": True}, schema) != []


def test_schema_enum_pattern_bounds_and_arrays():
    schema = {"type": "object", "properties": {
        "channel": {"type": "string", "enum": ["sms", "email"]},
        "code": {"type": "string", "pattern": "^[A-Z0-9]{4}$"},
        "n": {"type": "number", "minimum": 1, "maximum": 10},
        "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
    }}
    assert validate({"channel": "sms", "code": "AB12", "n": 2.5, "tags": ["a"]}, schema) == []
    assert len(validate({"channel": "fax", "code": "ab", "n": 11, "tags": ["a", "b", 3]},
                        schema)) == 5


def test_schema_can_opt_in_to_extra_properties():
    schema = {"type": "object", "additionalProperties": True, "properties": {}}
    assert validate({"anything": 1}, schema) == []
