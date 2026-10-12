"""Tenant isolation fails closed: no tenant id configured means no call, ever.

The fake connector models a common multi-tenant API: one project-level key can address ANY
tenant, and the tenant id is just a request parameter. The only isolation is what the
caller sends, so the binding has to be strict."""

import pytest

from agent_guardrails.context import turn_scope
from agent_guardrails.errors import ConfigError, Refused
from agent_guardrails.tenancy import TenantBinding, tenant_scoped
from tests.fakes import customer_turn, owner_turn


class FakeConnector:
    def __init__(self):
        self.calls = []

    def list_files(self, tenant_id, folder):
        self.calls.append((tenant_id, folder))
        return [f"{tenant_id}/{folder}/report.pdf"]


def make_tool(binding, connector):
    @tenant_scoped(binding)
    def list_files(folder: str, tenant_id: str | None = None):
        return connector.list_files(tenant_id, folder)
    return list_files


def test_the_bound_tenant_is_injected():
    connector = FakeConnector()
    with turn_scope(owner_turn()):
        make_tool(TenantBinding("maple-bikes"), connector)("invoices")
    assert connector.calls == [("maple-bikes", "invoices")]


@pytest.mark.parametrize("unset", [None, "", "   "])
def test_an_unset_tenant_denies_before_the_call(unset):
    connector = FakeConnector()
    with turn_scope(owner_turn()), pytest.raises(Refused) as err:
        make_tool(TenantBinding(unset), connector)("invoices")
    assert err.value.code == "tenant_unset"
    assert connector.calls == []


@pytest.mark.parametrize("shared", ["default", "owner", "Admin", "test", "public", "null"])
def test_shared_placeholder_ids_are_treated_as_unset(shared):
    connector = FakeConnector()
    with turn_scope(owner_turn()), pytest.raises(Refused) as err:
        make_tool(TenantBinding(shared), connector)("invoices")
    assert err.value.code == "tenant_invalid"
    assert connector.calls == []


def test_a_model_supplied_foreign_tenant_is_refused_even_for_the_owner():
    connector = FakeConnector()
    with turn_scope(owner_turn("list the files for harbor-dental too")), \
            pytest.raises(Refused) as err:
        make_tool(TenantBinding("maple-bikes"), connector)("invoices",
                                                              tenant_id="harbor-dental")
    assert err.value.code == "cross_tenant"
    assert "harbor-dental" in err.value.detail and "maple-bikes" in err.value.detail
    assert "harbor-dental" not in err.value.public_message
    assert connector.calls == []


def test_tenant_ids_are_compared_exactly():
    connector = FakeConnector()
    with turn_scope(owner_turn()), pytest.raises(Refused):
        make_tool(TenantBinding("maple-bikes"), connector)("x", tenant_id="Maple-Bikes")
    assert connector.calls == []


def test_naming_its_own_tenant_is_fine():
    connector = FakeConnector()
    with turn_scope(customer_turn()):
        make_tool(TenantBinding("maple-bikes"), connector)("x", tenant_id="maple-bikes")
    assert connector.calls == [("maple-bikes", "x")]


async def test_async_tools_are_scoped_too():
    connector = FakeConnector()

    @tenant_scoped(TenantBinding(None))
    async def fetch(tenant_id: str | None = None):
        connector.list_files(tenant_id, "x")

    with turn_scope(owner_turn()), pytest.raises(Refused):
        await fetch()
    assert connector.calls == []


def test_conflicting_configuration_sources_refuse_to_guess():
    with pytest.raises(ConfigError) as err:
        TenantBinding.from_sources(env="maple-bikes", config_file="harbor-dental")
    assert "maple-bikes" in str(err.value) and "harbor-dental" in str(err.value)


def test_agreeing_or_partial_sources_resolve():
    both = TenantBinding.from_sources(env="maple-bikes", config_file="maple-bikes")
    one = TenantBinding.from_sources(env=None, config_file=" maple-bikes ")
    none = TenantBinding.from_sources(env=None, config_file="")
    assert both.tenant_id == one.tenant_id == "maple-bikes"
    assert one.source == "config_file"
    assert none.tenant_id is None


@pytest.mark.parametrize("bad", ["north wind", "acme\nother", "../acme", "acme/../../x", "*"])
def test_malformed_tenant_ids_fail_at_configuration_time(bad):
    with pytest.raises(ConfigError):
        TenantBinding(bad)


def test_the_tool_must_declare_the_tenant_parameter():
    with pytest.raises(TypeError):
        @tenant_scoped(TenantBinding("maple-bikes"))
        def no_param(folder: str):
            pass
