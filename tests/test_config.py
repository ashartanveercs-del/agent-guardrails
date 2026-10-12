"""Settings come from environment variables and are validated at startup."""

from datetime import timedelta

import pytest

from agent_guardrails.config import Settings, read_env_file
from agent_guardrails.errors import ConfigError

FULL = {
    "GUARDRAILS_OWNER_PHONES": "+15550001111, +1 (555) 000-3333",
    "GUARDRAILS_OWNER_EMAILS": "owner@example.com",
    "GUARDRAILS_OWNER_ACCOUNTS": "slack:U0OWNER, discord:123456",
    "GUARDRAILS_TIMEZONE": "America/Chicago",
    "GUARDRAILS_TENANT_ID": "maple-bikes",
    "GUARDRAILS_MIN_INTERVAL_MINUTES": "15",
    "GUARDRAILS_APPROVAL_TTL_HOURS": "4",
    "GUARDRAILS_ENVELOPE_KEY": "x" * 40,
}


def test_full_configuration():
    s = Settings.from_env(FULL)
    assert s.owners.phones == {"+15550001111", "+15550003333"}
    assert s.owners.emails == {"owner@example.com"}
    assert s.owners.accounts["slack"] == {"U0OWNER"}
    assert s.timezone == "America/Chicago"
    assert s.tenant.tenant_id == "maple-bikes"
    assert s.min_schedule_interval == timedelta(minutes=15)
    assert s.approval_ttl == timedelta(hours=4)
    assert s.envelope_key == b"x" * 40


def test_defaults_are_conservative():
    s = Settings.from_env({})
    assert not s.owners.configured            # nobody is the owner until configured
    assert s.timezone == "UTC"
    assert s.tenant.tenant_id is None         # tenant-scoped tools will refuse
    assert s.min_schedule_interval == timedelta(minutes=5)
    assert s.approval_ttl == timedelta(hours=24)
    assert s.envelope_key is None


@pytest.mark.parametrize("name,value", [
    ("GUARDRAILS_OWNER_PHONES", "5550001111"),
    ("GUARDRAILS_OWNER_EMAILS", "Owner <owner@example.com>"),
    ("GUARDRAILS_OWNER_ACCOUNTS", "slack-U0OWNER"),
    ("GUARDRAILS_TIMEZONE", "Moon/Base"),
    ("GUARDRAILS_TENANT_ID", "north wind"),
    ("GUARDRAILS_MIN_INTERVAL_MINUTES", "1"),
    ("GUARDRAILS_MIN_INTERVAL_MINUTES", "often"),
    ("GUARDRAILS_APPROVAL_TTL_HOURS", "0"),
    ("GUARDRAILS_APPROVAL_TTL_HOURS", "1000"),
])
def test_bad_values_fail_at_startup_naming_the_variable(name, value):
    with pytest.raises(ConfigError, match=name):
        Settings.from_env({name: value})


def test_env_files_are_read_strictly(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# owner\nGUARDRAILS_OWNER_PHONES=+15550001111\n\n"
                    "GUARDRAILS_TIMEZONE = 'Europe/London'\n"
                    'GUARDRAILS_TENANT_ID="maple-bikes"\nEMPTY=\n', encoding="utf-8")
    values = read_env_file(path)
    assert values == {"GUARDRAILS_OWNER_PHONES": "+15550001111",
                      "GUARDRAILS_TIMEZONE": "Europe/London",
                      "GUARDRAILS_TENANT_ID": "maple-bikes", "EMPTY": ""}
    assert Settings.from_env(values).timezone == "Europe/London"


def test_a_malformed_env_file_line_is_an_error_naming_the_line(tmp_path):
    path = tmp_path / ".env"
    path.write_text("GUARDRAILS_TIMEZONE=UTC\nthis is not an assignment\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="line 2"):
        read_env_file(path)


def test_a_short_envelope_key_is_refused_without_echoing_it():
    secret = "tooshort-secret"
    with pytest.raises(ConfigError) as err:
        Settings.from_env({"GUARDRAILS_ENVELOPE_KEY": secret})
    assert "GUARDRAILS_ENVELOPE_KEY" in str(err.value)
    assert secret not in str(err.value)
