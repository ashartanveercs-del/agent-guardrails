"""The top-level package exposes the whole public API."""

import agent_guardrails as ag
import agent_guardrails.scheduling as sched

EXPECTED = {
    "Role", "Envelope", "SystemOrigin", "OwnerIdentity", "TurnContext", "classify_turn",
    "turn_scope", "current_turn", "mark_untrusted", "tainted_by", "TaintLedger",
    "owner_only", "send_gate", "own_records_only", "untrusted_output",
    "Refused", "ConfigError", "GuardrailError", "StateCorrupt",
    "Toolbox", "ApprovalQueue", "ApprovalStatus", "MemoryApprovalStore", "JsonApprovalStore",
    "requires_approval", "always", "unless_clean_owner", "when_tainted",
    "TenantBinding", "tenant_scoped",
    "CarryForward", "Candidate", "Backoff", "Status", "item_key",
    "seal_envelope", "open_envelope", "McpToolServer",
    "run_turn", "ModelReply", "ToolCall", "Settings", "__version__",
}


def test_everything_is_importable_from_the_package():
    assert set(ag.__all__) >= EXPECTED
    for name in ag.__all__:
        assert getattr(ag, name) is not None


def test_scheduling_subpackage():
    for name in ("SafeScheduler", "CommandRegistry", "MemoryBackend", "Job", "CronSchedule",
                 "CronError", "resolve_when", "time_of_day", "WhenError", "Resolved"):
        assert name in sched.__all__ and getattr(sched, name) is not None


def test_version_matches_package_metadata():
    from importlib.metadata import version
    assert ag.__version__ == version("agent-guardrails")
