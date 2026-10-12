"""Deterministic guardrails for tool-using AI agents.

Identity comes from verified channel metadata, permissions are enforced in code before any
side effect, consequential actions wait for an owner approval the model can't forge, and
scheduling, briefings and tenancy all fail closed.
"""

from ._version import __version__
from .approvals import (
    ApprovalQueue,
    ApprovalStatus,
    JsonApprovalStore,
    MemoryApprovalStore,
    always,
    requires_approval,
    unless_clean_owner,
    when_tainted,
)
from .carryforward import Backoff, BriefingPlan, Candidate, CarryForward, Status, item_key
from .config import Settings
from .context import TaintLedger, current_turn, mark_untrusted, tainted_by, turn_scope
from .errors import ConfigError, GuardrailError, Refused, StateCorrupt
from .gates import own_records_only, owner_only, send_gate, untrusted_output
from .identity import Envelope, OwnerIdentity, Role, SystemOrigin, TurnContext, classify_turn
from .loop import ModelReply, ToolCall, TurnResult, run_turn
from .mcp import McpToolServer
from .sealing import open_envelope, seal_envelope
from .tenancy import TenantBinding, tenant_scoped
from .toolbox import Toolbox

__all__ = [
    "ApprovalQueue", "ApprovalStatus", "Backoff", "BriefingPlan", "Candidate", "CarryForward",
    "ConfigError", "Envelope", "GuardrailError", "JsonApprovalStore", "McpToolServer",
    "MemoryApprovalStore", "ModelReply", "OwnerIdentity", "Refused", "Role", "Settings",
    "StateCorrupt", "Status", "SystemOrigin", "TaintLedger", "TenantBinding", "ToolCall",
    "Toolbox", "TurnContext", "TurnResult", "__version__", "always", "classify_turn",
    "current_turn", "item_key", "mark_untrusted", "open_envelope", "own_records_only",
    "owner_only", "requires_approval", "run_turn", "seal_envelope", "send_gate", "tainted_by",
    "tenant_scoped", "turn_scope", "unless_clean_owner", "untrusted_output", "when_tainted",
]
