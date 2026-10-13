# Design claims and their evidence

[README](../README.md) · [Executed verification](VERIFICATION.md)

The enforcement boundary is the tool call. The model supplies a tool name and arguments;
trusted adapter metadata supplies identity. This table connects the important claims to
implementation and executable checks.

| Claim | Implementation | Evidence |
|---|---|---|
| Missing or unverified metadata grants no owner privileges | [identity.py](../src/agent_guardrails/identity.py) | [test_identity.py](../tests/test_identity.py): exact phone matching, Unicode digits, reserved channels and dropped unverified sender identities |
| Refused tool calls never reach the side-effect body | [gates.py](../src/agent_guardrails/gates.py), [toolbox.py](../src/agent_guardrails/toolbox.py) | [test_gates.py](../tests/test_gates.py), [red-team corpus](../tests/redteam/attacks.py): spies count calls, including a fully compromised scripted model |
| An approval is bound to the reviewed payload and claimed at most once | [approvals.py](../src/agent_guardrails/approvals.py), [storage.py](../src/agent_guardrails/storage.py) | [test_approvals.py](../tests/test_approvals.py): tampered payloads, rotated codes, strict reply grammar and multiple real worker processes sharing a store |
| Untrusted content remains tainted in later turns and RPC calls | [context.py](../src/agent_guardrails/context.py), [loop.py](../src/agent_guardrails/loop.py), [mcp.py](../src/agent_guardrails/mcp.py) | [test_loop.py](../tests/test_loop.py), [test_mcp.py](../tests/test_mcp.py), [test_redteam.py](../tests/redteam/test_redteam.py): two-turn injection and per-conversation carryover |
| Scheduling uses real gaps and owner-local time | [cron.py](../src/agent_guardrails/scheduling/cron.py), [when.py](../src/agent_guardrails/scheduling/when.py) | [test_cron.py](../tests/test_cron.py), [test_when.py](../tests/test_when.py): midnight wrap, DST gaps and folds, unsupported schedules |
| Evidence is sensitive to weakened guards | [mutation_check.py](../scripts/mutation_check.py) | 16 mutations; [test_mutation_check.py](../tests/test_mutation_check.py) rejects collection/usage errors and verifies exact source restoration |

## Boundaries

- Your adapter must verify platform signatures before setting `Envelope.verified`; the
  library cannot establish that a webhook came from a provider.
- Sealed envelopes authenticate metadata and enforce an age limit. They are neither
  encrypted nor single-use tokens. The MCP-style server implements `initialize`, `ping`,
  `tools/list` and `tools/call`, rather than the entire MCP specification.
- Decorators only protect tools routed through them. They do not sandbox arbitrary Python,
  protect a compromised host, or assess the factual correctness of model text.
- At-most-once approvals favor avoiding duplicate side effects: a process crash after an
  execution claim can leave the action unresolved, requiring a new owner decision.
- A taint ledger's retention must cover the conversation history kept by your gateway.
  Persistence and cooperative file locking are required when workers share that history.

The full integration requirements remain in the README's [security notes](../README.md#security-notes).
