# Verification record — 2026-10-12

[README](../README.md) · [Design proof map](PROOF_MAP.md) · [CI workflow](../.github/workflows/ci.yml)

Executed locally on Windows 11 with CPython 3.12.10, from the repository root, using the
existing development virtual environment. All checks below were offline; no provider keys,
messages or live services were used. The date is the review's local date (America/Los_Angeles).

| Exact PowerShell command | Observed result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest -q -ra` | **583 passed**, 0 skipped, 0 failed; 13.37 s |
| `.\.venv\Scripts\python.exe -m ruff check src tests examples scripts` | All checks passed |
| `.\.venv\Scripts\python.exe examples\plain_agent_loop.py` | Exit 0; stranger-recipient send refused, private read hidden, content-bound owner approval completed, scheduled reminder and verified briefing shown |
| `.\.venv\Scripts\python.exe examples\mcp_client_demo.py` | Exit 0; real stdio child process, forged seal denied, own-record scope enforced, tenant argument rejected, server exited cleanly |
| `.\.venv\Scripts\python.exe scripts\mutation_check.py` | Exit 0; clean baseline passed; **16/16 mutations caught by actual test failures** |

Use `python -m pytest`, `python -m ruff` and forward-slash script paths from an activated
environment on other platforms. CI is configured for Linux/Python 3.11 and 3.12 plus
Windows/Python 3.12; its demos and mutation check are explicit workflow gates.

## Fixes validated in this review

- A non-ASCII envelope signature previously raised `TypeError` in `hmac.compare_digest`.
  Three new regression cases failed before the fix, then passed after malformed signatures
  were rejected as `None`. The full sealing file reports 19 passing cases.
- The mutation harness previously credited any nonzero pytest status. The new regression
  suite reproduced six failing cases before the fix; all seven now pass. A green baseline
  is required, collection/usage/no-tests errors never count as caught mutations, cached
  bytecode for the mutated module is removed, and source bytes are restored on timeout.

## What this proves and what remains outside it

The suite checks identity, tool schemas, refusal-before-side-effect behavior, approvals
across real worker processes, persistent taint, scheduling, tenancy and briefing hygiene.
Thirty scripted attacks run with a model that follows hostile instructions, including
cross-turn attacks; mutation testing shows the selected guards are behaviorally exercised.
This is not evidence about arbitrary model behavior, provider signature verification,
full MCP interoperability or a compromised host. See [the boundaries](PROOF_MAP.md#boundaries).

## Publication audit

The pre-publication audit inspected 55 tracked files and every reachable historical blob:
3 commits, 83 unique blobs. It checked file inventory and commit subjects, known credential
formats/private-key markers, private fleet names and paths, embedded addresses and URL
hosts. No credential or private infrastructure candidates were found. Phone numbers and
email addresses are fictional fixtures; signing keys in tests are explicit throwaway data;
`.env.example` leaves secret variables empty. Public author attribution is intentional.
No publication blocker was found; no history was rewritten.
