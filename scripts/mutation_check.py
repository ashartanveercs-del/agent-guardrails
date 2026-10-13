"""Prove the red-team suite has teeth: weaken one guard at a time and check it goes red.

    python scripts/mutation_check.py

Each mutation edits one line (or one statement) of the source, runs the red-team, tenancy
and approval tests, and restores the original file in a ``finally`` block. Exit code 0
means every mutation was caught.
"""

from __future__ import annotations

import os
import subprocess
import sys
from importlib.util import cache_from_source
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (what the mutation simulates, file, original text, weakened text)
MUTATIONS = [
    ("send gate lets third parties text anyone", "src/agent_guardrails/gates.py",
     "            if not turn.is_trusted:\n",
     "            if False:\n"),
    ("send gate ignores taint on owner and system turns", "src/agent_guardrails/gates.py",
     "            taint = tainted_by()\n",
     "            taint = frozenset()\n"),
    ("unverified envelopes count as verified", "src/agent_guardrails/identity.py",
     "    if not source.verified:\n",
     "    if False:\n"),
    ("unverified senders keep their claimed id", "src/agent_guardrails/identity.py",
     "        return TurnContext(Role.THIRD_PARTY, channel, \"\", unverified_id, owners, "
     "text=text,\n",
     "        return TurnContext(Role.THIRD_PARTY, channel, sender, unverified_id, owners, "
     "text=text,\n"),
    ("taint is ignored by the approval policy", "src/agent_guardrails/approvals.py",
     "    return not (turn.is_trusted and not taint)\n",
     "    return not turn.is_trusted\n"),
    ("own-records pinning disabled", "src/agent_guardrails/gates.py",
     "            if raw not in (None, \"\") and canonical_sender(turn.channel, raw) "
     "!= turn.sender:\n",
     "            if False:\n"),
    ("hidden tools become callable", "src/agent_guardrails/toolbox.py",
     "        if tool is None or turn.role not in tool.roles:\n",
     "        if tool is None:\n"),
    ("scheduler interval floor removed", "src/agent_guardrails/scheduling/scheduler.py",
     "        if gap < self.min_interval:\n",
     "        if False:\n"),
    ("approval pending cap removed", "src/agent_guardrails/approvals.py",
     "                if waiting >= self.max_pending_per_requester:\n",
     "                if False:\n"),
    ("tenant id accepted from the caller", "src/agent_guardrails/tenancy.py",
     "        if requested != own:\n",
     "        if False:\n"),
    ("MCP taint forgotten between calls and messages", "src/agent_guardrails/mcp.py",
     "        return self._taint.get(turn.turn_id, frozenset()) | "
     "self.taint_ledger.carried(turn)\n",
     "        return frozenset()\n"),
    ("taint ledger not consulted on the next turn", "src/agent_guardrails/loop.py",
     "        return ledger.carried(turn)\n",
     "        return frozenset()\n"),
    ("untracked history treated as clean", "src/agent_guardrails/loop.py",
     "    return frozenset({UNTRACKED_HISTORY}) if history and turn.is_trusted else "
     "frozenset()\n",
     "    return frozenset()\n"),
    ("decision grammar skips words it doesn't know", "src/agent_guardrails/approvals.py",
     "            return None                        # any other word may change the meaning\n",
     "            continue\n"),
    ("approval digest not checked", "src/agent_guardrails/approvals.py",
     "        elif not _same_digest(self._digest(code, approval.action, approval.payload),\n"
     "                              approval.digest):\n",
     "        elif False:\n"),
    ("approval store lock skipped", "src/agent_guardrails/approvals.py",
     "        with self._lock, self.store.lock():\n",
     "        with self._lock:\n"),
]


def main() -> int:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    argv = [sys.executable, "-B", "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
            "tests/redteam", "tests/test_tenancy.py", "tests/test_approvals.py"]
    baseline = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running pytest
        argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600, check=False)
    if baseline.returncode != 0:
        print("[ERROR ] clean baseline failed; no mutations attempted")
        print(baseline.stdout + baseline.stderr)
        return 1
    print("[BASELINE] clean suite passed")
    missed = 0
    for label, relative, original, weakened in MUTATIONS:
        path = ROOT / relative
        raw = path.read_bytes()                     # restored byte-for-byte afterwards
        source = raw.decode("utf-8")
        newline = "\r\n" if "\r\n" in source else "\n"
        text = source.replace("\r\n", "\n")
        if original not in text:
            print(f"[STALE ] {label}: the guarded line moved; update this script")
            missed += 1
            continue
        try:
            mutated = text.replace(original, weakened, 1).replace("\n", newline)
            path.write_bytes(mutated.encode("utf-8"))
            # -B prevents writes, but still reads existing bytecode. Remove this module's
            # cache so a same-size edit within one timestamp tick cannot be hidden by it.
            Path(cache_from_source(str(path))).unlink(missing_ok=True)
            proc = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running pytest
                argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600, check=False)
        finally:
            path.write_bytes(raw)
        first = next((ln for ln in proc.stdout.splitlines() if ln.startswith("FAILED")), "")
        caught = proc.returncode == 1 and bool(first)
        missed += not caught
        status = "CAUGHT" if caught else "MISSED" if proc.returncode == 0 else "ERROR "
        print(f"[{status}] {label}\n          {first[7:110]}")
        if status == "ERROR ":
            print(f"          pytest exit {proc.returncode}: no test-failure evidence")
    print(f"\n{len(MUTATIONS) - missed}/{len(MUTATIONS)} mutations caught")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
