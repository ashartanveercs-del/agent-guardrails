"""Prove the red-team suite has teeth: weaken one guard at a time and check it goes red.

    python scripts/mutation_check.py

Each mutation edits one line of the source, runs ``pytest tests/redteam``, and restores
the original file in a ``finally`` block. Exit code 0 means every mutation was caught.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (what the mutation simulates, file, original text, weakened text)
MUTATIONS = [
    ("send gate lets third parties text anyone", "src/agent_guardrails/gates.py",
     "            if _is_self(turn, chosen, target) or turn.owners.owns(chosen, target):\n"
     "                return\n",
     "            return\n"),
    ("unverified envelopes count as verified", "src/agent_guardrails/identity.py",
     "    if not source.verified:\n        return third_party(\"unverified envelope\")\n",
     ""),
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
    ("MCP taint forgotten between calls", "src/agent_guardrails/mcp.py",
     "                mark_untrusted(source)\n",
     "                pass\n"),
]


def main() -> int:
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
            proc = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running pytest
                [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                 "tests/redteam", "tests/test_tenancy.py"],
                cwd=ROOT, capture_output=True, text=True, timeout=600, check=False)
        finally:
            path.write_bytes(raw)
        caught = proc.returncode != 0
        missed += not caught
        first = next((ln for ln in proc.stdout.splitlines() if ln.startswith("FAILED")), "")
        print(f"[{'CAUGHT' if caught else 'MISSED'}] {label}\n          {first[7:110]}")
    print(f"\n{len(MUTATIONS) - missed}/{len(MUTATIONS)} mutations caught")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
