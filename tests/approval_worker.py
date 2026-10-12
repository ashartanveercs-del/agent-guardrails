"""One worker process for the at-most-once test: it decides an owner's "approve CODE" against
a JsonApprovalStore shared with other workers, and logs each execution to a file.

    python tests/approval_worker.py STORE LOG CODE START_AT
"""

from __future__ import annotations

import sys
import time

from agent_guardrails import (
    ApprovalQueue,
    Envelope,
    JsonApprovalStore,
    OwnerIdentity,
    classify_turn,
    turn_scope,
)

OWNER = "+15550001111"
KEY = b"k" * 32


def main(store: str, log: str, code: str, start_at: float) -> int:
    queue = ApprovalQueue(JsonApprovalStore(store), key=KEY)

    def send(to: str, body: str) -> dict[str, str]:
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(f"{to}\n")
        return {"to": to}

    queue.register("sms.send", send)
    turn = classify_turn(Envelope("sms", OWNER, verified=True, text=f"approve {code}"),
                         OwnerIdentity(phones=[OWNER]))
    while time.time() < start_at:            # line every worker up on the same moment
        time.sleep(0.001)
    with turn_scope(turn):
        print(" ".join(d.outcome for d in queue.decide()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])))
