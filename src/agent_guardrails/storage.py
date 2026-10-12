"""Small JSON state files with atomic replace.

A write goes to a temp file in the same directory, is fsynced, then ``os.replace``d over the
target, so a crash leaves either the old or the new state and never a torn file. A file
that exists but doesn't parse raises :class:`~agent_guardrails.errors.StateCorrupt`: for
an approval queue, silently starting empty would drop requests; for a briefing ledger it
would re-surface every reminder as brand new.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import StateCorrupt


class JsonFile:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def read(self, default: Any) -> Any:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return copy.deepcopy(default)
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise StateCorrupt(f"{self.path} is not valid JSON: {exc}") from None

    def write(self, data: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp",
                                   dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
