"""Small JSON state files with atomic replace, and a lock to share them between processes.

A write goes to a temp file in the same directory, is fsynced, then ``os.replace``d over the
target, so a crash leaves either the old or the new state and never a torn file. A file
that exists but doesn't parse raises :class:`~agent_guardrails.errors.StateCorrupt`: for
an approval queue, silently starting empty would drop requests; for a briefing ledger it
would re-surface every reminder as brand new.

Atomic replace keeps a file intact, not a read-modify-write: two workers that both read
before either writes will both act on the same state. :class:`FileLock` makes that a
critical section across processes.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Any

from .errors import StateCorrupt

if sys.platform == "win32":
    import msvcrt

    def _try_lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)      # raises OSError while another holds it

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _try_lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # raises OSError while another holds it

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class FileLock:
    """An exclusive lock on ``path`` shared by every process (and every ``FileLock`` object)
    that opens it. It is an OS lock (``flock`` / ``LockFileEx``) on its own open handle, so
    the OS releases it when a process dies and a crash never leaves a stale lock behind.
    Re-entrant for the thread that holds it; other threads and processes wait, up to
    ``timeout`` seconds, then get a :class:`TimeoutError`."""

    def __init__(self, path: str | os.PathLike[str], *, timeout: float = 30.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._owner = threading.RLock()
        self._depth = 0
        self._fd: int | None = None

    def __enter__(self) -> FileLock:
        if not self._owner.acquire(timeout=self.timeout):
            raise TimeoutError(f"timed out waiting for {self.path}")
        try:
            if self._depth == 0:
                self._fd = self._acquire()
            self._depth += 1
        except BaseException:
            self._owner.release()
            raise
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        try:
            self._depth -= 1
            if self._depth == 0 and self._fd is not None:
                fd, self._fd = self._fd, None
                try:
                    _unlock(fd)
                finally:
                    os.close(fd)
        finally:
            self._owner.release()

    def _acquire(self) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                try:
                    _try_lock(fd)
                    return fd
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out waiting for {self.path}") from None
                    time.sleep(0.005)
        except BaseException:
            os.close(fd)
            raise


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
