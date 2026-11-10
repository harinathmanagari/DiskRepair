"""Progress / log / cancellation plumbing shared by long-running operations."""

import threading
import time


class Cancelled(Exception):
    pass


class Task:
    def __init__(self, on_progress=None, on_log=None):
        self._on_progress = on_progress
        self._on_log = on_log
        self._cancel = threading.Event()
        self._last = 0.0

    def cancel(self):
        self._cancel.set()

    @property
    def cancelled(self):
        return self._cancel.is_set()

    def check(self):
        if self._cancel.is_set():
            raise Cancelled()

    def progress(self, fraction, message="", force=False):
        """Report progress (rate limited). Also a cancellation point."""
        self.check()
        now = time.monotonic()
        if self._on_progress and (force or now - self._last >= 0.1):
            self._last = now
            self._on_progress(max(0.0, min(1.0, fraction)), message)

    def log(self, message):
        if self._on_log:
            self._on_log(message)


def human_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024


def human_time(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"
