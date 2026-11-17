"""Tracks since when a keyed condition has been continuously true."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Hashable, Iterable


class SinceTracker:
    """Remembers when a condition became true.

    `grace` lets short gaps pass without resetting the start time. A crash-looping
    container is briefly Running between crashes, and that must not restart the
    clock for "has been crash looping for five minutes".
    """

    def __init__(self, grace: timedelta = timedelta(0)) -> None:
        self.grace = grace
        self._since: dict[Hashable, datetime] = {}
        self._last_true: dict[Hashable, datetime] = {}

    def update(self, key: Hashable, active: bool, now: datetime) -> datetime | None:
        """Record the current value and return the start time, or None.

        Within the grace period after the condition turned false, the old start
        time is still returned.
        """
        last = self._last_true.get(key)
        if active:
            if key not in self._since:
                self._since[key] = now
            self._last_true[key] = now
            return self._since[key]
        if last is not None and now - last > self.grace:
            self._since.pop(key, None)
            self._last_true.pop(key, None)
        return self._since.get(key)

    def since(self, key: Hashable) -> datetime | None:
        return self._since.get(key)

    def retain(self, keys: Iterable[Hashable]) -> None:
        keep = set(keys)
        for k in list(self._since):
            if k not in keep:
                self._since.pop(k, None)
                self._last_true.pop(k, None)
