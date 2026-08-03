from __future__ import annotations

import time
from dataclasses import dataclass


class BudgetExceeded(Exception):
    pass


class Budget:
    __slots__ = ("_remaining_units", "_deadline", "_checks")

    def __init__(self, units: int, seconds: float) -> None:
        self._remaining_units = max(1, units)
        self._deadline = time.monotonic() + max(0.05, seconds)
        self._checks = 0

    def spend(self, amount: int = 1) -> None:
        self._remaining_units -= amount
        if self._remaining_units <= 0:
            raise BudgetExceeded("đã dùng hết hạn mức phân tích cho tệp này")
        self._checks += 1
        if self._checks % 2048 == 0 and time.monotonic() > self._deadline:
            raise BudgetExceeded("đã hết thời gian phân tích cho tệp này")

    @property
    def exhausted(self) -> bool:
        return self._remaining_units <= 0 or time.monotonic() > self._deadline


@dataclass
class DepthGuard:
    limit: int
    depth: int = 0

    def __enter__(self) -> "DepthGuard":
        self.depth += 1
        if self.depth > self.limit:
            raise BudgetExceeded("vượt quá độ sâu lồng nhau cho phép")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.depth -= 1
