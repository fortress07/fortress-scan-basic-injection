from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, Optional, Tuple

from ...core.model import Category, Confidence, TraceStep

MAX_TRACE_STEPS = 12
MAX_TEXT_PARTS = 24


@dataclass(frozen=True)
class Taint:
    labels: FrozenSet[str] = frozenset()
    confidence: Confidence = Confidence.HIGH
    trace: Tuple[TraceStep, ...] = ()
    cleared: FrozenSet[Category] = frozenset()
    weakened: FrozenSet[Category] = frozenset()
    parameters: FrozenSet[str] = frozenset()
    low_signal: bool = False

    def active_for(self, category: Category) -> bool:
        return category not in self.cleared

    def weak_for(self, category: Category) -> bool:
        return category in self.weakened

    def with_step(self, step: TraceStep) -> "Taint":
        if len(self.trace) >= MAX_TRACE_STEPS:
            return self
        if self.trace and self.trace[-1].line == step.line and self.trace[-1].kind == step.kind:
            return self
        return replace(self, trace=self.trace + (step,))

    def cleared_for(self, categories: FrozenSet[Category]) -> Optional["Taint"]:
        return replace(self, cleared=self.cleared | categories)

    def fully_cleared(self) -> "Taint":
        return replace(self, cleared=frozenset(Category))

    @property
    def neutralized(self) -> bool:
        return len(self.cleared) >= len(Category)

    def weakened_for(self, categories: FrozenSet[Category]) -> "Taint":
        return replace(self, weakened=self.weakened | categories)

    def downgraded(self) -> "Taint":
        if self.confidence <= Confidence.LOW:
            return self
        return replace(self, confidence=Confidence(int(self.confidence) - 10))

    def describe(self) -> str:
        if not self.labels:
            return "untrusted input"
        return ", ".join(sorted(self.labels))


def merge_taint(left: Optional[Taint], right: Optional[Taint]) -> Optional[Taint]:
    if left is None:
        return right
    if right is None:
        return left
    trace = left.trace if len(left.trace) >= len(right.trace) else right.trace
    return Taint(
        labels=left.labels | right.labels,
        confidence=max(left.confidence, right.confidence),
        trace=trace[:MAX_TRACE_STEPS],
        cleared=left.cleared & right.cleared,
        weakened=left.weakened | right.weakened,
        parameters=left.parameters | right.parameters,
        low_signal=left.low_signal and right.low_signal,
    )


@dataclass(frozen=True)
class Value:
    taint: Optional[Taint] = None
    constant: bool = False
    text_parts: Tuple[str, ...] = ()
    elements: Tuple["Value", ...] = ()
    is_sequence: bool = False
    sanitized: bool = False

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)

    def tainted_for(self, category: Category) -> bool:
        return self.taint is not None and self.taint.active_for(category)

    def with_step(self, step: TraceStep) -> "Value":
        if self.taint is None:
            return self
        return replace(self, taint=self.taint.with_step(step))


UNKNOWN = Value()
CONSTANT = Value(constant=True)


def literal(text: str) -> Value:
    return Value(constant=True, text_parts=(text[:512],))


def combine(*values: Value) -> Value:
    taint: Optional[Taint] = None
    constant = True
    sanitized = False
    parts: Tuple[str, ...] = ()
    for value in values:
        taint = merge_taint(taint, value.taint)
        constant = constant and value.constant
        sanitized = sanitized or value.sanitized
        if len(parts) < MAX_TEXT_PARTS:
            parts = parts + value.text_parts[: MAX_TEXT_PARTS - len(parts)]
    return Value(
        taint=taint,
        constant=constant and bool(values),
        text_parts=parts,
        sanitized=sanitized,
    )


def merge_values(left: Value, right: Value) -> Value:
    return Value(
        taint=merge_taint(left.taint, right.taint),
        constant=left.constant and right.constant,
        text_parts=(left.text_parts + right.text_parts)[:MAX_TEXT_PARTS],
        elements=(),
        is_sequence=left.is_sequence and right.is_sequence,
        sanitized=left.sanitized or right.sanitized,
    )


Environment = Dict[str, Value]


def copy_environment(env: Environment) -> Environment:
    return dict(env)


def merge_environments(left: Environment, right: Environment) -> Environment:
    merged: Environment = {}
    for key in set(left) | set(right):
        left_value = left.get(key)
        right_value = right.get(key)
        if left_value is None:
            merged[key] = right_value if right_value is not None else UNKNOWN
        elif right_value is None:
            merged[key] = left_value
        else:
            merged[key] = merge_values(left_value, right_value)
    return merged


def environments_equal(left: Environment, right: Environment) -> bool:
    if set(left) != set(right):
        return False
    for key, value in left.items():
        other = right[key]
        left_taint = value.taint
        right_taint = other.taint
        if (left_taint is None) != (right_taint is None):
            return False
        if left_taint is not None and right_taint is not None:
            if left_taint.labels != right_taint.labels or left_taint.cleared != right_taint.cleared:
                return False
        if value.constant != other.constant:
            return False
    return True
