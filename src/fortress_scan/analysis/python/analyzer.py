from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...core.model import Category, Confidence, Finding, StepKind
from ...languages import PYTHON
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from . import specs
from .imports import ImportResolver, attribute_parts, dotted_name
from .taint import (
    CONSTANT,
    MAX_ENTRIES,
    UNKNOWN,
    CallableRef,
    Environment,
    Taint,
    Value,
    combine,
    copy_environment,
    environments_equal,
    limit_callables,
    literal,
    merge_environments,
    merge_taint,
    merge_values,
    ordered_callables,
    union_callables,
)

SUMMARY_MODE = "summary"
REPORT_MODE = "report"

_MAX_SUMMARY_ROUNDS = 4
_MAX_LOOP_ITERATIONS = 2
_MAX_BLOCK_DEPTH = 48
_SELF_NAMES = frozenset({"self", "cls", "mcs"})


class UnparsableSource(Exception):
    pass


@dataclass(frozen=True)
class SinkHit:
    parameter: str
    rule_id: str
    category: Category
    line: int
    column: int
    symbol: str
    description: str


@dataclass(frozen=True)
class ReturnEffect:
    cleared: FrozenSet[Category] = frozenset()
    sanitized: bool = False

    def merged(self, other: "ReturnEffect") -> "ReturnEffect":
        return ReturnEffect(
            cleared=self.cleared & other.cleared,
            sanitized=self.sanitized and other.sanitized,
        )


@dataclass
class Summary:
    returns: Dict[str, ReturnEffect] = field(default_factory=dict)
    sinks: FrozenSet[SinkHit] = frozenset()


@dataclass
class FunctionInfo:
    node: ast.AST
    qualname: str
    simple_name: str
    parameters: Tuple[str, ...]
    handler_sources: Dict[str, specs.SourceSpec] = field(default_factory=dict)


class PythonAnalyzer(Analyzer):
    name = "python-taint"
    languages = (PYTHON,)

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        try:
            tree = ast.parse(unit.source, filename=unit.relative_path)
        except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
            raise UnparsableSource(str(exc)) from exc
        module = ModuleAnalysis(unit, budget)
        return module.run(tree)


class ModuleAnalysis:
    def __init__(self, unit: AnalysisUnit, budget: Budget) -> None:
        self.unit = unit
        self.budget = budget
        self.builder = FindingBuilder(unit)
        self.imports = ImportResolver()
        self.functions: Dict[str, FunctionInfo] = {}
        self.functions_by_name: Dict[str, List[FunctionInfo]] = {}
        self.summaries: Dict[str, Summary] = {}
        self._name_values: Dict[str, Value] = {}
        self._attribute_refs: Dict[Tuple[str, str], FrozenSet[CallableRef]] = {}

    def name_value(self, qualname: str) -> Value:
        """Bare names repeat constantly; hand out one shared immutable value."""
        value = self._name_values.get(qualname)
        if value is None:
            value = Value(callables=frozenset({CallableRef(qualname=qualname)}))
            self._name_values[qualname] = value
        return value

    def attribute_refs(self, dotted: str, attribute: str) -> FrozenSet[CallableRef]:
        cached = self._attribute_refs.get((dotted, attribute))
        if cached is None:
            receiver = dotted[: len(dotted) - len(attribute) - 1]
            cached = frozenset(
                {
                    CallableRef(
                        qualname=self.imports.resolve(dotted),
                        attribute=attribute,
                        receiver=receiver or None,
                    )
                }
            )
            self._attribute_refs[(dotted, attribute)] = cached
        return cached

    def run(self, tree: ast.Module) -> List[Finding]:
        self.imports.collect(tree)
        self._collect_functions(tree)
        try:
            globals_env = self._collect_globals(tree)
            self._compute_summaries(globals_env)
            self._report(tree, globals_env)
        except BudgetExceeded:
            pass
        except RecursionError:
            pass
        return self.builder.findings

    def _collect_functions(self, tree: ast.Module) -> None:
        stack: List[Tuple[ast.AST, str]] = [(tree, "")]
        while stack:
            node, prefix = stack.pop()
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = "%s.%s" % (prefix, child.name) if prefix else child.name
                    info = FunctionInfo(
                        node=child,
                        qualname=qualname,
                        simple_name=child.name,
                        parameters=_parameter_names(child.args),
                        handler_sources=_handler_sources(child, self.imports),
                    )
                    self.functions[qualname] = info
                    self.functions_by_name.setdefault(child.name, []).append(info)
                    self.summaries[qualname] = Summary()
                    stack.append((child, qualname))
                elif isinstance(child, ast.ClassDef):
                    qualname = "%s.%s" % (prefix, child.name) if prefix else child.name
                    stack.append((child, qualname))

    def _collect_globals(self, tree: ast.Module) -> Environment:
        evaluator = Evaluator(self, None, SUMMARY_MODE, {})
        return evaluator.execute_module(tree)

    def _compute_summaries(self, globals_env: Environment) -> None:
        for _ in range(_MAX_SUMMARY_ROUNDS):
            changed = False
            for qualname, info in self.functions.items():
                evaluator = Evaluator(self, info, SUMMARY_MODE, globals_env)
                evaluator.execute_function(synthetic=True)
                summary = Summary(
                    returns=dict(evaluator.returned_parameters),
                    sinks=frozenset(evaluator.recorded_sinks),
                )
                if summary != self.summaries.get(qualname):
                    self.summaries[qualname] = summary
                    changed = True
            if not changed:
                return

    def _report(self, tree: ast.Module, globals_env: Environment) -> None:
        evaluator = Evaluator(self, None, REPORT_MODE, {})
        evaluator.execute_module(tree)
        for info in self.functions.values():
            worker = Evaluator(self, info, REPORT_MODE, globals_env)
            worker.execute_function(synthetic=False)

    def lookup_function(self, qualname: Optional[str]) -> Optional[FunctionInfo]:
        if not qualname:
            return None
        info = self.functions.get(qualname)
        if info is not None:
            return info
        simple = qualname.rsplit(".", 1)[-1]
        candidates = self.functions_by_name.get(simple)
        if candidates and len(candidates) == 1:
            return candidates[0]
        return None


class Evaluator:
    def __init__(
        self,
        module: ModuleAnalysis,
        function: Optional[FunctionInfo],
        mode: str,
        globals_env: Environment,
    ) -> None:
        self.module = module
        self.function = function
        self.mode = mode
        self.globals_env = globals_env
        self.returned_parameters: Dict[str, ReturnEffect] = {}
        self.recorded_sinks: Set[SinkHit] = set()
        self._depth = 0

    @property
    def builder(self) -> FindingBuilder:
        return self.module.builder

    @property
    def imports(self) -> ImportResolver:
        return self.module.imports

    def execute_module(self, tree: ast.Module) -> Environment:
        env: Environment = {}
        self._execute_block(tree.body, env)
        return env

    def execute_function(self, synthetic: bool) -> None:
        info = self.function
        if info is None:
            return
        node = info.node
        env: Environment = copy_environment(self.globals_env)
        for name in info.parameters:
            if name in _SELF_NAMES:
                continue
            if synthetic:
                env[name] = Value(
                    taint=Taint(
                        labels=frozenset({"parameter %s" % name}),
                        confidence=Confidence.HIGH,
                        parameters=frozenset({name}),
                        trace=(),
                    )
                )
            else:
                source = info.handler_sources.get(name)
                if source is None:
                    env[name] = UNKNOWN
                    continue
                step = self.builder.step(
                    StepKind.SOURCE,
                    getattr(node, "lineno", 1),
                    getattr(node, "col_offset", 0),
                    "%s đi vào qua tham số %s" % (source.label, name),
                )
                env[name] = Value(
                    taint=Taint(
                        labels=frozenset({source.label}),
                        confidence=source.confidence,
                        trace=(step,),
                        low_signal=source.low_signal,
                    )
                )
        self._execute_block(getattr(node, "body", []), env)

    def _execute_block(self, statements: Sequence[ast.stmt], env: Environment) -> Environment:
        if self._depth > _MAX_BLOCK_DEPTH:
            return env
        self._depth += 1
        try:
            for statement in statements:
                self.module.budget.spend()
                env = self._execute(statement, env)
        finally:
            self._depth -= 1
        return env

    def _execute(self, node: ast.stmt, env: Environment) -> Environment:
        if isinstance(node, ast.Assign):
            value = self._eval(node.value, env)
            for target in node.targets:
                self._bind(target, value, env)
            return env
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._bind(node.target, self._eval(node.value, env), env)
            return env
        if isinstance(node, ast.AugAssign):
            addition = self._eval(node.value, env)
            existing = self._eval(node.target, env)
            self._bind(node.target, merge_values(existing, addition), env)
            return env
        if isinstance(node, ast.Expr):
            self._eval(node.value, env)
            return env
        if isinstance(node, ast.Return):
            if node.value is not None:
                self._record_return(self._eval(node.value, env))
            return env
        if isinstance(node, ast.If):
            return self._execute_if(node, env)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            return self._execute_loop_for(node, env)
        if isinstance(node, ast.While):
            return self._execute_loop_while(node, env)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self._eval(item.context_expr, env)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, value, env)
            return self._execute_block(node.body, env)
        if isinstance(node, ast.Try):
            return self._execute_try(node, env)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in getattr(node, "decorator_list", []):
                self._eval(decorator, env)
            return env
        if isinstance(node, ast.Raise):
            for child in (node.exc, node.cause):
                if child is not None:
                    self._eval(child, env)
            return env
        if isinstance(node, ast.Assert):
            self._eval(node.test, env)
            if node.msg is not None:
                self._eval(node.msg, env)
            return env
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
            return env
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.Pass)):
            return env
        if isinstance(node, (ast.Break, ast.Continue)):
            return env
        match_node = getattr(ast, "Match", None)
        if match_node is not None and isinstance(node, match_node):
            return self._execute_match(node, env)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._eval(child, env)
        return env

    def _execute_if(self, node: ast.If, env: Environment) -> Environment:
        self._eval(node.test, env)
        positive, negative = _guarded_names(node.test)
        true_env = copy_environment(env)
        false_env = copy_environment(env)
        _apply_guards(true_env, positive)
        _apply_guards(false_env, negative)
        true_env = self._execute_block(node.body, true_env)
        false_env = self._execute_block(node.orelse, false_env)
        if _terminates(node.body):
            return false_env
        if node.orelse and _terminates(node.orelse):
            return true_env
        return merge_environments(true_env, false_env)

    def _execute_loop_for(self, node: ast.stmt, env: Environment) -> Environment:
        iterable = self._eval(node.iter, env)
        element = Value(taint=iterable.taint, constant=iterable.constant)
        self._bind(node.target, element, env)
        current = env
        for _ in range(_MAX_LOOP_ITERATIONS):
            candidate = self._execute_block(node.body, copy_environment(current))
            merged = merge_environments(current, candidate)
            if environments_equal(merged, current):
                current = merged
                break
            current = merged
        current = self._execute_block(node.orelse, current)
        return current

    def _execute_loop_while(self, node: ast.While, env: Environment) -> Environment:
        self._eval(node.test, env)
        current = env
        for _ in range(_MAX_LOOP_ITERATIONS):
            candidate = self._execute_block(node.body, copy_environment(current))
            merged = merge_environments(current, candidate)
            if environments_equal(merged, current):
                current = merged
                break
            current = merged
        return self._execute_block(node.orelse, current)

    def _execute_try(self, node: ast.Try, env: Environment) -> Environment:
        body_env = self._execute_block(node.body, copy_environment(env))
        merged = body_env
        for handler in node.handlers:
            handler_env = copy_environment(env)
            if handler.name:
                handler_env[handler.name] = UNKNOWN
            merged = merge_environments(merged, self._execute_block(handler.body, handler_env))
        merged = self._execute_block(node.orelse, merged)
        return self._execute_block(node.finalbody, merged)

    def _execute_match(self, node: ast.stmt, env: Environment) -> Environment:
        subject = self._eval(node.subject, env)
        merged: Optional[Environment] = None
        for case in node.cases:
            case_env = copy_environment(env)
            for name in _match_capture_names(case.pattern):
                case_env[name] = Value(taint=subject.taint, constant=subject.constant)
            if case.guard is not None:
                self._eval(case.guard, case_env)
            case_env = self._execute_block(case.body, case_env)
            merged = case_env if merged is None else merge_environments(merged, case_env)
        return merged if merged is not None else env

    def _bind(self, target: ast.expr, value: Value, env: Environment) -> None:
        if isinstance(target, ast.Name):
            if value.taint is not None:
                step = self.builder.step(
                    StepKind.PROPAGATION,
                    target.lineno,
                    target.col_offset,
                    "chảy vào biến %s" % target.id,
                )
                value = value.with_step(step)
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            elements = value.elements
            for index, item in enumerate(target.elts):
                if isinstance(item, ast.Starred):
                    self._bind(item.value, value, env)
                elif index < len(elements):
                    self._bind(item, elements[index], env)
                else:
                    self._bind(item, Value(taint=value.taint, constant=value.constant), env)
            return
        if isinstance(target, ast.Attribute):
            dotted = dotted_name(target)
            if dotted:
                env[dotted] = value
            return
        if isinstance(target, ast.Subscript):
            base = target.value
            if isinstance(base, ast.Name):
                existing = env.get(base.id, UNKNOWN)
                env[base.id] = merge_values(existing, value)
            return
        if isinstance(target, ast.Starred):
            self._bind(target.value, value, env)

    def _eval(self, node: Optional[ast.expr], env: Environment) -> Value:
        if node is None:
            return CONSTANT
        self.module.budget.spend()

        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return literal(node.value)
            if isinstance(node.value, bytes):
                return literal(node.value.decode("utf-8", errors="replace"))
            return CONSTANT
        if isinstance(node, ast.Name):
            return self._eval_name(node, env)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(node, env)
        if isinstance(node, ast.Call):
            return self._eval_call(node, env)
        if isinstance(node, ast.JoinedStr):
            parts = [self._eval(value, env) for value in node.values]
            return combine(*parts) if parts else CONSTANT
        if isinstance(node, ast.FormattedValue):
            value = self._eval(node.value, env)
            return Value(taint=value.taint, constant=value.constant, text_parts=value.text_parts)
        if isinstance(node, ast.BinOp):
            left = self._eval(node.left, env)
            right = self._eval(node.right, env)
            return combine(left, right)
        if isinstance(node, ast.BoolOp):
            values = [self._eval(item, env) for item in node.values]
            return combine(*values) if values else CONSTANT
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, env)
        if isinstance(node, ast.Compare):
            self._eval(node.left, env)
            for comparator in node.comparators:
                self._eval(comparator, env)
            return CONSTANT
        if isinstance(node, ast.IfExp):
            self._eval(node.test, env)
            return merge_values(self._eval(node.body, env), self._eval(node.orelse, env))
        if isinstance(node, ast.Subscript):
            return self._eval_subscript(node, env)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            elements = tuple(self._eval(item, env) for item in node.elts)
            aggregate = combine(*elements) if elements else CONSTANT
            return Value(
                taint=aggregate.taint,
                constant=aggregate.constant,
                text_parts=aggregate.text_parts,
                elements=elements,
                is_sequence=True,
                sanitized=aggregate.sanitized,
                callables=union_callables(elements),
            )
        if isinstance(node, ast.Dict):
            return self._eval_dict(node, env)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._eval_comprehension(node, env, (node.elt,))
        if isinstance(node, ast.DictComp):
            return self._eval_comprehension(node, env, (node.key, node.value))
        if isinstance(node, ast.Starred):
            return self._eval(node.value, env)
        if isinstance(node, ast.Await):
            return self._eval(node.value, env)
        if isinstance(node, ast.NamedExpr):
            value = self._eval(node.value, env)
            self._bind(node.target, value, env)
            return value
        if isinstance(node, ast.Lambda):
            return UNKNOWN
        if isinstance(node, ast.Slice):
            for part in (node.lower, node.upper, node.step):
                self._eval(part, env)
            return CONSTANT
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._eval(child, env)
        return UNKNOWN

    def _eval_name(self, node: ast.Name, env: Environment) -> Value:
        if node.id in env:
            return env[node.id]
        resolved = self.imports.resolve(node.id)
        source = specs.SOURCE_ATTRIBUTES.get(resolved)
        if source is not None and self._source_enabled(source):
            return self._tainted(node, source)
        if node.id.isupper() and len(node.id) > 1:
            return CONSTANT
        return self.module.name_value(resolved)

    def _eval_attribute(self, node: ast.Attribute, env: Environment) -> Value:
        dotted = dotted_name(node)
        if dotted is not None:
            if dotted in env:
                return env[dotted]
            resolved = self.imports.resolve(dotted)
            source = specs.SOURCE_ATTRIBUTES.get(resolved)
            if source is not None and self._source_enabled(source):
                return self._tainted(node, source)
            request_source = self._request_member_source(resolved, node.attr)
            if request_source is not None:
                return self._tainted(node, request_source)
        base = self._eval(node.value, env)
        callables: FrozenSet[CallableRef] = frozenset()
        if dotted is not None:
            callables = self.module.attribute_refs(dotted, node.attr)
        return Value(
            taint=base.taint,
            constant=base.constant,
            text_parts=base.text_parts,
            sanitized=base.sanitized,
            callables=callables,
        )

    def _eval_subscript(self, node: ast.Subscript, env: Environment) -> Value:
        base = self._eval(node.value, env)
        self._eval(node.slice, env)
        return Value(
            taint=base.taint,
            constant=base.constant,
            text_parts=base.text_parts,
            sanitized=base.sanitized,
            callables=_indexed_callables(base, node.slice),
        )

    def _eval_dict(self, node: ast.Dict, env: Environment) -> Value:
        values: List[Value] = []
        entries: List[Tuple[str, FrozenSet[CallableRef]]] = []
        for key, item in zip(node.keys, node.values):
            key_value = self._eval(key, env) if key is not None else CONSTANT
            item_value = self._eval(item, env)
            values.append(key_value)
            values.append(item_value)
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                entries.append((key.value, item_value.callables))
                if key.value in specs.NOSQL_OPERATOR_KEYS and item_value.taint is not None:
                    self._flag(
                        rule_id="FSB-NOSQL-001",
                        dynamic_rule=None,
                        node=key,
                        category=Category.NOSQL,
                        symbol=key.value,
                        description="toán tử NoSQL %s" % key.value,
                        value=item_value,
                    )
        aggregate = combine(*values) if values else CONSTANT
        return Value(
            taint=aggregate.taint,
            constant=aggregate.constant,
            sanitized=aggregate.sanitized,
            callables=union_callables(values),
            # A partial key map would read as "key absent" and hide a sink, so
            # an oversized literal keeps only the union.
            entries=tuple(entries) if len(entries) <= MAX_ENTRIES else (),
        )

    def _eval_comprehension(
        self, node: ast.expr, env: Environment, outputs: Sequence[ast.expr]
    ) -> Value:
        scope = copy_environment(env)
        for generator in node.generators:
            iterable = self._eval(generator.iter, scope)
            self._bind(
                generator.target, Value(taint=iterable.taint, constant=iterable.constant), scope
            )
            for condition in generator.ifs:
                self._eval(condition, scope)
                positive, _ = _guarded_names(condition)
                _apply_guards(scope, positive)
        parts = [self._eval(output, scope) for output in outputs]
        aggregate = combine(*parts) if parts else CONSTANT
        return Value(
            taint=aggregate.taint,
            constant=aggregate.constant,
            text_parts=aggregate.text_parts,
            is_sequence=True,
            sanitized=aggregate.sanitized,
        )

    def _eval_call(self, node: ast.Call, env: Environment) -> Value:
        qualname = self.imports.qualname_of(node.func)
        argument_values = [self._eval(argument, env) for argument in node.args]
        keyword_values = {
            keyword.arg: self._eval(keyword.value, env)
            for keyword in node.keywords
            if keyword.arg is not None
        }
        for keyword in node.keywords:
            if keyword.arg is None:
                self._eval(keyword.value, env)

        receiver = UNKNOWN
        callee = UNKNOWN
        if isinstance(node.func, ast.Attribute):
            receiver = self._eval(node.func.value, env)
            dotted = dotted_name(node.func)
            if dotted is not None:
                callee = env.get(dotted, UNKNOWN)
        elif isinstance(node.func, ast.Name):
            callee = env.get(node.func.id, UNKNOWN)
        elif isinstance(node.func, (ast.Call, ast.Subscript, ast.IfExp)):
            callee = self._eval(node.func, env)

        targets = _call_targets(node, qualname, callee)
        effective = targets[0].qualname if targets else None

        self._check_sink(node, targets, argument_values, keyword_values)

        if effective is not None:
            if effective in specs.TRUSTED_PRODUCERS:
                return Value(constant=False, sanitized=True)
            cleared = specs.SANITIZERS.get(effective)
            if cleared is not None:
                return self._sanitized(argument_values, keyword_values, cleared)
            weakened = specs.WEAK_SANITIZERS.get(effective)
            if weakened is not None:
                aggregate = combine(*argument_values) if argument_values else UNKNOWN
                if aggregate.taint is None:
                    return Value(constant=False, sanitized=True)
                return Value(
                    taint=aggregate.taint.weakened_for(weakened), constant=False, sanitized=True
                )
            source = specs.SOURCE_CALLS.get(effective)
            if source is not None and self._source_enabled(source):
                return self._tainted(node, source)

        if isinstance(node.func, ast.Attribute):
            method_source = specs.REQUEST_METHODS.get(node.func.attr)
            if method_source is not None and self._is_request_receiver(node.func.value):
                return self._tainted(node, method_source)
            handler_source = specs.HANDLER_METHODS.get(node.func.attr)
            if handler_source is not None and _is_self_reference(node.func.value):
                return self._tainted(node, handler_source)

        local = self.module.lookup_function(effective)
        if local is not None and local.node is not getattr(self.function, "node", None):
            return self._apply_summary(local, node, argument_values, keyword_values)

        if effective is not None and effective in specs.PROPAGATING_CALLS:
            return combine(*argument_values) if argument_values else UNKNOWN

        if isinstance(node.func, ast.Attribute) and node.func.attr in specs.PROPAGATING_METHODS:
            parts = [receiver] + argument_values
            aggregate = combine(*parts)
            return Value(
                taint=aggregate.taint,
                constant=aggregate.constant,
                text_parts=aggregate.text_parts,
                sanitized=aggregate.sanitized,
            )

        inputs = argument_values + list(keyword_values.values())
        if isinstance(node.func, ast.Attribute):
            inputs.append(receiver)
        aggregate_taint: Optional[Taint] = None
        sanitized = False
        for item in inputs:
            aggregate_taint = merge_taint(aggregate_taint, item.taint)
            sanitized = sanitized or item.sanitized
        # Naming a callable must not disturb the data the call carries, so the
        # reflected name rides along on the value the fallthrough already built.
        produced = (
            _reflected_callables(node, self.imports) if effective == "getattr" else frozenset()
        )
        if aggregate_taint is None:
            return Value(constant=False, sanitized=sanitized, callables=produced)
        return Value(
            taint=aggregate_taint.downgraded(),
            constant=False,
            sanitized=sanitized,
            callables=produced,
        )

    def _sanitized(
        self,
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
        cleared: FrozenSet[Category],
    ) -> Value:
        aggregate = combine(*argument_values) if argument_values else CONSTANT
        if aggregate.taint is None:
            return Value(
                constant=aggregate.constant, text_parts=aggregate.text_parts, sanitized=True
            )
        remaining = aggregate.taint.cleared_for(cleared)
        return Value(
            taint=remaining,
            constant=aggregate.constant,
            text_parts=aggregate.text_parts,
            sanitized=True,
        )

    def _apply_summary(
        self,
        callee: FunctionInfo,
        node: ast.Call,
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
    ) -> Value:
        summary = self.module.summaries.get(callee.qualname, Summary())
        bindings = _bind_arguments(callee.parameters, argument_values, keyword_values)
        result_taint: Optional[Taint] = None
        sanitized = False
        for parameter, value in bindings.items():
            if value.taint is None:
                continue
            for hit in summary.sinks:
                if hit.parameter != parameter:
                    continue
                self._emit_summary_hit(hit, node, value, callee)
            effect = summary.returns.get(parameter)
            if effect is None:
                continue
            sanitized = sanitized or effect.sanitized or bool(effect.cleared)
            result_taint = merge_taint(result_taint, value.taint.cleared_for(effect.cleared))
        if result_taint is None:
            return Value(constant=False, sanitized=sanitized)
        step = self.builder.step(
            StepKind.CALL,
            node.lineno,
            node.col_offset,
            "giá trị trả về từ %s()" % callee.simple_name,
        )
        return Value(taint=result_taint.with_step(step), constant=False, sanitized=sanitized)

    def _record_return(self, value: Value) -> None:
        taint = value.taint
        if taint is None or not taint.parameters:
            return
        effect = ReturnEffect(cleared=taint.cleared, sanitized=value.sanitized)
        for parameter in taint.parameters:
            existing = self.returned_parameters.get(parameter)
            self.returned_parameters[parameter] = (
                effect if existing is None else existing.merged(effect)
            )

    def _emit_summary_hit(
        self, hit: SinkHit, node: ast.Call, value: Value, callee: FunctionInfo
    ) -> None:
        taint = value.taint
        if taint is None or not taint.active_for(hit.category):
            return
        call_step = self.builder.step(
            StepKind.CALL,
            node.lineno,
            node.col_offset,
            "được truyền vào %s() ở tham số %s" % (callee.simple_name, hit.parameter),
        )
        if self.mode == SUMMARY_MODE:
            for parameter in taint.parameters:
                self.recorded_sinks.add(
                    SinkHit(
                        parameter=parameter,
                        rule_id=hit.rule_id,
                        category=hit.category,
                        line=hit.line,
                        column=hit.column,
                        symbol=hit.symbol,
                        description=hit.description,
                    )
                )
            return
        if taint.parameters:
            return
        sink_step = self.builder.step(
            StepKind.SINK, hit.line, hit.column, "chạy tới %s" % hit.description
        )
        self.builder.add(
            rule_id=hit.rule_id,
            line=hit.line,
            column=hit.column,
            symbol=hit.symbol,
            message="%s đi qua %s() rồi vào %s"
            % (taint.describe(), callee.simple_name, hit.description),
            confidence=_confidence_for(taint),
            trace=tuple(taint.trace) + (call_step, sink_step),
            tags=("interprocedural",),
        )

    def _check_sink(
        self,
        node: ast.Call,
        targets: Sequence[CallableRef],
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
    ) -> None:
        for target in targets:
            self._check_sink_target(node, target, argument_values, keyword_values)

    def _check_sink_target(
        self,
        node: ast.Call,
        target: CallableRef,
        argument_values: Sequence[Value],
        keyword_values: Dict[str, Value],
    ) -> None:
        if target.qualname in self.module.functions:
            return
        spec = specs.SINKS.get(target.qualname)
        if spec is None and target.attribute is not None:
            candidate = specs.METHOD_SINKS.get(target.attribute)
            if candidate is not None and self._method_sink_applies(
                candidate, target, argument_values
            ):
                spec = candidate
        if spec is None:
            return

        condition = spec.condition
        if condition == specs.YAML_LOAD and self._yaml_is_safe(node, keyword_values):
            return
        if condition == specs.NUMPY_LOAD and not _keyword_is_true(node, "allow_pickle"):
            return
        if condition == specs.TORCH_LOAD and not _keyword_is_false(node, "weights_only"):
            return
        if condition == specs.XML_PARSER:
            self._check_xml_parser(node)
            return

        if condition in (specs.SHELL_KWARG, specs.ARGV):
            shell_enabled = _keyword_is_true(node, "shell")
            if condition == specs.ARGV or not shell_enabled:
                self._check_program_argument(node, spec, argument_values)
                return

        positions = spec.positions or (0,)
        for index in positions:
            if index < len(argument_values):
                self._evaluate_sink_argument(
                    node, spec, argument_values[index], node.args[index]
                )
        for keyword in spec.keywords:
            if keyword in keyword_values:
                self._evaluate_sink_argument(node, spec, keyword_values[keyword], node)

    def _evaluate_sink_argument(
        self, node: ast.Call, spec: specs.SinkSpec, value: Value, argument_node: ast.AST
    ) -> None:
        if spec.condition == specs.SQL_TEXT and value.constant:
            return
        self._flag(
            rule_id=spec.tainted_rule,
            dynamic_rule=spec.dynamic_rule if spec.condition != specs.TAINT_ONLY else None,
            node=node,
            category=spec.category,
            symbol=spec.qualname,
            description=spec.description,
            value=value,
        )

    def _check_program_argument(
        self, node: ast.Call, spec: specs.SinkSpec, argument_values: Sequence[Value]
    ) -> None:
        if not argument_values:
            return
        target = argument_values[0]
        if target.is_sequence:
            if not target.elements:
                return
            wrapped = _shell_wrapper_element(target.elements)
            if wrapped is not None:
                self._flag(
                    rule_id="FSB-CMD-001",
                    dynamic_rule="FSB-CMD-003",
                    node=node,
                    category=Category.COMMAND,
                    symbol=spec.qualname,
                    description="một lệnh shell truyền qua cờ thông dịch",
                    value=wrapped,
                )
                return
            target = target.elements[0]
        self._flag(
            rule_id="FSB-CMD-002",
            dynamic_rule=None,
            node=node,
            category=Category.COMMAND,
            symbol=spec.qualname,
            description="chương trình được chạy trong %s" % spec.description,
            value=target,
        )

    def _flag(
        self,
        rule_id: str,
        dynamic_rule: Optional[str],
        node: ast.AST,
        category: Category,
        symbol: str,
        description: str,
        value: Value,
    ) -> None:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0)
        taint = value.taint
        if taint is not None and taint.active_for(category):
            if self.mode == SUMMARY_MODE:
                for parameter in taint.parameters:
                    self.recorded_sinks.add(
                        SinkHit(
                            parameter=parameter,
                            rule_id=rule_id,
                            category=category,
                            line=line,
                            column=column,
                            symbol=symbol,
                            description=description,
                        )
                    )
                return
            if taint.parameters:
                return
            step = self.builder.step(
                StepKind.SINK, line, column, "chạy tới %s" % description
            )
            confidence = _confidence_for(taint)
            if taint.weak_for(category):
                confidence = Confidence(max(int(Confidence.LOW), int(confidence) - 10))
            self.builder.add(
                rule_id=rule_id,
                line=line,
                column=column,
                symbol=symbol,
                message="%s chạy tới %s mà chưa được vô hiệu hóa" % (taint.describe(), description),
                end_line=getattr(node, "end_lineno", None),
                end_column=getattr(node, "end_col_offset", None),
                confidence=confidence,
                trace=tuple(taint.trace) + (step,),
            )
            return
        if self.mode != REPORT_MODE or dynamic_rule is None:
            return
        if value.constant or value.sanitized:
            return
        self.builder.add(
            rule_id=dynamic_rule,
            line=line,
            column=column,
            symbol=symbol,
            message="%s nhận một giá trị không phải hằng" % description,
            end_line=getattr(node, "end_lineno", None),
            end_column=getattr(node, "end_col_offset", None),
            trace=(self.builder.step(StepKind.SINK, line, column, description),),
        )

    def _method_sink_applies(
        self, spec: specs.SinkSpec, target: CallableRef, argument_values: Sequence[Value]
    ) -> bool:
        if spec.category is not Category.SQL:
            return True
        if _receiver_matches(target.receiver, specs.SQL_METHOD_RECEIVER_HINTS):
            return True
        for value in argument_values[:1]:
            if specs.SQL_STATEMENT.search(value.text):
                return True
        return False

    def _yaml_is_safe(self, node: ast.Call, keyword_values: Dict[str, Value]) -> bool:
        loader_node: Optional[ast.AST] = None
        for keyword in node.keywords:
            if keyword.arg == "Loader":
                loader_node = keyword.value
        if loader_node is None and len(node.args) > 1:
            loader_node = node.args[1]
        if loader_node is None:
            return False
        dotted = dotted_name(loader_node)
        if dotted is None:
            return False
        return dotted.rsplit(".", 1)[-1] in specs.SAFE_YAML_LOADERS

    def _check_xml_parser(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            expected = specs.XML_UNSAFE_KEYWORDS.get(keyword.arg or "")
            if expected is None:
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is expected:
                self.builder.add(
                    rule_id="FSB-XML-001",
                    line=node.lineno,
                    column=node.col_offset,
                    symbol="XMLParser",
                    message="parser XML được cấu hình %s=%r" % (keyword.arg, expected),
                )
                return

    def _request_member_source(
        self, resolved: str, attribute: str
    ) -> Optional[specs.SourceSpec]:
        source = specs.REQUEST_MEMBERS.get(attribute)
        if source is None:
            return None
        prefix = resolved.rsplit(".", 1)[0] if "." in resolved else ""
        if not prefix:
            return None
        tail = prefix.rsplit(".", 1)[-1].lower()
        if prefix in specs.REQUEST_RECEIVER_NAMES or tail in ("request", "req"):
            return source
        return None

    def _is_request_receiver(self, node: ast.AST) -> bool:
        parts = attribute_parts(node)
        if not parts:
            return False
        return parts[-1].lower() in ("request", "req", "handler")

    def _source_enabled(self, source: specs.SourceSpec) -> bool:
        if source.low_signal and not self.module.unit.config.include_low_signal_sources:
            return False
        return True

    def _tainted(self, node: ast.AST, source: specs.SourceSpec) -> Value:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0)
        step = self.builder.step(
            StepKind.SOURCE, line, column, "%s đi vào từ đây" % source.label
        )
        return Value(
            taint=Taint(
                labels=frozenset({source.label}),
                confidence=source.confidence,
                trace=(step,),
                low_signal=source.low_signal,
            ),
            constant=False,
        )


def _confidence_for(taint: Taint) -> Confidence:
    return taint.confidence


def _parameter_names(arguments: ast.arguments) -> Tuple[str, ...]:
    names: List[str] = []
    for argument in getattr(arguments, "posonlyargs", []) or []:
        names.append(argument.arg)
    for argument in arguments.args:
        names.append(argument.arg)
    if arguments.vararg is not None:
        names.append(arguments.vararg.arg)
    for argument in arguments.kwonlyargs:
        names.append(argument.arg)
    if arguments.kwarg is not None:
        names.append(arguments.kwarg.arg)
    return tuple(names)


def _bind_arguments(
    parameters: Sequence[str],
    argument_values: Sequence[Value],
    keyword_values: Dict[str, Value],
) -> Dict[str, Value]:
    positional = [name for name in parameters if name not in _SELF_NAMES]
    bindings: Dict[str, Value] = {}
    for index, value in enumerate(argument_values):
        if index < len(positional):
            bindings[positional[index]] = value
    for name, value in keyword_values.items():
        if name in parameters:
            bindings[name] = value
    return bindings


def _handler_sources(node: ast.AST, imports: ImportResolver) -> Dict[str, specs.SourceSpec]:
    sources: Dict[str, specs.SourceSpec] = {}
    arguments = node.args
    defaults = list(arguments.defaults) + list(arguments.kw_defaults or [])
    named = list(getattr(arguments, "posonlyargs", []) or []) + list(arguments.args)
    named += list(arguments.kwonlyargs)

    for default in defaults:
        if not isinstance(default, ast.Call):
            continue
        qualname = imports.qualname_of(default.func)
        source = specs.SOURCE_CALLS.get(qualname or "")
        if source is None:
            continue
        offset = len(arguments.args) - len(arguments.defaults)
        for index, default_node in enumerate(arguments.defaults):
            if default_node is default and 0 <= offset + index < len(arguments.args):
                sources[arguments.args[offset + index].arg] = source
        for index, default_node in enumerate(arguments.kw_defaults or []):
            if default_node is default and index < len(arguments.kwonlyargs):
                sources[arguments.kwonlyargs[index].arg] = source

    if _is_route_handler(node, imports):
        request_source = specs.SourceSpec("tham số của request HTTP", Confidence.HIGH)
        for argument in named:
            if argument.arg in _SELF_NAMES:
                continue
            sources.setdefault(argument.arg, request_source)
    elif node.name in specs.HANDLER_FUNCTION_NAMES:
        event_source = specs.SourceSpec("dữ liệu sự kiện", Confidence.MEDIUM)
        for argument in named:
            if argument.arg in specs.HANDLER_PARAMETER_NAMES:
                sources.setdefault(argument.arg, event_source)
    return sources


def _is_route_handler(node: ast.AST, imports: ImportResolver) -> bool:
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not isinstance(target, ast.Attribute):
            continue
        if target.attr not in specs.ROUTE_DECORATOR_ATTRIBUTES:
            continue
        parts = attribute_parts(target)
        if len(parts) < 2:
            continue
        receiver = parts[-2].lower()
        if receiver in specs.ROUTE_DECORATOR_RECEIVERS:
            return True
        resolved = imports.resolve(".".join(parts))
        if resolved.startswith(("flask", "fastapi", "starlette", "sanic", "quart", "bottle")):
            return True
    return False


def _keyword_is_true(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name:
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False


def _keyword_is_false(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name:
            return not (isinstance(keyword.value, ast.Constant) and keyword.value.value is True)
    return True


def _receiver_matches(receiver: Optional[str], hints: FrozenSet[str]) -> bool:
    if not receiver:
        return False
    for part in receiver.split("."):
        lowered = part.lower()
        for hint in hints:
            if hint in lowered:
                return True
    return False


def _call_targets(
    node: ast.Call, qualname: Optional[str], callee: Value
) -> Tuple[CallableRef, ...]:
    """Which callables this call may reach.

    A value that carries a tracked callable wins over the syntactic name: it
    means the name at the call site is a local alias rather than the API being
    called. Where nothing is tracked this reproduces the plain syntactic match.
    """
    if callee.callables:
        return ordered_callables(callee)
    if not isinstance(node.func, (ast.Name, ast.Attribute)) or qualname is None:
        return ()
    if isinstance(node.func, ast.Attribute):
        return (
            CallableRef(
                qualname=qualname,
                attribute=node.func.attr,
                receiver=dotted_name(node.func.value),
            ),
        )
    return (CallableRef(qualname=qualname),)


def _indexed_callables(base: Value, index: ast.expr) -> FrozenSet[CallableRef]:
    """Callables reachable through ``container[index]``.

    A constant index picks the exact element, so an unrelated entry in a
    dispatch table is not blamed. Anything else falls back to every callable the
    container holds, because the index cannot be pinned down.
    """
    if isinstance(index, ast.Constant):
        key = index.value
        if isinstance(key, int) and not isinstance(key, bool) and base.elements:
            if -len(base.elements) <= key < len(base.elements):
                return base.elements[key].callables
            return frozenset()
        if isinstance(key, str) and base.entries:
            matched: FrozenSet[CallableRef] = frozenset()
            for name, refs in base.entries:
                if name == key:
                    matched = matched | refs
            return limit_callables(matched)
    return base.callables


def _reflected_callables(node: ast.Call, imports: ImportResolver) -> FrozenSet[CallableRef]:
    """``getattr(obj, "name")`` names a callable just as ``obj.name`` does."""
    if len(node.args) < 2:
        return frozenset()
    attribute = node.args[1]
    if not (isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)):
        return frozenset()
    receiver = dotted_name(node.args[0])
    if receiver is None:
        return frozenset()
    return frozenset(
        {
            CallableRef(
                qualname=imports.resolve("%s.%s" % (receiver, attribute.value)),
                attribute=attribute.value,
                receiver=receiver,
            )
        }
    )


def _terminates(statements: Sequence[ast.stmt]) -> bool:
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.If):
        return _terminates(last.body) and _terminates(last.orelse)
    if isinstance(last, ast.With):
        return _terminates(last.body)
    return False


def _apply_guards(env: Environment, names: FrozenSet[str]) -> None:
    for name in names:
        value = env.get(name)
        if value is None or value.taint is None:
            continue
        env[name] = Value(
            taint=value.taint.fully_cleared(),
            constant=value.constant,
            text_parts=value.text_parts,
            sanitized=True,
        )


def _guarded_names(test: ast.expr) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        positive, negative = _guarded_names(test.operand)
        return negative, positive
    if isinstance(test, ast.BoolOp):
        collected = [_guarded_names(value) for value in test.values]
        if isinstance(test.op, ast.And):
            positive: FrozenSet[str] = frozenset()
            for item, _ in collected:
                positive = positive | item
            return positive, frozenset()
        shared: Optional[FrozenSet[str]] = None
        for item, _ in collected:
            shared = item if shared is None else (shared & item)
        return frozenset(), shared or frozenset()
    if isinstance(test, ast.Compare):
        return _guarded_names_compare(test)
    if isinstance(test, ast.Call):
        return _guarded_names_call(test)
    return frozenset(), frozenset()


def _guarded_names_compare(test: ast.Compare) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    if len(test.ops) != 1 or len(test.comparators) != 1:
        return frozenset(), frozenset()
    name = _simple_name(test.left)
    if name is None:
        return frozenset(), frozenset()
    operator = test.ops[0]
    comparator = test.comparators[0]
    if isinstance(operator, ast.In) and _is_allowlist(comparator):
        return frozenset({name}), frozenset()
    if isinstance(operator, ast.NotIn) and _is_allowlist(comparator):
        return frozenset(), frozenset({name})
    if isinstance(operator, ast.Eq) and isinstance(comparator, ast.Constant):
        return frozenset({name}), frozenset()
    if isinstance(operator, ast.NotEq) and isinstance(comparator, ast.Constant):
        return frozenset(), frozenset({name})
    return frozenset(), frozenset()


def _guarded_names_call(test: ast.Call) -> Tuple[FrozenSet[str], FrozenSet[str]]:
    function = test.func
    if isinstance(function, ast.Attribute):
        if function.attr in specs.SCALAR_GUARD_METHODS:
            name = _simple_name(function.value)
            if name is not None:
                return frozenset({name}), frozenset()
        if function.attr in ("fullmatch", "match"):
            name = _argument_name(test, 1)
            if name is not None and _is_anchored_pattern(test, function.attr):
                return frozenset({name}), frozenset()
    if isinstance(function, ast.Name):
        if function.id in ("isinstance", "issubclass"):
            name = _argument_name(test, 0)
            if name is not None:
                return frozenset({name}), frozenset()
        if function.id == "fullmatch":
            name = _argument_name(test, 1)
            if name is not None:
                return frozenset({name}), frozenset()
    return frozenset(), frozenset()


def _is_anchored_pattern(test: ast.Call, attribute: str) -> bool:
    if attribute == "fullmatch":
        return True
    if not test.args:
        return False
    pattern = test.args[0]
    if isinstance(pattern, ast.Constant) and isinstance(pattern.value, str):
        return pattern.value.startswith("^") and pattern.value.endswith("$")
    return False


def _argument_name(test: ast.Call, index: int) -> Optional[str]:
    if index < len(test.args):
        return _simple_name(test.args[index])
    return None


_SHELL_BINARIES = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "cmd", "cmd.exe", "powershell", "pwsh", "busybox"}
)
_SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command"})


def _shell_wrapper_element(elements: Sequence[Value]) -> Optional[Value]:
    if len(elements) < 3:
        return None
    program = _sole_text(elements[0])
    if program is None:
        return None
    if program.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() not in _SHELL_BINARIES:
        return None
    for index in range(1, len(elements) - 1):
        flag = _sole_text(elements[index])
        if flag is not None and flag in _SHELL_FLAGS:
            return elements[index + 1]
    return None


def _sole_text(value: Value) -> Optional[str]:
    if value.constant and len(value.text_parts) == 1:
        return value.text_parts[0]
    return None


def _is_self_reference(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in _SELF_NAMES


def _simple_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted_name(node)
    return None


def _is_allowlist(node: ast.AST) -> bool:
    if isinstance(node, (ast.Set, ast.List, ast.Tuple, ast.Dict)):
        return True
    if isinstance(node, ast.Name):
        return node.id.isupper() or node.id.startswith(("ALLOWED", "VALID", "PERMITTED"))
    if isinstance(node, ast.Attribute):
        return node.attr.isupper()
    return False


def _match_capture_names(pattern: ast.AST) -> List[str]:
    names: List[str] = []
    for node in ast.walk(pattern):
        capture = getattr(ast, "MatchAs", None)
        star = getattr(ast, "MatchStar", None)
        if capture is not None and isinstance(node, capture) and node.name:
            names.append(node.name)
        elif star is not None and isinstance(node, star) and node.name:
            names.append(node.name)
    return names
