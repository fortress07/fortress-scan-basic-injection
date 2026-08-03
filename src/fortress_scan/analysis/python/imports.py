from __future__ import annotations

import ast
from typing import Dict, List, Optional

_MAX_CHAIN_DEPTH = 12


class ImportResolver:
    def __init__(self) -> None:
        self._aliases: Dict[str, str] = {}

    def collect(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._add_import(node)
            elif isinstance(node, ast.ImportFrom):
                self._add_import_from(node)

    def _add_import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self._aliases[alias.asname] = alias.name
            else:
                head = alias.name.split(".", 1)[0]
                self._aliases.setdefault(head, head)

    def _add_import_from(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level and not module:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            target = "%s.%s" % (module, alias.name) if module else alias.name
            self._aliases[alias.asname or alias.name] = target

    def resolve(self, dotted: str) -> str:
        if not dotted:
            return dotted
        head, _, rest = dotted.partition(".")
        mapped = self._aliases.get(head)
        if mapped is None:
            return dotted
        return "%s.%s" % (mapped, rest) if rest else mapped

    def qualname_of(self, node: ast.AST) -> Optional[str]:
        dotted = dotted_name(node)
        if dotted is None:
            return None
        return self.resolve(dotted)

    def is_alias_of(self, name: str, target: str) -> bool:
        return self._aliases.get(name) == target


def dotted_name(node: ast.AST, depth: int = 0) -> Optional[str]:
    if depth > _MAX_CHAIN_DEPTH:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value, depth + 1)
        if base is None:
            return None
        return "%s.%s" % (base, node.attr)
    if isinstance(node, ast.Call):
        return dotted_name(node.func, depth + 1)
    return None


def attribute_parts(node: ast.AST) -> List[str]:
    dotted = dotted_name(node)
    return dotted.split(".") if dotted else []
