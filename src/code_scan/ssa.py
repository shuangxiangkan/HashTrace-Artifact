"""Lightweight symbolic expansion over Ghidra's near-SSA variables.

Ghidra's decompiler names most temporaries once (``iVar1``, ``uVar3``,
``puVar2`` ...), so a *position-insensitive* "what was this variable assigned"
map is usually correct without building a CFG. This lets a producer turn

    memcpy(dst, src, n)          # n = "uVar4"
    ... uVar4 = param_3 * 4 ...

into ``n -> "param_3 * 4"`` and answer "does the size derive from a parameter".

This is a **screening heuristic**, deliberately unsound:

- a variable assigned more than one distinct expression is left un-expanded
  (``ambiguous``); loop counters like ``i = i + 1`` land here;
- order, control flow and aliasing are ignored.

Real path reasoning is the LLM's job (step 3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import query
from .cst import node_text, walk

if TYPE_CHECKING:
    from tree_sitter import Node

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_TOKEN_RE = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[A-Za-z_]\w*")

# Ghidra decompiler intrinsics — width/sign juggling, not data origins.
_INTRINSIC_RE = re.compile(
    r"^(?:CONCAT\d*|SUB\d+|SEXT\d+|ZEXT\d+|S?CARRY\d*|SBORROW\d*|POPCOUNT\d*)$"
)

# Not variables worth chasing as "origins".
_KEYWORDS = frozenset(
    {
        "sizeof", "if", "else", "for", "while", "do", "return", "switch",
        "case", "default", "break", "continue", "goto", "typedef",
        "struct", "union", "enum", "const", "volatile", "static", "extern",
        "void", "char", "short", "int", "long", "float", "double", "signed",
        "unsigned", "NULL", "true", "false",
    }
)

_MAX_DEPTH = 6
_MAX_LEN = 4000  # stop expanding once the string gets absurd


@dataclass(frozen=True)
class Defs:
    """Position-insensitive assignment map for one function body."""

    single: dict[str, str] = field(default_factory=dict)  # var -> its one rhs
    ambiguous: frozenset[str] = frozenset()  # assigned >1 distinct rhs
    assigned: frozenset[str] = frozenset()  # every var written at least once

    def __bool__(self) -> bool:
        return bool(self.single or self.ambiguous)


def build_defs(node: Node, src: bytes) -> Defs:
    """Collect ``var -> rhs`` from every assignment / init under ``node``."""
    seen: dict[str, set[str]] = {}
    for assign in query.find_assignments(node, src):
        lhs = assign.lhs.strip()
        if not _IDENT_RE.fullmatch(lhs):  # skip ``a->b = ``, ``*p = ``, ``x[i] = ``
            continue
        seen.setdefault(lhs, set()).add(assign.rhs.strip())

    single: dict[str, str] = {}
    ambiguous: set[str] = set()
    for var, rhss in seen.items():
        if len(rhss) == 1:
            single[var] = next(iter(rhss))
        else:
            ambiguous.add(var)
    return Defs(
        single=single,
        ambiguous=frozenset(ambiguous),
        assigned=frozenset(seen),
    )


def _tokens(text: str):
    """Yield identifier tokens, skipping string / char literals."""
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if tok[:1] not in ('"', "'"):
            yield m.start(), tok


def expand(expr: str, defs: Defs, *, max_depth: int = _MAX_DEPTH) -> str:
    """Substitute known single-assignment variables in ``expr`` transitively.

    ``dst + i`` with ``dst = (char *)malloc(n * 4)`` -> ``(char *)malloc(n * 4) + i``.
    Cycles and ambiguous variables are left alone; growth is capped.
    """
    text = expr
    for _ in range(max_depth):
        rebuilt = []
        cursor = 0
        changed = False
        for start, tok in _tokens(text):
            rhs = defs.single.get(tok)
            if rhs is None or rhs == tok:
                continue
            after = text[start + len(tok):].lstrip()
            if after.startswith("("):  # foo(...) — a call, not a value
                continue
            rebuilt.append(text[cursor:start])
            rebuilt.append(f"({rhs})")
            cursor = start + len(tok)
            changed = True
        if not changed:
            return text
        rebuilt.append(text[cursor:])
        text = "".join(rebuilt)
        if len(text) > _MAX_LEN:
            return text
    return text


def origins(expr: str, defs: Defs) -> set[str]:
    """Leaf identifiers ``expr`` ultimately derives from.

    Fully expands, then keeps identifiers that are not locally-assigned
    variables and not C keywords — i.e. parameters, globals (``DAT_*`` /
    ``PTR_*``), and callee names. Callers usually intersect this with the
    function's parameter names.
    """
    expanded = expand(expr, defs)
    out: set[str] = set()
    for _, tok in _tokens(expanded):
        if tok in _KEYWORDS or tok in defs.assigned or _INTRINSIC_RE.match(tok):
            continue
        out.add(tok)
    return out


def local_names(node: Node, src: bytes) -> set[str]:
    """Identifiers declared as locals in ``node`` (``T x;`` / ``T x = ...;``)."""
    out: set[str] = set()
    for decl in walk(node, "declaration"):
        for child in decl.children:
            name = _declared_name(child, src)
            if name:
                out.add(name)
    return out


def _declared_name(node: Node, src: bytes) -> str | None:
    if node.type in ("identifier",):
        return node_text(node, src)
    if node.type in ("pointer_declarator", "array_declarator", "init_declarator"):
        inner = node.child_by_field_name("declarator")
        return _declared_name(inner, src) if inner is not None else None
    return None


__all__ = ["Defs", "build_defs", "expand", "local_names", "origins"]
