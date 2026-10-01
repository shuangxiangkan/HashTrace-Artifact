"""Expression helpers shared by the constant-propagation and taint analyses.

Extract ``lhs = rhs`` assignments from a statement subtree, constant-fold an
expression under a value environment, and collect the identifiers an expression
reads. Kept small and tree-sitter-driven; decompiled C only needs integer
folding and identifier tracking, not a full evaluator.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..cst import derived_defs, node_text, walk

if TYPE_CHECKING:
    from tree_sitter import Node as TSNode

_IDENT = re.compile(r"^[A-Za-z_]\w*$")
NAC = object()  # "not a constant" lattice top


def assignments_in(node: "TSNode", src: bytes) -> list[tuple[str, "TSNode"]]:
    """(lhs_identifier, rhs_node) for plain-variable assignments/initialisers in
    a statement subtree. Skips ``a->b = ``, ``*p = ``, ``x[i] = `` (lhs not a
    bare identifier) — those don't define a scalar we track."""
    out: list[tuple[str, "TSNode"]] = []
    for a in walk(node, "assignment_expression"):
        lhs = a.child_by_field_name("left")
        rhs = a.child_by_field_name("right")
        if lhs is not None and rhs is not None and lhs.type == "identifier":
            out.append((node_text(lhs, src), rhs))
    for d in walk(node, "init_declarator"):
        name = d.child_by_field_name("declarator")
        val = d.child_by_field_name("value")
        if name is not None and val is not None and name.type == "identifier":
            out.append((node_text(name, src), val))
    # Constructor-initialisation ``T k(a,b)`` and copy-writes ``memcpy(&x,src,n)``
    # define a scalar just as an assignment does; the rhs subtree carries the
    # provenance identifiers for used_idents().
    out.extend(derived_defs(node, src))
    return out


def used_idents(node: "TSNode", src: bytes) -> set[str]:
    """Identifiers read anywhere in a subtree (over-approximate; includes callees
    and type names, which callers intersect against the variable set).

    ``type_identifier`` is included too: a constructor-initialisation ``T k(a,b)``
    is a most-vexing parse, so its arguments ``a``/``b`` are reported as
    ``type_identifier`` rather than ``identifier``. Callers only ever intersect
    this set with known variable/parameter names, so the extra type names are
    harmless."""
    return {
        node_text(n, src)
        for kind in ("identifier", "type_identifier")
        for n in walk(node, kind)
    }


def eval_const(node: "TSNode", src: bytes, env: dict[str, object]):
    """Fold ``node`` to a Python int under ``env`` (var -> int|NAC), or NAC.

    Handles integer/char literals, identifiers (via env), parentheses, casts,
    unary +/-/~, and the common binary integer operators. Anything else -> NAC.
    """
    t = node.type
    if t in ("number_literal",):
        txt = node_text(node, src).rstrip("uUlL")
        try:
            return int(txt, 0)
        except ValueError:
            return NAC
    if t == "char_literal":
        s = node_text(node, src)
        m = re.search(r"'(\\?.)'", s)
        return ord(m.group(1)[-1]) if m else NAC
    if t == "identifier":
        name = node_text(node, src)
        return env.get(name, NAC)
    if t in ("parenthesized_expression",):
        inner = [c for c in node.children if c.is_named]
        return eval_const(inner[0], src, env) if inner else NAC
    if t == "cast_expression":
        v = node.child_by_field_name("value")
        return eval_const(v, src, env) if v is not None else NAC
    if t == "unary_expression":
        arg = node.child_by_field_name("argument")
        op = _op_text(node, src)
        v = eval_const(arg, src, env) if arg is not None else NAC
        if v is NAC:
            return NAC
        if op == "-":
            return -v
        if op == "+":
            return v
        if op == "~":
            return ~v
        return NAC
    if t == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        op = _op_text(node, src)
        a = eval_const(left, src, env) if left is not None else NAC
        b = eval_const(right, src, env) if right is not None else NAC
        if a is NAC or b is NAC:
            return NAC
        try:
            return _apply(op, a, b)
        except (ZeroDivisionError, ValueError):
            return NAC
    return NAC


def _op_text(node: "TSNode", src: bytes) -> str:
    op = node.child_by_field_name("operator")
    if op is not None:
        return node_text(op, src)
    # fallback: the unnamed operator child
    for c in node.children:
        if not c.is_named and c.type not in ("(", ")"):
            return c.type
    return ""


def _apply(op: str, a: int, b: int):
    return {
        "+": a + b, "-": a - b, "*": a * b,
        "/": a // b if b else NAC, "%": a % b if b else NAC,
        "<<": a << b, ">>": a >> b,
        "&": a & b, "|": a | b, "^": a ^ b,
    }.get(op, NAC)


__all__ = ["NAC", "assignments_in", "used_idents", "eval_const"]
