"""Flow-sensitive taint + path-sensitive bounds analysis — the precision core.

Two analyses over the CFG:

  1. a forward taint dataflow (sources = function parameters or recognized input
     calls; propagated through assignments and simple value locations; killed
     on definite reassignment to an untainted value), and
  2. a **path-sensitive upper-bound** analysis: a variable ``v`` is "bounded" at a
     use only when *every* path reaching that use proves ``v < X`` (or ``v <= X``).

The bound analysis is deliberately a **must-analysis** (intersection over paths),
edge-sensitive so a guard only bounds the branch it actually guards:

  * ``if (v < n)``  → ``v`` bounded on the **true** edge only.
  * ``if (v >= n) return;`` → ``v`` bounded on the **false** (fall-through) edge,
    and only survives to a use if the true edge cannot also reach it (the
    intersection handles this automatically — no hand-coded reachability).
  * ``==``/``!=`` prove no ordering bound and contribute nothing.
  * a bound only applies to a **bare** index ``a[v]`` — never ``a[v+100]`` or
    ``a[v*4]``, whose value the ``v < n`` check does not constrain.

Crucially a proven bound is a *confidence downgrade*, never a hard suppression:
we cannot prove ``n`` equals the real capacity of ``a``, so the finding stays a
candidate (ranked lower). Unknown ⇒ conservative, not "safe".
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass

from ..cst import declarator_name, node_text, walk
from ..query import find_calls
from . import cfg as cfg_mod
from . import dataflow
from .cfg import CFG
from .expr import assignments_in, used_idents

_IDENT = re.compile(r"[A-Za-z_]\w*")
_FIELD = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\.|->)\s*([A-Za-z_]\w*)\b")
_ELEMENT = re.compile(r"\b([A-Za-z_]\w*)\s*\[[^\]]+\]")
_DEREF = re.compile(r"(?<![\w*])\*\s*([A-Za-z_]\w*)\b")
_ADDRESS = re.compile(r"&\s*([A-Za-z_]\w*)\s*$")
_ALIAS_PREFIX = "@alias:"
_ELEMENT_PREFIX = "@element:"
_FIELD_PREFIX = "@field:"
_CMP_OPS = {"<", "<=", ">", ">=", "==", "!="}
# For ``L op R``: which operand gets a proven UPPER bound on the TRUE branch, and
# which on the FALSE branch. ``L < R`` true ⇒ L<R (L bounded); false ⇒ L>=R
# (R bounded). ``L >= R`` true ⇒ R<=L (R bounded); false ⇒ L<R (L bounded).
_BOUND_SIDES = {
    "<": ("left", "right"),
    "<=": ("left", "right"),
    ">": ("right", "left"),
    ">=": ("right", "left"),
}


def _value_dependencies(expr: str, state: set[str]) -> set[str]:
    """Tainted values read by an expression, including simple memory locations.

    An element's index is not its stored value. Keep the element and field
    locations separate from their owners so a tainted value in ``m[i]`` does
    not make a later hash of ``m``'s unrelated key appear input-controlled.
    """
    out = set(_IDENT.findall(expr or "")) & state
    for base, field in _FIELD.findall(expr):
        slot = f"{_FIELD_PREFIX}{base}.{field}"
        if slot in state:
            out.add(f"{base}.{field}")
    for base in _ELEMENT.findall(expr):
        if f"{_ELEMENT_PREFIX}{base}" in state:
            out.add(f"{base}[]")
    for pointer in _DEREF.findall(expr):
        prefix = f"{_ALIAS_PREFIX}{pointer}:"
        if any(alias[len(prefix):] in state for alias in state if alias.startswith(prefix)):
            out.add(f"*{pointer}")
    return out


def _memory_slot(expr: str) -> str | None:
    expr = expr.strip()
    match = _FIELD.fullmatch(expr)
    if match:
        return f"{_FIELD_PREFIX}{match[1]}.{match[2]}"
    match = _ELEMENT.fullmatch(expr)
    if match:
        return f"{_ELEMENT_PREFIX}{match[1]}"
    return None


def _taint_env(
    cfg: CFG,
    src: bytes,
    params: set[str],
    const_params: set[str],
    generated_at_byte: dict[int, set[str]],
) -> dict[int, set[str]]:
    """In-set of tainted variables from parameters and in-body source points."""
    seed = params - const_params
    generated_by_node: dict[int, set[str]] = {}
    byte_spans = cfg_mod.byte_index(cfg)
    for byte, variables in generated_at_byte.items():
        nid = cfg_mod.node_for_byte(byte_spans, byte)
        if nid is not None:
            generated_by_node.setdefault(nid, set()).update(variables)

    def transfer(nid: int, in_env: frozenset[str]) -> frozenset[str]:
        node = cfg.nodes[nid]
        if node.cst is None:
            return in_env
        tainted = set(in_env)
        assignments = (
            []
            if node.cst.type == "for_range_loop"
            else assignments_in(node.cst, src)
        )
        for lhs, rhs in assignments:
            rhs_text = node_text(rhs, src)
            # Taking an address transfers a reference, not the pointee's value.
            address = _ADDRESS.fullmatch(rhs_text.strip())
            if address is not None:
                tainted.discard(lhs)
            elif _value_dependencies(rhs_text, tainted | seed):
                tainted.add(lhs)
            else:
                tainted.discard(lhs)  # reassigned to something untainted
            # A plain pointer reassignment invalidates an earlier local alias.
            old_aliases = {
                marker for marker in tainted
                if marker.startswith(f"{_ALIAS_PREFIX}{lhs}:")
            }
            tainted.difference_update(old_aliases)
            if address is not None:
                tainted.add(f"{_ALIAS_PREFIX}{lhs}:{address[1]}")

        # CFG control nodes contain their entire nested body as a CST subtree.
        # Only visit direct statements here; a write in a branch must not be
        # applied before control actually reaches that statement.
        memory_statement = node.cst.type in {"declaration", "expression_statement"}
        for declaration in walk(node.cst, "init_declarator") if memory_statement else ():
            declarator = declaration.child_by_field_name("declarator")
            value = declaration.child_by_field_name("value")
            if declarator is None or declarator.type != "pointer_declarator" or value is None:
                continue
            pointer = declarator_name(declarator, src)
            address = _ADDRESS.fullmatch(node_text(value, src).strip())
            if pointer and address:
                tainted.add(f"{_ALIAS_PREFIX}{pointer}:{address[1]}")

        for assignment in walk(node.cst, "assignment_expression") if memory_statement else ():
            lhs = assignment.child_by_field_name("left")
            rhs = assignment.child_by_field_name("right")
            if lhs is None or rhs is None or lhs.type == "identifier":
                continue
            lhs_text = node_text(lhs, src)
            slot = _memory_slot(lhs_text)
            if slot is None and lhs_text.strip().startswith("*"):
                pointer = _DEREF.fullmatch(lhs_text.strip())
                if pointer:
                    prefix = f"{_ALIAS_PREFIX}{pointer[1]}:"
                    targets = [marker[len(prefix):] for marker in tainted
                               if marker.startswith(prefix)]
                    for target in targets:
                        if _value_dependencies(node_text(rhs, src), tainted | seed):
                            tainted.add(target)
                        elif len(targets) == 1:
                            tainted.discard(target)
                continue
            if slot is not None:
                if _value_dependencies(node_text(rhs, src), tainted | seed):
                    tainted.add(slot)
                elif slot.startswith(_FIELD_PREFIX):
                    # A field assignment overwrites that field. An element
                    # assignment cannot clear an unknown different element.
                    tainted.discard(slot)

        for call in (find_calls(node.cst, src, {"emplace_back", "push_back"})
                     if memory_statement else ()):
            if (call.receiver and _IDENT.fullmatch(call.receiver)
                    and any(_value_dependencies(arg, tainted | seed) for arg in call.args)):
                tainted.add(f"{_ELEMENT_PREFIX}{call.receiver}")
        if node.cst.type == "for_range_loop":
            iterable = node.cst.child_by_field_name("right")
            declarator = node.cst.child_by_field_name("declarator")
            variable = (
                declarator_name(declarator, src) if declarator is not None else None
            )
            if iterable is not None and variable:
                if used_idents(iterable, src) & (tainted | seed):
                    tainted.add(variable)
                else:
                    tainted.discard(variable)
        tainted.update(generated_by_node.get(nid, set()))
        return frozenset(tainted)

    out, converged = dataflow.fixpoint(
        cfg, entry_env=frozenset(seed), bottom=frozenset(),
        transfer=transfer, join=lambda a, b: a | b,
        eq=lambda a, b: a == b, forward=True,
    )
    if not converged:
        warnings.warn(
            "taint fixpoint did not converge; taint results may be unsound",
            dataflow.NonConvergenceWarning,
            stacklevel=2,
        )
    return {
        nid: set(dataflow.in_env_of(
            cfg, out, nid, entry_env=frozenset(seed), bottom=frozenset(),
            join=lambda a, b: a | b, forward=True))
        for nid in cfg.reachable
    }


def _guard_bounds(cfg: CFG, src: bytes) -> dict[int, tuple[set[str], set[str]]]:
    """For each 'cond' node, ``(true_vars, false_vars)``: variables proven to have
    an upper bound when the branch is taken TRUE / FALSE respectively.

    ``v < X`` upper-bounds ``v`` on true; its negation ``v >= X`` upper-bounds
    ``v`` on false. Boolean structure is respected (this is the P0 fix for ``||``):

      * ``A && B``: true = t(A) ∪ t(B);  false = f(A) ∩ f(B)
      * ``A || B``: true = t(A) ∩ t(B);  false = f(A) ∪ f(B)
      * ``!A``    : swap true/false of A

    so ``if (i < n || j < m)`` proves *neither* ``i`` nor ``j`` bounded on true.
    Only identifier operands count; ``==``/``!=`` contribute nothing."""
    out: dict[int, tuple[set[str], set[str]]] = {}
    for nid, node in cfg.nodes.items():
        if node.kind != "cond" or node.cst is None:
            continue
        tv, fv = _bounds_of(node.cst, src)
        if tv or fv:
            out[nid] = (tv, fv)
    return out


def _bounds_of(n, src: bytes) -> tuple[set[str], set[str]]:
    """Recursively derive ``(vars_bounded_if_true, vars_bounded_if_false)`` for a
    boolean condition CST, honouring &&/||/! short-circuit semantics."""
    t = n.type
    if t == "parenthesized_expression":
        inner = [c for c in n.children if c.is_named]
        return _bounds_of(inner[0], src) if inner else (set(), set())
    if t == "unary_expression":
        op = n.child_by_field_name("operator")
        arg = n.child_by_field_name("argument")
        if op is not None and node_text(op, src) == "!" and arg is not None:
            ft, ff = _bounds_of(arg, src)
            return ff, ft  # !A swaps true/false facts
        return set(), set()
    if t == "binary_expression":
        op = n.child_by_field_name("operator")
        optext = node_text(op, src) if op is not None else ""
        left = n.child_by_field_name("left")
        right = n.child_by_field_name("right")
        if optext in ("&&", "||") and left is not None and right is not None:
            lt, lf = _bounds_of(left, src)
            rt, rf = _bounds_of(right, src)
            if optext == "&&":
                return lt | rt, lf & rf
            return lt & rt, lf | rf  # ||
        sides = _BOUND_SIDES.get(optext)
        if sides is None:  # ==, !=, or non-comparison
            return set(), set()
        true_vars: set[str] = set()
        false_vars: set[str] = set()
        for bucket, which in ((true_vars, sides[0]), (false_vars, sides[1])):
            operand = n.child_by_field_name(which)
            if operand is not None and operand.type == "identifier":
                bucket.add(node_text(operand, src))
        return true_vars, false_vars
    return set(), set()


def _bounds_env(cfg: CFG, src: bytes) -> dict[int, set[str]]:
    """Path-sensitive upper-bound must-analysis.

    ``result[n]`` = variables proven upper-bounded on *every* path into node ``n``.
    Bounds are generated on guard edges (true/false as appropriate), killed when a
    variable is reassigned, and merged by **intersection** at joins — so a bound
    survives to a use only if no reaching path leaves it unproven.
    """
    guards = _guard_bounds(cfg, src)
    universe: set[str] = set()
    for tv, fv in guards.values():
        universe |= tv | fv
    if not universe:
        return {n: set() for n in cfg.reachable}

    kill: dict[int, set[str]] = {}
    for nid, node in cfg.nodes.items():
        if node.cst is not None:
            kill[nid] = {lhs for lhs, _ in assignments_in(node.cst, src)}

    def gen(p: int, n: int) -> set[str]:
        g = guards.get(p)
        if g is None:
            return set()
        tv, fv = g
        return tv if n in cfg.cond_true.get(p, set()) else fv

    # must-analysis: init every node to the universe (top), entry to empty.
    entry_in: dict[int, set[str]] = {n: set() for n in cfg.reachable}
    out: dict[int, set[str]] = {n: set(universe) for n in cfg.reachable}
    out[cfg.entry] = set()
    work: set[int] = set(cfg.reachable)
    while work:
        n = work.pop()
        preds = [p for p in cfg.pred(n) if p in out]
        if n == cfg.entry or not preds:
            in_n: set[str] = set()
        else:
            in_n = None  # type: ignore[assignment]
            for p in preds:
                contrib = out[p] | gen(p, n)
                in_n = set(contrib) if in_n is None else (in_n & contrib)
            in_n = in_n or set()
        entry_in[n] = in_n
        new_out = in_n - kill.get(n, set())
        if new_out != out[n]:
            out[n] = new_out
            work.update(s for s in cfg.succ(n) if s in out)
    return entry_in


def _bare_ident(expr: str) -> str | None:
    """If ``expr`` is a single identifier (optionally wrapped in casts/parens),
    return it; else None. ``i`` and ``(uint)i`` qualify; ``i + 1`` does not."""
    e = (expr or "").strip()
    prev = None
    while e != prev:
        prev = e
        e = re.sub(r"^\(\s*[\w ]+\s*\*?\s*\)\s*", "", e)  # strip leading cast
        if len(e) >= 2 and e[0] == "(" and e[-1] == ")":
            e = e[1:-1].strip()
    return e if _IDENT.fullmatch(e) else None


@dataclass
class TaintInfo:
    """Per-function analysis result queried by producers."""

    tainted: dict[int, set[str]]      # node -> tainted var names on entry
    bounded_at: dict[int, set[str]]   # node -> vars bounded by a dominating guard
    line_to_node: dict[int, int]      # source line -> a representative CFG node
    byte_spans: list[tuple[int, int, int]]  # (start, end, node) for byte lookup

    def node_for_line(self, line: int) -> int | None:
        return self.line_to_node.get(line)

    def vars_of(self, expr: str) -> set[str]:
        return set(_IDENT.findall(expr or ""))

    def tainted_vars(self, line: int, expr: str) -> set[str]:
        """Tainted values used by ``expr`` at a source line."""
        nid = self.line_to_node.get(line)
        if nid is None:
            return set()
        return _value_dependencies(expr, self.tainted.get(nid, set()))

    def is_tainted(self, line: int, expr: str) -> bool:
        return bool(self.tainted_vars(line, expr))

    def tainted_vars_at(self, byte: int, expr: str) -> set[str]:
        """Tainted values used by ``expr`` at an exact CST byte offset."""
        if byte < 0:
            return set()
        nid = cfg_mod.node_for_byte(self.byte_spans, byte)
        if nid is None:
            return set()
        return _value_dependencies(expr, self.tainted.get(nid, set()))

    def is_tainted_at(self, byte: int, expr: str) -> bool:
        return bool(self.tainted_vars_at(byte, expr))

    def is_bounded_at(self, byte: int, expr: str) -> bool:
        """True only when ``expr`` is a bare index variable proven upper-bounded on
        every path to the access at CST offset ``byte``. Uses byte-span node
        identity (not line) so several statements on one decompiled line don't
        share a bound. Compound indices (``v+1``, ``v*4``) are never bounded."""
        v = _bare_ident(expr)
        if v is None or byte < 0:
            return False
        nid = cfg_mod.node_for_byte(self.byte_spans, byte)
        return nid is not None and v in self.bounded_at.get(nid, set())


def analyze(
    cfg: CFG,
    src: bytes,
    params: set[str],
    const_params: set[str] | None = None,
    generated_at_byte: dict[int, set[str]] | None = None,
) -> TaintInfo:
    const_params = const_params or set()
    tainted = _taint_env(
        cfg, src, params, const_params, generated_at_byte or {}
    )
    bounded = _bounds_env(cfg, src)
    # map source line -> representative node (deepest/most-specific = last wins)
    line_to_node: dict[int, int] = {}
    for nid, node in cfg.nodes.items():
        if node.line and nid in cfg.reachable:
            line_to_node[node.line] = nid
    return TaintInfo(
        tainted=tainted, bounded_at=bounded, line_to_node=line_to_node,
        byte_spans=cfg_mod.byte_index(cfg),
    )


__all__ = ["TaintInfo", "analyze"]
