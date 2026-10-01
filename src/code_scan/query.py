"""C-construct queries over a parsed tree (built on :mod:`code_scan.cst`).

Given a function (or any node) this pulls out the things a vulnerability
producer reasons about: the function itself, calls, loops, assignments,
returns, memory accesses, guard conditions, binary operators, casts, and
per-variable use sites. Still domain-free — no vulnerability patterns here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import cst
from .cst import LOOP_TYPES, node_text, split_args, walk

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

COMPARE_OPS = frozenset({"<", "<=", ">", ">=", "==", "!="})
ARITH_OPS = frozenset({"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^"})

_INT_LITERAL_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*$")


# --------------------------------------------------------------------------- #
# data
# --------------------------------------------------------------------------- #
@dataclass
class Function:
    name: str
    return_type: str
    params: str
    body: str  # text between the outer braces, braces excluded
    start_line: int
    end_line: int
    node: "Node"  # the function_definition
    body_node: "Node"  # the compound_statement
    error_count: int = 0  # ERROR + MISSING nodes inside this function
    qualified_name: str | None = None

    @property
    def parse_ok(self) -> bool:
        return self.error_count == 0


@dataclass
class Call:
    name: str
    args: list[str]  # balanced, comment/cast left intact
    args_text: str
    line: int
    node: "Node"
    indirect: bool = False  # ``(*fp)(...)`` through a function pointer
    receiver: str | None = None  # ``m`` in ``m.emplace(...)``


@dataclass
class Assignment:
    lhs: str
    rhs: str
    is_declaration: bool
    line: int
    node: "Node"


@dataclass
class Return:
    value: str | None  # None for a bare ``return;``
    line: int
    node: "Node"


@dataclass
class Loop:
    kind: str  # one of cst.LOOP_TYPES
    header: str  # the ``for (...)`` / ``while (...)`` text, condition included
    line: int
    node: "Node"
    body_node: "Node | None"


@dataclass
class MemAccess:
    kind: str  # "subscript" | "deref"
    base: str  # base pointer / array expression text
    index: str | None  # non-constant index expression, if any
    offset: str | None  # pure integer-literal offset (e.g. "0x18"), if any
    elem_type: str | None  # element type from a cast: "int", "undefined8", ...
    is_write: bool
    line: int
    text: str
    node: "Node"


@dataclass
class Condition:
    kind: str  # "if" | "ternary"
    text: str
    vars: list[str]  # identifiers referenced in the condition
    line: int
    node: "Node"


@dataclass
class BinOp:
    op: str
    left: str
    right: str
    line: int
    node: "Node"


@dataclass
class Cast:
    target_type: str  # "int *", "uint", "char *"
    inner: str  # the cast operand text
    line: int
    node: "Node"


@dataclass
class VarUse:
    name: str
    is_write: bool
    line: int
    stmt: str  # enclosing statement text (whitespace collapsed)
    node: "Node"


# --------------------------------------------------------------------------- #
# functions
# --------------------------------------------------------------------------- #
def _function_declarator(node: Node) -> Node | None:
    if node.type == "function_declarator":
        return node
    for child in node.children:
        found = _function_declarator(child)
        if found is not None:
            return found
    return None


def _enclosing_scope(node: Node, src: bytes) -> list[str]:
    """Namespace/class scopes for an inline C++ method definition."""
    scopes: list[str] = []
    cur = node.parent
    while cur is not None:
        if cur.type in (
            "namespace_definition", "class_specifier", "struct_specifier",
        ):
            name = cur.child_by_field_name("name")
            if name is not None:
                scopes.append(node_text(name, src))
        cur = cur.parent
    scopes.reverse()
    return scopes


def extract_functions(tree: Tree, src: bytes) -> list[Function]:
    """All function definitions at file scope (and inside extern "C"/namespaces)."""
    # Walking for function_definition also reaches definitions wrapped by C++
    # templates and class/namespace bodies. Lambdas have their own node type and
    # are deliberately kept as part of their enclosing function.
    tops = list(walk(tree.root_node, "function_definition"))

    out: list[Function] = []
    for node in tops:
        declarator = node.child_by_field_name("declarator")
        body_node = node.child_by_field_name("body")
        if declarator is None or body_node is None:
            continue

        rt_parts = []
        for child in node.children:
            if child == declarator:
                break
            if child.type != "comment":
                rt_parts.append(node_text(child, src))
        return_type = " ".join(rt_parts).strip()

        func_decl = _function_declarator(declarator)
        if func_decl is None:
            continue

        # ``int *f()`` keeps the ``*`` on the declarator, not the type node.
        ptr = 0
        walk_d = declarator
        while walk_d is not None and walk_d.type != "function_declarator":
            if walk_d.type == "pointer_declarator":
                ptr += 1
            walk_d = walk_d.child_by_field_name("declarator")
        if ptr:
            return_type = f"{return_type} {'*' * ptr}".strip()

        name_node = func_decl.child_by_field_name("declarator")
        params_node = func_decl.child_by_field_name("parameters")
        name = (
            cst.declarator_name(name_node, src) if name_node is not None else None
        )
        if not name:
            continue

        params = node_text(params_node, src) if params_node is not None else ""
        if params.startswith("(") and params.endswith(")"):
            params = params[1:-1].strip()

        body = node_text(body_node, src)
        if body.startswith("{") and body.endswith("}"):
            body = body[1:-1]

        written_name = node_text(name_node, src) if name_node is not None else name
        scopes = _enclosing_scope(node, src)
        prefix = "::".join(scopes)
        if "::" in written_name:
            qualified_name = (
                written_name
                if not prefix or written_name.startswith(f"{prefix}::")
                else f"{prefix}::{written_name}"
            )
        else:
            qualified_name = "::".join([*scopes, name])

        out.append(
            Function(
                name=name,
                return_type=return_type,
                params=params,
                body=body,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                node=node,
                body_node=body_node,
                error_count=sum(
                    1 for n in walk(node) if n.is_error or n.is_missing
                ),
                qualified_name=qualified_name,
            )
        )
    return out


def single_function(
    source: str, *, language: cst.LanguageName = "c"
) -> Function | None:
    """Parse ``source`` and return its one top-level function, if any.

    Convenience for Ghidra output, where each ``functions.jsonl`` record holds
    exactly one function body.
    """
    src = source.encode("utf-8")
    funcs = extract_functions(cst.parse(src, language=language), src)
    return funcs[0] if funcs else None


# --------------------------------------------------------------------------- #
# calls
# --------------------------------------------------------------------------- #
def _callee(fn_node: Node, src: bytes) -> tuple[str, bool, str | None] | None:
    """``(name, is_indirect, receiver)`` for a call's function child.

    ``receiver`` preserves the object expression of a C++ member call, such as
    ``m`` in ``m.emplace(key, value)``. The result is None when Tree-sitter has
    parsed a Ghidra-style ``(scalar_type)(expr)`` cast as a call.
    """
    kind = fn_node.type
    if kind == "identifier":
        return node_text(fn_node, src), False, None
    if kind in ("qualified_identifier", "scoped_identifier", "template_function"):
        # Match configured sinks by their terminal name: std::memcpy -> memcpy.
        name = fn_node.child_by_field_name("name")
        target = name if name is not None else fn_node
        return (
            cst.declarator_name(target, src) or node_text(target, src),
            False,
            None,
        )
    if kind == "field_expression":  # p->fn(...) / p.fn(...)
        argument = fn_node.child_by_field_name("argument")
        field = fn_node.child_by_field_name("field")
        target = field if field is not None else fn_node
        receiver = node_text(argument, src) if argument is not None else None
        return node_text(target, src), False, receiver
    if kind == "parenthesized_expression":
        inner = [c for c in fn_node.children if c.type not in ("(", ")", "comment")]
        if inner and inner[0].type == "pointer_expression":  # (*fp)(...)
            ident = next(
                (node_text(n, src) for n in walk(inner[0], "identifier")), None
            )
            return (ident or node_text(inner[0], src)), True, None
        return None  # (type)(expr) cast, not a call
    return node_text(fn_node, src), False, None


def find_calls(node: Node, src: bytes, names: set[str] | None = None) -> list[Call]:
    """Every real ``call_expression`` under ``node`` (optionally filtered by callee).

    ``(scalar_type)(expr)`` casts that tree-sitter reports as calls are dropped;
    ``(*fp)(...)`` indirect calls are kept with ``indirect=True``.
    """
    out: list[Call] = []
    for call in walk(node, "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None:
            continue
        resolved = _callee(fn, src)
        if resolved is None:
            continue
        name, indirect, receiver = resolved
        if names is not None and name not in names:
            continue
        args_node = call.child_by_field_name("arguments")
        args_text = node_text(args_node, src) if args_node is not None else ""
        inner = args_text
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1]
        out.append(
            Call(
                name=name,
                args=split_args(inner),
                args_text=args_text,
                line=call.start_point[0] + 1,
                node=call,
                indirect=indirect,
                receiver=receiver,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# assignments / returns / loops
# --------------------------------------------------------------------------- #
def find_assignments(
    node: Node, src: bytes, var: str | None = None
) -> list[Assignment]:
    """Plain ``a = b`` and declaration-inits ``T a = b`` under ``node``."""
    out: list[Assignment] = []

    for assign in walk(node, "assignment_expression"):
        left = assign.child_by_field_name("left")
        right = assign.child_by_field_name("right")
        if left is None or right is None:
            continue
        lhs = node_text(left, src)
        if var is not None and lhs != var:
            continue
        out.append(
            Assignment(
                lhs=lhs,
                rhs=node_text(right, src),
                is_declaration=False,
                line=assign.start_point[0] + 1,
                node=assign,
            )
        )

    for decl in walk(node, "init_declarator"):
        declarator = decl.child_by_field_name("declarator")
        value = decl.child_by_field_name("value")
        if declarator is None or value is None:
            continue
        name = cst.declarator_name(declarator, src)
        if not name or (var is not None and name != var):
            continue
        out.append(
            Assignment(
                lhs=name,
                rhs=node_text(value, src),
                is_declaration=True,
                line=decl.start_point[0] + 1,
                node=decl,
            )
        )

    # Constructor-init ``T a(b,c)`` and copy-writes ``memcpy(&a,b,n)`` also define
    # ``a`` from the rhs subtree's identifiers; surface them so SSA expansion and
    # origin tracing reach the underlying inputs.
    for name, rhs_node in cst.derived_defs(node, src):
        if var is not None and name != var:
            continue
        out.append(
            Assignment(
                lhs=name,
                rhs=node_text(rhs_node, src),
                is_declaration=False,
                line=rhs_node.start_point[0] + 1,
                node=rhs_node,
            )
        )
    return out


def find_returns(node: Node, src: bytes) -> list[Return]:
    out: list[Return] = []
    for ret in walk(node, "return_statement"):
        value = None
        for child in ret.children:
            if child.type not in ("return", ";", "comment"):
                value = node_text(child, src)
                break
        out.append(Return(value=value, line=ret.start_point[0] + 1, node=ret))
    return out


def find_loops(node: Node, src: bytes) -> list[Loop]:
    out: list[Loop] = []
    for loop in walk(node):
        if loop.type not in LOOP_TYPES:
            continue
        body = loop.child_by_field_name("body")
        header_end = body.start_byte if body is not None else loop.end_byte
        header = src[loop.start_byte : header_end].decode("utf-8", errors="replace")
        out.append(
            Loop(
                kind=loop.type,
                header=header.strip(),
                line=loop.start_point[0] + 1,
                node=loop,
                body_node=body,
            )
        )
    return out


def loop_own_text(loop: Loop, src: bytes) -> str:
    """``loop``'s source with any *nested* loop bodies spliced out.

    Lets a check attribute something (a ref created per iteration, say) to the
    innermost loop only, instead of re-reporting it for every enclosing loop.
    """
    root = loop.node
    inner = [
        n
        for n in walk(root)
        if n.type in LOOP_TYPES
        and n.id != root.id
        and n.start_byte >= root.start_byte
        and n.end_byte <= root.end_byte
    ]
    spans = sorted((n.start_byte, n.end_byte) for n in inner)
    maximal: list[tuple[int, int]] = []
    for start, end in spans:
        if maximal and start < maximal[-1][1]:
            continue
        maximal.append((start, end))

    out = bytearray()
    cursor = root.start_byte
    for start, end in maximal:
        out += src[cursor:start]
        cursor = end
    out += src[cursor : root.end_byte]
    return out.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# memory accesses / guards / operators / casts / variable uses
# --------------------------------------------------------------------------- #
_LVAL_WRAPPERS = frozenset(
    {
        "parenthesized_expression",
        "cast_expression",
        "field_expression",
        "subscript_expression",
        "pointer_expression",
    }
)


def _contains(anc: "Node | None", n: Node) -> bool:
    return anc is not None and anc.start_byte <= n.start_byte and n.end_byte <= anc.end_byte


def _lvalue_write(node: Node) -> bool:
    """True if ``node`` (a subscript/deref access) is written.

    Ascends through lvalue wrappers — ``a[i].field = 1``, ``(a[i]) = 1``,
    ``*(cast)a[i] = 1``, nested subscripts — before deciding, and checks that the
    access lies inside the LHS (not the RHS) of the assignment. This is what
    keeps a write from being mis-reported as a read (a store is not a load)."""
    cur = node
    parent = cur.parent
    while parent is not None:
        if parent.type == "assignment_expression":
            return _contains(parent.child_by_field_name("left"), node)
        if parent.type == "update_expression":
            return True
        if parent.type == "init_declarator":
            return _contains(parent.child_by_field_name("declarator"), node)
        if parent.type in _LVAL_WRAPPERS:
            cur = parent
            parent = cur.parent
            continue
        return False
    return False


def _uniq(values) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _split_add(node: Node, src: bytes) -> tuple[str, str | None]:
    """For ``base + X`` return ``(base_text, X_text)``; otherwise ``(text, None)``."""
    while node.type == "parenthesized_expression":
        named = [c for c in node.children if c.is_named]
        if len(named) != 1:
            break
        node = named[0]
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if op is not None and left is not None and right is not None:
            if node_text(op, src) == "+":
                return node_text(left, src), node_text(right, src)
    return node_text(node, src), None


def find_mem_accesses(node: Node, src: bytes) -> list[MemAccess]:
    """Array subscripts and pointer dereferences under ``node``.

    Handles Ghidra's shapes: ``arr[i]`` / ``arr[i + 1]``;
    ``*(int *)(base + 0x18)`` (constant -> ``offset``);
    ``*(char *)(base + i * 4)`` (non-constant -> ``index``);
    ``*(T *)base`` / ``*base``. ``is_write`` is set for assignment / ``++`` / ``--``
    targets. ``&x`` is ignored.
    """
    out: list[MemAccess] = []

    for sub in walk(node, "subscript_expression"):
        arg = sub.child_by_field_name("argument")
        if arg is None:
            continue
        # tree-sitter-c exposes the index directly ("index"); tree-sitter-cpp
        # wraps it in a "indices" -> subscript_argument_list. Without this the
        # C++ frontend silently dropped every `a[i]` index (no OOB signal).
        idx = sub.child_by_field_name("index")
        if idx is not None:
            index_text: str | None = node_text(idx, src)
        else:
            index_text = None
            indices = sub.child_by_field_name("indices")
            if indices is not None:
                named = [c for c in indices.children if c.is_named]
                if len(named) == 1:
                    index_text = node_text(named[0], src)
                elif named:  # C++23 multidim a[i, j]
                    index_text = ", ".join(node_text(c, src) for c in named)
        out.append(
            MemAccess(
                kind="subscript",
                base=node_text(arg, src),
                index=index_text,
                offset=None,
                elem_type=None,
                is_write=_lvalue_write(sub),
                line=sub.start_point[0] + 1,
                text=node_text(sub, src),
                node=sub,
            )
        )

    # `p->field` is a dereference of `p`. Ghidra usually emits explicit offset
    # derefs, but IDA / recovered-type output uses `->`; record the base so UAF
    # (and other base-pointer checks) see the use. No index -> not an OOB signal.
    for fld in walk(node, "field_expression"):
        if not any(c.type == "->" or node_text(c, src) == "->" for c in fld.children):
            continue
        arg = fld.child_by_field_name("argument")
        if arg is None:
            continue
        out.append(
            MemAccess(
                kind="field",
                base=node_text(arg, src),
                index=None,
                offset=None,
                elem_type=None,
                is_write=_lvalue_write(fld),
                line=fld.start_point[0] + 1,
                text=node_text(fld, src),
                node=fld,
            )
        )

    for ptr in walk(node, "pointer_expression"):
        op = ptr.child_by_field_name("operator")
        if op is None or node_text(op, src) != "*":
            continue
        arg = ptr.child_by_field_name("argument")
        if arg is None:
            continue
        elem_type = None
        target = arg
        if target.type == "cast_expression":
            tdesc = target.child_by_field_name("type")
            if tdesc is not None:
                elem_type = node_text(tdesc, src).rstrip(" *").strip() or None
            val = target.child_by_field_name("value")
            if val is not None:
                target = val
        base, extra = _split_add(target, src)
        offset = index = None
        if extra is not None:
            if _INT_LITERAL_RE.match(extra.strip()):
                offset = extra.strip()
            else:
                index = extra
        out.append(
            MemAccess(
                kind="deref",
                base=base,
                index=index,
                offset=offset,
                elem_type=elem_type,
                is_write=_lvalue_write(ptr),
                line=ptr.start_point[0] + 1,
                text=node_text(ptr, src),
                node=ptr,
            )
        )

    return out


def find_conditions(node: Node, src: bytes) -> list[Condition]:
    """``if`` conditions and ``?:`` guards under ``node``.

    Loop headers are reported by :func:`find_loops`, not here.
    """
    out: list[Condition] = []
    for n in walk(node):
        if n.type == "if_statement":
            kind = "if"
        elif n.type == "conditional_expression":
            kind = "ternary"
        else:
            continue
        cond = n.child_by_field_name("condition")
        if cond is None:
            continue
        text = node_text(cond, src)
        if text.startswith("(") and text.endswith(")"):
            text = text[1:-1].strip()
        out.append(
            Condition(
                kind=kind,
                text=text,
                vars=_uniq(node_text(i, src) for i in walk(cond, "identifier")),
                line=cond.start_point[0] + 1,
                node=n,
            )
        )
    return out


def find_binary_ops(
    node: Node,
    src: bytes,
    ops: frozenset[str] | set[str] | None = None,
) -> list[BinOp]:
    """Binary expressions under ``node``, optionally filtered to ``ops``
    (see :data:`COMPARE_OPS` / :data:`ARITH_OPS`)."""
    out: list[BinOp] = []
    for be in walk(node, "binary_expression"):
        opn = be.child_by_field_name("operator")
        left = be.child_by_field_name("left")
        right = be.child_by_field_name("right")
        if opn is None or left is None or right is None:
            continue
        op = node_text(opn, src)
        if ops is not None and op not in ops:
            continue
        out.append(
            BinOp(
                op=op,
                left=node_text(left, src),
                right=node_text(right, src),
                line=be.start_point[0] + 1,
                node=be,
            )
        )
    return out


def find_casts(node: Node, src: bytes) -> list[Cast]:
    """``(type)expr`` casts under ``node`` (both C and C++ named casts)."""
    out: list[Cast] = []
    for c in walk(node, "cast_expression"):
        tdesc = c.child_by_field_name("type")
        val = c.child_by_field_name("value")
        if tdesc is None or val is None:
            continue
        out.append(
            Cast(
                target_type=node_text(tdesc, src).strip(),
                inner=node_text(val, src),
                line=c.start_point[0] + 1,
                node=c,
            )
        )
    return out


def var_uses(node: Node, src: bytes, name: str) -> list[VarUse]:
    """Every occurrence of identifier ``name`` under ``node``, read vs write,
    with the enclosing statement text."""
    out: list[VarUse] = []
    for ident in walk(node, "identifier"):
        if node_text(ident, src) != name:
            continue
        out.append(
            VarUse(
                name=name,
                is_write=_lvalue_write(ident),
                line=ident.start_point[0] + 1,
                stmt=" ".join(
                    node_text(cst.enclosing_statement(ident), src).split()
                ),
                node=ident,
            )
        )
    return out


__all__ = [
    "ARITH_OPS",
    "COMPARE_OPS",
    "Assignment",
    "BinOp",
    "Call",
    "Cast",
    "Condition",
    "Function",
    "Loop",
    "MemAccess",
    "Return",
    "VarUse",
    "extract_functions",
    "find_assignments",
    "find_binary_ops",
    "find_calls",
    "find_casts",
    "find_conditions",
    "find_loops",
    "find_mem_accesses",
    "find_returns",
    "loop_own_text",
    "single_function",
    "var_uses",
]
