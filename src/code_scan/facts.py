"""Compact, JSON-serialisable digest of one function.

``analyze()`` runs the :mod:`code_scan.query` extractors + :mod:`code_scan.ssa`
expansion once and rolls the result into a ``FunctionFacts`` that producers and
the step-3 prompt both consume, so neither re-walks the tree.

Unlike ``query``'s dataclasses these carry **no tree-sitter nodes** — the whole
structure goes through ``dataclasses.asdict`` cleanly.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from . import cst, query, ssa
from .analysis import cfg as cfg_mod
from .analysis import taint as taint_mod

if TYPE_CHECKING:
    from tree_sitter import Node

_WARNING_RE = re.compile(r"/\*\s*WARNING:?\s*(.*?)\s*\*/", re.DOTALL)
_GLOBAL_RE = re.compile(r"\b_{0,2}(?:DAT|PTR|UNK)_\w+\b")
_INTRINSIC_RE = re.compile(
    r"\b(CONCAT\d*|SUB\d+|SEXT\d+|ZEXT\d+|S?CARRY\d*|SBORROW\d*|POPCOUNT\d*)\b"
)
_STACK_CHK = "stack_chk_fail"


# --------------------------------------------------------------------------- #
# fact records
# --------------------------------------------------------------------------- #
@dataclass
class ArgFact:
    text: str
    expanded: str
    from_param: list[str]  # origins ∩ parameter names
    arith_ops: list[str]  # arithmetic operators anywhere in the arg


@dataclass
class CallFact:
    name: str  # as written, e.g. "_memcpy" / "__memcpy_chk"
    norm: str  # "memcpy"
    line: int
    indirect: bool
    fortified: bool  # a ``__*_chk`` bounded variant
    args: list[ArgFact]
    byte: int = -1  # CST start byte — stable node identity (line can collide)
    receiver: str | None = None  # object expression for a C++ member call


@dataclass
class MemFact:
    kind: str  # "subscript" | "deref"
    text: str
    base: str
    index: str | None
    offset: str | None
    elem_type: str | None
    is_write: bool
    line: int
    index_from_param: list[str]
    base_from_param: list[str]
    byte: int = -1  # CST start byte — stable node identity (line can collide)


@dataclass
class LoopFact:
    kind: str
    line: int
    depth: int  # 1 = outermost
    counter: str | None
    bound: str | None
    bound_from_param: list[str]
    body_writes: int
    body_calls: list[str]
    bound_op: str | None = None  # comparison op: '<'/'<=' = count, '!='  = sentinel


@dataclass
class GuardFact:
    kind: str  # "if" | "ternary"
    text: str
    vars: list[str]
    line: int


@dataclass
class AssignFact:
    """A ``var = ...`` to a plain identifier, with its line. Position-aware
    (unlike the SSA digest) so producers can reason about free-then-reassign."""

    var: str
    line: int
    byte: int = -1  # CST start byte — stable node identity (line can collide)


@dataclass
class FunctionFacts:
    name: str
    return_type: str
    params: list[str]  # parameter names
    param_decls: list[str]  # "int param_1", ...
    n_locals: int
    parse_ok: bool  # tree-sitter parsed this function with no ERROR/MISSING nodes
    error_count: int
    decompiler_warnings: list[str]
    string_refs: list[str]
    globals: list[str]
    intrinsics: list[str]
    stack_protected: bool
    max_loop_depth: int
    calls: list[CallFact]
    mem_reads: list[MemFact]
    mem_writes: list[MemFact]
    loops: list[LoopFact]
    guards: list[GuardFact]
    assignments: list[AssignFact]
    scalar_params: list[str]  # non-pointer params (a scalar count/index source)
    const_call_params: list[str]  # params constant at every known call site (one-hop)
    # Flow-sensitive analysis layer (CFG + taint). Excluded from to_dict because
    # they hold tree-sitter nodes / sets; producers consume them directly.
    cfg: Any = field(default=None, repr=False, compare=False)
    taint: Any = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        # Null the non-serialisable analysis fields before asdict recurses.
        d = dataclasses.asdict(dataclasses.replace(self, cfg=None, taint=None))
        d.pop("cfg", None)
        d.pop("taint", None)
        return d


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _parse_params(params_text: str) -> tuple[list[str], list[str]]:
    parts = [p.strip() for p in cst.split_args(params_text) if p.strip()]
    if parts in ([], ["void"]):
        return [], []
    names, decls = [], []
    for p in parts:
        decls.append(p)
        if p == "...":
            names.append("...")
            continue
        # Function-pointer params carry the name inside `(*name)(...)`, so the
        # last identifier token would wrongly be a type from the signature.
        fp = re.search(r"\(\s*\*+\s*([A-Za-z_]\w*)\s*\)", p)
        if fp is not None:
            names.append(fp.group(1))
            continue
        toks = re.findall(r"[A-Za-z_]\w*", p)
        names.append(toks[-1] if toks else p)
    return names, decls


def _normalise_callee(name: str) -> tuple[str, bool]:
    """('__memcpy_chk') -> ('memcpy', True); ('_strlen') -> ('strlen', False)."""
    norm = name.lstrip("_")
    fortified = norm.endswith("_chk")
    if fortified:
        norm = norm[: -len("_chk")]
    return norm, fortified


def _loop_depth(node: Node) -> int:
    depth = 1
    parent = node.parent
    while parent is not None:
        if parent.type in cst.LOOP_TYPES:
            depth += 1
        parent = parent.parent
    return depth


def _arg_nodes(call_node: Node) -> list[Node]:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if c.is_named]


def _expr_arith_ops(expr: str, language: cst.LanguageName = "c") -> set[str]:
    """Arithmetic operators in a bare expression string (via a throwaway parse)."""
    wrapped = f"int _t_ = {expr};"
    tree = cst.parse(wrapped, language=language)
    return {
        b.op
        for b in query.find_binary_ops(
            tree.root_node, wrapped.encode("utf-8"), query.ARITH_OPS
        )
    }


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
def analyze(
    fn: query.Function,
    src: bytes,
    const_param_positions: set[int] | None = None,
    *,
    language: cst.LanguageName = "c",
) -> FunctionFacts:
    body = fn.body_node
    body_text = cst.node_text(body, src)
    defs = ssa.build_defs(body, src)
    param_names, param_decls = _parse_params(fn.params)
    # Parameters that are a compile-time constant at every *known* call site
    # (one-hop interprocedural). Constant only proves "not dynamically
    # attacker-controlled" — NOT safe: `f(a, 1000)` with `a[1000]=…` is still a
    # deterministic OOB. So these stay taint sources (candidates are still
    # produced); the producer merely downgrades confidence via const_call_params.
    const_names = {
        param_names[i] for i in (const_param_positions or ()) if i < len(param_names)
    }
    pset = set(param_names)

    def from_param(expr: str) -> list[str]:
        # origins() sees through single-assignment temps; also count a raw
        # mention of a parameter name (Ghidra sometimes reassigns params, which
        # drops them from origins()).
        hits = ssa.origins(expr, defs) & pset
        hits |= {t for t in re.findall(r"[A-Za-z_]\w*", expr) if t in pset}
        return sorted(hits)

    # calls
    calls: list[CallFact] = []
    for call in query.find_calls(body, src):
        norm, fortified = _normalise_callee(call.name)
        arg_nodes = _arg_nodes(call.node)
        aligned = len(arg_nodes) == len(call.args)
        arg_facts: list[ArgFact] = []
        for i, text in enumerate(call.args):
            expanded = ssa.expand(text, defs)
            ops: set[str] = set()
            if aligned:
                ops |= {
                    b.op
                    for b in query.find_binary_ops(
                        arg_nodes[i], src, query.ARITH_OPS
                    )
                }
            if expanded != text:
                ops |= _expr_arith_ops(expanded, language)
            arg_facts.append(
                ArgFact(
                    text=text,
                    expanded=expanded,
                    from_param=from_param(text),
                    arith_ops=sorted(ops),
                )
            )
        calls.append(
            CallFact(
                name=call.name,
                norm=norm,
                line=call.line,
                indirect=call.indirect,
                fortified=fortified,
                args=arg_facts,
                byte=call.node.start_byte,
                receiver=call.receiver,
            )
        )

    # C++ delete/delete[] are expressions rather than calls in the grammar.
    # Represent them as a synthetic call so the existing path-sensitive
    # free/UAF typestate can reason about C and C++ lifetime operations alike.
    if language == "cpp":
        for deletion in cst.walk(body, "delete_expression"):
            operands = [c for c in deletion.children if c.is_named]
            if not operands:
                continue
            operand = operands[-1]
            text = cst.node_text(operand, src)
            expanded = ssa.expand(text, defs)
            spelling = cst.node_text(deletion, src)
            calls.append(
                CallFact(
                    name="delete[]" if "[" in spelling else "delete",
                    norm="delete",
                    line=cst.line_of(deletion),
                    indirect=False,
                    fortified=False,
                    args=[
                        ArgFact(
                            text=text,
                            expanded=expanded,
                            from_param=from_param(text),
                            arith_ops=sorted(_expr_arith_ops(expanded, language)),
                        )
                    ],
                    byte=deletion.start_byte,
                )
            )

    # memory accesses
    mem_reads: list[MemFact] = []
    mem_writes: list[MemFact] = []
    for m in query.find_mem_accesses(body, src):
        fact = MemFact(
            kind=m.kind,
            text=m.text,
            base=m.base,
            index=m.index,
            offset=m.offset,
            elem_type=m.elem_type,
            is_write=m.is_write,
            line=m.line,
            index_from_param=from_param(m.index) if m.index else [],
            base_from_param=from_param(m.base),
            byte=m.node.start_byte,
        )
        (mem_writes if m.is_write else mem_reads).append(fact)

    # loops
    loops: list[LoopFact] = []
    max_depth = 0
    for lp in query.find_loops(body, src):
        depth = _loop_depth(lp.node)
        max_depth = max(max_depth, depth)
        counter = bound = bound_op = None
        cond = lp.node.child_by_field_name("condition")
        if cond is not None:
            cmps = query.find_binary_ops(cond, src, query.COMPARE_OPS)
            if cmps:
                counter, bound = cmps[0].left.strip(), cmps[0].right.strip()
                bound_op = cmps[0].op
        body_node = lp.body_node
        loops.append(
            LoopFact(
                kind=lp.kind,
                line=lp.line,
                depth=depth,
                counter=counter,
                bound=bound,
                bound_op=bound_op,
                bound_from_param=from_param(bound) if bound else [],
                body_writes=sum(
                    1
                    for a in query.find_mem_accesses(body_node, src)
                    if a.is_write
                )
                if body_node is not None
                else 0,
                body_calls=sorted(
                    {c.name for c in query.find_calls(body_node, src)}
                )
                if body_node is not None
                else [],
            )
        )

    guards = [
        GuardFact(kind=g.kind, text=g.text, vars=list(g.vars), line=g.line)
        for g in query.find_conditions(body, src)
    ]

    # Plain-identifier assignments with line numbers, so producers can tell a
    # free-then-reassign (safe) from a real use/free-after-free.
    assignments = [
        AssignFact(var=a.lhs.strip(), line=a.line, byte=a.node.start_byte)
        for a in query.find_assignments(body, src)
        if re.fullmatch(r"[A-Za-z_]\w*", a.lhs.strip())
    ]

    # Flow-sensitive analysis: build a CFG, then run guard-sanitized parameter
    # taint over it. Parameters known constant at every call site (one-hop
    # interprocedural, seeded by the orchestrator) are excluded as taint sources.
    # Build a CFG and compute dominating-guard sanitization (which index/size
    # variables are bounded by an ``if (v < n)`` / loop guard that dominates
    # their use). The base "derives from a parameter" signal stays the
    # conservative position-insensitive one (``*_from_param`` above); the taint
    # layer contributes the *sanitizer* and CFG reachability the producers apply.
    function_cfg = cfg_mod.build_cfg(body, src)
    taint_info = taint_mod.analyze(function_cfg, src, pset)

    # Ghidra prints ``/* WARNING: ... */`` either inside the body or just above
    # the signature, so scan the function text plus a short preamble.
    pre_start = max(0, fn.node.start_byte - 400)
    warn_text = src[pre_start : fn.node.end_byte].decode("utf-8", errors="replace")
    warnings = sorted(
        {" ".join(m.group(1).split()) for m in _WARNING_RE.finditer(warn_text)}
    )
    strings = _uniq_cap(
        cst.node_text(n, src).strip('"')
        for n in cst.walk(body, "string_literal")
    )
    globals_ = _uniq_cap(m.group(0) for m in _GLOBAL_RE.finditer(body_text))
    intrinsics = sorted({m.group(1) for m in _INTRINSIC_RE.finditer(body_text)})

    return FunctionFacts(
        name=fn.name,
        return_type=fn.return_type,
        params=param_names,
        param_decls=param_decls,
        n_locals=len(ssa.local_names(body, src)),
        parse_ok=fn.parse_ok,
        error_count=fn.error_count,
        decompiler_warnings=warnings,
        string_refs=strings,
        globals=globals_,
        intrinsics=intrinsics,
        stack_protected=_STACK_CHK in body_text,
        max_loop_depth=max_depth,
        calls=calls,
        mem_reads=mem_reads,
        mem_writes=mem_writes,
        loops=loops,
        guards=guards,
        assignments=assignments,
        scalar_params=[
            n for n, decl in zip(param_names, param_decls) if "*" not in decl
        ],
        const_call_params=sorted(const_names),
        cfg=function_cfg,
        taint=taint_info,
    )


def analyze_source(
    source: str,
    const_param_positions: set[int] | None = None,
    *,
    language: cst.LanguageName = "c",
) -> FunctionFacts | None:
    """Parse and analyse one C/C++ function; return None if none is present."""
    fn = query.single_function(source, language=language)
    if fn is None:
        return None
    return analyze(
        fn,
        source.encode("utf-8"),
        const_param_positions=const_param_positions,
        language=language,
    )


def _uniq_cap(values, limit: int = 64) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
            if len(out) >= limit:
                break
    return out


__all__ = [
    "ArgFact",
    "AssignFact",
    "CallFact",
    "FunctionFacts",
    "GuardFact",
    "LoopFact",
    "MemFact",
    "analyze",
    "analyze_source",
]
