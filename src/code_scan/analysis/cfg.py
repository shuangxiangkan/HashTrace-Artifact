"""Control-flow graph built from a tree-sitter C function body.

Statement-level CFG (each node wraps one simple statement or a branch/loop
condition), with real edges for ``if``/``while``/``for``/``do``/``switch``,
``return``/``goto``/labels/``break``/``continue``. This is the structure the
dataflow framework runs over; it subsumes the ad-hoc branch-path/return/label
reachability the producers used before.

Deliberately *statement*-level (not full 3-address IL like Semgrep) — enough for
constant propagation, taint, and reachability on decompiled C, at a fraction of
the machinery. Unknown statement kinds degrade to an opaque node with normal
fall-through, so the graph is always well-formed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..cst import node_text

if TYPE_CHECKING:
    from tree_sitter import Node as TSNode

# Statement node types that carry no fall-through (they jump).
_JUMPS = {"return_statement", "goto_statement", "break_statement", "continue_statement"}
_LOOPS = {"while_statement", "for_statement", "do_statement", "for_range_loop"}

# Calls that never return: control does not fall through to the next statement.
# Modelling this stops (e.g.) the `__stack_chk_fail` epilogue from being spliced
# — via a false fall-through edge — into unrelated goto/switch code, which would
# fabricate infeasible cycles (seen inflating UAF/double-free). Names are matched
# with leading underscores stripped (Ghidra emits `__stack_chk_fail` etc.).
_NORETURN = frozenset({
    "stack_chk_fail", "chk_fail", "abort", "exit", "Exit", "assert_fail",
    "assert_perror_fail", "cxa_throw", "cxa_rethrow", "cxa_bad_cast",
    "cxa_bad_typeid", "cxa_pure_virtual", "cxa_deleted_virtual",
    "longjmp", "siglongjmp", "pthread_exit", "libc_fatal", "libc_message",
    "unreachable", "builtin_unreachable", "builtin_trap", "ZSt9terminatev",
    "ZSt17__throw_bad_allocv",
})


@dataclass
class Node:
    id: int
    kind: str          # 'entry'|'exit'|'stmt'|'cond'|'label'
    line: int
    text: str
    cst: "TSNode | None" = None


@dataclass
class CFG:
    entry: int
    exits: set[int]
    nodes: dict[int, Node]
    _succ: dict[int, set[int]] = field(default_factory=dict)
    _pred: dict[int, set[int]] = field(default_factory=dict)
    reachable: set[int] = field(default_factory=set)
    back_edges: set[tuple[int, int]] = field(default_factory=set)  # loop back-edges
    cond_true: dict[int, set[int]] = field(default_factory=dict)   # cond -> true-succs

    def succ(self, i: int) -> set[int]:
        return self._succ.get(i, set())

    def pred(self, i: int) -> set[int]:
        return self._pred.get(i, set())


class _Builder:
    def __init__(self, src: bytes):
        self.src = src
        self.nodes: dict[int, Node] = {}
        self.succ: dict[int, set[int]] = {}
        self.pred: dict[int, set[int]] = {}
        self._n = 0
        self.labels: dict[str, int] = {}
        self.pending_gotos: list[tuple[int, str]] = []
        # stacks of (continue_target, break_target) for enclosing loops/switches
        self.loop_stack: list[tuple[int | None, int]] = []
        self.cond_true: dict[int, set[int]] = {}  # cond -> true-branch succs
        self.entry = self._new("entry", None)
        self.exit = self._new("exit", None)

    def _new(self, kind: str, cst: "TSNode | None") -> int:
        i = self._n
        self._n += 1
        line = (cst.start_point[0] + 1) if cst is not None else 0
        text = node_text(cst, self.src)[:200] if cst is not None else kind
        self.nodes[i] = Node(id=i, kind=kind, line=line, text=text, cst=cst)
        self.succ[i] = set()
        self.pred[i] = set()
        return i

    def _edge(self, a: int, b: int) -> None:
        self.succ[a].add(b)
        self.pred[b].add(a)

    def _field(self, node: "TSNode", name: str):
        return node.child_by_field_name(name)

    def _stmts(self, node: "TSNode") -> list["TSNode"]:
        """Named child statements of a compound_statement (or a single stmt)."""
        if node.type == "compound_statement":
            return [c for c in node.children if c.is_named and c.type != "comment"]
        return [node]

    # Each _build_* returns (entries, exits): entry node ids to wire predecessors
    # into, and exit node ids that fall through to whatever follows.
    def build_seq(self, stmts: list["TSNode"]) -> tuple[list[int], list[int]]:
        entries: list[int] | None = None
        exits: list[int] = []
        for st in stmts:
            en, ex = self.build_stmt(st)
            if entries is None:
                entries = en
            for e in exits:
                for a in en:
                    self._edge(e, a)
            exits = ex
        if entries is None:
            return [], []
        return entries, exits

    def build_stmt(self, node: "TSNode") -> tuple[list[int], list[int]]:
        t = node.type
        if t == "compound_statement":
            return self.build_seq(self._stmts(node))
        if t == "if_statement":
            return self._build_if(node)
        if t in _LOOPS:
            return self._build_loop(node)
        if t == "switch_statement":
            return self._build_switch(node)
        if t == "case_statement":
            return self._build_case(node)
        if t == "labeled_statement":
            return self._build_labeled(node)
        if t == "return_statement":
            n = self._new("stmt", node)
            self._edge(n, self.exit)
            return [n], []
        if t == "goto_statement":
            n = self._new("stmt", node)
            lbl = self._field(node, "label")
            if lbl is not None:
                self.pending_gotos.append((n, node_text(lbl, self.src)))
            return [n], []
        if t in ("break_statement", "continue_statement"):
            n = self._new("stmt", node)
            if self.loop_stack:
                cont, brk = self.loop_stack[-1]
                tgt = brk if t == "break_statement" else cont
                if tgt is not None:
                    self._edge(n, tgt)
            return [n], []
        # A call to a noreturn function does not fall through — wire it to exit.
        if self._is_noreturn_stmt(node):
            n = self._new("stmt", node)
            self._edge(n, self.exit)
            return [n], []
        # A comma expression sequences its operands: `free(p), use(p)` must be two
        # ordered nodes, else an intra-node free+use collapses and the UAF is lost.
        if t == "expression_statement":
            inner = [c for c in node.children if c.is_named and c.type != "comment"]
            if len(inner) == 1 and inner[0].type == "comma_expression":
                parts = self._flatten_comma(inner[0])
                if len(parts) > 1:
                    ids = [self._new("stmt", p) for p in parts]
                    for a, b in zip(ids, ids[1:]):
                        self._edge(a, b)
                    return [ids[0]], [ids[-1]]
        # declaration, and anything else: opaque node, normal fall-through.
        n = self._new("stmt", node)
        return [n], [n]

    def _is_noreturn_stmt(self, node: "TSNode") -> bool:
        """True if ``node`` is an expression statement calling a noreturn function."""
        if node.type != "expression_statement":
            return False
        inner = [c for c in node.children if c.is_named and c.type != "comment"]
        if not inner or inner[0].type != "call_expression":
            return False
        fn = inner[0].child_by_field_name("function")
        if fn is None:
            return False
        return node_text(fn, self.src).lstrip("_") in _NORETURN

    def _flatten_comma(self, node: "TSNode") -> list["TSNode"]:
        """Left-to-right operands of a (possibly nested) comma_expression."""
        if node.type != "comma_expression":
            return [node]
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        out: list["TSNode"] = []
        out += self._flatten_comma(left) if left is not None else []
        out += self._flatten_comma(right) if right is not None else []
        return out or [node]

    def _build_if(self, node: "TSNode") -> tuple[list[int], list[int]]:
        cond = self._new("cond", self._field(node, "condition") or node)
        cons = self._field(node, "consequence")
        alt = self._field(node, "alternative")
        # tree-sitter-c wraps the else branch in an `else_clause` (else + stmt);
        # unwrap to the inner statement (a block, or another if for `else if`).
        if alt is not None and alt.type == "else_clause":
            inner = [c for c in alt.children if c.is_named and c.type != "comment"]
            alt = inner[-1] if inner else None
        exits: list[int] = []
        # An empty branch (`if(c){}`) must still leave a fall-through edge from the
        # cond — otherwise that path vanishes and dataflow facts on it are lost.
        if cons is not None:
            ten, tex = self.build_stmt(cons)
            if ten:
                for a in ten:
                    self._edge(cond, a)
                self.cond_true[cond] = set(ten)  # the 'true' branch of the if
                exits += tex
            else:
                exits.append(cond)  # empty consequence: true edge falls through
        else:
            exits.append(cond)
        if alt is not None:
            aen, aex = self.build_stmt(alt)
            if aen:
                for a in aen:
                    self._edge(cond, a)
                exits += aex
            else:
                exits.append(cond)  # empty else: false edge falls through
        else:
            exits.append(cond)  # no else: cond can fall through
        return [cond], exits

    def _build_loop(self, node: "TSNode") -> tuple[list[int], list[int]]:
        is_do = node.type == "do_statement"
        cond_node = self._field(node, "condition")
        cond = self._new("cond", cond_node or node)
        # An infinite loop (`while(true)`, `for(;;)`, `do..while(1)`) has no real
        # condition-false exit — only `break`/`return`/`goto` leave it. Emitting a
        # phantom cond->exit edge creates a path that skips the loop body, which
        # (e.g.) lets stale dataflow facts bypass the body's kills. Suppress it.
        cond_txt = (
            node_text(cond_node, self.src).strip().strip("()").strip()
            if cond_node is not None else ""
        )
        always_true = (
            cond_node is None and node.type != "for_range_loop"
        ) or cond_txt in ("true", "1")
        loop_exit = self._new("stmt", node)  # virtual post-loop join (break target)
        # `for` init runs once before the loop; `for` update runs after each body.
        pre_entry: int | None = None
        init = self._field(node, "initializer")
        if init is not None:
            pre_entry = self._new("stmt", init)
        update = self._field(node, "update")
        upd_node = self._new("stmt", update) if update is not None else None

        # continue jumps to the update (for) or the condition (while/do).
        cont_target = upd_node if upd_node is not None else cond
        self.loop_stack.append((cont_target, loop_exit))
        body = self._field(node, "body")
        ben, bex = self.build_stmt(body) if body is not None else ([cond], [cond])
        self.loop_stack.pop()

        back = upd_node if upd_node is not None else cond
        if upd_node is not None:
            self._edge(upd_node, cond)   # update -> re-test condition
        for e in bex:
            self._edge(e, back)          # body falls through to update/cond
        for a in ben:
            self._edge(cond, a)          # cond true -> body
        self.cond_true[cond] = set(ben)  # loop body is the 'true' branch
        if not always_true:
            self._edge(cond, loop_exit)  # cond false -> exit (real loops only)

        if is_do:
            # body executes first; entry is the body, then body -> cond.
            entry_nodes = ben
        elif pre_entry is not None:
            self._edge(pre_entry, cond)
            entry_nodes = [pre_entry]
        else:
            entry_nodes = [cond]
        return entry_nodes, [loop_exit]

    def _build_case(self, node: "TSNode") -> tuple[list[int], list[int]]:
        """A ``case``/``default`` clause: decompose its statements into the CFG
        (previously opaque, which hid intra-case free/use ordering)."""
        value = self._field(node, "value")
        vid = value.id if value is not None else None
        stmts = [
            c for c in node.children
            if c.is_named and c.type != "comment" and c.id != vid
        ]
        en, ex = self.build_seq(stmts)
        if not en:  # empty case: passthrough marker so fall-through still connects
            n = self._new("label", node)
            return [n], [n]
        return en, ex

    def _build_switch(self, node: "TSNode") -> tuple[list[int], list[int]]:
        cond = self._new("cond", self._field(node, "condition") or node)
        body = self._field(node, "body")
        loop_exit = self._new("stmt", node)
        self.loop_stack.append((None, loop_exit))  # break targets switch end
        prev_ex: list[int] = []
        if body is not None:
            for case in [c for c in body.children if c.is_named and c.type != "comment"]:
                en, ex = self.build_stmt(case)
                self._edge(cond, en[0] if en else loop_exit)
                for e in prev_ex:  # fall-through between cases
                    for a in en:
                        self._edge(e, a)
                prev_ex = ex
        for e in prev_ex:
            self._edge(e, loop_exit)
        self._edge(cond, loop_exit)  # default/no-match
        self.loop_stack.pop()
        return [cond], [loop_exit]

    def _build_labeled(self, node: "TSNode") -> tuple[list[int], list[int]]:
        lbl = self._field(node, "label")
        n = self._new("label", node)
        if lbl is not None:
            self.labels[node_text(lbl, self.src)] = n
        # the statement the label prefixes
        inner = [c for c in node.children if c.is_named and c.type not in ("comment",)
                 and c != lbl]
        if inner:
            en, ex = self.build_stmt(inner[-1])
            for a in en:
                self._edge(n, a)
            return [n], ex
        return [n], [n]

    def finish(self, body: "TSNode") -> CFG:
        en, ex = self.build_stmt(body)
        for a in en:
            self._edge(self.entry, a)
        for e in ex:
            self._edge(e, self.exit)
        # resolve gotos
        for gnode, name in self.pending_gotos:
            tgt = self.labels.get(name)
            if tgt is not None:
                self._edge(gnode, tgt)
        # reachability from entry
        reachable: set[int] = set()
        stack = [self.entry]
        while stack:
            x = stack.pop()
            if x in reachable:
                continue
            reachable.add(x)
            stack.extend(self.succ[x])
        # back-edges (loop edges) via iterative DFS: an edge to a node currently
        # on the DFS path is a back-edge. Used for acyclic reachability so
        # loop-carried pairs aren't treated as straight-line reachable.
        back: set[tuple[int, int]] = set()
        color: dict[int, int] = {}  # 0=gray(on path), 1=black(done)
        it: list[tuple[int, "list"]] = [(self.entry, list(self.succ[self.entry]))]
        color[self.entry] = 0
        while it:
            node, kids = it[-1]
            if kids:
                c = kids.pop()
                if color.get(c) == 0:
                    back.add((node, c))
                elif c not in color:
                    color[c] = 0
                    it.append((c, list(self.succ[c])))
            else:
                color[node] = 1
                it.pop()
        return CFG(
            entry=self.entry, exits={self.exit}, nodes=self.nodes,
            _succ=self.succ, _pred=self.pred, reachable=reachable, back_edges=back,
            cond_true=self.cond_true,
        )


def build_cfg(body: "TSNode", src: bytes) -> CFG:
    """Build a statement-level CFG from a function's ``compound_statement``."""
    return _Builder(src).finish(body)


def reaches(cfg: CFG, a: int, b: int, *, acyclic: bool = False) -> bool:
    """Is node ``b`` reachable from node ``a`` along control-flow edges?

    Subsumes the old branch-path / return / goto-label heuristics: mutually
    exclusive ``if``/``else`` arms have no path between them, a ``return`` before
    ``b`` cuts the path, and a ``b`` behind a label is reachable only via a real
    edge. With ``acyclic=True`` loop back-edges are skipped, so a free and a use
    in exclusive branches are not paired just because a surrounding loop could
    reach one from the other on a later iteration.
    """
    if a == b:
        return True
    seen: set[int] = set()
    stack = [a]
    while stack:
        x = stack.pop()
        for s in cfg.succ(x):
            if acyclic and (x, s) in cfg.back_edges:
                continue
            if s == b:
                return True
            if s not in seen:
                seen.add(s)
                stack.append(s)
    return False


def line_to_node(cfg: CFG) -> dict[int, int]:
    """Map each source line to a representative reachable CFG node on it."""
    out: dict[int, int] = {}
    for nid, node in cfg.nodes.items():
        if node.line and nid in cfg.reachable:
            out[node.line] = nid
    return out


def byte_index(cfg: CFG) -> list[tuple[int, int, int]]:
    """Sorted ``(start, end, node_id)`` spans of reachable CST-backed nodes, for
    :func:`node_for_byte`. Uses byte spans (not lines) so several statements on
    one decompiled line map to distinct nodes."""
    spans: list[tuple[int, int, int]] = []
    for nid, node in cfg.nodes.items():
        if nid in cfg.reachable and node.cst is not None:
            spans.append((node.cst.start_byte, node.cst.end_byte, nid))
    spans.sort()
    return spans


def node_for_byte(index: list[tuple[int, int, int]], byte: int) -> int | None:
    """Most-specific (smallest, innermost) reachable node whose span contains
    ``byte``. Ties broken toward the tightest span so a fact lands on its own
    statement node rather than an enclosing one."""
    best: tuple[int, int] | None = None  # (span_width, node_id)
    best_nid: int | None = None
    for start, end, nid in index:
        if start > byte:
            break
        if start <= byte < end:
            width = end - start
            if best is None or width < best[0]:
                best = (width, nid)
                best_nid = nid
    return best_nid


__all__ = [
    "CFG", "Node", "build_cfg", "reaches",
    "line_to_node", "byte_index", "node_for_byte",
]
