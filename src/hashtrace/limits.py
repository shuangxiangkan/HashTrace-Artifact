"""Detect quantity bounds and capacity-related context around hash operations."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from code_scan import cst, query, ssa
from code_scan.analysis import cfg as cfg_mod

from .extract import resolve_container
from .model import HashContainerFact, HashLimitFact, HashOperationFact

if TYPE_CHECKING:
    from tree_sitter import Node


_LOOP_TYPES = {"for_statement", "while_statement", "do_statement", "for_range_loop"}
_CAPACITY_METHODS = {"reserve", "rehash", "max_load_factor"}
_SWAP_COMPARISON = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}
_INT_LITERAL = re.compile(r"^[+-]?(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*$")
_CONSTANT_NAME = re.compile(
    r"^(?:(?:[A-Z][A-Z0-9_]*)|(?:k[A-Z][A-Za-z0-9_]*))"
    r"(?:::(?:[A-Z][A-Z0-9_]*|k[A-Z][A-Za-z0-9_]*))*$"
)


@dataclass(frozen=True)
class _SizeBound:
    receiver: str
    safe_when_true: bool
    expression: str
    limit_value: int | None
    fixed_limit: bool
    condition: "Node"
    line: int


def _unwrap(node: "Node | None") -> "Node | None":
    current = node
    while current is not None and current.type in {
        "condition_clause",
        "parenthesized_expression",
    }:
        value = current.child_by_field_name("value")
        children = [
            child for child in current.named_children if child.type != "comment"
        ]
        current = value or (children[0] if children else None)
    return current


def _parse_int(text: str) -> int | None:
    clean = text.strip()
    while clean.startswith("(") and clean.endswith(")"):
        clean = clean[1:-1].strip()
    if not _INT_LITERAL.fullmatch(clean):
        return None
    clean = re.sub(r"[uUlL]+$", "", clean)
    try:
        return int(clean, 0)
    except ValueError:
        return None


def _size_receiver(node: "Node", source: bytes) -> str | None:
    expression = _unwrap(node)
    if expression is None or expression.type != "call_expression":
        return None
    call = next(
        (
            call
            for call in query.find_calls(expression, source)
            if call.node.id == expression.id
        ),
        None,
    )
    if call is None or call.name != "size" or call.receiver is None or call.args:
        return None
    return call.receiver


def _size_bound(
    if_statement: "Node", source: bytes, definitions: ssa.Defs
) -> _SizeBound | None:
    condition = if_statement.child_by_field_name("condition")
    comparison = _unwrap(condition)
    if comparison is None or comparison.type != "binary_expression":
        return None
    left = comparison.child_by_field_name("left")
    right = comparison.child_by_field_name("right")
    operator = comparison.child_by_field_name("operator")
    if left is None or right is None or operator is None:
        return None
    op = cst.node_text(operator, source)
    if op not in _SWAP_COMPARISON:
        return None

    receiver = _size_receiver(left, source)
    limit_node = right
    if receiver is None:
        receiver = _size_receiver(right, source)
        limit_node = left
        op = _SWAP_COMPARISON[op]
    if receiver is None:
        return None

    limit_text = cst.node_text(limit_node, source)
    raw_limit = _parse_int(limit_text)
    if raw_limit is None:
        raw_limit = _parse_int(ssa.expand(limit_text, definitions))
    fixed_limit = raw_limit is not None or bool(
        _CONSTANT_NAME.fullmatch("".join(limit_text.split()).lstrip(":"))
    )
    safe_when_true = op in {"<", "<="}
    if raw_limit is None:
        effective_limit = None
    elif op in {"<", ">="}:
        effective_limit = raw_limit - 1
    else:
        effective_limit = raw_limit
    return _SizeBound(
        receiver=receiver,
        safe_when_true=safe_when_true,
        expression=cst.node_text(comparison, source),
        limit_value=effective_limit,
        fixed_limit=fixed_limit,
        condition=condition or comparison,
        line=cst.line_of(if_statement),
    )


def _dominators(cfg: cfg_mod.CFG) -> dict[int, set[int]]:
    reachable = set(cfg.reachable)
    dominators = {node: set(reachable) for node in reachable}
    dominators[cfg.entry] = {cfg.entry}
    changed = True
    while changed:
        changed = False
        for node in reachable - {cfg.entry}:
            predecessors = [pred for pred in cfg.pred(node) if pred in reachable]
            shared = (
                set.intersection(*(dominators[pred] for pred in predecessors))
                if predecessors
                else set()
            )
            updated = {node} | shared
            if updated != dominators[node]:
                dominators[node] = updated
                changed = True
    return dominators


def _postdominators(cfg: cfg_mod.CFG) -> dict[int, set[int]]:
    exit_node = next(iter(cfg.exits))
    reaches_exit = {
        node
        for node in cfg.reachable
        if cfg_mod.reaches(cfg, node, exit_node)
    }
    postdominators = {node: set(reaches_exit) for node in reaches_exit}
    postdominators[exit_node] = {exit_node}
    changed = True
    while changed:
        changed = False
        for node in reaches_exit - {exit_node}:
            successors = [succ for succ in cfg.succ(node) if succ in reaches_exit]
            shared = (
                set.intersection(*(postdominators[succ] for succ in successors))
                if successors
                else set()
            )
            updated = {node} | shared
            if updated != postdominators[node]:
                postdominators[node] = updated
                changed = True
    return postdominators


def _guard_applies(
    bound: _SizeBound,
    operation_node: int,
    cfg: cfg_mod.CFG,
    byte_index: list[tuple[int, int, int]],
    dominators: dict[int, set[int]],
) -> bool:
    condition_node = cfg_mod.node_for_byte(byte_index, bound.condition.start_byte)
    if condition_node is None or condition_node == operation_node:
        return False
    if condition_node not in dominators.get(operation_node, set()):
        return False
    true_successors = cfg.cond_true.get(condition_node, set())
    false_successors = cfg.succ(condition_node) - true_successors

    def reaches_operation(successors: set[int]) -> bool:
        return any(
            cfg_mod.reaches(cfg, successor, operation_node, acyclic=True)
            for successor in successors
        )

    true_reaches = reaches_operation(true_successors)
    false_reaches = reaches_operation(false_successors)
    if bound.safe_when_true:
        return true_reaches and not false_reaches
    return false_reaches and not true_reaches


def _container_cap_adjustment(
    limit: int | None, fixed_limit: bool
) -> tuple[str, float]:
    if not fixed_limit:
        return "context", 0.0
    if limit is None:
        return "partial", -1.0
    if limit <= 1024:
        return "strong", -3.0
    if limit <= 10000:
        return "partial", -2.0
    if limit <= 100000:
        return "partial", -0.5
    return "context", 0.0


def _operation_cap_adjustment(
    limit: int | None, fixed_limit: bool = True
) -> tuple[str, float]:
    if not fixed_limit:
        return "context", 0.0
    if limit is None:
        return "partial", -0.5
    if limit <= 256:
        return "partial", -1.5
    if limit <= 4096:
        return "partial", -0.5
    return "context", 0.0


def _eviction_adjustment(
    limit: int | None, fixed_limit: bool
) -> tuple[str, float]:
    if not fixed_limit:
        return "context", 0.0
    if limit is None:
        return "partial", -0.5
    if limit <= 1024:
        return "partial", -2.0
    if limit <= 10000:
        return "partial", -1.0
    if limit <= 100000:
        return "partial", -0.5
    return "context", 0.0


def _normal_expression(text: str) -> str:
    return "".join(text.split())


def _operation_cst(
    body: "Node", operation: HashOperationFact
) -> "Node | None":
    matches = [
        node
        for node in cst.walk(body)
        if node.start_byte == operation.byte and node.end_byte == operation.end_byte
    ]
    return min(matches, key=lambda node: node.end_byte - node.start_byte, default=None)


def _loop_step(update: "Node", counter: str, source: bytes) -> int | None:
    text = re.sub(r"\s+", "", cst.node_text(update, source))
    escaped = re.escape(counter)
    if re.fullmatch(rf"(?:\+\+{escaped}|{escaped}\+\+)", text):
        return 1
    if re.fullmatch(rf"(?:--{escaped}|{escaped}--)", text):
        return -1
    match = re.fullmatch(rf"{escaped}([+-])=([^;]+)", text)
    if match:
        amount = _parse_int(match.group(2))
        if amount is not None and amount > 0:
            return amount if match.group(1) == "+" else -amount
    return None


def _for_loop_count(loop: "Node", source: bytes) -> int | None:
    if loop.type != "for_statement":
        return None
    initializer = loop.child_by_field_name("initializer")
    condition = _unwrap(loop.child_by_field_name("condition"))
    update = loop.child_by_field_name("update")
    body = loop.child_by_field_name("body")
    if (
        initializer is None
        or condition is None
        or update is None
        or condition.type != "binary_expression"
    ):
        return None
    left = condition.child_by_field_name("left")
    right = condition.child_by_field_name("right")
    operator = condition.child_by_field_name("operator")
    if left is None or right is None or operator is None:
        return None
    op = cst.node_text(operator, source)
    if op not in _SWAP_COMPARISON:
        return None
    if left.type == "identifier":
        counter = cst.node_text(left, source)
        end = _parse_int(cst.node_text(right, source))
    elif right.type == "identifier":
        counter = cst.node_text(right, source)
        end = _parse_int(cst.node_text(left, source))
        op = _SWAP_COMPARISON[op]
    else:
        return None
    if end is None:
        return None

    starts = [
        assignment
        for assignment in query.find_assignments(initializer, source)
        if assignment.lhs.strip() == counter
    ]
    if not starts:
        return None
    start = _parse_int(starts[-1].rhs)
    step = _loop_step(update, counter, source)
    if start is None or step is None:
        return None

    if body is not None:
        if any(
            assignment.lhs.strip() == counter
            for assignment in query.find_assignments(body, source)
        ):
            return None
        if any(
            (argument := change.child_by_field_name("argument")) is not None
            and cst.node_text(argument, source).strip() == counter
            for change in cst.walk(body, "update_expression")
        ):
            return None

    if step > 0 and op in {"<", "<="}:
        if start > end or (start == end and op == "<"):
            return 0
        distance = end - start
        return math.ceil(distance / step) if op == "<" else distance // step + 1
    if step < 0 and op in {">", ">="}:
        if start < end or (start == end and op == ">"):
            return 0
        distance = start - end
        stride = -step
        return math.ceil(distance / stride) if op == ">" else distance // stride + 1
    return None


def _enclosing_loops(node: "Node") -> list["Node"]:
    loops: list["Node"] = []
    current = node.parent
    while current is not None:
        if current.type in _LOOP_TYPES:
            loops.append(current)
        if current.type == "function_definition":
            break
        current = current.parent
    return loops


def _bounded_loop_fact(
    operation_cst: "Node", source: bytes
) -> HashLimitFact | None:
    loops = _enclosing_loops(operation_cst)
    if not loops:
        return None
    counts = [_for_loop_count(loop, source) for loop in loops]
    if any(count is None for count in counts):
        return None
    total = math.prod(count for count in counts if count is not None)
    strength, adjustment = _operation_cap_adjustment(total)
    expression = " * ".join(str(count) for count in reversed(counts))
    return HashLimitFact(
        kind="operation-count-cap",
        strength=strength,
        expression=expression,
        limit_value=total,
        score_adjustment=adjustment,
        line=min(cst.line_of(loop) for loop in loops),
        evidence=f"enclosing for-loop(s) cap this hash operation at {total} execution(s)",
    )


def _range_inputs(operation_cst: "Node", source: bytes) -> set[str]:
    inputs: set[str] = set()
    for loop in _enclosing_loops(operation_cst):
        if loop.type != "for_range_loop":
            continue
        right = loop.child_by_field_name("right")
        if right is not None:
            inputs.add(_normal_expression(cst.node_text(right, source)))
    return inputs


def _capacity_context(
    function: query.Function,
    source: bytes,
    containers: list[HashContainerFact],
    container: HashContainerFact,
    operation_node: int,
    cfg: cfg_mod.CFG,
    byte_index: list[tuple[int, int, int]],
    dominators: dict[int, set[int]],
) -> list[HashLimitFact]:
    facts: list[HashLimitFact] = []
    for call in query.find_calls(function.body_node, source):
        if call.name not in _CAPACITY_METHODS or call.receiver is None:
            continue
        receiver = resolve_container(call.receiver, containers)
        if receiver is None or receiver.byte != container.byte:
            continue
        call_node = cfg_mod.node_for_byte(byte_index, call.node.start_byte)
        if call_node is None or call_node not in dominators.get(operation_node, set()):
            continue
        argument = call.args[0] if call.args else ""
        value = _parse_int(argument)
        if call.name == "reserve":
            detail = "preallocates buckets but does not cap entries or collision chains"
        elif call.name == "rehash":
            detail = "changes bucket count but does not prevent equal-hash collisions"
        else:
            detail = "changes the rehash threshold but does not cap collision chains"
        facts.append(
            HashLimitFact(
                kind=call.name.replace("_", "-"),
                strength="context",
                expression=cst.node_text(call.node, source),
                limit_value=value,
                score_adjustment=0.0,
                line=call.line,
                evidence=f"{container.qualified_name}.{call.name}({argument}) {detail}",
            )
        )
    return facts


def _eviction_policy(
    function: query.Function,
    source: bytes,
    containers: list[HashContainerFact],
    container: HashContainerFact,
    operation: HashOperationFact,
    operation_node: int,
    cfg: cfg_mod.CFG,
    byte_index: list[tuple[int, int, int]],
    definitions: ssa.Defs,
) -> list[HashLimitFact]:
    if not operation.may_grow:
        return []
    postdominators = _postdominators(cfg)
    facts: list[HashLimitFact] = []
    for statement in cst.walk(function.body_node, "if_statement"):
        bound = _size_bound(statement, source, definitions)
        if bound is None:
            continue
        resolved = resolve_container(bound.receiver, containers)
        if resolved is None or resolved.byte != container.byte:
            continue
        condition_node = cfg_mod.node_for_byte(
            byte_index, bound.condition.start_byte
        )
        if (
            condition_node is None
            or condition_node == operation_node
            or condition_node not in postdominators.get(operation_node, set())
            or not cfg_mod.reaches(
                cfg, operation_node, condition_node, acyclic=True
            )
        ):
            continue
        true_successors = cfg.cond_true.get(condition_node, set())
        false_successors = cfg.succ(condition_node) - true_successors
        unsafe_successors = (
            false_successors if bound.safe_when_true else true_successors
        )
        if not unsafe_successors:
            continue

        erase_call = None
        for call in query.find_calls(function.body_node, source, {"erase"}):
            target = resolve_container(call.receiver or "", containers)
            if target is None or target.byte != container.byte:
                continue
            erase_node = cfg_mod.node_for_byte(byte_index, call.node.start_byte)
            if erase_node is None:
                continue
            if all(
                erase_node == successor
                or erase_node in postdominators.get(successor, set())
                for successor in unsafe_successors
            ):
                erase_call = call
                break
        if erase_call is None:
            continue

        strength, adjustment = _eviction_adjustment(
            bound.limit_value, bound.fixed_limit
        )
        facts.append(
            HashLimitFact(
                kind="eviction-cap",
                strength=strength,
                expression=bound.expression,
                limit_value=bound.limit_value,
                score_adjustment=adjustment,
                line=bound.line,
                evidence=(
                    f"after growth, {container.qualified_name}.erase(...) is "
                    f"guaranteed on the over-limit branch: {bound.expression}"
                ),
            )
        )
    return facts


def analyze_operation_limits(
    function: query.Function,
    source: bytes,
    containers: list[HashContainerFact],
    container: HashContainerFact,
    operation: HashOperationFact,
    cfg: cfg_mod.CFG,
) -> tuple[HashLimitFact, ...]:
    """Return proven bounds and capacity context for one hash operation."""
    byte_index = cfg_mod.byte_index(cfg)
    operation_node = cfg_mod.node_for_byte(byte_index, operation.byte)
    operation_cst = _operation_cst(function.body_node, operation)
    if operation_node is None or operation_cst is None:
        return ()
    dominators = _dominators(cfg)
    definitions = ssa.build_defs(function.body_node, source)
    range_inputs = _range_inputs(operation_cst, source)
    limits: list[HashLimitFact] = []

    for if_statement in cst.walk(function.body_node, "if_statement"):
        bound = _size_bound(if_statement, source, definitions)
        if bound is None or not _guard_applies(
            bound, operation_node, cfg, byte_index, dominators
        ):
            continue
        resolved = resolve_container(bound.receiver, containers)
        normalized_receiver = _normal_expression(bound.receiver)
        if resolved is not None and resolved.byte == container.byte:
            strength, adjustment = _container_cap_adjustment(
                bound.limit_value, bound.fixed_limit
            )
            limits.append(
                HashLimitFact(
                    kind="container-size-cap",
                    strength=strength,
                    expression=bound.expression,
                    limit_value=bound.limit_value,
                    score_adjustment=adjustment,
                    line=bound.line,
                    evidence=(
                        f"control flow limits {container.qualified_name}.size() "
                        f"before this operation: {bound.expression}"
                    ),
                )
            )
        elif normalized_receiver in range_inputs:
            strength, adjustment = _operation_cap_adjustment(
                bound.limit_value, bound.fixed_limit
            )
            limits.append(
                HashLimitFact(
                    kind="input-size-cap",
                    strength=strength,
                    expression=bound.expression,
                    limit_value=bound.limit_value,
                    score_adjustment=adjustment,
                    line=bound.line,
                    evidence=(
                        f"range input {bound.receiver} is size-limited before "
                        f"this hash operation: {bound.expression}"
                    ),
                )
            )

    loop_fact = _bounded_loop_fact(operation_cst, source)
    if loop_fact is not None:
        limits.append(loop_fact)
    limits.extend(
        _capacity_context(
            function,
            source,
            containers,
            container,
            operation_node,
            cfg,
            byte_index,
            dominators,
        )
    )
    limits.extend(
        _eviction_policy(
            function,
            source,
            containers,
            container,
            operation,
            operation_node,
            cfg,
            byte_index,
            definitions,
        )
    )
    unique = {
        (fact.kind, fact.line, fact.expression): fact
        for fact in limits
    }
    return tuple(
        sorted(unique.values(), key=lambda fact: (fact.line, fact.kind))
    )


__all__ = ["analyze_operation_limits"]
