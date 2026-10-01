"""Extract external-input source facts from C/C++ function bodies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from code_scan import cst, query

from .model import InputSourceFact
from .source_rules import SourceRules

if TYPE_CHECKING:
    from tree_sitter import Node


def _contains(ancestor: "Node | None", node: "Node") -> bool:
    return (
        ancestor is not None
        and ancestor.start_byte <= node.start_byte
        and node.end_byte <= ancestor.end_byte
    )


def return_target(call_node: "Node", source: bytes) -> tuple[str, ...]:
    """Return the local variable receiving a call result, when it is explicit."""
    current = call_node
    while current.parent is not None:
        parent = current.parent
        if parent.type == "init_declarator":
            value = parent.child_by_field_name("value")
            declarator = parent.child_by_field_name("declarator")
            if _contains(value, call_node) and declarator is not None:
                name = cst.declarator_name(declarator, source)
                return (name,) if name else ()
        if parent.type == "assignment_expression":
            right = parent.child_by_field_name("right")
            left = parent.child_by_field_name("left")
            if (
                _contains(right, call_node)
                and left is not None
                and left.type == "identifier"
            ):
                return (cst.node_text(left, source),)
        if parent.type in cst.STATEMENT_TYPES:
            break
        current = parent
    return ()


def _argument_variables(node: "Node", source: bytes) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                cst.node_text(identifier, source)
                for identifier in cst.walk(node, "identifier")
            }
        )
    )


def find_input_sources(
    node: "Node",
    source: bytes,
    rules: SourceRules,
    *,
    function: str | None = None,
    path: str | None = None,
) -> list[InputSourceFact]:
    """Extract configured source calls and variables they taint."""
    facts: list[InputSourceFact] = []
    for call in query.find_calls(node, source):
        matching = rules.matching(call.name)
        if not matching:
            continue
        arguments = call.node.child_by_field_name("arguments")
        argument_nodes = list(arguments.named_children) if arguments is not None else []
        for rule in matching:
            if rule.output == "argument":
                index = rule.argument_index
                if index is None or index >= len(argument_nodes):
                    continue
                variables = _argument_variables(argument_nodes[index], source)
            else:
                variables = return_target(call.node, source)
            facts.append(
                InputSourceFact(
                    api=call.name,
                    kind=rule.kind,
                    output=rule.output,
                    variables=variables,
                    line=call.line,
                    byte=call.node.start_byte,
                    end_byte=call.node.end_byte,
                    function=function,
                    path=path,
                )
            )
    facts.sort(key=lambda fact: (fact.byte, fact.api, fact.output))
    return facts


def generated_taint(
    sources: list[InputSourceFact],
) -> dict[int, set[str]]:
    generated: dict[int, set[str]] = {}
    for source in sources:
        if source.variables:
            generated.setdefault(source.byte, set()).update(source.variables)
    return generated


__all__ = ["find_input_sources", "generated_taint", "return_target"]
