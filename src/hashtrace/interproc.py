"""Project-level propagation of external-input taint through direct calls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping

from code_scan import cst, facts, query, ssa
from code_scan.analysis import taint as taint_mod

from .model import InputSourceFact
from .source_rules import DEFAULT_SOURCE_RULES, SourceRules
from .sources import find_input_sources, generated_taint, return_target

if TYPE_CHECKING:
    from tree_sitter import Node


@dataclass(frozen=True)
class FunctionUnit:
    """One parsed project function and the source buffer that owns its CST."""

    key: str
    function: query.Function
    source: bytes
    language: cst.LanguageName = "cpp"
    path: str | None = None


@dataclass(frozen=True)
class TaintFlowPoint:
    """A call in the current function carrying original source provenance."""

    byte: int
    end_byte: int
    variables: tuple[str, ...]
    sources: tuple[InputSourceFact, ...]


@dataclass(frozen=True)
class ExternalTaintContext:
    """Final external-taint state consumed by the HashDoS detector."""

    taint: taint_mod.TaintInfo
    input_sources: tuple[InputSourceFact, ...]
    parameter_sources: Mapping[str, tuple[InputSourceFact, ...]]
    flow_points: tuple[TaintFlowPoint, ...]
    # The per-function analysis computed while preparing units. Carried so the
    # detector can reuse the CFG and parameter taint instead of recomputing them.
    function_facts: "facts.FunctionFacts | None" = None


@dataclass
class _PreparedUnit:
    unit: FunctionUnit
    function_facts: facts.FunctionFacts
    definitions: ssa.Defs
    calls: list[query.Call]
    returns: list[query.Return]
    local_sources: list[InputSourceFact]


def _source_key(source: InputSourceFact) -> tuple[object, ...]:
    return (
        source.path or "",
        source.function or "",
        source.byte,
        source.end_byte,
        source.api,
        source.output,
        source.kind,
        source.variables,
    )


def _ordered_sources(
    sources: set[InputSourceFact] | list[InputSourceFact] | tuple[InputSourceFact, ...],
) -> tuple[InputSourceFact, ...]:
    return tuple(sorted(set(sources), key=_source_key))


def _terminal_name(name: str) -> str:
    return name.rsplit("::", 1)[-1]


def _argument_nodes(call: query.Call) -> list["Node"]:
    arguments = call.node.child_by_field_name("arguments")
    return list(arguments.named_children) if arguments is not None else []


def _targets_by_call(
    prepared: list[_PreparedUnit],
) -> dict[tuple[str, int], tuple[_PreparedUnit, ...]]:
    by_name: dict[str, list[_PreparedUnit]] = {}
    for item in prepared:
        by_name.setdefault(_terminal_name(item.unit.function.name), []).append(item)

    targets: dict[tuple[str, int], tuple[_PreparedUnit, ...]] = {}
    for caller in prepared:
        for call in caller.calls:
            if call.indirect:
                continue
            matches = by_name.get(_terminal_name(call.name), [])
            if matches:
                targets[(caller.unit.key, call.node.start_byte)] = tuple(matches)
    return targets


def _point_sources_in_span(
    points: list[TaintFlowPoint] | tuple[TaintFlowPoint, ...],
    start_byte: int,
    end_byte: int,
) -> set[InputSourceFact]:
    out: set[InputSourceFact] = set()
    for point in points:
        if start_byte <= point.byte and point.end_byte <= end_byte:
            out.update(point.sources)
    return out


def _sources_for_expression(
    *,
    taint: taint_mod.TaintInfo,
    parameter_sources: Mapping[str, set[InputSourceFact]],
    points: list[TaintFlowPoint] | tuple[TaintFlowPoint, ...],
    all_sources: set[InputSourceFact],
    definitions: ssa.Defs,
    byte: int,
    end_byte: int,
    expression: str,
) -> set[InputSourceFact]:
    direct = _point_sources_in_span(points, byte, end_byte)
    tainted_vars = taint.tainted_vars_at(byte, expression)
    if not direct and not tainted_vars:
        return set()

    lineage = taint.vars_of(expression) | tainted_vars
    lineage.update(ssa.origins(expression, definitions))
    related = set(direct)
    for parameter, sources in parameter_sources.items():
        if parameter in lineage:
            related.update(sources)
    for point in points:
        if point.byte <= byte and set(point.variables) & lineage:
            related.update(point.sources)
    return related or set(all_sources)


def sources_for_expression(
    context: ExternalTaintContext,
    definitions: ssa.Defs,
    *,
    byte: int,
    end_byte: int,
    expression: str,
) -> tuple[InputSourceFact, ...]:
    """Return original external sources that can reach one local expression."""
    related = _sources_for_expression(
        taint=context.taint,
        parameter_sources={
            name: set(sources) for name, sources in context.parameter_sources.items()
        },
        points=context.flow_points,
        all_sources=set(context.input_sources),
        definitions=definitions,
        byte=byte,
        end_byte=end_byte,
        expression=expression,
    )
    return _ordered_sources(related)


def _prepare_units(
    units: list[FunctionUnit], rules: SourceRules
) -> list[_PreparedUnit]:
    prepared: list[_PreparedUnit] = []
    for unit in units:
        function_name = unit.function.qualified_name or unit.function.name
        prepared.append(
            _PreparedUnit(
                unit=unit,
                function_facts=facts.analyze(
                    unit.function, unit.source, language=unit.language
                ),
                definitions=ssa.build_defs(unit.function.body_node, unit.source),
                calls=query.find_calls(unit.function.body_node, unit.source),
                returns=query.find_returns(unit.function.body_node, unit.source),
                local_sources=find_input_sources(
                    unit.function.body_node,
                    unit.source,
                    rules,
                    function=function_name,
                    path=unit.path,
                ),
            )
        )
    return prepared


def _evaluate(
    item: _PreparedUnit,
    targets: Mapping[tuple[str, int], tuple[_PreparedUnit, ...]],
    parameter_state: Mapping[str, list[set[InputSourceFact]]],
    return_state: Mapping[str, set[InputSourceFact]],
) -> tuple[
    ExternalTaintContext,
    dict[tuple[str, int], set[InputSourceFact]],
    set[InputSourceFact],
]:
    params = item.function_facts.params
    incoming = parameter_state[item.unit.key]
    parameter_sources = {
        param: set(incoming[index])
        for index, param in enumerate(params)
        if incoming[index]
    }
    seeded_params = set(parameter_sources)

    points: list[TaintFlowPoint] = [
        TaintFlowPoint(
            byte=source.byte,
            end_byte=source.end_byte,
            variables=source.variables,
            sources=(source,),
        )
        for source in item.local_sources
    ]
    generated = generated_taint(item.local_sources)
    for call in item.calls:
        callees = targets.get((item.unit.key, call.node.start_byte), ())
        provenance: set[InputSourceFact] = set()
        for callee in callees:
            provenance.update(return_state[callee.unit.key])
        if not provenance:
            continue
        variables = return_target(call.node, item.unit.source)
        points.append(
            TaintFlowPoint(
                byte=call.node.start_byte,
                end_byte=call.node.end_byte,
                variables=variables,
                sources=_ordered_sources(provenance),
            )
        )
        if variables:
            generated.setdefault(call.node.start_byte, set()).update(variables)

    taint = taint_mod.analyze(
        item.function_facts.cfg,
        item.unit.source,
        seeded_params,
        generated_at_byte=generated,
    )
    all_sources = set(item.local_sources)
    for source_set in incoming:
        all_sources.update(source_set)
    for point in points:
        all_sources.update(point.sources)

    propagated: dict[tuple[str, int], set[InputSourceFact]] = {}
    for call in item.calls:
        callees = targets.get((item.unit.key, call.node.start_byte), ())
        if not callees:
            continue
        argument_nodes = _argument_nodes(call)
        for index, argument in enumerate(argument_nodes):
            expression = cst.node_text(argument, item.unit.source)
            sources = _sources_for_expression(
                taint=taint,
                parameter_sources=parameter_sources,
                points=points,
                all_sources=all_sources,
                definitions=item.definitions,
                byte=argument.start_byte,
                end_byte=argument.end_byte,
                expression=expression,
            )
            if not sources:
                continue
            for callee in callees:
                if index < len(callee.function_facts.params):
                    propagated.setdefault((callee.unit.key, index), set()).update(
                        sources
                    )

    returned: set[InputSourceFact] = set()
    for result in item.returns:
        if result.value is None:
            continue
        returned.update(
            _sources_for_expression(
                taint=taint,
                parameter_sources=parameter_sources,
                points=points,
                all_sources=all_sources,
                definitions=item.definitions,
                byte=result.node.start_byte,
                end_byte=result.node.end_byte,
                expression=result.value,
            )
        )

    context = ExternalTaintContext(
        taint=taint,
        input_sources=_ordered_sources(all_sources),
        parameter_sources={
            name: _ordered_sources(sources)
            for name, sources in parameter_sources.items()
        },
        flow_points=tuple(sorted(points, key=lambda point: point.byte)),
        function_facts=item.function_facts,
    )
    return context, propagated, returned


def analyze_external_taint(
    units: list[FunctionUnit],
    rules: SourceRules | None = None,
) -> dict[str, ExternalTaintContext]:
    """Propagate source provenance through direct arguments and return values."""
    if not units:
        return {}
    prepared = _prepare_units(units, rules or DEFAULT_SOURCE_RULES)
    targets = _targets_by_call(prepared)
    parameter_state = {
        item.unit.key: [set() for _ in item.function_facts.params]
        for item in prepared
    }
    return_state = {item.unit.key: set() for item in prepared}
    contexts: dict[str, ExternalTaintContext] = {}

    while True:
        changed = False
        next_contexts: dict[str, ExternalTaintContext] = {}
        additions: dict[tuple[str, int], set[InputSourceFact]] = {}
        returned_by_unit: dict[str, set[InputSourceFact]] = {}
        for item in prepared:
            context, propagated, returned = _evaluate(
                item, targets, parameter_state, return_state
            )
            next_contexts[item.unit.key] = context
            returned_by_unit[item.unit.key] = returned
            for destination, sources in propagated.items():
                additions.setdefault(destination, set()).update(sources)

        for (unit_key, index), sources in additions.items():
            before = len(parameter_state[unit_key][index])
            parameter_state[unit_key][index].update(sources)
            changed |= len(parameter_state[unit_key][index]) != before
        for unit_key, sources in returned_by_unit.items():
            before = len(return_state[unit_key])
            return_state[unit_key].update(sources)
            changed |= len(return_state[unit_key]) != before

        contexts = next_contexts
        if not changed:
            return contexts


__all__ = [
    "ExternalTaintContext",
    "FunctionUnit",
    "TaintFlowPoint",
    "analyze_external_taint",
    "sources_for_expression",
]
