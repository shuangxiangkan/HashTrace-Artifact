"""End-to-end static candidate generation for the first HashTrace milestone."""

from __future__ import annotations

import os
import re
from dataclasses import replace
from typing import Iterable, Literal

from code_scan import cst, facts, query, ssa
from code_scan.analysis import taint as taint_mod

from .collision import analyze_collision_risk
from .extract import (
    HashTranslationUnitIndex,
    build_translation_unit_index,
    containers_for_function,
    find_hash_operations,
)
from .interproc import (
    ExternalTaintContext,
    FunctionUnit,
    analyze_external_taint,
    sources_for_expression,
)
from .hasher import HasherIndex, analyze_container_hasher, build_hasher_index
from .keysource import analyze_key_source
from .lifecycle import LifecycleIndex, analyze_lifecycle, build_lifecycle_index
from .limits import analyze_operation_limits
from .model import HashContainerFact, HashDoSCandidate
from .source_rules import DEFAULT_SOURCE_RULES, SourceRules
from .sources import find_input_sources, generated_taint


_SCORES = {
    "insert": 7.0,
    "lookup": 5.0,
    "erase": 4.0,
}
_STORAGE_BONUS = {
    "local": 0.0,
    "static-local": 2.0,
    "member": 2.0,
    "global": 2.0,
}
_SOURCE_BONUS = {"network": 2.0, "request": 2.0, "stream": 1.0, "environment": 0.5}

# A lookup on a container that no attacker-controlled insert ever grows cannot be
# a HashDoS: the attacker can only read existing keys, not pack colliding entries.
_LOOKUP_ONLY_ADJUSTMENT = -3.0

SourceMode = Literal["parameters", "external", "all"]

# ``m.erase(it)`` where ``it`` is an iterator (from find/begin/end/...) performs
# no hashing — it removes the element the iterator already points to — so it is
# not a HashDoS operation. Matched when the key resolves to such a call with
# nothing after it (``.find(k)->second`` is a *value*, not an iterator).
_ITERATOR_CALL_RE = re.compile(
    r"\.(?:find|begin|end|cbegin|cend|rbegin|rend|lower_bound|upper_bound"
    r"|equal_range)\s*\([^;]*\)\s*$"
)


def _is_iterator_key(key_expr: str, definitions: ssa.Defs) -> bool:
    expanded = ssa.expand(key_expr, definitions).strip()
    while expanded.startswith("(") and expanded.endswith(")"):
        expanded = expanded[1:-1].strip()
    return bool(_ITERATOR_CALL_RE.search(expanded))


def _severity_for(score: float) -> str:
    if score >= 10.0:
        return "critical"
    if score >= 8.0:
        return "high"
    if score >= 5.0:
        return "medium"
    return "low"


def _container_identity(candidate) -> tuple:
    """Stable identity that unifies operations on the same container.

    Global/member containers are one logical store program-wide (matched by
    scope + qualified name); local/static-local ones are per definition site.
    """
    container = candidate.container
    if container.storage in ("global", "member"):
        return (container.storage, container.scope or "", container.qualified_name)
    return (
        container.storage,
        candidate.path or candidate.relative_path or "",
        container.byte,
    )


def annotate_lookup_only(
    candidates: list[HashDoSCandidate],
) -> list[HashDoSCandidate]:
    """Down-weight lookup candidates on containers with no attacker-controlled insert.

    Correlates the full candidate set: a container is "attacker-grown" only if some
    candidate inserts an attacker-controlled key into it. A pure-lookup candidate on
    a container that is never so grown (e.g. a fixed MIME/config table filled with
    literals) cannot be packed with collisions. This is a *down-weight*, never a
    suppression, so an insert missed elsewhere only lowers rank, never hides a bug.
    """
    grown = {
        _container_identity(candidate)
        for candidate in candidates
        if candidate.operation.category == "insert"
    }
    out: list[HashDoSCandidate] = []
    for candidate in candidates:
        if (
            candidate.operation.category == "lookup"
            and _container_identity(candidate) not in grown
        ):
            new_score = max(0.0, candidate.score + _LOOKUP_ONLY_ADJUSTMENT)
            out.append(
                replace(
                    candidate,
                    score=new_score,
                    severity=_severity_for(new_score),
                    status="mitigated" if new_score < 5.0 else candidate.status,
                    confidence="low",
                    evidence=candidate.evidence
                    + (
                        "no attacker-controlled insert to this container was "
                        "detected; the attacker can only look up existing keys, "
                        "not pack colliding entries",
                    ),
                )
            )
        else:
            out.append(candidate)
    return out


def _root(node):
    while node.parent is not None:
        node = node.parent
    return node


def detect_function(
    function: query.Function,
    source: bytes,
    *,
    language: cst.LanguageName = "cpp",
    index: HashTranslationUnitIndex | None = None,
    source_mode: SourceMode = "all",
    source_rules: SourceRules | None = None,
    external_context: ExternalTaintContext | None = None,
    hasher_index: HasherIndex | None = None,
    lifecycle_index: LifecycleIndex | None = None,
    project_containers: Iterable[HashContainerFact] = (),
) -> list[HashDoSCandidate]:
    """Detect attacker-controlled keys used by visible hash containers."""
    # RQ3 ablations: C1-C4 bypass classification checks; NONLOCAL_CONTAINERS
    # removes member/global container recovery while retaining local tables.
    ablate = {d for d in os.environ.get("HASHTRACE_ABLATE", "").split(",") if d}
    if source_mode not in ("parameters", "external", "all"):
        raise ValueError(f"unsupported source mode: {source_mode}")
    index = index or build_translation_unit_index(_root(function.node), source)
    hasher_index = hasher_index or build_hasher_index(_root(function.node), source)
    lifecycle_index = lifecycle_index or build_lifecycle_index(
        [function], source, index
    )
    containers = containers_for_function(
        function, source, index, extra_containers=project_containers
    )
    if "NONLOCAL_CONTAINERS" in ablate:
        containers = [
            container
            for container in containers
            if container.storage in ("local", "static-local")
        ]
    if not containers:
        return []
    operations = find_hash_operations(function.body_node, source, containers)
    if not operations:
        return []

    # Reuse the per-function analysis already computed during external-taint
    # preparation (same CFG + parameter taint); only recompute when absent.
    function_facts = (
        external_context.function_facts
        if external_context is not None
        and external_context.function_facts is not None
        else facts.analyze(function, source, language=language)
    )
    definitions = ssa.build_defs(function.body_node, source)
    parameters = set(function_facts.params)
    if external_context is not None and source_mode in ("external", "all"):
        input_sources = list(external_context.input_sources)
        external_taint = external_context.taint
    else:
        input_sources = (
            find_input_sources(
                function.body_node,
                source,
                source_rules or DEFAULT_SOURCE_RULES,
            )
            if source_mode in ("external", "all")
            else []
        )
        external_taint = (
            taint_mod.analyze(
                function_facts.cfg,
                source,
                set(),
                generated_at_byte=generated_taint(input_sources),
            )
            if input_sources
            else None
        )
    by_identity = {container.byte: container for container in containers}
    candidates: list[HashDoSCandidate] = []

    for operation in operations:
        if operation.category == "erase" and _is_iterator_key(
            operation.key_expr, definitions
        ):
            continue  # erase-by-iterator hashes nothing
        key_vars = function_facts.taint.vars_of(operation.key_expr)
        expanded_origins = ssa.origins(operation.key_expr, definitions)
        parameter_vars = (
            function_facts.taint.tainted_vars_at(
                operation.byte, operation.key_expr
            )
            if source_mode in ("parameters", "all")
            else set()
        )
        external_vars = (
            external_taint.tainted_vars_at(operation.byte, operation.key_expr)
            if external_taint is not None
            else set()
        )
        if external_context is not None and source_mode in ("external", "all"):
            related_sources = list(
                sources_for_expression(
                    external_context,
                    definitions,
                    byte=operation.byte,
                    end_byte=operation.end_byte,
                    expression=operation.key_expr,
                )
            )
            external_controlled = bool(external_vars or related_sources)
        else:
            direct_sources = [
                input_source
                for input_source in input_sources
                if operation.byte <= input_source.byte < operation.end_byte
            ]
            related_sources = []
            external_controlled = bool(external_vars or direct_sources)
        if "C1" not in ablate and not parameter_vars and not external_controlled:
            continue

        key_lineage = expanded_origins | key_vars | external_vars
        if external_context is None:
            related_sources = [
                input_source
                for input_source in input_sources
                if input_source in direct_sources
                or (
                    input_source.byte <= operation.byte
                    and bool(set(input_source.variables) & key_lineage)
                )
            ]
            if external_vars and not related_sources:
                related_sources = [
                    input_source
                    for input_source in input_sources
                    if input_source.byte <= operation.byte and input_source.variables
                ]

        parameter_origins = (expanded_origins | key_vars) & parameters
        tainted_names = set(parameter_origins if parameter_vars else ())
        for input_source in related_sources:
            matched = set(input_source.variables) & key_lineage
            tainted_names.update(matched or input_source.variables)
            if not input_source.variables:
                tainted_names.add(f"{input_source.api}()")
        tainted_by = tuple(sorted(tainted_names or parameter_vars or external_vars))
        container = by_identity[operation.container_byte]
        hasher = analyze_container_hasher(container, hasher_index)
        collision = analyze_collision_risk(container, hasher)
        limits = analyze_operation_limits(
            function,
            source,
            containers,
            container,
            operation,
            function_facts.cfg,
        )
        lifecycle = analyze_lifecycle(
            function,
            source,
            containers,
            container,
            operation,
            function_facts.cfg,
            lifecycle_index,
        )
        key_source = analyze_key_source(operation.key_expr, definitions)
        evidence = [
            f"{container.qualified_name} is a {container.storage} container "
            f"declared as {container.type_text}",
            f"{operation.operation} hashes key expression {operation.key_expr}",
            *hasher.evidence,
            *collision.evidence,
            *(limit.evidence for limit in limits),
            *lifecycle.evidence,
            *(key_source.evidence if key_source is not None else ()),
        ]
        if parameter_vars:
            evidence.append(
                f"key derives from function parameter(s): "
                f"{', '.join(sorted(parameter_origins or parameter_vars))}"
            )
        if external_controlled:
            apis = sorted({source.api for source in related_sources})
            evidence.append(
                f"external input reaches key via source API(s): {', '.join(apis)}"
            )
        source_bonus = max(
            (_SOURCE_BONUS.get(source.kind, 1.0) for source in related_sources),
            default=0.0,
        )
        strong_container_cap = "C4" not in ablate and any(
            limit.kind == "container-size-cap" and limit.strength == "strong"
            for limit in limits
        )
        scored_limit = any(limit.score_adjustment < 0 for limit in limits)
        randomized_key = key_source is not None and key_source.randomized
        if randomized_key or hasher.risk == "randomized" or strong_container_cap:
            confidence = "low"
        elif hasher.risk in ("weak", "fixed-seed") or collision.feasibility == "high":
            confidence = "high"
        elif scored_limit or lifecycle.score_adjustment < 0:
            confidence = "medium"
        elif any(source.kind in ("network", "request") for source in related_sources):
            confidence = "high"
        else:
            confidence = "medium"
        score = max(
            0.0,
            _SCORES[operation.category]
            + _STORAGE_BONUS.get(container.storage, 0.0)
            + source_bonus
            + hasher.score_adjustment
            + (0.0 if "C3" in ablate else collision.score_adjustment)
            + (0.0 if "C4" in ablate else sum(limit.score_adjustment for limit in limits))
            + (0.0 if "C4" in ablate else lifecycle.score_adjustment)
            + (key_source.score_adjustment if key_source is not None else 0.0),
        )
        severity = _severity_for(score)

        if randomized_key and "C1" not in ablate:
            # A server-generated random key removes attacker control of the
            # bucket distribution: mitigated regardless of the residual score.
            status = "mitigated"
        elif hasher.risk == "randomized" and "C2" not in ablate:
            # A per-process randomized hash (random seed / keyed hash) makes the
            # bucket assignment unpredictable offline, so an attacker cannot
            # construct a colliding set in advance -- the standard HashDoS
            # defense. This mitigates as decisively as a randomized key.
            status = "mitigated"
        elif lifecycle.cleanup == "guaranteed-key-erase" and "C4" not in ablate:
            # The inserted key is erased before it can accumulate, so the live set
            # never exceeds one entry regardless of how many operations run.
            status = "mitigated"
        elif "C4" not in ablate and lifecycle.persistence == "per-call" and any(
            limit.kind == "operation-count-cap"
            and limit.limit_value is not None
            and limit.limit_value <= 1024
            for limit in limits
        ):
            # A small fixed per-invocation operation cap bounds a non-persistent
            # table well below DoS scale; collisions cannot accumulate.
            status = "mitigated"
        elif score < 5.0 and strong_container_cap:
            status = "mitigated"
        elif collision.feasibility == "unknown":
            status = "needs-context"
        else:
            status = "candidate"

        candidates.append(
            HashDoSCandidate(
                function=function.qualified_name or function.name,
                line=operation.line,
                container=container,
                operation=operation,
                tainted_by=tainted_by,
                confidence=confidence,
                score=score,
                evidence=tuple(evidence),
                input_sources=tuple(related_sources),
                hasher=hasher,
                limits=limits,
                collision=collision,
                lifecycle=lifecycle,
                key_source=key_source,
                severity=severity,
                status=status,
            )
        )

    candidates.sort(key=lambda candidate: (-candidate.score, candidate.line))
    return candidates


def detect_source(
    source: str | bytes,
    *,
    language: cst.LanguageName = "cpp",
    source_mode: SourceMode = "all",
    source_rules: SourceRules | None = None,
) -> list[HashDoSCandidate]:
    """Parse one source buffer and return ranked HashDoS candidates."""
    raw = source.encode("utf-8") if isinstance(source, str) else source
    tree = cst.parse(raw, language=language)
    index = build_translation_unit_index(tree.root_node, raw)
    hasher_index = build_hasher_index(tree.root_node, raw)
    functions = query.extract_functions(tree, raw)
    lifecycle_index = build_lifecycle_index(functions, raw, index)
    units = [
        FunctionUnit(
            key=f"buffer:{function.node.start_byte}:{position}",
            function=function,
            source=raw,
            language=language,
        )
        for position, function in enumerate(functions)
    ]
    contexts = (
        analyze_external_taint(units, source_rules or DEFAULT_SOURCE_RULES)
        if source_mode in ("external", "all")
        else {}
    )
    candidates: list[HashDoSCandidate] = []
    for unit in units:
        candidates.extend(
            detect_function(
                unit.function,
                raw,
                language=language,
                index=index,
                source_mode=source_mode,
                source_rules=source_rules,
                external_context=contexts.get(unit.key),
                hasher_index=hasher_index,
                lifecycle_index=lifecycle_index,
            )
        )
    candidates = annotate_lookup_only(candidates)
    candidates.sort(key=lambda candidate: (-candidate.score, candidate.line))
    return candidates


__all__ = ["SourceMode", "annotate_lookup_only", "detect_function", "detect_source"]
