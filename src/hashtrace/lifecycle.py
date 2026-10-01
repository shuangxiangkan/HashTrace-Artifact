"""Container persistence and cleanup analysis for HashDoS candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from code_scan import cst, query
from code_scan.analysis import cfg as cfg_mod

from .extract import (
    HashTranslationUnitIndex,
    containers_for_function,
    resolve_container,
)
from .model import HashContainerFact, HashOperationFact, LifecycleFact


@dataclass(frozen=True)
class CleanupSite:
    container: str
    function: str
    line: int
    path: str | None = None


@dataclass(frozen=True)
class LifecycleIndex:
    cleanup_sites: tuple[CleanupSite, ...] = ()


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


def _normal_expression(expression: str) -> str:
    return "".join(expression.split())


def build_lifecycle_index(
    functions: Iterable[query.Function],
    source: bytes,
    index: HashTranslationUnitIndex,
    *,
    path: str | None = None,
) -> LifecycleIndex:
    """Index explicit cleanup entry points for persistent containers."""
    sites: list[CleanupSite] = []
    for function in functions:
        containers = containers_for_function(function, source, index)
        for call in query.find_calls(function.body_node, source, {"clear"}):
            container = resolve_container(call.receiver or "", containers)
            if container is None or container.storage not in {
                "member",
                "global",
                "static-local",
            }:
                continue
            sites.append(
                CleanupSite(
                    container=container.qualified_name,
                    function=function.qualified_name or function.name,
                    line=call.line,
                    path=path,
                )
            )
    sites.sort(key=lambda site: (site.container, site.path or "", site.line))
    return LifecycleIndex(tuple(sites))


def merge_lifecycle_indexes(indexes: Iterable[LifecycleIndex]) -> LifecycleIndex:
    unique = {
        (site.container, site.function, site.path, site.line): site
        for index in indexes
        for site in index.cleanup_sites
    }
    return LifecycleIndex(
        tuple(
            sorted(
                unique.values(),
                key=lambda site: (
                    site.container,
                    site.path or "",
                    site.line,
                    site.function,
                ),
            )
        )
    )


def analyze_lifecycle(
    function: query.Function,
    source: bytes,
    containers: list[HashContainerFact],
    container: HashContainerFact,
    operation: HashOperationFact,
    cfg: cfg_mod.CFG,
    index: LifecycleIndex | None = None,
) -> LifecycleFact:
    """Assess persistence and cleanup guaranteed after one hash operation."""
    persistent = container.storage in {"member", "global", "static-local"}
    base_persistence = "persistent" if persistent else "per-call"
    evidence = [
        (
            f"{container.qualified_name} persists beyond one function call"
            if persistent
            else f"{container.qualified_name} is local to this function call"
        )
    ]
    byte_index = cfg_mod.byte_index(cfg)
    operation_node = cfg_mod.node_for_byte(byte_index, operation.byte)
    postdominators = _postdominators(cfg)
    guaranteed: tuple[str, int] | None = None

    if operation_node is not None and operation_node in postdominators:
        for call in query.find_calls(function.body_node, source, {"clear", "erase"}):
            target = resolve_container(call.receiver or "", containers)
            if target is None or target.byte != container.byte:
                continue
            call_node = cfg_mod.node_for_byte(byte_index, call.node.start_byte)
            if (
                call_node is None
                or call_node == operation_node
                or call_node not in postdominators[operation_node]
                or not cfg_mod.reaches(
                    cfg, operation_node, call_node, acyclic=True
                )
            ):
                continue
            if call.name == "clear":
                guaranteed = ("guaranteed-clear", call.line)
                break
            if (
                operation.may_grow
                and call.args
                and _normal_expression(call.args[0])
                == _normal_expression(operation.key_expr)
            ):
                guaranteed = ("guaranteed-key-erase", call.line)
                break

    if guaranteed is not None:
        cleanup, line = guaranteed
        adjustment = -2.0 if persistent and operation.may_grow else 0.0
        persistence = (
            "cleared-before-return"
            if cleanup == "guaranteed-clear"
            else "key-erased-before-return"
        )
        evidence.append(
            f"{cleanup.replace('-', ' ')} post-dominates this hash operation"
        )
        return LifecycleFact(
            storage=container.storage,
            persistence=persistence,
            cleanup=cleanup,
            score_adjustment=adjustment,
            evidence=tuple(evidence),
            line=line,
        )

    related_sites = [
        site
        for site in (index.cleanup_sites if index is not None else ())
        if site.container == container.qualified_name
        and site.function != (function.qualified_name or function.name)
    ]
    if related_sites:
        site = related_sites[0]
        evidence.append(
            f"cleanup exists in {site.function}, but invocation is not proven on this path"
        )
        return LifecycleFact(
            storage=container.storage,
            persistence=base_persistence,
            cleanup="cleanup-entry-present",
            score_adjustment=0.0,
            evidence=tuple(evidence),
            line=site.line,
            path=site.path,
        )

    return LifecycleFact(
        storage=container.storage,
        persistence=base_persistence,
        cleanup="none",
        score_adjustment=0.0,
        evidence=tuple(evidence),
    )


__all__ = [
    "CleanupSite",
    "LifecycleIndex",
    "analyze_lifecycle",
    "build_lifecycle_index",
    "merge_lifecycle_indexes",
]
