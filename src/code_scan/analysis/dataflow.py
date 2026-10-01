"""Generic monotone dataflow fixpoint framework.

A direct Python port of the design in Semgrep/opengrep's ``Dataflow_core.ml``:
a worklist algorithm over CFG nodes, each holding an in/out environment (Appel,
*Modern Compiler Implementation in ML*). It is parameterised by a lattice
(``join`` + ``eq``) and a ``transfer`` function, and runs forward or backward.
Concrete analyses (constant propagation, taint) instantiate it.

Environments are arbitrary immutable values chosen by the analysis; the
framework only needs ``join`` (merge at control-flow joins) and ``eq`` (fixpoint
termination test).
"""

from __future__ import annotations

from collections.abc import Callable, Hashable
from typing import Any

from .cfg import CFG

Env = Any  # analysis-defined lattice element (must be immutable & eq-comparable)


class NonConvergenceWarning(RuntimeWarning):
    """A fixpoint hit ``max_iters`` before stabilising; its result is unsound.

    Analyses that consume :func:`fixpoint` should emit this (rather than silently
    returning a partial result) so a caller can distinguish a proven fact from an
    iteration-limited approximation."""


def _merge_in(
    cfg: CFG, out: dict[int, Env], node: int, entries, preds,
    entry_env: Env, bottom: Env, join: Callable[[Env, Env], Env],
) -> Env:
    """In-env of ``node`` = join of predecessors' out-envs, seeded from the first
    *real* predecessor (never from ``bottom`` — ``bottom`` is not assumed to be
    the join identity, so a meet/constant lattice is not silently collapsed)."""
    acc: Env = None
    started = False
    if node in entries:
        acc, started = entry_env, True
    for p in preds(node):
        if p in out:
            acc = out[p] if not started else join(acc, out[p])
            started = True
    return acc if started else bottom


def fixpoint(
    cfg: CFG,
    *,
    entry_env: Env,
    bottom: Env,
    transfer: Callable[[int, Env], Env],
    join: Callable[[Env, Env], Env],
    eq: Callable[[Env, Env], bool] | None = None,
    forward: bool = True,
    max_iters: int = 1_000_000,
) -> tuple[dict[int, Env], bool]:
    """Compute the out-environment at each reachable CFG node.

    Returns ``(out_mapping, converged)``. ``converged`` is False if the iteration
    limit was hit before a fixpoint — callers must not treat a non-converged
    result as sound.
    """
    eq = eq or (lambda a, b: a == b)
    preds = cfg.pred if forward else cfg.succ
    succs = cfg.succ if forward else cfg.pred
    entries = [cfg.entry] if forward else list(cfg.exits)

    out: dict[int, Env] = {n: bottom for n in cfg.reachable}
    work: set[int] = set(cfg.reachable)
    iters = 0
    while work and iters < max_iters:
        iters += 1
        n = work.pop()
        in_env = _merge_in(cfg, out, n, entries, preds, entry_env, bottom, join)
        new_out = transfer(n, in_env)
        if not eq(new_out, out[n]):
            out[n] = new_out
            work.update(s for s in succs(n) if s in out)
    return out, not work


def in_env_of(
    cfg: CFG, out: dict[int, Env], node: int, *, entry_env: Env, bottom: Env,
    join: Callable[[Env, Env], Env], forward: bool = True,
) -> Env:
    """Recover the in-environment at ``node`` from a finished ``out`` mapping."""
    entries = [cfg.entry] if forward else list(cfg.exits)
    preds = cfg.pred if forward else cfg.succ
    return _merge_in(cfg, out, node, entries, preds, entry_env, bottom, join)


__all__ = ["CFG", "Env", "NonConvergenceWarning", "fixpoint", "in_env_of"]
