"""Constant / symbolic-value propagation — a forward dataflow instance.

Mirrors Semgrep's ``Dataflow_svalue``: a flow-sensitive map from variable to a
compile-time integer constant (or NAC, "not a constant"). Used to recognise
constant loop bounds / sizes / indices so producers can suppress writes whose
"attacker-controlled" value is really a constant. Cross-function param constness
(one-hop) is seeded via ``const_params``.
"""

from __future__ import annotations

import warnings

from . import dataflow
from .cfg import CFG
from .expr import NAC, assignments_in, eval_const


def _join(e1: dict, e2: dict) -> dict:
    out: dict[str, object] = {}
    for k in e1.keys() | e2.keys():
        if k in e1 and k in e2 and e1[k] is not NAC and e1[k] == e2[k]:
            out[k] = e1[k]
        else:
            out[k] = NAC  # differs, or defined on only one path
    return out


def constant_env(
    cfg: CFG, src: bytes, *, const_params: dict[str, int] | None = None
) -> dict[int, dict]:
    """Return the in-environment (var -> int|NAC) at each CFG node.

    ``const_params`` seeds parameters known to be constant at every call site
    (one-hop interprocedural); other parameters start as NAC.
    """
    seed = dict(const_params or {})

    def transfer(nid: int, in_env: dict) -> dict:
        node = cfg.nodes[nid]
        env = dict(in_env)
        if node.cst is not None:
            for lhs, rhs in assignments_in(node.cst, src):
                env[lhs] = eval_const(rhs, src, env)
        return env

    out, converged = dataflow.fixpoint(
        cfg, entry_env=seed, bottom={}, transfer=transfer, join=_join,
        eq=lambda a, b: a == b, forward=True,
    )
    if not converged:
        warnings.warn(
            "constant-propagation fixpoint did not converge; results may be unsound",
            dataflow.NonConvergenceWarning,
            stacklevel=2,
        )
    # recover in-env per node for consumers (what's known when the node runs)
    return {
        nid: dataflow.in_env_of(
            cfg, out, nid, entry_env=seed, bottom={}, join=_join, forward=True
        )
        for nid in cfg.reachable
    }


def is_constant(env: dict, name: str) -> bool:
    v = env.get(name, NAC)
    return v is not NAC


__all__ = ["constant_env", "is_constant"]
