"""One-hop interprocedural constant propagation.

Across all of a binary's functions, find which parameter *positions* of each
function are a compile-time constant at **every** known call site. A constant
argument proves a parameter is not *dynamically* attacker-controlled — NOT that
it is safe — so callers use this only to **downgrade** confidence (e.g. a
string-decryption helper whose length is always a literal), never to drop a
candidate.

One hop, whole-program (cross-file). OpenGrep OSS does have free *intra-file*
cross-function taint (`--taint-intrafile`); what it lacks is cross-file / multi-
hop propagation and a "derives-from-parameter" source that isn't a named API —
which is the gap this fills for decompiled C. Reuses each function's decompiled
body, so no extra decompilation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from .. import cst
from ..cst import node_text
from .expr import NAC, eval_const


def _scan(
    code: str, language: cst.LanguageName = "c"
) -> tuple[list[tuple[str, list[bool]]], set[str]]:
    """Return ``(calls, escaped)`` for one function body.

    ``calls`` = ``(callee_name, [is_const_per_positional_arg])`` for direct calls.
    ``escaped`` = every identifier used as a **value** rather than a direct-call
    callee — i.e. any occurrence *except* the ``function`` position of a
    ``call_expression``. This catches ``reg(f)``, ``reg(&f)``, ``fp = f`` and
    ``obj.cb = f`` alike: a function whose name is taken as a value may be invoked
    indirectly, so its call sites are not enumerable and it must not be judged
    closed-world. (Over-approximate — a local sharing a name only costs one
    suppression, the safe direction.)
    """
    src = code.encode("utf-8")
    tree = cst.parse(code, language=language)
    calls: list[tuple[str, list[bool]]] = []
    non_value_ids: set[int] = set()  # callee names + definition names (not values)
    for call in cst.walk(tree.root_node, "call_expression"):
        args = call.child_by_field_name("arguments")
        arg_nodes = [c for c in args.children if c.is_named] if args else []
        fn = call.child_by_field_name("function")
        if fn is not None and fn.type == "identifier":
            non_value_ids.add(fn.id)
            calls.append(
                (node_text(fn, src),
                 [eval_const(a, src, {}) is not NAC for a in arg_nodes])
            )
    # A function's own definition/declaration name is not a value-use of it.
    for decl in cst.walk(tree.root_node, "function_declarator"):
        name = decl.child_by_field_name("declarator")
        if name is not None and name.type == "identifier":
            non_value_ids.add(name.id)
    escaped = {
        node_text(idn, src)
        for idn in cst.walk(tree.root_node, "identifier")
        if idn.id not in non_value_ids
    }
    return calls, escaped


def const_param_positions(
    records: Iterable[dict],
    normalize: Callable[[str, str | None], str],
) -> dict[str, set[int]]:
    """Map ``function_name -> {positions constant at every call site}``.

    Sound (closed-world) conditions for a position ``i`` to qualify:

    * the function is called directly at least once, and **every** direct call
      supplies position ``i`` — i.e. ``i < min arity`` over all call sites (a call
      that omits the position is *not* evidence of constness there), and
    * every call that supplies it passes a compile-time constant, and
    * the function's name never escapes as a value (no possible indirect call
      whose arguments we cannot see).

    Anything not provable stays *unknown* (excluded) — conservative, never
    assumed safe.
    """
    all_const: dict[str, dict[int, bool]] = {}
    min_arity: dict[str, int] = {}
    escaped: set[str] = set()
    for r in records:
        code = r.get("decompiled")
        if not code:
            continue
        try:
            language = r.get("language", "c")
            calls, esc = _scan(
                normalize(code, r.get("backend")),
                "cpp" if language == "cpp" else "c",
            )
        except Exception:  # pragma: no cover - defensive on odd pseudocode
            continue
        escaped |= esc
        for name, consts in calls:
            d = all_const.setdefault(name, {})
            min_arity[name] = min(min_arity.get(name, len(consts)), len(consts))
            for i, is_const in enumerate(consts):
                d[i] = is_const if i not in d else (d[i] and is_const)
    out: dict[str, set[int]] = {}
    for name, d in all_const.items():
        if name in escaped:
            continue  # address-taken: call sites not enumerable
        arity = min_arity.get(name, 0)
        positions = {i for i, ok in d.items() if ok and i < arity}
        if positions:
            out[name] = positions
    return out


__all__ = ["const_param_positions"]
