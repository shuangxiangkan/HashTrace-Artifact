"""Estimate whether collisions are constructible for a static candidate."""

from __future__ import annotations

import re

from .model import CollisionRiskFact, HashContainerFact, HasherRiskFact


_INTEGRAL_TYPE = re.compile(
    r"\b(?:bool|char|short|int|long|size_t|ptrdiff_t|u?int(?:8|16|32|64)_t)\b"
)
_STRING_TYPE = re.compile(r"(?:basic_string|string|string_view)")


def _key_category(key_type: str | None) -> str:
    if not key_type:
        return "unknown"
    clean = " ".join(key_type.split())
    if "*" in clean:
        return "pointer"
    if _STRING_TYPE.search(clean):
        return "string"
    if _INTEGRAL_TYPE.search(clean) or clean.startswith("enum "):
        return "integral"
    return "structured"


def analyze_collision_risk(
    container: HashContainerFact, hasher: HasherRiskFact
) -> CollisionRiskFact:
    """Return a conservative construction strategy, not a vulnerability proof."""
    category = _key_category(container.key_type)
    pattern = hasher.collision_pattern
    bits = hasher.output_bits

    if hasher.risk == "randomized":
        return CollisionRiskFact(
            feasibility="low",
            key_category=category,
            strategy="recover the runtime seed or use an in-process hash oracle",
            score_adjustment=0.0,
            evidence=("recognized per-process randomization obstructs offline collisions",),
            output_bits=bits,
        )
    if hasher.risk == "weak" or bits == 0:
        return CollisionRiskFact(
            feasibility="high",
            key_category=category,
            strategy="construct distinct keys with the same direct hash output",
            score_adjustment=2.0,
            evidence=(
                f"hasher output is key-independent ({pattern or 'weak output'})",
            ),
            output_bits=bits,
        )
    if bits is not None and bits <= 16:
        return CollisionRiskFact(
            feasibility="high",
            key_category=category,
            strategy="enumerate keys and group them by the restricted hash output",
            score_adjustment=2.0,
            evidence=(
                f"hasher restricts output to about {bits} bit(s) via {pattern}",
            ),
            output_bits=bits,
        )
    if bits is not None and bits <= 32:
        return CollisionRiskFact(
            feasibility="medium",
            key_category=category,
            strategy="use a compiled hash oracle to search the reduced output domain",
            score_adjustment=1.0,
            evidence=(
                f"hasher restricts output to about {bits} bit(s) via {pattern}",
            ),
            output_bits=bits,
        )
    if pattern == "key length only":
        return CollisionRiskFact(
            feasibility="high",
            key_category=category,
            strategy="generate distinct keys with the same length",
            score_adjustment=2.0,
            evidence=("hasher depends only on key length",),
        )
    if hasher.kind == "default" and category == "integral":
        return CollisionRiskFact(
            feasibility="medium",
            key_category=category,
            strategy="test arithmetic same-bucket keys against the target standard library",
            score_adjustment=1.0,
            evidence=(
                "default integral hashes are commonly identity-like, but the C++ "
                "standard does not require a specific mapping",
            ),
        )
    if hasher.kind == "default" and category == "string":
        return CollisionRiskFact(
            feasibility="medium",
            key_category=category,
            strategy="compile a target-library hash oracle and search same-bucket keys",
            score_adjustment=0.0,
            evidence=(
                "default string hash behavior depends on the standard-library implementation",
            ),
        )
    if category == "pointer":
        return CollisionRiskFact(
            feasibility="low",
            key_category=category,
            strategy="verify whether the attacker controls pointer identity, not only pointee data",
            score_adjustment=-1.0,
            evidence=("pointer-key values are usually process-controlled addresses",),
            output_bits=bits,
        )
    if hasher.risk in {"fixed-seed", "deterministic", "runtime-seeded"}:
        return CollisionRiskFact(
            feasibility="medium",
            key_category=category,
            strategy="compile the custom hasher as an oracle and group keys by bucket",
            score_adjustment=0.5 if hasher.risk == "fixed-seed" else 0.0,
            evidence=(
                f"{hasher.risk} custom hashing is reproducible or locally observable",
            ),
            output_bits=bits,
        )
    return CollisionRiskFact(
        feasibility="unknown",
        key_category=category,
        strategy="resolve the hasher definition before collision generation",
        score_adjustment=0.0,
        evidence=("insufficient static information to choose a collision strategy",),
        output_bits=bits,
    )


__all__ = ["analyze_collision_risk"]
