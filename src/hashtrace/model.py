"""Domain facts emitted by the HashDoS static analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class TypeAliasFact:
    """A ``using`` or ``typedef`` alias for a known hash-container type."""

    name: str
    kind: str
    target_type_text: str
    key_type: str | None
    value_type: str | None
    hasher_type: str | None
    scope: str | None
    line: int
    byte: int

    @property
    def qualified_name(self) -> str:
        return f"{self.scope}::{self.name}" if self.scope else self.name

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HashContainerFact:
    """A directly declared hash container visible in one function."""

    name: str
    kind: str
    type_text: str
    key_type: str | None
    value_type: str | None
    hasher_type: str | None
    line: int
    byte: int
    storage: str = "local"
    scope: str | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.scope}::{self.name}" if self.scope else self.name

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HashOperationFact:
    """An operation whose behavior depends on hashing a key."""

    container: str
    operation: str
    category: str
    key_expr: str
    may_grow: bool
    line: int
    byte: int
    container_byte: int = -1
    end_byte: int = -1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InputSourceFact:
    """An API call that introduces externally controlled data into a function."""

    api: str
    kind: str
    output: str
    variables: tuple[str, ...]
    line: int
    byte: int
    end_byte: int
    function: str | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HasherRiskFact:
    """Static assessment of the hash function selected by one container."""

    hasher_type: str
    kind: str
    risk: str
    score_adjustment: float
    evidence: tuple[str, ...]
    definition: str | None = None
    line: int | None = None
    path: str | None = None
    collision_pattern: str | None = None
    output_bits: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HashLimitFact:
    """A proven operation-count/container-size bound or capacity context."""

    kind: str
    strength: str
    expression: str
    limit_value: int | None
    score_adjustment: float
    line: int
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CollisionRiskFact:
    """Estimated feasibility and local strategy for constructing collisions."""

    feasibility: str
    key_category: str
    strategy: str
    score_adjustment: float
    evidence: tuple[str, ...]
    output_bits: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class KeySourceFact:
    """Evidence that the hashed key is server-generated / random, not attacker-chosen."""

    randomized: bool
    generator: str | None
    score_adjustment: float
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LifecycleFact:
    """Persistence and cleanup assessment for one container operation."""

    storage: str
    persistence: str
    cleanup: str
    score_adjustment: float
    evidence: tuple[str, ...]
    line: int | None = None
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HashDoSCandidate:
    """An attacker-controlled key reaching a known hash-container operation."""

    function: str
    line: int
    container: HashContainerFact
    operation: HashOperationFact
    tainted_by: tuple[str, ...]
    confidence: str
    score: float
    evidence: tuple[str, ...]
    path: str | None = None
    relative_path: str | None = None
    language: str | None = None
    input_sources: tuple[InputSourceFact, ...] = ()
    hasher: HasherRiskFact | None = None
    limits: tuple[HashLimitFact, ...] = ()
    collision: CollisionRiskFact | None = None
    lifecycle: LifecycleFact | None = None
    key_source: KeySourceFact | None = None
    severity: str = "medium"
    status: str = "candidate"

    def to_dict(self) -> dict[str, Any]:
        """Return a compact report record suitable for JSON serialization."""
        return {
            "path": self.path,
            "relative_path": self.relative_path,
            "language": self.language,
            "function": self.function,
            "line": self.line,
            "container": self.container.name,
            "container_type": self.container.kind,
            "container_storage": self.container.storage,
            "container_scope": self.container.scope,
            "container_declaration_line": self.container.line,
            "key_type": self.container.key_type,
            "hasher_type": self.container.hasher_type,
            "hasher_analysis": self.hasher.to_dict() if self.hasher else None,
            "collision_analysis": (
                self.collision.to_dict() if self.collision else None
            ),
            "lifecycle_analysis": (
                self.lifecycle.to_dict() if self.lifecycle else None
            ),
            "key_source_analysis": (
                self.key_source.to_dict() if self.key_source else None
            ),
            "operation": self.operation.operation,
            "operation_category": self.operation.category,
            "key": self.operation.key_expr,
            "may_grow": self.operation.may_grow,
            "tainted_by": list(self.tainted_by),
            "input_sources": [source.to_dict() for source in self.input_sources],
            "confidence": self.confidence,
            "score": self.score,
            "severity": self.severity,
            "status": self.status,
            "evidence": list(self.evidence),
            "limits": [limit.to_dict() for limit in self.limits],
        }


__all__ = [
    "HashContainerFact",
    "CollisionRiskFact",
    "LifecycleFact",
    "HashDoSCandidate",
    "HashOperationFact",
    "HashLimitFact",
    "HasherRiskFact",
    "InputSourceFact",
    "KeySourceFact",
    "TypeAliasFact",
]
