"""HashDoS-specific analysis built on the reusable ``code_scan`` core."""

from .collision import analyze_collision_risk
from .detector import SourceMode, detect_function, detect_source
from .extract import (
    HashTranslationUnitIndex,
    build_translation_unit_index,
    containers_for_function,
    find_hash_containers,
    find_hash_operations,
    find_type_aliases,
)
from .model import (
    CollisionRiskFact,
    HashContainerFact,
    HashDoSCandidate,
    HashLimitFact,
    HashOperationFact,
    InputSourceFact,
    HasherRiskFact,
    LifecycleFact,
    TypeAliasFact,
)
from .hasher import (
    HasherIndex,
    analyze_container_hasher,
    build_hasher_index,
    merge_hasher_indexes,
)
from .interproc import (
    ExternalTaintContext,
    FunctionUnit,
    analyze_external_taint,
)
from .limits import analyze_operation_limits
from .lifecycle import (
    CleanupSite,
    LifecycleIndex,
    analyze_lifecycle,
    build_lifecycle_index,
    merge_lifecycle_indexes,
)
from .scan import ScanIssue, ScanReport, scan_path
from .sarif import report_to_sarif
from .source_rules import (
    DEFAULT_SOURCE_RULES,
    InputSourceRule,
    SourceRules,
    load_source_rules,
)
from .sources import find_input_sources

__all__ = [
    "CleanupSite",
    "CollisionRiskFact",
    "HashContainerFact",
    "HashDoSCandidate",
    "HashLimitFact",
    "HashOperationFact",
    "HashTranslationUnitIndex",
    "HasherIndex",
    "HasherRiskFact",
    "ExternalTaintContext",
    "FunctionUnit",
    "InputSourceFact",
    "InputSourceRule",
    "LifecycleFact",
    "LifecycleIndex",
    "ScanIssue",
    "ScanReport",
    "SourceMode",
    "SourceRules",
    "TypeAliasFact",
    "build_translation_unit_index",
    "build_hasher_index",
    "analyze_external_taint",
    "analyze_container_hasher",
    "analyze_collision_risk",
    "analyze_lifecycle",
    "analyze_operation_limits",
    "build_lifecycle_index",
    "containers_for_function",
    "detect_function",
    "detect_source",
    "find_hash_containers",
    "find_hash_operations",
    "find_input_sources",
    "find_type_aliases",
    "load_source_rules",
    "merge_hasher_indexes",
    "merge_lifecycle_indexes",
    "report_to_sarif",
    "scan_path",
    "DEFAULT_SOURCE_RULES",
]
