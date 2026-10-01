"""SARIF 2.1.0 rendering for HashTrace scan reports."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .model import HashDoSCandidate
    from .scan import ScanReport


_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)


def _level(candidate: "HashDoSCandidate") -> str:
    if candidate.severity in {"critical", "high"}:
        return "error"
    if candidate.severity == "medium":
        return "warning"
    return "note"


def _fingerprint(candidate: "HashDoSCandidate") -> str:
    identity = ":".join(
        (
            candidate.relative_path or candidate.path or "<buffer>",
            candidate.function,
            str(candidate.line),
            candidate.container.qualified_name,
            candidate.operation.operation,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _result(candidate: "HashDoSCandidate") -> dict[str, Any]:
    uri = candidate.relative_path or candidate.path or "<buffer>"
    collision = candidate.collision
    feasibility = collision.feasibility if collision else "unknown"
    message = (
        f"{candidate.operation.operation} uses attacker-controlled key "
        f"{candidate.operation.key_expr} in {candidate.container.qualified_name}; "
        f"collision feasibility={feasibility}, score={candidate.score:g}"
    )
    return {
        "ruleId": "HASHTRACE001",
        "level": _level(candidate),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": candidate.line},
                },
                "logicalLocations": [
                    {"name": candidate.function, "kind": "function"}
                ],
            }
        ],
        "partialFingerprints": {"hashtrace/v1": _fingerprint(candidate)},
        "properties": candidate.to_dict(),
    }


def report_to_sarif(report: "ScanReport") -> dict[str, Any]:
    """Convert one structured scan report to a SARIF 2.1.0 document."""
    notifications = [
        {
            "level": "warning",
            "message": {"text": f"{issue.path}: {issue.message}"},
        }
        for issue in report.errors
    ]
    invocation: dict[str, Any] = {
        "executionSuccessful": not report.errors,
        "properties": {
            "target": report.target,
            "sourceMode": report.source_mode,
            "filesScanned": report.files_scanned,
            "functionsScanned": report.functions_scanned,
        },
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HashTrace",
                        "version": "0.1.0",
                        "rules": [
                            {
                                "id": "HASHTRACE001",
                                "name": "AttackerControlledHashKey",
                                "shortDescription": {
                                    "text": "Attacker-controlled key reaches a C/C++ hash container"
                                },
                                "fullDescription": {
                                    "text": (
                                        "A statically identified hash operation may be "
                                        "susceptible to collision-driven denial of service."
                                    )
                                },
                                "defaultConfiguration": {"level": "warning"},
                            }
                        ],
                    }
                },
                "invocations": [invocation],
                "results": [_result(candidate) for candidate in report.candidates],
            }
        ],
    }


__all__ = ["report_to_sarif"]
