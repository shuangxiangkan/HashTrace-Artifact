"""File and project-tree scanning for HashTrace."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from code_scan import cst, query

from .detector import annotate_lookup_only, detect_function
from .extract import (
    HashTranslationUnitIndex,
    build_translation_unit_index,
    find_type_aliases,
)
from .model import TypeAliasFact
from .interproc import FunctionUnit, analyze_external_taint
from .hasher import (
    HasherIndex,
    build_hasher_index,
    collect_randomized_seed_names,
    merge_hasher_indexes,
)
from .lifecycle import (
    LifecycleIndex,
    build_lifecycle_index,
    merge_lifecycle_indexes,
)
from .model import HashDoSCandidate
from .source_rules import DEFAULT_SOURCE_RULES, SourceRules


DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "build",
        "dist",
        "node_modules",
    }
)


@dataclass(frozen=True)
class ScanIssue:
    path: str
    message: str


@dataclass(frozen=True)
class ScanReport:
    target: str
    source_mode: str
    files_discovered: int
    files_scanned: int
    functions_scanned: int
    parse_error_files: int
    candidates: tuple[HashDoSCandidate, ...]
    errors: tuple[ScanIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "source_mode": self.source_mode,
            "files_discovered": self.files_discovered,
            "files_scanned": self.files_scanned,
            "functions_scanned": self.functions_scanned,
            "parse_error_files": self.parse_error_files,
            "candidate_count": len(self.candidates),
            "error_count": len(self.errors),
            "errors": [asdict(error) for error in self.errors],
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


@dataclass(frozen=True)
class _ParsedFile:
    path: Path
    relative_path: str
    source: bytes
    language: cst.LanguageName
    index: HashTranslationUnitIndex
    hasher_index: HasherIndex
    lifecycle_index: LifecycleIndex
    functions: tuple[query.Function, ...]


def _source_paths(target: Path, skip_dirs: set[str]) -> list[Path]:
    if not target.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")
    if target.is_file():
        if target.suffix.lower() not in cst.SOURCE_EXTENSIONS:
            raise ValueError(f"not a supported C/C++ source file: {target}")
        return [target]

    paths: list[Path] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(directory for directory in dirs if directory not in skip_dirs)
        base = Path(root)
        for name in sorted(files):
            path = base / name
            if path.suffix.lower() in cst.SOURCE_EXTENSIONS:
                paths.append(path)
    return paths


def _error_count(tree) -> int:
    return sum(
        1 for node in cst.walk(tree.root_node) if node.is_error or node.is_missing
    )


def _parse_source(
    path: Path, language: str, source: bytes | None = None
) -> tuple[Any, bytes, cst.LanguageName]:
    if language not in ("auto", "c", "cpp"):
        raise ValueError(f"unsupported language option: {language}")
    if source is None:
        source = path.read_bytes()
    resolved = cst.language_for_path(path, language)
    tree = cst.parse(source, language=resolved)

    # A .h file may contain either language. Parse both and retain the tree with
    # fewer recovery nodes; ties preserve the conventional C interpretation.
    if language == "auto" and path.suffix.lower() == ".h":
        alternative = "cpp" if resolved == "c" else "c"
        other_tree = cst.parse(source, language=alternative)
        if _error_count(other_tree) < _error_count(tree):
            tree, resolved = other_tree, alternative
    return tree, source, resolved


def _relative_path(path: Path, target: Path) -> str:
    if target.is_file():
        return path.name
    try:
        return str(path.relative_to(target))
    except ValueError:
        return path.name


def scan_path(
    target: str | Path,
    *,
    language: str = "auto",
    min_score: float = 0.0,
    skip_dirs: Iterable[str] = DEFAULT_SKIP_DIRS,
    source_mode: str = "all",
    source_rules: SourceRules | None = None,
) -> ScanReport:
    """Scan one source file or a directory tree and return a structured report."""
    if source_mode not in ("parameters", "external", "all"):
        raise ValueError(f"unsupported source mode: {source_mode}")
    root = Path(target).expanduser().resolve()
    paths = _source_paths(root, set(skip_dirs))
    candidates: list[HashDoSCandidate] = []
    errors: list[ScanIssue] = []
    files_scanned = 0
    functions_scanned = 0
    parse_error_files = 0
    parsed_files: list[_ParsedFile] = []

    # Sound, cheap early-exit *before parsing*: any std ``unordered_*`` container
    # (even via a ``using`` alias, whose target text contains "unordered")
    # requires the substring to appear in at least one scanned file. If it appears
    # nowhere, no candidate is possible — skip parsing and analysis entirely. This
    # keeps large pure-C projects (e.g. mongoose's 1.1 MB mongoose.c, which has no
    # such containers) to a few seconds of I/O instead of parsing every file.
    file_bytes: list[tuple[Path, bytes]] = []
    for path in paths:
        try:
            file_bytes.append((path, path.read_bytes()))
        except OSError as exc:
            errors.append(ScanIssue(path=str(path), message=str(exc)))
    files_scanned = len(file_bytes)
    if not any(b"unordered_" in data for _, data in file_bytes):
        return ScanReport(
            target=str(root),
            source_mode=source_mode,
            files_discovered=len(paths),
            files_scanned=files_scanned,
            functions_scanned=0,
            parse_error_files=0,
            candidates=(),
            errors=tuple(errors),
        )

    # Phase 1: parse every file (reusing the bytes already read) and collect its
    # functions and file-scope aliases. Tree nodes stay alive via the retained
    # ``functions``, so keeping root_node here adds no material memory.
    raw: list[tuple[Path, str, bytes, cst.LanguageName, Any, tuple]] = []
    for path, data in file_bytes:
        try:
            tree, source, resolved_language = _parse_source(path, language, data)
            if tree.root_node.has_error:
                parse_error_files += 1
            functions = query.extract_functions(tree, source)
            functions_scanned += len(functions)
            raw.append(
                (
                    path,
                    _relative_path(path, root),
                    source,
                    resolved_language,
                    tree.root_node,
                    tuple(functions),
                )
            )
        except (RuntimeError, ValueError) as exc:
            errors.append(ScanIssue(path=str(path), message=str(exc)))

    # Phase 2: pool all file-scope aliases project-wide, then build each file's
    # index/lifecycle with that pool so cross-header (`#include`d) type aliases
    # resolve — the tool does not expand includes.
    seen_aliases: dict[tuple[str, str], TypeAliasFact] = {}
    project_randomized: set[str] = set()
    for _, _, source, _, root_node, _ in raw:
        for alias in find_type_aliases(root_node, source, include_local=False):
            seen_aliases[(alias.qualified_name, alias.target_type_text)] = alias
        project_randomized |= collect_randomized_seed_names(root_node, source)
    project_aliases = tuple(seen_aliases.values())

    for path, relative_path, source, resolved_language, root_node, functions in raw:
        index = build_translation_unit_index(
            root_node, source, extra_aliases=project_aliases
        )
        lifecycle_index = build_lifecycle_index(
            functions, source, index, path=str(path)
        )
        parsed_files.append(
            _ParsedFile(
                path=path,
                relative_path=relative_path,
                source=source,
                language=resolved_language,
                index=index,
                hasher_index=build_hasher_index(
                    root_node,
                    source,
                    path=str(path),
                    extra_randomized_names=project_randomized,
                ),
                lifecycle_index=lifecycle_index,
                functions=functions,
            )
        )

    units: list[FunctionUnit] = []
    unit_files: dict[str, _ParsedFile] = {}
    for parsed in parsed_files:
        for position, function in enumerate(parsed.functions):
            key = f"{parsed.path}:{function.node.start_byte}:{position}"
            unit = FunctionUnit(
                key=key,
                function=function,
                source=parsed.source,
                language=parsed.language,
                path=str(parsed.path),
            )
            units.append(unit)
            unit_files[key] = parsed

    contexts = {}
    if source_mode in ("external", "all"):
        try:
            contexts = analyze_external_taint(
                units, source_rules or DEFAULT_SOURCE_RULES
            )
        except (RuntimeError, ValueError) as exc:
            errors.append(
                ScanIssue(path=str(root), message=f"interprocedural taint analysis failed: {exc}")
            )
    project_hasher_index = merge_hasher_indexes(
        parsed.hasher_index for parsed in parsed_files
    )
    project_lifecycle_index = merge_lifecycle_indexes(
        parsed.lifecycle_index for parsed in parsed_files
    )
    # Pool member/global containers declared anywhere in the project, so a field
    # declared in a header (``header_list _headers;``) is visible to a method that
    # operates on it from a separate .cpp — the tool does not expand ``#include``.
    project_containers = tuple(
        container
        for parsed in parsed_files
        for container in parsed.index.containers
        if container.storage in ("member", "global")
    )
    for unit in units:
        parsed = unit_files[unit.key]
        try:
            for candidate in detect_function(
                unit.function,
                parsed.source,
                language=parsed.language,
                index=parsed.index,
                source_mode=source_mode,
                source_rules=source_rules or DEFAULT_SOURCE_RULES,
                external_context=contexts.get(unit.key),
                hasher_index=project_hasher_index,
                lifecycle_index=project_lifecycle_index,
                project_containers=project_containers,
            ):
                candidates.append(
                    replace(
                        candidate,
                        path=str(parsed.path),
                        relative_path=parsed.relative_path,
                        language=parsed.language,
                    )
                )
        except (RuntimeError, ValueError) as exc:
            errors.append(ScanIssue(path=str(parsed.path), message=str(exc)))

    # Correlate lookups with inserts across the whole project (down-weighting
    # read-only containers) before the score threshold, so a demoted candidate
    # can fall below --min-score.
    candidates = annotate_lookup_only(candidates)
    candidates = [c for c in candidates if c.score >= min_score]

    candidates.sort(
        key=lambda candidate: (
            -candidate.score,
            candidate.relative_path or "",
            candidate.line,
        )
    )
    return ScanReport(
        target=str(root),
        source_mode=source_mode,
        files_discovered=len(paths),
        files_scanned=files_scanned,
        functions_scanned=functions_scanned,
        parse_error_files=parse_error_files,
        candidates=tuple(candidates),
        errors=tuple(errors),
    )


__all__ = ["DEFAULT_SKIP_DIRS", "ScanIssue", "ScanReport", "scan_path"]
