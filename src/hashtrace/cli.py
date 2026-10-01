"""Command-line interface for HashTrace."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .harness import verify_candidates
from .sarif import report_to_sarif
from .scan import DEFAULT_SKIP_DIRS, ScanReport, scan_path
from .source_rules import load_source_rules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashtrace",
        description="Detect HashDoS risks in C/C++ source code",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a C/C++ source file or directory for HashDoS candidates")
    scan.add_argument("target", help="source file or directory to scan")
    scan.add_argument(
        "--language",
        choices=("auto", "c", "cpp"),
        default="auto",
        help="parser language; by default chosen from the file extension and parse quality",
    )
    scan.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="report only candidates with at least this score",
    )
    scan.add_argument(
        "--source-mode",
        choices=("parameters", "external", "all"),
        default="all",
        help="key sources: function parameters, external input APIs, or both (default: all)",
    )
    scan.add_argument(
        "--source-rules",
        metavar="PATH",
        help="JSON file that extends or replaces the default input-source rules",
    )
    scan.add_argument(
        "--format",
        choices=("json", "jsonl", "sarif"),
        default="json",
        help="report format (default: json)",
    )
    scan.add_argument("-o", "--output", help="report file (default: standard output)")
    scan.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="additional directory name to skip; may be repeated",
    )
    scan.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit with status 1 when candidates are found",
    )

    verify = commands.add_parser(
        "verify",
        help="generate collision probes for candidates and optionally compile and run them",
    )
    verify.add_argument("target", help="source file or directory to scan")
    verify.add_argument("--language", choices=("auto", "c", "cpp"), default="auto")
    verify.add_argument(
        "--source-mode", choices=("parameters", "external", "all"), default="all"
    )
    verify.add_argument("--source-rules", metavar="PATH")
    verify.add_argument(
        "--exclude-dir", action="append", default=[], metavar="NAME"
    )
    verify.add_argument(
        "--min-score",
        type=float,
        default=8.0,
        help="generate probes only for candidates with at least this score (default: 8.0)",
    )
    verify.add_argument(
        "-o",
        "--out",
        default="hashtrace-probes",
        help="probe output directory (default: ./hashtrace-probes)",
    )
    verify.add_argument(
        "-n",
        type=int,
        default=20000,
        dest="n",
        help="number of keys per workload (default: 20000)",
    )
    verify.add_argument(
        "--run",
        action="store_true",
        help="compile and run the probes (requires g++ or clang++) and report slowdown ratios",
    )
    verify.add_argument(
        "--fail-on-confirmed",
        action="store_true",
        help="exit with status 1 when a probe confirms a slowdown",
    )
    return parser


def _render(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n"
    if output_format == "sarif":
        return json.dumps(report_to_sarif(report), ensure_ascii=False, indent=2) + "\n"
    lines = [
        json.dumps(candidate.to_dict(), ensure_ascii=False)
        for candidate in report.candidates
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def _emit(payload: str, output: str | None) -> None:
    if output is None or output == "-":
        sys.stdout.write(payload)
        return
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _scan_command(args: argparse.Namespace) -> int:
    skip_dirs = set(DEFAULT_SKIP_DIRS) | set(args.exclude_dir)
    try:
        source_rules = load_source_rules(args.source_rules)
        report = scan_path(
            args.target,
            language=args.language,
            min_score=args.min_score,
            skip_dirs=skip_dirs,
            source_mode=args.source_mode,
            source_rules=source_rules,
        )
        _emit(_render(report, args.format), args.output)
    except (OSError, ValueError) as exc:
        print(f"hashtrace: {exc}", file=sys.stderr)
        return 2

    print(
        "[HashTrace] "
        f"files {report.files_scanned}/{report.files_discovered}, "
        f"functions {report.functions_scanned}, "
        f"candidates {len(report.candidates)}, "
        f"errors {len(report.errors)}",
        file=sys.stderr,
    )
    if report.files_discovered and not report.files_scanned:
        return 2
    if args.fail_on_findings and report.candidates:
        return 1
    return 0


def _verify_command(args: argparse.Namespace) -> int:
    skip_dirs = set(DEFAULT_SKIP_DIRS) | set(args.exclude_dir)
    try:
        source_rules = load_source_rules(args.source_rules)
        report = scan_path(
            args.target,
            language=args.language,
            min_score=args.min_score,
            skip_dirs=skip_dirs,
            source_mode=args.source_mode,
            source_rules=source_rules,
        )
        results = verify_candidates(
            list(report.candidates),
            args.out,
            run=args.run,
            n=args.n,
            min_score=args.min_score,
        )
    except (OSError, ValueError) as exc:
        print(f"hashtrace: {exc}", file=sys.stderr)
        return 2

    confirmed = 0
    for result in results:
        if not args.run:
            print(f"  probe → {result.probe_path}  ({result.location} {result.container})")
            continue
        if result.confirmed:
            confirmed += 1
            print(
                f"  ✓ CONFIRMED  insert={result.insert_ratio:g}x "
                f"lookup={result.lookup_ratio:g}x  max_bucket={result.max_bucket}  "
                f"{result.location} {result.container}"
            )
        elif result.confirmed is False:
            print(
                f"  · not confirmed  insert={result.insert_ratio:g}x "
                f"lookup={result.lookup_ratio:g}x  {result.location}"
            )
        else:
            print(f"  ! {result.detail}  {result.location}")

    print(
        f"[HashTrace] candidates {len(report.candidates)}, "
        f"probes generated {len(results)}"
        + (f", confirmed {confirmed}" if args.run else "")
        + f", output directory {args.out}",
        file=sys.stderr,
    )
    if not results:
        print(
            "  (no probe generated: every candidate is mitigated, scores below\n"
            "   --min-score, or uses a key type or hasher the probe cannot\n"
            "   reproduce; probes cover string keys with std::hash or a\n"
            "   reproducible custom hasher, and integer keys with std::hash)",
            file=sys.stderr,
        )
    if args.fail_on_confirmed and confirmed:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan":
        return _scan_command(args)
    if args.command == "verify":
        return _verify_command(args)
    return 2


__all__ = ["main"]
