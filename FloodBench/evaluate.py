#!/usr/bin/env python3
"""Score HashTrace on FloodBench and reproduce the paper's benchmark tables.

Each case is scanned separately together with common/hashers.h. A case counts
as detected when its report contains a candidate with score >= 5 whose status
is not "mitigated". Cases P01-P33 are exploitable and N01-N17 are safe.

Usage (from the HashTrace-Artifact directory):
    python3 FloodBench/evaluate.py                 # full HashTrace
    python3 FloodBench/evaluate.py --ablation C1   # one ablation configuration
    python3 FloodBench/evaluate.py --all           # full HashTrace and every ablation
    python3 FloodBench/evaluate.py --dynamic       # compile and run collision probes
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
ARTIFACT_DIR = BENCH_DIR.parent
CASES_DIR = BENCH_DIR / "cases"
HASHERS = BENCH_DIR / "common" / "hashers.h"
CONFIG = {"source_mode": "all", "min_score": 5.0}

# Values of HASHTRACE_ABLATE, in the row order of the paper's ablation table.
CONFIGURATIONS = {
    "full": ("", "Full HashTrace"),
    "NONLOCAL_CONTAINERS": ("NONLOCAL_CONTAINERS", "- member/global recovery"),
    "C1": ("C1", "- input-to-key reachability"),
    "C2": ("C2", "- hash predictability"),
    "C3": ("C3", "- collision constructibility"),
    "C4": ("C4", "- collision accumulation"),
}


def cases():
    """Yield (case directory, label) for every case, in case-id order."""
    for case_dir in sorted(CASES_DIR.iterdir()):
        if (case_dir / "prog.cpp").is_file():
            yield case_dir, {"id": case_dir.name, "vulnerable": case_dir.name.startswith("P")}


def prepare(case_dir: Path, workdir: Path) -> None:
    """Copy one case next to the shared hash definitions."""
    (workdir / "prog.cpp").write_text((case_dir / "prog.cpp").read_text())
    (workdir / "hashers.h").write_text(HASHERS.read_text())


def scan_case(workdir: Path, ablate: str, report_path: Path) -> dict:
    env = dict(os.environ, HASHTRACE_ABLATE=ablate)
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(ARTIFACT_DIR / "src"), env.get("PYTHONPATH")])
    )
    subprocess.run(
        [
            sys.executable, "-m", "hashtrace", "scan", str(workdir),
            "--source-mode", CONFIG["source_mode"],
            "--min-score", str(CONFIG["min_score"]),
            "--format", "json", "-o", str(report_path),
        ],
        env=env,
        check=True,
        stderr=subprocess.DEVNULL,
    )
    return json.loads(report_path.read_text(encoding="utf-8"))


def is_detected(report: dict, label: dict) -> bool:
    return any(
        candidate["status"] != "mitigated" and candidate["score"] >= CONFIG["min_score"]
        for candidate in report["candidates"]
    )


def evaluate(name: str, output_dir: Path) -> dict:
    ablate, _ = CONFIGURATIONS[name]
    config_dir = output_dir / name
    config_dir.mkdir(parents=True, exist_ok=True)
    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    false_positives, false_negatives = [], []
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for case_dir, label in cases():
            case_id = label["id"]
            prepare(case_dir, workdir)
            report = scan_case(workdir, ablate, config_dir / f"{case_id}.json")
            if report["errors"]:
                raise RuntimeError(f"{case_id}: scan errors: {report['errors']}")
            detected = is_detected(report, label)
            if label["vulnerable"] and detected:
                counts["TP"] += 1
            elif label["vulnerable"]:
                counts["FN"] += 1
                false_negatives.append(case_id)
            elif detected:
                counts["FP"] += 1
                false_positives.append(case_id)
            else:
                counts["TN"] += 1
    tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "configuration": name,
        **counts,
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1": round(f1, 2),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def validate(output_dir: Path, n: int) -> list[dict]:
    """Run HashTrace's dynamic validation (hashtrace verify --run) on every case."""
    sys.path.insert(0, str(ARTIFACT_DIR / "src"))
    os.environ["HASHTRACE_ABLATE"] = ""
    from hashtrace.harness import _find_compiler, verify_candidates
    from hashtrace.scan import scan_path

    if _find_compiler() is None:
        raise SystemExit("dynamic validation needs a C++ compiler (g++, clang++, or c++)")
    probes_root = output_dir / "probes"
    rows = []
    print(f"{'Case':<30} {'Probes':>6} {'Confirmed':>9} {'Insert':>9} "
          f"{'Lookup':>9} {'Max bucket':>10}")
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for case_dir, label in cases():
            case_id = label["id"]
            prepare(case_dir, workdir)
            report = scan_path(
                workdir, min_score=CONFIG["min_score"], source_mode=CONFIG["source_mode"]
            )
            results = verify_candidates(
                list(report.candidates), probes_root / case_id,
                run=True, n=n, min_score=CONFIG["min_score"],
            )
            confirmed = [r for r in results if r.confirmed]
            row = {
                "case": case_id,
                "vulnerable": label["vulnerable"],
                "probes": len(results),
                "confirmed": len(confirmed),
                "insert_ratio": max((r.insert_ratio or 0.0 for r in results), default=None),
                "lookup_ratio": max((r.lookup_ratio or 0.0 for r in results), default=None),
                "max_bucket": max((r.max_bucket or 0 for r in results), default=None),
                "probe_results": [r.to_dict() for r in results],
            }
            rows.append(row)
            if results:
                print(f"{case_id:<30} {len(results):>6} {len(confirmed):>9} "
                      f"{row['insert_ratio']:>8.0f}x {row['lookup_ratio']:>8.0f}x "
                      f"{row['max_bucket']:>10}", flush=True)
            else:
                print(f"{case_id:<30} {0:>6} {'-':>9}", flush=True)
    for vulnerable, group_name in ((True, "exploitable"), (False, "safe")):
        group = [r for r in rows if r["vulnerable"] is vulnerable]
        print(f"{group_name}: {sum(r['confirmed'] > 0 for r in group)}/{len(group)} cases "
              f"confirmed, {sum(r['probes'] == 0 for r in group)} without a probe")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--ablation",
        choices=[name for name in CONFIGURATIONS if name != "full"],
        help="remove one component (sets HASHTRACE_ABLATE)",
    )
    group.add_argument("--all", action="store_true", help="run every configuration")
    group.add_argument(
        "--dynamic", action="store_true",
        help="compile and run collision probes for every case (needs g++ or clang++)",
    )
    parser.add_argument(
        "-n", type=int, default=20000,
        help="keys per workload for --dynamic (default: 20000)",
    )
    parser.add_argument(
        "-o", "--output-dir", default="floodbench-output",
        help="directory for per-case JSON reports and summary.json "
             "(default: floodbench-output)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    if args.dynamic:
        rows = validate(output_dir, args.n)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "dynamic.json").write_text(
            json.dumps(rows, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\nProbes and dynamic.json written to {output_dir}/")
        return 0

    if args.all:
        names = list(CONFIGURATIONS)
    else:
        names = [args.ablation or "full"]

    results = []
    print(f"{'Configuration':<30} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} "
          f"{'Prec.':>6} {'Rec.':>6} {'F1':>6}  False positives")
    for name in names:
        result = evaluate(name, output_dir)
        results.append(result)
        print(f"{CONFIGURATIONS[name][1]:<30} {result['TP']:>3} {result['FP']:>3} "
              f"{result['FN']:>3} {result['TN']:>3} {result['precision']:>6.2f} "
              f"{result['recall']:>6.2f} {result['f1']:>6.2f}  "
              f"{', '.join(c[:3] for c in result['false_positives'])}",
              flush=True)
    (output_dir / "summary.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    print(f"\nReports and summary.json written to {output_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
