# FloodBench

FloodBench contains 50 labeled C++ cases distilled from real hash-table usage: 33 exploitable (`P01`–`P33`) and 17 safe (`N01`–`N17`). Each case is in `cases/<case-id>/prog.cpp`; custom hash functions shared by the cases are in `common/hashers.h`.

## Commands

Run from the `HashTrace-Artifact` directory.

```bash
# Results of HashTrace on FloodBench (under a minute)
python3 FloodBench/evaluate.py

# Full HashTrace plus each ablation (under a minute)
python3 FloodBench/evaluate.py --all

# Dynamic validation: compile and run a collision probe for every case (10–15 minutes)
python3 FloodBench/evaluate.py --dynamic
```

Per-case reports and a summary are written to `floodbench-output/`. A case counts as detected when HashTrace reports a candidate whose status is not `mitigated`. Ablations are selected with the `HASHTRACE_ABLATE` environment variable (`NONLOCAL_CONTAINERS`, `C1`–`C4`).

`--dynamic` generates probes for 32 of the 33 exploitable cases (all confirmed) and for the six false-positive safe cases; a probe measures the hash table in isolation, without the program's input limits.

To scan a single case by hand:

```bash
mkdir -p /tmp/case && cp FloodBench/cases/P01_httpquery_stdhash/prog.cpp FloodBench/common/hashers.h /tmp/case/
PYTHONPATH=src python3 -m hashtrace scan /tmp/case --min-score 5 --format json
```
