# HashTrace

HashTrace detects hash-collision denial-of-service (HashDoS) risks in C++ source code. It statically identifies hash-table operations whose keys an attacker can control and collide, and generates collision probes that measure the resulting slowdown.

## Layout

- `src/hashtrace/` — HashTrace: static candidate analysis (`scan`) and dynamic collision validation (`verify`).
- `src/code_scan/` — parsing and program-analysis core.
- `FloodBench/` — the FloodBench benchmark (50 C++ cases) and its evaluation script.

## Installation

Requires Python 3.10+. `verify --run` also needs a C++17 compiler (`g++` or `clang++`).

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Static analysis: report HashDoS candidates as JSON
PYTHONPATH=src python3 -m hashtrace scan <source-dir> --format json -o report.json

# Dynamic validation: generate, compile, and run collision probes for the candidates
PYTHONPATH=src python3 -m hashtrace verify <source-dir> --run -o probes
```

To reproduce the FloodBench results, see [FloodBench/README.md](FloodBench/README.md).

See [NOTICE](NOTICE) for source attribution and licensing status.
