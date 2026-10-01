"""Flow-sensitive analysis layer for step 2.

Mirrors the proven Semgrep/opengrep architecture — CST -> CFG -> a generic
dataflow fixpoint framework -> analysis instances (constant propagation, taint)
-- but scoped to decompiled C. Producers consume the resulting facts instead of
re-deriving control flow ad hoc.
"""
