# ADR 0002: Specificity-constrained generalisation for auto-Sigma

- Status: accepted
- Date: 2026-09-26

## Context

The MVP synthesizer (`synth.py`) emitted exact-value Sigma selections, and
only for events that mapped to an ATT&CK technique. On real CAPE data this
fails in two ways:

1. Most malware writes files, registry values and processes with names that
   are randomised per run, so exact values almost never fire on a sibling
   sample.
2. The technique-gated selections that do survive are generic (for example
   "any write under `\CurrentVersion\Run\`"). They fire across families,
   and a small synthetic benign corpus cannot catch that.

## Decision

`specimen/detect.py`:

- takes every host-visible action of the run (process creation, registry
  write, file write) as a candidate;
- builds a generalisation ladder per value: exact (user profile and SIDs
  wildcarded), then hex and numbers wildcarded, then file stem wildcarded,
  then parent directory wildcarded;
- keeps the **most general rung with no more than `max_neg_hits` matches
  on a negative corpus** that still has at least 10 literal characters
  after generic prefixes such as `C:\Users\*\AppData\Local` are removed;
- matches rules and traces through one line format and compiled
  case-insensitive regexes, so validating against thousands of traces is
  cheap.

The negative corpus is the synthetic benign traces, plus other-family runs
when they are available (the benchmark uses 1,500 of them).

## Consequences

- Rule quality is measured instead of assumed (`benchmarks/bench_rules.py`),
  with sibling recall and cross-family FPR on a later time split.
- Other families are a proxy for "benign" and are not a substitute for a
  real benign behaviour corpus. That limitation is documented.
- Rules stay plain Sigma: wildcards in values, standard logsource
  categories, `status: experimental`.
