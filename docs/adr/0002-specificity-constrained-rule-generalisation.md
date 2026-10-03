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

The negative corpus is the synthetic benign traces plus the packaged
Avast-CTU corpus (`specimen/data/negatives.json.gz`, 200 training runs per
family) with the family the trained model *predicts* left out, so that a
sample's own siblings do not veto its rules. Without a family model nothing
is left out. `analyze` and `report` use the same synthesizer and corpus.

## Consequences

- Rule quality is measured instead of assumed (`benchmarks/bench_rules.py`),
  with sibling recall and cross-family FPR on a later time split, and benign
  FPR on 32,673 benign Speakeasy emulation reports (a lower bound, because an
  emulator records fewer host actions than a sandbox).
- The benchmark separates the shipped setting (predicted family left out,
  using out-of-fold family predictions) from *oracle* settings that leave
  out the true family, which the product cannot know.
- Generic prefixes that carry no family signal (hive roots, `\Environment`,
  `Local Settings\MuiCache`, user profile folders) do not count towards the
  10 literal characters.
- Rules stay plain Sigma: wildcards in values, standard logsource
  categories, `status: experimental`.
