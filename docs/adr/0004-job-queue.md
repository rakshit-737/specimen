# ADR 0004: File-ledger job queue before Redis/RQ

- Status: accepted
- Date: 2026-09-26

## Context

The spec lists a job queue (Redis/RQ or Celery) for many samples. For the
report-replay pipeline, one job takes milliseconds to a second, and a
broker adds an operational dependency without a real benefit yet.

## Decision

`specimen/jobqueue.py` gives the queue semantics that matter now:

- an append-only `jobs.jsonl` ledger that records each job as queued, then
  done or failed, keyed by the SHA-256 of the input;
- resumability: re-running a batch skips jobs that are already done;
- isolation: a process pool where one bad report fails its own job and not
  the batch.

## Consequences

`specimen batch <dir>` handles tens of thousands of reports on one host.
Swapping the executor for RQ workers is a local change, and the ledger
format stays the same. Distributed execution is out of scope until live
detonation exists, because that is where the real latency comes from.
