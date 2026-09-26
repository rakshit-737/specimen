# ADR 0001: Replay public sandbox reports instead of detonating samples

- Status: accepted
- Date: 2026-09-26

## Context

The spec's full vision includes a disposable QEMU/KVM detonation VM with
eBPF/Sysmon capture (Stages 4-6). Running live malware needs proven network
isolation, snapshot/revert and a handling discipline that a solo portfolio
project on a shared Windows workstation cannot give. The project brief also
forbids downloading, storing or executing live binaries.

## Decision

SPECIMEN consumes *recorded behaviour*: its own JSON trace format, full
CAPEv2/Cuckoo reports, the reduced Avast-CTU reports and API-call sequences.
All of them go through adapters (`specimen/adapters/`) into one `Trace`
model. The "detonate" branch of the static gate replays such a trace.
No code path runs, loads or unpacks a sample.

## Consequences

- Every stage after detonation (provenance, timeline, scoring, family
  attribution, rule synthesis, report) is exercised on ~49k real CAPE runs.
- The detonation controller and eBPF capture remain roadmap items, and the
  interface they must meet is fixed: emit a trace or a CAPE-shaped report.
- Reduced reports have no per-event timestamps, so the adapter gives events
  a deterministic synthetic order and flags them `synthetic_ts`. Timelines
  built from them are ordered, not timed.
