# Python API

The core package is standard-library only; `specimen.ml` needs the `[ml]` extra.

## Pipeline

::: specimen.pipeline
    options:
      members: [run, run_report, behaviour_score, is_sysmon]

## Adapters

::: specimen.adapters.cape
    options:
      members: [cape_to_trace, static_pe]

::: specimen.adapters.api_seq

::: specimen.adapters.sysmon
    options:
      members: [sysmon_to_trace]

## Behaviour scoring

::: specimen.api_behaviour
    options:
      members: [ApiBehaviourModel, api_sequence, ngrams]

::: specimen.scoring
    options:
      members: [featurize, score, event_anomaly]

## Detection synthesis

::: specimen.detect
    options:
      members: [synthesize_sigma, synthesize_yara_pe]

## Report

::: specimen.report
    options:
      members: [build_report, render_markdown, fuse]

## Data models

::: specimen.models
