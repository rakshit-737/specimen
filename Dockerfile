# syntax=docker/dockerfile:1
# SPECIMEN: offline report/trace analysis. Never executes samples.
# Base pinned by digest (python:3.12-slim); Dependabot bumps it.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY specimen ./specimen
RUN pip wheel --no-cache-dir --no-deps -w /wheels .

FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/specimen-malware-analysis" \
      org.opencontainers.image.description="Sample-to-story malware analysis pipeline (lab-only, never executes samples)" \
      org.opencontainers.image.licenses="MIT"
# The API behaviour model and the negative corpus ship inside the wheel.
# Optional family / EMBER models: mount them read-only at /opt/specimen/models.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SPECIMEN_MODELS=/opt/specimen/models
# install from a bind mount so the wheel never lands in a layer; then drop pip (unused at runtime)
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-cache-dir /wheels/*.whl \
    && pip uninstall -y pip \
    && useradd --create-home --uid 10001 specimen \
    && mkdir -p /opt/specimen/models
USER specimen
WORKDIR /work
ENTRYPOINT ["specimen"]
CMD ["--help"]
