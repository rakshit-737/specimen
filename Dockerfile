# SPECIMEN: offline report/trace analysis. Never executes samples.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY specimen ./specimen
RUN pip wheel --no-cache-dir --no-deps -w /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/specimen" \
      org.opencontainers.image.description="Sample-to-story malware analysis pipeline (lab-only, never executes samples)" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SPECIMEN_MODELS=/opt/specimen/models
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels \
    && useradd --create-home --uid 10001 specimen
COPY models /opt/specimen/models
USER specimen
WORKDIR /work
ENTRYPOINT ["specimen"]
CMD ["--help"]
