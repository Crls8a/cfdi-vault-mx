FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install ".[infra]"

VOLUME ["/app/storage", "/app/logs"]

# The Typer console script is gone. Every Compose service sets its own
# entrypoint/command explicitly (`worker`, `ledger-publisher`, `sat-monitor`,
# `app`), so this pair only serves a bare `docker run` with no command. It
# defaults to the same one-shot dependency check the `app` service runs, which
# keeps `docker run <image>` a useful smoke test instead of an error.
ENTRYPOINT ["python"]
CMD ["-m", "cfdi_vault.doctor_runner"]
