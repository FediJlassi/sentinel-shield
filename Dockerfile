FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

COPY pyproject.toml uv.lock ./
RUN uv sync --locked

COPY app ./app
COPY configs ./configs

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin defender \
    && chown -R defender:defender /srv
USER 10001:10001

EXPOSE 8080
CMD ["uv", "run", "--no-project", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
