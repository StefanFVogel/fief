FROM --platform=$BUILDPLATFORM node:24-slim AS assets

WORKDIR /build

COPY package.json package-lock.json rollup.config.js ./
COPY js js
COPY styles styles
COPY fief fief

RUN npm ci && npm run build

FROM --platform=$BUILDPLATFORM python:3.12-slim AS wheel

WORKDIR /build

COPY README.md pyproject.toml ./
COPY --from=assets /build/fief fief

RUN pip install build Babel \
    && pybabel compile --domain=messages --directory=fief/locale \
    && python -m build --wheel --outdir /dist

FROM python:3.12-slim

ENV PYTHONUNBUFFERED 1

WORKDIR /app

RUN --mount=type=bind,from=wheel,source=/dist,target=/dist \
    apt-get update && apt-get install -y build-essential redis libpq-dev \
    && pip install --upgrade pip supervisor \
    && python --version \
    && pip install /dist/*.whl \
    && apt-get autoremove -y build-essential \
    && mkdir -p /data/db

COPY docker/supervisord.conf /etc/supervisord.conf

ENV DATABASE_LOCATION=/data/db
ENV SECRETS_DIR /run/secrets
ENV TELEMETRY_ENABLED=false

ENV PORT=8000
EXPOSE ${PORT}

CMD ["supervisord", "-c", "/etc/supervisord.conf"]
