# ---- Stage 0: build / install dependencies ----
FROM python:3.12-slim AS build

# Install build deps (minimal)
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what we need to install dependencies
COPY requirements.txt requirements-dev.txt ./

# Install dependencies into a wheelhouse inside /opt/wheels to avoid pip caching
RUN python -m pip install --upgrade pip setuptools wheel \
 && python -m pip wheel --wheel-dir /opt/wheels -r requirements.txt

# ---- Stage 1: runtime image ----
FROM python:3.12-slim AS runtime

# Create a non-root user for runtime safety
RUN addgroup --system app && adduser --system --ingroup app app

WORKDIR /app

# Copy wheels from build stage and install
COPY --from=build /opt/wheels /opt/wheels
COPY requirements.txt requirements-dev.txt ./
RUN python -m pip install --no-index --find-links /opt/wheels -r requirements.txt \
 && rm -rf /opt/wheels /root/.cache/pip

# Copy only package code (no keys)
COPY src /app/src
COPY pyproject.toml README.md /app/

ENV PYTHONPATH=/app/src \
    # default env var(s) point to where keys will be mounted in prod
    SIGNING_KEY_PATH=/run/secrets/signing_k1.priv \
    VERIFY_KEY_PATH=/run/secrets/signing_k1.pub \
    AEAD_KEY_PATH=/run/secrets/aead_k1.bin \
    ACTIVE_SIGNING_KID=k1 \
    ACTIVE_AEAD_KID=k1

# Use a non-root user
USER app

EXPOSE 8000

# Healthcheck (simple): HTTP 200 on root or /health if you add one
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:8000/ || exit 1

# Entrypoint: run uvicorn
CMD ["uvicorn", "crypto_service.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
