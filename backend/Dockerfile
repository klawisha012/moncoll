FROM python:3.11-slim

WORKDIR /app

# Install system deps + Python deps first (cached when src/ changes)
COPY requirements.txt .

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl certbot curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --upgrade pip --no-cache-dir \
    && pip install --no-cache-dir -r requirements.txt

# Application source comes last so iterative rebuilds are fast
COPY src/ ./src/
COPY alembic.ini ./alembic.ini
COPY alembic/ ./alembic/

# Non-root runtime. /var/run/docker.sock access is granted at runtime via
# docker-compose.yml's `group_add: ["${DOCKER_GID:-999}"]` (joins the host's
# docker group). Without that group_add the container can't reload Angie or
# bring up user-supplied compose connections - intentional: missing
# group_add fails loudly rather than silently running as root.
# Volume mount targets (/var/lib/angie, /etc/angie/http.d, /var/lib/waf)
# come from the host as root-owned; on upgrade, run:
#   sudo chown -R 1000:${DOCKER_GID:-999} configs/angie/http.d var/log/angie
# See .gstack/security-reports/2026-05-20-043200.json F4.
RUN useradd --create-home --uid 1000 app \
    && chown -R app:app /app

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/metrics > /dev/null || exit 1

CMD ["sh", "-c", "alembic upgrade head && uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload"]