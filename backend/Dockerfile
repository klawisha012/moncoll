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

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/metrics > /dev/null || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]