FROM python:3.11-slim

WORKDIR /app

COPY src/ ./src/
COPY requirements.txt .

RUN apt-get update && apt-get install -y openssl \
    && pip install --upgrade pip --no-cache-dir \
    && pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]