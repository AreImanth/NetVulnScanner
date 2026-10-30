FROM python:3.11-slim

# nmap + raw socket support deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# data volume mount point
RUN mkdir -p /app/data/reports

ENV REPORT_DIR=/app/data/reports \
    CACHE_FILE=/app/data/cve_cache.json \
    DB_PATH=/app/data/jobs.db \
    ALLOWED_CIDRS=0.0.0.0/0 \
    PORT=8000

EXPOSE 8000

CMD sh -c 'uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}'