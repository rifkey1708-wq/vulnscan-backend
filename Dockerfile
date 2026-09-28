FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap nikto sqlmap curl wget procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY keepalive.sh .
RUN chmod +x keepalive.sh

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--timeout-keep-alive", "120"]
