FROM python:3.12-slim

# Fix apt sources + install tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    procps \
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Install nikto manually (karena apt repo kadang gak ada)
RUN wget -q https://github.com/sullo/nikto/archive/master.tar.gz \
    && tar -xzf master.tar.gz \
    && mv nikto-master /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && rm master.tar.gz

# Install sqlmap
RUN wget -q https://github.com/sqlmapproject/sqlmap/archive/master.tar.gz \
    && tar -xzf master.tar.gz \
    && mv sqlmap-master /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py \
    && rm master.tar.gz

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
