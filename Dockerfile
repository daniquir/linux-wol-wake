FROM python:3.10-slim

# System dependencies for network scanning and video
RUN apt-get update && apt-get install -y \
    iputils-ping \
    nmap \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Network caps (NET_RAW) required for Scapy/nmap; extended timeout for scans
# Single worker: in-memory login lockout is not shared across workers
CMD ["gunicorn", "--bind", "0.0.0.0:5055", "--timeout", "120", "--workers", "1", "app.main:app"]
