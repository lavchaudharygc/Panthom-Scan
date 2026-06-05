# ─── PHANTOM SCAN v5.0 — Docker Container ───────────────────────
# Runs headless (no GUI) scan from command-line inside container.
# GUI mode requires X11 forwarding or VNC (see docker-compose).
FROM python:3.11-slim

LABEL maintainer="YourName"
LABEL description="Phantom Scan v5.0 — Advanced Port Scanner + Vulnerability Assessment"
LABEL version="5.0"

# System dependencies for tkinter GUI (optional — only if X11 is forwarded)
RUN apt-get update && apt-get install -y \
    python3-tk \
    tk-dev \
    iputils-ping \
    net-tools \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phantom_scan.py .
COPY phantom_cli.py .

# Default: run CLI scanner (no GUI needed inside container)
ENTRYPOINT ["python3", "phantom_cli.py"]
CMD ["--help"]
