# ────────────────────────────────────────────────────────────────────────────
# MeTHash - Dockerfile
# Build:   docker build -t methash .
# Run:     docker run -p 5000:5000 methash
# ────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create models directory
RUN mkdir -p models

# Default command: run Flask app
EXPOSE 5000
CMD ["python", "app/app.py"]
