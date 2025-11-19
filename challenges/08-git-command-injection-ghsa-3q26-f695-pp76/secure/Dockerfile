FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY secure/server.py /app/server.py
# Secrets are mounted at runtime via volume, not baked into image layers

EXPOSE 8000
CMD ["uvicorn", "server:mcp.app", "--host", "0.0.0.0", "--port", "8000"]
