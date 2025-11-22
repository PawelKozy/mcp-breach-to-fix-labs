FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY helper/server.py /app/server.py

EXPOSE 8000
CMD ["uvicorn", "server:mcp.app", "--host", "0.0.0.0", "--port", "8000"]
