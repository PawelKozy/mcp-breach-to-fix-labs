FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY server.py /app/server.py
COPY tickets.db /app/tickets.db

RUN pip install --no-cache-dir "mcp[cli]" fastapi uvicorn

EXPOSE 8000
CMD ["uvicorn", "server:mcp.app", "--host", "0.0.0.0", "--port", "8000"]
