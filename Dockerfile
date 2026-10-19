FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY duogaurd_mcp /app/duogaurd_mcp

# --group local pulls torch/transformers for the bundled DuoGuard model (needs pip >= 25.1)
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir . --group local

RUN python -m duogaurd_mcp.main download

EXPOSE 8000

CMD ["python", "-m", "duogaurd_mcp.main", "dashboard"]
