FROM python:3.11-slim

# Build args: which server module and which port to expose
ARG SERVER_MODULE=router.server
ARG SERVER_PORT=8000

ENV SERVER_MODULE=${SERVER_MODULE}
ENV SERVER_PORT=${SERVER_PORT}
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System deps — git needed for ticket sandbox clone
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY mcp/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP source tree
COPY mcp/ ./

# Non-root user for defense-in-depth
RUN useradd -m -u 1001 mcpuser && chown -R mcpuser:mcpuser /app
USER mcpuser

EXPOSE ${SERVER_PORT}

# Each server: `python3 -m <module> <port>`
CMD python3 -m ${SERVER_MODULE} ${SERVER_PORT}
