FROM python:3.12-slim AS base

# Non-root user for runtime safety.
RUN useradd --create-home --shell /bin/bash app
WORKDIR /app

# Install build deps then the package itself. Using ``pip install .`` keeps
# the image compact (no source tree, no tests).
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir .

USER app

# Persist the downloaded SQLite snapshot across container restarts.
ENV BDU_FSTEC_CACHE_DIR=/home/app/.cache/bdu-fstec-mcp
RUN mkdir -p "$BDU_FSTEC_CACHE_DIR"
VOLUME ["/home/app/.cache/bdu-fstec-mcp"]

# The MCP server speaks JSON-RPC over stdio — keep stdin/stdout unbuffered.
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["bdu-fstec-mcp"]
CMD ["run"]
