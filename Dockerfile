# syntax=docker/dockerfile:1
#
# TraceMend container image — CLI and MCP (stdio) server in one small image.
# Build:  docker build -t tracemend:0.1.0 .   |   podman build -t tracemend:0.1.0 .
# Run:    docker run --rm -v "$PWD:/workspace" -v tracemend-state:/data tracemend:0.1.0 analyze trace.json
#
# The image is intentionally single-stage and dependency-light: the runtime
# dependencies are click, pydantic, rich and the official mcp SDK.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="TraceMend" \
      org.opencontainers.image.description="Find the waste. Fix the agent. Analyze AI agent execution traces, detect inefficient tool usage and safely optimize agent instructions." \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/kartikav05/tracemend"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    TRACEMEND_DATA_DIR=/data

WORKDIR /app

# Packaging metadata first so dependency resolution and the wheel build stay cached
# when only source files change.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Install TraceMend into the system interpreter, then drop privileges and prepare the
# two directories the tool actually touches: /data (SQLite state) and /workspace (the
# project being analyzed). Running as a non-root user keeps a trace file, an approved
# patch or an MCP-triggered write from touching anything the user could not touch.
RUN pip install . \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin tracemend \
 && mkdir -p /data /workspace \
 && chown -R tracemend:tracemend /data /workspace /app

# Baked-in fixtures make the image demonstrable with no bind mount at all:
#   docker run --rm tracemend:0.1.0 analyze /app/examples/inefficient_run.json
COPY --chown=tracemend:tracemend examples /app/examples

USER tracemend

# Analysis, findings, proposals, approvals and applied patches all live in SQLite.
# Without this volume the approval record cannot outlive the container, and the
# approve/apply boundary breaks. Mount it for anything beyond a one-shot report.
VOLUME ["/data"]

WORKDIR /workspace

ENTRYPOINT ["tracemend"]
CMD ["--help"]
