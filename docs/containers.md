# Containers

The repository ships a `Dockerfile` and a matching `.dockerignore`, so the CLI and the stdio MCP server run from one image.

[← Back to README](../README.md) · [Setup](./setup.md) · [MCP](./mcp.md)

`docker` here is the standard CLI; every build and run command below works the same with `podman`.

```bash
# Build the image, tagged with the version in pyproject.toml.
docker build -t tracemend:0.1.0 .
podman build -t tracemend:0.1.0 .
```

## What the image contains

The image is deliberately single-stage: `python:3.12-slim`, with TraceMend installed from this project's own `pyproject.toml`.
It runs as the non-root user `tracemend` (UID 10001), sets `ENTRYPOINT ["tracemend"]` and `WORKDIR /workspace`, keeps its SQLite state in `/data` (`TRACEMEND_DATA_DIR=/data`), and bakes the example fixtures in at `/app/examples`.

## What the image does not do

The image never writes outside `/workspace` and `/data`, and it makes no network calls.
That is why `--network none` is safe to add to every run below.

## Running the image

A self-contained smoke run needs no mounts at all:

```bash
docker run --rm --network none tracemend:0.1.0 analyze /app/examples/inefficient_run.json
```

Analyzing a project on the host, read-only:

```bash
docker run --rm --network none -v "$PWD:/workspace:ro" -w /workspace tracemend:0.1.0 analyze examples/inefficient_run.json
```

`--network none` is safe and recommended: TraceMend makes no network calls, and the flag makes that guarantee visible rather than merely documented.

> **Note.** The approval record lives in SQLite under `TRACEMEND_DATA_DIR`, and every
> `docker run` starts from an empty `/data`. Without a persistent state volume, the `run_id`
> printed by one invocation is invisible to the next and the approve/apply boundary cannot
> work. Mount `-v tracemend-state:/data` on every step of a fix flow.

## The full fix flow

The full fix flow, one container per step, all sharing that volume:

```bash
docker run --rm --network none -v tracemend-state:/data -v "$PWD:/workspace:ro" -w /workspace \
  tracemend:0.1.0 analyze examples/inefficient_run.json

docker run --rm --network none -v tracemend-state:/data -v "$PWD:/workspace:ro" -w /workspace \
  tracemend:0.1.0 fix propose <run-id> <finding-id> --workspace .

docker run --rm --network none -v tracemend-state:/data tracemend:0.1.0 fix diff <proposal-id>

# Approval is a human act, so `fix approve` needs a terminal.
docker run -it --rm --network none -v tracemend-state:/data tracemend:0.1.0 fix approve <proposal-id>

# Only this step needs the workspace writable.
docker run --rm --network none -v tracemend-state:/data -v "$PWD:/workspace" -w /workspace \
  tracemend:0.1.0 fix apply <proposal-id>
```

`fix approve` deliberately refuses to run when stdin is not a TTY (`approval requires an interactive terminal`), which is why it takes `-it`; `--yes` exists only for a deliberate scripted local run.

## MCP over stdio

MCP over stdio needs an open stdin rather than a terminal:

```bash
docker run -i --rm --network none -v tracemend-state:/data tracemend:0.1.0 mcp
```

Use `-i` and **not** `-it` here — a TTY corrupts the JSON-RPC framing on stdio.

## Bind mounts on Linux

On Linux, files written through a bind mount are owned by the container UID, so pass `--user "$(id -u):$(id -g)"` on Docker or `--userns=keep-id` on Podman when you intend to apply a fix into a bind-mounted working tree.

## CI

`.github/workflows/ci.yml` has a `container` job that `needs: test`.
It builds with `docker build -t tracemend:ci .`, then checks the entrypoint (`--version` and `--help`), analyzes and compares the baked-in fixtures with `--network none` and validates the JSON, proves SQLite state survives across separate containers through the `/data` named volume, and asserts `fix approve` refuses to run without a TTY.

> **Note.** This image was built and exercised locally with Podman 5.5.2 on Apple Silicon, and
> every command above was run against it: the zero-mount smoke run, read-only analysis of a host
> project, SQLite state shared across separate containers through `tracemend-state`, the full
> propose → diff → approve → apply → undo cycle writing through a bind mount, and MCP over `-i`
> stdin. The result is `python:3.12-slim` plus this project's dependencies, 202 MB on disk.
> `.github/workflows/ci.yml` repeats the build and the same smoke checks on every push.

## Related

- [README](../README.md) — project overview and the full command reference.
- [Setup](./setup.md) — installing TraceMend locally.
- [MCP](./mcp.md) — the stdio MCP server and client configuration.
- [Fix workflow](./fix-workflow.md) — analyze → propose → approve → apply, end to end.
