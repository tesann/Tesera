# .TES

Cryptographic provenance for digital media — an open infrastructure that records the origin and evolution of images and video (like Git for media).

This repository is **Python-first**. TypeScript integration is planned for later.

## Setup

Requires [uv](https://docs.astral.sh/uv/) (`brew install uv` or see the uv docs).

```bash
uv sync
```

## Tests

```bash
uv run pytest
```

## Layout

- `packages/core` — hashing, signing, commits, store, chain (future)
- `packages/cli` — CLI tool (future)
- `packages/c2pa_bridge` — C2PA manifest bridge (future)
- `docs/` — documentation
- `examples/` — integration examples
- `fixtures/` — test media files
