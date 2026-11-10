# SeekAuth

Backend-only NetEase Noah's Ark (FateArk) verification server for Minecraft rental servers.
Licensed under **GPL-3.0-only** — see [LICENSE](LICENSE).

## Requirements

* Python 3.11+
* [uv](https://docs.astral.sh/uv/) (any recent version)

## Quick start

```bash
cd SeekAuth

# 1. install dependencies (creates .venv)
uv sync

# 2. put the keys in place
#    keys/server_private.pem   verification-server private key
#    keys/client_private.pem   FateArk client private key
#    keys/fbtokens.json        compact token -> full cookie mapping

# 3. copy the env template and set at least SEEK_ADMIN_TOKEN
cp .env.example .env

# 4. run
uv run seek-auth --host 127.0.0.1 --port 18080
```

Once it is up:

| URL | What |
|---|---|
| `http://127.0.0.1:18080/health` | liveness + table counts |
| `http://127.0.0.1:18080/docs` | interactive OpenAPI docs |
| `http://127.0.0.1:18080/api/admin/*` | admin API (Bearer `SEEK_ADMIN_TOKEN`) |
| `http://127.0.0.1:18080/api/new`, `/api/phoenix/*` | FateArk endpoints for clients |

Equivalent launch forms:

```bash
uv run seek_auth --host 127.0.0.1 --port 18080
uv run python -m seek_auth --host 127.0.0.1 --port 18080
.\.venv\Scripts\seek-auth.exe --host 127.0.0.1 --port 18080
```

## Checks

```bash
uv run pytest
uv run ruff check .
uv run mypy src
```
