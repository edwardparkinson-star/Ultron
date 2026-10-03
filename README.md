# ULTRON — JARVIS Batcomputer

**Built by Cyber Wolf Studios.** A two-piece voice-command system: a FastAPI
brain server that answers through Ollama, and a wake-word voice client for
your local machine.

## Layout

| File | Purpose |
|---|---|
| `server.py` | Cloud brain: `POST /command` answers via Ollama; `GET /shodan/{ip}` host intel (needs `SHODAN_API_KEY`); port-forward endpoints (see below) |
| `client.py` | Local client: hears "hey jarvis", transcribes with faster-whisper, speaks replies with edge-tts |
| `requirements-server.txt` / `requirements-client.txt` | pip deps for each side |
| `.env.example` | copy to `.env` — keys live there, never in code |

## Permission

ULTRON does not run without permission. Set `ULTRON_API_KEY` in the
server's `.env` — the server refuses to boot without it, and `/command`
plus `/shodan/{ip}` reject any caller that doesn't send the same key as
the `X-API-Key` header (403 otherwise). The client reads the key from its
own `ULTRON_API_KEY` env var. See `LICENSE`: possession of the code does
not grant the right to run it.


## Port forward to a camera

Open a local port that relays to a camera or device you own. The relay
listens on **127.0.0.1 only** — never exposed to the network. All three
endpoints need the `X-API-Key` header like everything else.

```bash
# forward local 8554 -> camera at 192.168.1.50:554 (RTSP)
curl -X POST localhost:8000/port-forward \
  -H 'Content-Type: application/json' -H 'X-API-Key: YOUR_KEY' \
  -d '{"target_host":"192.168.1.50","target_port":554,"local_port":8554}'

# list active forwards
curl localhost:8000/port-forwards -H 'X-API-Key: YOUR_KEY'

# stop one
curl -X DELETE localhost:8000/port-forward/8554 -H 'X-API-Key: YOUR_KEY'
```

Then view the camera at `127.0.0.1:8554` as if it were local.

## File vault + database query

Upload intelligence files and databases to the server, then query them.
Files land in `~/ultron-data` (override with `ULTRON_DATA_DIR`), 100 MB
max per file. Filenames are sanitized — no path escapes. `/query` is
read-only: only `SELECT` statements run, against the database in
read-only mode. All four endpoints need the `X-API-Key` header.

```bash
# upload a database (or any file)
curl -X POST localhost:8000/upload -H 'X-API-Key: YOUR_KEY' \
  -F 'file=@intel.db;filename=intel.db'

# list the vault
curl localhost:8000/files -H 'X-API-Key: YOUR_KEY'

# read-only SQL against an uploaded SQLite database
curl -X POST localhost:8000/query -H 'X-API-Key: YOUR_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"db":"intel.db","sql":"SELECT * FROM assets"}'

# delete one
curl -X DELETE localhost:8000/files/intel.db -H 'X-API-Key: YOUR_KEY'
```

## Run it (GitHub Codespaces)

1. Open this repo → green **Code** button → **Codespaces** → create one.
2. In the terminal:
   ```bash
   cp .env.example .env   # fill in OLLAMA_HOST, ULTRON_API_KEY, keys
   python -m uvicorn server:app --host 0.0.0.0 --port 8000
   ```
3. Port 8000 forwards automatically — set it to **Public** and use that URL
   as the client's `JARVIS_URL`.

## Run the client (laptop)

```bash
pip install -r requirements-client.txt
export JARVIS_URL="https://your-server:8000/command"
python client.py
```
