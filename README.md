# ULTRON — JARVIS Batcomputer

**Built by Cyber Wolf Studios.** A two-piece voice-command system: a FastAPI
brain server that answers through Ollama, and a wake-word voice client for
your local machine.

## Layout

| File | Purpose |
|---|---|
| `server.py` | Cloud brain: `POST /command` answers via Ollama; `GET /shodan/{ip}` host intel (needs `SHODAN_API_KEY`) |
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
