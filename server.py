#!/usr/bin/env python3
"""
JARVIS Batcomputer — cloud brain server.

FastAPI service: POST a text command to /command, get JARVIS's reply
from Ollama. Runs on the cloud box (e.g. RunPod); the local client
talks to it over HTTPS.

PERMISSION: this server is private property of Cyber Wolf Studios. It
will not boot without ULTRON_API_KEY set, and every command endpoint
rejects callers that don't present the key. Possession of the code does
not grant the right to run it.

Setup:
    pip install -r requirements-server.txt
    cp .env.example .env   # fill in your values (keys NEVER go in code)
    uvicorn server:app --host 0.0.0.0 --port 8000

Env (.env supported):
    OLLAMA_HOST     Ollama base URL             (default http://localhost:11434)
    DEFAULT_MODEL   Ollama model                (default llama3.2)
    SHODAN_API_KEY  optional — enables /shodan/{ip} lookups
    ULTRON_API_KEY  REQUIRED — the server refuses to boot without it, and
                    every command endpoint rejects callers without it.
"""

import hmac
import os
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

load_dotenv()

try:
    from shodan import Shodan
    _HAS_SHODAN = True
except ImportError:
    _HAS_SHODAN = False

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "llama3.2")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
ULTRON_API_KEY = os.getenv("ULTRON_API_KEY", "").strip()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not ULTRON_API_KEY:
        raise RuntimeError(
            "ULTRON_API_KEY is not set — this server will not run "
            "without permission configured. Set it in the environment "
            "or .env and restart.")
    yield


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_permission(key: str = Security(api_key_header)):
    """Gate: no valid key, no use. Wrong key and missing key both fail."""
    if not key or not hmac.compare_digest(key, ULTRON_API_KEY):
        raise HTTPException(
            status_code=403,
            detail="Permission required — a valid API key was not provided.")


app = FastAPI(title="JARVIS Batcomputer", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _shodan():
    """Shodan client, or None when the key/package is missing."""
    if not _HAS_SHODAN or not SHODAN_API_KEY:
        return None
    return Shodan(SHODAN_API_KEY)


class Command(BaseModel):
    text: str


class Reply(BaseModel):
    response: str
    status: str = "success"


@app.get("/status")
async def status():
    return {"status": "JARVIS online", "system": "Batcomputer Tactical Core"}


@app.post("/command", response_model=Reply,
           dependencies=[Depends(require_permission)])
async def process_command(cmd: Command):
    text = cmd.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Empty command.")
    try:
        # trust_env=False: ignore proxy env vars (a malformed no_proxy
        # breaks httpx with "Invalid port" on some hosts).
        async with httpx.AsyncClient(timeout=90.0, trust_env=False) as client:
            payload = {
                "model": DEFAULT_MODEL,
                "prompt": (
                    "You are JARVIS, a tactical AI assistant inspired by "
                    "Iron Man and the Batcomputer. Be precise, strategic, "
                    "and slightly sarcastic. Keep every answer short and "
                    f"speakable. User: {text}"
                ),
                "stream": False,
            }
            r = await client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502,
                            detail=f"Ollama unreachable: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return Reply(response=(data.get("response") or
                           "No response generated.").strip())


@app.get("/shodan/{ip}", dependencies=[Depends(require_permission)])
async def shodan_lookup(ip: str):
    """Host intel via Shodan. Needs SHODAN_API_KEY in the environment."""
    api = _shodan()
    if api is None:
        raise HTTPException(status_code=501, detail=(
            "Shodan is not configured — install the shodan package "
            "and set SHODAN_API_KEY."))
    try:
        host = api.host(ip)
    except Exception as e:
        raise HTTPException(status_code=502,
                            detail=f"Shodan query failed: {e}")
    return {
        "ip": host.get("ip_str"),
        "org": host.get("org"),
        "os": host.get("os"),
        "ports": host.get("ports"),
        "hostnames": host.get("hostnames"),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
